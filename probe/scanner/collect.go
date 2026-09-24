package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/models"
	"yugsight/normalizer"
	"yugsight/scanner"
)

// collect.go 探针"本机枚举"能力(任务类型 collect)。
//
// 与端口/主机扫描的区别: 这类任务**不触网**, 只采集探针所在机器自身的资产面
// (进程 / 服务 / 已安装软件 / 监听端口), 回答的是"这台机器上跑了什么",
// 而不是"网络上有哪些主机"。中心端据此做资产台账与暴露面核查。
//
// 平台差异(项目规则 2: Windows 专属代码放 *_windows.go, 非 Windows 配空桩):
//
//	进程    Windows = kernel32 CreateToolhelp32Snapshot FFI; 非 Windows = 读 /proc
//	服务    Windows = advapi32 EnumServicesStatus FFI;     非 Windows = 降级为空
//	软件    Windows = 注册表 Uninstall 键;                 非 Windows = 降级为空
//	监听端口 跨平台: net 标准库对本机地址做连接探测(见 probeListenPorts)
//
// 降级一律**记录到 HostEnum.Notes 并继续**, 不返回错误、不静默丢弃 ——
// 中心端要能看出"这一项是平台不支持还是枚举失败"(项目规则 3/4)。
//
// 可注入: 三个枚举器与端口探测器都可被测试替换, 单测不需要真实 Windows API。

// ProcInfo 一个进程。
type ProcInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Exe  string `json:"exe,omitempty"`
}

// ServiceInfo 一个系统服务。
type ServiceInfo struct {
	Name    string `json:"name"`
	Display string `json:"display,omitempty"`
	State   string `json:"state,omitempty"`
}

// SoftwareInfo 一条已安装软件记录。
type SoftwareInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
}

// ListenPort 一个监听端口。
//
// 只有 Proto/Addr/Port: 标准库拿不到"端口属于哪个进程"的跨平台口径
// (Windows 需 iphlpapi 扩展表、Linux 需解析 /proc/<pid>/fd  inode 映射),
// 与其填一个多半是错的 PID, 不如留空并明确说明。
type ListenPort struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr,omitempty"`
	Port  int    `json:"port"`
}

// HostEnum 本机枚举结果。
type HostEnum struct {
	Hostname  string         `json:"hostname"`
	OS        string         `json:"os"`
	Processes []ProcInfo     `json:"processes"`
	Services  []ServiceInfo  `json:"services"`
	Software  []SoftwareInfo `json:"software"`
	Ports     []ListenPort   `json:"ports"`
	// Notes 降级说明(平台不支持 / 枚举失败)。**不静默**: 空列表也意味着
	// "这一项没采到", 中心端据此区分"确实没有"与"没采到"。
	Notes []string `json:"notes,omitempty"`
}

// ===== 可注入的枚举器(平台实现在 *_windows.go / collect_other.go 注册) =====

var (
	procLister func() ([]ProcInfo, error)
	svcLister  func() ([]ServiceInfo, error)
	softLister func() ([]SoftwareInfo, error)
	// listenProber 单端口监听判定(测试注入; nil 用默认的本机连接探测)
	listenProber func(port int) bool
)

// SetProcessLister 注入进程枚举器(测试用; 传 nil 恢复平台实现需重启进程,
// 测试里一般注入自己的实现即可)。
func SetProcessLister(f func() ([]ProcInfo, error)) { procLister = f }

// SetServiceLister 注入服务枚举器(测试用)。
func SetServiceLister(f func() ([]ServiceInfo, error)) { svcLister = f }

// SetSoftwareLister 注入软件枚举器(测试用)。
func SetSoftwareLister(f func() ([]SoftwareInfo, error)) { softLister = f }

// SetListenProber 注入"某端口是否在本机监听"的判定(测试用; 传 nil 恢复默认)。
func SetListenProber(f func(port int) bool) { listenProber = f }

// EnumerateHost 采集本机资产面(任一环节失败都降级, 整体不返回错误)。
func EnumerateHost(ports []int) HostEnum {
	out := HostEnum{OS: runtime.GOOS}
	if h, err := os.Hostname(); err == nil {
		out.Hostname = strings.TrimSpace(h)
	}
	out.Processes = collectWith(procLister, "进程", &out.Notes)
	out.Services = collectWith(svcLister, "服务", &out.Notes)
	out.Software = collectWith(softLister, "软件", &out.Notes)
	out.Ports = ListenPorts(ports)
	if len(out.Ports) == 0 && len(ports) > 0 {
		out.Notes = append(out.Notes, "监听端口: 候选端口均未连通(可能本机无监听或回环探测被限制)")
	}
	return out
}

// collectWith 调一个枚举器并把降级原因写进 notes(泛型避免三份复制代码)。
func collectWith[T any](f func() ([]T, error), name string, notes *[]string) []T {
	if f == nil {
		*notes = append(*notes, name+": 当前平台未提供实现, 已降级为空")
		return nil
	}
	v, err := f()
	if err != nil {
		*notes = append(*notes, fmt.Sprintf("%s: 枚举失败(%v), 已降级为空", name, err))
		return nil
	}
	if len(v) == 0 {
		*notes = append(*notes, name+": 枚举结果为空")
		return nil
	}
	return v
}

// ===== 监听端口枚举 =====

// ListenPorts 判定候选端口中哪些在本机处于监听状态。
//
// 纯标准库下没有"列出监听套接字"的跨平台 API(net 包没有 Listeners() 这样的
// 接口), 唯一可行的跨平台判定是**对本机地址发起连接**: 能连上说明有人监听。
// 精度受两处限制, 都写进文档而非假装不存在:
//
//  1. 只检查候选端口(默认探针端口集), 不在候选里的监听端口不会出现在结果中;
//  2. 只连本机地址回环 + 本机网卡 IP, 仅绑定到其它地址的端口可能漏检。
func ListenPorts(ports []int) []ListenPort {
	if len(ports) == 0 {
		return nil
	}
	if listenProber != nil {
		var out []ListenPort
		for _, p := range ports {
			if listenProber(p) {
				out = append(out, ListenPort{Proto: "tcp", Port: p})
			}
		}
		return out
	}
	return probeListenPorts(ports)
}

// probeListenPorts 并发探测"本机地址 × 候选端口"的可连接性。
//
// 并发是必要的: 串行时最坏情况 = 端口数 × 地址数 × 超时, 30 多个端口就能拖到
// 几十秒; 并发后整体耗时≈一次超时。
func probeListenPorts(ports []int) []ListenPort {
	addrs := localProbeAddrs()
	var (
		mu   sync.Mutex
		out  []ListenPort
		sem  = make(chan struct{}, 64)
		wg   sync.WaitGroup
		seen = map[int]bool{}
	)
	for _, p := range ports {
		for _, a := range addrs {
			wg.Add(1)
			go func(addr string, port int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				c, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), 300*time.Millisecond)
				if err != nil {
					return
				}
				_ = c.Close()
				mu.Lock()
				defer mu.Unlock()
				if seen[port] {
					return
				}
				seen[port] = true
				out = append(out, ListenPort{Proto: "tcp", Addr: addr, Port: port})
			}(a, p)
		}
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// localProbeAddrs 本机探测地址(回环优先, 再补少量本机网卡 IP)。
//
// 上限 4 个: 多网卡机器可能有十几个地址, 每个都要乘一遍端口数, 全列出来会
// 把一次枚举放大成上千次连接尝试 —— 那是"自己对自己"的探测风暴, 必须克制。
func localProbeAddrs() []string {
	addrs := []string{"127.0.0.1"}
	if v4 := strings.TrimSpace(scanner.LocalIP()); v4 != "" && v4 != "127.0.0.1" && !strings.Contains(v4, ":") {
		addrs = append(addrs, v4)
	}
	if self, err := net.InterfaceAddrs(); err == nil {
		for _, a := range self {
			if len(addrs) >= 4 {
				break
			}
			ip, ok := a.(*net.IPNet)
			if !ok || ip.IP == nil || ip.IP.IsLoopback() {
				continue
			}
			v4 := ip.IP.To4()
			if v4 == nil {
				continue // IPv6 跳过: 探测面太大且内网台账以 v4 为主
			}
			s := v4.String()
			if s != "" && !containsStr(addrs, s) {
				addrs = append(addrs, s)
			}
		}
	}
	return addrs
}

// ===== 任务入口 =====

// scanCollect 本机枚举任务: 结果落成"本机资产 + 一条信息级发现摘要"。
//
// 口径(与 normalizer.ProbeReport 对齐): 进程/服务/软件数量进资产 Tags,
// 监听端口进 Ports, 摘要进一条 info 发现 —— 中心端归一化后即可在资产页看到
// 这台探针"装了什么、跑了什么、开了哪些口子"。
func (t *Task) scanCollect(ctx context.Context, progress Progress) {
	progress.Emit("本机枚举: 进程 / 服务 / 软件 / 监听端口")
	if ctx.Err() != nil {
		return
	}
	en := EnumerateHost(t.cfg.Ports)
	for _, n := range en.Notes {
		progress.Emit("本机枚举降级: " + n)
	}
	ip := collectLocalIP(t.Target)

	ports := make([]int, 0, len(en.Ports))
	for _, lp := range en.Ports {
		ports = append(ports, lp.Port)
	}
	sort.Ints(ports)

	a := normalizer.ProbeAsset{
		IP:       ip,
		Hostname: en.Hostname,
		OS:       en.OS,
		Ports:    ports,
		Service:  "本机枚举",
		Version:  runtime.GOOS + "/" + runtime.GOARCH,
		Tags: []string{
			"本机枚举",
			fmt.Sprintf("进程:%d", len(en.Processes)),
			fmt.Sprintf("服务:%d", len(en.Services)),
			fmt.Sprintf("软件:%d", len(en.Software)),
		},
	}
	t.addAsset(a)

	detail := fmt.Sprintf("进程 %d, 服务 %d, 已安装软件 %d, 监听端口 %d 个",
		len(en.Processes), len(en.Services), len(en.Software), len(ports))
	if len(ports) > 0 {
		detail += ": " + intsToStr(ports)
	}
	for _, n := range en.Notes {
		detail += "; " + n
	}
	t.addVuln(newProbeVuln(ip, 0, "info", "本机枚举", detail, "", ""))
	progress.Emit(fmt.Sprintf("本机枚举完成: %s", detail))
}

// collectLocalIP 确定本机资产 IP: 目标显式给了 IP 就用它, 否则取本机出口 IP,
// 再不行退回 127.0.0.1(保证资产一定能落到中心端, 不因取不到 IP 就整条丢弃)。
func collectLocalIP(target string) string {
	if ip := models.NormIP(strings.TrimSpace(target)); ip != "" {
		return ip
	}
	if v := strings.TrimSpace(scanner.LocalIP()); v != "" {
		return v
	}
	return "127.0.0.1"
}

// intsToStr 端口列表转逗号串(摘要用; 超长截断避免撑爆协议单行上限)。
func intsToStr(ports []int) string {
	var sb strings.Builder
	for i, p := range ports {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.Itoa(p))
		if sb.Len() > 200 {
			sb.WriteString("...")
			break
		}
	}
	return sb.String()
}
