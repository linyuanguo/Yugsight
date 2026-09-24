package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// ParseHosts 从 CIDR(192.168.1.0/24)、IP 范围(a.b.c.d-a.b.c.e)、逗号分隔列表或单个 IP 解析主机列表
// 安全上限：单次最多 4096 个主机
func ParseHosts(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("目标不能为空")
	}
	if strings.Contains(s, ",") {
		var all []string
		for _, part := range strings.Split(s, ",") {
			hosts, err := ParseHosts(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			all = append(all, hosts...)
		}
		seen := map[string]bool{}
		var dedup []string
		for _, h := range all {
			if !seen[h] {
				seen[h] = true
				dedup = append(dedup, h)
			}
		}
		return dedup, nil
	}
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("无效的 CIDR: %s", s)
		}
		if ipnet.IP.To4() == nil {
			return nil, fmt.Errorf("仅支持 IPv4 CIDR")
		}
		ones, _ := ipnet.Mask.Size()
		count := uint64(1) << uint(32-ones)
		if count > 4096 {
			return nil, fmt.Errorf("网段过大(单次最多 4096 个主机, 请使用 /22 或更小的网段)")
		}
		start := ipToUint32(ipnet.IP.To4())
		var hosts []string
		for i := uint32(0); i < uint32(count); i++ {
			if ones <= 30 && (i == 0 || i == uint32(count)-1) {
				continue // 跳过网络地址和广播地址
			}
			hosts = append(hosts, uint32ToIP(start+i).String())
		}
		return hosts, nil
	}
	if i := strings.Index(s, "-"); i > 0 {
		startIP := net.ParseIP(strings.TrimSpace(s[:i]))
		endStr := strings.TrimSpace(s[i+1:])
		endIP := net.ParseIP(endStr)
		if endIP == nil && startIP != nil {
			// 支持缩写形式 192.168.1.10-30: 用起始地址的前三段补全
			o := strings.Split(startIP.String(), ".")
			endIP = net.ParseIP(o[0] + "." + o[1] + "." + o[2] + "." + endStr)
		}
		if startIP == nil || endIP == nil || startIP.To4() == nil || endIP.To4() == nil {
			return nil, fmt.Errorf("无效的 IP 范围: %s", s)
		}
		s4, e4 := startIP.To4(), endIP.To4()
		if s4[0] != e4[0] || s4[1] != e4[1] || s4[2] != e4[2] {
			return nil, fmt.Errorf("范围扫描仅支持同一 C 段")
		}
		a, b := ipToUint32(s4), ipToUint32(e4)
		if a > b {
			a, b = b, a
		}
		if b-a+1 > 4096 {
			return nil, fmt.Errorf("范围过大(单次最多 4096 个主机)")
		}
		var hosts []string
		for n := a; n <= b; n++ {
			hosts = append(hosts, uint32ToIP(n).String())
		}
		return hosts, nil
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return []string{ip.String()}, nil
	}
	return nil, fmt.Errorf("无法识别的目标: %s (支持 CIDR / 单 IP / a.b.c.d-x.x.x.x / 逗号列表)", s)
}

// HasConfirmedResponse 目标是否对本机做出了"确定存活"的应答(ICMP 或 ARP)。
//
// 【为什么要和三路探测分开看】判定"存活"这件事, ICMP/ARP 应答与"某个端口开放"
// 的可信度并不相同:
//
//   - ICMP echo / ARP: 收到应答 = 该地址上确实有一台主机在回包, 是**确定性证据**;
//   - "探针端口开放": 只能说明你恰好猜中了它开放的服务端口 —— 猜不中不代表主机
//     不在线(只开 445 的 Windows 主机对 80 端口探测的应答就是"不存活")。
//
// 因此 ICMP/ARP 均无应答时切到**宽松模式**: 只要探测端口有开放就纳入结果并标注
// "端口推断", 避免整段扫描一无所获; 而"严格模式"(可配置)只接受确定性证据,
// 适合"我只想验证某几台机器在不在线"的场景。
func HasConfirmedResponse(icmp, arp bool) bool { return icmp || arp }

// classifyAlive 把三路探测证据合成为"存活判定"结论(纯逻辑, 与网络无关)。
//
// 抽成独立函数的理由: 这段判定是"存活扫描"最核心、也最容易写错的口径, 但它被
// 埋在 scanIPsWithMode 的 goroutine 里, 依赖真实 ICMP/ARP/端口探测 —— 在 CI/沙箱
// 里根本跑不出稳定结论, 于是改成纯函数后可以穷举所有证据组合来守护。
//
// 返回 (计入存活, 被严格模式排除, 是否仅凭端口推断)。
// 三模式语义:
//
//	strict=true  仅 ICMP/ARP 应答计入存活; 仅端口开放者 excluded+1 但仍会上报;
//	strict=false ICMP/ARP 应答或端口开放都计入存活(inferred 标记证据来源)。
//
// 注意: 调用方需保证 res.alive 已为真(无任何响应者不会走到这里)。
func classifyAlive(strict, icmp, arp bool) (alive, excluded, inferred bool) {
	confirmed := HasConfirmedResponse(icmp, arp)
	switch {
	case strict && !confirmed:
		// 严格模式: 只探测到端口开放 -> 不计入存活, 但不算"不存在"
		return false, true, true
	case !confirmed:
		// 宽松模式: 端口开放即视为存活, 标注为"端口推断"
		return true, false, true
	default:
		return true, false, false
	}
}

// buildIPEvent 组装单台主机的 ip 事件(前端 handleEvent 的 ip 分支按此结构渲染)。
//
// 抽成纯函数的目的: 这是**对外契约**, 前端直接读 ip/alive/ports/icmp/arp/inferred/
// rttMs/mac/excludedByStrict 这些键。契约一旦漏键, 前端表现为"某一列空白"而非报错,
// 极难发现 —— 独立出来才能不依赖网络地断言字段完整性(见 alive_mode_test.go)。
//
// 【ports 必须无条件带上】存活探测用的端口本身就是一次真实探测, 顺带探到的开放
// 端口对用户有价值; 丢掉它会迫使用户再跑一次端口扫描, 同一批端口被探两遍。
// 严格模式排除的主机同样要带 ports —— 恰恰是这类主机只有端口信息可展示。
func buildIPEvent(host string, res hostProbeResult, inferred, excludedByStrict bool) map[string]any {
	// ports 归一成"永不 nil"的切片。注意**不能**写成 `if ev["ports"] == nil`:
	// res.ports 为 []int(nil) 时, 存进 any 会得到"类型为 []int、值为 nil"的非空
	// 接口, 与 nil 比较恒为 false, 归一化会静默失效, JSON 依旧序列化成 null。
	// 必须在赋值前对**具体类型**判空。这个坑已由真机冒烟实测暴露(见 c3 记录)。
	ports := res.ports
	if ports == nil {
		ports = []int{}
	}
	ev := map[string]any{
		"ip": host, "alive": true, "ports": ports,
		"icmp": res.icmp, "arp": res.arp, "inferred": inferred,
		"rttMs": res.rtt,
	}
	if res.mac != "" {
		ev["mac"] = res.mac
	}
	if excludedByStrict {
		ev["excludedByStrict"] = true
	}
	return ev
}

// hostProbeResult 单主机存活探测结果
type hostProbeResult struct {
	alive bool
	icmp  bool
	arp   bool
	rtt   int64
	mac   string
	ports []int
}

// probeHost2 对单个主机并发执行 ICMP ping 与 ARP 查询, 任一应答即视为"确定存活"。
//
// 【为什么要加 ARP】纯 ICMP 判定会漏掉一类最常见的目标: 开了防火墙但确实在线、
// 也确实开放端口的 Windows 主机(默认丢弃 ICMP echo)。这类主机只能靠端口探测
// 发现, 而端口探测的覆盖面完全取决于用户填了哪些端口 —— 用户填 "80" 时一个只开
// 445/3389 的在线主机就被判为"不存活"。ARP 是链路层协议, 同网段内几乎必答,
// 且不受主机防火墙影响, 正好补上这个缺口(与探针侧 scanAlive 的三路互补同口径)。
// 跨网段时目标不在本广播域, ARP 无应答属正常, 不会误判。
//
// c7 起 scanIPsWithMode 已委托统一扫描引擎 UnifiedScan, 本函数降级为
// probeHostUnified 的兼容适配层(保留原签名, 供既有调用方编译), 底层探测与统一
// 引擎共用同一套实现 —— 端口经 probeOnePort 探测(顺带抓取服务 banner), 开放端口
// 列表升序返回, 与旧 probeHost(sort.Ints 后返回)口径一致。
func probeHost2(ctx context.Context, ip string, ports []int, timeout time.Duration, seq uint16, icmpAvail, arpAvail bool) hostProbeResult {
	u := probeHostUnified(ctx, ip, ports, timeout, seq, icmpAvail, arpAvail, true)
	res := hostProbeResult{icmp: u.icmp, arp: u.arp, rtt: u.rtt, mac: u.mac}
	for _, pd := range u.portDetails {
		if pd.State == "open" {
			res.ports = append(res.ports, pd.Port)
		}
	}
	// probeHostUnified 不带 alive 字段, 由证据合成: ICMP/ARP 应答或任一端口开放
	res.alive = res.icmp || res.arp || len(res.ports) > 0
	return res
}

// ScanIPs 网段存活扫描(宽松模式)：收到 ICMP / ARP 应答或任一探测端口开放即视为存活。
//
// 宽松模式的原因: 用户填 "80" 时, 只开 445 的在线主机拿不到 ICMP/ARP 应答, 若按
// 严格判定就会被报成"不存活", 而用户看到的结果是"整个网段全灭"——比多报几台更糟。
// 需要严格口径时用 ScanIPsStrict(仅 ICMP/ARP 应答), 前端"存活判定"下拉可选。
func ScanIPs(ctx context.Context, hosts []string, probePorts []int, concurrency int, timeout time.Duration, emit Emit) int {
	alive, _ := scanIPsWithMode(ctx, hosts, probePorts, concurrency, timeout, false, emit)
	return alive
}

// ScanIPsStrict 严格存活扫描：只认 ICMP / ARP 应答(端口推断的主机不计入存活)。
func ScanIPsStrict(ctx context.Context, hosts []string, probePorts []int, concurrency int, timeout time.Duration, emit Emit) int {
	alive, _ := scanIPsWithMode(ctx, hosts, probePorts, concurrency, timeout, true, emit)
	return alive
}

// ScanIPsWithDetail 宽松/严格两模式共用入口, 额外返回被严格模式排除的主机数,
// 供调用方向用户解释"为什么只活 X 台"(排除数非 0 时前端会给出提示)。
func ScanIPsWithDetail(ctx context.Context, hosts []string, probePorts []int, concurrency int, timeout time.Duration, strict bool, emit Emit) (alive, excluded int) {
	return scanIPsWithMode(ctx, hosts, probePorts, concurrency, timeout, strict, emit)
}

// scanIPsWithMode 三模式(strict/loose)共用实现 —— c7 起委托统一扫描引擎
// UnifiedScan, 判定口径与事件契约由 unifiedAliveScan 复用 classifyAlive /
// buildIPEvent 保持完全一致。相比旧实现, 端口探测顺带抓取服务 banner, 且开放端口
// 会额外回传 "port" 事件(一次 TCP 连接同时产出存活证据与服务信息, 消除两套扫描
// 重复发包), 前端按既有 port 分支处理、无需改动。
//
// ctx 取消语义: 由 UnifiedScan 统一保证 —— 取消后剩余主机不再入队, 在途拨号经
// DialContext 快速失败, goroutine 全部退出(无泄漏)。
func scanIPsWithMode(ctx context.Context, hosts []string, probePorts []int, concurrency int, timeout time.Duration, strict bool, emit Emit) (int, int) {
	mode := AliveModeLoose
	if strict {
		mode = AliveModeStrict
	}
	alive, excluded, _, _ := UnifiedScan(ctx, hosts, probePorts, mode, concurrency, timeout, emit)
	return alive, excluded
}
