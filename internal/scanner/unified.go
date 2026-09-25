package scanner

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// AliveMode 存活判定模式(统一扫描专用)。
//
// 与旧"存活扫描"的 strict/loose 两态相比, 这里把"端口开放"的定位讲清楚, 并新增
// none —— "跳过存活判定、只做端口扫描", 让"我要端口清单"与"我要知道谁在线"不再是
// 两个割裂的入口, 而是同一套探测下的不同口径(端口只拨号一次, 两种结论共用这一次连接)。
type AliveMode string

const (
	// AliveModeStrict 仅 ARP + ICMP 应答判定存活; TCP 端口开放只作为附加信息,
	// 不参与存活判定(只开 445 的主机对 80 探测无应答时, 仍算"不存活")。
	AliveModeStrict AliveMode = "strict"
	// AliveModeLoose ARP/ICMP 优先; 两者都无应答时, 只要有探测端口开放即判定存活
	// (标注为"端口推断"), 避免"只开 445 的在线主机被报成不存活"导致整段网段全灭。
	AliveModeLoose AliveMode = "loose"
	// AliveModeNone 跳过存活判定, 直接执行端口扫描(输出开放端口 + 服务/banner)。
	AliveModeNone AliveMode = "none"
)

// ParseAliveMode 解析存活模式字符串。
//
// 空值与未知值一律归一到"宽松"—— 这是旧存活扫描的默认口径, 保证既有
// /api/scan(aliveMode 缺省)行为零变化; 只有显式 "strict"/"none" 才走新分支。
func ParseAliveMode(s string) AliveMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict", "严格":
		return AliveModeStrict
	case "none", "off", "跳过", "端口":
		return AliveModeNone
	default: // 空值 / "loose" / "宽松" / 未知 -> 宽松(与旧默认一致)
		return AliveModeLoose
	}
}

// hostUnifiedResult 单主机统一探测结果(ICMP/ARP 证据 + 全部端口明细)。
type hostUnifiedResult struct {
	icmp        bool
	arp         bool
	rtt         int64
	mac         string
	portDetails []PortResult
}

// probeHostUnified 对单主机并发执行 ICMP + ARP(可选) + TCP 端口探测(带 banner),
// 一次探测同时拿到"存活证据"与"开放端口明细" —— 这是 c7 消除重复发包的核心:
// 端口只拨号一次, 存活判定与服务识别共用这一次连接。
//
// doAlive=false 时跳过 ICMP/ARP(none 模式的单主机形态), 只探端口。
func probeHostUnified(ctx context.Context, ip string, ports []int, timeout time.Duration, seq uint16, icmpAvail, arpAvail, doAlive bool) hostUnifiedResult {
	var (
		mu  sync.Mutex
		res hostUnifiedResult
	)
	var wg sync.WaitGroup
	if doAlive && icmpAvail {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, rtt, _ := PingICMP(ip, seq, timeout); ok {
				mu.Lock()
				res.icmp, res.rtt = true, rtt
				mu.Unlock()
			}
		}()
	}
	if doAlive && arpAvail {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// ArpProbeOne 在非 Windows 或接口缺失时返回错误, 直接忽略(能力缺失 ≠ 目标离线)
			if mac, err := ArpProbeOne(ip, uint32(timeout.Milliseconds())); err == nil && mac != "" {
				mu.Lock()
				res.arp, res.mac = true, mac
				mu.Unlock()
			}
		}()
	}
	d := net.Dialer{Timeout: timeout}
	for _, p := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			r := probeOnePort(ctx, d, ip, p, timeout)
			mu.Lock()
			res.portDetails = append(res.portDetails, r)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(res.portDetails, func(i, j int) bool { return res.portDetails[i].Port < res.portDetails[j].Port })
	return res
}

// UnifiedScan 统一扫描入口: 一次探测同时输出"主机存活状态 + 开放端口(含服务/banner)"。
//
// 三种模式严格遵守约定(见 AliveMode):
//   - strict: 仅 ICMP/ARP 判存活, 端口为附加信息;
//   - loose:  ICMP/ARP 优先, 无应答时端口开放判存活;
//   - none:   跳过存活判定, 直接多主机端口扫描。
//
// "主机存活列表 + 每个主机的开放端口列表"经事件流逐条回传(每台主机一条 "ip" 事件,
// 每个端口一条 "port" 事件), 供 SSE 消费方边扫边收; 返回值是聚合统计与耗时:
//
//	alive     计入存活的主机数(none 模式恒 0)
//	excluded  被严格模式排除的主机数(仅端口开放、无 ICMP/ARP 应答)
//	openPorts 开放端口总数
//	elapsed   本次扫描总耗时(毫秒级取整)
//
// 事件口径(与旧扫描完全兼容, 前端 renderEvent 无需改动):
//   - 每台主机回传一条 "ip" 事件(存活证据 + 开放端口号);
//   - strict/loose 下每个开放端口一条 "port" 事件(服务名 + banner + 时延);
//   - none 下开放与关闭端口都回传 "port" 事件 —— 与旧 ScanPorts 逐端口上报口径
//     一致(关闭端口计入统计、不上展示), ScanPorts 的兼容委托依赖这一点。
//
// ctx 取消语义: 排队等槽位时监听 ctx.Done, 取消后剩余目标不再入队, 在途拨号经
// DialContext 快速失败, 无 goroutine 泄漏。
func UnifiedScan(ctx context.Context, hosts []string, ports []int, mode AliveMode, concurrency int, timeout time.Duration, emit Emit) (alive, excluded, openPorts int, elapsed time.Duration) {
	start := time.Now()
	defer func() { elapsed = time.Since(start).Round(time.Millisecond) }()
	if emit == nil {
		emit = func(string, any) {}
	}
	if len(hosts) == 0 || len(ports) == 0 {
		return 0, 0, 0, 0
	}
	if concurrency <= 0 {
		concurrency = 100
	}
	switch mode {
	case AliveModeNone:
		openPorts = unifiedPortScan(ctx, hosts, ports, concurrency, timeout, emit)
	default:
		alive, excluded, openPorts = unifiedAliveScan(ctx, hosts, ports, mode == AliveModeStrict, concurrency, timeout, emit)
	}
	// elapsed 由 defer 统一按真实耗时填充
	return alive, excluded, openPorts, 0
}

// unifiedAliveScan strict/loose 共用的存活 + 端口统一探测。
//
// 判定口径完全复用既有 classifyAlive / buildIPEvent(与旧"存活扫描"一致, 不改变业务
// 语义), 唯一增量是: 端口只拨号一次且顺带抓 banner, 开放端口额外回传 "port" 事件。
func unifiedAliveScan(ctx context.Context, hosts []string, ports []int, strict bool, concurrency int, timeout time.Duration, emit Emit) (alive, excluded, openPorts int) {
	icmpAvail := InitICMP()
	if !icmpAvail {
		emit("status", map[string]any{"msg": "ICMP 不可用(需管理员), TCP/ARP 仍可用"})
	}
	arpAvail := ArpHardwareAvailable()
	if !arpAvail && runtime.GOOS == "windows" {
		emit("status", map[string]any{"msg": "ARP 不可用(系统接口缺失), 仅用 ICMP+TCP"})
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	// macsByHost 收集所有收到 ARP 应答的主机 -> MAC, 扫描结束后做"同 MAC 聚集"
	// 检测(见 buildMACWarnings)—— 代理 ARP 假存活的自动识别就靠它。
	macsByHost := map[string]string{}
	for i, h := range hosts {
		wg.Add(1)
		go func(idx int, h string) {
			defer wg.Done()
			// 排队等并发槽位时监听 ctx: 取消则剩余主机不再入队, 直接退出, 防止 goroutine 堆积
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			res := probeHostUnified(ctx, h, ports, timeout, uint16(idx), icmpAvail, arpAvail, true)
			// 虚拟 MAC(01:00:5E)的 ARP 应答是网段内某台设备代答(代理 ARP), 应答方
			// 不是目标主机: 不能作为存活证据, MAC 也不展示(这类"存活"是假阳性)
			res.arp, res.mac = dropVirtualARP(res.arp, res.mac)
			var open []int
			for _, pd := range res.portDetails {
				if pd.State == "open" {
					open = append(open, pd.Port)
				}
			}
			hasOpen := len(open) > 0
			if !res.icmp && !res.arp && !hasOpen {
				emit("ip", map[string]any{"ip": h, "alive": false, "ports": []int{}, "icmp": false, "arp": false, "rttMs": int64(0)})
				return
			}
			// 判定口径与旧"存活扫描"完全一致(strict/loose), 不改变业务语义
			counted, excludedByStrict, inferred := classifyAlive(strict, res.icmp, res.arp)
			mu.Lock()
			if counted {
				alive++
			}
			if excludedByStrict {
				excluded++
			}
			openPorts += len(open)
			if res.mac != "" {
				macsByHost[h] = res.mac
			}
			mu.Unlock()
			// "ip" 事件: 存活证据 + 开放端口号(前端 ip 分支直接渲染)
			emit("ip", buildIPEvent(h, hostProbeResult{alive: true, icmp: res.icmp, arp: res.arp, rtt: res.rtt, mac: res.mac, ports: open}, inferred, excludedByStrict))
			// "port" 事件: 开放端口的服务/banner 明细(统一扫描相对存活扫描的增量信息)
			for _, pd := range res.portDetails {
				if pd.State == "open" {
					emit("port", pd)
				}
			}
		}(i, h)
	}
	wg.Wait()
	// 代理 ARP 假存活自动识别: 多台主机回同一(真实) MAC 时提示一行, 让用户知道
	// "这些 IP 可能并不存在, 是设备代答"。
	// 虚拟 MAC(01:00:5E)组不提示 —— 那类应答在探测阶段已按"目标主机不存在"处理
	// (证据失效, 见 dropVirtualARP), 无需再解释。
	for _, msg := range buildMACWarnings(macsByHost) {
		emit("status", map[string]any{"msg": msg})
	}
	return alive, excluded, openPorts
}

// isVirtualMAC 判断 IANA 保留虚拟 MAC(01:00:5E 前缀, VRRP 等虚拟协议专用, 真实
// 网卡不会使用)。整段 IP 都以这类 MAC 应答 ARP, 说明是某台设备(通常是网关/路由
// 器)在代理代答, 应答方不是目标主机。
func isVirtualMAC(mac string) bool {
	return strings.HasPrefix(strings.ToLower(mac), "01:00:5e")
}

// dropVirtualARP 失效虚拟 MAC 的 ARP 证据: 应答方是代答设备而非目标主机, 既不能
// 计入存活, MAC 也不展示。真实 MAC / 无应答原样透传。
func dropVirtualARP(arp bool, mac string) (bool, string) {
	if arp && isVirtualMAC(mac) {
		return false, ""
	}
	return arp, mac
}

// buildMACWarnings 把"收到 ARP 应答的 主机->MAC"分组, 找出 2 台及以上共用同一
// 真实 MAC 的组, 生成一行简短提示(纯逻辑, 不碰网络, 可单测)。
//
// 为什么 2 台就提示: 两台不同 IP 共用同一 MAC, 要么是单台多 IP 主机, 要么是整段
// 代答(假存活), 提示里并列两种可能, 不武断下结论。
//
// 虚拟 MAC(01:00:5E)组跳过: 探测阶段已失效其证据(见 dropVirtualARP), 正常不会
// 出现在 macsByHost 里; 此处兜底, 即使出现也不刷屏。
func buildMACWarnings(macsByHost map[string]string) []string {
	if len(macsByHost) < 2 {
		return nil
	}
	groups := map[string][]string{}
	for ip, mac := range macsByHost {
		groups[mac] = append(groups[mac], ip)
	}
	var out []string
	for mac, ips := range groups {
		if len(ips) < 2 || isVirtualMAC(mac) {
			continue
		}
		sort.Strings(ips)
		out = append(out, fmt.Sprintf("提示: %d 台主机以同一 MAC %s 应答 ARP(单台多 IP 主机或代理 ARP 代答, 可 arp -a 复核)。涉及: %s",
			len(ips), mac, joinIPsLimited(ips, 10)))
	}
	sort.Strings(out)
	return out
}

// joinIPsLimited 最多列 n 个, 超出部分折叠成"…另有 k 个", 防止大网段下提示行爆炸。
func joinIPsLimited(ips []string, n int) string {
	if len(ips) <= n {
		return strings.Join(ips, ", ")
	}
	return strings.Join(ips[:n], ", ") + fmt.Sprintf(", …另有 %d 个", len(ips)-n)
}

// unifiedPortScan none 模式: 跳过存活判定, 多主机端口扫描。
//
// 扁平并发池(跨主机共享并发上限): 把 host × port 展开成一组探测任务统一排队,
// 而不是"逐主机串行、机内并发" —— 大网段下后者会慢一个数量级。
//
// 端口事件 = 开放 + 关闭都回传, 与旧 ScanPorts 的逐端口上报口径完全一致
// (前端只展示开放端口, 关闭端口计入统计) —— ScanPorts 的兼容委托从这里收集
// 全量结果, 若只回传开放端口, 调用方拿到的结果集会静默缩水。
func unifiedPortScan(ctx context.Context, hosts []string, ports []int, concurrency int, timeout time.Duration, emit Emit) (openPorts int) {
	d := net.Dialer{Timeout: timeout}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, h := range hosts {
		for _, p := range ports {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()
				select {
				case <-ctx.Done():
					return
				case sem <- struct{}{}:
				}
				defer func() { <-sem }()
				r := probeOnePort(ctx, d, h, p, timeout)
				if r.State == "open" {
					mu.Lock()
					openPorts++
					mu.Unlock()
				}
				emit("port", r)
			}(h, p)
		}
	}
	wg.Wait()
	return openPorts
}
