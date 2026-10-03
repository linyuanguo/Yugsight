package scanner

// 路由跟踪(2026-09-30 用户要求: 连通性测试加 tracert/端口跟踪, ping 与端口两种)。
//
// 平台实测结论(2026-09-30, Windows 管理员环境, 与系统 tracert 逐跳对照一致):
//   - raw ip4:1(ICMP) 套接字 + IP_TTL 逐跳控制可用 → ICMP(ping) 模式完整逐跳跟踪;
//   - Windows 不允许 ip4:6/ip4:0 原始套接字(WSAEACCES), 且内核不将 UDP 探测包引发的
//     ICMP 错误报文投递到原始套接字(实测局域网网关也收不到) → tcptraceroute 式
//     "逐跳走端口"在 Windows 不可行。端口模式采用两段组合:
//     a) ICMP 跟踪拿逐跳 IP(同一目的地的路由与协议无关, 同一条路);
//     b) 普通 TCP 连接 + IP_TTL 逐跳探测, 找目标端口响应的最小 TTL
//     (SYN-ACK=端口开放 / RST=端口关闭), 即"经 N 跳可达该端口"。
//   - Linux/macOS 同一实现(原始 ICMP 需 root/admin, 与存活探测同权限口径)。
//
// 读回帧格式跨平台不一致(Windows 无外层 IP 头, Linux 带完整 IP 包)→ 两种都处理(stripIPHeader)。

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// TraceHop 路由中的一跳。
type TraceHop struct {
	Hop int    `json:"hop"`
	IP  string `json:"ip"`    // 空 = 该跳超时(*)
	RTT int64  `json:"rttMs"` // -1 = 超时
}

// TraceResult 路由跟踪结果。
type TraceResult struct {
	Target     string     `json:"target"`
	Resolved   string     `json:"resolved"`
	Port       int        `json:"port"`        // 0 = ICMP(ping) 模式
	Reached    bool       `json:"reached"`
	PortState  string     `json:"portState"`   // 端口模式: open/closed/timeout; ICMP 模式为空
	HopsNeeded int        `json:"hopsNeeded"`  // 目标端口响应的最小 TTL(端口模式; 0=不可达)
	Note       string     `json:"note"`        // 补充说明
	Hops       []TraceHop `json:"hops"`
	ElapsedMs  int64      `json:"elapsedMs"`
}

// matchHopPacket 判定读回的 ICMP(已剥外层 IP 头)是否属于本次跟踪:
// "reply" = echo 应答(目标到达); "hop" = time exceeded(中间跳); "" = 无关
// (raw 套接字收到本机所有 ICMP, 必须按 id/seq 过滤, 否则别的进程的 ping 应答会混进结果)。
// time exceeded 内嵌 = 原 IP 头(20 字节) + 原数据报前 8 字节(我们的 echo 头: id 在 4-5, seq 在 6-7)。
func matchHopPacket(data []byte, id, seq uint16) string {
	if len(data) < 8 {
		return ""
	}
	switch data[0] {
	case 0: // echo reply
		if binary.BigEndian.Uint16(data[4:6]) == id {
			return "reply"
		}
	case 11: // time exceeded
		if len(data) >= 8+20+8 {
			rid := binary.BigEndian.Uint16(data[8+20+4 : 8+20+6])
			rseq := binary.BigEndian.Uint16(data[8+20+6 : 8+20+8])
			if rid == id && rseq == seq {
				return "hop"
			}
		}
	}
	return ""
}

// stripIPHeader 读回若带外层 IP 头(Linux)则剥掉; Windows 只回 payload, 原样返回。
func stripIPHeader(buf []byte) []byte {
	if len(buf) > 0 && buf[0]&0xf0 == 0x40 {
		iph := int(buf[0]&0x0f) * 4
		if len(buf) > iph {
			return buf[iph:]
		}
	}
	return buf
}

// sysconner 取原始 fd 所需的最小接口(Go 1.25 的 net 连接类型均为带 SyscallConn 的指针结构体)。
type sysconner interface{ SyscallConn() (syscall.RawConn, error) }

// setConnTTL 对任意 net 套接字(原始 ICMP / 普通 TCP 等)设置 IP_TTL。
func setConnTTL(c any, ttl int) error {
	sc, ok := c.(sysconner)
	if !ok {
		return fmt.Errorf("套接字类型不支持 SyscallConn: %T", c)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = setIPTTL(fd, ttl)
	}); err != nil {
		return err
	}
	return serr
}

// TraceRoute 执行路由跟踪。port=0 为 ICMP(ping) 模式; port>0 为端口模式(ICMP 逐跳 + TCP 端口探测)。
// 仅在能力缺失(原始套接字不可用=未提权)时返回 error; 探测"不可达"属于结果而非错误。
func TraceRoute(target string, port int, maxHops int, perHop time.Duration) (*TraceResult, error) {
	if maxHops < 1 {
		maxHops = 15
	}
	if maxHops > 30 {
		maxHops = 30
	}
	if perHop <= 0 {
		perHop = time.Second
	}
	if perHop > 3*time.Second {
		perHop = 3 * time.Second
	}

	dest, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return nil, fmt.Errorf("目标解析失败: %w", err)
	}
	resolved := dest.IP.String()

	pc, err := net.ListenPacket("ip4:1", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("路由跟踪需提权进程(原始 ICMP 套接字不可用): %w", err)
	}
	defer func() { _ = pc.Close() }()

	// 读协程: 收全部 ICMP, 剥外层头, 投通道。deadline 超时只是"本窗口没包", 不能退出
	// (套接字未关闭, 后续跳还有响应); 真正退出只发生在套接字被关闭时。
	type rawPkt struct {
		from string // 源 IP(ReadFrom 返回的地址, 字符串即可, 避免断言失败 nil 风险)
		data []byte
		t    time.Time
	}
	pkts := make(chan rawPkt, 64)
	go func() {
		buf := make([]byte, 1500)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, from, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			data := stripIPHeader(buf[:n])
			if len(data) == 0 {
				continue
			}
			cp := make([]byte, len(data))
			copy(cp, data)
			select {
			case pkts <- rawPkt{from: from.String(), data: cp, t: time.Now()}:
			default: // 通道满(极端情况)丢弃, 不阻塞读循环
			}
		}
	}()

	// 本次跟踪的 echo id(按 PID 错开, 降低与系统 ping 等他人流量的碰撞概率)
	id := uint16(os.Getpid()&0xffff) ^ 0x7A3B
	startAll := time.Now()
	hops := make([]TraceHop, 0, maxHops)
	reached := false
	reachedAt := 0
	consecTimeout := 0

	for ttl := 1; ttl <= maxHops; ttl++ {
		if err := setConnTTL(pc, ttl); err != nil {
			return nil, fmt.Errorf("设置 TTL 失败: %w", err)
		}
		pkt := make([]byte, 8+16)
		pkt[0] = 8 // echo request
		binary.BigEndian.PutUint16(pkt[4:], id)
		binary.BigEndian.PutUint16(pkt[6:], uint16(ttl))
		for i := 8; i < len(pkt); i++ {
			pkt[i] = byte(i)
		}
		binary.BigEndian.PutUint16(pkt[2:], icmpChecksum(pkt))
		_ = pc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := pc.WriteTo(pkt, dest); err != nil {
			hops = append(hops, TraceHop{Hop: ttl, RTT: -1})
			consecTimeout++
			if consecTimeout >= 3 {
				break // 连续 3 跳全超时 = 链路已无进展, 不必继续
			}
			continue
		}

		sendAt := time.Now()
		deadline := sendAt.Add(perHop)
		var hopKind, hopIP string
		var hopRTT int64 = -1
		for time.Now().Before(deadline) {
			select {
			case p := <-pkts:
				if hopKind == "" {
					if k := matchHopPacket(p.data, id, uint16(ttl)); k != "" {
						hopKind = k
						hopIP = p.from
						hopRTT = p.t.Sub(sendAt).Milliseconds()
					}
				}
			case <-time.After(time.Until(deadline)):
			}
			if hopKind != "" {
				break
			}
		}

		if hopKind != "" {
			hops = append(hops, TraceHop{Hop: ttl, IP: hopIP, RTT: hopRTT})
			consecTimeout = 0
			if hopKind == "reply" {
				reached = true
				reachedAt = ttl
				break
			}
		} else {
			hops = append(hops, TraceHop{Hop: ttl, RTT: -1})
			consecTimeout++
			if consecTimeout >= 3 {
				break
			}
		}
	}

	res := &TraceResult{
		Target: target, Resolved: resolved, Port: port,
		Reached: reached, Hops: hops,
	}

	if port > 0 {
		if reached {
			// 逐跳列表已证明路由可达: 直接连目标端口确认开放/关闭(不限 TTL 的普通连接)
			res.PortState = tcpPortState(resolved, port, perHop)
			res.HopsNeeded = reachedAt
		} else {
			// ICMP 未到达(目标或中间设备可能过滤 ICMP) → 端口探测兜底:
			// 普通 TCP 连接 + IP_TTL 逐跳, 找目标端口响应的最小 TTL
			h, st := tcpTTLProbe(resolved, port, maxHops, 500*time.Millisecond)
			res.HopsNeeded = h
			res.PortState = st
			if h > 0 {
				res.Reached = true
				res.Note = "目标未回应 ICMP(可能被过滤), 逐跳列表来自 ICMP(可能不完整); 端口经 " + strconv.Itoa(h) + " 跳可达"
			} else {
				res.Note = "ICMP 与端口探测均不可达"
			}
		}
	}
	// 2026-10-01: 耗时在端口探测之后再结算 —— 此前在探测前就取 time.Since,
	// 页面显示的耗时只含 ICMP 逐跳部分, 漏掉 TCP 探测的几秒(与用户感知的等待对不上)。
	res.ElapsedMs = time.Since(startAll).Milliseconds()
	return res, nil
}

// tcpPortState 普通 TCP 连接检查目标端口(open/closed/timeout)。
func tcpPortState(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err == nil {
		_ = conn.Close()
		return "open"
	}
	if isRefused(err) {
		return "closed"
	}
	return "timeout"
}

// tcpTTLProbe 以 IP_TTL=1..maxHops 逐跳发 TCP 连接, 找目标端口响应的最小 TTL。
// SYN-ACK(连接成功)=端口开放; RST(连接被拒)=端口关闭但目标已到达; 超时=包死在中间, 下一跳。
// Dialer.Control 在 socket 创建后、connect 前执行, 是设置 IP_TTL 的正确时机。
func tcpTTLProbe(ip string, port int, maxHops int, dialTimeout time.Duration) (int, string) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	for ttl := 1; ttl <= maxHops; ttl++ {
		ttl := ttl
		d := &net.Dialer{Timeout: dialTimeout}
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = setIPTTL(fd, ttl)
			}); err != nil {
				return err
			}
			return serr
		}
		conn, err := d.Dial("tcp4", addr)
		if err == nil {
			_ = conn.Close()
			return ttl, "open"
		}
		if isRefused(err) {
			return ttl, "closed"
		}
	}
	return 0, "timeout"
}

// isRefused "连接被拒"(收到 RST)。措辞跨平台不同:
// Windows 是 "actively refused it", Linux 是 "connection refused", 统一按 refused 子串判。
func isRefused(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "refused")
}
