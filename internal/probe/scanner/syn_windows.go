//go:build windows

package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"yugsight/internal/scanner"
)

// syn_windows.go SYN 半开扫描的 Windows 实现(原始套接字 FFI)。
//
// 为什么用 FFI 而不是 Go 标准库: Go 在 Windows 上没有暴露 sendto/recvfrom
// (syscall.Sendto/Recvfrom 在 windows 上是返回 EWINDOWS 的桩), 且原始套接字必须
// 自己保证 WSAStartup 已执行。因此这里直连 ws2_32.dll 的最小符号集 ——
// 不引入 cgo、不引入第三方依赖(项目硬约束)。
//
// 收包口径: 原始套接字收到的总是"带 IP 头"的完整报文, 因此判定统一走
// syn.go 的 classifySynReply(先剥 IP 头再取 TCP 标志位)。

const (
	afInet     = 2
	sockRaw    = 3
	ipprotoTCP = 6
	ipprotoIP  = 0
	ipHdrIncl  = 2

	solSocket  = 0xFFFF
	soRcvTimeo = 0x1006

	// Winsock 错误码(WSAGetLastError 返回值, 与 errno 不同源)
	wsaEACCES     = 10013 // 权限不足: 非管理员或被系统策略禁止
	wsaETIMEDOUT  = 10060 // SO_RCVTIMEO 超时
	wsaEWOULDBLOCK = 10035

	// tokenElevation / TOKEN_QUERY: 判断进程是否已提升(管理员)
	tokenQuery     = 0x0400
	tokenElevation = 2
)

var (
	ws2          = syscall.NewLazyDLL("ws2_32.dll")
	pWSAStartup  = ws2.NewProc("WSAStartup")
	pSocket      = ws2.NewProc("socket")
	pSendto      = ws2.NewProc("sendto")
	pRecvfrom    = ws2.NewProc("recvfrom")
	pClosesocket = ws2.NewProc("closesocket")
	pSetsockopt  = ws2.NewProc("setsockopt")
	pGetLastErr  = ws2.NewProc("WSAGetLastError")

	advapi32       = syscall.NewLazyDLL("advapi32.dll")
	pOpenProcToken = advapi32.NewProc("OpenProcessToken")
	pGetTokenInfo  = advapi32.NewProc("GetTokenInformation")
	kernel32dll    = syscall.NewLazyDLL("kernel32.dll")
	pCloseHandle   = kernel32dll.NewProc("CloseHandle")

	wsaOnce   sync.Once
	wsaInitErr error
	adminOnce sync.Once
	adminOK   bool
)

// wsockInit Winsock 初始化(必须自己做: raw socket 路径不经过 net 包)。
func wsockInit() error {
	wsaOnce.Do(func() {
		var data [512]byte
		for _, p := range []*syscall.LazyProc{pWSAStartup, pSocket, pSendto, pRecvfrom, pClosesocket, pSetsockopt, pGetLastErr} {
			if err := p.Find(); err != nil {
				wsaInitErr = fmt.Errorf("ws2_32.dll 符号缺失: %w", err)
				return
			}
		}
		if r, _, _ := pWSAStartup.Call(0x0202, uintptr(unsafe.Pointer(&data[0]))); r != 0 {
			wsaInitErr = fmt.Errorf("WSAStartup 失败: %d", r)
		}
	})
	return wsaInitErr
}

// wsaErrno 取上一次 Winsock 错误码。
func wsaErrno() int {
	c, _, _ := pGetLastErr.Call()
	return int(c)
}

// hasAdminPrivilege 进程是否已提升(管理员)。
//
// 与根包 elevate_windows.go 的 isAdmin 同手法(GetTokenInformation + TokenElevation),
// 探针端不能引用 main 包, 因此在此独立实现一份。
func hasAdminPrivilege() bool {
	adminOnce.Do(func() {
		var token uintptr
		if r, _, _ := pOpenProcToken.Call(^uintptr(0), tokenQuery, uintptr(unsafe.Pointer(&token))); r == 0 {
			return
		}
		defer pCloseHandle.Call(token)
		var elevated uint32
		var returned uintptr
		r, _, _ := pGetTokenInfo.Call(token, tokenElevation,
			uintptr(unsafe.Pointer(&elevated)), 4, uintptr(unsafe.Pointer(&returned)))
		adminOK = r != 0 && elevated != 0
	})
	return adminOK
}

// synPlatformSupported Windows 下需管理员权限才能建原始套接字。
func synPlatformSupported() bool {
	if err := wsockInit(); err != nil {
		return false
	}
	return hasAdminPrivilege()
}

// synScanPorts SYN 半开扫描: 每端口发一个 SYN, 按回包判 open/closed/filtered。
//
// 返回 error 时调用方应降级为全连接扫描(不视为任务失败)。
// ctx 取消时立即返回(已收到的判定不丢)。
func synScanPorts(ctx context.Context, host string, ports []int, timeout time.Duration) ([]scanner.PortResult, error) {
	if len(ports) == 0 {
		return nil, nil
	}
	if !synPlatformSupported() {
		return nil, errSynUnsupported
	}
	dstIP, err := resolveIPv4(host)
	if err != nil {
		return nil, err
	}
	srcIP, err := localIPv4For(dstIP)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}

	fd, err := openRawSocket()
	if err != nil {
		return nil, err
	}
	defer closesocketFn(fd)
	setRecvTimeout(fd, timeout)
	// IP_HDRINCL 可能被拒(Windows 对"自带 IP 头的 TCP 报文"有限制), 失败即改由内核填头
	hdrIncl := setHdrIncl(fd)

	// ---- 发送 ----
	seqBase := uint32(time.Now().UnixNano())
	portOf := make(map[uint16]int, len(ports))
	sentAt := make(map[uint16]time.Time, len(ports))
	for i, p := range ports {
		if ctx.Err() != nil {
			break
		}
		if p < 1 || p > 65535 {
			continue
		}
		sp := synSrcPort(i)
		pkt, err := buildSynPacket(srcIP, dstIP, sp, uint16(p), seqBase+uint32(i), hdrIncl)
		if err != nil {
			return nil, err
		}
		sendErr := sendtoFn(fd, pkt, dstIP, p)
		if sendErr != nil && hdrIncl {
			// 自带 IP 头被拒: 退回"内核填 IP 头"模式重试一次
			hdrIncl = false
			if pkt2, err2 := buildSynPacket(srcIP, dstIP, sp, uint16(p), seqBase+uint32(i), false); err2 == nil {
				sendErr = sendtoFn(fd, pkt2, dstIP, p)
			}
		}
		if sendErr != nil {
			// 发送被拒 = 本机不具备 SYN 能力(权限/策略), 交回上层降级
			return nil, fmt.Errorf("SYN 发送被拒(%v)", sendErr)
		}
		portOf[sp] = p
		sentAt[sp] = time.Now()
	}
	if len(portOf) == 0 {
		return nil, errSynUnsupported
	}

	// ---- 收包 ----
	states := make(map[uint16]string, len(portOf))
	latency := make(map[uint16]int64, len(portOf))
	buf := make([]byte, 65535)
	replies := 0
	for len(states) < len(portOf) {
		if ctx.Err() != nil {
			break
		}
		n, err := recvfromFn(fd, buf)
		if err != nil {
			if errors.Is(err, errSynTimeout) {
				break // 等待窗口内没有更多回包
			}
			continue // 其它错误: 再等下一次(可能是无关的 ICMP 或缓冲区问题)
		}
		replies++
		sp, state, matched := classifySynReply(dstIP, buf[:n])
		if !matched {
			continue
		}
		if _, ok := portOf[sp]; !ok {
			continue // 不是本次探测的源端口
		}
		if _, dup := states[sp]; dup {
			continue // 首个回包为准(重传/重复应答不改变结论)
		}
		states[sp] = state
		if at, ok := sentAt[sp]; ok {
			latency[sp] = time.Since(at).Milliseconds()
		}
	}
	if replies == 0 {
		// 一个回包都没有: Windows 上典型是内核 TCP 栈抢答/策略拦截,
		// 此时"全 filtered"是假结论, 必须降级(宁可慢, 不能扫了等于没扫)。
		return nil, errSynNoReply
	}

	out := make([]scanner.PortResult, 0, len(ports))
	for i, p := range ports {
		sp := synSrcPort(i)
		state, ok := states[sp]
		if !ok {
			state = synStateFiltered
		}
		r := scanner.PortResult{IP: host, Port: p, State: state}
		if state == synStateOpen {
			r.Service = scanner.ServiceName(p)
			r.LatencyMs = latency[sp]
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

// ===== 原始套接字 FFI =====

func openRawSocket() (uintptr, error) {
	if err := wsockInit(); err != nil {
		return 0, err
	}
	r, _, _ := pSocket.Call(afInet, sockRaw, ipprotoTCP)
	if int(int32(r)) == -1 {
		code := wsaErrno()
		if code == wsaEACCES {
			return 0, errSynUnsupported
		}
		return 0, fmt.Errorf("创建原始套接字失败(WSA %d)", code)
	}
	return r, nil
}

func closesocketFn(fd uintptr) { pClosesocket.Call(fd) }

// setHdrIncl 开启 IP_HDRINCL(报文自带 IP 头); 返回是否设置成功。
func setHdrIncl(fd uintptr) bool {
	v := int32(1)
	r, _, _ := pSetsockopt.Call(fd, ipprotoIP, ipHdrIncl, uintptr(unsafe.Pointer(&v)), 4)
	return r == 0
}

// setRecvTimeout 设置接收超时(Windows 的 SO_RCVTIMEO 参数是毫秒 DWORD, 不是 timeval)。
func setRecvTimeout(fd uintptr, d time.Duration) {
	ms := int(d / time.Millisecond)
	if ms < 1 {
		ms = 1
	}
	if ms > 60000 {
		ms = 60000
	}
	v := int32(ms)
	pSetsockopt.Call(fd, solSocket, soRcvTimeo, uintptr(unsafe.Pointer(&v)), 4)
}

// sendtoFn 发送一个报文到 dst:port(sockaddr_in 手工构造, 网络序)。
func sendtoFn(fd uintptr, pkt []byte, dst netip.Addr, port int) error {
	if len(pkt) == 0 {
		return errors.New("空报文")
	}
	var sa [16]byte
	binary.BigEndian.PutUint16(sa[0:2], afInet)
	binary.BigEndian.PutUint16(sa[2:4], uint16(port))
	copy(sa[4:8], dst.AsSlice())
	r, _, _ := pSendto.Call(fd,
		uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), 0,
		uintptr(unsafe.Pointer(&sa[0])), 16)
	if int(int32(r)) == -1 {
		return fmt.Errorf("WSA %d", wsaErrno())
	}
	return nil
}

// recvfromFn 收一个报文; 超时返回 errSynTimeout(调用方据此结束等待)。
func recvfromFn(fd uintptr, buf []byte) (int, error) {
	var from [16]byte
	fromLen := int32(len(from))
	r, _, _ := pRecvfrom.Call(fd,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0,
		uintptr(unsafe.Pointer(&from[0])), uintptr(unsafe.Pointer(&fromLen)))
	if int(int32(r)) == -1 {
		if code := wsaErrno(); code == wsaETIMEDOUT || code == wsaEWOULDBLOCK {
			return 0, errSynTimeout
		}
		return 0, fmt.Errorf("recvfrom 失败(WSA %d)", wsaErrno())
	}
	return int(r), nil
}

// ===== 地址解析 / 本机源 IP =====

func resolveIPv4(host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil && a.Is4() {
		return a, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("目标解析失败: %w", err)
	}
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok && a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("目标不是 IPv4: %s", host)
}

// localIPv4For 取出网到 dst 时使用的本机 IPv4(伪首部校验和需要真实源 IP)。
//
// UDP connect 不发任何报文, 只让内核做一次路由选择, 因此"无网络"也能拿到接口地址;
// 拿不到就没法算 TCP 校验和, 直接降级(算错校验和的包目标一律丢弃, 结果必然全 filtered)。
func localIPv4For(dst netip.Addr) (netip.Addr, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(dst.String(), "80"), 300*time.Millisecond)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("无法确定本机源 IP: %w", err)
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("本机源 IP 解析失败: %w", err)
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !a.Is4() {
		return netip.Addr{}, fmt.Errorf("本机源 IP 非 IPv4: %s", host)
	}
	return a, nil
}
