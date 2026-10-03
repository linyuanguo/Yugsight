//go:build linux

package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
)

// collector_linux.go 探针端 AF_PACKET 原始套接字采集器(Linux)。
//
// 为什么需要(2026-09-27): ARP 异常监测(kind=arp)需要在探针本机网卡上抓帧。
// Windows 走 Npcap(collector_windows.go); 探针生产环境多为 Linux 服务器,
// 用纯标准库 AF_PACKET 原始套接字(SOCK_RAW + ETH_P_ALL)抓全量帧,
// 不引入 gopacket/libpcap 第三方依赖(项目硬约束: 纯标准库单二进制)。
//
// 权限要求: CAP_NET_RAW(root 或对应 capability)。打不开时 Start 返回明确
// 错误, 任务按"能力缺失"失败回传(项目规则: 不能静默返回空结果)。
//
// BPF 说明: 原始套接字路径不编译 BPF 表达式(那需要 libpcap), cfg.Filter
// 在本采集器上被忽略, 帧全量透传给 sink, 由调用方(ARP 监测 / 抓包)在用户态
// 自行做协议过滤。副作用: Linux 上"扫描过程抓包"会录全量流量(仍受
// MaxBytes/MaxPackets 上限保护)。
//
// 与 Windows 实现同一套 Collector 接口, 扫描层零感知; 平台差异收敛在本文件。

// ethPAll 捕获所有协议(0x0003, 需网络字节序传给 socket 的 protocol 参数)。
const ethPAll = 0x0003

// afpacketCollector AF_PACKET 采集器。
type afpacketCollector struct {
	mu     sync.Mutex
	fd     int
	cancel context.CancelFunc
	done   chan struct{}
}

// NewAFPacketCollector 构造 AF_PACKET 采集器(Start 时才真正开 socket)。
func NewAFPacketCollector() Collector { return &afpacketCollector{} }

// Name 采集器名称(能力上报用)。
func (c *afpacketCollector) Name() string { return "afpacket" }

// pickIfIndex 选择要抓包的网卡: 指定名直接查; 否则选第一个非回环、非虚口、
// UP 且带 IPv4 地址的网卡(WSL 的 eth0 也符合)。全不符合时退回第一个 UP 的
// 非回环网卡, 再没有才报错。
func pickIfIndex(device string) (int, string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0, "", fmt.Errorf("枚举网卡失败: %w", err)
	}
	if device != "" && device != "local" {
		for _, ifi := range ifs {
			if ifi.Name == device {
				return ifi.Index, ifi.Name, nil
			}
		}
		return 0, "", fmt.Errorf("网卡 %s 不存在", device)
	}
	// 虚口前缀黑名单: 容器/虚拟化接口上的流量不代表真实局域网
	virtualPrefixes := []string{"docker", "veth", "virbr", "lxc", "br-"}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		virtual := false
		for _, p := range virtualPrefixes {
			if strings.HasPrefix(ifi.Name, p) {
				virtual = true
				break
			}
		}
		if virtual {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
				return ifi.Index, ifi.Name, nil
			}
		}
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		return ifi.Index, ifi.Name, nil
	}
	return 0, "", fmt.Errorf("未找到可用网卡")
}

// htons16 主机序 -> 网络序(16 位)。
func htons16(v uint16) uint16 { return (v&0xff) << 8 | (v >> 8) }

// Start 打开原始套接字并开始读包(阻塞直到 ctx 取消或读取持续失败)。
//
// 与 Windows 实现同契约: 调用方应放在独立 goroutine; sink 返回 false 立即停止。
func (c *afpacketCollector) Start(ctx context.Context, cfg CaptureConfig, sink func([]byte) bool) error {
	ifindex, ifname, err := pickIfIndex(cfg.Device)
	if err != nil {
		return err
	}

	// socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)): 该网卡上的全量帧
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons16(ethPAll)))
	if err != nil {
		return fmt.Errorf("打开原始套接字失败(%s): %v —— ARP 监测需要 root 或 CAP_NET_RAW 权限", ifname, err)
	}
	c.mu.Lock()
	c.fd = fd
	c.mu.Unlock()
	defer c.close()

	// 绑定到指定网卡: 用标准库自带的 SockaddrLinklayer(AF_PACKET 的 sockaddr_ll)。
	// 注意 Linux 版该结构无 Family 字段(隐式 AF_PACKET), Ifindex 是 int。
	sa := &syscall.SockaddrLinklayer{
		Ifindex: ifindex,
	}
	if err := syscall.Bind(fd, sa); err != nil {
		return fmt.Errorf("绑定网卡 %s 失败: %v", ifname, err)
	}

	// 300ms 读超时: 让读循环周期性返回以便检查 ctx 取消(与 Windows 300ms 同口径)
	tv := syscall.Timeval{Sec: 0, Usec: 300000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("设置读超时失败: %v", err)
	}

	// ctx 取消时立即关 fd 解除 read 阻塞
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.mu.Lock()
	c.cancel = cancel
	c.done = make(chan struct{})
	done := c.done
	c.mu.Unlock()
	defer close(done)
	go func() {
		<-runCtx.Done()
		c.close() // 幂等: 与 defer 双关, 只求尽快解阻塞
	}()

	buf := make([]byte, 65535)
	var errs int
	for {
		if runCtx.Err() != nil {
			return nil
		}
		// Linux 的 syscall.Read 返回 (n, err) 两个值(Windows 是三个)
		n, rerr := syscall.Read(fd, buf)
		if rerr == syscall.EAGAIN || rerr == syscall.EWOULDBLOCK {
			continue // 读超时: 正常等待
		}
		if rerr != nil {
			// fd 被取消关闭时 read 返回错误属正常路径
			if runCtx.Err() != nil {
				return nil
			}
			errs++
			if errs > 20 {
				return fmt.Errorf("网卡 %s 读取持续失败(接口已移除或驱动异常)", ifname)
			}
			continue
		}
		if n < 14 {
			continue // 残帧: 不足以太网头, 丢弃
		}
		if !sink(buf[:n]) {
			return nil
		}
	}
}

// Stop 停止采集(关闭 fd, 读循环随即退出)。
func (c *afpacketCollector) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// close 关闭套接字(幂等)。
func (c *afpacketCollector) close() {
	c.mu.Lock()
	fd := c.fd
	c.fd = -1
	c.mu.Unlock()
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}

// init 注册 Linux 采集器(包初始化即注入, 与 Windows 同模式)。
//
// 注册后 CaptureSupported()=true, 探针能力上报会带上抓包/ARP 监测能力,
// 中心端可据此调度; 无权限的环境由任务执行时的明确失败兜底。
func init() { SetCollector(NewAFPacketCollector()) }
