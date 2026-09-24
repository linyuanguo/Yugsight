//go:build windows

package scanner

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"
)

// arpprobe_windows.go Windows ARP 存活探测(Link Layer 层, 与 ICMP/TCP 互补)。
//
// 为什么需要 ARP 探测:
//
//	ICMP 常被防火墙丢弃, TCP 探测只覆盖开放端口的机器; 而同一广播域内 ARP
//	几乎不可能被过滤(交换机转发依赖它), 因此对"本网段存活主机发现"ARP 是最可靠的手段。
//
// 实现方式: 调用 iphlpapi.dll 的 SendARP —— 由系统代发 ARP 请求并同步等待应答,
// 返回目标 MAC。相比自己用原始套接字拼 ARP 帧:
//   - 不需要管理员权限(项目内 ICMP 需要管理员, ARP 不需要, 这是它的额外价值);
//   - 不引入 cgo / 第三方依赖(纯 syscall, 与 pcap_windows.go 同风格);
//   - 由系统处理重试与时序, 稳定性更好。
//
// 已知限制: SendARP 只在"目标与本机同一广播域(同网段)"时可能成功;
// 跨网段会失败(返回 ERROR_GEN_FAILURE 或超时), 属于预期行为 —— 上层按"无应答"处理。

// ErrArpUnsupported ARP 探测在当前平台不可用(见 arpprobe_other.go)。
var ErrArpUnsupported = errors.New("ARP 探测仅支持 Windows")

var (
	arpOnce    sync.Once
	arpSend    *syscall.Proc
	arpOK      bool
	arpLoadErr error
)

// initArp 懒加载 iphlpapi.dll 的 SendARP(失败只记状态, 不 panic)。
//
// 原型(DWORD = uint32):
//
//	DWORD SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen);
//
//	- DestIP 网络字节序的目标 IPv4;
//	- SrcIP  0 表示由系统选择源地址;
//	- pMacAddr 接收 6 字节 MAC;
//	- PhyAddrLen 入参为缓冲长度, 出参为实际长度;
//	- 返回值 0 = 成功(NO_ERROR), 非 0 = 失败(ERROR_GEN_FAILURE/ERROR_BAD_NET_NAME 等)。
func initArp() bool {
	arpOnce.Do(func() {
		dll, err := syscall.LoadDLL("iphlpapi.dll")
		if err != nil {
			arpLoadErr = fmt.Errorf("加载 iphlpapi.dll 失败: %w", err)
			return
		}
		p, err := dll.FindProc("SendARP")
		if err != nil {
			arpLoadErr = fmt.Errorf("未找到 SendARP 导出: %w", err)
			return
		}
		arpSend = p
		arpOK = true
	})
	return arpOK
}

// ArpHardwareAvailable 本机是否具备 ARP 探测能力(供探针能力上报)。
func ArpHardwareAvailable() bool { return initArp() }

// ArpProbeOne 查询 ip 的 MAC 地址。timeoutMs 为 0 时取 1000ms。
// 返回 ("", nil) 表示"无应答"(目标不在本网段/不存在/被隔离), 属正常结果;
// 只有平台能力缺失时才返回错误。
//
// 注意: SendARP 本身是同步阻塞调用且没有超时参数, 超时由系统内部决定(通常 1-3 秒)。
// 为避免恶意/离线目标把扫描拖长, 上层应按并发上限调用(probe/agentexec 已限制并发)。
func ArpProbeOne(ip string, timeoutMs uint32) (string, error) {
	if !initArp() {
		if arpLoadErr != nil {
			return "", fmt.Errorf("%w: %v", ErrArpUnsupported, arpLoadErr)
		}
		return "", ErrArpUnsupported
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("无效 IP: %s", ip)
	}
	v4 := parsed.To4()
	if v4 == nil {
		return "", fmt.Errorf("仅支持 IPv4: %s", ip)
	}
	// IPAddr 为网络字节序的 4 字节: 直接取 To4 切片拼成 uint32
	dest := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])

	var mac [8]byte
	macLen := uint32(len(mac))
	r, _, _ := arpSend.Call(
		uintptr(dest),
		0, // SrcIP = 0: 由系统选择源接口/地址
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if r != 0 {
		// 非 0 一律视为"无应答": ARP 探测失败是常态(跨网段/目标关机/隔离),
		// 返回错误会让上层把整轮扫描判为失败, 因此这里吞掉错误只回空值。
		return "", nil
	}
	if macLen < 6 {
		return "", nil
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]), nil
}
