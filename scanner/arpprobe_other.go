//go:build !windows

package scanner

// arpprobe_other.go 非 Windows 平台 ARP 探测空桩(与 arpprobe_windows.go 一一对应)。
//
// ARP 是链路层协议, 探测实现依赖平台原生能力:
//   - Windows: SendARP(iphlpapi.dll), 系统代发 ARP 请求并返回 MAC;
//   - 其它平台: 没有等价的纯标准库接口(需原始以太网帧 + AF_PACKET/BPF, 且要 root),
//     因此这里统一返回"不支持", 由上层降级为 ICMP/TCP 存活探测。
//
// 上层(probe/agentexec)拿到 ErrArpUnsupported 时应静默降级而非报错:
// 探针跨平台部署, 缺少 ARP 只意味着探测手段少一种, 不影响扫描结论。

import "errors"

// ErrArpUnsupported ARP 探测在当前平台不可用。
var ErrArpUnsupported = errors.New("ARP 探测仅支持 Windows")

// ArpProbeOne 查询 ip 的 MAC 地址。非 Windows 恒返回不支持错误。
func ArpProbeOne(ip string, timeoutMs uint32) (string, error) {
	return "", ErrArpUnsupported
}

// ArpHardwareAvailable ARP 探测是否可用(非 Windows 恒为 false)。
func ArpHardwareAvailable() bool { return false }
