//go:build !linux && !windows

package probe

import (
	"net"
	"sort"
	"time"
)

// ===== 其它平台(macOS 等): 只有接口清单, 没有字节计数 =====
//
// 不硬凑速率: 这些平台拿不到累计字节(/proc 无、PDH 无), 速率一律 0(UI 显示为
// 无流量), 但清单/状态/MAC/IP 是标准库能给的 —— 有就给, 不为了"列齐全"编造速率。

func sampleIfaces(interval time.Duration) []IfaceSample {
	list, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]IfaceSample, 0, len(list))
	for _, ifc := range list {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		it := IfaceSample{Name: ifc.Name}
		if m := ifc.HardwareAddr.String(); m != "" {
			it.MAC = m
		}
		if ifc.Flags&net.FlagUp != 0 {
			it.State = "up"
		} else {
			it.State = "down"
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			it.IP = ip.String()
			break
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
