package probe

import (
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// CollectNodeInfo 采集探针节点主机信息(中心端注册/心跳上报, 同时落 DAO 持久化)。
//
// 全部字段尽力而为: 任一子项采集失败只留空, 不返回错误、不中断注册流程。
func CollectNodeInfo(name, version string) *NodeInfo {
	host, _ := os.Hostname()
	info := &NodeInfo{
		Name:      name,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Hostname:  host,
		CPUCores:  runtime.NumCPU(),
		Version:   version,
		StartedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	if info.Name == "" {
		info.Name = host
	}
	info.OSVersion = osVersion()
	info.CPUModel = cpuModel()
	if total, used, ok := memStatsOS(); ok {
		info.MemTotal, info.MemUsed = total, used
	}
	if total, used, ok := diskStatsOS(); ok {
		info.DiskTotal, info.DiskUsed = total, used
	}
	info.NetIfaces, info.LocalIPs, info.Gateway, info.DNS = netInfo()
	info.NpcapInstalled = npcapInstalled()
	info.Engines = engineVersions()
	return info
}

// netInfo 采集网卡(IP/MAC)/ 本机 IP 列表 / 默认网关 / DNS。
func netInfo() (ifaces []NetIface, ips []string, gateway string, dns []string) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, nil, "", nil
	}
	for _, ifc := range list {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		item := NetIface{Name: ifc.Name}
		if mac := ifc.HardwareAddr.String(); mac != "" {
			item.MAC = mac
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				if item.IP == "" {
					item.IP = v4.String()
				}
				ips = append(ips, v4.String())
			}
		}
		if ifc.Flags&net.FlagUp != 0 {
			ifaces = append(ifaces, item)
		}
	}
	// 网关与 DNS: 平台实现(Windows 走 ipconfig 解析, 其它平台读 /etc/resolv.conf 等)
	gateway = defaultGateway()
	dns = dnsServers()
	if len(ips) == 0 {
		if ip := firstLocalIP(); ip != "" {
			ips = append(ips, ip)
		}
	}
	return ifaces, ips, gateway, dns
}

// firstLocalIP 兜底取一个本机 IPv4(与 scanner 同思路, 不依赖外网连通)。
func firstLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() {
			if v4 := n.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}

// CpuSample CPU 累计节拍采样点: prev 用于按两次采样的差值粗算占用率。
type CpuSample struct {
	Total uint64
	Idle  uint64
	At    time.Time
}

// SampleCPU 采集一次 CPU 累计节拍(平台实现)。
func SampleCPU() CpuSample { return sampleCPU() }

// CPUPercent 由前后两次采样计算 CPU 占用百分比(0-100);
// 采样缺失/无有效差值时返回 0(前端展示为 "-")。
func CPUPercent(prev, cur CpuSample) float64 {
	if prev.Total == 0 || cur.Total <= prev.Total {
		return 0
	}
	dt := cur.Total - prev.Total
	di := uint64(0)
	if cur.Idle > prev.Idle {
		di = cur.Idle - prev.Idle
	}
	if dt == 0 || di > dt {
		return 0
	}
	return float64(dt-di) * 100 / float64(dt)
}

// MemPercent 内存占用百分比。
func MemPercent(total, used uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) * 100 / float64(total)
}

// atoiSafe 宽松解析整数字符串(采集辅助)。
func atoiSafe(s string) uint64 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
