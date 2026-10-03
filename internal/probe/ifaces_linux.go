//go:build linux

package probe

import (
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ===== Linux: /proc/net/dev 累计值 + /sys/class/net 状态/MAC =====
//
// 为什么不用 net.Interfaces() 拿流量: 标准库只给接口清单与标志位, 没有字节计数。
// /proc/net/dev 是内核权威累计值(收/发字节), 两拍差分 ÷ 窗口即速率; 状态与 MAC
// 从 /sys/class/net/<name>/{operstate,address} 读(比 ioctl 更省事且无需特权)。

var (
	ifaceMu     sync.Mutex
	ifacePrev   = map[string]ifaceCum{}
	ifacePrevAt time.Time // 上一拍时间(2026-10-02: 速率分母改用真实窗口)
	ifaceHas    bool      // 是否已有基线(首拍只建基线)
)

func sampleIfaces(interval time.Duration) []IfaceSample {
	cum, err := readNetDev()
	if err != nil {
		return nil // 无 /proc(极简容器) → 降级, 不报错
	}
	ifaceMu.Lock()
	defer ifaceMu.Unlock()
	// 分母 = 距上一拍的真实间隔而非固定 interval: 心跳拍≈30s 时两者一致, 但中心端
	// 按 /monitor/status 轮询拍(15s)调本函数, 固定 30s 分母会把速率恒定算成一半。
	// 无上一拍时间(首拍/进程重启后第二拍丢失)时回退固定 interval 兜底。
	dt := 0.0
	if ifaceHas && !ifacePrevAt.IsZero() {
		if s := time.Since(ifacePrevAt).Seconds(); s > 0 {
			dt = s
		}
	}
	if dt <= 0 && interval > 0 {
		dt = interval.Seconds()
	}
	out := make([]IfaceSample, 0, len(cum))
	for name, c := range cum {
		it := IfaceSample{Name: name, State: ifaceOperState(name)}
		if m := sysIfaceFile(name, "address"); m != "" {
			it.MAC = m
		}
		if ip := ifaceIPv4(name); ip != "" {
			it.IP = ip
		}
		it.Speed = ifaceSpeed(name)
		if ifaceHas && dt > 0 {
			if p, ok := ifacePrev[name]; ok {
				it.InBps = ifaceDelta(p.rx, c.rx, dt)
				it.OutBps = ifaceDelta(p.tx, c.tx, dt)
			}
		}
		out = append(out, it)
	}
	ifacePrev = cum
	ifacePrevAt = time.Now()
	ifaceHas = true
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ifaceDelta 累计值差分速率: 计数回绕/接口重置(cur < prev)时归 0, 绝不出负速率。
func ifaceDelta(prev, cur uint64, dt float64) float64 {
	if cur < prev || dt <= 0 {
		return 0
	}
	return float64(cur-prev) / dt
}

// readNetDev 读 /proc/net/dev(解析在共享文件 parseNetDev, 平台无关可单测)。
func readNetDev() (map[string]ifaceCum, error) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	return parseNetDev(string(b)), nil
}

// ifaceOperState 链路状态: /sys 的 operstate 为准, 读不到用 net.Interfaces 的
// FlagUp 兜底, 都没有返回 ""(UI 显示 '-')。
func ifaceOperState(name string) string {
	if v := strings.ToLower(strings.TrimSpace(sysIfaceFile(name, "operstate"))); v != "" {
		switch v {
		case "up":
			return "up"
		case "unknown":
			return "" // 内核也没确定(如未插线的虚拟口), 不冒充 down
		default:
			return "down" // down / lowerlayerdown / notpresent / testing / dormant
		}
	}
	if ifc, err := net.InterfaceByName(name); err == nil {
		if ifc.Flags&net.FlagUp != 0 {
			return "up"
		}
		return "down"
	}
	return ""
}

// ifaceSpeed 端口带宽(bps): /sys/class/net/<name>/speed 单位是 Mbit/s,
// 读不到或为 -1(虚拟口/未协商)返回 0 = 未知(UI 显示 '-', 不按 1G 假算)。
func ifaceSpeed(name string) int64 {
	s := strings.TrimSpace(sysIfaceFile(name, "speed"))
	if s == "" || strings.HasPrefix(s, "-") {
		return 0
	}
	mbps := parseU64(s)
	if mbps <= 0 || mbps > 1_000_000 { //  sanity: 1 Tbit 以上不当真
		return 0
	}
	return int64(mbps) * 1_000_000
}

func sysIfaceFile(name, file string) string {
	b, err := os.ReadFile("/sys/class/net/" + name + "/" + file)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ifaceIPv4 网卡上第一个全局 IPv4(回环/链路本地不算)。
func ifaceIPv4(name string) string {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip.String()
	}
	return ""
}
