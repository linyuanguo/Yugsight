//go:build !windows

package probe

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ===== 非 Windows 实现: 读取 /proc 与 /etc 采集, 全部失败降级为空值 =====
// osVersion 读取 /etc/os-release 的 PRETTY_NAME(缺失时回退 /etc/issue 再回退 GOOS)。
func osVersion() string {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "PRETTY_NAME="); ok {
				return strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	if b, err := os.ReadFile("/etc/issue"); err == nil {
		if lines := strings.Split(string(b), "\n"); len(lines) > 0 {
			if s := strings.TrimSpace(lines[0]); s != "" {
				return s
			}
		}
	}
	return runtime.GOOS
}

// cpuModel 读取 /proc/cpuinfo 的 model name(ARM 平台为 Hardware)。
func cpuModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model name", "Hardware":
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// memStatsOS 读取 /proc/meminfo 的 MemTotal / MemAvailable(单位 kB)。
func memStatsOS() (total, used uint64, ok bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	var t, avail uint64
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			t = atoiSafe(f[1]) * 1024
		case "MemAvailable":
			avail = atoiSafe(f[1]) * 1024
		}
	}
	if t == 0 {
		return 0, 0, false
	}
	if avail > t {
		avail = t
	}
	return t, t - avail, true
}

// diskStatsOS 用 Statfs 读根分区容量。
func diskStatsOS() (total, used uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0, false
	}
	bs := uint64(st.Bsize)
	total = st.Blocks * bs
	free := st.Bavail * bs
	if free > total {
		free = total
	}
	return total, total - free, true
}

// sampleCPU 读取 /proc/stat 首行的累计节拍。
func sampleCPU() CpuSample {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return CpuSample{At: time.Now()}
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 {
		return CpuSample{At: time.Now()}
	}
	f := strings.Fields(lines[0])
	if len(f) < 5 || f[0] != "cpu" {
		return CpuSample{At: time.Now()}
	}
	var total, idle uint64
	for i, v := range f[1:] {
		n := atoiSafe(v)
		total += n
		if i == 3 || i == 4 { // idle + iowait
			idle += n
		}
	}
	return CpuSample{Total: total, Idle: idle, At: time.Now()}
}

// defaultGateway 解析 /proc/net/route 的默认路由(网关字段为小端十六进制)。
func defaultGateway() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for i, ln := range strings.Split(string(b), "\n") {
		if i == 0 {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		n, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		return strconv.Itoa(int(n&0xff)) + "." + strconv.Itoa(int((n>>8)&0xff)) + "." +
			strconv.Itoa(int((n>>16)&0xff)) + "." + strconv.Itoa(int((n>>24)&0xff))
	}
	return ""
}

// dnsServers 解析 /etc/resolv.conf。
func dnsServers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = appendUnique(out, f[1])
		}
	}
	return out
}

// npcapInstalled 非 Windows 平台无 Npcap(抓包走 libpcap, 不在此检测)。
func npcapInstalled() bool { return false }
