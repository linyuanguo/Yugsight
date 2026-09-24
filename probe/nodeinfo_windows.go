//go:build windows

package probe

import (
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

// ===== Windows 实现: 走系统命令/内核32 API 采集, 全部失败降级为空值 =====

// osVersion 返回系统版本描述(未做 manifest 时 RtlGetVersion 也只能拿到兼容版本号, 够用)。
func osVersion() string {
	var vi struct {
		Size             uint32
		Major            uint32
		Minor            uint32
		Build            uint32
		PlatformID       uint32
		CSDVersion       [128]uint16
		ServicePackMajor uint16
		ServicePackMinor uint16
		SuiteMask        uint16
		ProductType      byte
		Reserved         byte
	}
	vi.Size = uint32(unsafe.Sizeof(vi))
	dll := syscallNewLazyDLL("ntdll.dll")
	proc := dll.NewProc("RtlGetVersion")
	if r, _, _ := proc.Call(uintptr(unsafe.Pointer(&vi))); r == 0 {
		return "Windows " + itoa(int(vi.Major)) + "." + itoa(int(vi.Minor)) + " (Build " + itoa(int(vi.Build)) + ")"
	}
	return runtime.GOOS
}

// cpuModel 从注册表读取 CPU 型号(失败返回空)。
func cpuModel() string {
	const (
		hkLM  = 0x80000002
		keyRd = 0x20019
	)
	adv := syscallNewLazyDLL("advapi32.dll")
	openProc := adv.NewProc("RegOpenKeyExW")
	queryProc := adv.NewProc("RegQueryValueExW")
	closeProc := adv.NewProc("RegCloseKey")

	path, _ := windowsUTF16PtrFromString(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`)
	name, _ := windowsUTF16PtrFromString("ProcessorNameString")
	var h uintptr
	if r, _, _ := openProc.Call(hkLM, uintptr(unsafe.Pointer(path)), 0, keyRd, uintptr(unsafe.Pointer(&h))); r != 0 {
		return ""
	}
	defer closeProc.Call(h)
	var typ, size uint32 = 0, 512
	buf := make([]uint16, 256)
	if r, _, _ := queryProc.Call(h, uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r != 0 {
		return ""
	}
	return strings.TrimSpace(windowsUTF16ToString(buf))
}

// memStatsOS 读取物理内存总量/已用(GlobalMemoryStatusEx)。
func memStatsOS() (total, used uint64, ok bool) {
	var st struct {
		Length               uint32
		MemoryLoad           uint32
		TotalPhys            uint64
		AvailPhys            uint64
		TotalPageFile        uint64
		AvailPageFile        uint64
		TotalVirtual         uint64
		AvailVirtual         uint64
		AvailExtendedVirtual uint64
	}
	st.Length = uint32(unsafe.Sizeof(st))
	k := syscallNewLazyDLL("kernel32.dll")
	proc := k.NewProc("GlobalMemoryStatusEx")
	if r, _, _ := proc.Call(uintptr(unsafe.Pointer(&st))); r == 0 {
		return 0, 0, false
	}
	return st.TotalPhys, st.TotalPhys - st.AvailPhys, true
}

// diskStatsOS 读取系统盘容量(GetDiskFreeSpaceExW)。
func diskStatsOS() (total, used uint64, ok bool) {
	k := syscallNewLazyDLL("kernel32.dll")
	proc := k.NewProc("GetDiskFreeSpaceExW")
	root, _ := windowsUTF16PtrFromString("C:\\")
	var freeAvail, totalBytes, totalFree uint64
	if r, _, _ := proc.Call(
		uintptr(unsafe.Pointer(root)),
		uintptr(unsafe.Pointer(&freeAvail)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	); r == 0 {
		return 0, 0, false
	}
	return totalBytes, totalBytes - totalFree, true
}

// sampleCPU Windows 无 GetSystemTimes 的 syscall 包装, 解析 wmic 输出成本高,
// 这里用 GetTickCount64 作总时长近似(仅用于展示负载趋势, 精度要求低)。
func sampleCPU() CpuSample {
	k := syscallNewLazyDLL("kernel32.dll")
	proc := k.NewProc("GetTickCount64")
	r, _, _ := proc.Call()
	return CpuSample{Total: uint64(r), Idle: 0, At: time.Now()}
}

// defaultGateway 解析 ipconfig 输出取默认网关。
func defaultGateway() string {
	out := runCmd("ipconfig")
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if strings.HasPrefix(t, "Default Gateway") || strings.HasPrefix(t, "默认网关") {
			if _, v := splitKeyValue(t); v != "" {
				if ip := firstIPv4(v); ip != "" {
					return ip
				}
			}
		}
	}
	return ""
}

// dnsServers 解析 ipconfig /all 输出取 DNS 服务器列表。
func dnsServers() []string {
	out := runCmd("ipconfig", "/all")
	var dns []string
	collect := false
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if t == "" {
			collect = false
			continue
		}
		k, v := splitKeyValue(t)
		if strings.Contains(k, "DNS Servers") || strings.Contains(k, "DNS 服务器") {
			collect = true
			if ip := firstIPv4(v); ip != "" {
				dns = appendUnique(dns, ip)
			}
			continue
		}
		// 续行(缩进且无冒号)仍属上一个键
		if collect && !strings.Contains(t, ":") {
			if ip := firstIPv4(t); ip != "" {
				dns = appendUnique(dns, ip)
			}
		} else if collect {
			collect = false
		}
	}
	return dns
}

// npcapInstalled Npcap 是否安装: 复用注册表三级证据中的最强证据(驱动服务)。
func npcapInstalled() bool {
	var h uintptr
	adv := syscallNewLazyDLL("advapi32.dll")
	openProc := adv.NewProc("RegOpenKeyExW")
	closeProc := adv.NewProc("RegCloseKey")
	p, _ := windowsUTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\npcap`)
	if r, _, _ := openProc.Call(0x80000002, uintptr(unsafe.Pointer(p)), 0, 0x20019, uintptr(unsafe.Pointer(&h))); r == 0 {
		closeProc.Call(h)
		return true
	}
	return false
}

func runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	setHideWindow(cmd)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	// ipconfig 中文输出为 GBK, 这里做宽松处理: 版本号/地址通常是 ASCII, 直接按 UTF-8 读仍可提取
	return decodeConsole(out)
}
