package envdetect

// Windows 专属: 注册表检测 Npcap 驱动 + 安装器查找/启动。
// 纯标准库: Go 1.25 的 syscall 包已移除注册表包装函数,
// 这里与 pcap_windows.go 同风格, 直接对 advapi32.dll 做 FFI 调用。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modAdvapi    = syscall.NewLazyDLL("advapi32.dll")
	procRegOpen  = modAdvapi.NewProc("RegOpenKeyExW")
	procRegQuery = modAdvapi.NewProc("RegQueryValueExW")
	procRegClose = modAdvapi.NewProc("RegCloseKey")
)

const (
	hkLM              = 0x80000002 // HKEY_LOCAL_MACHINE 伪句柄
	keyRead           = 0x20019    // KEY_READ = KEY_QUERY_VALUE | KEY_ENUMERATE_SUBKEYS
	regErrorSuccess   = 0
	regErrorNoSuchKey = 2          // ERROR_FILE_NOT_FOUND
	regTypeSz         = 1          // REG_SZ
)

// regOpenKey 打开 HKLM\subkey(只读), 返回句柄; 键不存在返回 0
func regOpenKey(subkey string) uintptr {
	p, _ := syscall.UTF16PtrFromString(subkey)
	h, _, _ := procRegOpen.Call(
		uintptr(hkLM),
		uintptr(unsafe.Pointer(p)),
		0,
		uintptr(keyRead),
		0,
		0,
	)
	return h
}

// regString 读 HKLM\subkey 下的 REG_SZ 值, 键/值不存在返回空
func regString(subkey, value string) string {
	h := regOpenKey(subkey)
	if h == 0 {
		return ""
	}
	defer procRegClose.Call(h)
	vp, _ := syscall.UTF16PtrFromString(value)
	var typ uint32
	var cb uint32
	r, _, _ := procRegQuery.Call(
		h,
		uintptr(unsafe.Pointer(vp)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		0,
		uintptr(unsafe.Pointer(&cb)),
	)
	if r != regErrorSuccess || cb == 0 {
		return ""
	}
	buf := make([]byte, cb)
	r, _, _ = procRegQuery.Call(
		h,
		uintptr(unsafe.Pointer(vp)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&cb)),
	)
	if r != regErrorSuccess || typ != regTypeSz {
		return ""
	}
	return strings.TrimSpace(syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(&buf[0]))[:cb/2]))
}

// regExists 判断 HKLM\subkey 是否存在
func regExists(subkey string) bool {
	h := regOpenKey(subkey)
	if h == 0 {
		return false
	}
	procRegClose.Call(h)
	return true
}

// detectNpcap 读注册表检测 Npcap 驱动(三级证据, 任一命中即判定已安装):
//  1. HKLM\SYSTEM\CurrentControlSet\Services\npcap -> 驱动服务(最强证据, 驱动随服务加载)
//  2. HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Npcap -> 安装记录 + DisplayVersion
//  3. System32\npcap\wpcap.dll 文件存在 -> 文件兜底(兼容 winpcap 模式安装)
func detectNpcap() NpcapStatus {
	s := NpcapStatus{Supported: true, Source: "-"}
	if regExists(`SYSTEM\CurrentControlSet\Services\npcap`) {
		s.Installed = true
		s.Source = "registry-service"
	}
	if regExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Npcap`) {
		if !s.Installed {
			s.Installed = true
			s.Source = "registry-uninstall"
		}
		if v := regString(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Npcap`, "DisplayVersion"); v != "" {
			s.Version = v
		}
	}
	if !s.Installed {
		if _, err := os.Stat(`C:\Windows\System32\npcap\wpcap.dll`); err == nil {
			s.Installed = true
			s.Source = "file"
		}
	}
	s.Installer = shortPath(findInstaller())
	return s
}

// findInstaller 在项目根目录(exe 同目录)查找 Npcap 安装器:
// 优先精确匹配 npcap-setup.exe, 其次官方安装器 npcap-*.exe(如 npcap-1.86.exe)
func findInstaller() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var fallback string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.ToLower(e.Name())
		if !strings.HasSuffix(n, ".exe") {
			continue
		}
		if n == "npcap-setup.exe" {
			return filepath.Join(dir, e.Name())
		}
		if strings.HasPrefix(n, "npcap-") && fallback == "" {
			fallback = filepath.Join(dir, e.Name())
		}
	}
	return fallback
}

// StartInstaller 启动 Npcap 安装器。免费版不支持静默安装, 以 GUI 向导运行,
// 返回进程句柄供调用方轮询安装完成/用户取消(与抓包一键安装同一策略)。
func StartInstaller(path string) (*exec.Cmd, error) {
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}
