//go:build windows

package probe

import (
	"os/exec"
	"strings"
	"syscall"
)

// syscallNewLazyDLL 包装 syscall.NewLazyDLL(Go 1.25 仍保留该 API, 此处集中以便后续替换)。
func syscallNewLazyDLL(name string) *syscall.LazyDLL { return syscall.NewLazyDLL(name) }

// windowsUTF16PtrFromString 字符串转 UTF-16 指针(注册表/文件路径用)。
func windowsUTF16PtrFromString(s string) (*uint16, error) {
	return syscall.UTF16PtrFromString(s)
}

// windowsUTF16ToString []uint16 -> string(去尾部 \0)。
func windowsUTF16ToString(buf []uint16) string {
	if len(buf) == 0 {
		return ""
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return syscall.UTF16ToString(buf[:end])
}

// setHideWindow 隐藏子进程控制台窗口(windowsgui 构建下必须, 否则会闪黑框)。
func setHideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// decodeConsole 宽松解码控制台输出(中文 GBK 输出按字节处理, 提取 ASCII 地址/版本足够)。
func decodeConsole(b []byte) string { return strings.TrimSpace(string(b)) }
