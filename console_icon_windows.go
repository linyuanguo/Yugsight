//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

const WM_SETICON = 0x0080

// setConsoleIcon 给控制台窗口设置 yugsight 自定义图标(任务栏/Alt+Tab 可见)。
//
// 【为什么需要】console 子系统的窗口由 conhost.exe 托管, 任务栏图标是 conhost 的
// 默认终端图标, 不是 yugsight 的。通过 WM_SETICON 消息覆盖 conhost 窗口的图标。
//
// 【实现】从 exe 文件本身提取嵌入图标(ExtractIconExW, 图标由 build/rsrc.syso 注入),
// 再 SendMessageW(WM_SETICON) 到 GetConsoleWindow() 返回的句柄。
//
// 【降级】无控制台/提取失败/句柄无效 → 静默返回, 不影响启动(项目规则 3/4)。
func setConsoleIcon() {
	defer func() { _ = recover() }()
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exe16, _ := syscall.UTF16PtrFromString(exe)
	var hLarge, hSmall uintptr
	n, _, _ := shell32.NewProc("ExtractIconExW").Call(
		uintptr(unsafe.Pointer(exe16)),
		0, // 图标索引 0 = 第一个(大图标)
		uintptr(unsafe.Pointer(&hLarge)),
		uintptr(unsafe.Pointer(&hSmall)),
		1,
	)
	if n == 0 || hLarge == 0 {
		return
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	user32 := syscall.NewLazyDLL("user32.dll")
	send := user32.NewProc("SendMessageW")
	send.Call(hwnd, WM_SETICON, 1, hLarge) // 大图标(任务栏)
	if hSmall != 0 {
		send.Call(hwnd, WM_SETICON, 0, hSmall) // 小图标(Alt+Tab)
	}
}
