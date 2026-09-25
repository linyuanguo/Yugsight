//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// showMessage 在无控制台(windowsgui)构建下用系统消息框提示错误
// 必须用 MessageBoxW: 传的是 UTF-16 指针, 用 MessageBoxA 会把 UTF-16 字节按 ANSI 解析,
// 中文全部乱码且遇到 0x00/0x1A 字节提前截断(表现为窗口里只剩 "W" 之类的半个词)
func showMessage(title, text string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("MessageBoxW")
	proc.Call(0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(text))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
		0x0010) // MB_ICONINFORMATION
}
