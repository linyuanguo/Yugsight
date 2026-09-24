//go:build windows

package main

import (
	"unsafe"
)

const (
	stdInputHandle  = uintptr(0xFFFFFFF6) // (DWORD)-10
	enableLineInput = 0x0002
	enableEchoInput = 0x0004
)

var (
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// setStdinRaw 把控制台 stdin 设为 raw mode(去掉行缓冲+回显)。
//
// 【为什么需要】Windows 控制台默认是 line-buffered: 按 O 后字符回显到屏幕,
// 但 os.Stdin.Read 要等回车才收到数据 —— 用户按 O 没反应, 字符"变成输入 o 了"。
// 去掉 ENABLE_LINE_INPUT + ENABLE_ECHO_INPUT 后, 单字节 Read 立即生效,
// 按 O 即刻触发 openBrowser, 无需回车。
//
// 【保留 ENABLE_PROCESSED_INPUT(0x01)】Ctrl+C 仍然正常生成 CTRL_C_EVENT 退出程序。
//
// 【降级】无控制台/非控制台句柄 → 静默返回, 不影响主流程。
func setStdinRaw() {
	defer func() { _ = recover() }()
	h, _, _ := procGetStdHandle.Call(stdInputHandle)
	if h == 0 {
		return
	}
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	newMode := mode &^ (enableLineInput | enableEchoInput)
	if newMode != mode {
		procSetConsoleMode.Call(h, uintptr(newMode))
	}
}
