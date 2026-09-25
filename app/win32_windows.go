//go:build windows

package main

import "syscall"

// 共享 Win32 DLL 句柄:
//   - elevate_windows.go(提权/单实例) 用 kernel32 / shell32
//   - console_windows.go(控制台控制处理器) 用 kernel32
//
// 原先这些句柄声明在 tray_windows.go 里, 自绘窗口移除后在此集中, 供各 Windows 文件共用。
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
)
