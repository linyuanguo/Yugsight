//go:build !windows

package main

import "os/exec"

// hideConsoleWindow 非 Windows 平台无 CREATE_NO_WINDOW 概念:
// Linux/macOS 下子进程不继承"控制台窗口", 终端复用父进程的 tty, 无需任何处理。
// 保留空实现是为了让 capture_api.go 等调用点无需分平台编译。
func hideConsoleWindow(cmd *exec.Cmd) {}
