//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// minimizeConsoleWindow 非 Windows 无"控制台窗口"概念, 空操作
// (Windows 版见 console_windows.go: 启动自动最小化, 不挡视线)。
func minimizeConsoleWindow() {}

// installConsoleQuitHandler 非 Windows 平台没有控制台控制处理器, 用信号(Ctrl+C / SIGTERM)停止服务
func installConsoleQuitHandler(quit chan struct{}) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		select {
		case <-quit:
		default:
			close(quit)
		}
	}()
}
