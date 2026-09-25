//go:build !windows

// settings_reload_unix.go SIGUSR1 触发配置热重载(Unix)。
//
// Windows 无 SIGUSR1(signal.Notify 传它会直接报 "signal not supported"),
// 故按项目规则拆文件: 本文件仅非 Windows 编译, Windows 走 settings_reload_other.go 空桩
// (那边靠文件监听覆盖同一需求)。
package main

import (
	"os"
	"os/signal"
	"syscall"
)

// RegisterReloadSignal 注册 SIGUSR1 → 热重载。
func RegisterReloadSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		for range ch {
			ReloadSettings("收到 SIGUSR1")
		}
	}()
}
