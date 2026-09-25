//go:build windows

// settings_reload_other.go Windows 侧空桩: 本平台没有 SIGUSR1。
//
// 文件监听(settings_reload.go 的 5 秒轮询)与 POST /api/v2/config/reload
// 已完整覆盖"改配置不重启"的需求, 无需信号通道。
package main

// RegisterReloadSignal Windows 无 SIGUSR1, 空实现(保持调用点跨平台一致)。
func RegisterReloadSignal() {}
