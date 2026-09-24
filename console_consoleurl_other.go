//go:build !windows

package main

// setConsoleTitle 非 Windows 空桩(项目规则 2: Windows 专属功能必须配 *_other.go,
// 保证全平台编译通过)。终端标题在 Linux/macOS 走的是 ANSI 转义序列, 但本程序在
// 这些平台主要作为服务运行(无交互终端), 设置了也没人看, 故不做。
// 快捷键 O 打开页面的能力在非 Windows 上是可用的(console_consoleurl.go 是纯逻辑)。
func setConsoleTitle(title string) {
	_ = title
}

// hasConsole 非 Windows 恒为 true:
// 标题设置在非 Windows 上是 no-op, 但按 O 键打开页面的能力是可用的(stdout/stderr 走
// 终端时 stdin 通常也在), 故不做额外判断, 让快捷键在 Linux/macOS 也能生效。
func hasConsole() bool { return true }

// pinURLTopline 非 Windows 空桩(项目规则 2: Windows 专属功能必须配 *_other.go)。
// 顶栏常显依赖 conhost 的屏幕缓冲区 API(GetConsoleScreenBufferInfo 等);
// Linux/macOS 终端理论上可用 ANSI 转义序列实现同效果, 但本程序在这些平台主要
// 作为服务跑(无交互终端), 故不做。consolePinAfterLog 的调用路径照常走,
// 这里空操作即可, 日志输出零受影响。
func pinURLTopline() {}
