//go:build windows

package main

import (
	"syscall"
)

// 控制台控制事件类型(SetConsoleCtrlHandler 回调参数)
const (
	ctrlCEVENT        = 0 // Ctrl+C
	ctrlBreakEvent    = 1 // Ctrl+Break
	ctrlCloseEvent    = 2 // 关闭控制台窗口(点 X)
	ctrlLogoffEvent   = 5 // 用户注销
	ctrlShutdownEvent = 6 // 系统关机
)

var (
	procSetConsoleCtrlHandler = kernel32.NewProc("SetConsoleCtrlHandler")
	procSetConsoleOutputCP    = kernel32.NewProc("SetConsoleOutputCP")
	procShowWindow            = syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow")
)

// swMinimize: ShowWindow 的最小化指令
const swMinimize = 6

// consoleQuitFn: 控制台控制回调经它通知主流程退出(内部关闭 quit 通道)
var consoleQuitFn func()

// consoleCtrlHandler 控制台控制回调。
// 系统会在独立线程调用它, 必须极轻: 不阻塞、不长耗时, 只做"关通道/记日志"这类动作。
//
// 【为什么关窗(X)不再停服务】双击部署的真实流程是: 双击 exe → 等浏览器弹出 →
// 关掉黑窗口(用户把它当"启动器窗口")。旧设计"关窗=停服务"会让用户每次都在
// 不知不觉中杀掉服务, 页面随即空白, 只能反复重启(实测一天内发生 3 次)。
// 现在关窗=用户不想看日志: 控制台窗口被系统销毁, 进程留在后台继续运行,
// 停服务改走网页顶栏"停止服务"按钮(/api/quit)或恢复窗口后 Ctrl+C。
// 注销/关机仍必须停止。
func consoleCtrlHandler(dwCtrlType uintptr) uintptr {
	switch dwCtrlType {
	case ctrlCloseEvent:
		// 不关闭 quit 通道 → 服务继续。此时控制台已随窗口销毁, stdout 写入
		// 静默失败(logLine 忽略错误), 文件日志照常落 logs/。
		go logLine("控制台窗口已关闭: 服务继续在后台运行(页面不受影响; 停止服务请用网页顶栏\"停止服务\"按钮)")
		return 1 // 已处理: 阻止默认处理器终止进程
	case ctrlCEVENT, ctrlBreakEvent, ctrlLogoffEvent, ctrlShutdownEvent:
		if consoleQuitFn != nil {
			consoleQuitFn()
		}
		return 1 // 已处理: 交回主流程走干净退出(结束抓包子进程等)
	}
	return 0
}

// minimizeConsoleWindow 把控制台窗口最小化到任务栏(启动即执行: 黑窗口不挡视线,
// 想看日志从任务栏恢复; 点 X 只关窗口不停服务, 见 consoleCtrlHandler)。
//
// 【降级】无控制台(以 -no-browser 从 cmd 跑等场景控制台仍在, 但后台服务/无窗口
// 构建时 GetConsoleWindow 返回 0)或 API 失败 → 静默忽略, 绝不影响主流程。
func minimizeConsoleWindow() {
	defer func() { _ = recover() }()
	if !hasConsole() { // 无控制台(如误用 -H windowsgui 构建, 见 console_consoleurl_windows.go)
		return
	}
	h, _, _ := procGetConsoleWindow.Call() // 与 hasConsole 同包, 复用其声明
	procShowWindow.Call(h, swMinimize)
}

// installConsoleQuitHandler 注册控制台控制处理器。
// 控制台窗口即服务"界面": 日志实时打印到 stdout;
// 关闭窗口 / Ctrl+C / Ctrl+Break / 注销 / 关机, 任一发生都停止服务。
func installConsoleQuitHandler(quit chan struct{}) {
	consoleQuitFn = func() {
		select {
		case <-quit:
		default:
			close(quit)
		}
	}
	procSetConsoleCtrlHandler.Call(syscall.NewCallback(consoleCtrlHandler), 1)
}
