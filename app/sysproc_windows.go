//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// createNoWindow = CREATE_NO_WINDOW: 子进程不分配控制台窗口。
//
// ===== 为什么必须显式加这个标志 =====
//
// 主程序按约定构建为**控制台子系统**(见 scripts/build.ps1, 那里明确禁止加
// -H windowsgui, 因为"控制台窗口即服务界面"): 进程自带一个控制台窗口, 任务栏
// 能看到、日志实时打印, 关窗即停止服务。
//
// 但控制台是有"继承性"的: 父进程是控制台进程时, 它通过 exec.Command 拉起的
// 子进程(同样是控制台子系统)会**再分配一个自己的控制台窗口** —— 任务栏于是
// 多出第二个窗口, 标题和主服务窗口几乎一样(都是主程序 exe 名), 用户根本分不清
// 哪个是服务本体。实际会浮出窗口的路径有三处:
//
//	1. 抓包 worker   : exe -pcap=capture ...      (capture_api.go)
//	2. Npcap 安装器  : npcap-*.exe                (capture_api.go)
//	3. 外部扫描引擎  : nmap / trivy / zap         (engine/job_windows.go)
//
// 这些子进程的输出全部经管道/os.StdoutPipe 捕获, 本就不需要自己的窗口。统一用
// CREATE_NO_WINDOW 创建, 控制台一个都不多。
//
// 【坑】不要用 SysProcAttr.HideWindow 代替: 它只对*窗口*类进程有效(且需要 STARTUPINFO
// 的 SW_HIDE 路径), 对控制台子系统进程仍会把控制台建出来, 只是尝试隐藏, 结果依旧
// 可能在任务栏闪出一个窗口。CREATE_NO_WINDOW 是"根本不创建控制台", 语义无歧义。
const createNoWindow = 0x08000000

// hideConsoleWindow 让子进程不分配控制台窗口(仅设置启动标志, 不清理原有值)。
func hideConsoleWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
