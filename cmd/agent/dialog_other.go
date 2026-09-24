//go:build !windows

// dialog_other.go 探针端交互对话框(非 Windows 空桩)。
//
// 非 Windows 平台上 agent 通常在 systemd/终端中运行, 没有"双击"这种部署方式,
// 也就没有"看不到控制台输出"的问题 —— 直接打日志让用户看到即可, 不引入弹框依赖
// (Linux 弹框需要 zenity/xdialog 等外部程序, 与"零第三方依赖"约束冲突)。
//
// 必须存在此文件(规则 2): 保证 Linux/macOS 也能编译通过。
package main

import "time"

// promptCenterAddr 非 Windows 平台不支持弹框输入, 恒返回空串,
// 由上层按"未配置中心端地址"打印控制台指引。
func promptCenterAddr(title, prompt string, timeoutSec int) string {
	_, _ = title, prompt
	_ = timeoutSec
	return ""
}

// centerPromptSupported 非 Windows 不弹框: Linux 上探针由 systemd 管理,
// 连不上中心端时静默重试是正确行为, 不该弹出无人应答的窗口。
func centerPromptSupported() bool { return false }

// promptCenterFailure 非 Windows 恒返回"无操作"(不弹框、不退出、不静默)。
func promptCenterFailure(curAddr string, offlineFor time.Duration) (addr, token string, snoozeMin int, wantExit bool) {
	return "", "", 0, false
}

// ShowConfirm 非 Windows 恒返回 false(不卸载): 卸载是 Windows 安装目录里的
// 交互动作, Linux 上"删除目录 + 停用 systemd unit"是运维动作, 不该由本程序代劳。
func ShowConfirm(title, msg string) bool {
	_, _ = title, msg
	return false
}

// ShowInfo 非 Windows 平台的提示框空实现(改为无操作, 日志由调用方负责)。
func ShowInfo(title, msg string) {
	_, _ = title, msg
}
