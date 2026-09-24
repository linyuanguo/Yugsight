//go:build !windows

// install_other.go 探针自安装空桩(规则 2: Windows 专属功能配空桩, 全平台可编译)。
//
// 非 Windows 的部署方式是 systemd/终端命令, 没有"双击安装"这种形态;
// 开机自启是 Windows 注册表的产物(Linux 用 systemd unit, 属运维动作)。
// 单实例检查在非 Windows 上直接放行: 探针在 Linux 上的重复启动由 systemd
// 的 unit 语义管理, 这里不越权拦截 —— 误拦会让排查时手动多开一次都做不到。
package main

import "errors"

func acquireSingleInstance() bool { return true }

func releaseSingleInstance() {}

// installAndLaunch 恒返回 false(不走安装流程), 由 main 继续原前台流程。
func installAndLaunch() bool { return false }

// isUninstallLaunch 非 Windows 恒 false(卸载程序只在 Windows 安装目录里生成)。
func isUninstallLaunch() bool { return false }

// runUninstall 非 Windows 无操作(卸载 = 停止服务 + 删除目录, 由运维/systemd 处理)。
func runUninstall() {}

// relaunchSelf 非 Windows 无安装目录/无窗口语义, 恒返回错误由上层降级处理
// (连接守卫只在 Windows 激活, 正常不会走到这里)。
func relaunchSelf(center string) error {
	return errors.New("非 Windows 平台不支持以新地址重启自身")
}
