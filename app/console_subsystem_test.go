// console_subsystem_test.go 守住"Windows 主程序必须是控制台子系统"这条约束。
//
// ===== 为什么需要这个测试 =====
//
// 本项目把控制台窗口当作服务界面: 日志实时打印到 stdout, 关窗/Ctrl+C 即停止服务
// (见 console_windows.go 与 main.go 的 installConsoleQuitHandler)。
//
// 但 Windows 下 Go 只要带上 `-H windowsgui` 就会切成 GUI 子系统 —— 此时进程
// **完全不分配控制台**, 任务栏看不到任何窗口。诡异之处在于: 进程照常运行、Web
// 页面照常打开、所有功能都正常, 只是"没有窗口"。用户第一反应是"服务没起来"或
// "程序坏了", 而实际程序一切正常, 排查方向完全被带偏。
//
// 这个坑在本项目真实发生过(早期版本用 -H windowsgui + 自绘任务栏窗口, 自绘窗口
// 因原生崩溃 0xC0000005 被移除后改回控制台方案), 所以用测试把构建产物钉死。
//
// 测试直接读 PE 头: 比"检查构建命令里有没有字符串"可靠得多 —— 后者无法发现
// 通过 GOFLAGS / 环境变量 / 其他方式注入的 -H windowsgui。
package main

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// peSubsystemConsole / peSubsystemWindowsGUI PE 可选头里的子系统取值
const (
	peSubsystemWindowsGUI = 2
	peSubsystemConsole    = 3
)

// readPESubsystem 读取 PE 文件的子系统类型。
//
// 定位过程: DOS 头 0x3C 处是 PE 签名偏移 -> 该偏移后 4 字节是 "PE\0\0" ->
// COFF 头 20 字节 -> 可选头起始, 子系统是可选头里偏移 0x44 的 uint16。
// (即文件内 = DOS 头 0x3C 取到的偏移 + 4 + 20 + 0x44)
func readPESubsystem(path string) (uint16, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var dos [64]byte
	if _, err := f.ReadAt(dos[:], 0); err != nil {
		return 0, err
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return 0, errors.New("不是有效的 PE 文件(缺少 MZ 签名)")
	}
	peOff := binary.LittleEndian.Uint32(dos[0x3C:0x40])

	var sig [4]byte
	if _, err := f.ReadAt(sig[:], int64(peOff)); err != nil {
		return 0, err
	}
	if sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0 {
		return 0, errors.New("不是有效的 PE 文件(缺少 PE 签名)")
	}

	// 可选头起点 = PE 签名(4) + COFF 头(20)
	var buf [2]byte
	subOff := int64(peOff) + 4 + 20 + 0x44
	if _, err := f.ReadAt(buf[:], subOff); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(buf[:]), nil
}

// TestBuiltMainExeIsConsoleSubsystem 若 exe 同目录已构建出主程序, 它必须是控制台子系统。
//
// 找不到产物时 Skip 而不是失败: 测试可能跑在未构建源码树上(CI 只跑 go test)。
// 这是条件性校验, 有产物就一定要合规。
func TestBuiltMainExeIsConsoleSubsystem(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("无法定位测试可执行文件")
	}
	sub, err := readPESubsystem(exe)
	if err != nil {
		t.Fatalf("读取自身 PE 头失败: %v", err)
	}
	// 关键断言: go test 编译出的测试二进制同样是主包构建参数下的产物,
	// 若构建流程里混入了 -H windowsgui, 这里就会先暴露出来。
	if sub != peSubsystemConsole {
		t.Fatalf("测试二进制子系统 = %d, 期望 %d(控制台)。"+
			"说明构建参数里混入了 -H windowsgui, 会导致服务端没有控制台窗口(只见页面)",
			sub, peSubsystemConsole)
	}
}

// TestConsoleSubsystemIfBuilt 检查构建脚本产出的 exe(存在则校验)
func TestConsoleSubsystemIfBuilt(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Skip("无法获取工作目录")
	}
	// 构建脚本现在的产物是**带平台后缀**的名字(不再另存短名 yugsight.exe, 原因
	// 见 scripts/build.ps1 循环内注释: 两个不同进程名的二进制并存会让旧实例占住
	// 端口提供旧路由表)。短名仍列在候选里, 只是为了覆盖历史上留下的旧产物。
	candidates := []string{
		filepath.Join(root, "dist", "yugsight_windows_amd64.exe"),
		filepath.Join(root, "yugsight_windows_amd64.exe"),
		filepath.Join(root, "yugsight.exe"),
		filepath.Join(root, "tmp-smoke", "yugsight.exe"),
	}
	checked := 0
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		sub, err := readPESubsystem(p)
		if err != nil {
			t.Errorf("%s: 读取 PE 头失败: %v", p, err)
			continue
		}
		checked++
		if sub != peSubsystemConsole {
			t.Errorf("%s 子系统 = %d, 期望 %d(控制台); "+
				"带 -H windowsgui 构建会让任务栏看不到控制台窗口", p, sub, peSubsystemConsole)
		}
	}
	if checked == 0 {
		t.Skip("尚未构建主程序 exe, 跳过(用 scripts/build.ps1 构建后再跑即可覆盖)")
	}
}
