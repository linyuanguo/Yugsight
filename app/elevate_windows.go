//go:build windows

package main

import (
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	advapi32              = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken  = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
	procCloseHandle       = kernel32.NewProc("CloseHandle")
	procShellExecuteW     = shell32.NewProc("ShellExecuteW")
	procCreateMutexW      = kernel32.NewProc("CreateMutexW")
)

const (
	processQueryInformation = 0x0400
	tokenElevation          = 2
	swShownormal            = 1
	errAlreadyExists        = 183 // ERROR_ALREADY_EXISTS
)

// isAdmin 判断当前进程是否以管理员(提升)权限运行
func isAdmin() bool {
	var token uintptr
	// 当前进程伪句柄 (HANDLE)-1
	if r, _, _ := procOpenProcessToken.Call(^uintptr(0), processQueryInformation, uintptr(unsafe.Pointer(&token))); r == 0 {
		return false
	}
	defer procCloseHandle.Call(token)
	var elevated uint32
	var returned uintptr
	if r, _, _ := procGetTokenInformation.Call(token, tokenElevation, uintptr(unsafe.Pointer(&elevated)), 4, uintptr(unsafe.Pointer(&returned))); r == 0 {
		return false
	}
	return elevated != 0
}

// ensureSingleInstance 防止重复启动: 已有实例运行时提示并退出
// (双击多次、提权 re-exec 等场景都会触发)
func ensureSingleInstance() {
	name, _ := syscall.UTF16PtrFromString(`Local\Yugsight`)
	h, _, lastErr := procCreateMutexW.Call(uintptr(unsafe.Pointer(name)), 0, 0)
	if h == 0 || lastErr.(syscall.Errno) != errAlreadyExists {
		return
	}
	showMessage(appName+" 已在运行",
		"检测到另一个 "+appName+" 实例正在运行(请查看 "+appName+" 控制台窗口或已打开的浏览器页面)。\n若认为其实未运行, 请在任务管理器中结束 "+appName+" 主程序进程后重试。")
	os.Exit(0)
}

// ensureAdmin 未以管理员运行时, 通过 UAC 提权重启自身:
//   - 提权请求发出后当前进程立即退出, 新(管理员)进程带 -elevated 继续执行, 结构上不可能循环提权
//   - UAC 60 秒无响应(如远程桌面等弹不出确认框的会话)则降级为普通权限继续运行, 绝不挂死
func ensureAdmin() {
	if isAdmin() {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	args := strings.Join(append(append([]string{}, os.Args[1:]...), "-elevated"), " ")
	pVerb, _ := syscall.UTF16PtrFromString("runas")
	pExe, _ := syscall.UTF16PtrFromString(exe)
	pArgs, _ := syscall.UTF16PtrFromString(args)
	ch := make(chan uintptr, 1)
	go func() {
		r, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(pVerb)), uintptr(unsafe.Pointer(pExe)), uintptr(unsafe.Pointer(pArgs)), 0, swShownormal)
		ch <- r
	}()
	select {
	case ret := <-ch:
		if ret <= 32 {
			showMessage(appName+" 需要管理员权限",
				"启动被拒绝: 本工具默认以管理员身份运行(ICMP ping 等探测需要管理员权限)。\n\n若你取消了 UAC 确认框, 请重新运行; 或加参数 -no-admin 以普通权限启动(此时 ICMP 不可用)。")
			os.Exit(1)
		}
		// 提权请求已发出, 退出当前普通权限进程
		os.Exit(0)
	case <-time.After(60 * time.Second):
		logLine("UAC 提权 60 秒无响应, 降级为普通权限运行(ICMP ping 将不可用)")
		showMessage(appName+" 无法弹出 UAC 确认框",
			"当前会话(如远程桌面)可能无法弹出 UAC 确认框。\n将降级为普通权限运行: ICMP ping 不可用, 其余功能正常。")
	}
}
