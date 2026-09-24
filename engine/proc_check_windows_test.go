//go:build windows

package engine

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32test  = syscall.NewLazyDLL("kernel32.dll")
	procOpenProc  = kernel32test.NewProc("OpenProcess") // 直连 FFI, 避免 syscall 包装层懒加载状态
	procWaitObj   = kernel32test.NewProc("WaitForSingleObject")
	procCloseHnd  = kernel32test.NewProc("CloseHandle")
	procEnumProcs = syscall.NewLazyDLL("psapi.dll").NewProc("EnumProcesses")
)

const (
	processQueryLimitedInformation = 0x1000
	syncObjectWaitTimeout          = 0x00000102 // WAIT_TIMEOUT
)

// openProcHandle 打开进程句柄(失败返回 0)
func openProcHandle(pid int) uintptr {
	h, _, _ := procOpenProc.Call(processQueryLimitedInformation, 0, uintptr(uint32(pid)))
	return h
}

// procTerminated 判断"该 PID 当前是否对应一个已终止执行的进程"。
//
// 单一判据都不可靠, 此处三条判据取"任一成立即已终止":
//  1. OpenProcess 失败          → PID 无对应进程(已完全回收);
//  2. WaitForSingleObject 立即有信号 → 进程已终止(句柄对象可能尚未回收);
//  3. PID 不在系统进程快照中    → 与 tasklist 口径一致(兜底)。
//
// 单独用 1 或 2 会出现在本沙箱中观察到的假阳性: 读到的 PID 与目标子进程并非同一
// 对象(文件写入/关闭竞态), 此时对象仍"活着"但快照里根本没有该 PID。
func procTerminated(pid int) bool {
	if pid <= 0 {
		return true
	}
	h := openProcHandle(pid)
	if h == 0 {
		return true
	}
	r, _, _ := procWaitObj.Call(h, 0)
	_, _, _ = procCloseHnd.Call(h)
	if r == 0 { // WAIT_OBJECT_0
		return true
	}
	return !pidInSnapshot(pid)
}

// pidInSnapshot 用 EnumProcesses 取全系统 PID 快照, 判断 pid 是否在其中
// (等价 tasklist, 但不依赖外部命令与输出解析)。
func pidInSnapshot(pid int) bool {
	const maxProcs = 8192
	pids := make([]uint32, maxProcs)
	var needed uint32
	r, _, _ := procEnumProcs.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)*4),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 {
		return true // 快照失败: 保守认为存在, 交由前两条判据决定
	}
	n := int(needed) / 4
	if n > len(pids) {
		n = len(pids)
	}
	for i := 0; i < n; i++ {
		if int(pids[i]) == pid {
			return true
		}
	}
	return false
}

// processGone 判断进程是否已消亡(仅测试用)
func processGone(pid int) bool { return procTerminated(pid) }

// childAlive 判断进程当前是否存活(用于排除"读到半截 PID 文件"造成的假阳性)。
func childAlive(pid int) bool { return !procTerminated(pid) }

// waitProcessGone 轮询等待进程消亡(终止是异步的, 给系统回收时间), 上限 wait。
// 仅测试用。
func waitProcessGone(pid int, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		if processGone(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}
