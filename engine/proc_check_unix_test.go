//go:build !windows

package engine

import (
	"syscall"
	"time"
)

// processGone 判断进程是否已消亡(Unix: kill(pid, 0) 返回 ESRCH = 不存在)。
// 仅测试用。
func processGone(pid int) bool {
	if pid <= 0 {
		return true
	}
	return syscall.Kill(pid, 0) == syscall.ESRCH
}

// childAlive 判断进程当前是否存活(用于排除"读到半截 PID 文件"造成的假阳性)。
func childAlive(pid int) bool { return !processGone(pid) }

// waitProcessGone 轮询等待进程消亡(终止是异步的, 给内核回收时间), 上限 wait。
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
