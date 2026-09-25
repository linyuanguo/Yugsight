//go:build !windows

package engine

import (
	"os"
	"os/exec"
	"syscall"
)

// Linux / macOS 进程树终止: 独立进程组方案。
//
// 引擎子进程启动时置 SysProcAttr.Setpgid(自成进程组, 子进程为组长),
// 取消 / 超时用 kill(-pid, SIGKILL) 击杀整个进程组 ——
// 内核会把组内所有进程(主进程 + 引擎递归派生的全部子进程)一并杀掉,
// 无残留子进程、不占用端口与系统资源。

// jobProc 进程组句柄; Windows 实现见 job_windows.go(Job Object 方案)
type jobProc struct {
	pgid int
}

func newJobProc() *jobProc {
	return &jobProc{}
}

// apply 在 cmd.Start() 前调用: 让子进程进入独立进程组
func (j *jobProc) apply(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// attach 在 cmd.Start() 后调用: 记录进程组 ID(= 子进程 pid, 组长)
func (j *jobProc) attach(proc *os.Process) {
	j.pgid = proc.Pid
}

// kill 终止整个进程组(主进程 + 全部子进程)。
// 进程组已消亡时 kill 返回 ESRCH, 视为成功(与 Windows 降级路径语义一致)。
func (j *jobProc) kill() error {
	if j.pgid > 0 {
		if err := syscall.Kill(-j.pgid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
	}
	return nil
}

// release Unix 下无内核资源需要释放
func (j *jobProc) release() {}
