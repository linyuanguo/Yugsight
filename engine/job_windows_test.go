//go:build windows

package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestTaskkillTreeFallback 直接验证降级路径 taskkillTree 本身:
// 派生"父 → 子"两级进程树, 对父进程执行 taskkill /T /F, 子进程必须一并消亡。
// 这条路径用于 Job Object 不可用的环境(受限会话 / 服务账户 / 已被外层 Job 包住),
// 是"递归 kill 子进程树"检查点在真实 Windows 上的兜底保证。
func TestTaskkillTreeFallback(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")

	// powershell 派生子进程(cmd 长 ping)并记录其 PID, 父进程随后长等待
	psCmd := "Start-Process -PassThru -WindowStyle Hidden -FilePath cmd -ArgumentList " +
		"'/c','ping -n 300 127.0.0.1 >nul' | " +
		"ForEach-Object { $_.Id | Out-File -FilePath '" + pidFile + "' -Encoding ascii }; " +
		"Start-Sleep 300"
	parent := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	if err := parent.Start(); err != nil {
		t.Skipf("powershell 不可用, 跳过降级路径验证: %v", err)
	}
	defer func() {
		_ = parent.Process.Kill()
		_ = parent.Wait()
	}()

	// 等子进程 PID 写入(Out-File 非原子写, 需重试解析)
	var childPid int
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if data, rerr := os.ReadFile(pidFile); rerr == nil {
			if n, aerr := strconv.Atoi(strings.TrimSpace(string(data))); aerr == nil && n > 0 && childAlive(n) {
				childPid = n
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if childPid == 0 {
		t.Skip("未能获取子进程 PID, 跳过降级路径验证")
	}

	// 走降级路径: taskkill /T /F 递归终止父进程及其子进程树
	if err := taskkillTree(parent.Process.Pid); err != nil {
		t.Fatalf("taskkillTree 应成功: %v", err)
	}

	if !waitProcessGone(childPid, 5*time.Second) {
		t.Fatalf("taskkill 降级路径未递归杀掉子进程 %d(残留进程)", childPid)
	}
}

// TestTaskkillTreeAlreadyGone 进程已消亡时 taskkill 返回非零(未找到进程),
// 应视为成功而非错误 —— 避免取消已自然结束的任务时报假错误。
func TestTaskkillTreeAlreadyGone(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "exit", "0")
	if err := cmd.Start(); err != nil {
		t.Skipf("cmd 不可用: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait() // 进程已退出(句柄对象可能尚未回收)

	if err := taskkillTree(pid); err != nil {
		t.Fatalf("进程已消亡时不应报错: %v", err)
	}
	if err := taskkillTree(0); err != nil {
		t.Fatalf("非法 PID 应静默返回: %v", err)
	}
}

// TestJobProcDegradeFlag 验证 Job 不可用时会置降级标记, 且 kill 仍能终止进程树。
func TestJobProcDegradeFlag(t *testing.T) {
	j := newJobProc()
	cmd := exec.Command("cmd", "/c", "ping", "-n", "300", "127.0.0.1", ">nul")
	j.apply(cmd)
	if err := cmd.Start(); err != nil {
		t.Skipf("cmd 不可用: %v", err)
	}
	j.attach(cmd.Process)
	defer j.release()

	// 无论 Job 是否可用, kill 都必须让进程消失
	if err := j.kill(); err != nil {
		t.Fatalf("kill 应成功: %v", err)
	}
	if !waitProcessGone(cmd.Process.Pid, 5*time.Second) {
		t.Fatalf("kill 后进程 %d 仍在运行", cmd.Process.Pid)
	}
	_ = cmd.Wait()
}
