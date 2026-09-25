//go:build windows

package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Windows 进程树终止: Job Object(首选) + taskkill /T /F(降级兜底)。
//
// 为什么需要降级: Job Object 是内核级进程树容器, 递归终止最彻底, 但它需要
// 当前进程具备创建 / 配置 Job 的权限。以下环境里 CreateJobObject 成功但
// SetInformationJobObject 返回 ERROR_BAD_LENGTH(24)、AssignProcessToJobObject
// 返回 Access is denied —— 典型如受限会话 / 服务账户 / 已被外层 Job 包住的进程。
// 因此本文件把 Job Object 当作"可选增强":
//
//  1. apply(Start 前): 创建 Job 并开启 KILL_ON_JOB_CLOSE; 任一步失败即记日志并
//     把该任务标记为 job 不可用(不返回错误, 不影响引擎执行);
//  2. attach(Start 后): 把引擎进程加入 Job; 失败同样降级;
//  3. kill(取消 / 超时 / 暂停): Job 可用 → TerminateJobObject 一次性终止整棵树;
//     Job 不可用 → taskkill /T /F /PID <pid> 递归终止进程树(系统自带命令,
//     无需 Job 权限), 最后再用 Process.Kill 兜底主进程。
//
// 两条路径都保证"不留残留子进程、不占用端口与系统资源"这一检查点。
//
// 注: Go 1.25 的 syscall 包已移除 Job Object 系列函数, 此处走 kernel32.dll FFI
// (与 envdetect_windows.go 注册表 FFI 同风格)。

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW   = kernel32.NewProc("CreateJobObjectW")
	procSetInfoJobObject   = kernel32.NewProc("SetInformationJobObject")
	procAssignProcToJob    = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject = kernel32.NewProc("TerminateJobObject")
)

const (
	// JobObjectExtendedLimitInformation = 6 (winnt.h 枚举值; 早期误写成 9 会导致
	// SetInformationJobObject 返回 ERROR_BAD_LENGTH)
	jobObjectExtendedLimitInformation = 6
	jobObjectLimitKillOnJobClose      = 0x00002000
	processSetQuota                   = 0x0100 // AssignProcessToJobObject 所需访问权

	// createNoWindow = CREATE_NO_WINDOW: 子进程不分配控制台窗口。
	// 主程序是控制台子系统(见 scripts/build.ps1: 绝不能用 -H windowsgui), 它与主程序
	// **共用同一个控制台**; 若不给引擎子进程加这个标志, 每个引擎进程都会在任务栏多出
	// 一个控制台窗口, 用户会以为"启动了多个服务", 关窗还可能顺手关掉正在跑的扫描。
	createNoWindow = 0x08000000

	// taskkillTimeout 单个任务 taskkill 的执行上限(防止降级路径自身挂死)
	taskkillTimeout = 10 * time.Second
)

// jobBasicLimit JOBOBJECT_BASIC_LIMIT_INFORMATION(布局与 Windows SDK 一致,
// Go 结构体对齐规则保证与 C 布局相同)
type jobBasicLimit struct {
	PerProcessJobMemoryLimit int64
	PerJobMemoryLimit        int64
	LimitFlags               uint32
	MinimumWorkingSetSize    int64
	MaximumWorkingSetSize    int64
	ActiveProcessLimit       uint32
	Affinity                 uintptr
	PriorityClass            uint32
	SchedulingClass          uint32
}

// jobIO JOBOBJECT_IO_LIMIT_INFORMATION
type jobIO struct {
	AllowPrioBoost                 int32
	ReadRateControlBytesPerSecond  int64
	WriteRateControlBytesPerSecond int64
}

// jobExtendedLimit JOBOBJECT_EXTENDED_LIMIT_INFORMATION
type jobExtendedLimit struct {
	BasicLimitInformation jobBasicLimit
	IoInfo                jobIO
	ProcessMemoryLimit    int64
	JobMemoryLimit        int64
	PeakProcessMemoryUsed int64
	PeakJobMemoryUsed     int64
}

// jobProc 进程树句柄(Job Object 句柄 + 降级所需的进程 PID); 其它平台见 job_unix.go
type jobProc struct {
	mu     sync.Mutex
	h      syscall.Handle
	pid    int
	degrad bool // Job 不可用, 走 taskkill 降级路径
}

func newJobProc() *jobProc {
	return &jobProc{}
}

// apply 在 cmd.Start() 前调用: 屏蔽子进程控制台窗口 + 创建 Job 并开启 KILL_ON_JOB_CLOSE。
// 失败不返回错误(Job 为可选增强), 由 attach 决定是否降级。
func (j *jobProc) apply(cmd *exec.Cmd) {
	// 引擎子进程无需自己的控制台(输出经管道捕获), 复用主程序控制台会在任务栏
	// 多出窗口; CREATE_NO_WINDOW 让它彻底无窗口。
	// 注意不要用 HideWindow(那只是"窗口隐藏", 控制台进程仍会被创建出来)。
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}

	j.mu.Lock()
	defer j.mu.Unlock()
	r, _, err := procCreateJobObjectW.Call(0, 0)
	if r == 0 {
		j.degrad = true
		logQuiet("警告: 创建 Job Object 失败, 进程树终止降级为 taskkill: " + callErr(err))
		return
	}
	j.h = syscall.Handle(r)

	info := jobExtendedLimit{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	sr, _, serr := procSetInfoJobObject.Call(
		uintptr(j.h),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)
	if sr == 0 {
		// KILL_ON_JOB_CLOSE 没设上: Job 仍可能可用, 但不保证句柄关闭时杀进程,
		// 保守起见直接降级, 走 taskkill(其行为确定且可验证)。
		j.degrad = true
		_ = syscall.CloseHandle(j.h)
		j.h = 0
		logQuiet("警告: 配置 Job Object 失败, 进程树终止降级为 taskkill: " + callErr(serr))
	}
}

// attach 在 cmd.Start() 后调用: 把引擎进程加入 Job。
// Go 1.25 移除了 Process.Handle(), 用 OpenProcess 重开带 PROCESS_SET_QUOTA
// 权限的句柄来执行加入操作(该权限是 AssignProcessToJobObject 的必要条件)。
// 加入失败(权限不足 / 进程已在其它 Job 中)时降级为 taskkill。
func (j *jobProc) attach(proc *os.Process) {
	if proc == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.pid = proc.Pid
	if j.h == 0 {
		j.degrad = true
		return
	}
	p, err := syscall.OpenProcess(processSetQuota, false, uint32(proc.Pid))
	if err != nil {
		j.degrad = true
		logQuiet(fmt.Sprintf("警告: 打开进程句柄失败(pid=%d), 进程树终止降级为 taskkill: %v",
			proc.Pid, err))
		return
	}
	defer syscall.CloseHandle(p)
	ar, _, aerr := procAssignProcToJob.Call(uintptr(j.h), uintptr(p))
	if ar == 0 {
		j.degrad = true
		logQuiet(fmt.Sprintf("警告: 加入 Job Object 失败(pid=%d), 进程树终止降级为 taskkill: %s",
			proc.Pid, callErr(aerr)))
	}
}

// kill 递归终止整个进程树(主进程 + 引擎派生的全部子进程):
// Job 可用走 TerminateJobObject; 否则走 taskkill /T /F(递归终止子进程树)。
func (j *jobProc) kill() error {
	j.mu.Lock()
	h, pid, degrad := j.h, j.pid, j.degrad
	j.mu.Unlock()

	if h != 0 && !degrad {
		if r, _, _ := procTerminateJobObject.Call(uintptr(h), 1); r != 0 {
			return nil
		}
		// Job 终止未生效(句柄失效 / 引擎已逃出 Job): 降级 taskkill 兜底,
		// 失败时把两条路径的原因一并带回, 便于排查残留进程
		tkErr := taskkillTree(pid)
		if tkErr != nil {
			logQuiet(fmt.Sprintf("警告: 终止进程树失败(pid=%d): Job 与 taskkill 均未生效(%v)",
				pid, tkErr))
			return tkErr
		}
		return nil
	}
	return taskkillTree(pid)
}

// release 关闭 Job 句柄(KILL_ON_JOB_CLOSE 生效时兼作残留进程的最后清理)
func (j *jobProc) release() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.h != 0 {
		_ = syscall.CloseHandle(j.h)
		j.h = 0
	}
}

// taskkillTree 用系统自带 taskkill 递归终止进程树(降级路径, 无需 Job 权限)。
// 进程已退出时 taskkill 返回非零(未找到进程), 视为成功。
func taskkillTree(pid int) error {
	if pid <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), taskkillTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)) //nolint:gosec // 参数为执行器内部 PID
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("taskkill 超时: %w", err)
		}
		if processGoneInProc(pid) {
			return nil // 树已消亡, taskkill 报未找到属正常
		}
		return err
	}
	return nil
}

// processGoneInProc 判断 PID 当前是否对应一个"已终止"的进程(生产路径用)。
//
// 与测试辅助 processGone(procTerminated) 采用同一组判据, 只是这里用 syscall
// 包装层而非直连 FFI —— 二者对"终止"的判定必须一致, 否则会出现测试通过而
// 线上误判的割裂。
//
// 【为什么 OpenProcess 成功不能算"还活着"】taskkill 对已退出但句柄未回收的
// 进程会报 ERRORLEVEL 128("没有找到进程"), 此时 OpenProcess 仍可能成功
// (句柄对象尚未回收)、但 WaitForSingleObject 立即返回有信号。若只判
// OpenProcess, 这种情况会被误判为"进程仍在"→ taskkillTree 上报错误 →
// 上层把"进程其实已消亡"当成终止失败(本仓库引擎测试中表现为 flaky 失败)。
func processGoneInProc(pid int) bool {
	if pid <= 0 {
		return true
	}
	const processQueryLimitedInformation = 0x1000
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return true // 无对应进程: 已完全回收
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	// WaitForSingleObject(h, 0): WAIT_OBJECT_0(0) = 已终止; WAIT_TIMEOUT(258) = 仍在运行
	ev, werr := syscall.WaitForSingleObject(h, 0)
	if werr != nil {
		return false // 等待失败: 保守认为仍在运行, 交由上层按错误处理
	}
	return ev == uint32(syscall.WAIT_OBJECT_0)
}

// callErr 取 LazyProc.Call 返回的 error 文本(LazyProc.Call 在调用成功时
// 返回的 err 为 "The operation completed successfully." 之类的固定文本,
// 因此仅作日志展示用, 不用于判定成功与否)
func callErr(err error) string {
	if err == nil {
		return "未知错误"
	}
	return err.Error()
}

// logQuiet 生产日志(与 executor.go 的 log 同通道; 独立函数便于本文件自包含)
func logQuiet(s string) { log(s) }
