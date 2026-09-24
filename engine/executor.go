// Package engine 本地外部引擎 CLI 执行器(任务 6.1: 外部引擎调度适配器)。
//
// 对 exe 同目录 ./bin/ 下三类引擎(nmapcore / trivycore / zapcore, 命名约定同
// envdetect 包)提供统一执行封装:
//
//   - 二进制查找: bin/ 内精确匹配 <前缀>[.exe] 优先, 否则前缀匹配
//     (nmapcore / nmapcore.exe / nmap-7.94.exe 均可命中);
//   - 参数组装: ArgsNmap / ArgsTrivyFS / ArgsTrivyImage / ArgsZap 提供各引擎
//     默认参数(输出格式与 normalizer 适配器 nmap -oJ / trivy -f json / zap -J 一致);
//   - 双捕获: stdout / stderr 分离捕获, 各有大小上限(默认 8MB), 超限丢弃剩余
//     并标记 Truncated, 防止引擎刷爆输出拖垮进程;
//   - 超时控制: 任务级 / 全局超时, 超时后递归终止整个进程树并标记 TimedOut;
//   - 生命周期管理: 任务注册进执行器, Cancel / Pause / CancelAll(任务暂停/取消
//     时)递归 kill 子进程树 ——
//     Windows 用 Job Object(KILL_ON_JOB_CLOSE + TerminateJobObject),
//     其它平台用独立进程组(Setpgid + kill(-pid)) ——
//     防止引擎残留子进程占用端口与系统资源;
//   - 异常容错: 引擎文件缺失、进程崩溃、执行超时均捕获为错误 + 日志,
//     不 panic, 不中断主服务。
//
// 纯标准库零第三方依赖; Windows 进程树实现见 job_windows.go(kernel32 FFI,
// Go 1.25 syscall 包已移除 Job Object 函数), 其它平台见 job_unix.go, 全平台可编译。
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 引擎名常量(bin/ 目录前缀, 与 envdetect 引擎命名一致:
// nmapcore / trivycore / zapcore 均可命中)
const (
	NameNmap  = "nmap"
	NameTrivy = "trivy"
	NameZap   = "zap"
)

const (
	// DefaultMaxOutput 默认单路(stdout/stderr)捕获上限(字节)
	DefaultMaxOutput = 8 * 1024 * 1024
	// DefaultTimeout 默认执行器的单任务超时(防止引擎挂死拖垮扫描任务)
	DefaultTimeout = 10 * time.Minute
)

// Config 执行器全局配置
type Config struct {
	// BinDir 引擎二进制目录, 缺省 = exe 同目录 ./bin/
	BinDir string
	// Timeout 单任务默认超时; 0 = 不超时(由调用方 context 控制)
	Timeout time.Duration
	// MaxOutput 单路输出捕获上限(字节), 0 = DefaultMaxOutput
	MaxOutput int
	// WorkDir 引擎工作目录(空 = 当前目录)
	WorkDir string
	// Env 附加环境变量(KEY=VALUE, 默认继承主进程)
	Env []string
}

// Spec 单次执行请求
type Spec struct {
	// Engine 引擎名(nmap / trivy / zap), 用于在 bin/ 目录查找二进制
	Engine string
	// Bin 显式二进制路径(非空时优先, Engine 仅用于日志)
	Bin string
	// Args 引擎参数
	Args []string
	// Stdin 可选的 stdin 内容
	Stdin string
	// Timeout 任务级超时(0 = 用 Config.Timeout)
	Timeout time.Duration
}

// Result 执行结果(所有异常路径均填充, 调用方据此降级)
type Result struct {
	ID        string        `json:"id"`
	Engine    string        `json:"engine"`
	Bin       string        `json:"bin"`
	Args      []string      `json:"args"`
	OK        bool          `json:"ok"`
	ExitCode  int           `json:"exitCode"`
	Duration  time.Duration `json:"duration"`
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	// Truncated 输出超过捕获上限被截断(JSON 类结果此时不可直接解析)
	Truncated bool `json:"truncated"`
	// Cancelled 任务被取消(暂停/取消)
	Cancelled bool `json:"cancelled"`
	// TimedOut 执行超时
	TimedOut bool `json:"timedOut"`
	// Error 失败原因说明(成功时为空)
	Error string `json:"error,omitempty"`
}

// RunningInfo 运行中任务信息(诊断 / 前端展示)
type RunningInfo struct {
	ID      string    `json:"id"`
	Engine  string    `json:"engine"`
	Bin     string    `json:"bin"`
	Args    []string  `json:"args"`
	Started time.Time `json:"started"`
}

// runState 运行中任务状态
type runState struct {
	id      string
	engine  string
	bin     string
	args    []string
	started time.Time
	cmd     *exec.Cmd
	job     *jobProc
	cancel  context.CancelFunc
}

// Executor 统一 CLI 执行器: 负责任务注册、双路输出捕获、进程树终止。
// 并发安全, 可全局共享一个实例。
type Executor struct {
	cfg  Config
	mu   sync.Mutex
	seq  int
	runs map[string]*runState
}

var (
	logMu sync.Mutex
	logf  = func(string) {}

	defOnce sync.Once
	def     *Executor
)

// SetLogger 注入主程序日志函数(并入 yugsight.log)
func SetLogger(f func(string)) {
	logMu.Lock()
	if f != nil {
		logf = f
	}
	logMu.Unlock()
}

func log(s string) {
	logMu.Lock()
	f := logf
	logMu.Unlock()
	f("引擎执行器: " + s)
}

// Default 返回全局默认执行器(bin/ = exe 同目录, 单任务超时 10 分钟)。
// 主服务退出前调用 CancelAll 清理残留引擎子进程。
func Default() *Executor {
	defOnce.Do(func() {
		def = NewExecutor(Config{Timeout: DefaultTimeout})
	})
	return def
}

// NewExecutor 创建执行器(缺省字段自动补默认值)
func NewExecutor(cfg Config) *Executor {
	if cfg.BinDir == "" {
		cfg.BinDir = defaultBinDir()
	}
	if cfg.MaxOutput <= 0 {
		cfg.MaxOutput = DefaultMaxOutput
	}
	if cfg.Timeout < 0 {
		cfg.Timeout = 0
	}
	return &Executor{cfg: cfg, runs: make(map[string]*runState)}
}

// defaultBinDir exe 同目录的 bin/(与 envdetect 约定一致)
func defaultBinDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(".", "bin")
	}
	return filepath.Join(filepath.Dir(exe), "bin")
}

// Run 同步执行引擎直到完成(或超时/取消), 返回结果:
//
//  1. 定位二进制(显式 Bin > bin/ 前缀查找);
//  2. 注册任务、启动子进程并挂接进程树(Job Object / 独立进程组);
//  3. 等待退出; ctx 取消或超时时先递归 kill 整个进程树再返回。
//
// 引擎缺失 / 启动失败 / 超时 / 取消 / 非零退出 / 进程崩溃均返回错误与 Result,
// 全程不 panic, 由调用方决定降级方式(如切换回内置引擎)。
func (e *Executor) Run(ctx context.Context, spec Spec) (res *Result, err error) {
	// 顶层兜底: 任何意外都转成错误返回, 不击穿主服务
	defer func() {
		if r := recover(); r != nil {
			log(fmt.Sprintf("执行器内部异常(engine=%s): %v", spec.Engine, r))
			res = &Result{Engine: spec.Engine, OK: false,
				Error: fmt.Sprintf("执行器内部异常: %v", r)}
			err = fmt.Errorf("执行器内部异常: %v", r)
		}
	}()

	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		isTimeout := errors.Is(ctx.Err(), context.DeadlineExceeded)
		return &Result{
			Engine:   spec.Engine,
			Args:     spec.Args,
			Cancelled: !isTimeout,
			TimedOut: isTimeout,
			Error:    "上下文已结束: " + ctx.Err().Error(),
		}, ctx.Err()
	}

	bin := strings.TrimSpace(spec.Bin)
	if bin == "" {
		b, ferr := e.findBin(spec.Engine)
		if ferr != nil {
			log("引擎二进制未找到: " + ferr.Error())
			return &Result{Engine: spec.Engine, OK: false, Error: ferr.Error()}, ferr
		}
		bin = b
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = e.cfg.Timeout
	}
	// 超时 ctx 的 cancel 必须显式 defer 释放(setupTimeoutCtx 内部处理),
	// 否则 go vet 报 lostcancel, 且定时器会一直挂到超时点。
	runCtx, cancel := setupTimeoutCtx(ctx, timeout)
	defer cancel()

	cmd := exec.Command(bin, spec.Args...)
	cmd.Dir = e.cfg.WorkDir
	if len(e.cfg.Env) > 0 {
		// Go 1.25 移除了 Cmd.ExtraEnv, 用完整 Env(继承 + 附加)
		cmd.Env = append(os.Environ(), e.cfg.Env...)
	}

	stdout := newCappedWriter(e.cfg.MaxOutput)
	stderr := newCappedWriter(e.cfg.MaxOutput)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if spec.Stdin != "" {
		cmd.Stdin = strings.NewReader(spec.Stdin)
	}

	job := newJobProc()
	job.apply(cmd)

	started := time.Now()
	if serr := cmd.Start(); serr != nil {
		job.release()
		log(fmt.Sprintf("引擎启动失败: engine=%s bin=%s err=%s", spec.Engine, bin, serr.Error()))
		werr := fmt.Errorf("引擎进程启动失败: %w", serr)
		return &Result{Engine: spec.Engine, Bin: bin, Args: spec.Args,
			OK: false, Error: werr.Error()}, werr
	}
	job.attach(cmd.Process)

	id := e.register(spec.Engine, bin, spec.Args, started, cmd, job, cancel)
	defer e.deregister(id)
	defer job.release()

	log(fmt.Sprintf("引擎任务启动: id=%s engine=%s bin=%s args=[%s]",
		id, spec.Engine, bin, strings.Join(spec.Args, " ")))

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var waitErr error
	killed, killedTimeout := false, false
	select {
	case waitErr = <-done:
	case <-runCtx.Done():
		killed = true
		killedTimeout = errors.Is(runCtx.Err(), context.DeadlineExceeded)
		e.killTree(id)
		reason := "取消"
		if killedTimeout {
			reason = "超时"
		}
		log(fmt.Sprintf("引擎任务%s: id=%s engine=%s", reason, id, spec.Engine))
		select {
		case waitErr = <-done:
		case <-time.After(3 * time.Second):
			// 极端情况: 有子进程逃出了进程树仍占着输出管道。
			// 进程树实际已被终止, 先返回; 残留的 Wait goroutine 会在
			// 子进程退出后自行结束(此处留痕)
			waitErr = context.Canceled
			log("警告: 终止进程树后等待输出管道超过 3s, 可能存在树外残留子进程 (id=" + id + ")")
		}
	}

	duration := time.Since(started)
	res = &Result{
		ID:        id,
		Engine:    spec.Engine,
		Bin:       bin,
		Args:      spec.Args,
		Duration:  duration,
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: stdout.Overflowed() || stderr.Overflowed(),
	}

	switch {
	case killed && killedTimeout:
		res.TimedOut = true
		res.Error = fmt.Sprintf("执行超时(超过 %s), 进程树已终止", timeout)
		err = errors.New(res.Error)
	case killed:
		res.Cancelled = true
		res.Error = "任务被取消(暂停/取消), 进程树已终止"
		err = errors.New(res.Error)
	default:
		switch werr := waitErr.(type) {
		case nil:
			res.OK = true
			log(fmt.Sprintf("引擎任务完成: id=%s engine=%s 耗时=%s 输出=%dB/%dB",
				id, spec.Engine, res.Duration, len(res.Stdout), len(res.Stderr)))
		case *exec.ExitError:
			res.ExitCode = werr.ExitCode()
			if res.ExitCode < 0 {
				res.Error = fmt.Sprintf("引擎进程异常崩溃(退出码 %d, stderr: %s)",
					res.ExitCode, tail(stderr.String(), 200))
			} else {
				res.Error = fmt.Sprintf("引擎进程以退出码 %d 结束(stderr: %s)",
					res.ExitCode, tail(stderr.String(), 200))
			}
			log(fmt.Sprintf("引擎任务非零退出: id=%s engine=%s code=%d",
				id, spec.Engine, res.ExitCode))
			err = fmt.Errorf("引擎进程退出码 %d", res.ExitCode)
		default:
			res.Error = "执行错误: " + werr.Error()
			err = werr
			log("引擎任务执行错误: id=" + id + " engine=" + spec.Engine + " err=" + werr.Error())
		}
	}
	return res, err
}

// setupTimeoutCtx 组合超时与取消: timeout<=0 时仅返回可取消 ctx。
// 返回的 cancel 释放全部内部资源(含超时定时器)。
func setupTimeoutCtx(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

// Cancel 取消指定任务: 递归终止整个进程树(含引擎派生的所有子进程)。
// 对应 Run 立即返回 Cancelled 的 Result。任务不存在或已结束返回 false。
func (e *Executor) Cancel(id string) bool {
	e.mu.Lock()
	rs := e.runs[id]
	e.mu.Unlock()
	if rs == nil {
		return false
	}
	log("任务取消: id=" + id + " engine=" + rs.engine)
	rs.cancel()
	return true
}

// Pause 任务"暂停": 外部引擎是一次性 CLI 进程, 无进程级挂起能力,
// 暂停语义按终止实现(等价 Cancel), 已产出的输出随 Result 保留, 供重跑/续扫。
func (e *Executor) Pause(id string) bool {
	return e.Cancel(id)
}

// CancelAll 取消全部运行中任务(主服务退出时调用, 防引擎残留进程),
// 返回被取消的任务数。
func (e *Executor) CancelAll() int {
	e.mu.Lock()
	ids := make([]string, 0, len(e.runs))
	for id := range e.runs {
		ids = append(ids, id)
	}
	e.mu.Unlock()
	for _, id := range ids {
		e.mu.Lock()
		rs := e.runs[id]
		e.mu.Unlock()
		if rs != nil {
			rs.cancel()
		}
	}
	if len(ids) > 0 {
		log(fmt.Sprintf("批量取消引擎任务: %d 个", len(ids)))
	}
	return len(ids)
}

// Running 返回当前运行中的任务列表
func (e *Executor) Running() []RunningInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RunningInfo, 0, len(e.runs))
	for _, rs := range e.runs {
		out = append(out, RunningInfo{
			ID: rs.id, Engine: rs.engine, Bin: rs.bin,
			Args: rs.args, Started: rs.started,
		})
	}
	return out
}

func (e *Executor) register(engine, bin string, args []string, started time.Time, cmd *exec.Cmd, job *jobProc, cancel context.CancelFunc) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	id := "eng-" + strconv.Itoa(e.seq)
	e.runs[id] = &runState{
		id: id, engine: engine, bin: bin, args: args,
		started: started, cmd: cmd, job: job, cancel: cancel,
	}
	return id
}

func (e *Executor) deregister(id string) {
	e.mu.Lock()
	delete(e.runs, id)
	e.mu.Unlock()
}

// killTree 终止任务对应的整个进程树(主进程 + 引擎递归派生的所有子进程)
func (e *Executor) killTree(id string) {
	e.mu.Lock()
	rs := e.runs[id]
	e.mu.Unlock()
	if rs == nil {
		return
	}
	if kerr := rs.job.kill(); kerr != nil {
		log(fmt.Sprintf("警告: 进程树终止未完全生效 (id=%s): %s", id, kerr.Error()))
	}
	if rs.cmd != nil && rs.cmd.Process != nil {
		_ = rs.cmd.Process.Kill() // 兜底: 再 kill 一次主进程
	}
}

// findBin 按 envdetect 约定在 bin/ 目录查找引擎二进制:
// 精确匹配 <前缀>[.exe] 优先, 否则取任意以 <前缀> 开头的可执行文件
// (nmapcore / nmapcore.exe / nmap-7.94.exe 均可命中)。
// 目录缺失 / 未命中返回错误(引擎为可选外部资源, 调用方降级即可)。
func (e *Executor) findBin(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("引擎名为空")
	}
	dir := e.cfg.BinDir
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		return "", fmt.Errorf("引擎目录不存在或不可读: %s (%s)", dir, rerr.Error())
	}
	prefix := strings.ToLower(name)
	isWin := runtime.GOOS == "windows"
	var loose string
	for _, en := range entries {
		if en.IsDir() {
			continue
		}
		n := strings.ToLower(en.Name())
		if isWin && !strings.HasSuffix(n, ".exe") {
			continue
		}
		if !isWin && strings.Contains(n, ".") {
			continue
		}
		if n == prefix || n == prefix+".exe" {
			return filepath.Join(dir, en.Name()), nil
		}
		if strings.HasPrefix(n, prefix) && loose == "" {
			loose = en.Name()
		}
	}
	if loose != "" {
		return filepath.Join(dir, loose), nil
	}
	// 套装引擎(nmap): 入口在 bin/nmapcore/ 子目录内(engmgr 整包落位), 顶层扫不到。
	// 没有这一步会表现为"nmap 明明装好了, 扫描时却报引擎未找到"。
	if p, ok := findBinInSubdir(dir, prefix, isWin); ok {
		return p, nil
	}
	// bin/ 与套装子目录都没有 -> 回退系统 PATH: 覆盖"引擎是第三方自装(apt/brew 装到
	// PATH)而非放进 exe 同目录 bin/"的场景。name 是基础命令名(nmap/trivy/zap/nuclei),
	// LookPath 直接按它查 PATH; 找不到才报"未安装"(引擎为可选, 调用方降级, 不 panic)。
	// 用 pathLookup 变量(而非直接 exec.LookPath)是为了让测试能注入"PATH 无此引擎"的
	// 确定性环境 —— 开发机上 PATH 可能有 nmap, 直接调用会让"空目录应报未找到"用例漂移。
	if lp, lerr := pathLookup(name); lerr == nil {
		return lp, nil
	}
	return "", fmt.Errorf("引擎 %s 未找到(bin 目录 %s 无匹配, 系统 PATH 中亦无 %s)", name, dir, name)
}

// pathLookup 系统 PATH 查询的可注入实现(默认 exec.LookPath, 测试可替换)。
var pathLookup = exec.LookPath

// findBinInSubdir 在 bin/<prefix>* 子目录中递归查找可执行入口(供多文件套装引擎使用)。
// 目录名以 prefix 开头即视为该引擎的套装目录, 避免扫到别的引擎。
//
// 【为什么 Windows 还要认 .bat】nmap 的入口是 nmap.exe, 但 ZAP 的 Windows 入口是
// **zap.bat**(官方跨平台免安装包里根本没有 zap.exe —— 它靠 .bat 拼 java 命令行再跑
// zap.jar)。只认 .exe 会让"装好的 ZAP"被判为未安装。
//
// 优先级刻意是 .exe > .bat: 若用户自行放了真正的 exe 启动器(或未来官方提供),
// 优先用它 —— .bat 需要 shell 包装才能执行(见 runCommand), 路径更曲折。
func findBinInSubdir(dir, prefix string, isWin bool) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, en := range entries {
		if !en.IsDir() {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(en.Name()), prefix) {
			continue
		}
		var exeHit, batHit string
		_ = filepath.Walk(filepath.Join(dir, en.Name()), func(p string, info os.FileInfo, werr error) error {
			if werr != nil || info == nil || info.IsDir() {
				return nil
			}
			n := strings.ToLower(info.Name())
			if isWin {
				if !strings.HasPrefix(n, prefix) {
					return nil
				}
				switch {
				case strings.HasSuffix(n, ".exe") && exeHit == "":
					exeHit = p
				case strings.HasSuffix(n, ".bat") && batHit == "":
					batHit = p
				}
			} else if !strings.Contains(n, ".") && strings.HasPrefix(n, prefix) && exeHit == "" {
				exeHit = p
			}
			return nil
		})
		if exeHit != "" {
			return exeHit, true
		}
		if batHit != "" {
			return batHit, true
		}
	}
	return "", false
}

// cappedWriter 带大小上限的写入流: 写满即停止(丢弃剩余),
// 永不阻塞、永不无限占用内存 —— 防止引擎输出巨大拖垮主进程。
type cappedWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	max  int
	over bool
}

func newCappedWriter(max int) *cappedWriter {
	if max <= 0 {
		max = DefaultMaxOutput
	}
	return &cappedWriter{max: max}
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.over || c.buf.Len() >= c.max {
		c.over = true
		return len(p), nil
	}
	if n := c.max - c.buf.Len(); len(p) > n {
		c.buf.Write(p[:n])
		c.over = true
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}

func (c *cappedWriter) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *cappedWriter) Overflowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.over
}

// tail 取字符串末尾 n 个字符(日志摘要用)
func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "..." + string(r[len(r)-n:])
}
