package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ===== 跨平台测试命令辅助(只用系统自带命令) =====

// sleepArgs 返回"睡眠 60 秒"的跨平台命令
func sleepArgs() (bin string, args []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/c", "ping", "-n", "60", "127.0.0.1", ">nul"}
	}
	return "sh", []string{"-c", "sleep 60"}
}

func echoArgs(msg string, toStderr bool) (bin string, args []string) {
	if runtime.GOOS == "windows" {
		if toStderr {
			return "cmd", []string{"/c", "echo", msg, "1>&2"}
		}
		return "cmd", []string{"/c", "echo", msg}
	}
	if toStderr {
		return "sh", []string{"-c", "echo " + msg + " >&2"}
	}
	return "sh", []string{"-c", "echo " + msg}
}

func exitArgs(code int) (bin string, args []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/c", "exit", strconv.Itoa(code)}
	}
	return "sh", []string{"-c", "exit " + strconv.Itoa(code)}
}

func newTestExecutor(t *testing.T, cfg Config) *Executor {
	t.Helper()
	if cfg.BinDir == "" {
		cfg.BinDir = t.TempDir() // 空 bin 目录(覆盖"引擎未找到"路径)
	}
	if cfg.MaxOutput == 0 {
		cfg.MaxOutput = 64 * 1024
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second // 全局兜底, 防用例挂死
	}
	return NewExecutor(cfg)
}

// waitForTask 等待执行器中运行任务数达到 n, 返回其中一个任务 ID
func waitForTask(t *testing.T, e *Executor, n int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rs := e.Running(); len(rs) == n {
			return rs[0].ID
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待运行中任务(%d 个)超时", n)
	return ""
}

func TestRunOK(t *testing.T) {
	e := newTestExecutor(t, Config{})
	bin, args := echoArgs("hello-engine", false)
	res, err := e.Run(context.Background(), Spec{Bin: bin, Args: args})
	if err != nil {
		t.Fatalf("成功执行不应返回错误: %v", err)
	}
	if !res.OK || res.ExitCode != 0 {
		t.Fatalf("应成功: %+v", res)
	}
	if !strings.Contains(res.Stdout, "hello-engine") {
		t.Fatalf("stdout 未捕获: %q", res.Stdout)
	}
	if res.ID == "" {
		t.Fatal("任务应有 ID")
	}
}

func TestRunStderrCaptured(t *testing.T) {
	e := newTestExecutor(t, Config{})
	bin, args := echoArgs("err-line-42", true)
	res, _ := e.Run(context.Background(), Spec{Bin: bin, Args: args})
	if res == nil || !res.OK {
		t.Fatalf("应正常退出: %+v", res)
	}
	if !strings.Contains(res.Stderr, "err-line-42") {
		t.Fatalf("stderr 未捕获: %q", res.Stderr)
	}
	if strings.Contains(res.Stdout, "err-line-42") {
		t.Fatalf("stdout/stderr 混淆: %q", res.Stdout)
	}
}

func TestRunStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cmd 无简单的 stdin 回显命令")
	}
	e := newTestExecutor(t, Config{})
	res, err := e.Run(context.Background(), Spec{
		Bin:   "sh",
		Args:  []string{"-c", "cat"},
		Stdin: "stdin-data-123\n",
	})
	if err != nil || res == nil || !res.OK {
		t.Fatalf("stdin 执行应成功: %v %+v", err, res)
	}
	if !strings.Contains(res.Stdout, "stdin-data-123") {
		t.Fatalf("stdin 未透传: %q", res.Stdout)
	}
}

func TestRunNonZeroExit(t *testing.T) {
	e := newTestExecutor(t, Config{})
	bin, args := exitArgs(3)
	res, err := e.Run(context.Background(), Spec{Bin: bin, Args: args})
	if err == nil {
		t.Fatal("非零退出应返回错误")
	}
	if res.OK || res.ExitCode != 3 {
		t.Fatalf("应记录退出码 3: %+v", res)
	}
}

func TestRunTimeoutKillsProcess(t *testing.T) {
	e := newTestExecutor(t, Config{Timeout: 1 * time.Second})
	bin, args := sleepArgs()
	start := time.Now()
	res, err := e.Run(context.Background(), Spec{Bin: bin, Args: args})
	if err == nil {
		t.Fatal("超时应返回错误")
	}
	if !res.TimedOut {
		t.Fatalf("应标记超时: %+v", res)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("超时控制未生效, 耗时 %v", d)
	}
}

func TestRunCancel(t *testing.T) {
	e := newTestExecutor(t, Config{})
	bin, args := sleepArgs()
	doneCh := make(chan *Result, 1)
	go func() {
		res, _ := e.Run(context.Background(), Spec{Bin: bin, Args: args})
		doneCh <- res
	}()
	id := waitForTask(t, e, 1)
	if !e.Cancel(id) {
		t.Fatal("Cancel 应返回 true")
	}
	select {
	case res := <-doneCh:
		if res == nil || !res.Cancelled {
			t.Fatalf("应标记取消: %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消后 Run 未返回")
	}
}

func TestRunPauseEqualsCancel(t *testing.T) {
	e := newTestExecutor(t, Config{})
	bin, args := sleepArgs()
	doneCh := make(chan *Result, 1)
	go func() {
		res, _ := e.Run(context.Background(), Spec{Bin: bin, Args: args})
		doneCh <- res
	}()
	id := waitForTask(t, e, 1)
	if !e.Pause(id) {
		t.Fatal("Pause 应返回 true")
	}
	select {
	case res := <-doneCh:
		if res == nil || !res.Cancelled {
			t.Fatalf("暂停(=终止)应标记取消: %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("暂停后 Run 未返回")
	}
}

func TestCancelAll(t *testing.T) {
	e := newTestExecutor(t, Config{})
	bin, args := sleepArgs()
	doneCh := make(chan *Result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			res, _ := e.Run(context.Background(), Spec{Bin: bin, Args: args})
			doneCh <- res
		}()
	}
	waitForTask(t, e, 2)
	if n := e.CancelAll(); n != 2 {
		t.Fatalf("CancelAll 应取消 2 个任务, 实际 %d", n)
	}
	for i := 0; i < 2; i++ {
		select {
		case res := <-doneCh:
			if res == nil || !res.Cancelled {
				t.Fatalf("任务应标记取消: %+v", res)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("CancelAll 后 Run 未返回")
		}
	}
}

// TestTreeKill 验证取消时递归杀掉子进程树:
// 父进程(引擎替身)派生一个长命子进程并记录其 PID,
// 取消父进程后, 子进程也必须被进程树终止一起杀掉(防残留)。
func TestTreeKill(t *testing.T) {
	e := newTestExecutor(t, Config{})
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")

	var bin string
	var args []string
	if runtime.GOOS == "windows" {
		// powershell: 派生子进程(cmd 长 ping)并把子进程 PID 写入文件, 父进程持续等待
		psCmd := "Start-Process -PassThru -WindowStyle Hidden -FilePath cmd -ArgumentList " +
			"'/c','ping -n 300 127.0.0.1 >nul' | " +
			"ForEach-Object { $_.Id | Out-File -FilePath '" + pidFile + "' -Encoding ascii }; " +
			"Start-Sleep 300"
		bin = "powershell"
		args = []string{"-NoProfile", "-Command", psCmd}
	} else {
		bin = "sh"
		args = []string{"-c", "sleep 300 & echo $! > " + pidFile + "; wait"}
	}

	type runOut struct {
		res   *Result
		err   error
		start bool // 是否成功启动过进程
	}
	doneCh := make(chan runOut, 1)
	go func() {
		res, rerr := e.Run(context.Background(), Spec{Bin: bin, Args: args})
		doneCh <- runOut{res: res, err: rerr, start: !(rerr != nil && strings.Contains(rerr.Error(), "启动失败"))}
	}()

	// 等待子进程 PID 写入(在子进程被取消前必须拿到, 因此不能在 goroutine 里
	// 调用 t.Skip —— 测试辅助只能在测试主 goroutine 使用)。
	// 注意: powershell 的 Out-File 不是原子写, 首读可能拿到半截内容, 需重试解析。
	var childPid int
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if data, rerr := os.ReadFile(pidFile); rerr == nil {
			if n, aerr := strconv.Atoi(strings.TrimSpace(string(data))); aerr == nil && n > 0 {
				if childAlive(n) {
					childPid = n
					break
				}
				// 解析出的 PID 已不存在(文件写入中途被读 / PID 复用), 等下次重写
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if childPid == 0 {
		out := <-doneCh // 回收任务, 避免残留
		if !out.start {
			t.Skipf("测试命令不可用, 跳过: %v", out.err)
		}
		t.Skip("未能获取引擎子进程 PID, 跳过进程树终止验证")
	}

	id := waitForTask(t, e, 1)
	if !e.Cancel(id) {
		t.Fatal("Cancel 应成功")
	}
	select {
	case out := <-doneCh:
		if out.res == nil || !out.res.Cancelled {
			t.Fatalf("应标记取消: %+v", out.res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消后 Run 未返回")
	}

	// 子进程应已被进程树终止一起杀掉(进程退出是异步的, 轮询等待回收)
	if !waitProcessGone(childPid, 5*time.Second) {
		out, _ := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(childPid)).CombinedOutput()
		t.Fatalf("子进程 %d 未被进程树终止杀掉(残留进程); tasklist: %s", childPid, string(out))
	}
}

func TestMissingBinary(t *testing.T) {
	e := newTestExecutor(t, Config{}) // 空 bin 目录
	res, err := e.Run(context.Background(), Spec{Engine: NameNmap})
	if err == nil {
		t.Fatal("引擎缺失应返回错误")
	}
	if res == nil || res.OK {
		t.Fatalf("结果应标记失败: %+v", res)
	}
	// 执行器仍可继续使用(不崩溃主服务)
	bin, args := echoArgs("still-alive", false)
	res2, err2 := e.Run(context.Background(), Spec{Bin: bin, Args: args})
	if err2 != nil || res2 == nil || !res2.OK {
		t.Fatalf("失败后执行器应可用: %v %+v", err2, res2)
	}
}

// TestFindBinPathFallback 守卫 PATH 回退契约: bin/ 无匹配时按 PATH 查系统自装引擎,
// 命中则返回 PATH 路径。若回退被删, "装在 PATH 里的引擎"将永远报未找到(静默失效)。
func TestFindBinPathFallback(t *testing.T) {
	oldLookup := pathLookup
	pathLookup = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	t.Cleanup(func() { pathLookup = oldLookup })
	e := NewExecutor(Config{BinDir: t.TempDir(), Timeout: 5 * time.Second, MaxOutput: 64 * 1024})
	got, err := e.findBin(NameNmap)
	if err != nil {
		t.Fatalf("PATH 有引擎应命中: %v", err)
	}
	if got != "/usr/bin/nmap" {
		t.Fatalf("应命中 PATH 路径, 实际 %s", got)
	}
}

func TestFindBin(t *testing.T) {
	// PATH 回退是真实环境依赖(开发机 PATH 可能有 nmap), 强制"PATH 无此引擎"
	// 让"空目录应报未找到"用例在任何机器上都确定通过, 不随环境漂移。
	oldLookup := pathLookup
	pathLookup = func(string) (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { pathLookup = oldLookup })

	dir := t.TempDir()
	e := NewExecutor(Config{BinDir: dir, Timeout: 5 * time.Second, MaxOutput: 64 * 1024})

	if _, err := e.findBin(NameNmap); err == nil {
		t.Fatal("空目录应报未找到")
	}

	if runtime.GOOS == "windows" {
		// Windows: 建桩文件只验证路径命中(不执行)
		p := filepath.Join(dir, "nmapcore.exe")
		if werr := os.WriteFile(p, []byte("stub"), 0o644); werr != nil {
			t.Fatal(werr)
		}
		got, err := e.findBin(NameNmap)
		if err != nil {
			t.Fatalf("应命中 nmapcore.exe: %v", err)
		}
		if got != p {
			t.Fatalf("命中错误路径: %s", got)
		}
		p2 := filepath.Join(dir, "zap-2.14.exe")
		if werr := os.WriteFile(p2, []byte("stub"), 0o644); werr != nil {
			t.Fatal(werr)
		}
		got2, err := e.findBin(NameZap)
		if err != nil {
			t.Fatalf("前缀匹配应命中 zap-2.14.exe: %v", err)
		}
		if got2 != p2 {
			t.Fatalf("命中错误路径: %s", got2)
		}
		return
	}

	p := filepath.Join(dir, "nmapcore")
	if werr := os.WriteFile(p, []byte("#!/bin/sh\necho resolved-ok\n"), 0o755); werr != nil {
		t.Fatal(werr)
	}
	got, err := e.findBin(NameNmap)
	if err != nil {
		t.Fatalf("应命中 nmapcore: %v", err)
	}
	if got != p {
		t.Fatalf("命中错误路径: %s", got)
	}
	res, err := e.Run(context.Background(), Spec{Engine: NameNmap})
	if err != nil || res == nil || !res.OK {
		t.Fatalf("查到的引擎应可执行: %v %+v", err, res)
	}
	if !strings.Contains(res.Stdout, "resolved-ok") {
		t.Fatalf("输出不符: %q", res.Stdout)
	}

	p2 := filepath.Join(dir, "zap-2.14")
	if werr := os.WriteFile(p2, []byte("#!/bin/sh\necho ok\n"), 0o755); werr != nil {
		t.Fatal(werr)
	}
	got2, err := e.findBin(NameZap)
	if err != nil {
		t.Fatalf("前缀匹配应命中 zap-2.14: %v", err)
	}
	if got2 != p2 {
		t.Fatalf("命中错误路径: %s", got2)
	}
}

func TestOutputCap(t *testing.T) {
	e := NewExecutor(Config{BinDir: t.TempDir(), MaxOutput: 1024, Timeout: 15 * time.Second})
	var bin string
	var args []string
	if runtime.GOOS == "windows" {
		bin = "cmd"
		args = []string{"/c", "for /L %i in (1,1,100) do @echo 0123456789"}
	} else {
		bin = "sh"
		args = []string{"-c", "yes 0123456789 | head -c 4096"}
	}
	res, _ := e.Run(context.Background(), Spec{Bin: bin, Args: args})
	if res == nil || !res.OK {
		t.Fatalf("应正常退出: %+v", res)
	}
	if !res.Truncated {
		t.Fatal("超限输出应标记截断")
	}
	if len(res.Stdout) != 1024 {
		t.Fatalf("stdout 应截断为 1024 字节, 实际 %d", len(res.Stdout))
	}
}

func TestRunContextDoneBeforeStart(t *testing.T) {
	e := newTestExecutor(t, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	res, err := e.Run(ctx, Spec{Bin: "whatever", Args: []string{"x"}})
	if err == nil {
		t.Fatal("已取消的 ctx 应返回错误")
	}
	if res == nil || !res.Cancelled {
		t.Fatalf("应标记取消: %+v", res)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("应快速返回(不启动进程)")
	}
}

func TestArgBuilders(t *testing.T) {
	// -Pn 不可省: Windows nmap 主机发现走 pcap 嗅探, VPN 虚拟网卡/无 Npcap 环境
	// 下 pcap_create 失败直接 QUITTING(2026-09-20 实测)。删前先看 ArgsNmap 注释。
	if got := strings.Join(ArgsNmap("192.168.1.10", []int{80, 443}), " ");
		got != "-sT -Pn -p 80,443 --open -oJ - 192.168.1.10" {
		t.Fatalf("ArgsNmap 不符: %s", got)
	}
	if got := strings.Join(ArgsNmap("10.0.0.1", nil, "-A"), " ");
		got != "-sT -Pn -p 80,443 --open -oJ - -A 10.0.0.1" {
		t.Fatalf("ArgsNmap(带追加参数)不符: %s", got)
	}
	// XML 落文件版(Windows 唯一可用形态): -oJ 在 Windows nmap 上值会被当成目标。
	if got := strings.Join(ArgsNmapFile("10.0.0.1", []int{22}, `C:\tmp\n.xml`), " ");
		got != "-sT -Pn -p 22 --open -oX C:\\tmp\\n.xml 10.0.0.1" {
		t.Fatalf("ArgsNmapFile 不符: %s", got)
	}
	if got := strings.Join(ArgsTrivyFS("/opt/app"), " "); got != "fs -f json /opt/app" {
		t.Fatalf("ArgsTrivyFS 不符: %s", got)
	}
	if got := strings.Join(ArgsTrivyImage("nginx:1.25"), " "); got != "image -f json nginx:1.25" {
		t.Fatalf("ArgsTrivyImage 不符: %s", got)
	}
	// 用整串断言(而非 Contains)钉住"无窗 + 正确扫描参数":
	//   -cmd        不可省: 去掉它 ZAP 会弹 Swing GUI 窗口并常驻(见 ArgsZap 注释)
	//   -quickurl   不可换成 -t: -t/-J 在 ZAP 2.17 已不可用, ZAP 会只打帮助不扫描
	//   -quickout   报告类型由扩展名决定, 故传 .json
	// 整串断言的意义: 任何人想删 -cmd 或改回 -t/-J, 都必须先改这条测试。
	if got := strings.Join(ArgsZap("http://192.168.1.10", "/tmp/zap.json"), " ");
		got != "-cmd -quickurl http://192.168.1.10 -quickout /tmp/zap.json" {
		t.Fatalf("ArgsZap 不符(注意 -cmd 不可省, 否则 ZAP 会弹窗): %s", got)
	}
}
