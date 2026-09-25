//go:build windows

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunBatchLauncherOnWindows 验证执行器能跑 .bat 启动脚本。
//
// 【为什么需要】ZAP 官方跨平台免安装包里 **没有 zap.exe**, Windows 入口是 zap.bat
// (脚本内部拼 java 命令行再跑 zap.jar)。若执行器只会 exec.Command(<exe>) 而无法处理
// .bat, 则"ZAP 装好了却永远执行失败"。
//
// 这里用真实 .bat 验证: Go 的 exec.Command 在 Windows 上对 .bat 会经由 cmd.exe 解释,
// 能正常启动、传参、收 stdout/stderr —— 无需我们手工套 `cmd /c`。
// (若将来 Go 行为变化导致失效, 本用例会立刻红灯, 而不是等到用户报"ZAP 不工作"。)
func TestRunBatchLauncherOnWindows(t *testing.T) {
	dir := t.TempDir()
	// 真实布局: 整包落在 bin/zapcore/ 下(engmgr 的 BundleDir), 入口是包内的 zap.bat。
	// 顶层不扫 .bat 是刻意为之 —— 顶层只放单文件引擎, .bat 必须来自套装目录。
	bundle := filepath.Join(dir, "zapcore", "ZAP_2.17.0")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	bat := filepath.Join(bundle, "zap.bat")
	// 脚本回显收到的参数, 并往 stderr 写一行, 用于同时验证双路捕获
	script := "@echo off\r\n" +
		"echo LAUNCHER_OK args=%*\r\n" +
		"echo LAUNCHER_ERR 1>&2\r\n" +
		"exit /b 0\r\n"
	if err := os.WriteFile(bat, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	e := NewExecutor(Config{BinDir: dir, Timeout: 30 * time.Second})
	// 引擎名 zap → findBin 会按前缀找到套装内的 zap.bat
	res, err := e.Run(context.Background(), Spec{Engine: NameZap, Args: []string{"-J", "out.json"}})
	if err != nil {
		t.Fatalf("执行 .bat 启动器失败: %v (res=%+v)", err, res)
	}
	if res == nil || !res.OK {
		t.Fatalf("结果应标记成功: %+v", res)
	}
	if !strings.Contains(res.Stdout, "LAUNCHER_OK") {
		t.Fatalf("未捕获到脚本 stdout: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "-J out.json") {
		t.Fatalf("参数未正确传给 .bat: %q", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "LAUNCHER_ERR") {
		t.Fatalf("未捕获到脚本 stderr: %q", res.Stderr)
	}
	if !strings.HasSuffix(strings.ToLower(res.Bin), ".bat") {
		t.Fatalf("应定位到 .bat 启动器, 实际 %q", res.Bin)
	}
}

// TestFindBinPrefersExeOverBat 同名同前缀时优先 .exe 而不是 .bat。
//
// .bat 需要靠 cmd.exe 解释, 多一层 shell; 若用户/上游提供了真正的 exe, 应当优先用。
func TestFindBinPrefersExeOverBat(t *testing.T) {
	dir := t.TempDir()
	// 同一套装目录里同时放 .bat 与 .exe
	bundle := filepath.Join(dir, "zapcore", "ZAP")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"zap.bat", "zap.exe"} {
		if err := os.WriteFile(filepath.Join(bundle, n), []byte("stub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := NewExecutor(Config{BinDir: dir, Timeout: 5 * time.Second})
	got, err := e.findBin(NameZap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.ToLower(got), ".exe") {
		t.Fatalf("应优先 .exe, 实际 %q", got)
	}
}

// TestFindBinFallsBackToBatWhenNoExe 套装里只有 .bat 时必须能命中(正是 ZAP 的真实情形)。
func TestFindBinFallsBackToBatWhenNoExe(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "zapcore", "ZAP_2.17.0")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	// 干扰项: 同目录的 jar 不能被当成入口
	for _, n := range []string{"zap.bat", "zap.jar", "zap-2.17.0.jar"} {
		if err := os.WriteFile(filepath.Join(bundle, n), []byte("stub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := NewExecutor(Config{BinDir: dir, Timeout: 5 * time.Second})
	got, err := e.findBin(NameZap)
	if err != nil {
		t.Fatalf("应命中 zap.bat: %v", err)
	}
	if !strings.HasSuffix(strings.ToLower(got), "zap.bat") {
		t.Fatalf("应命中 zap.bat(而非 jar), 实际 %q", got)
	}
}
