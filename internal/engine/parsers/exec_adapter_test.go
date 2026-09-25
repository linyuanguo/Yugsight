package parsers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yugsight/internal/engine"
	"yugsight/internal/normalizer"
	)

// nil 执行器 → ExecFuncOf 返回 nil → 编排器走"未配置外部引擎"降级
func TestExecFuncOfNil(t *testing.T) {
	if f := ExecFuncOf(nil); f != nil {
		t.Fatal("nil 执行器应返回 nil ExecFunc")
	}
	o := NewEngineOrchestrator(nil, builtinFallback(1, 0))
	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if !out.Degraded {
		t.Fatal("纯内置模式应标记降级")
	}
}

// 引擎二进制不存在(用真实 Executor + 空 bin 目录): 执行失败 → 自动降级, 不 panic
func TestEngineOrchestratorMissingBinary(t *testing.T) {
	dir := t.TempDir() // 空 bin 目录, 必然找不到引擎
	ex := engine.NewExecutor(engine.Config{BinDir: dir})
	o := NewEngineOrchestrator(ex, builtinFallback(2, 1))
	o.SetLogger(func(string) {})

	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1", Ports: []int{80}})
	if err != nil {
		t.Fatalf("引擎缺失应降级而非报错: %v", err)
	}
	if !out.Degraded {
		t.Fatal("引擎缺失应降级")
	}
	if out.Result == nil || len(out.Result.Assets) != 2 {
		t.Fatalf("降级后应拿到内置结果: %+v", out.Result)
	}
	if !strings.Contains(out.DegradeReason, "执行失败") {
		t.Errorf("降级原因错误: %q", out.DegradeReason)
	}
}

// 真实执行器 + 真实可执行文件: 走通 执行→解析→归一化 全链路。
// 用系统自带命令作为"引擎"替身, 输出 nmap XML。
func TestEngineOrchestratorRealExec(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过真实进程执行")
	}
	dir := t.TempDir()
	bin := fakeEngineBinary(t, dir)
	if bin == "" {
		t.Skip("当前平台无可用命令替身")
	}

	ex := engine.NewExecutor(engine.Config{BinDir: dir, Timeout: 30 * time.Second})
	o := NewEngineOrchestrator(ex, builtinFallback(1, 0))
	o.SetLogger(func(string) {})

	// 参数完全由替身忽略, 这里只需保证能跑起来
	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"})
	if err != nil {
		t.Fatalf("真实执行链路失败: %v", err)
	}
	if out.Degraded {
		t.Fatalf("替身引擎输出合法 XML, 不应降级: %+v", out)
	}
	if out.Result == nil || len(out.Result.Assets) == 0 {
		t.Fatalf("应解析出资产: %+v", out.Result)
	}
}

// 替身脚本输出非法内容 → 解析失败 → 降级
func TestEngineOrchestratorRealExecBadOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过真实进程执行")
	}
	dir := t.TempDir()
	// 替身名为 trivy(与请求的引擎名一致), 输出非 JSON 内容
	if fakeEngineBinaryFor(t, dir, "trivy", "not-a-report-at-all") == "" {
		t.Skip("当前平台无可用命令替身")
	}
	ex := engine.NewExecutor(engine.Config{BinDir: dir, Timeout: 30 * time.Second})
	o := NewEngineOrchestrator(ex, builtinFallback(1, 1))
	o.SetLogger(func(string) {})

	out, err := o.Run(context.Background(), Request{Kind: "trivy", Target: "img:1"})
	if err != nil {
		t.Fatalf("解析失败应降级而非报错: %v", err)
	}
	if !out.Degraded || !strings.Contains(out.DegradeReason, "解析失败") {
		t.Fatalf("应因解析失败降级: %+v", out)
	}
}

// ZapArtifact 参数与读取/清理
func TestZapArtifact(t *testing.T) {
	dir := t.TempDir()
	args, read, cleanup := ZapArtifact(dir, "scan:1/2")
	if len(args) != 2 || args[0] != "-J" {
		t.Fatalf("参数应为 -J <file>, 实际 %v", args)
	}
	file := args[1]
	if strings.ContainsAny(filepath.Base(file), ": /\\") {
		t.Errorf("文件名未安全化: %s", file)
	}
	if !strings.HasPrefix(file, dir) {
		t.Errorf("报告文件应落在指定目录: %s", file)
	}
	// 读取不存在的文件 → 错误(编排器据此降级)
	if _, err := read(); err == nil {
		t.Error("文件不存在应返回错误")
	}
	if err := os.WriteFile(file, []byte(zapSample), 0o600); err != nil {
		t.Fatalf("写入测试报告失败: %v", err)
	}
	data, err := read()
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(data) == 0 {
		t.Error("应读到报告内容")
	}
	cleanup()
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Error("cleanup 应删除报告文件")
	}
	// 空目录 / 空 id 走默认值
	args2, _, cleanup2 := ZapArtifact("", "")
	if len(args2) != 2 || !strings.Contains(args2[1], "zap") {
		t.Errorf("默认参数异常: %v", args2)
	}
	cleanup2()
}

// 端到端: 替身 ZAP 引擎落报告文件 → 编排器读文件 → 解析 → 归一化
func TestEngineOrchestratorZapReportFile(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过真实进程执行")
	}
	dir := t.TempDir()
	// 替身脚本接收 -J <file> 并把报告写入该文件(模拟 zap)
	if !fakeZapBinary(t, dir) {
		t.Skip("当前平台无可用命令替身")
	}
	ex := engine.NewExecutor(engine.Config{BinDir: dir, Timeout: 30 * time.Second})
	o := NewEngineOrchestrator(ex, builtinFallback(1, 0))
	o.SetLogger(func(string) {})

	args, read, cleanup := ZapArtifact(dir, "e2e")
	defer cleanup()
	out, err := o.Run(context.Background(), Request{
		Kind: "zap", Target: "http://10.0.0.5:8080", Args: args, ReadArtifact: read,
	})
	if err != nil {
		t.Fatalf("端到端失败: %v", err)
	}
	if out.Degraded {
		t.Fatalf("报告文件合法, 不应降级: %+v", out)
	}
	if len(out.Result.Assets) != 1 {
		t.Errorf("应解析出 1 个站点资产: %d", len(out.Result.Assets))
	}
	titles := make([]string, 0, len(out.Result.Vulns))
	for _, v := range out.Result.Vulns {
		titles = append(titles, v.Title)
	}
	// 归一化合并键不含 URL 路径: 同站点同标题的多实例会被合并为 1 条漏洞
	if len(out.Result.Vulns) != 2 {
		t.Errorf("应合并为 2 条漏洞(XSS + 缺失安全头), 实际 %d: %v", len(out.Result.Vulns), titles)
	}
	// 同资产同标题的两条 XSS 实例在归一化层被合并为一条, 且证据全部保留
	for _, v := range out.Result.Vulns {
		if strings.Contains(v.Title, "Cross Site Scripting") {
			if len(v.EvidenceRecords) != 2 {
				t.Errorf("XSS 应保留 2 条证据记录: %d", len(v.EvidenceRecords))
			}
		}
	}
	_ = normalizer.SourceZAP
}
