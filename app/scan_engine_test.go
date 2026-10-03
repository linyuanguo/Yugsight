package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"yugsight/internal/engine/parsers"
	"yugsight/internal/models"
	"yugsight/internal/scanner"
)

// fakeZapReport 引擎替身产出的 ZAP JSON 报告(一条 high 告警)。
const fakeZapReport = `{"site":[{"name":"http://10.0.0.5","host":"10.0.0.5","port":"80","ssl":false,
"alerts":[{"pluginid":"10202","name":"Absence of Anti-CSRF Tokens","riskcode":"2","confidence":"Medium",
"desc":"No Anti-CSRF tokens were found","solution":"Use anti-CSRF tokens","cweid":"352",
"instances":[{"uri":"http://10.0.0.5/","method":"GET","evidence":"<form action=/login>"}]}]}]}`

// TestRunEngineScanZapFindings 引擎链路端到端(用注入的引擎替身, 不依赖 bin/ 里的真实引擎):
// 结果转 finding 事件且标 source=engine, 落库归一化后仍是 engine 来源,
// ZAP 报告文件必须在返回前清理掉。
func TestRunEngineScanZapFindings(t *testing.T) {
	o := instanceOrchestrator()
	if o == nil {
		t.Fatal("编排器不应为 nil")
	}
	prev := o.Exec
	t.Cleanup(func() { o.SetExec(prev) })

	// 注入"引擎可用"探测: 真实 bin/ 无 zap, 但下面的 Exec 替身代表引擎逻辑可用,
	// 预判若查真实二进制会误拦。与 engine.pathLookup 同手法, 用完还原。
	prevProbe := engineProbe
	engineProbe = func(string) (string, error) { return "/fake/zap", nil }
	t.Cleanup(func() { engineProbe = prevProbe })

	var reportPath string
	o.SetExec(func(ctx context.Context, engineName string, args []string) ([]byte, bool, error) {
		// 替身按 -quickout 落报告文件(真实 ZAP 只支持落文件, 不支持 stdout)
		for i, a := range args {
			if a == "-quickout" && i+1 < len(args) {
				reportPath = args[i+1]
				if err := os.WriteFile(reportPath, []byte(fakeZapReport), 0o600); err != nil {
					return nil, false, err
				}
			}
		}
		return nil, false, nil
	})

	// 2026-09-26: 默认已改为内置, 测外部引擎链路必须显式选引擎(Engine=zap)。
	req := scanReq{Type: "web", URL: "http://10.0.0.5", Ports: "80", Engine: "zap"}
	sink := newScanSink(req, "10.0.0.5", 80)
	var mu sync.Mutex
	var finds []engineFinding
	emit := func(event string, data any) {
		// 与生产口径一致: runScanPipeline 传入的是 emitAI, 转发后顺带收集落库
		sink.observe(event, data)
		if event == "finding" {
			if f, ok := data.(engineFinding); ok {
				mu.Lock()
				finds = append(finds, f)
				mu.Unlock()
			}
		}
	}
	if !runEngineScan(context.Background(), req, sink, emit) {
		t.Fatal("引擎可用时不应降级(应返回 true)")
	}
	mu.Lock()
	got := len(finds)
	src := ""
	if got > 0 {
		src = finds[0].Source
	}
	mu.Unlock()
	if got != 1 {
		t.Fatalf("引擎 finding 数=%d, want 1", got)
	}
	if src != engineFindingSource {
		t.Errorf("引擎 finding 应标 source=%s, 实为 %q", engineFindingSource, src)
	}
	res := sink.normalize()
	if res == nil || len(res.Vulns) != 1 {
		t.Fatalf("落库归一化应拿到 1 条漏洞: %+v", res)
	}
	if res.Vulns[0].Source != engineFindingSource {
		t.Errorf("落库漏洞来源应为 %s, 实为 %s", engineFindingSource, res.Vulns[0].Source)
	}
	if reportPath == "" {
		t.Fatal("替身未收到 -quickout 参数, ZAP 报告路径未生效")
	}
	if _, err := os.Stat(reportPath); !os.IsNotExist(err) {
		t.Errorf("ZAP 报告文件未在返回前清理: %s (err=%v)", reportPath, err)
	}
}

// TestRunEngineScanDegradesToBuiltin 降级契约: 引擎不可用时必须返回 false
// (调用方回落内置流程)且不产生任何 finding。
func TestRunEngineScanDegradesToBuiltin(t *testing.T) {
	o := instanceOrchestrator()
	prev := o.Exec
	o.SetExec(nil) // 等价于"外部引擎未启用/未装配"
	t.Cleanup(func() { o.SetExec(prev) })

	req := scanReq{Type: "host", IP: "127.0.0.1", Ports: "1", Engine: "nmap"}
	sink := newScanSink(req, "127.0.0.1", 0)
	var msgs []string
	emit := func(event string, data any) {
		if event == "finding" {
			t.Error("降级路径不应产生 finding")
		}
		if m, ok := data.(map[string]any); ok {
			msgs = append(msgs, fmt.Sprint(m["msg"]))
		}
	}
	if runEngineScan(context.Background(), req, sink, emit) {
		t.Fatal("引擎不可用时必须返回 false, 由调用方回落内置流程")
	}
	if !strings.Contains(strings.Join(msgs, "|"), "回落内置引擎") {
		t.Errorf("降级应给出回落提示, 实为 %v", msgs)
	}
}

// TestRunEngineScanEngineMissing 引擎二进制缺失时直接回落内置(不进入 orchestrator):
// 验证执行前预判生效 —— 不触发 orchestrator 降级兜底(degradeCount 不增), 即不会
// "先跑一遍兜底端口探测、再由内置流程重扫"的重复(默认启用后引擎未装是常见状态)。
func TestRunEngineScanEngineMissing(t *testing.T) {
	o := instanceOrchestrator()
	if o == nil {
		t.Fatal("编排器不应为 nil")
	}
	prev := o.Exec
	t.Cleanup(func() { o.SetExec(prev) })
	// 注入"引擎缺失"探测, 确保走预判回落(不依赖测试机是否装了 nmap)。
	prevProbe := engineProbe
	engineProbe = func(string) (string, error) { return "", fmt.Errorf("not installed") }
	t.Cleanup(func() { engineProbe = prevProbe })

	before := o.Stats().DegradeCount
	req := scanReq{Type: "host", IP: "127.0.0.1", Ports: "1", Engine: "nmap"}
	sink := newScanSink(req, "127.0.0.1", 0)
	var found bool
	emit := func(event string, data any) {
		if event == "finding" {
			found = true
		}
	}
	if runEngineScan(context.Background(), req, sink, emit) {
		t.Fatal("引擎缺失必须返回 false, 由调用方回落内置流程")
	}
	if found {
		t.Error("预判回落不应产生 finding")
	}
	if after := o.Stats().DegradeCount; after != before {
		t.Errorf("预判回落不应触发 orchestrator 降级(degradeCount %d -> %d), 否则重复端口探测", before, after)
	}
}

// TestEngineScanType 只有 host/port/web 可交给编排器(其余类型走内置, 零行为变化)。
func TestEngineScanType(t *testing.T) {
	for _, typ := range []string{"host", "port", "web"} {
		if !engineScanType(typ) {
			t.Errorf("%s 应可交给引擎编排", typ)
		}
	}
	for _, typ := range []string{"ip", "alive", "unified", ""} {
		if engineScanType(typ) {
			t.Errorf("%s 不应改变执行链路", typ)
		}
	}
}

// TestEngineScanActive 编排判定(单一口径): 非编排类型恒 false; useEngine 显式值覆盖默认。
// 显式分支不依赖总开关(enabled), 保证测试稳定; 默认(nil)路径"跟随 enabled"由
// engineOn 的 nil→true 保证(见 engine_api_test.go 的 TestEngineOn)。
func TestEngineScanActive(t *testing.T) {
	var on, off bool = true, false
	// 非编排类型: 无论 useEngine 都 false
	if engineScanActive(scanReq{Type: "ip", UseEngine: &on}) {
		t.Error("ip(非编排类型)不应走引擎")
	}
	// 编排类型 + 显式 false = 强制内置(不依赖总开关)
	if engineScanActive(scanReq{Type: "host", UseEngine: &off}) {
		t.Error("host + useEngine=false 应强制内置")
	}
	// 编排类型 + 显式 true = 强制引擎(不依赖总开关)
	if !engineScanActive(scanReq{Type: "host", UseEngine: &on}) {
		t.Error("host + useEngine=true 应走引擎")
	}
}

// TestEngineZapArtifactArgs ZapArtifact 与 buildArgs 的口径必须一致:
// 下发的 -quickout 路径就是 ZapArtifact 会去读的那个文件, 否则会读到空文件 → 误判"引擎无输出"。
func TestEngineZapArtifactArgs(t *testing.T) {
	args, read, cleanup := parsers.ZapArtifact(t.TempDir(), "scan-1")
	defer cleanup()
	if len(args) < 2 {
		t.Fatalf("ZapArtifact 应返回 (开关, 路径), 实为 %v", args)
	}
	if err := os.WriteFile(args[len(args)-1], []byte(fakeZapReport), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := read()
	if err != nil || len(b) == 0 {
		t.Fatalf("read 回调读不到报告: len=%d err=%v", len(b), err)
	}
}

// TestResolveScanEngine 引擎选择契约(2026-09-26: 让用户按类型自选引擎):
// 显式 Engine > 老 UseEngine > 默认内置, 且类型与引擎错配时回落内置(不误用)。
//
// 守的是两个关键口径:
//  1. 默认必须内置 —— 否则网段/主机扫描又被"默认 nmap"拖慢(用户反馈"比内置慢");
//  2. 显式选外部引擎才走外部, 错配(如 host 选 zap)不误用不匹配的引擎。
func TestResolveScanEngine(t *testing.T) {
	var on, off bool = true, false
	// 默认(无 Engine/UseEngine) → 内置(快)
	if name, ext := resolveScanEngine(scanReq{Type: "host"}); ext {
		t.Errorf("未显式选引擎应默认内置, 实为 (%s, external=%v)", name, ext)
	}
	// 显式 Engine=nmap(host) → 外部 nmap
	if name, ext := resolveScanEngine(scanReq{Type: "host", Engine: "nmap"}); !ext || name != "nmap" {
		t.Errorf("host + engine=nmap 应走 nmap, 实为 (%s, %v)", name, ext)
	}
	// 显式 Engine=zap(web) → 外部 zap
	if name, ext := resolveScanEngine(scanReq{Type: "web", Engine: "zap"}); !ext || name != "zap" {
		t.Errorf("web + engine=zap 应走 zap, 实为 (%s, %v)", name, ext)
	}
	// 显式 Engine=builtin → 内置
	if _, ext := resolveScanEngine(scanReq{Type: "host", Engine: "builtin"}); ext {
		t.Error("engine=builtin 应内置")
	}
	// 类型错配: host 选 zap → 回落内置(不误用)
	if _, ext := resolveScanEngine(scanReq{Type: "host", Engine: "zap"}); ext {
		t.Error("host 类型选 zap 属错配, 应回落内置")
	}
	// 非编排类型: ip 选 nmap → 内置
	if _, ext := resolveScanEngine(scanReq{Type: "ip", Engine: "nmap"}); ext {
		t.Error("ip(非编排类型)不走外部引擎")
	}
	// 老字段 UseEngine=true → 默认外部(兼容老脚本)
	if _, ext := resolveScanEngine(scanReq{Type: "host", UseEngine: &on}); !ext {
		t.Error("useEngine=true(老字段)应走外部引擎")
	}
	// 老字段 UseEngine=false → 内置
	if _, ext := resolveScanEngine(scanReq{Type: "host", UseEngine: &off}); ext {
		t.Error("useEngine=false 应内置")
	}
}

// TestServiceAssetsFromModel nmap 资产 → ServiceAsset 转换(探测/漏洞分离的桥接, 2026-09-26):
// 资产级 Service/Version 按端口展开, web 端口标 https 方案, 空 IP/空端口跳过。
// 守的是"nmap 探测结果能喂给 nuclei 模板"这个衔接 —— 转换漏端口或方案标错,
// nmap 方案下的 nuclei 叠加就会静默漏扫 web 漏洞。
func TestServiceAssetsFromModel(t *testing.T) {
	assets := []*models.Asset{
		{IP: "10.0.0.5", Ports: []int{80, 443, 22}, Service: "nginx", Version: "1.18"},
		{IP: "", Ports: []int{80}},      // 空 IP 跳过
		{IP: "10.0.0.6", Ports: []int{}}, // 无开放端口跳过
	}
	got := serviceAssetsFromModel(assets)
	if len(got) != 3 {
		t.Fatalf("应展开 3 个 ServiceAsset(10.0.0.5 的 80/443/22), 实为 %d", len(got))
	}
	byPort := map[int]scanner.ServiceAsset{}
	for _, s := range got {
		byPort[s.Port] = s
	}
	if s := byPort[443]; s.Scheme != "https" {
		t.Errorf("443 应为 https 方案, 实为 %s", s.Scheme)
	}
	if s := byPort[80]; s.Scheme != "http" {
		t.Errorf("80 应为 http 方案, 实为 %s", s.Scheme)
	}
	if s := byPort[22]; s.Product != "nginx" {
		t.Errorf("服务名应透传到 Product, 实为 %s", s.Product)
	}
}
