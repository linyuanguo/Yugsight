package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"yugsight/internal/engine/parsers"
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

	req := scanReq{Type: "web", URL: "http://10.0.0.5", Ports: "80"}
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

	req := scanReq{Type: "host", IP: "127.0.0.1", Ports: "1"}
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
