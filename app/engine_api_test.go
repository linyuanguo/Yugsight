package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"yugsight/internal/engine/parsers"
	"yugsight/internal/normalizer"
)

// TestEngineAPISmoke 任务 6.2 引擎编排 API 冒烟:
// /api/engine/status 快照 + /api/engine/refresh 重建(默认配置下外部引擎关闭)。
func TestEngineAPISmoke(t *testing.T) {
	resetOrchestrator()

	w := httptest.NewRecorder()
	handleEngineStatus(w, httptest.NewRequest("GET", "/api/engine/status", nil))
	if w.Code != 200 {
		t.Fatalf("status=%d body=%.300s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, key := range []string{
		`"enabled"`, `"execReady"`, `"fallbackReady"`, `"degradeCount"`,
		`"detected"`, `"degradeLog"`, `"binDir"`,
	} {
		if !strings.Contains(body, key) {
			t.Fatalf("engine status 缺字段 %s: %.400s", key, body)
		}
	}
	// 内置兜底必须就绪(降级目标永不为空), 否则"不中断任务"无从保证
	var snap struct {
		FallbackReady bool `json:"fallbackReady"`
	}
	if err := json.Unmarshal([]byte(body), &snap); err != nil {
		t.Fatalf("解析状态失败: %v", err)
	}
	if !snap.FallbackReady {
		t.Error("内置引擎兜底应始终就绪")
	}

	// refresh: 200 且可重复调用
	w = httptest.NewRecorder()
	handleEngineRefresh(w, httptest.NewRequest("POST", "/api/engine/refresh", nil))
	if w.Code != 200 {
		t.Fatalf("refresh status=%d", w.Code)
	}

	// 非 POST -> 405
	w = httptest.NewRecorder()
	handleEngineRefresh(w, httptest.NewRequest("GET", "/api/engine/refresh", nil))
	if w.Code != 405 {
		t.Fatalf("refresh GET status=%d, want 405", w.Code)
	}
}

// TestBuiltinRunnerFallback 内置兜底 Runner 必须返回可用批次(不报错、链路不中断)。
// 用回环地址 + 一个几乎不可能开放的端口, 避免测试发真实外网流量。
func TestBuiltinRunnerFallback(t *testing.T) {
	rb, err := builtinRunner(context.Background(), parsers.Request{Kind: "nmap", Target: "127.0.0.1", Ports: []int{1}})
	if err != nil {
		t.Fatalf("内置兜底不应报错: %v", err)
	}
	if rb == nil || rb.Source != normalizer.SourcePortScan {
		t.Fatalf("内置兜底应返回 PortScan 来源批次: %+v", rb)
	}
	// 归一化后仍应得到合法结果(空结果也合法: 端口未开放属正常)
	res := normalizer.Normalize(rb)
	if res == nil {
		t.Fatal("归一化不应返回 nil")
	}
}

// TestParseTargetHost 目标串归一化: URL / image: / fs: / 带端口 前缀处理。
// 注意: 返回的是"可直连的主机串"(可能含端口), 不做端口剥离。
func TestParseTargetHost(t *testing.T) {
	cases := map[string]string{
		"10.0.0.1":                  "10.0.0.1",
		"http://10.0.0.5:8080/x":    "10.0.0.5:8080",
		"https://example.com/a?b=1": "example.com",
		"image:nginx:1.21":          "nginx:1.21",
		"fs:/app":                   "app",
		"10.0.0.1:443":              "10.0.0.1:443",
		"  ":                        "",
	}
	for in, want := range cases {
		if got := parseTargetHost(in); got != want {
			t.Errorf("parseTargetHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEngineSnapshotInInfo 精简快照可用于 /api/info 内联(字段可序列化)。
func TestEngineSnapshotInInfo(t *testing.T) {
	snap := engineSnapshot()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("快照序列化失败: %v", err)
	}
	if !strings.Contains(string(b), "enabled") {
		t.Fatalf("快照缺 enabled: %s", b)
	}
}

// TestUIHasTask62 校验嵌入页面含任务 6.2 新增 UI 元素(防 id 拼写错误)。
func TestUIHasTask62(t *testing.T) {
	data, err := uiFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, id := range []string{
		"engStats", "engLog", "engHint", "btnEngRefresh",
		"loadEngine", "/api/engine/status", "/api/engine/refresh",
	} {
		if !strings.Contains(s, id) {
			t.Fatalf("UI 缺少元素: %s", id)
		}
	}
}
