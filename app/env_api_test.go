package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"yugsight/internal/envdetect"
	"yugsight/internal/sse"
)

// TestEnvAPI 任务 4.2 环境检测 API 冒烟:
// /api/env 快照 / /api/env/refresh 重检 / /api/env/install 分支守卫
func TestEnvAPI(t *testing.T) {
	envdetect.Init()

	// /api/env: 200 且含引擎与 Npcap 段
	w := httptest.NewRecorder()
	handleEnvStatus(w, httptest.NewRequest("GET", "/api/env", nil))
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `"engines"`) || !strings.Contains(body, `"npcap"`) {
		t.Fatalf("env status=%d body=%.300s", w.Code, body)
	}
	// 三个引擎必须在场
	for _, name := range []string{envdetect.EngineNmap, envdetect.EngineTrivy, envdetect.EngineZap} {
		if !strings.Contains(body, name) {
			t.Fatalf("env 缺少引擎 %s: %.300s", name, body)
		}
	}

	// /api/env/refresh: 200
	w = httptest.NewRecorder()
	handleEnvRefresh(w, httptest.NewRequest("POST", "/api/env/refresh", nil))
	if w.Code != 200 {
		t.Fatalf("refresh status=%d", w.Code)
	}

	// /api/env/refresh 非 POST -> 405
	w = httptest.NewRecorder()
	handleEnvRefresh(w, httptest.NewRequest("GET", "/api/env/refresh", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("refresh GET status=%d, want 405", w.Code)
	}

	// /api/env/install: 非 POST -> 405
	w = httptest.NewRecorder()
	handleEnvInstall(w, httptest.NewRequest("GET", "/api/env/install", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("install GET status=%d, want 405", w.Code)
	}
	if runtime.GOOS == "windows" {
		w = httptest.NewRecorder()
		handleEnvInstall(w, httptest.NewRequest("POST", "/api/env/install", nil))
		body = w.Body.String()
		// 本机必命中"已安装"或"未找到安装器"守卫分支(400);
		// 唯一不放行的场景是: 未安装且存在安装器 -> 会拉起真实安装向导, 测试中禁止
		if w.Code != 400 {
			t.Fatalf("install 应被守卫拦截 status=%d body=%.200s", w.Code, body)
		}
	}
}

// TestEventsEndpoint 任务 4.2 SSE 端点接线: 全局 hub 的 handler 产出 SSE 流
func TestEventsEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	sse.Default().Handler()(rec, httptest.NewRequest("GET", "/api/events", nil).WithContext(ctx))
	body := rec.Body.String()
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("content-type = %s", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, "event: hello") {
		t.Fatalf("缺 hello 事件: %q", body)
	}
}

// TestScanEventBroadcast 任务 4.2 扫描事件广播: handleScan 的 emit 同时推给 SSE 订阅者。
// 用不存在的目标触发 web 扫描的 fail 路径, 产生 status/done 事件(不产生真实网络流量)。
func TestScanEventBroadcast(t *testing.T) {
	initAI(false) // 初始化全局 aiAn(测试环境无 ai.json -> 禁用), 避免 handleScan 内 nil 解引用
	hub := sse.Default()
	ch, cancel := hub.Subscribe(1 << 62)
	defer cancel()

	req := httptest.NewRequest("POST", "/api/scan", strings.NewReader(`{"type":"web","url":"not-a-url"}`))
	w := httptest.NewRecorder()
	// handleScan 需要 Flusher; NewRecorder 实现 Flush
	handleScan(w, req)

	seen := map[string]bool{}
	deadline := time.After(3 * time.Second)
	for len(seen) < 2 { // status(错误) + done
		select {
		case ev := <-ch:
			seen[ev.Name] = true
		case <-deadline:
			t.Fatalf("SSE 订阅者未收到扫描事件广播: %v", seen)
		}
	}
}

// TestUIHasTask42 校验嵌入页面含任务 4.2 新增 UI 元素(防 id 拼写错误)
func TestUIHasTask42(t *testing.T) {
	data, err := uiFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, id := range []string{
		"evtCard", "envCard", "evtLog", "envBody",
		"openEvt", "closeEvt", "loadEnv", "renderEnv",
		"btnNpcapInstall", "btnEnvRefresh", "envChip", "evtClear",
		"/api/events", "/api/env",
	} {
		if !strings.Contains(s, id) {
			t.Fatalf("UI 缺少元素: %s", id)
		}
	}
}
