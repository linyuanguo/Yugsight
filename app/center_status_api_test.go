package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"yugsight/internal/collect"
	"yugsight/internal/db"
	"yugsight/internal/scheduler"
	"yugsight/internal/server"
)

// centerStatusTestMode 进入测试模式: 免鉴权 + 注入"未启动"的调度器与采集引擎
// 单例(Once 标记为已执行, 防止 instanceScheduler/instanceCollect 用开发机上
// 残留的 settings.json 重建并启动真实循环 —— 与 schedAPITestMode 同一手法)。
func centerStatusTestMode(t *testing.T) {
	t.Helper()
	prevAuth := authDisabled
	authDisabled = true

	prevSched, prevSchedOnce := schedInst, schedOnce
	schedOnce = &sync.Once{}
	schedOnce.Do(func() {}) // 标记已执行 -> 懒加载短路
	schedInst = scheduler.New(scheduler.Config{Enabled: false},
		func(ctx context.Context, task *scheduler.Task, progress func(string)) (string, error) {
			return "", nil
		})

	prevNode, prevNodeOnce := nodeInst, nodeOnce
	nodeOnce = &sync.Once{}
	nodeOnce.Do(func() {})
	nodeInst = collect.New(collect.Config{}, nil, nil) // 未 Start, 零循环

	prevProbe := probeCenter
	probeCenter = nil // 不依赖探针中心端, 断言"未启用"分支

	t.Cleanup(func() {
		authDisabled = prevAuth
		schedInst, schedOnce = prevSched, prevSchedOnce
		nodeInst, nodeOnce = prevNode, prevNodeOnce
		probeCenter = prevProbe
	})
}

// resetCPUBaseline 清空 CPU 采样基线(全局状态, 用例间隔离)。
func resetCPUBaseline(t *testing.T) {
	t.Helper()
	prev := (*cpuTicks)(nil)
	cpuSampleMu.Lock()
	prev, cpuPrev = cpuPrev, nil
	cpuSampleMu.Unlock()
	t.Cleanup(func() {
		cpuSampleMu.Lock()
		cpuPrev = prev
		cpuSampleMu.Unlock()
	})
}

// TestCenterStatusAPI 接口结构契约: 全字段齐备 + 数据库可用时 db.ok=true。
//
// 断言走"反序列化后取字段"而不是字符串包含: 大 JSON 里子对象 key 按字母序
// 重排, 字符串匹配会随字段增减脆断。
func TestCenterStatusAPI(t *testing.T) {
	h, _ := newV2TestEnv(t)
	centerStatusTestMode(t)
	resetCPUBaseline(t)

	w := doReq(t, h, "GET", "/api/v2/center/status", "")
	if w.Code != 200 {
		t.Fatalf("status=%d body=%.300s", w.Code, w.Body.String())
	}
	out := decodeResp(t, w)
	if out.Code != server.CodeOK {
		t.Fatalf("resp code=%d message=%s", out.Code, out.Message)
	}
	m, ok := out.Data.(map[string]any)
	if !ok {
		t.Fatalf("data 不是对象: %#v", out.Data)
	}

	// 服务身份与运行时长
	if m["version"] != appVersion {
		t.Fatalf("version=%v 应为 %v", m["version"], appVersion)
	}
	if up, ok := m["uptimeSec"].(float64); !ok || up < 0 {
		t.Fatalf("uptimeSec 异常: %v", m["uptimeSec"])
	}

	// 主机负载: 内存/磁盘在当前平台必须可用(系统调用失败=真异常)
	mem := mustMap(t, m, "mem")
	if mem["ok"] != true {
		t.Fatalf("mem 采集失败: %v", mem)
	}
	if total := num(t, mem, "total"); total <= 0 {
		t.Fatalf("mem.total 应为正: %v", mem)
	}
	if used := num(t, mem, "used"); used > num(t, mem, "total") {
		t.Fatalf("mem.used 超过 total: %v", mem)
	}
	disk := mustMap(t, m, "disk")
	if disk["ok"] != true {
		t.Fatalf("disk 采集失败: %v", disk)
	}
	if total := num(t, disk, "total"); total <= 0 || num(t, disk, "free") < 0 {
		t.Fatalf("disk 数值异常: %v", disk)
	}

	// 任务队列: 空调度器 = 0 等待/0 运行, items 是空数组而非 null
	tasks := mustMap(t, m, "tasks")
	if tasks["queued"] != float64(0) || tasks["running"] != float64(0) {
		t.Fatalf("空调度器应全 0: %v", tasks)
	}
	if items, ok := tasks["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("items 应为空数组: %v", tasks["items"])
	}

	// 数据链路: 测试库可用; 探针中心端未启用; SSE 补发窗口固定 256
	links := mustMap(t, m, "links")
	dbm := mustMap(t, links, "db")
	if dbm["ok"] != true || dbm["type"] != "sqlite" {
		t.Fatalf("db 状态异常: %v", dbm)
	}
	if links["probeCenterEnabled"] != false || links["probesOnline"] != float64(0) {
		t.Fatalf("探针未启用时应为 false/0: %v", links)
	}
	sse := mustMap(t, links, "sse")
	if sse["ringCap"] != float64(256) {
		t.Fatalf("ringCap 应为 256: %v", sse)
	}
}

// TestCenterStatusCPUBaseline CPU 使用率 = 两次采样差分: 首次 null(无基线,
// 前端显示"-"), 间隔后再调一次必须出数且在 0-100 内。
func TestCenterStatusCPUBaseline(t *testing.T) {
	h, _ := newV2TestEnv(t)
	centerStatusTestMode(t)
	resetCPUBaseline(t)

	first := centerStatusData(t, h)
	cpu := mustMap(t, first, "cpu")
	if cpu["percent"] != nil {
		t.Fatalf("首次调用无基线, percent 应为 null: %v", cpu)
	}

	time.Sleep(120 * time.Millisecond) // 让两次采样的节拍差可测(任何平台都 >0)
	second := centerStatusData(t, h)
	cpu2 := mustMap(t, second, "cpu")
	p, ok := cpu2["percent"].(float64)
	if !ok {
		t.Fatalf("第二次调用 percent 应为数字: %v", cpu2)
	}
	if p < 0 || p > 100 {
		t.Fatalf("percent 越界: %v", p)
	}
}

// TestCenterStatusDegradesWithoutDB 数据库不可用时接口不 503、结构完整、
// db.ok=false(逐项降级, 面板常驻不应被单点数据源拖垮)。
func TestCenterStatusDegradesWithoutDB(t *testing.T) {
	centerStatusTestMode(t)
	resetCPUBaseline(t)

	prevGet := v2GetDB
	v2GetDB = func() *db.Database { return nil }
	t.Cleanup(func() { v2GetDB = prevGet })

	req := httptest.NewRequest("GET", "/api/v2/center/status", nil)
	w := httptest.NewRecorder()
	hCenterStatus(w, req)
	if w.Code != 200 {
		t.Fatalf("db 不可用也应 200(逐项降级), got %d", w.Code)
	}
	var body struct {
		Code int    `json:"code"`
		Data map[string]any
	}
	if err := jsonUnmarshalSafe(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if body.Code != server.CodeOK {
		t.Fatalf("code=%d", body.Code)
	}
	links := mustMap(t, body.Data, "links")
	if dbm := mustMap(t, links, "db"); dbm["ok"] != false {
		t.Fatalf("db 不可用时 ok 应为 false: %v", dbm)
	}
	// 其余子项不受影响
	if mem := mustMap(t, body.Data, "mem"); mem["ok"] != true {
		t.Fatalf("db 故障不应连带 mem 降级: %v", mem)
	}
}

// ===== 辅助 =====

// centerStatusData 请求一次中心端状态接口并解出 data 对象。
func centerStatusData(t *testing.T, h http.Handler) map[string]any {
	t.Helper()
	w := doReq(t, h, "GET", "/api/v2/center/status", "")
	if w.Code != 200 {
		t.Fatalf("status=%d body=%.300s", w.Code, w.Body.String())
	}
	out := decodeResp(t, w)
	if out.Code != server.CodeOK {
		t.Fatalf("resp code=%d message=%s", out.Code, out.Message)
	}
	m, ok := out.Data.(map[string]any)
	if !ok {
		t.Fatalf("data 不是对象: %#v", out.Data)
	}
	return m
}

func mustMap(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("字段 %s 缺失或非对象: %v", key, m[key])
	}
	return v
}

func num(t *testing.T, m map[string]any, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("字段 %s 缺失或非数字: %v", key, m[key])
	}
	return v
}
