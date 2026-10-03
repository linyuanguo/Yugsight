package main

// node_templates_test.go 采集模板(阶段 C)契约测试。
//
// 守的契约(改坏会静默失效):
//  1. 模板 CRUD: PUT 整体替换 + 校验(未知协议/重复 ID → 400, 坏条目不静默丢);
//  2. 建任务继承: 选模板的任务自动把模板默认阈值写入 PerNode[taskID]
//     (之后仍可在"每节点阈值"覆盖 —— 继承是一次性起点);
//  3. 删任务联动清 PerNode 残留(否则 settings.json 留孤儿 key)。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"yugsight/internal/collect"
	"yugsight/internal/monitor"
)

// injectNoNodeSources 注入空采集/监控单例 + 临时 settings 路径
// (模板/阈值都会落 settings.json, 必须隔离, 防污染真实 exe 目录)。
func injectNoNodeSources(t *testing.T) {
	t.Helper()
	resetCollectForTest()
	nodeInst = collect.New(collect.Config{}, func() collect.Config { return collect.Config{} }, nil)
	resetMonitorForTest()
	monInst = monitor.New(monitor.Config{}, func() monitor.Config { return monitor.Config{} }, nil)
	setSettingsTestPath(filepath.Join(t.TempDir(), "settings.json"))
	t.Cleanup(func() {
		setSettingsTestPath("")
		resetSettingsCache()
		resetCollectForTest()
		resetMonitorForTest()
	})
}

func putJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("PUT", path, strings.NewReader(body)))
	return w
}

func TestNodeTemplatesCRUD(t *testing.T) {
	h, _ := newV2TestEnv(t)
	injectNoNodeSources(t)

	// 非法: 未知协议 → 400(静默丢模板会让"建任务选了模板却没继承"最难排查)
	w := putJSON(t, h, "/api/v2/node/templates", `{"templates":[{"id":"t1","name":"x","protocol":"nonsense"}]}`)
	if w.Code != 400 {
		t.Fatalf("未知协议应 400, got %d: %.300s", w.Code, w.Body.String())
	}
	// 非法: 重复 ID → 400
	w = putJSON(t, h, "/api/v2/node/templates",
		`{"templates":[{"id":"t1","name":"a","protocol":"snmp"},{"id":"t1","name":"b","protocol":"ssh"}]}`)
	if w.Code != 400 {
		t.Fatalf("重复 ID 应 400, got %d", w.Code)
	}
	// 合法: 两条模板
	w = putJSON(t, h, "/api/v2/node/templates",
		`{"templates":[{"id":"t1","name":"Linux 服务器","protocol":"ssh","alerts":{"cpuPct":80}},` +
			`{"id":"t2","name":"交换机","protocol":"snmp"}]}`)
	if w.Code != 200 {
		t.Fatalf("保存应 200, got %d: %.300s", w.Code, w.Body.String())
	}
	// 回读: 两条都在
	w = doReq(t, h, "GET", "/api/v2/node/templates", "")
	var out struct {
		Data struct {
			Count int `json:"count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Data.Count != 2 {
		t.Fatalf("模板数应为 2, got %d: %s", out.Data.Count, w.Body.String())
	}
}

// TestTemplateInheritOnTaskCreate 建任务选模板 → PerNode[taskID] 继承模板阈值。
func TestTemplateInheritOnTaskCreate(t *testing.T) {
	h, d := newV2TestEnv(t)
	injectNoNodeSources(t)

	// 先存一个带默认阈值的模板
	w := putJSON(t, h, "/api/v2/node/templates",
		`{"templates":[{"id":"t1","name":"低配服务器","protocol":"ssh","alerts":{"cpuPct":60}}]}`)
	if w.Code != 200 {
		t.Fatalf("存模板失败: %d %.300s", w.Code, w.Body.String())
	}

	// 用该模板建任务
	body := `{"name":"web01","side":"host","protocol":"ssh","target":"192.168.1.50","templateId":"t1"}`
	w = doReq(t, h, "POST", "/api/v2/node/tasks", body)
	if w.Code != 200 {
		t.Fatalf("建任务应 200, got %d: %.300s", w.Code, w.Body.String())
	}
	taskID := "ssh-192.168.1.50" // 稳定 ID = 协议 + 目标(冒号→下划线)

	// 继承: 状态接口回带的 perNode 应含该任务且 cpuPct=60
	w = doReq(t, h, "GET", "/api/v2/node/status", "")
	var st struct {
		Data struct {
			PerNode map[string]collect.Alerts `json:"perNode"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	a, ok := st.Data.PerNode[taskID]
	if !ok {
		t.Fatalf("建任务应继承模板阈值到 PerNode[%s], got: %s", taskID, w.Body.String())
	}
	if a.CPUPct != 60 {
		t.Fatalf("继承的 cpuPct 应为 60, got %d", a.CPUPct)
	}

	// 删任务 → PerNode 残留应被清(否则 settings.json 留孤儿 key)
	w = doReq(t, h, "DELETE", "/api/v2/node/tasks/"+taskID, "")
	if w.Code != 200 {
		t.Fatalf("删任务应 200, got %d", w.Code)
	}
	w = doReq(t, h, "GET", "/api/v2/node/status", "")
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := st.Data.PerNode[taskID]; ok {
		t.Fatalf("删任务后应清除 PerNode 残留: %s", w.Body.String())
	}
	_ = d
}
