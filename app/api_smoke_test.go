package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yugsight/internal/scanner"
)

// TestVulnAPI 漏洞库 API 冒烟: 规则列表 / 内置 JSON / 导入校验(不真实写盘)
func TestVulnAPI(t *testing.T) {
	if _, errs := scanner.LoadVulnLibrary(); len(errs) > 0 {
		t.Logf("漏洞库加载警告: %v", errs)
	}
	// /api/vuln/rules: 须带 rules 列表 + 适用范围字段 + scopes 汇总
	w := httptest.NewRecorder()
	handleVulnRules(w, httptest.NewRequest("GET", "/api/vuln/rules", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"rules"`) {
		t.Fatalf("rules status=%d body=%.200s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"scopes"`) {
		t.Fatalf("rules 响应缺少 scopes 汇总: %.300s", body)
	}
	if !strings.Contains(body, `"scope":"web"`) && !strings.Contains(body, `"scope":"host"`) {
		t.Fatalf("rules 响应规则项缺少已归一化的 scope 字段: %.300s", body)
	}
	// 反序列化校验: scope 必须是 web/host, 不能是空串(前端表格直接渲染该字段)
	var rulesResp struct {
		Count  int            `json:"count"`
		Scopes map[string]int `json:"scopes"`
		Rules  []struct {
			ID    string `json:"id"`
			Scope string `json:"scope"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(body), &rulesResp); err != nil {
		t.Fatalf("rules 响应解析失败: %v", err)
	}
	if rulesResp.Count != len(rulesResp.Rules) {
		t.Fatalf("count=%d 与 rules 长度 %d 不一致", rulesResp.Count, len(rulesResp.Rules))
	}
	if rulesResp.Scopes["web"]+rulesResp.Scopes["host"] != rulesResp.Count {
		t.Fatalf("scopes 汇总 %v 与 count=%d 不匹配", rulesResp.Scopes, rulesResp.Count)
	}
	for _, rule := range rulesResp.Rules {
		if rule.Scope != "web" && rule.Scope != "host" {
			t.Fatalf("规则 %s 的 scope 取值非法/为空: %q", rule.ID, rule.Scope)
		}
	}
	// /api/vuln/builtin
	w = httptest.NewRecorder()
	handleVulnBuiltin(w, httptest.NewRequest("GET", "/api/vuln/builtin", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"rules"`) {
		t.Fatalf("builtin status=%d body=%.200s", w.Code, w.Body.String())
	}
	// /api/vuln/import: 非法 JSON -> 400
	w = httptest.NewRecorder()
	handleVulnImport(w, httptest.NewRequest("POST", "/api/vuln/import", strings.NewReader("not-json")))
	if w.Code != 400 {
		t.Fatalf("import 非法JSON status=%d", w.Code)
	}
	// /api/vuln/import: 缺必填字段的规则 -> 400(不落盘)
	w = httptest.NewRecorder()
	handleVulnImport(w, httptest.NewRequest("POST", "/api/vuln/import",
		strings.NewReader(`{"rules":[{"id":"t","name":"t"}]}`)))
	if w.Code != 400 {
		t.Fatalf("import 无效规则 status=%d", w.Code)
	}
}

// TestUIContainsNewUI 校验嵌入页面含全部新增 UI 元素(防 id 拼写错误)
func TestUIContainsNewUI(t *testing.T) {
	data, err := uiFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, id := range []string{
		"vulnCard", "bpfEx", "repScans", "nucleiParams",
		"vulnImportMask", "vulnJsonMask",
		"loadVulnRules", "renderBpfExamples", "selectedScans",
		// 任务 3.2: 白名单 / 误报管控
		"ctlCard", "wlBody", "fpBody", "loadCtl", "fp-mark",
	} {
		if !strings.Contains(s, id) {
			t.Fatalf("UI 缺少元素: %s", id)
		}
	}
}

// TestRulesUpdateAPI 规则库更新 API 冒烟: 状态 / 进度 / 日志 / 回滚参数校验。
//
// 只做只读与参数校验路径的验证: 更新与回滚会真实写 rules/ 目录与发起外网请求,
// 属端到端测试范畴(见 c5 冒烟记录), 单测里刻意不触发, 避免污染开发机规则库。
func TestRulesUpdateAPI(t *testing.T) {
	// GET /api/rules/update/status: 必须回传前端渲染所需的全部字段
	w := httptest.NewRecorder()
	handleRulesUpdateStatus(w, httptest.NewRequest("GET", "/api/rules/update/status", nil))
	if w.Code != 200 {
		t.Fatalf("status status=%d body=%.300s", w.Code, w.Body.String())
	}
	var st map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("status 响应解析失败: %v", err)
	}
	// 前端模板直接取用这几个字段, 缺失会导致页面渲染出空白而不是报错, 必须显式断言
	for _, k := range []string{"localCommit", "tiered", "backups", "direct"} {
		if _, ok := st[k]; !ok {
			t.Errorf("status 响应缺少字段 %q", k)
		}
	}
	direct, ok := st["direct"].(map[string]any)
	if !ok {
		t.Fatalf("direct 字段类型异常: %T", st["direct"])
	}
	if _, ok := direct["enabled"]; !ok {
		t.Error("direct 段缺少 enabled 字段(前端据此决定一键更新按钮是否可点)")
	}

	// status 拒绝非 GET
	w = httptest.NewRecorder()
	handleRulesUpdateStatus(w, httptest.NewRequest("POST", "/api/rules/update/status", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status 应拒绝 POST, got %d", w.Code)
	}

	// GET /api/rules/update/progress: 空闲态也必须可访问(返回 running=false)
	w = httptest.NewRecorder()
	handleRulesUpdateProgress(w, httptest.NewRequest("GET", "/api/rules/update/progress", nil))
	if w.Code != 200 {
		t.Fatalf("progress status=%d", w.Code)
	}
	var prog map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &prog); err != nil {
		t.Fatalf("progress 响应解析失败: %v", err)
	}
	if _, ok := prog["running"]; !ok {
		t.Error("progress 响应缺少 running 字段(轮询据此判断任务是否结束)")
	}

	// GET /api/rules/update/log: 无日志也必须返回 200 + entries 数组而非 null
	w = httptest.NewRecorder()
	handleRulesUpdateLog(w, httptest.NewRequest("GET", "/api/rules/update/log", nil))
	if w.Code != 200 {
		t.Fatalf("log status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"entries"`) {
		t.Errorf("log 响应缺少 entries 字段: %.200s", w.Body.String())
	}

	// GET /api/rules/update/direct/status: 未启用时也应回 200 + hint, 而不是报错,
	// 否则前端只能显示"查询失败", 用户无从知道该怎么开启
	w = httptest.NewRecorder()
	handleRulesDirectStatus(w, httptest.NewRequest("GET", "/api/rules/update/direct/status", nil))
	if w.Code != 200 {
		t.Fatalf("direct/status status=%d body=%.200s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"enabled"`) {
		t.Errorf("direct/status 缺少 enabled 字段: %.200s", w.Body.String())
	}

	// POST /api/rules/update/restore: 缺 backup 字段 -> 400(不得误触真实回滚)
	w = httptest.NewRecorder()
	handleRulesUpdateRestore(w, httptest.NewRequest("POST", "/api/rules/update/restore",
		strings.NewReader(`{}`)))
	if w.Code != 400 {
		t.Fatalf("restore 缺 backup 应为 400, got %d body=%.200s", w.Code, w.Body.String())
	}

	// POST /api/rules/update/restore: 非法备份名 -> 400 且带原因
	w = httptest.NewRecorder()
	handleRulesUpdateRestore(w, httptest.NewRequest("POST", "/api/rules/update/restore",
		strings.NewReader(`{"backup":"../../etc"}`)))
	if w.Code != 400 {
		t.Fatalf("restore 非法备份名应为 400, got %d body=%.200s", w.Code, w.Body.String())
	}

	// restore 拒绝非 POST
	w = httptest.NewRecorder()
	handleRulesUpdateRestore(w, httptest.NewRequest("GET", "/api/rules/update/restore", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("restore 应拒绝 GET, got %d", w.Code)
	}
}
