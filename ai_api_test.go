package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yugsight/ai"
	"yugsight/report"
)

// aiTestMux 阶段 3 AI 路由的测试 mux(与 v2 组独立, 免登录模式直通)。
func aiTestMux(t *testing.T) http.Handler {
	t.Helper()
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })
	mux := http.NewServeMux()
	RegisterAIRoutes(mux)
	return mux
}

// aiSettingsEnv 把 settings.json 指向临时目录并写入给定内容, 并装配
// ai 包(配置读取器/记忆源/RAG 索引 —— 即 InitAI 的测试版)。
// 收尾时把 ai 包状态全部复位(不读真配置/不依赖已关闭的测试库)。
func aiSettingsEnv(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setSettingsTestPath(path)
	resetSettingsCache()
	InitAI()
	t.Cleanup(func() {
		setSettingsTestPath("")
		resetSettingsCache()
		ai.SetConfigReader(func() ([]byte, bool) { return nil, false })
		ai.SetMemoryStore(func() ai.MemoryStore { return nil })
		ai.SetRAGIndex(nil)
		ai.SetRetriever(nil)
	})
}

// aiChatMock 替换 LLM 调用为固定应答(离线), 返回捕获的 user 提示词
// (指针变量本身 —— 调用前读它是空串, 调用后读它是 Prompt 全文)。
func aiChatMock(t *testing.T, answer string) *string {
	t.Helper()
	captured := new(string)
	ai.SetChatFnForTest(func(ctx context.Context, b ai.BasicConfig, system, u string) (string, error) {
		*captured = u
		return answer, nil
	})
	t.Cleanup(func() { ai.SetChatFnForTest(nil) })
	return captured
}

const aiEnabledSettings = `{"ai":{"enabled":true,"apiBase":"http://127.0.0.1:9999/v1","model":"test-model"}}`

// TestAIStatusShape 状态接口契约: 默认全关 + 模块开关 + 三套模板 +
// RAG/记忆库配置齐全(业务页 AI 按钮的置灰依据就是这里)。
func TestAIStatusShape(t *testing.T) {
	aiSettingsEnv(t, "")
	h := aiTestMux(t)
	w := doReq(t, h, "GET", "/api/ai", "")
	if w.Code != 200 {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, key := range []string{
		`"enabled":false`, `"modules"`, `"prompts"`, `"rag"`, `"memory"`,
		"maxContext", "temperature", "topP",
	} {
		if !strings.Contains(body, key) {
			t.Fatalf("status 缺少 %s: %s", key, body)
		}
	}
}

// TestAIConfigSaveMerge 基础配置保存: 只动基础键, prompts/rag/memory
// 不受影响(合并写契约 —— 误整节覆盖会让用户已改的模板/文档配置丢失)。
func TestAIConfigSaveMerge(t *testing.T) {
	aiSettingsEnv(t, aiEnabledSettings)
	// 先改一套模板, 作为"其它键"的探针
	h := aiTestMux(t)
	w := doReq(t, h, "POST", "/api/ai/templates", `{"key":"scan","content":"自定义模板 {{raw_data}}"}`)
	if w.Code != 200 {
		t.Fatalf("模板保存: %d %s", w.Code, w.Body.String())
	}

	// 保存基础配置(只传部分字段)
	w = doReq(t, h, "POST", "/api/ai/config", `{"apiBase":"http://10.0.0.1:8080/v1","model":"q1","timeoutSec":120,"modules":{"capture":false}}`)
	if w.Code != 200 {
		t.Fatalf("config 保存: %d %s", w.Code, w.Body.String())
	}

	// 回读: 新值生效
	w = doReq(t, h, "GET", "/api/ai", "")
	body := w.Body.String()
	for _, key := range []string{`"apiBase":"http://10.0.0.1:8080/v1"`, `"model":"q1"`, `"timeoutSec":120`, `"capture":false`} {
		if !strings.Contains(body, key) {
			t.Fatalf("保存未生效 %s: %s", key, body)
		}
	}
	// 模板探针仍在(未被基础配置保存冲掉)
	w = doReq(t, h, "GET", "/api/ai/templates", "")
	if !strings.Contains(w.Body.String(), "自定义模板") {
		t.Fatalf("基础配置保存冲掉了模板: %s", w.Body.String())
	}

	// 未知模板键 400
	if w := doReq(t, h, "POST", "/api/ai/templates", `{"key":"bogus","content":"x"}`); w.Code != 400 {
		t.Fatalf("未知模板键应 400: %d", w.Code)
	}
	// 恢复默认
	if w := doReq(t, h, "POST", "/api/ai/templates/reset", `{"key":"scan"}`); w.Code != 200 {
		t.Fatalf("reset: %d %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/ai/templates", "")
	if strings.Contains(w.Body.String(), "自定义模板") {
		t.Fatal("恢复默认后不应再有自定义内容")
	}
}

// TestAIRAGDocsLifecycle 文档库全生命周期: 上传(分片) → 列表 →
// 检索 → 禁用(检索不到) → 删除; 空文档拒绝。
func TestAIRAGDocsLifecycle(t *testing.T) {
	// RAG 文档存 v2 库(ai_docs 表), 需要注入测试库
	_, d := newV2TestEnv(t)
	aiSettingsEnv(t, "")
	h := aiTestMux(t)
	_ = d

	// 空文档 400
	if w := doReq(t, h, "POST", "/api/ai/rag/docs", `{"name":"空","content":"   "}`); w.Code != 400 {
		t.Fatalf("空文档应 400: %d", w.Code)
	}

	// 上传
	w := doReq(t, h, "POST", "/api/ai/rag/docs",
		`{"name":"Redis 手册","category":"漏洞手册","content":"Redis 未授权访问: 6379 端口无密码。\n\n修复: 设置 requirepass 并限制来源。"}`)
	if w.Code != 200 {
		t.Fatalf("上传: %d %s", w.Code, w.Body.String())
	}

	// 列表(先取 ID, 再断言展示)
	wList := doReq(t, h, "GET", "/api/ai/rag", "")
	if wList.Code != 200 || !strings.Contains(wList.Body.String(), "Redis 手册") {
		t.Fatalf("列表: %d %s", wList.Code, wList.Body.String())
	}
	// 根包 jsonOK 直出(无 data 壳)
	var listResp struct {
		Docs []struct {
			ID string `json:"id"`
		} `json:"docs"`
	}
	if err := jsonUnmarshalBody(wList, &listResp); err != nil {
		t.Fatal(err)
	}
	if len(listResp.Docs) != 1 {
		t.Fatalf("应有 1 篇文档: %s", wList.Body.String())
	}
	id := listResp.Docs[0].ID

	// 检索命中(查询词用 ASCII, 避免 URL 空格)
	w = doReq(t, h, "GET", "/api/ai/rag/search?q=Redis", "")
	if !strings.Contains(w.Body.String(), "requirepass") {
		t.Fatalf("检索未命中: %s", w.Body.String())
	}

	// 禁用 → 检索不到
	w = doReq(t, h, "POST", "/api/ai/rag/docs/"+id+"/toggle", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("禁用: %d %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/ai/rag/search?q=Redis", "")
	if strings.Contains(w.Body.String(), "requirepass") {
		t.Fatal("禁用文档不应被检索到")
	}

	// 删除
	if w := doReq(t, h, "DELETE", "/api/ai/rag/docs/"+id, ""); w.Code != 200 {
		t.Fatalf("删除: %d %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/ai/rag", "")
	if strings.Contains(w.Body.String(), "Redis 手册") {
		t.Fatal("删除后列表仍有该文档")
	}
}

// TestAIMemoryConfig 记忆库配置: 默认全开 + 保存后回读一致 +
// 非法值不覆盖。
func TestAIMemoryConfig(t *testing.T) {
	aiSettingsEnv(t, "")
	h := aiTestMux(t)

	w := doReq(t, h, "GET", "/api/ai/memory", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"retainDays":30`) {
		t.Fatalf("默认: %d %s", w.Code, w.Body.String())
	}

	w = doReq(t, h, "POST", "/api/ai/memory",
		`{"enabled":false,"retainDays":7,"maxItems":5,"compress":false,"scopes":{"alerts":true}}`)
	if w.Code != 200 {
		t.Fatalf("保存: %d %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/ai/memory", "")
	body := w.Body.String()
	for _, key := range []string{`"enabled":false`, `"retainDays":7`, `"maxItems":5`, `"compress":false`, `"alerts":true`, `"assets":false`} {
		if !strings.Contains(body, key) {
			t.Fatalf("回读缺 %s: %s", key, body)
		}
	}
}

// TestAIAnalyzeWriteBack 分析触发 → 报告中心回写(AI 三字段) →
// 详情接口可见; 未启用时 503; 模块关闭时 503。
func TestAIAnalyzeWriteBack(t *testing.T) {
	aiSettingsEnv(t, aiEnabledSettings)
	mock := aiChatMock(t, "结论: 发现 Redis 未授权访问, 风险高。建议: 立即设置密码。")

	hV2, d := newV2TestEnv(t)
	seed := seedRaw(t, d, report.RawModScan, "扫描报告A", []string{"10.0.0.1"}, nil, mustTime(t, "2026-09-23T09:00:00Z"))

	hAI := aiTestMux(t)

	// 未启用场景: 换一个关闭配置的 settings(重设) —— 用新测试目录
	aiSettingsEnv(t, `{"ai":{"enabled":false}}`)
	if w := doReq(t, hAI, "POST", "/api/ai/analyze", `{"reportId":"`+seed.ID+`"}`); w.Code != 503 {
		t.Fatalf("未启用应 503: %d %s", w.Code, w.Body.String())
	}

	// 启用 + 模块关闭
	aiSettingsEnv(t, `{"ai":{"enabled":true,"modules":{"scan":false}}}`)
	if w := doReq(t, hAI, "POST", "/api/ai/analyze", `{"reportId":"`+seed.ID+`"}`); w.Code != 503 {
		t.Fatalf("模块关应 503: %d %s", w.Code, w.Body.String())
	}

	// 启用 → 分析成功并回写
	aiSettingsEnv(t, aiEnabledSettings)
	w := doReq(t, hAI, "POST", "/api/ai/analyze", `{"reportId":"`+seed.ID+`"}`)
	if w.Code != 200 {
		t.Fatalf("analyze: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "发现 Redis 未授权访问") {
		t.Fatalf("应答缺研判: %s", w.Body.String())
	}
	if !strings.Contains(*mock, "扫描报告A") && !strings.Contains(*mock, "10.0.0.1") {
		t.Fatalf("Prompt 未含报告数据: %s", *mock)
	}

	// 报告中心详情: AI 三字段可见
	w = doReq(t, hV2, "GET", "/api/v2/raw/"+seed.ID, "")
	body := w.Body.String()
	for _, key := range []string{"aiAnalyzedAt", "发现 Redis 未授权访问", "aiData"} {
		if !strings.Contains(body, key) {
			t.Fatalf("详情缺 %s: %s", key, body)
		}
	}

	// 参数缺失 400
	if w := doReq(t, hAI, "POST", "/api/ai/analyze", `{}`); w.Code != 400 {
		t.Fatalf("缺参数应 400: %d", w.Code)
	}
}

// TestAIMergeKeepsAI 合并报告保留源报告的 AI 研判(多选合并原始报告
// + AI 分析报告的底座契约)。
func TestAIMergeKeepsAI(t *testing.T) {
	aiSettingsEnv(t, "")
	hV2, d := newV2TestEnv(t)

	a := seedRaw(t, d, report.RawModScan, "报告A(已分析)", []string{"10.0.0.1"}, nil, mustTime(t, "2026-09-23T09:00:00Z"))
	b := seedRaw(t, d, report.RawModCapture, "报告B", []string{"10.0.0.2"}, nil, mustTime(t, "2026-09-23T10:00:00Z"))

	// 给 A 直接写 AI 字段(模拟分析回写)
	got, err := d.RawReports().Get(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	when := mustTime(t, "2026-09-23T11:00:00Z")
	got.AIAnalyzedAt = &when
	got.AINote = "AI: 报告A 存在高危漏洞"
	got.AIData = []byte(`{"model":"m"}`)
	if _, err := d.RawReports().Upsert(got); err != nil {
		t.Fatal(err)
	}

	w := doReq(t, hV2, "POST", "/api/v2/raw/merge",
		`{"ids":["`+a.ID+`","`+b.ID+`"],"title":"汇总"}`)
	if w.Code != 200 {
		t.Fatalf("merge: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "含 AI 分析 1") {
		t.Fatalf("摘要未计 AI 数: %s", w.Body.String())
	}
	// 取合并报告 ID, 详情(带 payload)里 mergedFrom 应保留 A 的 AI 内容
	var mergeResp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := jsonUnmarshalBody(w, &mergeResp); err != nil {
		t.Fatal(err)
	}
	if mergeResp.Data.ID == "" {
		t.Fatalf("无合并报告 ID: %s", w.Body.String())
	}
	w = doReq(t, hV2, "GET", "/api/v2/raw/"+mergeResp.Data.ID, "")
	if !strings.Contains(w.Body.String(), "AI: 报告A 存在高危漏洞") {
		t.Fatalf("合并丢失 AI 内容: %.500s", w.Body.String())
	}
}

// mustTime 测试用时间解析(失败即 Fatal, 不返回零值掩盖问题)。
func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// jsonUnmarshalBody 响应体解码(测试辅助)。
func jsonUnmarshalBody(w *httptest.ResponseRecorder, v any) error {
	return json.Unmarshal(w.Body.Bytes(), v)
}
