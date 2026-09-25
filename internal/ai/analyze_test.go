package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// setupAnalyzeEnv 测试环境: 配置读取器 + ChatFn 接缝 + 记忆/索引置空。
// 返回捕获器: system/user 可被断言。
type chatCapture struct {
	system string
	user   string
	answer string
	err    error
}

func setupAnalyzeEnv(t *testing.T, cfgJSON string) *chatCapture {
	t.Helper()
	cap := &chatCapture{answer: "结论: 正常。分析: 无异常。建议: 无需处置。"}
	SetChatFnForTest(func(ctx context.Context, b BasicConfig, system, user string) (string, error) {
		cap.system, cap.user = system, user
		if cap.err != nil {
			return "", cap.err
		}
		return cap.answer, nil
	})
	reader := func() ([]byte, bool) { return nil, false }
	if cfgJSON != "" {
		b := []byte(cfgJSON)
		reader = func() ([]byte, bool) { return b, true }
	}
	SetConfigReader(reader)
	SetMemoryStore(func() MemoryStore { return nil })
	SetRetriever(nil)
	t.Cleanup(func() {
		SetChatFnForTest(nil)
		SetConfigReader(func() ([]byte, bool) { return nil, false })
		SetMemoryStore(func() MemoryStore { return nil })
		SetRetriever(nil)
	})
	return cap
}

const enabledCfg = `{"enabled":true,"apiBase":"http://x","model":"m1"}`

// TestAnalyzeGate 双保险闸门: 全局关 / 模块关 / 未知模块, 都不发出 LLM 调用
// (chatFn 未被调用 = 捕获器 system 为空)。
func TestAnalyzeGate(t *testing.T) {
	cap := setupAnalyzeEnv(t, "")
	_, err := Analyze(context.Background(), Input{Module: "scan", Payload: json.RawMessage(`{}`)})
	if err == nil || !strings.Contains(err.Error(), "AI 未启用") {
		t.Fatalf("全局关应拒绝: %v", err)
	}
	if cap.system != "" {
		t.Fatal("拒绝时不应调用 LLM")
	}

	cap = setupAnalyzeEnv(t, `{"enabled":true,"modules":{"scan":false}}`)
	_, err = Analyze(context.Background(), Input{Module: "scan"})
	if err == nil || !strings.Contains(err.Error(), "关闭") {
		t.Fatalf("模块关应拒绝: %v", err)
	}
	if cap.system != "" {
		t.Fatal("模块关时不应调用 LLM")
	}

	cap = setupAnalyzeEnv(t, enabledCfg)
	if _, err = Analyze(context.Background(), Input{Module: "nosuch"}); err == nil {
		t.Fatal("未知模块应拒绝")
	}
}

// TestAnalyzeFullPipeline 全链路: 模板渲染 + 记忆注入 + RAG 参考段 +
// 结果字段。
func TestAnalyzeFullPipeline(t *testing.T) {
	cap := setupAnalyzeEnv(t, enabledCfg)

	// 记忆: 一条资产扫描记录
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.Local)
	SetMemoryStore(func() MemoryStore {
		return staticStore{
			assets: []MemoryEntry{{At: now.Add(-time.Hour), Label: "10.0.0.1 | high | Redis 未授权访问"}},
		}
	})
	// RAG: 一篇含查询词的文档(经统一检索器; 无 embedding → 关键词模式)
	SetRetriever(NewRetriever(NewIndex([]*Doc{
		docFor(t, "d1", "Redis 手册", "Redis 未授权访问的修复: 设置 requirepass。", true),
	})))

	payload := json.RawMessage(`{"findings":[{"title":"Redis 未授权访问","severity":"high"}],"rounds":[{"ok":true}]}`)
	res, err := Analyze(context.Background(), Input{
		Module:  "capture",
		Payload: payload,
		Assets:  []string{"10.0.0.1"},
		Summary: "Redis 未授权访问",
		Target:  "10.0.0.1",
		Now:     now,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	// system 边界恒定
	if !strings.Contains(cap.system, "不生成或执行任何 POC") {
		t.Fatalf("system 边界缺失: %s", cap.system)
	}
	// 模板渲染: 默认抓包模板的标题 + 时间 + 资产
	if !strings.Contains(cap.user, "实时抓包结果") || !strings.Contains(cap.user, "10.0.0.1") {
		t.Fatalf("模板渲染缺失: %s", cap.user)
	}
	if !strings.Contains(cap.user, "2026-09-23 10:00:00") {
		t.Fatal("时间变量未渲染")
	}
	// 记忆注入
	if !strings.Contains(cap.user, "【资产扫描记录】") || !strings.Contains(cap.user, "Redis 未授权访问") {
		t.Fatalf("记忆未注入: %s", cap.user)
	}
	// RAG 参考段
	if !strings.Contains(cap.user, "参考文档 1: Redis 手册") {
		t.Fatalf("RAG 参考段缺失: %s", cap.user)
	}
	// 结果字段
	if res.RAGHits != 1 || res.MemoryItems != 1 || res.Template != TplLabel(TplCapture) {
		t.Fatalf("结果字段: hits=%d mem=%d tpl=%s", res.RAGHits, res.MemoryItems, res.Template)
	}
	var data map[string]any
	if err := json.Unmarshal(res.AIData, &data); err != nil {
		t.Fatalf("aiData 非法: %v", err)
	}
	if data["model"] != "m1" || data["ragHits"] != float64(1) {
		t.Fatalf("aiData 字段: %v", data)
	}
	if res.Note != cap.answer {
		t.Fatalf("note=%s", res.Note)
	}
}

// TestAnalyzeLLMError LLM 失败原样上抛(装配层 502, 报告不写坏)。
func TestAnalyzeLLMError(t *testing.T) {
	cap := setupAnalyzeEnv(t, enabledCfg)
	cap.err = context.DeadlineExceeded
	_, err := Analyze(context.Background(), Input{Module: "scan", Payload: json.RawMessage(`{}`)})
	if err == nil || err != context.DeadlineExceeded {
		t.Fatalf("应透传 LLM 错误: %v", err)
	}
}

// TestAnalyzeVarExtraction 变量抽取: scan_result 取 findings 字段,
// metric_data 取 rounds/events/targets 之一, 无字段 = "无"。
func TestAnalyzeVarExtraction(t *testing.T) {
	cap := setupAnalyzeEnv(t, enabledCfg)
	// scan 模块: findings → scan_result
	_, err := Analyze(context.Background(), Input{
		Module:  "scan",
		Payload: json.RawMessage(`{"findings":[{"title":"XSS"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cap.user, "XSS") || !strings.Contains(cap.user, "扫描结果(漏洞清单)") {
		t.Fatalf("scan_result 未注入: %s", cap.user)
	}
	// monitor 模块: events → metric_data
	_, err = Analyze(context.Background(), Input{
		Module:  "monitor",
		Payload: json.RawMessage(`{"events":[{"type":"offline"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cap.user, "offline") {
		t.Fatalf("metric_data 未注入: %s", cap.user)
	}
	// 空 payload: raw_data = 无原始数据, 不 panic
	if _, err = Analyze(context.Background(), Input{Module: "capture"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cap.user, "无原始数据") {
		t.Fatalf("空 payload 口径: %s", cap.user)
	}
}

// staticStore 单范围固定数据的假 Store。
type staticStore struct {
	assets     []MemoryEntry
	alerts     []MemoryEntry
	captures   []MemoryEntry
	metrics    []MemoryEntry
}

func (s staticStore) AssetHistory(since time.Time, limit int) ([]MemoryEntry, error) {
	return s.take(s.assets, since, limit), nil
}
func (s staticStore) AlertHistory(since time.Time, limit int) ([]MemoryEntry, error) {
	return s.take(s.alerts, since, limit), nil
}
func (s staticStore) CaptureHistory(since time.Time, limit int) ([]MemoryEntry, error) {
	return s.take(s.captures, since, limit), nil
}
func (s staticStore) MetricHistory(since time.Time, limit int) ([]MemoryEntry, error) {
	return s.take(s.metrics, since, limit), nil
}

func (s staticStore) take(items []MemoryEntry, since time.Time, limit int) []MemoryEntry {
	var out []MemoryEntry
	for _, it := range items {
		if !it.At.Before(since) {
			out = append(out, it)
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}
