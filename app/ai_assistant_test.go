// ai_assistant_test.go 小 Y 问答助手契约测试(2026-09-27)。
//
// 守"会静默失效"的契约(不复述实现):
//   - Prompt 拼接顺序(任务书): 系统 PROMPT 在前, 页面上下文在后, 提问独立 ——
//     顺序漂移会让模型把页面数据当指令(提示注入面)或丢失"只基于页面数据"约束;
//   - 页面数据必须脱敏后注入(密钥类字段不能进 LLM, 安全边界);
//   - 未自定义 PROMPT 时回退内置默认(用户删空保存 = 恢复默认, 不是变空提示词);
//   - 会话上下文按用户隔离 + 覆盖传参优先(答的必须是当前页面)。
package main

import (
	"strings"
	"testing"

	"yugsight/internal/ai"
)

func TestAssistantPromptAssemblyOrder(t *testing.T) {
	prompt := "SYSTEM-PROMPT-ANCHOR"
	data := map[string]any{"total": 5, "list": []any{map[string]any{"title": "Redis 未授权访问"}}}

	system, user := buildAssistantMessages(prompt, "vulns", "漏洞管理", data, "高危有几个?", "zh")

	// 任务书顺序: 1.系统 PROMPT 2.页面上下文 3.提问
	if !strings.HasPrefix(system, prompt) {
		t.Fatalf("system 必须以系统 PROMPT 开头: %q", system[:min(len(system), 40)])
	}
	idxPrompt := strings.Index(system, "SYSTEM-PROMPT-ANCHOR")
	idxCtx := strings.Index(system, "当前页面上下文")
	if idxCtx < 0 || idxCtx < idxPrompt {
		t.Fatalf("页面上下文必须在系统 PROMPT 之后: prompt@%d ctx@%d", idxPrompt, idxCtx)
	}
	// 提问独立于 system(进 user 消息)
	if user != "高危有几个?" || strings.Contains(system, "高危有几个?") {
		t.Fatalf("提问必须作为 user 消息: user=%q", user)
	}
	// "只基于页面数据"约束必须随上下文注入
	if !strings.Contains(system, "只基于以上页面数据回答") {
		t.Fatalf("缺少'只基于页面数据'约束: %q", system)
	}
}

func TestAssistantPromptNoContext(t *testing.T) {
	system, user := buildAssistantMessages("P-ANCHOR", "", "", nil, "你好", "zh")
	if system != "P-ANCHOR" {
		t.Fatalf("无上下文时 system 应只有 PROMPT: %q", system)
	}
	if user != "你好" {
		t.Fatalf("user 应为提问: %q", user)
	}
}

func TestAssistantPromptDesensitizesData(t *testing.T) {
	// 页面数据里可能含口令/令牌(如抓包页、弱口令页) —— 进 LLM 前必须脱敏
	data := map[string]any{
		"hit": "password=secret123",
		"auth": map[string]any{"x_api_key": "abc-123-token"},
	}
	system, _ := buildAssistantMessages("P", "weakpass", "弱口令", data, "命中了什么?", "zh")
	if strings.Contains(system, "secret123") {
		t.Fatalf("口令值必须脱敏, 实际注入: %q", system)
	}
	if !strings.Contains(system, "***") {
		t.Fatalf("脱敏后应含 *** 占位: %q", system)
	}
}

func TestAssistantPromptTruncatesOversizedData(t *testing.T) {
	big := strings.Repeat("x", 20*1024) // 超过 assistantCtxMaxBytes(16KB)
	system, _ := buildAssistantMessages("P", "assets", "资产", map[string]any{"blob": big}, "q", "zh")
	if len(system) > len("P")+assistantCtxMaxBytes+1024 {
		t.Fatalf("超长上下文未截断: system 长度 %d", len(system))
	}
	if !strings.Contains(system, "...[truncated]") {
		t.Fatalf("截断标记缺失: %q", system[len(system)-60:])
	}
}

func TestAssistantDefaultPromptFallback(t *testing.T) {
	// 未配置 assistant 节 = 默认关 + 空 PROMPT → 回退内置默认(不是空提示词)
	cfg := ai.LoadConfig(nil)
	if cfg.Assistant.Enabled {
		t.Fatalf("小 Y 必须默认关闭(规则 5)")
	}
	if cfg.AssistantPrompt("zh") == "" || !strings.Contains(cfg.AssistantPrompt("zh"), "小Y") {
		t.Fatalf("空 PROMPT 必须回退内置默认: %q", cfg.AssistantPrompt("zh")[:min(len(cfg.AssistantPrompt("zh")), 40)])
	}
	// 2026-10-04 i18n: 未自定义时英文 UI 回英文人设
	if !strings.Contains(cfg.AssistantPrompt("en"), "XiaoY") || strings.Contains(cfg.AssistantPrompt("en"), "小Y") {
		t.Fatalf("英文默认人设错误: %q", cfg.AssistantPrompt("en")[:min(len(cfg.AssistantPrompt("en")), 40)])
	}
	// 自定义 PROMPT 必须被尊重(不随语言自动翻译)
	cfg2 := ai.LoadConfig([]byte(`{"assistant":{"enabled":true,"prompt":"CUSTOM-ANCHOR"}}`))
	if !cfg2.Assistant.Enabled {
		t.Fatalf("enabled=true 必须被尊重")
	}
	if cfg2.AssistantPrompt("zh") != "CUSTOM-ANCHOR" || cfg2.AssistantPrompt("en") != "CUSTOM-ANCHOR" {
		t.Fatalf("自定义 PROMPT 必须生效且不被翻译: %q", cfg2.AssistantPrompt("zh"))
	}
}

func TestAssistantSessionCtxPerUser(t *testing.T) {
	setAssistantCtx("alice", assistantCtx{PageType: "vulns", Data: map[string]any{"n": 1}})
	setAssistantCtx("bob", assistantCtx{PageType: "console", Data: map[string]any{"n": 2}})

	a, ok := getAssistantCtx("alice")
	if !ok || a.PageType != "vulns" {
		t.Fatalf("alice 上下文应独立: %+v", a)
	}
	b, _ := getAssistantCtx("bob")
	if b.PageType != "console" {
		t.Fatalf("bob 上下文被污染: %+v", b)
	}
	// 同用户二次上报 = 覆盖(最新页面为准)
	setAssistantCtx("alice", assistantCtx{PageType: "vulndetail"})
	a, _ = getAssistantCtx("alice")
	if a.PageType != "vulndetail" {
		t.Fatalf("二次上报应覆盖旧值: %+v", a)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
