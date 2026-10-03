// ai_assistant_api.go 小 Y 问答助手(2026-09-27) —— main 包与 ai 包的装配连接点。
//
// 分工(与 ai_api.go 同角色):
//
//	ai 包(internal/ai)  配置结构 + 默认系统提示词(纯逻辑, 可离线单测);
//	本文件              路由 / 会话上下文暂存 / Prompt 拼接 / LLM 调用适配层接线。
//
// 设计要点:
//   - 模型调用不写第二套 HTTP 路径: 复用 scanner.AIAnalyzer.StreamChat
//     (OpenAI 兼容协议统一封装, backend=ollama 即本地模型扩展位, SSE 流式
//     + 重试 + 全局并发限流全部现成);
//   - Prompt 拼接顺序(任务书): ①系统 PROMPT ②页面上下文 ③用户提问。
//     ①②进 system 消息(约束必须贯穿整个生成过程), ③进 user 消息;
//   - 页面上下文双通道: 前端路由变化时上报(POST /api/v1/ai/context, 按登录
//     用户暂存于内存), 提问时前端再带一次(覆盖传参优先) —— 保证"答的是
//     用户当前正在看的页面", 不依赖可能滞后的暂存值;
//   - 鉴权复用现有登录体系(requireAuth, 不新增独立账号);
//   - 默认关闭(规则 5): assistant.enabled 零值 = 关, 关闭时接口返回未启用,
//     前端隐藏助手入口, 不发起任何 LLM 调用。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"yugsight/internal/ai"
	"yugsight/internal/scanner"
)

const (
	assistantCtxLimit    = 128       // 会话上下文缓存上限(按登录用户, 128 远超同时在线数)
	assistantCtxMaxBytes = 16 * 1024 // 页面上下文注入 LLM 的脱敏后上限(防挤占上下文预算)
	assistantQuestionMax = 2000      // 单条提问长度上限(字符)
)

// ===== 会话级页面上下文暂存 =====
//
// 按登录用户暂存"最新页面上下文"(前端路由变化时上报)。纯内存不落库:
// 上下文是瞬态 UI 状态, 重启丢失无影响(前端下次路由变化会重新上报)。
// authDisabled(免登录模式)下所有请求归入 "local" 单一键。

type assistantCtx struct {
	PageType string // 页面类型(vulns/vulndetail/nodemonitor/console/...)
	PageName string // 页面名称(路由 meta.title)
	Data     any    // 页面关键数据(列表/详情/筛选条件)
	At       time.Time
}

var (
	assistantMu   sync.Mutex
	assistantCtxs = map[string]assistantCtx{}
)

func setAssistantCtx(user string, c assistantCtx) {
	assistantMu.Lock()
	defer assistantMu.Unlock()
	if len(assistantCtxs) >= assistantCtxLimit && !containsAssistantCtx(user) {
		evictOldestAssistantCtx()
	}
	c.At = time.Now()
	assistantCtxs[user] = c
}

func getAssistantCtx(user string) (assistantCtx, bool) {
	assistantMu.Lock()
	defer assistantMu.Unlock()
	c, ok := assistantCtxs[user]
	return c, ok
}

func containsAssistantCtx(user string) bool {
	_, ok := assistantCtxs[user]
	return ok
}

func evictOldestAssistantCtx() {
	var oldest string
	var oldestAt time.Time
	for u, c := range assistantCtxs {
		if oldest == "" || c.At.Before(oldestAt) {
			oldest, oldestAt = u, c.At
		}
	}
	if oldest != "" {
		delete(assistantCtxs, oldest)
	}
}

// assistantUser 当前会话用户(与 whoami 同口径; 免登录模式/无效会话 → "local")。
func assistantUser(r *http.Request) string {
	if c, err := r.Cookie("yugsight_session"); err == nil && c.Value != "" {
		if u := sessionUser(c.Value); u != "" {
			return u
		}
	}
	return "local"
}

// ===== Prompt 拼接(任务书顺序: 系统 PROMPT → 页面上下文 → 用户提问) =====

// buildAssistantMessages 组装小 Y 的 LLM 请求消息。
//
// 顺序(任务书): 1.系统 PROMPT 2.页面上下文数据 3.用户当前提问。
// 落地方式: ①+② 拼进 system 消息(上下文约束"只基于页面数据回答"属于全局
// 规则, 放 system 比放 user 约束力强), ③ 作为 user 消息。
// 页面数据先 JSON 序列化再脱敏(可能含口令/令牌类字段), 超限截断。
func buildAssistantMessages(prompt string, pageType, pageName string, data any, question string) (system, user string) {
	system = prompt
	if data == nil {
		return system, question
	}
	b, err := json.Marshal(data)
	if err != nil {
		return system, question // 数据不可序列化 = 无上下文, 不阻断问答
	}
	dataJSON := scanner.DesensitizeRaw(string(b), assistantCtxMaxBytes)
	label := "未识别页面"
	if pageType != "" {
		label = pageType
		if pageName != "" {
			label = pageName + "(" + pageType + ")"
		}
	}
	system += "\n\n## 当前页面上下文\n用户当前所在页面: " + label +
		"\n页面数据(JSON, 已脱敏):\n" + dataJSON +
		"\n\n请严格只基于以上页面数据回答; 数据中没有的信息, 明确告知\"当前页面数据中未包含该信息\", 不要编造。"
	return system, question
}

// ===== 路由与 handler =====

// registerAssistantRoutes 小 Y 路由(在 RegisterAIRoutes 内统一注册)。
// 全部 requireAuth —— 复用现有登录鉴权体系, 不新增独立账号(任务书要求)。
func registerAssistantRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/ai/assistant", requireAuth(handleAssistantStatus))
	mux.HandleFunc("POST /api/v1/ai/assistant", requireAuth(adminOrOperator(handleAssistantSave)))
	mux.HandleFunc("POST /api/v1/ai/context", requireAuth(handleAssistantContext))
	mux.HandleFunc("POST /api/v1/ai/chat", requireAuth(handleAssistantChat))
}

// handleAssistantStatus GET /api/v1/ai/assistant 小 Y 状态 + 配置总览。
//
// 前端两处消费: ①助手悬浮组件(入口显隐依据 effective, 30s 轮询);
// ②AI 配置页(回显 PROMPT 与自定义标记)。
func handleAssistantStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := ai.CurrentConfig()
	jsonOK(w, map[string]any{
		// enabled = 小 Y 开关; aiEnabled = AI 全局开关;
		// effective = 两者都开才算可用(小 Y 依赖 LLM, 全局关 = 助手不可用)
		"enabled":         cfg.Assistant.Enabled,
		"aiEnabled":       cfg.Enabled,
		"effective":       cfg.Enabled && cfg.Assistant.Enabled,
		"backend":         cfg.Backend,
		"model":           cfg.Model,
		"prompt":          cfg.AssistantPrompt(),
		"defaultPrompt":   ai.DefaultAssistantPrompt(),
		"hasCustomPrompt": strings.TrimSpace(cfg.Assistant.Prompt) != "",
	})
}

// handleAssistantSave POST /api/v1/ai/assistant 保存小 Y 配置(即时生效, 无需重启)。
//
// 请求体字段均为可选(指针区分"传了"与"没传", 与 handleAIConfigSave 同口径):
//   - enabled: 小 Y 总开关; 开启时联动置 AI 全局开关(小 Y 依赖 LLM),
//     关闭时不动全局(抓包/扫描/监控的 AI 分析不受影响);
//   - prompt:  系统提示词; 空串 = 恢复内置默认;
//   - apiBase/apiKey/model: 模型基础配置(与 AI 配置页基础卡同一数据源,
//     小 Y 卡内编辑后随本接口一并落盘)。
func handleAssistantSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enabled *bool   `json:"enabled"`
		Prompt  *string `json:"prompt"`
		APIBase *string `json:"apiBase"`
		APIKey  *string `json:"apiKey"`
		Model   *string `json:"model"`
	}
	if err := decodeAIBody(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	cfg := ai.CurrentConfig()
	b := cfg.BasicConfig
	if req.APIBase != nil && strings.TrimSpace(*req.APIBase) != "" {
		b.APIBase = strings.TrimSpace(*req.APIBase)
	}
	if req.APIKey != nil {
		b.APIKey = strings.TrimSpace(*req.APIKey)
	}
	if req.Model != nil && strings.TrimSpace(*req.Model) != "" {
		b.Model = strings.TrimSpace(*req.Model)
	}
	if req.Enabled != nil && *req.Enabled {
		b.Enabled = true // 开启小 Y 必须同时启用全局 AI(LLM 调用总闸)
	}
	as := cfg.Assistant
	if req.Enabled != nil {
		as.Enabled = *req.Enabled
	}
	if req.Prompt != nil {
		as.Prompt = strings.TrimSpace(*req.Prompt) // 空串 = 恢复内置默认 PROMPT
	}
	keys := map[string]any{
		"enabled": b.Enabled, "backend": b.Backend, "apiBase": b.APIBase,
		"apiKey": b.APIKey, "model": b.Model, "maxTokens": b.MaxTokens,
		"timeoutSec": b.TimeoutSec, "maxContext": b.MaxContext,
		"temperature": b.Temperature, "topP": b.TopP,
		"retry": b.Retry, "maxEvidence": b.MaxEvidence,
		"desensitize": b.Desensitize, "maxConcurrency": b.MaxConcurrency,
		"modules": cfg.Modules,
		"assistant": as,
	}
	if err := updateAISec(keys, true); err != nil {
		jsonErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	jsonOK(w, map[string]any{"saved": true, "assistant": as, "effective": b.Enabled && as.Enabled})
}

// handleAssistantContext POST /api/v1/ai/context 前端路由变化时上报最新页面上下文。
//
// 按登录用户暂存(内存, 见 assistantCtxs); 上报失败不阻塞前端(前端静默吞错)。
func handleAssistantContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PageType string `json:"pageType"`
		PageName string `json:"pageName"`
		Data     any    `json:"data"`
	}
	if err := decodeAIBody(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.PageType) == "" {
		jsonErr(w, http.StatusBadRequest, "pageType 为空")
		return
	}
	setAssistantCtx(assistantUser(r), assistantCtx{
		PageType: strings.TrimSpace(req.PageType),
		PageName: strings.TrimSpace(req.PageName),
		Data:     req.Data,
	})
	jsonOK(w, map[string]any{"saved": true})
}

// handleAssistantChat POST /api/v1/ai/chat 问答核心(SSE 流式返回)。
//
// 请求体:
//
//	{"question": "...", "pageType": "...", "pageName": "...", "data": {...}}
//
// pageType/data 为覆盖传参(前端提问时实时采集, 优先); 缺省时回退到该用户
// 最近一次上报的会话上下文(任务书: "问答默认带入最近一次页面上下文")。
//
// 响应(SSE, 与扫描 SSE 同格式家族):
//
//	event: delta  data: {"t":"增量文本"}
//	event: done   data: {"full":"完整回答","elapsedMs":1234}
//	event: error  data: {"error":"..."}
func handleAssistantChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := ai.CurrentConfig()
	if !cfg.Enabled || !cfg.Assistant.Enabled {
		// 任务书: 总开关关闭时所有相关接口返回未启用(前端据此隐藏入口)
		jsonErr(w, http.StatusServiceUnavailable, "小 Y 助手未启用(请在 AI 配置页开启)")
		return
	}
	var req struct {
		Question string `json:"question"`
		PageType string `json:"pageType"`
		PageName string `json:"pageName"`
		Data     any    `json:"data"`
	}
	if err := decodeAIBody(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	question := strings.TrimSpace(req.Question)
	if question == "" {
		jsonErr(w, http.StatusBadRequest, "question 为空")
		return
	}
	if len(question) > assistantQuestionMax {
		jsonErr(w, http.StatusBadRequest, "提问过长(上限 "+fmt.Sprint(assistantQuestionMax)+" 字符)")
		return
	}

	// 页面上下文: 覆盖传参优先, 缺省回退会话最近上报值
	pageType, pageName, data := req.PageType, req.PageName, req.Data
	if strings.TrimSpace(pageType) == "" && data == nil {
		if c, ok := getAssistantCtx(assistantUser(r)); ok {
			pageType, pageName, data = c.PageType, c.PageName, c.Data
		}
	}

	system, user := buildAssistantMessages(cfg.AssistantPrompt(), pageType, pageName, data, question)

	// 模型适配层: 复用既有 LLM 统一调用封装(OpenAI 兼容协议; backend=ollama
	// 即本地模型扩展位) —— 不写第二套 HTTP 调用路径。配置每次实时读取,
	// AI 配置页改动即时生效。
	an := scanner.NewAIAnalyzer(cfg.BasicConfig.ToScanner())
	// 超时口径与 handleAIAnalyze 一致: max(配置timeoutSec, 600s), 上限 1800s ——
	// 本地大模型(如 35B)生成慢, 60s 默认值会被中途切断, 用户无需改配置。
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout < 600*time.Second {
		timeout = 600 * time.Second
	}
	if timeout > 1800*time.Second {
		timeout = 1800 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	fl, ok := w.(http.Flusher)
	if !ok {
		jsonErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	start := time.Now()
	full, err := an.StreamChat(ctx, system, user, func(d string) {
		writeSSE(w, fl, "delta", map[string]any{"t": d})
	})
	if err != nil {
		logLine("[小Y] 问答调用失败: " + err.Error())
		writeSSE(w, fl, "error", map[string]any{"error": err.Error()})
		return
	}
	if strings.TrimSpace(full) == "" {
		full = "(模型未返回内容, 请检查 AI 配置或稍后重试)"
	}
	writeSSE(w, fl, "done", map[string]any{
		"full": full, "elapsedMs": time.Since(start).Milliseconds(),
	})
}

// writeSSE 写一条 SSE 事件并刷新。
func writeSSE(w http.ResponseWriter, fl http.Flusher, event string, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
	fl.Flush()
}
