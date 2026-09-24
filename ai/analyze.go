// analyze.go 全链路 AI 分析管线(阶段 3 核心)。
//
// 数据流: 业务页点"AI 分析" → 装配层(ai_api.go)拿到原始报告 →
//   Analyze():
//     1. 读 AI 配置(全局参数 + 模块开关 + 对应 Prompt 模板)
//     2. 组装变量: {{raw_data}}(脱敏截断) / {{asset_info}} / {{scan_result}}
//        / {{metric_data}} / {{time}} / {{structured_memory}}(记忆库检索)
//     3. 模板 RAG 绑定开启 → 文档库向量检索 TopK 片段(参考资料段)
//     4. 组装 system+user 提交 LLM(复用 scanner.AIAnalyzer: 脱敏/限流/重试/超时)
//     5. 返回 Result(研判全文 + 结构化审计元数据), 装配层回写报告中心
//
// 降级口径(规则 4): 配置缺失/模块关闭 → 明确错误(按钮侧已置灰, 这里是
// 双保险); RAG 无命中/记忆库为空 → 对应变量为"无", 不阻断分析;
// LLM 失败 → 原样上抛(装配层 502, 报告不写坏)。
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"yugsight/scanner"
)

// Input 一次分析请求的输入(装配层从原始报告拆出)。
type Input struct {
	Module  string          // capture/scan/weakpass/monitor/collect/merged
	Payload json.RawMessage // 报告正文(sections 等, 不透明)
	Assets  []string        // 报告涉及的资产 IP(记忆库/展示用)
	Summary string          // 列表摘要(拼 RAG 查询词用)
	Target  string          // 目标/标题(拼 RAG 查询词用)
	Now     time.Time       // 分析时间(缺省 = 当前时间)
}

// Result 分析结果(装配层回写 raw_reports 的 ai 三字段)。
type Result struct {
	Note        string          // LLM 研判全文(aiNote)
	AIData      json.RawMessage // 结构化审计元数据(aiData)
	Model       string
	Template    string
	RAGHits     int
	MemoryItems int
	ElapsedMs   int64
}

// ChatFn 一次 LLM 调用的抽象。默认实现走 scanner.AIAnalyzer;
// 测试/装配层可替换(如离线 mock)—— 命名带 ForTest 表明用途,
// 生产代码不应调用。
type ChatFn func(ctx context.Context, basic BasicConfig, system, user string) (string, error)

var (
	chatFnMu sync.RWMutex
	chatFn   ChatFn
)

// SetChatFnForTest 替换 LLM 调用实现(测试接缝, 装配层不用)。
// 传 nil 恢复默认实现。
func SetChatFnForTest(f ChatFn) {
	chatFnMu.Lock()
	if f == nil {
		chatFn = defaultChat
	} else {
		chatFn = f
	}
	chatFnMu.Unlock()
}

// defaultChat 生产路径: scanner.AIAnalyzer(流式, 内部已做脱敏/限流/重试/超时)。
func defaultChat(ctx context.Context, basic BasicConfig, system, user string) (string, error) {
	an := scanner.NewAIAnalyzer(basic.ToScanner())
	return an.StreamChat(ctx, system, user, nil)
}

// 系统级固定边界(不可被 Prompt 模板覆盖 —— 安全红线):
// 只解读、不判定新漏洞、不生成 POC/攻击命令、只基于给定数据、中文。
const aiSystemPrompt = `你是 Yugsight(御视) 安全运维分析助手。严格边界:
1) 只对给定的原始数据做后置分析与解读, 不重新判定漏洞是否存在, 不生成或执行任何 POC/探测/攻击命令;
2) 结论只基于给定数据(原始数据、参考文档、历史记忆), 不臆测未提供的信息;
3) 用中文回答, 结论先行, 简明结构化。`

// Analyze 执行一次完整分析(配置 → 变量 → RAG → 记忆 → LLM)。
func Analyze(ctx context.Context, in Input) (*Result, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	key, ok := TplKeyForModule(in.Module)
	if !ok {
		return nil, fmt.Errorf("不支持的 AI 分析模块: %q", in.Module)
	}
	cfg := CurrentConfig()
	if !cfg.Enabled {
		return nil, fmt.Errorf("AI 未启用(请在 AI 配置页测试并保存)")
	}
	if !cfg.ModuleEnabled(key) {
		return nil, fmt.Errorf("该模块的 AI 分析已被管理员关闭(AI 配置页 → 模块总开关)")
	}
	tpl, err := cfg.Prompt(key)
	if err != nil {
		return nil, err
	}

	// ---- 变量组装 ----
	vars := map[string]string{
		"time":   in.Now.Format("2006-01-02 15:04:05"),
		"raw_data":           rawText(in.Payload, cfg.MaxContext),
		"asset_info":         assetText(in.Assets),
		"scan_result":        extractField(in.Payload, "findings", cfg.MaxContext/2),
		"metric_data":        extractFirstField(in.Payload, cfg.MaxContext/2, "rounds", "events", "targets"),
	}
	// 结构化记忆(范围/时长/条数/压缩由配置决定)
	memText := "无历史记忆(或超出保留时长)"
	memItems := 0
	if cfg.Memory.Enabled {
		if store := memoryStore(); store != nil {
			memText, memItems = Gather(cfg.Memory, in.Now, store)
		}
	}
	vars["structured_memory"] = memText

	// ---- RAG 检索(模板级绑定; 走统一检索器: 向量/关键词 + 可选重排 + 内置降级) ----
	ragText := ""
	ragHits := 0
	ragMode := ""
	if cfg.RAG.Enabled && tpl.RAG {
		topK := tpl.TopK
		if topK <= 0 {
			topK = cfg.RAG.TopK
		}
		if rt := CurrentRetriever(); rt != nil {
			hits := rt.Search(ctx, ragQuery(in), topK)
			ragHits = len(hits)
			ragText = FormatHits(hits, 0)
			ragMode = rt.Mode()
		}
	}

	user := Render(tpl.Content, vars)
	if strings.TrimSpace(ragText) != "" {
		user += "\n\n=== 参考文档(RAG 知识库检索结果, 仅作背景参考) ===" + ragText
	}

	// ---- LLM 调用 ----
	t0 := time.Now()
	out, err := chat(ctx, cfg.BasicConfig, aiSystemPrompt, user)
	elapsed := time.Since(t0).Milliseconds()
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, fmt.Errorf("AI 返回为空")
	}

	aiData, _ := json.Marshal(map[string]any{
		"model":       cfg.Model,
		"backend":     cfg.Backend,
		"template":    tpl.Name,
		"module":      in.Module,
		"ragEnabled":  cfg.RAG.Enabled && tpl.RAG,
		"ragHits":     ragHits,
		"ragMode":     ragMode, // vector=向量检索 / keyword=关键词降级; 空=未检索
		"memoryItems": memItems,
		"scopes":      cfg.Memory.ScopesLabel(),
		"elapsedMs":   elapsed,
		"analyzedAt":  in.Now.Format(time.RFC3339),
	})
	return &Result{
		Note:        out,
		AIData:      aiData,
		Model:       cfg.Model,
		Template:    tpl.Name,
		RAGHits:     ragHits,
		MemoryItems: memItems,
		ElapsedMs:   elapsed,
	}, nil
}

// chat 取当前 ChatFn 调用(读锁, 避免并发替换时半读半写)。
func chat(ctx context.Context, basic BasicConfig, system, user string) (string, error) {
	chatFnMu.RLock()
	f := chatFn
	chatFnMu.RUnlock()
	if f == nil {
		f = defaultChat
	}
	return f(ctx, basic, system, user)
}

// ===== 变量取值辅助 =====

// rawText 原始正文: 脱敏 + 截断(超 MaxContext 预算留截断标记)。
// 脱敏复用 scanner.Desensitize(与既有 AI 链路同一实现, 口径不漂移)。
func rawText(payload json.RawMessage, budget int) string {
	if budget <= 0 {
		budget = defMaxContext
	}
	if len(payload) == 0 {
		return "无原始数据"
	}
	s := scanner.DesensitizeRaw(string(payload), budget)
	if len(s) > budget {
		s = s[:budget] + "\n...(数据过长, 已截断)"
	}
	return s
}

// assetText 资产 IP 清单。
func assetText(assets []string) string {
	if len(assets) == 0 {
		return "无"
	}
	return strings.Join(assets, ", ")
}

// extractField 从 payload 取某字段序列化(截断); 无该字段 → "无"。
// findings 这类嵌套 JSON 直接原样给 LLM 读(结构化字段名自解释,
// 不二次加工 —— 加工规则本身就是猜测)。
func extractField(payload json.RawMessage, field string, budget int) string {
	if len(payload) == 0 {
		return "无"
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(payload, &obj); err != nil {
		return "无"
	}
	raw, ok := obj[field]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return "无"
	}
	s := scanner.DesensitizeRaw(string(raw), budget)
	if len(s) > budget {
		s = s[:budget] + "..."
	}
	return s
}

// extractFirstField 取第一个存在的字段(监控模块的指标数据在不同报告里
// 字段名不同: monitor=targets/rounds, collect=events/rounds)。
func extractFirstField(payload json.RawMessage, budget int, fields ...string) string {
	if len(payload) == 0 {
		return "无"
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(payload, &obj); err != nil {
		return "无"
	}
	for _, f := range fields {
		if raw, ok := obj[f]; ok && len(raw) > 0 && string(raw) != "null" {
			s := scanner.DesensitizeRaw(string(raw), budget)
			if len(s) > budget {
				s = s[:budget] + "..."
			}
			return s
		}
	}
	return "无"
}

// ragQuery 拼 RAG 查询词: 摘要 + 目标 + 原始数据前 500 字。
// (纯数据进向量引擎前同样走一遍脱敏, 双保险。)
func ragQuery(in Input) string {
	parts := []string{in.Summary, in.Target}
	if p := rawText(in.Payload, 500); p != "无原始数据" {
		parts = append(parts, p)
	}
	return scanner.DesensitizeRaw(strings.Join(parts, " "), 1000)
}

// ===== 装配层注入点 =====

var (
	memoryStoreFn func() MemoryStore
	ragIndexFn    func() *Index
	retrieverFn   func() *Retriever
	ragIdxMu      sync.RWMutex
)

// SetMemoryStore 注入结构化记忆数据源(装配层用 v2DB 实现)。
func SetMemoryStore(f func() MemoryStore) {
	ragIdxMu.Lock()
	memoryStoreFn = f
	ragIdxMu.Unlock()
}

// memoryStore 当前记忆数据源(测试可置 nil)。
func memoryStore() MemoryStore {
	ragIdxMu.RLock()
	defer ragIdxMu.RUnlock()
	if memoryStoreFn == nil {
		return nil
	}
	return memoryStoreFn()
}

// SetRAGIndex 注入当前 RAG 文档索引(装配层在文档增删改后重建)。
// 传 nil = 清空(文档库不可用, RAG 降级为"无参考")。
func SetRAGIndex(ix *Index) {
	ragIdxMu.Lock()
	ragIndexFn = func() *Index { return ix }
	ragIdxMu.Unlock()
}

// RAGIndex 当前 RAG 索引。
func RAGIndex() *Index {
	ragIdxMu.RLock()
	f := ragIndexFn
	ragIdxMu.RUnlock()
	if f == nil {
		return nil
	}
	return f()
}

// SetRetriever 注入当前 RAG 统一检索器(装配层在索引/向量配置变化后重建)。
// 传 nil = RAG 检索不可用(分析降级为"无参考")。
func SetRetriever(rt *Retriever) {
	ragIdxMu.Lock()
	if rt == nil {
		retrieverFn = nil
	} else {
		retrieverFn = func() *Retriever { return rt }
	}
	ragIdxMu.Unlock()
}

// CurrentRetriever 当前 RAG 统一检索器(业务层只依赖它, 不感知向量/关键词/重排)。
func CurrentRetriever() *Retriever {
	ragIdxMu.RLock()
	f := retrieverFn
	ragIdxMu.RUnlock()
	if f == nil {
		return nil
	}
	return f()
}
