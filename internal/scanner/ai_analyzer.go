// ai_analyzer.go Yugsight AI 后置分析模块(可选插件, 不改变原有扫描引擎)。
//
// 定位与边界(硬性约束):
//   - AI 只做扫描结果的【后置分析】, 不参与漏洞判定; 命中与否永远以
//     扫描引擎(nuclei 模板 / 内置 vuln 规则)为准, 本模块只解读、不新增、不改动。
//   - 不生成、不执行任何 POC / 探测 / 攻击命令。
//   - 可一键全局关闭(-ai / 配置 enabled=false), 关闭时完全不发起 LLM 调用, 不占用资源。
//   - 送入 LLM 的所有数据必须先脱敏(擦除 Authorization/Cookie/Bearer/密码类参数/JWT)。
//
// 能力:
//   - 两种后端: Ollama 本地模型 / OpenAI 兼容远程 API(同一 /chat/completions 协议)。
//   - 三套内置 Prompt: 单漏洞研判 / 批量扫描汇总 / 修复建议(区分 Windows/Linux/中间件)。
//   - SSE 流式: 复用 scanner.Emit, 事件名 "ai", 与扫描事件(status/finding/done)同格式。
//   - 全局并发限流 + 证据哈希结果缓存, 防止短时间大量 LLM 调用卡死程序 / 重复调用。
//
// 调用示例(主程序接线, 仅示意, 不改扫描核心):
//
//	an := scanner.NewGlobalAIAnalyzer()          // 从全局配置读取
//	if an.Enabled() {
//	    // ① 任务结束批量汇总(扫描完成后, emit 复用扫描 SSE)
//	    if res, err := an.AnalyzeScanBatch(assets, vulns, emit); err == nil { ... }
//	    // ② 单条漏洞误报研判(前端按需触发)
//	    if res, err := an.AnalyzeSingleVuln(v, asset); err == nil { ... }
//	    // ③ 单条漏洞修复建议
//	    if res, err := an.AnalyzeRemediation(v, asset); err == nil { ... }
//	}
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultAIModelOllama = "http://127.0.0.1:11434/v1"
	defaultAIModelOpenAI = "https://api.openai.com/v1"
	defaultAIModelName   = "qwen2.5:7b"
	defaultOpenAIName    = "gpt-4o-mini"
	defaultAITimeout     = 120 * time.Second
	// 4096 而非 2048: 思考型模型(Qwen3 等)会先输出 reasoning_content 再给正式
	// 回答, 2048 常常被"思考"整段吃光, 正式回答 content 为空, 页面报"无返回
	// 内容"。加大预算后两种模型都能拿到可用回答(有 reasoning_content 回退兜底)。
	defaultAIMaxTokens   = 4096
	defaultAIMaxEvidence = 20 * 1024 // 单条证据脱敏后上限
	defaultAIMaxConc     = 4         // 全局并发 AI 请求数
	aiCacheLimit         = 512       // 结果缓存上限(超限整体重置, 防无界增长)

	// eventAI AI 分析 SSE 事件名(与扫描事件同格式, 事件名独立便于前端区分)
	eventAI = "ai"
)

var (
	// aiLog 模块日志(默认 slog.Default, 可由主程序通过 SetAILogger 接管)
	aiLog = slog.Default()

	// aiDesensitizeWarn 脱敏开关关闭告警只记录一次, 避免每次调用刷屏
	aiDesensitizeWarn sync.Once

	// 脱敏正则(进程级编译一次, 避免每次调用重新编译)
	aiReAuthHeader = regexp.MustCompile(`(?im)^(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token|X-Auth-Api-Key|X-Csrf-Token|X-Xsrf-Token|X-Access-Token|X-Session-Token|Token|Session|JSESSIONID)\s*:\s*.*$`)
	aiReBearer     = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]+`)
	aiReJWT        = regexp.MustCompile(`eyJ[A-Za-z0-9._\-]{8,}`)
	aiRePwd        = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*([=:])\s*[^\s&"']+`)
)

// SetAILogger 接管模块日志(主程序可注入自己的 handler, 默认写 stderr)
func SetAILogger(l *slog.Logger) {
	if l != nil {
		aiLog = l
	}
}

// ===== 配置 =====

// AIModelConfig AI 后端配置。0/空值字段由 normalizeConfig 补齐默认值。
type AIModelConfig struct {
	Enabled        bool   `json:"enabled"`        // AI 功能总开关(关闭=不发起任何 LLM 调用)
	Backend        string `json:"backend"`        // "ollama"(本地) | "openai"(远程 OpenAI 兼容)
	APIBase        string `json:"apiBase"`        // 模型地址
	APIKey         string `json:"apiKey"`         // 远程 API 密钥(本地 Ollama 可空)
	Model          string `json:"model"`          // 模型名称
	MaxTokens      int    `json:"maxTokens"`      // 最大输出 token
	TimeoutSec     int    `json:"timeoutSec"`     // 单次请求超时(秒)
	Retry          int    `json:"retry"`          // 失败重试次数(0=不重试)
	MaxEvidence    int    `json:"maxEvidence"`    // 单条证据脱敏后最大字节
	Desensitize    bool   `json:"desensitize"`    // 脱敏开关(默认 true; 出于安全, 关闭时仍强制脱敏并告警)
	MaxConcurrency int    `json:"maxConcurrency"` // 全局并发 AI 请求数
	// Temperature 采样温度。0 = 不写该参数, 走服务端默认(既有行为: 固定 0.2)。
	// 由 AI 配置页(阶段 3)的用户设置透传, 老配置无此字段行为不变。
	Temperature float64 `json:"temperature"`
	// TopP 核采样。0 = 不发送(服务端默认 1.0, 与既有行为一致)。
	TopP float64 `json:"topP"`
}

// DefaultAIConfig 返回默认配置(Ollama 本地, 总开关/脱敏默认开)
func DefaultAIConfig() AIModelConfig {
	return AIModelConfig{
		Enabled:        true,
		Backend:        "ollama",
		APIBase:        defaultAIModelOllama,
		Model:          defaultAIModelName,
		MaxTokens:      defaultAIMaxTokens,
		TimeoutSec:     int(defaultAITimeout.Seconds()),
		Retry:          1,
		MaxEvidence:    defaultAIMaxEvidence,
		Desensitize:    true,
		MaxConcurrency: defaultAIMaxConc,
	}
}

var (
	aiCfgMu sync.RWMutex
	aiCfg   = DefaultAIConfig()
)

// SetGlobalConfig 设置全局 AI 配置(供主程序读取 ai.json 后注入)
func SetGlobalConfig(c AIModelConfig) {
	c = normalizeConfig(c)
	aiCfgMu.Lock()
	aiCfg = c
	aiCfgMu.Unlock()
	applyConcurrency(c.MaxConcurrency)
}

// GlobalConfig 返回全局 AI 配置的副本
func GlobalConfig() AIModelConfig {
	aiCfgMu.RLock()
	defer aiCfgMu.RUnlock()
	return aiCfg
}

// normalizeConfig 补齐默认值
func normalizeConfig(c AIModelConfig) AIModelConfig {
	if c.Backend == "" {
		c.Backend = "ollama"
	}
	if c.APIBase == "" {
		if c.Backend == "openai" {
			c.APIBase = defaultAIModelOpenAI
		} else {
			c.APIBase = defaultAIModelOllama
		}
	}
	if c.Model == "" {
		if c.Backend == "openai" {
			c.Model = defaultOpenAIName
		} else {
			c.Model = defaultAIModelName
		}
	}
	if c.MaxTokens <= 0 {
		c.MaxTokens = defaultAIMaxTokens
	}
	if c.TimeoutSec <= 0 {
		c.TimeoutSec = int(defaultAITimeout.Seconds())
	}
	if c.MaxEvidence <= 0 {
		c.MaxEvidence = defaultAIMaxEvidence
	}
	if c.MaxConcurrency <= 0 {
		c.MaxConcurrency = defaultAIMaxConc
	}
	return c
}

// ===== 全局并发限流(标准库实现, 零外部依赖) =====

var (
	aiConcMu  sync.RWMutex
	aiMaxConc = defaultAIMaxConc
	aiSem     = make(chan struct{}, defaultAIMaxConc)
)

// SetMaxAIConcurrency 设置全局并发 AI 请求上限(<=0 用默认)
func SetMaxAIConcurrency(n int) {
	if n <= 0 {
		n = defaultAIMaxConc
	}
	aiConcMu.Lock()
	aiMaxConc = n
	aiSem = make(chan struct{}, n) // 旧槽位由在途请求自行释放, 无泄漏
	aiConcMu.Unlock()
}

// acquireAI 获取一个全局 AI 并发槽位, 返回释放函数; ctx 取消/超时返回 error。
// 关闭态在调用本函数之前已被拦截, 故此处不会在禁用时占用资源。
func acquireAI(ctx context.Context) (release func(), err error) {
	aiConcMu.RLock()
	sem := aiSem
	aiConcMu.RUnlock()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func applyConcurrency(n int) {
	if n > 0 {
		SetMaxAIConcurrency(n)
	}
}

// ===== 结果缓存(相同脱敏证据 -> 复用, 避免重复调用 LLM) =====

type aiResultStore struct {
	mu    sync.Mutex
	items map[string]*AIResult
}

func newAIResultStore() *aiResultStore {
	return &aiResultStore{items: make(map[string]*AIResult, 64)}
}

func (c *aiResultStore) get(key string) (*AIResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.items[key]
	return r, ok
}

func (c *aiResultStore) put(key string, r *AIResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= aiCacheLimit {
		c.items = make(map[string]*AIResult, 64) // 上限保护: 超限整体重置(与 nuclei 缓存一致)
	}
	c.items[key] = r
}

// aiResultCache 全局结果缓存(跨任务复用; key 含模型名, 换模型自动失效)
var aiResultCache = newAIResultStore()

// ===== 输入 / 输出 DTO =====

// Vuln AI 分析的漏洞输入 DTO(只读, 由扫描引擎的 Finding/NucleiFinding 组装而来)。
// 独立定义, 不依赖也不修改 vuln.go 的 VulnRule 与 web.go 的 Finding。
type Vuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // high / medium / low / info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Source   string `json:"source,omitempty"` // nuclei / nuclei-builtin / ""(内置规则)
	CVE      string `json:"cve,omitempty"`
	Path     string `json:"path,omitempty"`
	// 原始请求/响应证据(送入 LLM 前必须经 Desensitize 脱敏)
	Request  string `json:"request"`
	Response string `json:"response"`
}

// AIResult AI 分析结构化输出(仅附加到报告, 不修改原始漏洞判定)。
type AIResult struct {
	Mode          string   `json:"mode"` // finding / report / remediation
	RiskSummary   string   `json:"riskSummary"`
	FalsePositive int      `json:"falsePositive"` // 误报可能性 0-100(越高越可能是误报)
	NeedReview    bool     `json:"needReview"`    // 是否建议人工复核
	ReviewAdvice  string   `json:"reviewAdvice"`  // 人工复核建议
	RootCause     string   `json:"rootCause"`     // 根因分析
	Remediation   string   `json:"remediation"`   // 修复建议
	HighRiskAssets []string `json:"highRiskAssets,omitempty"` // 高危资产清单(批量)
	LateralRisk    string   `json:"lateralRisk,omitempty"`    // 横向渗透风险提示(批量)
	// 元信息(溯源 / 审计)
	Model     string `json:"model"`
	ElapsedMs int64  `json:"elapsedMs"`
	FromCache bool   `json:"fromCache"` // 结果来自缓存(未实时调用 LLM)
}

// ===== 内置 Prompt 模板 =====
//
// 三套系统提示词硬编码【角色边界(不判定/不 POC) + 严格 JSON 契约(对齐 AIResult)】。
// 占位数据由 buildXxxPrompt 组装(已脱敏)后作为 user 消息, 与 system 提示词分离。

const promptSingleVuln = `你是资深安全运维专家, 负责对 Yugsight 扫描引擎已命中的单条漏洞做"误报研判"。
严格边界(必须遵守):
1. 只做后置研判, 不得重新判定该漏洞是否存在, 不得生成或执行任何 POC/探测/攻击命令。
2. 结论仅基于提供的(已脱敏)证据, 不臆测未提供的信息。
3. 只输出一个 JSON 对象(无 markdown、无多余文字), 字段:
{"riskSummary":"一句话风险概述","falsePositive":0到100整数(是误报的可能性,100=几乎确定误报,0=几乎确定真实风险),"needReview":true或false(是否建议人工复核),"reviewAdvice":"人工复核建议(不需复核则空串)","rootCause":"基于证据的根因/触发条件分析"}
研判要点: 响应状态码、响应体特征、是否为统一错误页/WAF 拦截页、路径是否为真实资源、是否属于通用文本误匹配。`

const promptBatchSummary = `你是资深安全评估专家, 基于 Yugsight 一次扫描的全部(已脱敏)资产与漏洞命中结果做整体汇总。
严格边界(必须遵守):
1. 只做汇总/排序/解读, 不得新增或改动任何漏洞判定, 不得生成或执行 POC。
2. 仅基于提供的资产与命中清单, 不臆测未列出的主机/服务。
3. 只输出一个 JSON 对象(无 markdown、无多余文字), 字段:
{"riskSummary":"整体风险摘要(含高危项概述)","falsePositive":0到100整数(整份结果误报占比估计,100=多为误报,0=多为真实风险),"needReview":true或false,"reviewAdvice":"需重点复核项(否则空串)","highRiskAssets":["高危资产 ip:port 列表, 可为空"],"lateralRisk":"横向渗透风险提示(结合开放服务/同网段暴露面, 无则空串)"}
请重点标出被外部可访问的高危资产, 并评估同一网段内是否存在可横向移动的攻击面。`

const promptRemediation = `你是资深安全运维专家, 针对 Yugsight 扫描引擎已命中的单条漏洞给出可落地的修复方案。
严格边界(必须遵守):
1. 只给修复/加固/验证建议, 不做漏洞判定, 不生成或执行 POC/攻击命令。
2. 建议须与漏洞类型匹配, 基于提供的命中信息, 不臆测环境。
3. 只输出一个 JSON 对象(无 markdown、无多余文字), 字段:
{"riskSummary":"漏洞一句话概述","falsePositive":0到100整数(误报可能性),"needReview":true或false,"reviewAdvice":"需复核原因(否则空串)","remediation":"分步骤可落地修复方案, 须区分 Windows / Linux / 中间件 分别给出; 含具体配置项/版本升级/访问控制, 并说明如何验证已修复"}
若目标平台未知, 请在 remediation 中先说明判断依据再分平台给出建议。`

// ===== AIAnalyzer =====

// AIAnalyzer 独立 AI 分析引擎。持有配置、HTTP 客户端; 限流/缓存为进程级全局。
type AIAnalyzer struct {
	cfg    AIModelConfig
	client *http.Client
}

// NewAIAnalyzer 用给定配置构建分析器(自动补齐默认值)
func NewAIAnalyzer(c AIModelConfig) *AIAnalyzer {
	c = normalizeConfig(c)
	applyConcurrency(c.MaxConcurrency)
	return &AIAnalyzer{
		cfg:    c,
		client: &http.Client{Timeout: time.Duration(c.TimeoutSec) * time.Second},
	}
}

// NewGlobalAIAnalyzer 从全局配置构建分析器(主程序读取 ai.json 后调 SetGlobalConfig)
func NewGlobalAIAnalyzer() *AIAnalyzer {
	return NewAIAnalyzer(GlobalConfig())
}

// Enabled 返回 AI 总开关状态(关闭时所有 Analyze* 立即返回错误, 不占用资源)
func (a *AIAnalyzer) Enabled() bool { return a.cfg.Enabled }

// Config 返回当前配置副本
func (a *AIAnalyzer) Config() AIModelConfig { return a.cfg }

// SetTransport 注入自定义 HTTP Transport(主要用于单元测试 mock LLM 响应, 避免真实网络)
func (a *AIAnalyzer) SetTransport(rt http.RoundTripper) {
	if a.client != nil && rt != nil {
		a.client.Transport = rt
	}
}

func (a *AIAnalyzer) timeout() time.Duration {
	return time.Duration(a.cfg.TimeoutSec) * time.Second
}

func (a *AIAnalyzer) ensureEnabled() error {
	if !a.cfg.Enabled {
		return errors.New("AI 分析已关闭")
	}
	return nil
}

// Desensitize 对一段原始 HTTP 报文(请求或响应)脱敏并截断到 MaxEvidence。
// 脱敏开关关闭时仍强制脱敏(安全兜底, 约束: 送入 LLM 的数据必须脱敏), 仅记录一次告警。
func (a *AIAnalyzer) Desensitize(raw string) string {
	if !a.cfg.Desensitize {
		aiDesensitizeWarn.Do(func() {
			aiLog.Warn("脱敏开关已关闭: 出于安全仍强制脱敏(生产环境请保持开启)")
		})
	}
	return DesensitizeRaw(raw, a.cfg.MaxEvidence)
}

// DesensitizeRaw 纯函数脱敏(不依赖实例, 便于单元测试):
// 擦除敏感响应/请求头(Authorization/Cookie/Bearer/密码类参数/JWT), 并截断到 maxBytes。
func DesensitizeRaw(raw string, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = defaultAIMaxEvidence
	}
	s := aiReAuthHeader.ReplaceAllString(raw, "$1: ***REDACTED***")
	s = aiReBearer.ReplaceAllString(s, "Bearer ***")
	s = aiReJWT.ReplaceAllString(s, "***JWT***")
	s = aiRePwd.ReplaceAllString(s, "$1$2***")
	if len(s) > maxBytes {
		s = s[:maxBytes] + "\n...[truncated]"
	}
	return s
}

// ===== 核心分析函数 =====

// AnalyzeSingleVuln 单条漏洞误报研判(非流式)。
// vuln 为扫描引擎产出的命中, asset 为其所属资产指纹; 结果只附加, 不改原始判定。
func (a *AIAnalyzer) AnalyzeSingleVuln(vuln *Vuln, asset *ServiceAsset) (*AIResult, error) {
	return a.analyzeSingle(vuln, asset, nil)
}

// AnalyzeSingleVulnStream 单条漏洞误报研判(SSE 流式): 增量文本经 emit 实时推送,
// 事件名 "ai", 与扫描事件(status/finding/done)同格式。
func (a *AIAnalyzer) AnalyzeSingleVulnStream(vuln *Vuln, asset *ServiceAsset, emit Emit) (*AIResult, error) {
	return a.analyzeSingle(vuln, asset, emit)
}

func (a *AIAnalyzer) analyzeSingle(vuln *Vuln, asset *ServiceAsset, emit Emit) (*AIResult, error) {
	if err := a.ensureEnabled(); err != nil {
		return nil, err
	}
	if vuln == nil {
		return nil, errors.New("漏洞数据为空")
	}
	key := a.cacheKeyForSingle(vuln, asset)
	if r, ok := aiResultCache.get(key); ok {
		c := *r
		c.FromCache = true
		aiLog.Info("命中 AI 结果缓存", "title", vuln.Title)
		return &c, nil
	}
	return a.runOnce(key, promptSingleVuln,
		a.buildSinglePrompt(vuln, asset), "finding", emit,
		func() string { return a.cacheKeyForSingle(vuln, asset) })
}

// AnalyzeScanBatch 全任务批量风险汇总(非流式)。输入全部资产指纹与漏洞命中。
func (a *AIAnalyzer) AnalyzeScanBatch(assets []*ServiceAsset, vulns []*Vuln) (*AIResult, error) {
	return a.analyzeBatch(assets, vulns, nil)
}

// AnalyzeScanBatchStream 全任务批量风险汇总(SSE 流式)。
func (a *AIAnalyzer) AnalyzeScanBatchStream(assets []*ServiceAsset, vulns []*Vuln, emit Emit) (*AIResult, error) {
	return a.analyzeBatch(assets, vulns, emit)
}

func (a *AIAnalyzer) analyzeBatch(assets []*ServiceAsset, vulns []*Vuln, emit Emit) (*AIResult, error) {
	if err := a.ensureEnabled(); err != nil {
		return nil, err
	}
	if len(assets) == 0 && len(vulns) == 0 {
		return nil, errors.New("资产与漏洞数据均为空")
	}
	key := a.cacheKeyForBatch(assets, vulns)
	if r, ok := aiResultCache.get(key); ok {
		c := *r
		c.FromCache = true
		aiLog.Info("命中 AI 结果缓存(batch)")
		return &c, nil
	}
	return a.runOnce(key, promptBatchSummary,
		a.buildBatchPrompt(assets, vulns), "report", emit,
		func() string { return a.cacheKeyForBatch(assets, vulns) })
}

// AnalyzeRemediation 单条漏洞修复建议(非流式), 区分 Windows/Linux/中间件。
func (a *AIAnalyzer) AnalyzeRemediation(vuln *Vuln, asset *ServiceAsset) (*AIResult, error) {
	return a.analyzeRemediation(vuln, asset, nil)
}

// AnalyzeRemediationStream 单条漏洞修复建议(SSE 流式)。
func (a *AIAnalyzer) AnalyzeRemediationStream(vuln *Vuln, asset *ServiceAsset, emit Emit) (*AIResult, error) {
	return a.analyzeRemediation(vuln, asset, emit)
}

func (a *AIAnalyzer) analyzeRemediation(vuln *Vuln, asset *ServiceAsset, emit Emit) (*AIResult, error) {
	if err := a.ensureEnabled(); err != nil {
		return nil, err
	}
	if vuln == nil {
		return nil, errors.New("漏洞数据为空")
	}
	key := a.cacheKeyForSingle(vuln, asset) + "|remediation"
	if r, ok := aiResultCache.get(key); ok {
		c := *r
		c.FromCache = true
		return &c, nil
	}
	return a.runOnce(key, promptRemediation,
		a.buildRemediationPrompt(vuln, asset), "remediation", emit,
		func() string { return a.cacheKeyForSingle(vuln, asset) + "|remediation" })
}

// runOnce 统一执行: 限流 -> 流式调用 -> 解析 -> 缓存。emit 为 nil 时不推送。
func (a *AIAnalyzer) runOnce(key, system, user, mode string, emit Emit, keyFn func() string) (*AIResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout())
	defer cancel()
	release, err := acquireAI(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取 AI 并发槽位: %w", err)
	}
	defer release()

	if emit != nil {
		emit(eventAI, map[string]any{"mode": mode, "stage": "start"})
	}
	start := time.Now()
	full, err := a.StreamChat(ctx, system, user, func(d string) {
		if emit != nil {
			emit(eventAI, map[string]any{"mode": mode, "delta": d})
		}
	})
	if err != nil {
		if emit != nil {
			emit(eventAI, map[string]any{"mode": mode, "error": err.Error()})
		}
		aiLog.Error("AI 调用失败", "mode", mode, "err", err)
		return nil, err
	}
	res := parseAIResult(mode, full, a.cfg.Model, time.Since(start))
	aiResultCache.put(keyFn(), res)
	if emit != nil {
		emit(eventAI, map[string]any{"mode": mode, "stage": "done", "result": res})
	}
	return res, nil
}

// ===== 底层流式调用(OpenAI 兼容 /chat/completions, stream=true) =====

// chatCompletionsURL 由 API Base 拼出 chat/completions 地址。
//
// 【为什么要做后缀判定】用户常把"完整端点"当成 API Base 贴进来
// (如 http://host:8082/v1/chat/completions)。若无条件再拼一次 /chat/completions,
// 实际请求会变成 .../chat/completions/chat/completions, 服务端返回 404, 而页面
// 只显示 "LLM HTTP 404" —— 用户完全看不出是地址多粘了一截(实测踩过)。
// Base 已以 /chat/completions 结尾时直接用它, 否则补上。
func chatCompletionsURL(base string) string {
	b := strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(b, "/chat/completions") {
		return b
	}
	return b + "/chat/completions"
}

type llmHTTPError struct {
	status int
	url    string
}

// Error 带上请求地址: 4xx 绝大多数是"地址/模型填错", 只报状态码无法自查,
// 用户只能反复试。地址里不含密钥(密钥在请求头), 可以直接展示。
func (e *llmHTTPError) Error() string {
	if e.url != "" {
		return fmt.Sprintf("LLM HTTP %d (请求地址: %s)", e.status, e.url)
	}
	return fmt.Sprintf("LLM HTTP %d", e.status)
}

// isRetryable 网络错误/超时/5xx/429 可重试; 其余 4xx 不重试。
func isRetryable(err error) bool {
	var he *llmHTTPError
	if errors.As(err, &he) {
		return he.status >= 500 || he.status == 429
	}
	return true
}

// StreamChat 流式调用 LLM。onDelta 每收到一段增量文本回调, 返回完整文本。
// 内置超时/重试/上下文取消, 任何错误都返回 error(绝不 panic), 不吞异常。
func (a *AIAnalyzer) StreamChat(ctx context.Context, system, user string, onDelta func(string)) (string, error) {
	if onDelta == nil {
		onDelta = func(string) {}
	}
	// temperature: 用户显式设置(>0)才采用, 否则保持既有固定值 0.2 —— 老配置
	// (无该字段)行为零变化; top_p 同理, 0=不发送(服务端默认)。
	temp := 0.2
	if a.cfg.Temperature > 0 {
		temp = a.cfg.Temperature
	}
	payload := map[string]any{
		"model":       a.cfg.Model,
		"max_tokens":  a.cfg.MaxTokens,
		"stream":      true,
		"temperature": temp,
		"messages": []map[string]any{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}
	if a.cfg.TopP > 0 {
		payload["top_p"] = a.cfg.TopP
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("序列化请求失败: %w", err)
	}
	url := chatCompletionsURL(a.cfg.APIBase)

	attempts := a.cfg.Retry + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			d := time.Duration(1<<(i-1)) * 500 * time.Millisecond
			if d > 5*time.Second {
				d = 5 * time.Second
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(d):
			}
		}
		full, rerr := a.streamOnce(ctx, url, body, onDelta)
		if rerr == nil {
			return full, nil
		}
		lastErr = rerr
		if full != "" {
			break // 已产生部分输出, 不重试(避免重复推送增量)
		}
		if !isRetryable(rerr) {
			break
		}
		aiLog.Warn("AI 调用失败, 准备重试", "attempt", i+1, "err", rerr)
	}
	return "", lastErr
}

// streamOnce 单次 HTTP 调用。兼容真流式(SSE)与非流式(整段 JSON)两种返回。
func (a *AIAnalyzer) streamOnce(ctx context.Context, url string, body []byte, onDelta func(string)) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 LLM 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		aiLog.Warn("LLM 返回错误状态", "status", resp.StatusCode, "url", url, "body", string(raw))
		return "", &llmHTTPError{status: resp.StatusCode, url: url}
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", fmt.Errorf("读取 LLM 流失败: %w", err)
		}
		return "", errors.New("LLM 无返回内容")
	}
	first := sc.Text()

	// 非流式兜底: 整段 JSON(部分服务忽略 stream=true)
	if !strings.HasPrefix(strings.TrimSpace(first), "data:") {
		var b strings.Builder
		b.WriteString(first)
		for sc.Scan() {
			b.WriteByte('\n')
			b.WriteString(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return b.String(), fmt.Errorf("读取 LLM 响应失败: %w", err)
		}
		var full struct {
			Choices []struct {
				Message struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
				} `json:"message"`
			} `json:"choices"`
			Error struct{ Message string `json:"message"` } `json:"error"`
		}
		if err := json.Unmarshal([]byte(b.String()), &full); err == nil {
			if full.Error.Message != "" {
				return "", fmt.Errorf("LLM 返回错误: %s", full.Error.Message)
			}
			if len(full.Choices) > 0 {
				m := full.Choices[0].Message
				// 思考型模型(llama.cpp 等)在 max_tokens 被思考过程吃光时
				// content 为空、只有 reasoning_content —— 回退展示思考内容,
				// 否则页面只会报"无返回内容", 用户无法区分是模型还是网络问题。
				c := m.Content
				if strings.TrimSpace(c) == "" {
					c = m.ReasoningContent
				}
				onDelta(c)
				return c, nil
			}
			return "", errors.New("LLM 无返回内容")
		}
		// 既非 SSE 也非 JSON: 原样返回
		return b.String(), nil
	}

	// SSE 流式解析。b 收集正式回答, rb 单独收集思考内容(reasoning_content):
	// 混在一起会把"思考过程"当成正文推送, 用户看到的是几千字推理而不是结论。
	var b, rb strings.Builder
	_ = a.feedSSELine(first, &b, &rb, onDelta)
	for sc.Scan() {
		if a.feedSSELine(sc.Text(), &b, &rb, onDelta) { // 返回 true 表示 [DONE]
			break
		}
	}
	if err := sc.Err(); err != nil {
		return b.String(), fmt.Errorf("读取 LLM 流失败: %w", err)
	}
	if b.Len() == 0 {
		if rb.Len() > 0 {
			// 思考型模型: token 预算被思考吃光, 正式回答为空 —— 回退思考内容
			onDelta(rb.String())
			return rb.String(), nil
		}
		return "", errors.New("LLM 无返回内容")
	}
	return b.String(), nil
}

// feedSSELine 解析一行 SSE, 把增量写入 b(正式回答, 同时回调 onDelta)与
// rb(思考内容, 仅在结束时回退使用); 返回是否收到 [DONE]。
func (a *AIAnalyzer) feedSSELine(line string, b, rb *strings.Builder, onDelta func(string)) bool {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "data:") {
		return false
	}
	data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
	if data == "[DONE]" {
		return true
	}
	var chunk struct {
		Choices []struct {
			Delta struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"delta"`
		} `json:"choices"`
		Error struct{ Message string `json:"message"` } `json:"error"`
	}
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return false // 忽略无法解析的行
	}
	if chunk.Error.Message != "" {
		aiLog.Warn("LLM 流内错误", "err", chunk.Error.Message)
		return true
	}
	for _, c := range chunk.Choices {
		if c.Delta.Content != "" {
			b.WriteString(c.Delta.Content)
			onDelta(c.Delta.Content)
		}
		if c.Delta.ReasoningContent != "" {
			rb.WriteString(c.Delta.ReasoningContent)
		}
	}
	return false
}

// ===== Prompt 数据组装(全部走脱敏) =====

func (a *AIAnalyzer) buildSinglePrompt(v *Vuln, as *ServiceAsset) string {
	var b strings.Builder
	if as != nil {
		b.WriteString(fmt.Sprintf("目标: %s (%s %s)\n", as.HostPort(), as.Product, as.Version))
	}
	b.WriteString(fmt.Sprintf("漏洞: [%s] %s (source=%s, cve=%s, path=%s)\n", v.Severity, v.Title, v.Source, v.CVE, v.Path))
	if v.Detail != "" {
		b.WriteString(v.Detail + "\n")
	}
	b.WriteString("证据(已脱敏):\n---REQUEST---\n")
	b.WriteString(a.Desensitize(v.Request))
	b.WriteString("\n---RESPONSE---\n")
	b.WriteString(a.Desensitize(v.Response))
	b.WriteString("\n")
	return b.String()
}

func (a *AIAnalyzer) buildBatchPrompt(assets []*ServiceAsset, vulns []*Vuln) string {
	const maxAssets, maxVulns = 100, 200
	var b strings.Builder
	b.WriteString("资产指纹:\n")
	for i, as := range assets {
		if i >= maxAssets {
			b.WriteString(fmt.Sprintf("...共 %d 个资产, 仅列前 %d\n", len(assets), maxAssets))
			break
		}
		b.WriteString(fmt.Sprintf("- %s %s %s\n", as.HostPort(), as.Product, as.Version))
	}
	b.WriteString("\n漏洞命中(已脱敏摘要, 不含原始报文):\n")
	for i, v := range vulns {
		if i >= maxVulns {
			b.WriteString(fmt.Sprintf("...共 %d 条, 仅列前 %d\n", len(vulns), maxVulns))
			break
		}
		b.WriteString(fmt.Sprintf("- [%s] %s (source=%s, cve=%s)\n", v.Severity, v.Title, v.Source, v.CVE))
	}
	return b.String()
}

func (a *AIAnalyzer) buildRemediationPrompt(v *Vuln, as *ServiceAsset) string {
	var b strings.Builder
	if as != nil {
		b.WriteString(fmt.Sprintf("目标: %s (%s %s)\n", as.HostPort(), as.Product, as.Version))
	}
	b.WriteString(fmt.Sprintf("漏洞: [%s] %s (source=%s, cve=%s, path=%s)\n", v.Severity, v.Title, v.Source, v.CVE, v.Path))
	if v.Detail != "" {
		b.WriteString(v.Detail + "\n")
	}
	b.WriteString("证据(已脱敏):\n")
	b.WriteString(a.Desensitize(v.Response))
	b.WriteString("\n")
	return b.String()
}

// ===== 缓存 key(基于脱敏内容, 绝不缓存原始凭据) =====

func (a *AIAnalyzer) cacheKeyForSingle(v *Vuln, as *ServiceAsset) string {
	var assetKey string
	if as != nil {
		assetKey = as.HostPort() + "/" + as.Product + "/" + as.Version
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|single|%s|%s|%s|%s|%s|%s|%s",
		a.cfg.Model, v.ID, v.Title, v.Severity, v.Source,
		a.Desensitize(v.Request), a.Desensitize(v.Response), assetKey)))
	return hex.EncodeToString(h[:])
}

func (a *AIAnalyzer) cacheKeyForBatch(assets []*ServiceAsset, vulns []*Vuln) string {
	var b strings.Builder
	b.WriteString(a.cfg.Model)
	b.WriteString("|batch|")
	for _, as := range assets {
		b.WriteString(as.HostPort())
		b.WriteByte('/')
	}
	b.WriteByte('|')
	for _, v := range vulns {
		b.WriteString(v.Title)
		b.WriteByte('|')
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

// ===== 输出解析(容错, 不 panic / 不吞异常) =====

// parseAIResult 解析 LLM 文本为 AIResult; 解析失败时降级为原文 + 强制人工复核。
func parseAIResult(mode, full, model string, elapsed time.Duration) *AIResult {
	res := &AIResult{Mode: mode, Model: model, ElapsedMs: elapsed.Milliseconds()}
	if err := json.Unmarshal([]byte(extractJSON(full)), res); err != nil {
		res.RiskSummary = strings.TrimSpace(full)
		res.NeedReview = true
		res.ReviewAdvice = "AI 输出非结构化, 已降级为原文, 请人工复核"
		aiLog.Warn("AI 输出解析失败, 已降级", "mode", mode, "err", err)
	}
	if res.FalsePositive < 0 {
		res.FalsePositive = 0
	}
	if res.FalsePositive > 100 {
		res.FalsePositive = 100
	}
	return res
}

// extractJSON 从模型输出中截取 JSON 对象(去除 ```json 围栏与前后多余文本)。
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		if j := strings.Index(rest, "\n"); j >= 0 {
			rest = rest[j+1:]
		}
		if k := strings.LastIndex(rest, "```"); k >= 0 {
			rest = rest[:k]
		}
		s = strings.TrimSpace(rest)
	}
	if a := strings.Index(s, "{"); a >= 0 {
		if b := strings.LastIndex(s, "}"); b > a {
			s = s[a : b+1]
		}
	}
	return s
}
