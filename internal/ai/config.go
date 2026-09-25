// config.go AI 配置(阶段 3) —— settings.json 的 ai 节的完整配置。
//
// 分工边界:
//
//	scanner.AIModelConfig  只管"LLM 后端怎么调"(一期的最小集合);
//	本包                   管"全链路分析"(基础参数 + 模块开关 + Prompt 模板 +
//	                       RAG 文档库 + 结构化记忆库), 是 AI 配置页的唯一事实来源。
//
// 读取方式与 scheduler/db 同口径: 包不感知 settings.json, 装配层(main 包)
// 通过 SetConfigReader 注入"给我 ai 节原始 JSON"的函数, 各模块拿到原始字节
// 自行解析 —— 新增字段不波及装配层。
//
// 默认值策略(先填默认再 Unmarshal 覆盖): JSON 里没写的字段保持默认;
// 显式写 false/0 会被尊重(覆盖默认)。这样"用户显式关闭某开关"与
// "用户没写这个字段"不会混淆。
package ai

import (
	"encoding/json"
	"fmt"
	"sync"

	"yugsight/internal/scanner"
)

// 模板键(业务模块 → Prompt 模板)。weakpass/merged 复用 scan 模板。
const (
	TplCapture  = "capture"  // 实时抓包 → 流量分析模板
	TplScan     = "scan"     // 扫描作业(含弱口令/合并报告) → 漏洞报告模板
	TplMonitor  = "monitor"  // 节点监控(含节点采集) → 监控告警研判模板
)

// TplLabel 模板键的中文展示名。
func TplLabel(k string) string {
	switch k {
	case TplCapture:
		return "流量分析模板"
	case TplScan:
		return "漏洞报告模板"
	case TplMonitor:
		return "监控告警研判模板"
	}
	return k
}

// TplKeyForModule 业务模块映射到模板键。
// 返回 ("", false) 表示该模块没有对应的分析入口(未知模块)。
func TplKeyForModule(module string) (string, bool) {
	switch module {
	case "capture":
		return TplCapture, true
	case "scan", "weakpass", "merged":
		return TplScan, true
	case "monitor", "collect":
		return TplMonitor, true
	}
	return "", false
}

// ModuleKeyForTemplate 模板键对应的模块开关(capture/scan/monitor)。
func ModuleKeyForTemplate(k string) string {
	switch k {
	case TplCapture:
		return "capture"
	case TplMonitor:
		return "monitor"
	default:
		return "scan"
	}
}

// PromptVars 模板占位变量全集(UI 展示与渲染共用)。
var PromptVars = []string{
	"raw_data",           // 原始数据(脱敏后)
	"asset_info",         // 资产信息(IP 清单)
	"scan_result",        // 扫描漏洞清单(扫描类模块)
	"metric_data",        // 指标/事件数据(监控类模块)
	"time",               // 分析时间
	"structured_memory",  // 结构化记忆库检索结果
}

// BasicConfig AI 基础参数(ai 节顶层字段, 与 scanner.AIModelConfig 同名兼容)。
type BasicConfig struct {
	Enabled        bool    `json:"enabled"`        // 全局总开关
	Backend        string  `json:"backend"`        // ollama | openai
	APIBase        string  `json:"apiBase"`        // API 地址
	APIKey         string  `json:"apiKey"`         // API Key
	Model          string  `json:"model"`          // 模型名称
	MaxTokens      int     `json:"maxTokens"`      // 最大输出 token
	TimeoutSec     int     `json:"timeoutSec"`     // 请求超时(秒)
	MaxContext     int     `json:"maxContext"`     // 最大上下文长度(输入预算, 字符)
	Temperature    float64 `json:"temperature"`    // 采样温度(0=服务端默认 0.2)
	TopP           float64 `json:"topP"`           // 核采样(0=不发送)
	Retry          int     `json:"retry"`          // 失败重试次数
	MaxEvidence    int     `json:"maxEvidence"`    // 单条证据脱敏后最大字节
	Desensitize    bool    `json:"desensitize"`    // 脱敏开关(关闭仍强制脱敏)
	MaxConcurrency int     `json:"maxConcurrency"` // 全局并发 AI 请求数
}

// ToScanner 转 scanner 模块配置(后端调用参数)。
func (b BasicConfig) ToScanner() scanner.AIModelConfig {
	return scanner.AIModelConfig{
		Enabled:        b.Enabled,
		Backend:        b.Backend,
		APIBase:        b.APIBase,
		APIKey:         b.APIKey,
		Model:          b.Model,
		MaxTokens:      b.MaxTokens,
		TimeoutSec:     b.TimeoutSec,
		Retry:          b.Retry,
		MaxEvidence:    b.MaxEvidence,
		Desensitize:    b.Desensitize,
		MaxConcurrency: b.MaxConcurrency,
		Temperature:    b.Temperature,
		TopP:           b.TopP,
	}
}

// ModuleSwitches 三大业务模块的 AI 分析开关。
// 关闭 = 对应业务页面的 AI 分析按钮置灰(前端读 /api/ai 的 modules 判定);
// 默认全开 —— 最终是否可用仍受全局 enabled 约束, "默认开"不产生任何 LLM 调用。
type ModuleSwitches struct {
	Capture bool `json:"capture"` // 实时抓包 AI 分析
	Scan    bool `json:"scan"`    // 扫描结果 AI 研判(弱口令检测同用此开关)
	Monitor bool `json:"monitor"` // 节点监控告警 AI 分析
}

// PromptTemplate 一套 Prompt 模板(三套预设: 流量/漏洞/监控)。
type PromptTemplate struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	RAG     bool   `json:"rag"`  // 是否启用 RAG 检索文档片段
	TopK    int    `json:"topK"` // RAG 检索条数(模板级, 覆盖 rag.topK)
}

// RAGConfig RAG 非结构化知识库(文档库)参数。
type RAGConfig struct {
	Enabled   bool `json:"enabled"`
	TopK      int  `json:"topK"`      // 默认检索条数
	ChunkSize int  `json:"chunkSize"` // 分片大小(字符)
	MaxChunks int  `json:"maxChunks"` // 单文档最大分片数(超限截断)
	MaxDocs   int  `json:"maxDocs"`   // 文档总数上限(超限拒绝新增)
}

// MemoryScopes 结构化记忆库的检索范围(四项独立勾选)。
type MemoryScopes struct {
	Assets   bool `json:"assets"`   // 资产历史扫描记录(漏洞库)
	Alerts   bool `json:"alerts"`   // 历史告警事件(节点采集事件)
	Captures bool `json:"captures"` // 历史抓包分析记录(原始报告 capture)
	Metrics  bool `json:"metrics"`  // 节点历史指标(采集轮次)
}

// MemoryConfig 结构化记忆库参数。
//
// 与 RAG 的严格区分(页面文案口径):
//   - RAG     = 非结构化文档(安全基线/漏洞手册/设备资料/运维文档)的向量检索,
//     数据来自用户上传, 存 ai_docs 表;
//   - 记忆库  = 平台数据库内**结构化历史记录**的按时间窗检索, 数据来自业务落库
//     (漏洞/告警事件/抓包报告/采集指标), 不额外存储, 只读 + 保留时长控制。
type MemoryConfig struct {
	Enabled      bool         `json:"enabled"`      // 全局总开关
	RetainDays   int          `json:"retainDays"`   // 记忆保留时长(天)
	MaxItems     int          `json:"maxItems"`     // 每个范围的最大检索条数
	Compress     bool         `json:"compress"`     // 记忆压缩(单行摘要 vs 完整内容)
	Scopes       MemoryScopes `json:"scopes"`
}

// EmbeddingConfig 向量嵌入接口(OpenAI 兼容 /embeddings)参数。
//
// 可选插拔(默认关): 未启用时 RAG 走内置 TF-IDF 关键词检索(见 rag.go),
// 不调用任何向量服务。启用后文档分片在索引构建时向量化并落库(Chunk.Vec),
// 检索走余弦相似度。字段收敛于 settings.json 的 ai.embedding 节(配置唯一)。
//
// 命名沿用 ai 节既有 camelCase 口径(apiBase/model/timeoutSec), 与任务书
// 示例的 base_url/model_name 对应: apiBase=base_url, model=model_name,
// batchSize=batch_size, topN=top_n —— 保持 ai 节字段风格统一。
type EmbeddingConfig struct {
	Enabled    bool    `json:"enabled"`    // 开关(默认关)
	APIBase    string  `json:"apiBase"`    // 接口地址(OpenAI 兼容, 如 http://host:8080/v1)
	APIKey     string  `json:"apiKey"`     // API Key(本地模型可空)
	Model      string  `json:"model"`      // 模型名称(如 bge-m3)
	BatchSize  int     `json:"batchSize"`  // 单次请求的分片批量
	Dimension  int     `json:"dimension"`  // 向量维度(须与服务端一致)
	TimeoutSec int     `json:"timeoutSec"` // 单次请求超时(秒)
}

// RerankerConfig 重排序接口(OpenAI/Jina 兼容 /rerank)参数。
//
// 可选插拔(默认关): 未启用时直接返回初筛 TopN, 不调用重排服务。启用后
// 对初筛候选池重打分取前 N。字段收敛于 settings.json 的 ai.reranker 节。
type RerankerConfig struct {
	Enabled    bool    `json:"enabled"`    // 开关(默认关)
	APIBase    string  `json:"apiBase"`    // 接口地址(OpenAI/Jina 兼容)
	APIKey     string  `json:"apiKey"`     // API Key
	Model      string  `json:"model"`      // 模型名称(如 bge-reranker-v2-m3)
	TopN       int     `json:"topN"`       // 重排序返回数量
	TimeoutSec int     `json:"timeoutSec"` // 单次请求超时(秒)
}

// Config AI 完整配置(ai 节)。
//
// BasicConfig **内嵌**(不是带 "basic" 键的字段): ai 节是平铺结构 ——
// enabled/apiBase/model 与 modules/prompts/rag/memory 同级。嵌套会
// 让所有基础字段整体丢失(unmarshal 找不到 "basic" 键), 表现为
// "页面保存了 enabled=true, 读出来永远是 false"。
type Config struct {
	BasicConfig
	Modules   ModuleSwitches             `json:"modules"`
	Prompts   map[string]*PromptTemplate `json:"prompts"`
	RAG       RAGConfig                  `json:"rag"`
	Memory    MemoryConfig               `json:"memory"`
	Embedding EmbeddingConfig            `json:"embedding"`
	Reranker  RerankerConfig             `json:"reranker"`
}

// 默认值(先填这些, 再被 JSON 覆盖)。
const (
	defMaxContext    = 32000
	defTimeoutSec    = 60
	defMaxTokens     = 4096
	defMaxEvidence   = 20 * 1024
	defMaxConc       = 4
	defRetainDays    = 30
	defMaxItems      = 20
	defChunkSize     = 800
	defMaxChunks     = 200
	defMaxDocs       = 50
	defTopK          = 3
	// embedding/reranker 默认(新增可选组件, 默认全关 —— 规则 5)。
	defEmbBatch      = 32
	defEmbDim        = 1024
	defEmbTimeout    = 30
	defRerankTopN    = 5
	defRerankTimeout = 30
	// memoryMaxChars 注入 {{structured_memory}} 的总字符预算
	// (记忆只是参考资料, 不能挤占原始数据的上下文份额)。
	memoryMaxChars = 4096
	// ragTextMaxChars 注入 Prompt 的 RAG 参考片段总字符预算。
	ragTextMaxChars = 6000
)

// DefaultConfig 全默认配置。
func DefaultConfig() *Config {
	return &Config{
		BasicConfig: BasicConfig{
			Enabled:        false, // 全局默认关(规则 5); 页面"测试并保存"通过即开
			Backend:        "openai",
			MaxTokens:      defMaxTokens,
			TimeoutSec:     defTimeoutSec,
			MaxContext:     defMaxContext,
			Temperature:    0.2,
			TopP:           0.9,
			Retry:          1,
			MaxEvidence:    defMaxEvidence,
			Desensitize:    true,
			MaxConcurrency: defMaxConc,
		},
		Modules: ModuleSwitches{Capture: true, Scan: true, Monitor: true},
		Prompts: map[string]*PromptTemplate{
			TplCapture: {Name: TplLabel(TplCapture), Content: DefaultPrompt(TplCapture), RAG: true, TopK: defTopK},
			TplScan:    {Name: TplLabel(TplScan), Content: DefaultPrompt(TplScan), RAG: true, TopK: defTopK},
			TplMonitor: {Name: TplLabel(TplMonitor), Content: DefaultPrompt(TplMonitor), RAG: true, TopK: defTopK},
		},
		RAG: RAGConfig{Enabled: true, TopK: defTopK, ChunkSize: defChunkSize, MaxChunks: defMaxChunks, MaxDocs: defMaxDocs},
		Memory: MemoryConfig{
			Enabled: true, RetainDays: defRetainDays, MaxItems: defMaxItems, Compress: true,
			Scopes: MemoryScopes{Assets: true, Alerts: true, Captures: true, Metrics: true},
		},
		// 新增可选组件默认全关: 未启用不调用任何外部向量/重排服务,
		// RAG 自动降级为内置关键词检索(兼容历史用户, 升级零影响)。
		Embedding: EmbeddingConfig{
			Enabled: false, BatchSize: defEmbBatch, Dimension: defEmbDim, TimeoutSec: defEmbTimeout,
		},
		Reranker: RerankerConfig{
			Enabled: false, TopN: defRerankTopN, TimeoutSec: defRerankTimeout,
		},
	}
}

// LoadConfig 解析 ai 节原始 JSON(缺失 = 全默认)。
//
// 实现: 默认值 + Unmarshal 覆盖。json.Unmarshal 只覆盖 JSON 里出现的
// 键, 缺的保持默认 —— 与"显式 null 视为未配置"的 settings.go 口径一致
// (装配层 section() 已把 null 当不存在处理, 这里收到的不是 "null")。
func LoadConfig(raw []byte) *Config {
	cfg := DefaultConfig()
	if len(raw) == 0 || string(raw) == "null" {
		return cfg
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		// 配置损坏不抛错: 回退全默认并留痕由调用方记日志(规则 4 降级不崩)
		return DefaultConfig()
	}
	cfg.normalize()
	return cfg
}

// normalize 兜底补齐(非法值钳制, 不改变显式配置)。
func (c *Config) normalize() {
	if c.MaxContext <= 0 {
		c.MaxContext = defMaxContext
	}
	if c.TimeoutSec <= 0 {
		c.TimeoutSec = defTimeoutSec
	}
	if c.MaxTokens <= 0 {
		c.MaxTokens = defMaxTokens
	}
	if c.MaxEvidence <= 0 {
		c.MaxEvidence = defMaxEvidence
	}
	if c.MaxConcurrency <= 0 {
		c.MaxConcurrency = defMaxConc
	}
	if c.RAG.TopK <= 0 {
		c.RAG.TopK = defTopK
	}
	if c.RAG.ChunkSize <= 0 {
		c.RAG.ChunkSize = defChunkSize
	}
	if c.RAG.MaxChunks <= 0 {
		c.RAG.MaxChunks = defMaxChunks
	}
	if c.RAG.MaxDocs <= 0 {
		c.RAG.MaxDocs = defMaxDocs
	}
	if c.Memory.RetainDays <= 0 {
		c.Memory.RetainDays = defRetainDays
	}
	if c.Memory.MaxItems <= 0 {
		c.Memory.MaxItems = defMaxItems
	}
	// embedding/reranker 数值兜底(开关本身是 bool, 无需钳制)。
	if c.Embedding.BatchSize <= 0 {
		c.Embedding.BatchSize = defEmbBatch
	}
	if c.Embedding.Dimension <= 0 {
		c.Embedding.Dimension = defEmbDim
	}
	if c.Embedding.TimeoutSec <= 0 {
		c.Embedding.TimeoutSec = defEmbTimeout
	}
	if c.Reranker.TopN <= 0 {
		c.Reranker.TopN = defRerankTopN
	}
	if c.Reranker.TimeoutSec <= 0 {
		c.Reranker.TimeoutSec = defRerankTimeout
	}
	if c.Prompts == nil {
		c.Prompts = map[string]*PromptTemplate{}
	}
	for k, def := range DefaultConfig().Prompts {
		p, ok := c.Prompts[k]
		if !ok || p == nil || p.Content == "" {
			c.Prompts[k] = def
			continue
		}
		if p.TopK <= 0 {
			p.TopK = defTopK
		}
	}
}

// Prompt 取某模板(不存在 = 报错, 调用方按模块键取不会走到这里)。
func (c *Config) Prompt(key string) (*PromptTemplate, error) {
	p, ok := c.Prompts[key]
	if !ok || p == nil || p.Content == "" {
		return nil, fmt.Errorf("Prompt 模板不存在: %s", key)
	}
	return p, nil
}

// ModuleEnabled 某模板键对应的模块开关。
func (c *Config) ModuleEnabled(key string) bool {
	switch key {
	case TplCapture:
		return c.Modules.Capture
	case TplMonitor:
		return c.Modules.Monitor
	default:
		return c.Modules.Scan
	}
}

var (
	cfgReaderMu sync.RWMutex
	cfgReader   func() ([]byte, bool) // 装配层注入; nil = 全默认
)

// SetConfigReader 注入 ai 节读取函数(装配层传 settings section 闭包)。
// 与 scheduler.SetConfigReader 同口径; 传 nil 无法复位(测试用"总返回不存在"复位)。
func SetConfigReader(f func() ([]byte, bool)) {
	cfgReaderMu.Lock()
	if f != nil {
		cfgReader = f
	}
	cfgReaderMu.Unlock()
}

// CurrentConfig 当前生效的 AI 配置(每次实时读取, 页面保存后立即生效)。
func CurrentConfig() *Config {
	cfgReaderMu.RLock()
	f := cfgReader
	cfgReaderMu.RUnlock()
	if f == nil {
		return DefaultConfig()
	}
	raw, ok := f()
	if !ok || len(raw) == 0 {
		return DefaultConfig()
	}
	return LoadConfig(raw)
}
