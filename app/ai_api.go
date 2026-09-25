// ai_api.go AI 全链路分析模块(阶段 3) —— main 包与 ai 包的唯一连接点。
//
// 分工(与 scheduler_api / report_raw_api 同角色):
//
//	ai 包      纯逻辑: 配置解析 / Prompt 渲染 / RAG 向量引擎 / 记忆检索 /
//	           分析管线(依赖注入, 可离线单测);
//	本文件     装配: settings.json 的 ai 读写 / v2DB 数据源 / RAG 索引生命周期 /
//	           HTTP 路由 / 报告中心回写。
//
// 路由(除 /api/ai 与 /api/ai/test 外全部 requireAuth, 写操作 adminOrOperator):
//
//	GET    /api/ai                      状态+配置总览(业务页 AI 按钮的开关依据)
//	POST   /api/ai/config               保存基础配置+模块开关(测试并保存走 /api/ai/test)
//	POST   /api/ai/test                 连通性测试(旧端点, 行为不变)
//	GET    /api/ai/templates            三套 Prompt 模板
//	POST   /api/ai/templates            保存模板
//	POST   /api/ai/templates/reset      恢复默认模板
//	GET    /api/ai/rag                  文档库状态+文档列表+RAG 参数
//	POST   /api/ai/rag/config           保存 RAG 参数
//	POST   /api/ai/rag/docs             上传文档(分片+向量化)
//	POST   /api/ai/rag/docs/{id}/toggle 启用/禁用
//	DELETE /api/ai/rag/docs/{id}        删除
//	GET    /api/ai/rag/search           检索预览
//	GET    /api/ai/memory               记忆库配置
//	POST   /api/ai/memory               保存记忆库配置
//	POST   /api/ai/analyze              执行分析并回写报告中心
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"yugsight/internal/ai"
	"yugsight/internal/collect"
	"yugsight/internal/db"
	"yugsight/internal/report"
)

// ===== RAG 索引生命周期 =====

var ragIndexMu sync.Mutex

// loadRAGIndex 从 ai_docs 表重建索引 + 统一检索器(启动时 + 文档增删改后调用)。
//
// 只做"加载 + 构建", 不做向量计算(向量化是独立的补全流程 vectorizeAllAsync,
// 避免启动/变更被外部 embedding 服务阻塞)。检索器按当前配置装配 embedding/
// reranker: 未启用的组件不构造客户端(不占资源, 规则 2)。
//
// 失败 = 降级(索引/检索器置空, RAG 按"无参考"处理, 不阻断分析)。
func loadRAGIndex() {
	ragIndexMu.Lock()
	defer ragIndexMu.Unlock()
	d := v2DB()
	if d == nil || d.AIDocs() == nil {
		ai.SetRAGIndex(nil)
		ai.SetRetriever(nil)
		return
	}
	docs, err := d.AIDocs().List()
	if err != nil {
		logLine("[AI] RAG 文档索引加载失败: "+err.Error())
		ai.SetRAGIndex(nil)
		ai.SetRetriever(nil)
		return
	}
	list := make([]*ai.Doc, 0, len(docs))
	for _, doc := range docs {
		if doc != nil {
			list = append(list, doc)
		}
	}
	cfg := ai.CurrentConfig()
	ix := ai.NewIndex(list)
	rt := ai.NewRetriever(ix)
	if cfg.Embedding.Enabled {
		rt.SetEmbedder(ai.NewOpenAIEmbedder(cfg.Embedding))
	}
	if cfg.Reranker.Enabled {
		rt.SetReranker(ai.NewOpenAIReranker(cfg.Reranker))
	}
	ai.SetRAGIndex(ix)
	ai.SetRetriever(rt)
}

// ===== 向量补全(启用 embedding 时: 分片 → 向量化 → 落库) =====
//
// 口径: 向量是 TF 之上的"派生索引"(与 TF-IDF 的 IDF 延迟计算同思路), 但按
// 任务要求落库复用现有数据层(Chunk.Vec 存于 ai_docs, 非外部向量库)。以
// EmbeddingKey(模型:维度) 为指纹: 换模型/维度 → 旧向量失效 → 整体重算, 避免
// 用错维度/空间的向量得出错误"语义命中"。
//
// 时机: ①上传新文档(单篇同步, 快); ②启用/变更 embedding 配置(全量后台异步,
// 不阻塞 HTTP 与启动); ③启动时若语料缺向量(自愈, 后台异步)。

// vectorizeDoc 对单篇文档嵌入并向量化(幂等: 指纹已匹配则跳过)。
// 失败返回 error(调用方降级关键词, 规则 4); 成功=已落库(含指纹)。
func vectorizeDoc(d *db.Database, doc *ai.Doc, emb *ai.EmbeddingConfig) error {
	if d == nil || d.AIDocs() == nil {
		return errors.New("数据表不可用")
	}
	key := ai.EmbeddingKey(*emb)
	if doc.EmbKey == key {
		return nil // 已按当前配置向量化(幂等)
	}
	// 只对非空分片向量化(空分片无向量也无检索意义)。
	var texts []string
	var idx []int
	for i := range doc.Chunks {
		if strings.TrimSpace(doc.Chunks[i].Text) != "" {
			texts = append(texts, doc.Chunks[i].Text)
			idx = append(idx, i)
		}
	}
	if len(texts) == 0 {
		doc.EmbKey = key
		_, uerr := d.AIDocs().Upsert(doc)
		return uerr
	}
	vecs, err := ai.NewOpenAIEmbedder(*emb).Embed(context.Background(), texts)
	if err != nil {
		return err
	}
	for j, ci := range idx {
		if j >= len(vecs) {
			break
		}
		doc.Chunks[ci].Vec = vecs[j]
	}
	doc.EmbKey = key
	_, uerr := d.AIDocs().Upsert(doc)
	return uerr
}

// needsVectorization 语料里是否还有"启用且缺当前指纹向量"的文档(决定要不要
// 触发后台补全)。全部已向量化的文档 → false(启动时快速短路, 不白跑异步)。
func needsVectorization(cfg *ai.Config) bool {
	if !cfg.Embedding.Enabled {
		return false
	}
	d := v2DB()
	if d == nil || d.AIDocs() == nil {
		return false
	}
	docs, err := d.AIDocs().List()
	if err != nil {
		return false
	}
	key := ai.EmbeddingKey(cfg.Embedding)
	for _, doc := range docs {
		if doc != nil && doc.Enabled && doc.EmbKey != key {
			return true
		}
	}
	return false
}

var vectorizeBusyMu sync.Mutex
var vectorizeBusy bool

// vectorizeAllAsync 后台对全部启用文档补/刷新向量, 完成后重建索引。
// 并发保护: 同时只有一个在跑(重复触发幂等跳过)。只持 DAO 快照指针(不持
// Database 门面) —— 与 Close 置 nil 的竞争风险见 db 包说明。
func vectorizeAllAsync(cfg *ai.Config) {
	vectorizeBusyMu.Lock()
	if vectorizeBusy {
		vectorizeBusyMu.Unlock()
		return
	}
	vectorizeBusy = true
	vectorizeBusyMu.Unlock()
	go func() {
		defer func() {
			vectorizeBusyMu.Lock()
			vectorizeBusy = false
			vectorizeBusyMu.Unlock()
		}()
		d := v2DB()
		if d == nil {
			return
		}
		dao := d.AIDocs() // DAO 快照(异步期间可能 Close, 不持有 Database)
		if dao == nil {
			return
		}
		docs, err := dao.List()
		if err != nil {
			logLine("[AI] 向量补全: 读取文档失败: "+err.Error())
			return
		}
		key := ai.EmbeddingKey(cfg.Embedding)
		done, fail, skip := 0, 0, 0
		for _, doc := range docs {
			if doc == nil || !doc.Enabled {
				continue
			}
			if doc.EmbKey == key {
				skip++
				continue
			}
			if err := vectorizeDoc(d, doc, &cfg.Embedding); err != nil {
				fail++
				logLine("[AI] 向量补全失败(文档「"+doc.Name+"」降级关键词检索): "+err.Error())
			} else {
				done++
			}
		}
		logLine(fmt.Sprintf("[AI] 向量补全完成: 新向量化 %d 篇, 已就绪跳过 %d 篇, 失败 %d 篇", done, skip, fail))
		loadRAGIndex() // 刷新索引与检索器(带上新向量)
	}()
}

// ===== ai 节读写(settings.json, 合并式: 只动自己的键) =====

// readAISecFromDisk 从**磁盘**读 ai 节为 map(缺失/损坏 = 空 map)。
//
// 为什么读盘而不读内存缓存: 与 writeSection 同口径 —— 内存缓存是启动
// 时快照, 用户可能运行期手改过 settings.json; 合并源必须是"当前真实内容",
// 否则程序保存会把用户手改的部分冲掉(项目 settings.go 注释里的坑)。
func readAISecFromDisk() map[string]any {
	m := map[string]any{}
	data, err := os.ReadFile(settingsFilePath())
	if err != nil || len(data) == 0 {
		return m
	}
	disk := map[string]json.RawMessage{}
	if uerr := json.Unmarshal(stripBOM(data), &disk); uerr != nil {
		return m
	}
	if raw, ok := disk[secAI]; ok {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

// updateAISec 合并写 ai 节的若干键(保留其余键: prompts/rag/memory 互不干扰)。
// 写后重置配置缓存(让 ai 包读到新值); 基础参数变化时热生效
// (重建全局分析器, 免重启, 与 /api/ai/test 同口径)。
func updateAISec(keys map[string]any, reinitAnalyzer bool) error {
	m := readAISecFromDisk()
	for k, v := range keys {
		m[k] = v
	}
	if err := writeSection(secAI, m); err != nil {
		return err
	}
	resetSettingsCache()
	if reinitAnalyzer {
		initAI(false)
	}
	return nil
}

// updateAIPrompt 保存单套模板(prompts 子键合并, 其余两套不动)。
func updateAIPrompt(key string, p *ai.PromptTemplate) error {
	m := readAISecFromDisk()
	pm := map[string]any{}
	if raw, ok := m["prompts"]; ok {
		if b, err := json.Marshal(raw); err == nil {
			_ = json.Unmarshal(b, &pm)
		}
	}
	pm[key] = p
	m["prompts"] = pm
	if err := writeSection(secAI, m); err != nil {
		return err
	}
	resetSettingsCache()
	return nil
}

// ===== 状态与配置 =====

// handleAIStatus GET /api/ai
//
// 向后兼容: 保留旧字段(enabled/backend/apiBase/model, 经典页与
// Capture.vue 依赖), 新增阶段 3 字段(模块开关/模板/RAG/记忆库)。
// 业务页 AI 按钮的置灰依据就是这里的 enabled + modules。
func handleAIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := ai.CurrentConfig()
	rag := cfg.RAG
	d := v2DB()
	docCount := 0
	if d != nil && d.AIDocs() != nil {
		docCount, _ = d.AIDocs().Count()
	}
	jsonOK(w, map[string]any{
		// 旧字段(兼容经典页)
		"enabled": cfg.Enabled,
		"backend": cfg.Backend,
		"apiBase": cfg.APIBase,
		"model":   cfg.Model,
		// 阶段 3: 基础参数
		"maxTokens":      cfg.MaxTokens,
		"timeoutSec":     cfg.TimeoutSec,
		"maxContext":     cfg.MaxContext,
		"temperature":    cfg.Temperature,
		"topP":           cfg.TopP,
		"maxConcurrency": cfg.MaxConcurrency,
		// 阶段 3: 模块开关(业务页按钮置灰依据)
		"modules": cfg.Modules,
		// 阶段 3: 模板(不含正文, 正文走 /api/ai/templates)
		"prompts": promptMeta(cfg),
		// 阶段 3: RAG
		"rag": map[string]any{"enabled": rag.Enabled, "topK": rag.TopK, "docCount": docCount},
		// RAG 向量检索组件(可选插拔): 前端据此置灰/隐藏配置项(不回显密钥)
		"embedding": aiEmbeddingPublic(cfg.Embedding),
		"reranker":  aiRerankerPublic(cfg.Reranker),
		// 阶段 3: 记忆库
		"memory":       cfg.Memory,
		"memoryScopes": cfg.Memory.ScopesLabel(),
	})
}

func promptMeta(cfg *ai.Config) map[string]any {
	out := map[string]any{}
	for k, p := range cfg.Prompts {
		if p == nil {
			continue
		}
		out[k] = map[string]any{"name": p.Name, "rag": p.RAG, "topK": p.TopK}
	}
	return out
}

// handleAIConfigSave POST /api/ai/config
//
// 保存基础参数 + 模块总开关。指针字段区分"传了"与"没传"(没传的保持
// 现值) —— 经典页只传 apiBase/apiKey/model 也完全兼容(其余键不动)。
func handleAIConfigSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		APIBase     string  `json:"apiBase"`
		APIKey      string  `json:"apiKey"`
		Model       string  `json:"model"`
		TimeoutSec  *int    `json:"timeoutSec"`
		MaxContext  *int    `json:"maxContext"`
		MaxTokens   *int    `json:"maxTokens"`
		Temperature *float64 `json:"temperature"`
		TopP        *float64 `json:"topP"`
		Modules     *ai.ModuleSwitches `json:"modules"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	cfg := ai.CurrentConfig()
	b := cfg.BasicConfig
	if strings.TrimSpace(req.APIBase) != "" {
		b.APIBase = strings.TrimSpace(req.APIBase)
	}
	if req.APIKey != "" {
		b.APIKey = strings.TrimSpace(req.APIKey)
	}
	if strings.TrimSpace(req.Model) != "" {
		b.Model = strings.TrimSpace(req.Model)
	}
	if req.TimeoutSec != nil {
		b.TimeoutSec = *req.TimeoutSec
	}
	if req.MaxContext != nil {
		b.MaxContext = *req.MaxContext
	}
	if req.MaxTokens != nil {
		b.MaxTokens = *req.MaxTokens
	}
	if req.Temperature != nil {
		b.Temperature = *req.Temperature
	}
	if req.TopP != nil {
		b.TopP = *req.TopP
	}
	keys := map[string]any{
		"enabled": b.Enabled, "backend": b.Backend, "apiBase": b.APIBase,
		"apiKey": b.APIKey, "model": b.Model, "maxTokens": b.MaxTokens,
		"timeoutSec": b.TimeoutSec, "maxContext": b.MaxContext,
		"temperature": b.Temperature, "topP": b.TopP,
		"retry": b.Retry, "maxEvidence": b.MaxEvidence,
		"desensitize": b.Desensitize, "maxConcurrency": b.MaxConcurrency,
	}
	if req.Modules != nil {
		cfg.Modules = *req.Modules
	}
	keys["modules"] = cfg.Modules
	if err := updateAISec(keys, true); err != nil {
		jsonErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	jsonOK(w, map[string]any{"saved": true, "modules": cfg.Modules})
}

// ===== Prompt 模板 =====

// handleAITemplates GET /api/ai/templates
func handleAITemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := ai.CurrentConfig()
	out := make([]map[string]any, 0, len(cfg.Prompts))
	for _, k := range []string{ai.TplCapture, ai.TplScan, ai.TplMonitor} {
		p, ok := cfg.Prompts[k]
		if !ok || p == nil {
			continue
		}
		out = append(out, map[string]any{
			"key": k, "label": ai.TplLabel(k),
			"name": p.Name, "content": p.Content, "rag": p.RAG, "topK": p.TopK,
		})
	}
	jsonOK(w, map[string]any{"templates": out, "vars": ai.PromptVars})
}

// handleAITemplateSave POST /api/ai/templates
// {key, content?, name?, rag?, topK?} —— content 空 = 只改绑定参数。
func handleAITemplateSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Key     string  `json:"key"`
		Content string  `json:"content"`
		Name    string  `json:"name"`
		RAG     *bool   `json:"rag"`
		TopK    *int    `json:"topK"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if _, ok := ai.TplKeyForModule(req.Key); !ok {
		jsonErr(w, http.StatusBadRequest, "未知模板键(可选: capture / scan / monitor)")
		return
	}
	cfg := ai.CurrentConfig()
	prev, err := cfg.Prompt(req.Key)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	content := prev.Content
	if strings.TrimSpace(req.Content) != "" {
		if len(req.Content) > 16000 {
			jsonErr(w, http.StatusBadRequest, "模板过长(上限 16000 字符)")
			return
		}
		content = req.Content
	}
	p := &ai.PromptTemplate{
		Name:    prev.Name,
		Content: content,
		RAG:     prev.RAG,
		TopK:    prev.TopK,
	}
	if strings.TrimSpace(req.Name) != "" {
		p.Name = strings.TrimSpace(req.Name)
	}
	if req.RAG != nil {
		p.RAG = *req.RAG
	}
	if req.TopK != nil && *req.TopK > 0 {
		p.TopK = *req.TopK
	}
	if err := updateAIPrompt(req.Key, p); err != nil {
		jsonErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	jsonOK(w, map[string]any{"saved": true, "key": req.Key})
}

// handleAITemplateReset POST /api/ai/templates/reset {key}
func handleAITemplateReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if _, ok := ai.TplKeyForModule(req.Key); !ok {
		jsonErr(w, http.StatusBadRequest, "未知模板键(可选: capture / scan / monitor)")
		return
	}
	def := ai.DefaultConfig().Prompts[req.Key]
	p := &ai.PromptTemplate{
		Name: def.Name, Content: def.Content, RAG: def.RAG, TopK: def.TopK,
	}
	if err := updateAIPrompt(req.Key, p); err != nil {
		jsonErr(w, http.StatusInternalServerError, "恢复失败: "+err.Error())
		return
	}
	jsonOK(w, map[string]any{"reset": true, "key": req.Key})
}

// ===== RAG 文档库 =====

// aiEmbeddingPublic / aiRerankerPublic 组件配置的对前端视图。
//
// 刻意**不回显 apiKey**(与 LLM 配置 handleAIStatus 同口径 —— 该接口不返回
// LLM 的 apiKey): 密钥进响应体会被浏览器历史/代理日志留存, 而"保存时空=保留
// 现值"已让前端无需预填 key 也能安全保存。前端 key 输入框留空即沿用已存值。
func aiEmbeddingPublic(c ai.EmbeddingConfig) map[string]any {
	return map[string]any{
		"enabled": c.Enabled, "apiBase": c.APIBase, "model": c.Model,
		"batchSize": c.BatchSize, "dimension": c.Dimension, "timeoutSec": c.TimeoutSec,
	}
}

func aiRerankerPublic(c ai.RerankerConfig) map[string]any {
	return map[string]any{
		"enabled": c.Enabled, "apiBase": c.APIBase, "model": c.Model,
		"topN": c.TopN, "timeoutSec": c.TimeoutSec,
	}
}

// handleAIRAG GET /api/ai/rag —— 状态 + 文档列表 + 参数。
func handleAIRAG(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := ai.CurrentConfig()
	docs := []map[string]any{}
	d := v2DB()
	if d != nil && d.AIDocs() != nil {
		all, _ := d.AIDocs().List()
		for _, doc := range all {
			if doc == nil {
				continue
			}
			docs = append(docs, map[string]any{
				"id": doc.ID, "name": doc.Name, "category": doc.Category,
				"enabled": doc.Enabled, "size": doc.Size,
				"chunks": len(doc.Chunks), "createdAt": doc.CreatedAt,
			})
		}
		sort.Slice(docs, func(i, j int) bool {
			a, _ := docs[i]["createdAt"].(int64)
			b, _ := docs[j]["createdAt"].(int64)
			return a > b
		})
	}
	jsonOK(w, map[string]any{
		"enabled":   cfg.RAG.Enabled,
		"topK":      cfg.RAG.TopK,
		"chunkSize": cfg.RAG.ChunkSize,
		"maxChunks": cfg.RAG.MaxChunks,
		"maxDocs":   cfg.RAG.MaxDocs,
		// 向量检索组件配置(可选插拔, 默认关; 不回显密钥)
		"embedding": aiEmbeddingPublic(cfg.Embedding),
		"reranker":  aiRerankerPublic(cfg.Reranker),
		"docs":      docs,
	})
}

// handleAIRAGConfig POST /api/ai/rag/config
//
// 保存 RAG 参数 + 向量检索组件(Embedding/Reranker)。三块独立: 只传哪块就改
// 哪块(其余保持现值)。embedding 开关/模型变化时触发后台向量补全 + 重建索引
// (换模型 → 旧向量指纹失效 → 重算)。
func handleAIRAGConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enabled   *bool               `json:"enabled"`
		TopK      *int                `json:"topK"`
		ChunkSize *int                `json:"chunkSize"`
		MaxChunks *int                `json:"maxChunks"`
		MaxDocs   *int                `json:"maxDocs"`
		Embedding *ai.EmbeddingConfig `json:"embedding"`
		Reranker  *ai.RerankerConfig  `json:"reranker"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	cfg := ai.CurrentConfig()
	rag := cfg.RAG
	if req.Enabled != nil {
		rag.Enabled = *req.Enabled
	}
	if req.TopK != nil && *req.TopK > 0 {
		rag.TopK = *req.TopK
	}
	if req.ChunkSize != nil && *req.ChunkSize > 0 {
		rag.ChunkSize = *req.ChunkSize
	}
	if req.MaxChunks != nil && *req.MaxChunks > 0 {
		rag.MaxChunks = *req.MaxChunks
	}
	if req.MaxDocs != nil && *req.MaxDocs > 0 {
		rag.MaxDocs = *req.MaxDocs
	}
	keys := map[string]any{"rag": rag}
	// embedding/reranker: 字段合并写(与 LLM 保存同口径 —— 字符串空=保持现值)。
	// 关键: apiKey 不在响应里回显, 前端重开页面后它是空的, 若整块替换会把
	// 已存的 key 冲掉; 故"空=保留现值", 只有用户重新输入才覆盖。
	if req.Embedding != nil {
		e := cfg.Embedding
		e.Enabled = req.Embedding.Enabled
		if req.Embedding.APIBase != "" {
			e.APIBase = strings.TrimSpace(req.Embedding.APIBase)
		}
		if req.Embedding.APIKey != "" {
			e.APIKey = strings.TrimSpace(req.Embedding.APIKey)
		}
		if req.Embedding.Model != "" {
			e.Model = strings.TrimSpace(req.Embedding.Model)
		}
		if req.Embedding.BatchSize > 0 {
			e.BatchSize = req.Embedding.BatchSize
		}
		if req.Embedding.Dimension > 0 {
			e.Dimension = req.Embedding.Dimension
		}
		if req.Embedding.TimeoutSec > 0 {
			e.TimeoutSec = req.Embedding.TimeoutSec
		}
		cfg.Embedding = e
		keys["embedding"] = e
	}
	if req.Reranker != nil {
		rr := cfg.Reranker
		rr.Enabled = req.Reranker.Enabled
		if req.Reranker.APIBase != "" {
			rr.APIBase = strings.TrimSpace(req.Reranker.APIBase)
		}
		if req.Reranker.APIKey != "" {
			rr.APIKey = strings.TrimSpace(req.Reranker.APIKey)
		}
		if req.Reranker.Model != "" {
			rr.Model = strings.TrimSpace(req.Reranker.Model)
		}
		if req.Reranker.TopN > 0 {
			rr.TopN = req.Reranker.TopN
		}
		if req.Reranker.TimeoutSec > 0 {
			rr.TimeoutSec = req.Reranker.TimeoutSec
		}
		cfg.Reranker = rr
		keys["reranker"] = rr
	}
	if err := updateAISec(keys, false); err != nil {
		jsonErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	cur := ai.CurrentConfig()
	// 向量检索组件变化 → 重建索引(装配新客户端) + 必要时后台补全向量。
	if req.Embedding != nil || req.Reranker != nil {
		loadRAGIndex()
		if cur.Embedding.Enabled && needsVectorization(cur) {
			vectorizeAllAsync(cur)
		}
	}
	jsonOK(w, map[string]any{
		"saved":     true,
		"rag":       cur.RAG,
		"embedding": aiEmbeddingPublic(cur.Embedding),
		"reranker":  aiRerankerPublic(cur.Reranker),
	})
}

const ragDocMaxBytes = 2 << 20 // 单文档 2MB(分片向量要存 JSONL, 防撑爆)

// handleAIRAGDocUpload POST /api/ai/rag/docs
// {name, category, content} —— 上传即分片 + 向量化(TF), 立即可被检索。
func handleAIRAGDocUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		Content  string `json:"content"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "文档名称必填")
		return
	}
	content := req.Content
	if len(content) > ragDocMaxBytes {
		jsonErr(w, http.StatusBadRequest, fmt.Sprintf("文档过大(上限 %d 字节)", ragDocMaxBytes))
		return
	}
	cfg := ai.CurrentConfig()
	d := v2DB()
	if d == nil || d.AIDocs() == nil {
		jsonErr(w, http.StatusServiceUnavailable, "数据表不可用")
		return
	}
	if n, _ := d.AIDocs().Count(); n >= cfg.RAG.MaxDocs {
		jsonErr(w, http.StatusBadRequest, fmt.Sprintf("文档数已达上限(%d 篇), 请先删除旧文档", cfg.RAG.MaxDocs))
		return
	}
	chunks := ai.BuildDocIndex(content, cfg.RAG.ChunkSize, cfg.RAG.MaxChunks)
	if len(chunks) == 0 {
		jsonErr(w, http.StatusBadRequest, "文档正文为空(无可分片文本)")
		return
	}
	doc := &ai.Doc{
		ID:        ai.NewDocID(),
		Name:      name,
		Category:  strings.TrimSpace(req.Category),
		Enabled:   true,
		CreatedAt: time.Now().UnixMilli(),
		Size:      len([]byte(content)),
		Chunks:    chunks,
	}
	if _, err := d.AIDocs().Upsert(doc); err != nil {
		jsonErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	// 启用 embedding → 新文档即时向量化(单篇同步, 快); 失败不阻断上传,
	// 该文档降级为关键词检索(规则 4 降级不崩)。
	vectorized := false
	if cfg.Embedding.Enabled {
		if verr := vectorizeDoc(d, doc, &cfg.Embedding); verr != nil {
			logLine("[AI] 新文档「"+name+"」向量化失败(降级关键词检索): "+verr.Error())
		} else if doc.EmbKey != "" {
			vectorized = true
		}
	}
	loadRAGIndex()
	jsonOK(w, map[string]any{"id": doc.ID, "chunks": len(chunks), "vectorized": vectorized})
}

// handleAIRAGDocToggle POST /api/ai/rag/docs/{id}/toggle
func handleAIRAGDocToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	d := v2DB()
	if d == nil || d.AIDocs() == nil {
		jsonErr(w, http.StatusServiceUnavailable, "数据表不可用")
		return
	}
	doc, err := d.AIDocs().Get(id)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "文档不存在")
		return
	}
	doc.Enabled = !doc.Enabled
	if _, err := d.AIDocs().Upsert(doc); err != nil {
		jsonErr(w, http.StatusInternalServerError, "更新失败: "+err.Error())
		return
	}
	loadRAGIndex()
	jsonOK(w, map[string]any{"id": id, "enabled": doc.Enabled})
}

// handleAIRAGDocDelete DELETE /api/ai/rag/docs/{id}
func handleAIRAGDocDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	d := v2DB()
	if d == nil || d.AIDocs() == nil {
		jsonErr(w, http.StatusServiceUnavailable, "数据表不可用")
		return
	}
	if _, err := d.AIDocs().Delete(id); err != nil {
		jsonErr(w, http.StatusNotFound, "文档不存在")
		return
	}
	loadRAGIndex()
	jsonOK(w, map[string]any{"deleted": true, "id": id})
}

// handleAIRAGSearch GET /api/ai/rag/search?q= —— 检索预览(调试/验收用)。
func handleAIRAGSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		jsonErr(w, http.StatusBadRequest, "缺少检索词 q")
		return
	}
	rt := ai.CurrentRetriever()
	if rt == nil {
		jsonOK(w, map[string]any{"hits": []any{}, "empty": true, "mode": ""})
		return
	}
	hits := rt.Search(r.Context(), q, ai.CurrentConfig().RAG.TopK)
	if hits == nil {
		hits = []ai.Hit{}
	}
	// 回带实际检索模式(向量/关键词降级), 前端可提示"当前为关键词检索"
	jsonOK(w, map[string]any{"hits": hits, "mode": rt.Mode()})
}

// ===== 结构化记忆库 =====

// handleAIMemory GET /api/ai/memory
func handleAIMemory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := ai.CurrentConfig()
	jsonOK(w, map[string]any{
		"config":       cfg.Memory,
		"scopesLabel":  cfg.Memory.ScopesLabel(),
		"scopesList":   []string{"assets", "alerts", "captures", "metrics"},
	})
}

// handleAIMemorySave POST /api/ai/memory
func handleAIMemorySave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enabled      *bool         `json:"enabled"`
		RetainDays   *int          `json:"retainDays"`
		MaxItems     *int          `json:"maxItems"`
		Compress     *bool         `json:"compress"`
		Scopes       *ai.MemoryScopes `json:"scopes"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	cfg := ai.CurrentConfig()
	m := cfg.Memory
	if req.Enabled != nil {
		m.Enabled = *req.Enabled
	}
	if req.RetainDays != nil && *req.RetainDays > 0 {
		m.RetainDays = *req.RetainDays
	}
	if req.MaxItems != nil && *req.MaxItems > 0 {
		m.MaxItems = *req.MaxItems
	}
	if req.Compress != nil {
		m.Compress = *req.Compress
	}
	if req.Scopes != nil {
		m.Scopes = *req.Scopes
	}
	if err := updateAISec(map[string]any{"memory": m}, false); err != nil {
		jsonErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	jsonOK(w, map[string]any{"saved": true, "memory": m})
}

// ===== 记忆数据源(v2DB 实现 ai.MemoryStore) =====

// aiMemoryStore 结构化记忆库的四个范围, 全部读 v2DB 只读降级:
// 库不可用/单表读失败 = 该范围缺席(返回空), 不阻断分析。
type aiMemoryStore struct{}

func (aiMemoryStore) AssetHistory(since time.Time, limit int) ([]ai.MemoryEntry, error) {
	d := v2DB()
	if d == nil || d.Vulns() == nil {
		return nil, nil
	}
	all, err := d.Vulns().Since(since)
	if err != nil {
		return nil, nil
	}
	sort.Slice(all, func(i, j int) bool { return all[i].FoundAt.After(all[j].FoundAt) })
	if len(all) > limit {
		all = all[:limit]
	}
	out := make([]ai.MemoryEntry, 0, len(all))
	for _, v := range all {
		label := fmt.Sprintf("%s | %s | %s", v.AssetIP, v.Severity, v.Title)
		if v.CVE != "" {
			label += " | " + v.CVE
		}
		out = append(out, ai.MemoryEntry{At: v.FoundAt, Label: label})
	}
	return out, nil
}

func (aiMemoryStore) AlertHistory(since time.Time, limit int) ([]ai.MemoryEntry, error) {
	d := v2DB()
	if d == nil || d.CollectEvents() == nil {
		return nil, nil
	}
	all, err := d.CollectEvents().List()
	if err != nil {
		return nil, nil
	}
	var out []ai.MemoryEntry
	for _, e := range all {
		if e.At.Before(since) {
			continue
		}
		out = append(out, ai.MemoryEntry{
			At:     e.At,
			Label:  fmt.Sprintf("%s | %s | %s | %s", e.Target, e.Level, e.Type, e.Msg),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (aiMemoryStore) CaptureHistory(since time.Time, limit int) ([]ai.MemoryEntry, error) {
	d := v2DB()
	if d == nil || d.RawReports() == nil {
		return nil, nil
	}
	all, err := d.RawReports().List()
	if err != nil {
		return nil, nil
	}
	var out []ai.MemoryEntry
	for _, r := range all {
		if r == nil || r.Module != report.RawModCapture || r.CreatedAt.Before(since) {
			continue
		}
		label := r.Title
		if r.Summary != "" {
			label += " | " + r.Summary
		}
		if r.AINote != "" {
			n := r.AINote
			if len(n) > 80 {
				n = n[:80] + "..."
			}
			label += " | AI: " + n
		}
		out = append(out, ai.MemoryEntry{At: r.CreatedAt, Label: label})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (aiMemoryStore) MetricHistory(since time.Time, limit int) ([]ai.MemoryEntry, error) {
	d := v2DB()
	if d == nil || d.CollectSamples() == nil {
		return nil, nil
	}
	all, err := d.CollectSamples().List()
	if err != nil {
		return nil, nil
	}
	var out []ai.MemoryEntry
	for _, s := range all {
		if s.At.Before(since) {
			continue
		}
		state := "正常"
		if !s.OK {
			state = "异常: " + s.Err
		}
		out = append(out, ai.MemoryEntry{
			At:     s.At,
			Label:  fmt.Sprintf("%s | %s | %s", s.Target, state, compactMetrics(s.Metrics)),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// compactMetrics 指标压缩为 "cpu=85 mem=72" 一行(前 8 项, 防过长)。
func compactMetrics(ms []collect.Metric) string {
	if len(ms) == 0 {
		return "无指标"
	}
	n := len(ms)
	if n > 8 {
		n = 8
	}
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf("%s=%g", ms[i].Name, ms[i].Value))
	}
	return strings.Join(parts, " ")
}

// ===== AI 分析(触发 + 回写报告中心) =====

// handleAIAnalyze POST /api/ai/analyze
//
// {reportId} 分析已有报告(业务页从报告列表拿到 ID);
// {module}   现场生成对应模块快照报告再分析:
//   - capture  = 当前抓包会话(会话无数据 → 409)
//   - monitor  = SNMP 设备监控最新快照
//   - collect  = 节点采集最新快照(含最近告警事件)
//   - scan/weakpass = 最近 10 分钟内自动存档的扫描报告(报告异步落库,
//     10 分钟窗口覆盖"扫描刚结束点按钮"的间隙)
//
// 分析结果回写报告 AI 三字段(aiNote/aiData/aiAnalyzedAt) —— 报告中心
// 随即同时展示原始数据与 AI 研判。
func handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ReportID string `json:"reportId"`
		Module   string `json:"module"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	cfg := ai.CurrentConfig()
	if !cfg.Enabled {
		jsonErr(w, http.StatusServiceUnavailable, "AI 未启用(请在 AI 配置页测试并保存)")
		return
	}
	d := v2DB()
	if d == nil || d.RawReports() == nil {
		jsonErr(w, http.StatusServiceUnavailable, "数据表不可用")
		return
	}

	var rr *report.RawReport
	switch {
	case req.ReportID != "":
		got, err := d.RawReports().Get(req.ReportID)
		if err != nil {
			jsonErr(w, http.StatusNotFound, "报告不存在")
			return
		}
		rr = got
	case req.Module != "":
		var err error
		rr, err = freshRawReport(d, req.Module, currentUser())
		if err != nil {
			jsonErr(w, http.StatusConflict, err.Error())
			return
		}
		if err := saveRawReport(d, rr); err != nil {
			jsonErr(w, http.StatusInternalServerError, "报告存档失败: "+err.Error())
			return
		}
	default:
		jsonErr(w, http.StatusBadRequest, "需指定 reportId 或 module")
		return
	}

	// 模块开关二次校验(按钮已置灰, 这里是 API 级双保险)
	if key, ok := ai.TplKeyForModule(rr.Module); ok && !cfg.ModuleEnabled(key) {
		jsonErr(w, http.StatusServiceUnavailable, "该模块的 AI 分析已被管理员关闭")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	res, err := ai.Analyze(ctx, ai.Input{
		Module:  rr.Module,
		Payload: rr.Payload,
		Assets:  rr.Assets,
		Summary: rr.Summary,
		Target:  strings.TrimSpace(rr.Title + " " + rr.Target),
	})
	if err != nil {
		// LLM 失败不写报告(半截结果落库比没有更糟 —— 用户会当结论看)
		jsonErr(w, http.StatusBadGateway, "AI 分析失败: "+err.Error())
		return
	}

	now := time.Now()
	rr.AIAnalyzedAt = &now
	rr.AINote = res.Note
	rr.AIData = res.AIData
	if _, err := d.RawReports().Upsert(rr); err != nil {
		jsonErr(w, http.StatusInternalServerError, "分析完成但回写报告失败: "+err.Error())
		return
	}
	jsonOK(w, map[string]any{
		"reportId":     rr.ID,
		"module":       rr.Module,
		"aiNote":       res.Note,
		"aiData":       res.AIData,
		"aiAnalyzedAt": now,
		"model":        res.Model,
		"template":     res.Template,
		"ragHits":      res.RAGHits,
		"memoryItems":  res.MemoryItems,
		"elapsedMs":    res.ElapsedMs,
	})
}

// freshRawReport 按模块现场生成一份原始报告(capture 需会话有数据,
// scan/weakpass 需近期已存档)。
func freshRawReport(d *db.Database, module string, operator string) (*report.RawReport, error) {
	switch module {
	case report.RawModCapture:
		rr := buildRawCaptureReport()
		if rr == nil {
			return nil, errors.New("当前没有可分析的抓包数据(请先开始抓包并产生报文)")
		}
		return rr, nil
	case report.RawModMonitor:
		rr := buildRawMonitorReport(operator)
		if rr == nil {
			return nil, errors.New("当前没有可分析的监控数据(未配置设备/节点)")
		}
		return rr, nil
	case "collect":
		rr := buildRawCollectReport(operator)
		if rr == nil {
			return nil, errors.New("当前没有可分析的节点采集数据")
		}
		return rr, nil
	case report.RawModScan, report.RawModWeakPass:
		rr, err := latestRawReportWithin(d, module, 10*time.Minute)
		if err != nil || rr == nil {
			name := "扫描"
			if module == report.RawModWeakPass {
				name = "弱口令"
			}
			return nil, fmt.Errorf("最近 10 分钟内没有 %s 报告(任务可能尚未结束, 结束后报告会自动存档)", name)
		}
		return rr, nil
	default:
		return nil, errors.New("不支持的模块(可选: capture / monitor / collect / scan / weakpass)")
	}
}

// latestRawReportWithin 取某模块最近 window 内最新的一份报告。
func latestRawReportWithin(d *db.Database, module string, window time.Duration) (*report.RawReport, error) {
	all, err := d.RawReports().List()
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-window)
	var best *report.RawReport
	for _, r := range all {
		if r == nil || r.Module != module || r.CreatedAt.Before(cutoff) {
			continue
		}
		if best == nil || r.CreatedAt.After(best.CreatedAt) {
			best = r
		}
	}
	return best, nil
}

// RegisterAIRoutes 阶段 3 AI 模块路由(装配层唯一入口)。
func RegisterAIRoutes(mux *http.ServeMux) {
	// GET /api/ai 保留旧路径(经典页/业务页徽标依赖), 升级为完整状态;
	// POST /api/ai 保留经典页抓包摘要分析旧流程(handleAI, Vue 页不再使用)
	mux.HandleFunc("GET /api/ai", requireAuth(handleAIStatus))
	mux.HandleFunc("POST /api/ai", requireAuth(handleAI))
	mux.HandleFunc("POST /api/ai/config", requireAuth(adminOrOperator(handleAIConfigSave)))
	mux.HandleFunc("POST /api/ai/test", requireAuth(adminOrOperator(handleAITest)))
	mux.HandleFunc("GET /api/ai/templates", requireAuth(handleAITemplates))
	mux.HandleFunc("POST /api/ai/templates", requireAuth(adminOrOperator(handleAITemplateSave)))
	mux.HandleFunc("POST /api/ai/templates/reset", requireAuth(adminOrOperator(handleAITemplateReset)))
	mux.HandleFunc("GET /api/ai/rag", requireAuth(handleAIRAG))
	mux.HandleFunc("POST /api/ai/rag/config", requireAuth(adminOrOperator(handleAIRAGConfig)))
	mux.HandleFunc("POST /api/ai/rag/docs", requireAuth(adminOrOperator(handleAIRAGDocUpload)))
	mux.HandleFunc("POST /api/ai/rag/docs/{id}/toggle", requireAuth(adminOrOperator(handleAIRAGDocToggle)))
	mux.HandleFunc("DELETE /api/ai/rag/docs/{id}", requireAuth(adminOrOperator(handleAIRAGDocDelete)))
	mux.HandleFunc("GET /api/ai/rag/search", requireAuth(handleAIRAGSearch))
	mux.HandleFunc("GET /api/ai/memory", requireAuth(handleAIMemory))
	mux.HandleFunc("POST /api/ai/memory", requireAuth(adminOrOperator(handleAIMemorySave)))
	mux.HandleFunc("POST /api/ai/analyze", requireAuth(adminOrOperator(handleAIAnalyze)))
}

// InitAI 启动装配(在 main 里 db 打开后调用):
// 1) 注入 ai 包的配置读取器(settings 的 ai 节);
// 2) 注入结构化记忆数据源(v2DB);
// 3) 构建 RAG 索引。
func InitAI() {
	ai.SetConfigReader(func() ([]byte, bool) { return section(secAI, "") })
	ai.SetMemoryStore(func() ai.MemoryStore { return aiMemoryStore{} })
	loadRAGIndex()
	// 自愈: 启用 embedding 但语料缺向量(首次启用/换模型/上次补全未完成)→
	// 后台补全(不阻塞启动)。已全量向量化时 needsVectorization 快速短路。
	if cfg := ai.CurrentConfig(); cfg.Embedding.Enabled && needsVectorization(cfg) {
		vectorizeAllAsync(cfg)
	}
}
