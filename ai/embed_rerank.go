// embed_rerank.go RAG 向量化与重排序的统一接口层(OpenAI 兼容协议)。
//
// 设计目标(对应任务"接口统一/可选插拔/自动降级"):
//
//   - 抽象统一接口层: Embedder / Reranker 两个接口是业务层的唯一依赖;
//     Retriever(rag_pipeline.go) 只调这两个接口, 不感知底层是远程服务
//     还是本地模型, 也不感知"到底调没调"(降级由 Retriever 决策)。
//   - 接口统一: 两者均走 OpenAI 兼容格式 —— Embedding 用 /embeddings,
//     Reranker 用 /rerank(OpenAI/Jina/Cohere 通用形态), 可对接任意兼容
//     协议的云服务与本地推理服务(vLLM / Ollama / TEI / Xinference)。
//   - 可选插拔: 客户端未启用时根本不会被构造(装配层按配置决定), 不占资源。
//   - 自动降级: 任何调用失败一律返回 error(不 panic), 由 Retriever 捕获
//     后回退关键词检索 / 保持初筛顺序 —— 外部服务挂了不阻断 AI 分析。
//
// 零第三方依赖: 仅标准库 net/http + encoding/json。
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ===== 统一接口层 =====

// Embedder 向量嵌入接口。默认实现 OpenAIEmbedder; 测试/本地模型可替换。
type Embedder interface {
	// Embed 批量文本 → 与输入同序的向量。任一批次失败返回 error(调用方降级)。
	Embed(ctx context.Context, texts []string) ([][]float64, error)
}

// Reranker 重排序接口。默认实现 OpenAIReranker。
type Reranker interface {
	// Rerank 对 (query, docs) 逐条打分, 返回与 docs 同序的相关性分数
	// (越大越相关)。失败返回 error(调用方降级为初筛顺序)。
	Rerank(ctx context.Context, query string, docs []string) ([]float64, error)
}

// endpoint 由 API Base 拼出某端点(剥尾部斜杠)。Base 为空返回空串,
// 由调用方判"未配置"。
func endpoint(base, path string) string {
	b := strings.TrimRight(strings.TrimSpace(base), "/")
	if b == "" {
		return ""
	}
	return b + path
}

// ===== 向量嵌入(OpenAI 兼容 /embeddings) =====

// OpenAIEmbedder OpenAI 兼容的向量嵌入客户端(支持批量 + 指定维度)。
type OpenAIEmbedder struct {
	cfg    EmbeddingConfig
	client *http.Client
}

// NewOpenAIEmbedder 构建嵌入客户端(超时取配置, 0=30s 兜底)。
func NewOpenAIEmbedder(cfg EmbeddingConfig) *OpenAIEmbedder {
	t := time.Duration(cfg.TimeoutSec) * time.Second
	if t <= 0 {
		t = 30 * time.Second
	}
	return &OpenAIEmbedder{cfg: cfg, client: &http.Client{Timeout: t}}
}

// Embed 按 batchSize 分批调用 /embeddings, 拼回与输入同序的全量向量。
// 任一批次失败即整体返回 error —— 调用方(Retriever)据此降级关键词检索,
// 而不是"半截向量参与检索"(部分分片有向量、部分没有会让余弦比较失去一致性)。
func (e *OpenAIEmbedder) Embed(ctx context.Context, texts []string) ([][]float64, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	batch := e.cfg.BatchSize
	if batch <= 0 {
		batch = defEmbBatch
	}
	var out [][]float64
	for start := 0; start < len(texts); start += batch {
		end := start + batch
		if end > len(texts) {
			end = len(texts)
		}
		vecs, err := e.embedBatch(ctx, texts[start:end])
		if err != nil {
			return nil, err
		}
		out = append(out, vecs...)
	}
	return out, nil
}

// embedBatch 单批调用。请求 {model, input, dimensions?}; 响应
// {"data":[{"index":i,"embedding":[...]}]}(按 index 对齐输入顺序)。
func (e *OpenAIEmbedder) embedBatch(ctx context.Context, batch []string) ([][]float64, error) {
	if e.cfg.APIBase == "" {
		return nil, errors.New("embedding 未配置接口地址(apiBase)")
	}
	if e.cfg.Model == "" {
		return nil, errors.New("embedding 未配置模型名称(model)")
	}
	url := endpoint(e.cfg.APIBase, "/embeddings")
	body := map[string]any{"model": e.cfg.Model, "input": batch}
	if e.cfg.Dimension > 0 {
		body["dimensions"] = e.cfg.Dimension
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.cfg.APIKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 embedding 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("embedding HTTP %d (地址 %s): %s", resp.StatusCode, url, strings.TrimSpace(string(msg)))
	}
	var parsed struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("解析 embedding 响应失败: %w", err)
	}
	out := make([][]float64, len(batch))
	for _, d := range parsed.Data {
		if d.Index >= 0 && d.Index < len(batch) {
			out[d.Index] = d.Embedding
		}
	}
	for i, v := range out {
		if v == nil {
			return nil, fmt.Errorf("embedding 缺少第 %d 条向量", i)
		}
	}
	return out, nil
}

// ===== 重排序(OpenAI/Jina 兼容 /rerank) =====

// OpenAIReranker OpenAI/Jina/Cohere 兼容的重排序客户端。
type OpenAIReranker struct {
	cfg    RerankerConfig
	client *http.Client
}

// NewOpenAIReranker 构建重排客户端(超时取配置, 0=30s 兜底)。
func NewOpenAIReranker(cfg RerankerConfig) *OpenAIReranker {
	t := time.Duration(cfg.TimeoutSec) * time.Second
	if t <= 0 {
		t = 30 * time.Second
	}
	return &OpenAIReranker{cfg: cfg, client: &http.Client{Timeout: t}}
}

// Rerank 调用 /rerank 打分。请求 {model, query, documents, top_n};
// 响应兼容两种字段名 {"results":[{"index":i,"relevance_score":s}]} 或
// {"results":[{"index":i,"score":s}]}(Cohere/Jina 用 relevance_score,
// 部分 TEI 用 score)。返回与 docs 同序的分数(缺项=0, 自然排到末尾)。
func (r *OpenAIReranker) Rerank(ctx context.Context, query string, docs []string) ([]float64, error) {
	if len(docs) == 0 {
		return nil, nil
	}
	if r.cfg.APIBase == "" {
		return nil, errors.New("reranker 未配置接口地址(apiBase)")
	}
	if r.cfg.Model == "" {
		return nil, errors.New("reranker 未配置模型名称(model)")
	}
	url := endpoint(r.cfg.APIBase, "/rerank")
	topN := r.cfg.TopN
	if topN <= 0 || topN > len(docs) {
		topN = len(docs)
	}
	body := map[string]any{
		"model":     r.cfg.Model,
		"query":     query,
		"documents": docs,
		"top_n":     topN,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.APIKey)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 reranker 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("reranker HTTP %d (地址 %s): %s", resp.StatusCode, url, strings.TrimSpace(string(msg)))
	}
	var parsed struct {
		Results []struct {
			Index          int     `json:"index"`
			RelevanceScore float64 `json:"relevance_score"`
			Score          float64 `json:"score"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("解析 reranker 响应失败: %w", err)
	}
	out := make([]float64, len(docs))
	for _, res := range parsed.Results {
		if res.Index >= 0 && res.Index < len(docs) {
			s := res.RelevanceScore
			if s == 0 {
				s = res.Score // 兼容仅返回 score 字段的实现
			}
			out[res.Index] = s
		}
	}
	return out, nil
}
