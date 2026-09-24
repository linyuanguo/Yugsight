// rag_pipeline.go RAG 统一检索入口(业务层的唯一依赖 —— 抽象统一接口层)。
//
// 三段式检索(对应任务"文档分片 → 向量化/关键词 → 重排序(可选) → 注入"):
//
//   1. 初筛候选池: embedding 启用且分片有同维向量 → 向量余弦(SearchVector);
//      未启用 / 无向量 / 维度不符 / 向量结果为空 → 降级内置 TF-IDF 关键词(Search);
//   2. 重排序(可选): reranker 启用 → 对候选池重打分排序; 未启用 / 调用失败
//      → 保持初筛顺序(自动降级, 不阻断);
//   3. 截断 topK 返回。
//
// 降级口径(规则 4): 本函数**永不因外部向量/重排服务失败而返回 error** ——
// 外部服务挂了只影响结果质量(退回关键词/初筛序), 绝不阻断 AI 分析主流程。
// 业务层(Analyze)只调 Search, 不感知底层实现与是否降级。
package ai

import (
	"context"
	"fmt"
	"sort"
)

// Retriever RAG 统一检索器(包装索引 + 可选 embedding/reranker)。
type Retriever struct {
	ix   *Index
	emb  Embedder // nil = 关键词模式
	rr   Reranker // nil = 不重排
	mode string   // 最近一次实际初筛模式(vector/keyword), 供 aiData 审计展示
}

// NewRetriever 用索引构建检索器(emb/rr 默认 nil, 按需 Set)。
func NewRetriever(ix *Index) *Retriever {
	return &Retriever{ix: ix}
}

// SetEmbedder 注入向量嵌入实现(nil = 关键词模式)。
func (r *Retriever) SetEmbedder(e Embedder) { r.emb = e }

// SetReranker 注入重排序实现(nil = 不重排)。
func (r *Retriever) SetReranker(rr Reranker) { r.rr = rr }

// Mode 最近一次初筛模式(vector/keyword), 供审计展示; 未检索过 = keyword。
func (r *Retriever) Mode() string {
	if r == nil || r.mode == "" {
		return "keyword"
	}
	return r.mode
}

// Search 执行一次统一检索(三段式 + 内置降级链)。空索引/空语料返回 nil。
func (r *Retriever) Search(ctx context.Context, query string, topK int) []Hit {
	if r == nil || r.ix == nil {
		return nil
	}
	if topK <= 0 {
		topK = defTopK
	}
	// 候选池: 初筛多取若干倍, 给重排序留空间(重排是"重排"不是"扩召回")。
	cand := topK * 4
	if cand < 8 {
		cand = 8
	}

	var pool []Hit
	r.mode = "keyword"
	if r.emb != nil {
		qv, err := r.emb.Embed(ctx, []string{query})
		if err == nil && len(qv) > 0 && len(qv[0]) > 0 {
			if v := r.ix.SearchVector(qv[0], cand); len(v) > 0 {
				pool = v
				r.mode = "vector"
			}
		}
		// err(服务不可用) 或 向量无结果 → 落空到下面的关键词降级
	}
	if len(pool) == 0 {
		pool = r.ix.Search(query, cand) // 内置 TF-IDF 关键词(初筛兼降级)
		r.mode = "keyword"
	}
	if len(pool) == 0 {
		return nil
	}

	// 重排序(可选, 失败降级保持初筛序)
	if r.rr != nil {
		if re, err := r.rerank(ctx, query, pool); err == nil && len(re) > 0 {
			pool = re
		}
	}
	if len(pool) > topK {
		pool = pool[:topK]
	}
	return pool
}

// rerank 调重排服务对候选池重排, 分数覆盖 Hit.Score(0-1 语义, 前端展示)。
func (r *Retriever) rerank(ctx context.Context, query string, pool []Hit) ([]Hit, error) {
	docs := make([]string, len(pool))
	for i, h := range pool {
		docs[i] = h.Text
	}
	scores, err := r.rr.Rerank(ctx, query, docs)
	if err != nil {
		return nil, err
	}
	if len(scores) != len(pool) {
		return nil, fmt.Errorf("reranker 分数(%d)与候选数(%d)不一致", len(scores), len(pool))
	}
	type ordered struct {
		i int
		s float64
	}
	ord := make([]ordered, len(pool))
	for i, s := range scores {
		ord[i] = ordered{i, s}
	}
	sort.SliceStable(ord, func(a, b int) bool { return ord[a].s > ord[b].s })
	out := make([]Hit, len(pool))
	for i, o := range ord {
		h := pool[o.i]
		h.Score = o.s
		out[i] = h
	}
	return out, nil
}
