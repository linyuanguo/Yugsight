package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ===== 测试替身(离线, 不依赖网络) =====

// fakeEmbedder 恒定返回同一查询向量(向量模式检索测试用)。
type fakeEmbedder struct{ vec []float64 }

func (f fakeEmbedder) Embed(ctx context.Context, texts []string) ([][]float64, error) {
	out := make([][]float64, len(texts))
	for i := range out {
		out[i] = f.vec
	}
	return out, nil
}

// errEmbedder 模拟 embedding 服务不可用(触发关键词降级)。
type errEmbedder struct{}

func (errEmbedder) Embed(ctx context.Context, texts []string) ([][]float64, error) {
	return nil, errors.New("embedding service down")
}

// fakeReranker 按文本内容查表打分(重排测试用)。
type fakeReranker struct{ scores map[string]float64 }

func (f fakeReranker) Rerank(ctx context.Context, query string, docs []string) ([]float64, error) {
	out := make([]float64, len(docs))
	for i, d := range docs {
		out[i] = f.scores[d]
	}
	return out, nil
}

// errReranker 模拟重排服务不可用(触发"保持初筛序"降级)。
type errReranker struct{}

func (errReranker) Rerank(ctx context.Context, query string, docs []string) ([]float64, error) {
	return nil, errors.New("reranker down")
}

func vecDoc(id, name string, vec []float64) *Doc {
	return &Doc{
		ID: id, Name: name, Enabled: true,
		Chunks: []Chunk{{Text: name + " 内容片段", TF: map[string]int{"x": 1}, Vec: vec}},
	}
}

// ===== 三段式检索 + 降级链 =====

// TestRetrieverVectorMode 向量模式: 查询向量与分片向量余弦排序, topK 截断。
func TestRetrieverVectorMode(t *testing.T) {
	docs := []*Doc{
		vecDoc("a", "Alpha", []float64{1, 0, 0}),
		vecDoc("b", "Beta", []float64{0, 1, 0}),
		vecDoc("c", "Gamma", []float64{0.9, 0.1, 0}),
	}
	rt := NewRetriever(NewIndex(docs))
	rt.SetEmbedder(fakeEmbedder{vec: []float64{1, 0, 0}})
	hits := rt.Search(context.Background(), "任意查询", 2)
	if rt.Mode() != "vector" {
		t.Fatalf("应为向量模式: %s", rt.Mode())
	}
	if len(hits) != 2 || hits[0].DocID != "a" || hits[1].DocID != "c" {
		t.Fatalf("向量排序错: %+v", hits)
	}
	// 分数应降序
	if hits[0].Score < hits[1].Score {
		t.Fatalf("分数非降序: %+v", hits)
	}
}

// TestRetrieverKeywordFallback 未启用 embedding → 内置 TF-IDF 关键词。
func TestRetrieverKeywordFallback(t *testing.T) {
	docs := []*Doc{docFor(t, "d1", "Redis 手册", "Redis 未授权访问漏洞: 6379 端口开放且无密码。", true)}
	rt := NewRetriever(NewIndex(docs))
	hits := rt.Search(context.Background(), "Redis 未授权访问 6379", 3)
	if rt.Mode() != "keyword" {
		t.Fatalf("无 embedding 应为关键词模式: %s", rt.Mode())
	}
	if len(hits) == 0 || hits[0].DocID != "d1" {
		t.Fatalf("关键词命中错: %+v", hits)
	}
}

// TestRetrieverVectorDegradeToKeyword embedding 启用但文档未向量化(无 Vec)
// → 向量无结果 → 自动降级关键词(不静默丢文档)。
func TestRetrieverVectorDegradeToKeyword(t *testing.T) {
	docs := []*Doc{docFor(t, "d1", "Redis 手册", "Redis 未授权访问漏洞: 6379 端口开放。", true)}
	rt := NewRetriever(NewIndex(docs))
	rt.SetEmbedder(fakeEmbedder{vec: []float64{1, 0, 0}}) // 查询有向量, 文档无
	hits := rt.Search(context.Background(), "Redis 未授权访问 6379", 3)
	if rt.Mode() != "keyword" {
		t.Fatalf("文档无向量应降级关键词: %s", rt.Mode())
	}
	if len(hits) == 0 || hits[0].DocID != "d1" {
		t.Fatalf("降级后应命中: %+v", hits)
	}
}

// TestRetrieverEmbedErrorDegrade embedding 调用失败 → 降级关键词(不阻断)。
func TestRetrieverEmbedErrorDegrade(t *testing.T) {
	docs := []*Doc{docFor(t, "d1", "Redis 手册", "Redis 未授权访问漏洞: 6379 端口开放。", true)}
	rt := NewRetriever(NewIndex(docs))
	rt.SetEmbedder(errEmbedder{})
	hits := rt.Search(context.Background(), "Redis 未授权访问 6379", 3)
	if rt.Mode() != "keyword" {
		t.Fatalf("embedding 失败应降级关键词: %s", rt.Mode())
	}
	if len(hits) == 0 {
		t.Fatal("降级后应有结果")
	}
}

// TestRetrieverDimMismatchDegrade 维度不一致(换模型未重算)→ 该分片不参与
// 向量检索 → 降级关键词(绝不用错维度的向量算余弦)。
func TestRetrieverDimMismatchDegrade(t *testing.T) {
	docs := []*Doc{{
		ID: "d1", Name: "n", Enabled: true,
		Chunks: []Chunk{{Text: "Redis 未授权访问 6379", TF: map[string]int{"redis": 1}, Vec: []float64{1, 0}}},
	}}
	rt := NewRetriever(NewIndex(docs))
	rt.SetEmbedder(fakeEmbedder{vec: []float64{1, 0, 0}}) // 3 维 vs 文档 2 维
	hits := rt.Search(context.Background(), "Redis 未授权访问 6379", 3)
	if rt.Mode() != "keyword" {
		t.Fatalf("维度不符应降级: %s", rt.Mode())
	}
	if len(hits) == 0 {
		t.Fatalf("降级后应命中: %+v", hits)
	}
}

// TestRetrieverRerank 重排: 初筛序与最终序可不同(重排按相关性重打分)。
func TestRetrieverRerank(t *testing.T) {
	docs := []*Doc{
		vecDoc("a", "A", []float64{1, 0, 0}),
		vecDoc("b", "B", []float64{0.5, 0.5, 0}),
		vecDoc("c", "C", []float64{0.1, 0.1, 0}),
	}
	rt := NewRetriever(NewIndex(docs))
	rt.SetEmbedder(fakeEmbedder{vec: []float64{1, 0, 0}})
	// reranker 认为 C 最相关(覆盖初筛余弦序)
	rt.SetReranker(fakeReranker{scores: map[string]float64{"C 内容片段": 1.0, "B 内容片段": 0.5, "A 内容片段": 0.1}})
	hits := rt.Search(context.Background(), "q", 3)
	if len(hits) != 3 || hits[0].DocID != "c" {
		t.Fatalf("重排后 c 应第一: %+v", hits)
	}
}

// TestRetrieverRerankFailDegrade 重排失败 → 保持初筛序(不阻断, 规则 4)。
func TestRetrieverRerankFailDegrade(t *testing.T) {
	docs := []*Doc{
		vecDoc("a", "A", []float64{1, 0, 0}),
		vecDoc("b", "B", []float64{0.1, 0.1, 0}),
	}
	rt := NewRetriever(NewIndex(docs))
	rt.SetEmbedder(fakeEmbedder{vec: []float64{1, 0, 0}})
	rt.SetReranker(errReranker{})
	hits := rt.Search(context.Background(), "q", 3)
	if len(hits) == 0 || hits[0].DocID != "a" {
		t.Fatalf("重排失败应保持初筛序(a 第一): %+v", hits)
	}
}

// TestRetrieverNil 空检索器/空索引不 panic。
func TestRetrieverNil(t *testing.T) {
	var rt *Retriever
	if hits := rt.Search(context.Background(), "q", 3); len(hits) != 0 {
		t.Fatalf("nil 检索器应空: %+v", hits)
	}
	if NewRetriever(nil).Search(context.Background(), "q", 3) != nil {
		t.Fatal("nil 索引应空")
	}
}

// ===== 向量指纹 =====

func TestEmbeddingKey(t *testing.T) {
	k1 := EmbeddingKey(EmbeddingConfig{Model: "bge-m3", Dimension: 1024})
	k2 := EmbeddingKey(EmbeddingConfig{Model: "bge-m3", Dimension: 768})
	k3 := EmbeddingKey(EmbeddingConfig{Model: "other", Dimension: 1024})
	if k1 == k2 || k1 == k3 || k2 == k3 {
		t.Fatalf("指纹应区分模型/维度: %s %s %s", k1, k2, k3)
	}
}

// ===== 配置收敛(settings.json 的 ai 节) =====

// TestConfigEmbeddingRerankerDefaults 默认全关 + 数值默认(规则 5 默认关)。
func TestConfigEmbeddingRerankerDefaults(t *testing.T) {
	cfg := LoadConfig(nil)
	if cfg.Embedding.Enabled || cfg.Reranker.Enabled {
		t.Fatal("embedding/reranker 默认必须关")
	}
	if cfg.Embedding.BatchSize != defEmbBatch || cfg.Embedding.Dimension != defEmbDim || cfg.Embedding.TimeoutSec != defEmbTimeout {
		t.Fatalf("embedding 默认漂移: %+v", cfg.Embedding)
	}
	if cfg.Reranker.TopN != defRerankTopN || cfg.Reranker.TimeoutSec != defRerankTimeout {
		t.Fatalf("reranker 默认漂移: %+v", cfg.Reranker)
	}
}

// TestConfigEmbeddingRerankerOverride 显式覆盖 + 未写字段保持默认(合并语义)。
func TestConfigEmbeddingRerankerOverride(t *testing.T) {
	raw := []byte(`{"embedding":{"enabled":true,"apiBase":"http://x/v1","model":"bge-m3","batchSize":8,"dimension":768},
		"reranker":{"enabled":true,"model":"bge-reranker-v2-m3","topN":10}}`)
	cfg := LoadConfig(raw)
	if !cfg.Embedding.Enabled || cfg.Embedding.Model != "bge-m3" || cfg.Embedding.BatchSize != 8 || cfg.Embedding.Dimension != 768 {
		t.Fatalf("embedding 覆盖错: %+v", cfg.Embedding)
	}
	if !cfg.Reranker.Enabled || cfg.Reranker.Model != "bge-reranker-v2-m3" || cfg.Reranker.TopN != 10 {
		t.Fatalf("reranker 覆盖错: %+v", cfg.Reranker)
	}
	// 未写的数值字段保持默认(不被 0 覆盖)
	if cfg.Embedding.TimeoutSec != defEmbTimeout || cfg.Reranker.TimeoutSec != defRerankTimeout {
		t.Fatalf("未写超时应保持默认: emb=%+v rr=%+v", cfg.Embedding, cfg.Reranker)
	}
}

// ===== OpenAI 兼容客户端(httptest 模拟服务端) =====

// TestOpenAIEmbedder 批量 + 按 index 对齐输入顺序。
func TestOpenAIEmbedder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("path: %s", r.URL.Path)
		}
		var req struct {
			Model      string   `json:"model"`
			Input      []string `json:"input"`
			Dimensions int      `json:"dimensions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("解码请求: %v", err)
		}
		if req.Dimensions != 4 {
			t.Errorf("dimensions 未透传: %d", req.Dimensions)
		}
		// 向量按内容决定(与批次无关), 便于断言"全局顺序正确"
		vecFor := map[string][]float64{
			"a": {1, 0, 0, 0}, "b": {0, 2, 0, 0}, "c": {0, 0, 3, 0},
		}
		data := make([]map[string]any, 0, len(req.Input))
		for i, s := range req.Input {
			data = append(data, map[string]any{"index": i, "embedding": vecFor[s]})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer srv.Close()
	// batchSize=2 → "a","b" 一批, "c" 一批; 断言跨批次的全局顺序与内容对齐
	emb := NewOpenAIEmbedder(EmbeddingConfig{APIBase: srv.URL + "/v1", Model: "m", BatchSize: 2, Dimension: 4})
	vecs, err := emb.Embed(context.Background(), []string{"a", "b", "c"})
	if err != nil || len(vecs) != 3 {
		t.Fatalf("embed: %v (n=%d)", err, len(vecs))
	}
	if vecs[0][0] != 1 || vecs[1][1] != 2 || vecs[2][2] != 3 {
		t.Fatalf("全局顺序/对齐错: %v", vecs)
	}
}

// TestOpenAIEmbedderError HTTP 4xx → 明确 error(调用方降级)。
func TestOpenAIEmbedderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid model"}`))
	}))
	defer srv.Close()
	emb := NewOpenAIEmbedder(EmbeddingConfig{APIBase: srv.URL + "/v1", Model: "m"})
	if _, err := emb.Embed(context.Background(), []string{"a"}); err == nil {
		t.Fatal("HTTP 400 应报错")
	}
}

// TestOpenAIEmbedderNoBase 未配置地址 → error(不发起请求)。
func TestOpenAIEmbedderNoBase(t *testing.T) {
	emb := NewOpenAIEmbedder(EmbeddingConfig{Model: "m"})
	if _, err := emb.Embed(context.Background(), []string{"a"}); err == nil {
		t.Fatal("未配置地址应报错")
	}
}

// TestOpenAIReranker relevance_score 打分 + index 对齐。
func TestOpenAIReranker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/rerank" {
			t.Errorf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"index": 0, "relevance_score": 0.9},
			{"index": 1, "relevance_score": 0.2},
			{"index": 2, "relevance_score": 0.5},
		}})
	}))
	defer srv.Close()
	rr := NewOpenAIReranker(RerankerConfig{APIBase: srv.URL + "/v1", Model: "m", TopN: 5})
	scores, err := rr.Rerank(context.Background(), "q", []string{"d0", "d1", "d2"})
	if err != nil || len(scores) != 3 {
		t.Fatalf("rerank: %v (n=%d)", err, len(scores))
	}
	if scores[0] != 0.9 || scores[1] != 0.2 || scores[2] != 0.5 {
		t.Fatalf("分数对齐错: %v", scores)
	}
}

// TestOpenAIRerankerScoreFallback 兼容仅返回 score 字段的实现(TEI)。
func TestOpenAIRerankerScoreFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"index": 0, "score": 0.7},
		}})
	}))
	defer srv.Close()
	rr := NewOpenAIReranker(RerankerConfig{APIBase: srv.URL + "/v1", Model: "m", TopN: 1})
	scores, err := rr.Rerank(context.Background(), "q", []string{"d0"})
	if err != nil || scores[0] != 0.7 {
		t.Fatalf("score 兜底错: %v (%v)", scores, err)
	}
}

// TestOpenAIRerankerError HTTP 4xx → error(重排降级保持初筛序)。
func TestOpenAIRerankerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	rr := NewOpenAIReranker(RerankerConfig{APIBase: srv.URL + "/v1", Model: "m", TopN: 5})
	if _, err := rr.Rerank(context.Background(), "q", []string{"d0"}); err == nil {
		t.Fatal("HTTP 500 应报错")
	}
}
