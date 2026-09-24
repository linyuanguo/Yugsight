// rag.go RAG 非结构化知识库(文档库): 分片 + 向量化 + 检索。
//
// 【向量引擎选型】纯标准库硬约束下不引外部 embedding 服务/第三方库,
// 用**内置 TF-IDF 向量引擎**(纯 Go 实现, 离线可用):
//
//   - 分片: 文档按段落→句子切分为 ~chunkSize 字符的分片;
//   - 向量化: 每个分片存 TF(词频)向量; IDF 在查询时按当前语料计算
//     (延迟计算 = 增删文档无需全量重算, 且向量存储与语料规模解耦);
//   - 检索: 查询向量与分片向量的余弦相似度取 TopK。
//
// 分词口径(无第三方中文分词库): ASCII 连续字母数字串为一个词(小写化),
// 中文按**二字滑窗(bigram)** 切分 —— 安全文档的关键词(如"未授权""端口
// 开放")在 bigram 下仍有足够区分度; 单字中文词退化为单字。
//
// 与结构化记忆库的区分(页面口径): RAG 存的是**用户上传的文档**
// (安全基线/漏洞手册/设备资料/运维文档), 数据在 ai_docs 表;
// 记忆库读的是**平台业务落库的结构化历史**, 不额外存储。
package ai

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Chunk 一个文档分片(正文 + TF 词频向量 + 可选嵌入向量)。
//
// 双向量并存: TF(内置, 恒在, 供关键词检索降级)与 Vec(外部 embedding,
// 启用时计算落库)。Vec 空 = 该分片未向量化(关键词模式)。
type Chunk struct {
	Text string         `json:"text"`
	TF   map[string]int `json:"tf,omitempty"`
	Vec  []float64      `json:"vec,omitempty"` // 嵌入向量(启用 embedding 时落库; 空=关键词模式)
}

// Doc 一篇知识库文档(分片后的向量索引; 不存全文 —— 分片即全文切片,
// 存全文会让 JSONL 体积翻倍)。
//
// 向量指纹 EmbKey: 记录"用哪个模型+哪个维度算的向量"。换 embedding 模型
// 或维度后旧向量即失效(维度/空间不一致, 余弦相似度无意义), 指纹不匹配时
// 整体重算 —— 否则会用错向量得出错误的"语义命中"(与空结果误读同级危险)。
type Doc struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Category  string  `json:"category"` // 安全基线/漏洞手册/设备资料/运维文档/其它
	Enabled   bool    `json:"enabled"`
	CreatedAt int64   `json:"createdAt"` // unix 毫秒(与实体序列化解耦, db 层转 time)
	Size      int     `json:"size"`     // 原文字节数
	EmbKey    string  `json:"embKey,omitempty"` // 向量指纹(模型:维度); 空=未向量化
	Chunks    []Chunk `json:"chunks"`
}

// CategoryList 文档分类(上传时选择, 展示分组用)。
var CategoryList = []string{"安全基线", "漏洞手册", "设备资料", "运维文档", "其它"}

// NewDocID 文档唯一 ID(与 report.NewRawReportID 同口径: 前缀 + 纳秒 + 随机)。
func NewDocID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("aidoc-%d-%s", time.Now().UnixNano(), hex.EncodeToString(b))
}

// EntityID / Validate 满足 db 泛型表的 Entity 约定(db 包靠鸭子类型接入,
// ai 不 import db)。
func (d *Doc) EntityID() string {
	if d.ID == "" {
		d.ID = NewDocID()
	}
	return d.ID
}

func (d *Doc) Validate() error {
	d.Name = strings.TrimSpace(d.Name)
	if d.Name == "" {
		return errors.New("文档缺少名称")
	}
	if len(d.Chunks) == 0 {
		return errors.New("文档正文为空(无可分片文本)")
	}
	if d.Category == "" {
		d.Category = "其它"
	}
	if d.CreatedAt == 0 {
		d.CreatedAt = time.Now().UnixMilli()
	}
	return nil
}

// Hit 一条检索结果。
type Hit struct {
	DocID   string  `json:"docId"`
	DocName string  `json:"docName"`
	Category string `json:"category,omitempty"`
	Score   float64 `json:"score"`
	Text    string  `json:"text"`
}

// Index 内存向量索引(由装配层从 db 加载; 只读检索 + 增删改后重载)。
//
// 为什么不持久化"最终向量": TF-IDF 的 IDF 分量依赖整个语料,
// 增删一篇文档后所有向量的 IDF 都变。存 TF、查询时算 IDF 是标准的
// 轻量做法, 也避免"文档一变动就全量重算重存"的写放大。
type Index struct {
	docs []*Doc
}

// NewIndex 用文档列表构建索引(装配层在列表变化后调用)。
func NewIndex(docs []*Doc) *Index {
	return &Index{docs: docs}
}

// Docs 当前索引的文档(浅引用, 调用方只读)。
func (ix *Index) Docs() []*Doc { return ix.docs }

// Count 启用文档数。
func (ix *Index) Count() int {
	n := 0
	for _, d := range ix.docs {
		if d.Enabled {
			n++
		}
	}
	return n
}

// Search 在启用文档里检索 TopK 分片(按相似度降序)。
// 语料为空/查询无有效词时返回 nil(调用方按"无参考"处理)。
func (ix *Index) Search(query string, topK int) []Hit {
	if topK <= 0 {
		topK = defTopK
	}
	qtf := termFreqs(tokenize(query))
	if len(qtf) == 0 {
		return nil
	}
	// 语料 = 全部启用文档的启用分片
	type chunkRef struct {
		doc  *Doc
		chun *Chunk
	}
	var refs []chunkRef
	n := 0
	for _, d := range ix.docs {
		if !d.Enabled {
			continue
		}
		for i := range d.Chunks {
			if len(d.Chunks[i].TF) == 0 {
				continue
			}
			refs = append(refs, chunkRef{doc: d, chun: &d.Chunks[i]})
			n++
		}
	}
	if n == 0 {
		return nil
	}
	// df: 词出现在多少个分片里(分片级, 与向量粒度一致)
	df := make(map[string]int)
	for _, r := range refs {
		for t := range r.chun.TF {
			df[t]++
		}
	}
	idf := func(t string) float64 { return idfValue(n, df[t]) }
	// 查询向量 (tf*idf) 及其模长
	qv := make(map[string]float64, len(qtf))
	qnorm := 0.0
	for t, c := range qtf {
		w := float64(c) * idf(t)
		qv[t] = w
		qnorm += w * w
	}
	qnorm = math.Sqrt(qnorm)
	if qnorm == 0 {
		return nil
	}
	type scored struct {
		r     chunkRef
		score float64
	}
	var out []scored
	for _, r := range refs {
		// 分片向量模长(只累加本分片的词, idf 同查询口径)
		cnorm := 0.0
		for t, c := range r.chun.TF {
			w := float64(c) * idf(t)
			cnorm += w * w
		}
		cnorm = math.Sqrt(cnorm)
		if cnorm == 0 {
			continue
		}
		dot := 0.0
		for t, w := range qv {
			if c, ok := r.chun.TF[t]; ok {
				dot += w * float64(c) * idf(t)
			}
		}
		if dot <= 0 {
			continue
		}
		out = append(out, scored{r: r, score: dot / (qnorm * cnorm)})
	}
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].score > out[j].score })
	if len(out) > topK {
		out = out[:topK]
	}
	hits := make([]Hit, 0, len(out))
	for _, s := range out {
		hits = append(hits, Hit{
			DocID:    s.r.doc.ID,
			DocName:  s.r.doc.Name,
			Category: s.r.doc.Category,
			Score:    s.score,
			Text:     s.r.chun.Text,
		})
	}
	return hits
}

func idfValue(nChunks, d int) float64 {
	// 平滑 IDF: ln(1 + (N-df+0.5)/(df+0.5)), 恒正且 df 越大越小;
	// 词只出现在一个分片时值最大(越"稀有"的关键词区分度越高)
	v := float64(nChunks-d+1)/float64(d+1)
	if v < 0 {
		v = 0
	}
	return math.Log(1 + v)
}

// ===== 向量检索(启用 embedding 时; 降级链由 Retriever 编排, 见 rag_pipeline.go) =====

// SearchVector 向量模式初筛: 查询向量与分片向量余弦相似度, 取 candidates 条。
//
// 只参与"已向量化且与查询同维"的分片; 维度不一致(换模型未重算)或无向量的
// 分片跳过 —— 由 Retriever 在向量结果为空时降级关键词检索兜底(不静默丢文档)。
func (ix *Index) SearchVector(qv []float64, candidates int) []Hit {
	if len(qv) == 0 || candidates <= 0 {
		return nil
	}
	type scored struct {
		doc   *Doc
		chun  *Chunk
		score float64
	}
	var out []scored
	for _, d := range ix.docs {
		if !d.Enabled {
			continue
		}
		for i := range d.Chunks {
			v := d.Chunks[i].Vec
			if len(v) != len(qv) {
				continue // 维度不一致(换模型未重算) → 该分片不参与向量检索
			}
			s := cosine(qv, v)
			if s <= 0 {
				continue
			}
			out = append(out, scored{doc: d, chun: &d.Chunks[i], score: s})
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].score > out[j].score })
	if len(out) > candidates {
		out = out[:candidates]
	}
	hits := make([]Hit, 0, len(out))
	for _, s := range out {
		hits = append(hits, Hit{
			DocID: s.doc.ID, DocName: s.doc.Name, Category: s.doc.Category,
			Score: s.score, Text: s.chun.Text,
		})
	}
	return hits
}

// cosine 余弦相似度(维度不一致或零向量返回 0)。
func cosine(a, b []float64) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// EmbeddingKey 向量指纹(模型 + 维度): 两者任一变化, 旧向量即失效需重算。
// 与 Chunk.Vec 落库的 Doc.EmbKey 比对, 决定是否补算。
func EmbeddingKey(c EmbeddingConfig) string {
	return c.Model + ":" + strconv.Itoa(c.Dimension)
}

// ===== 分片 =====

// ChunkText 把文档正文切分为分片(每片约 size 字符, 上限 maxChunks)。
//
// 切分策略: 段落(\n)优先 —— 段落是文档语义的最小完整单位; 单段超限时
// 按句子(。！？!?;；)再切; 单句仍超限才硬切。保证: 不丢字、顺序不变、
// 分片间不重叠(重叠窗口对 TF-IDF 无收益, 还徒增存储)。
func ChunkText(s string, size, maxChunks int) []string {
	if size <= 0 {
		size = defChunkSize
	}
	if maxChunks <= 0 {
		maxChunks = defMaxChunks
	}
	var parts []string
	flush := func(piece string) {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			return
		}
		if len(parts) >= maxChunks {
			return // 超上限的分片丢弃(上限保护, 不是静默截断——Size 记录原文)
		}
		// 单段超限 → 句子切(按字符数与 size 比较, 中文 3 字节/字不能混用字节)
		for charLen(piece) > size {
			cut := size
			if i := findSentenceCut(piece, size); i > 0 {
				cut = i
			}
			parts = append(parts, strings.TrimSpace(piece[:cut]))
			piece = piece[cut:]
			if len(parts) >= maxChunks {
				return
			}
		}
		if strings.TrimSpace(piece) != "" {
			parts = append(parts, piece)
		}
	}
	for _, para := range strings.Split(s, "\n") {
		if len(parts) >= maxChunks {
			break
		}
		// 段落内已有累积时尝试合并(小段落拼到接近 size 再输出)
		if i := len(parts) - 1; i >= 0 && parts[i] != "" && charLen(parts[i])+charLen(para)+1 <= size {
			parts[i] += "\n" + para
		} else {
			flush(para)
		}
	}
	return parts
}

// charLen 字符数(rune 数), 与 findSentenceCut 的字符口径一致。
func charLen(s string) int { return utf8.RuneCountInString(s) }

// findSentenceCut 在 s 前 size **字符**范围内找最后一个句子边界
// (返回可切字节位置)。
//
// 注意: size 是字符数(与 ChunkText 的 charLen 口径一致), 但中文 3 字节/字,
// 边界位置必须按字节返回(用于 s[:cut] 切片)。按字节比较 size 会让中文
// 场景的"窗口"缩水到 1/3 —— 每句都成了"一整片"。
func findSentenceCut(s string, size int) int {
	pos := 0 // 已消耗字节数(边界位置)
	chars := 0
	last := 0
	for _, r := range s {
		pos += len(string(r))
		chars++
		if chars > size {
			break
		}
		if r == '.' || r == '!' || r == '?' || r == '。' || r == '！' || r == '？' || r == '；' || r == ';' || r == '\n' {
			last = pos
		}
	}
	if last == 0 || last < pos/2 {
		return 0 // 没有像样的句子边界, 交回硬切
	}
	return last
}

// ===== 分词与 TF =====

// tokenize 分词: ASCII 词(连续字母数字及 . _ : / - 等, 小写化, 长度≥2)
// + 中文按**连续 CJK 串**处理: 单字串 → 单字词, 多字串 → bigram 滑窗。
// (按 run 处理而不是逐字回退: 逐字回退会让"安全"输出 bigram"安全"后又
// 输出单字"全", 词表被污染。)
func tokenize(s string) []string {
	var out []string
	var ascii []rune
	var cjkRun []rune
	flushASCII := func() {
		if len(ascii) >= 2 {
			out = append(out, strings.ToLower(string(ascii)))
		}
		ascii = ascii[:0]
	}
	flushCJK := func() {
		if len(cjkRun) == 1 {
			out = append(out, string(cjkRun[0]))
		}
		for i := 0; i+1 < len(cjkRun); i++ {
			out = append(out, string(cjkRun[i])+string(cjkRun[i+1]))
		}
		cjkRun = cjkRun[:0]
	}
	for _, r := range s {
		switch {
		case isCJK(r):
			flushASCII()
			cjkRun = append(cjkRun, r)
		case isASCIIWordChar(r):
			flushCJK()
			ascii = append(ascii, r)
		default:
			flushASCII()
			flushCJK()
		}
	}
	flushASCII()
	flushCJK()
	return out
}

// isCJK 常用汉字区(含扩展 A)。
func isCJK(r rune) bool {
	return (r >= 0x4E00 && r <= 0x9FFF) || (r >= 0x3400 && r <= 0x4DBF)
}

// isASCIIWordChar ASCII 词字符(字母/数字/常见标识符符号)。
func isASCIIWordChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '_' || r == '-' || r == '.' || r == '/' || r == ':' || r == '#'
}

// termFreqs 词频统计。
func termFreqs(terms []string) map[string]int {
	m := make(map[string]int, len(terms))
	for _, t := range terms {
		m[t]++
	}
	return m
}

// BuildDocIndex 文档正文 → 分片 + TF 向量(上传/重建时调用)。
func BuildDocIndex(content string, chunkSize, maxChunks int) []Chunk {
	chunks := ChunkText(content, chunkSize, maxChunks)
	out := make([]Chunk, 0, len(chunks))
	for _, c := range chunks {
		out = append(out, Chunk{Text: c, TF: termFreqs(tokenize(c))})
	}
	return out
}

// ===== 检索结果格式化(注入 Prompt 用) =====

// FormatHits 把检索结果拼成 Prompt 参考段(带来源标注, 总量超预算截断)。
func FormatHits(hits []Hit, maxChars int) string {
	if maxChars <= 0 {
		maxChars = ragTextMaxChars
	}
	if len(hits) == 0 {
		return ""
	}
	var b strings.Builder
	for i, h := range hits {
		head := h.DocName
		if h.Category != "" {
			head += "(" + h.Category + ")"
		}
		b.WriteString("\n--- 参考文档 " + strconv.Itoa(i+1) + ": " + head + " ---\n")
		t := h.Text
		if len(t) > 1200 {
			t = t[:1200] + "..."
		}
		b.WriteString(t)
		if len(b.String()) > maxChars {
			b.WriteString("\n...(参考内容超出预算, 已截断)")
			break
		}
	}
	return b.String()
}
