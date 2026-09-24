package ai

import (
	"strings"
	"testing"
)

// TestTokenize 分词契约: ASCII 词小写化 + 中文 bigram(单字串退化为单字)。
func TestTokenize(t *testing.T) {
	got := tokenize("Redis 未授权访问 port 6379")
	want := []string{"redis", "未授", "授权", "权访", "访问", "port", "6379"}
	if len(got) != len(want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got=%v want=%v", got, want)
		}
	}
	// 单字中文
	if got := tokenize("网"); len(got) != 1 || got[0] != "网" {
		t.Fatalf("单字中文: %v", got)
	}
	// 无有效词
	if got := tokenize("！@# 1"); len(got) != 0 {
		t.Fatalf("纯标点/单字符: %v", got)
	}
}

// TestChunkText 分片契约: 不丢字、顺序不变、小段合并、超限按句子切、
// 上限生效。
func TestChunkText(t *testing.T) {
	// 短段落合并成一片
	parts := ChunkText("第一段\n第二段\n第三段", 200, 10)
	if len(parts) != 1 || !strings.Contains(parts[0], "第一段") || !strings.Contains(parts[0], "第三段") {
		t.Fatalf("短段应合并: %v", parts)
	}
	// 长句按句子边界切(size=50 字符, 中文 3 字节/字 —— 边界按字符算)
	long := strings.Repeat("这是一个测试句子。", 30) // 330 字
	parts = ChunkText(long, 50, 10)
	total := 0
	for _, p := range parts {
		total += len(p)
		if charLen(p) > 50 {
			t.Fatalf("分片超长: %d 字", charLen(p))
		}
	}
	// 不丢字: 分片文本(去空白)之和 == 原文(去空白)
	strip := func(s string) string {
		s = strings.ReplaceAll(s, "\n", "")
		return s
	}
	if total != len(strip(long)) {
		t.Fatalf("丢字: 分片合计 %d, 原文 %d", total, len(strip(long)))
	}
	// 上限
	parts = ChunkText(strings.Repeat("长段\n", 100), 100, 3)
	if len(parts) > 3 {
		t.Fatalf("上限未生效: %d 片", len(parts))
	}
}

func docFor(t *testing.T, id, name, content string, enabled bool) *Doc {
	t.Helper()
	return &Doc{
		ID: id, Name: name, Category: "漏洞手册", Enabled: enabled,
		CreatedAt: 1, Size: len(content),
		Chunks:    BuildDocIndex(content, defChunkSize, defMaxChunks),
	}
}

// TestRAGSearchRelevance 相关性: 含查询独有词的文档排第一; 无关查询
// 不硬凑结果。
func TestRAGSearchRelevance(t *testing.T) {
	docs := []*Doc{
		docFor(t, "d1", "Redis 手册", "Redis 未授权访问漏洞: 6379 端口开放且无密码时, 攻击者可写入 crontab 获取权限。修复: 设置 requirepass 并绑定内网。", true),
		docFor(t, "d2", "Web 基线", "Web 服务器安全基线: 关闭目录遍历, 设置 HSTS 与 CSP 响应头, 禁用默认管理页面。", true),
		docFor(t, "d3", "交换机资料", "锐捷交换机默认账号密码为 admin/admin, 生产环境必须修改并启用 AAA 认证。", true),
	}
	ix := NewIndex(docs)

	hits := ix.Search("Redis 未授权访问 6379", 2)
	if len(hits) == 0 {
		t.Fatal("应命中")
	}
	if hits[0].DocID != "d1" {
		t.Fatalf("第一命中应为 Redis 手册: got=%s score=%v", hits[0].DocID, hits[0].Score)
	}
	// 第二命中不该比第一差太多(排序降序)
	if len(hits) > 1 && hits[1].Score > hits[0].Score {
		t.Fatal("结果未按相似度降序")
	}

	// 交换机查询 → d3 第一
	hits = ix.Search("交换机默认账号密码", 1)
	if len(hits) == 0 || hits[0].DocID != "d3" {
		t.Fatalf("交换机查询命中错: %+v", hits)
	}

	// 完全无关词 → 空(不硬凑)
	if hits := ix.Search("zzqqxxyyww", 3); len(hits) != 0 {
		t.Fatalf("无关词不应命中: %+v", hits)
	}
}

// TestRAGSearchDisabledExcluded 禁用的文档不参与检索(启用/禁用开关的
// 核心语义: 禁用了 = 这篇资料对 AI 不可见)。
func TestRAGSearchDisabledExcluded(t *testing.T) {
	docs := []*Doc{
		docFor(t, "on", "启用文档", "OpenSSH 暴力破解: 应限制来源并启用公钥登录。", true),
		docFor(t, "off", "禁用文档", "OpenSSH 暴力破解: 应限制来源并启用公钥登录。", false),
	}
	ix := NewIndex(docs)
	hits := ix.Search("OpenSSH 暴力破解", 5)
	for _, h := range hits {
		if h.DocID == "off" {
			t.Fatal("禁用文档被检索到了")
		}
	}
	if len(hits) == 0 || hits[0].DocID != "on" {
		t.Fatalf("启用文档应命中: %+v", hits)
	}
}

// TestRAGSearchEmpty 空语料/空索引/空查询 = 空结果(不 panic)。
func TestRAGSearchEmpty(t *testing.T) {
	if hits := NewIndex(nil).Search("任意查询词", 3); len(hits) != 0 {
		t.Fatal("空语料不应命中")
	}
	if hits := NewIndex([]*Doc{docFor(t, "d", "n", "内容", true)}).Search("", 3); len(hits) != 0 {
		t.Fatal("空查询不应命中")
	}
	if hits := NewIndex([]*Doc{docFor(t, "d", "n", "内容", true)}).Search("无关词组", 0); len(hits) != 0 {
		t.Fatal("topK<=0 走默认, 语料无该词时不应命中")
	}
}

// TestFormatHits 参考段格式: 带来源标注, 超预算截断。
func TestFormatHits(t *testing.T) {
	hits := []Hit{
		{DocID: "d1", DocName: "基线", Category: "安全基线", Score: 0.9, Text: "条目一内容"},
		{DocID: "d2", DocName: "手册", Score: 0.5, Text: strings.Repeat("长", 2000)},
	}
	out := FormatHits(hits, 0)
	if !strings.Contains(out, "参考文档 1: 基线(安全基线)") || !strings.Contains(out, "参考文档 2: 手册") {
		t.Fatalf("格式错: %s", out)
	}
	// 小预算: 截断标记
	out = FormatHits(hits, 60)
	if !strings.Contains(out, "已截断") {
		t.Fatalf("小预算应截断: %s", out)
	}
	if FormatHits(nil, 0) != "" {
		t.Fatal("空 hits 应返回空串")
	}
}

// TestDocValidate 实体契约: 名称必填/分片非空/分类与时间缺省补全。
func TestDocValidate(t *testing.T) {
	d := &Doc{Name: "基线", Chunks: []Chunk{{Text: "x", TF: map[string]int{"x": 1}}}}
	if err := d.Validate(); err != nil {
		t.Fatalf("合法文档: %v", err)
	}
	if d.Category != "其它" || d.CreatedAt == 0 {
		t.Fatalf("缺省未补全: %+v", d)
	}
	// ID 由 EntityID 惰性分配(与 RawReport 同口径)
	if d.EntityID() == "" {
		t.Fatal("EntityID 应分配 ID")
	}
	if err := (&Doc{Chunks: []Chunk{{Text: "x", TF: map[string]int{"x": 1}}}}).Validate(); err == nil {
		t.Fatal("缺名称应报错")
	}
	if err := (&Doc{Name: "n"}).Validate(); err == nil {
		t.Fatal("无分片应报错")
	}
}

// TestNewDocIDUnique ID 唯一(同毫秒也不撞)。
func TestNewDocIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewDocID()
		if !strings.HasPrefix(id, "aidoc-") || seen[id] {
			t.Fatalf("ID 异常: %s", id)
		}
		seen[id] = true
	}
}

// TestDocEntityID Entity 契约(空 ID 自动生成, 稳定)。
func TestDocEntityID(t *testing.T) {
	d := &Doc{}
	id1 := d.EntityID()
	if id1 == "" || d.EntityID() != id1 {
		t.Fatalf("EntityID 不稳定: %s / %s", id1, d.EntityID())
	}
}
