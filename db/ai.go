package db

import (
	"yugsight/ai"
)

// AIDocDAO AI RAG 知识库文档表(阶段 3, 第 19 表: data/ai_docs.jsonl)。
//
// 与 raw_reports 的关系: 互不引用。
//
//	ai_docs     = 用户上传的**非结构化文档**(安全基线/漏洞手册/设备资料/
//	              运维文档)的分片向量索引, 供 Prompt 的 RAG 检索;
//	raw_reports = 业务模块执行后的**结构化结果**(抓包/扫描/监控...),
//	              其 ai 三字段存的是 AI 对"该报告"的研判结果。
//
// 存储口径: 只存分片(TF 向量), 不存全文 —— 分片即全文切片, 存全文
// 会让 JSONL 体积翻倍(见 ai/rag.go 头部说明)。
type AIDocDAO struct {
	*Table[*ai.Doc]
}

func newAITable(path string) (*AIDocDAO, error) {
	t, err := NewTable[*ai.Doc]("ai_docs", path, func() *ai.Doc { return &ai.Doc{} })
	if err != nil {
		return nil, err
	}
	return &AIDocDAO{t}, nil
}
