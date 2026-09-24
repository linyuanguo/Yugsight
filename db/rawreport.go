package db

import (
	"yugsight/report"
)

// RawReportDAO 原始结构化报告表(报告中心二期)。
//
// 与 ReportDAO(渲染报告存档)并存:
//
//	raw_reports  = 业务模块执行完成后的原始结构化结果(抓包/扫描/弱口令/监控/合并);
//	reports      = 从数据库聚合渲染的交付材料(HTML/Word/PDF)。
//
// 数据流是"原始报告 → (三期 AI 分析) → (可选) 渲染报告", 两张表互不引用,
// 合并报告的 SourceIDs 只记录原始报告 ID, 不跨表。
type RawReportDAO struct {
	*Table[*report.RawReport]
}

func newRawReportTable(path string) (*RawReportDAO, error) {
	t, err := NewTable[*report.RawReport]("raw_reports", path, func() *report.RawReport {
		return &report.RawReport{}
	})
	if err != nil {
		return nil, err
	}
	return &RawReportDAO{t}, nil
}

// ReleasePayload 返回剥离正文的副本(列表/统计接口不随响应回传大体量 payload,
// 详情接口才带; 返回副本而非就地改, 避免污染内存缓存)。
func (d *RawReportDAO) ReleasePayload(r *report.RawReport) *report.RawReport {
	if r == nil {
		return nil
	}
	cp := *r
	cp.Payload = nil
	return &cp
}
