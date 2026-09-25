package db

import (
	"time"

	"yugsight/internal/report"
)

// ===== 报告存档表(任务 7.2) =====
//
// 数据契约说明: 存档与模板实体直接复用 report 包的 Archive / Template 类型,
// 而不是在 db 包再定义一遍包装结构。
//
// 为什么这次不复用"实体外包装"模式(对比 Asset/Vuln 的做法):
//
//	Asset/Vuln 的包装是为了挂 ScanTaskID/UpdatedAt 这类"库内元字段";
//	报告存档不需要任何库内元字段(它的字段本身就是业务字段, 见 report.Archive),
//	再包一层只会产生两套字段名(A.Archive.Title 与 A.Title), 装配层来回转换,
//	是纯粹的负担。
//
// 分层方向检查: report 包不 import db(它只依赖 models + 标准库),
// 因此 db -> report 单向依赖不构成循环引用。

// ReportDAO 报告存档 DAO: 基础 CRUD(存档为"出具即定稿", 故不提供 Update 场景
// 变更语义 —— 需要更新请用 Upsert; 但改历史存档内容会让已交付报告与库中不一致,
// 业务层应避免; DAO 层仍保留通用能力)。
type ReportDAO struct {
	*Table[*report.Archive]
}

// newReportTable 打开报告存档表。
func newReportTable(path string) (*ReportDAO, error) {
	t, err := NewTable[*report.Archive]("reports", path, func() *report.Archive { return &report.Archive{} })
	if err != nil {
		return nil, err
	}
	return &ReportDAO{Table: t}, nil
}

// ReleaseContent 清空存档正文(列表/详情响应不回传大字段, 下载接口单独提供)。
//
// 直接修改传入的记录对象: 调用方拿到的是 Table 内部缓存的指针(文件引擎返回
// 的是引用而非副本), 因此本方法会同时清空缓存里的 Content —— 这是不可接受的
// 副作用(下载历史报告会拿到空内容)。
//
// 为规避该风险, 这里改为"仅对调用方可见的副本生效": 返回一份浅拷贝供响应使用。
// 保留本方法名以兼容调用点, 但语义为"返回去掉正文的副本"; 调用方必须使用返回值。
func (d *ReportDAO) ReleaseContent(a *report.Archive) *report.Archive {
	if a == nil {
		return nil
	}
	cp := *a
	cp.Content = ""
	cp.ContentB64 = "" // Word 二进制正文同样不回传(列表/详情不需要, 下载接口单独提供)
	return &cp
}

// MarkStatus 更新存档状态。
func (d *ReportDAO) MarkStatus(id, status string) error {
	a, err := d.Get(id)
	if err != nil {
		return err
	}
	a.Status = status
	return d.Update(a)
}

// Since 按创建时间过滤(>= t)。
func (d *ReportDAO) Since(t time.Time) ([]*report.Archive, error) {
	return d.Query(func(a *report.Archive) bool { return !a.CreatedAt.Before(t) })
}

// ===== 报告模板表 =====

// ReportTemplateDAO 报告模板 DAO(自定义页眉页脚)。
type ReportTemplateDAO struct {
	*Table[*report.Template]
}

// newReportTemplateTable 打开报告模板表。
func newReportTemplateTable(path string) (*ReportTemplateDAO, error) {
	t, err := NewTable[*report.Template]("report_templates", path, func() *report.Template { return &report.Template{} })
	if err != nil {
		return nil, err
	}
	return &ReportTemplateDAO{Table: t}, nil
}
