// memory.go 结构化记忆库: 从平台数据库的业务历史记录里按时间窗检索,
// 压缩后注入 Prompt 的 {{structured_memory}} 变量。
//
// 与 RAG 文档库的严格区分(页面文案同口径):
//
//	RAG      非结构化文档(用户上传的基线/手册/资料) → 向量检索, 存 ai_docs 表
//	记忆库   平台数据库内**结构化历史**(漏洞/告警/抓包报告/采集指标) →
//	         按保留时长 + 范围勾选只读检索, **不额外存储**(数据源即业务落库)
//
// 数据访问边界: 本包不 import db —— MemoryStore 是接口, 由装配层(main 包)
// 用 v2DB() 各表实现。这样 ai 包可离线单测(假 Store), 也避免"配置包
// 反向依赖数据层"的耦合。
package ai

import (
	"strings"
	"time"
)

// MemoryEntry 一条结构化记忆(某范围的一行历史)。
type MemoryEntry struct {
	At     time.Time `json:"at"`
	Label  string    `json:"label"`          // 单行摘要(压缩模式的正文)
	Detail string    `json:"detail,omitempty"` // 完整内容(非压缩模式拼接在摘要后)
}

// MemoryStore 四个检索范围的实现(装配层注入 v2DB 实现)。
// 各方法自行负责: 保留时长过滤(since) + 排序(新→旧) + 条数上限(limit)。
type MemoryStore interface {
	AssetHistory(since time.Time, limit int) ([]MemoryEntry, error)   // 资产历史扫描记录
	AlertHistory(since time.Time, limit int) ([]MemoryEntry, error)   // 历史告警事件
	CaptureHistory(since time.Time, limit int) ([]MemoryEntry, error) // 历史抓包分析记录
	MetricHistory(since time.Time, limit int) ([]MemoryEntry, error)  // 节点历史指标
}

// Gather 按配置收集结构化记忆, 返回 (注入文本, 总条数)。
//
// 口径:
//   - 记忆库关闭/全范围为空 → "无历史记忆(记忆库未启用/或超出保留时长)";
//   - 压缩模式: 每条形如 "[MM-dd HH:mm] label";
//   - 非压缩模式: 摘要后附 detail(完整内容由装配层给出);
//   - 单范围读失败不阻断整体(该范围缺席, 其余照常 —— 降级不崩);
//   - 总文本超 memoryMaxChars 截断(参考资料不能挤占原始数据预算)。
func Gather(cfg MemoryConfig, now time.Time, store MemoryStore) (string, int) {
	if store == nil || !cfg.Enabled {
		return "无历史记忆(记忆库未启用)", 0
	}
	since := now.AddDate(0, 0, -cfg.RetainDays)
	scopes := []struct {
		label string
		on    bool
		get   func() ([]MemoryEntry, error)
	}{
		{"资产扫描记录", cfg.Scopes.Assets, func() ([]MemoryEntry, error) { return store.AssetHistory(since, cfg.MaxItems) }},
		{"历史告警事件", cfg.Scopes.Alerts, func() ([]MemoryEntry, error) { return store.AlertHistory(since, cfg.MaxItems) }},
		{"抓包分析记录", cfg.Scopes.Captures, func() ([]MemoryEntry, error) { return store.CaptureHistory(since, cfg.MaxItems) }},
		{"节点历史指标", cfg.Scopes.Metrics, func() ([]MemoryEntry, error) { return store.MetricHistory(since, cfg.MaxItems) }},
	}

	var b strings.Builder
	total := 0
	for _, sc := range scopes {
		if !sc.on {
			continue
		}
		items, err := sc.get()
		if err != nil || len(items) == 0 {
			continue
		}
		b.WriteString("\n【" + sc.label + "】\n")
		for _, it := range items {
			line := "[" + it.At.Format("01-02 15:04") + "] " + it.Label
			if !cfg.Compress && it.Detail != "" {
				line += "\n    " + it.Detail
			}
			b.WriteString(line + "\n")
		}
		total += len(items)
	}
	if total == 0 {
		return "无历史记忆(或超出保留时长)", 0
	}
	out := b.String()
	if len(out) > memoryMaxChars {
		out = out[:memoryMaxChars] + "\n...(记忆内容超出预算, 已截断)"
	}
	return out, total
}

// ScopesLabel 已勾选范围的中文标签(配置页/审计展示用)。
func (c MemoryConfig) ScopesLabel() string {
	var names []string
	if c.Scopes.Assets {
		names = append(names, "资产扫描记录")
	}
	if c.Scopes.Alerts {
		names = append(names, "历史告警事件")
	}
	if c.Scopes.Captures {
		names = append(names, "抓包分析记录")
	}
	if c.Scopes.Metrics {
		names = append(names, "节点历史指标")
	}
	return strings.Join(names, ",")
}
