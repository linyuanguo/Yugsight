// data.go 统一报告数据结构 ReportData(二期报告中心)。
//
// 为什么需要这一层:
//
//	报告模板(HTML/Word 两套出口)只该认识"一份数据的形状", 不该认识 Snapshot /
//	SnapshotStats / Header / PackConfig 四个来源。此前渲染要分别取占位符表、
//	统计结构、页眉结构, 新增一个变量要改三处, 模板作者也没有可读的变量清单。
//	ReportData 是模板的唯一入参: 加变量只改这里, 文档与模板同步更新。
//
// 模板可用变量(README 与 build/report_templates/*/config.yaml 注释同源):
//
//	.Title .Subtitle .TaskName .Client .Operator .Tool .GeneratedAtText
//	.Targets .Assets .Vulns .Stats .SevRows .Summary
//	.Logo .Accent .Footer .Cover .Sections
package report

import (
	"fmt"
	"strings"
	"time"

	"yugsight/models"
)

// ReportData 渲染报告所需的全部数据(模板唯一入参)。
type ReportData struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	// TaskName 任务名(报告来自哪次扫描; 手工生成时与 Title 相同)
	TaskName string `json:"taskName,omitempty"`
	// Client 客户名(config.yaml 的 client)
	Client   string `json:"client,omitempty"`
	Operator string `json:"operator,omitempty"`
	Tool     string `json:"tool,omitempty"`

	GeneratedAt     time.Time `json:"generatedAt"`
	GeneratedAtText string    `json:"generatedAtText"`

	// Targets 扫描目标(资产 IP + 任务目标去重, 上限 200 防封面撑爆)
	Targets []string `json:"targets,omitempty"`
	Assets  []*models.Asset `json:"assets,omitempty"`
	Vulns   []*models.Vuln  `json:"vulns,omitempty"`
	// ScansView 扫描范围章节(模板直接 range, 不必再理解 ScanInfo 来源)
	ScansView []ScanInfo `json:"scans,omitempty"`
	// TopoRows 拓扑章节的扁平行(前端画布用节点+边, 报告只需要可读的表格行)
	TopoRows []TopoRow `json:"topoRows,omitempty"`

	Stats    SnapshotStats `json:"stats"`
	SevRows  []SevRow      `json:"sevRows,omitempty"`
	Summary  string        `json:"summary,omitempty"`

	// 品牌与版式(来自模板 config.yaml)
	Logo    string   `json:"logo,omitempty"`
	Accent  string   `json:"accent,omitempty"`
	Footer  string   `json:"footer,omitempty"`
	Cover   bool     `json:"cover"`
	Sections []string `json:"sections,omitempty"`
}

// TopoRow 拓扑表格行(报告里的拓扑章节: 一行一个节点)。
type TopoRow struct {
	Label     string `json:"label"`
	KindName  string `json:"kindName"`
	Addr      string `json:"addr,omitempty"`
	Service   string `json:"service,omitempty"`
	Risk      string `json:"risk"`
	VulnCount int    `json:"vulnCount"`
}

// SevRow 等级分布行(模板画概览条/表用; 比让模板去遍历 map 简单且顺序稳定)。
type SevRow struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// 等级展示名(与前端漏洞页同文案)。
var sevLabels = []struct {
	Key   string
	Label string
}{
	{"critical", "严重"},
	{"high", "高危"},
	{"medium", "中危"},
	{"low", "低危"},
	{"info", "提示"},
}

// BuildReportData 由快照 + 统计 + 模板包装配 ReportData。
//
// 降级: snap 为 nil 时返回只带默认字段的结构(不 panic) —— 模板预览会用空数据
// 调它, "空数据也能渲染出一份完整样式的报告"正是预览的意义。
func BuildReportData(snap *Snapshot, stats SnapshotStats, pack *Pack, subtitle string) *ReportData {
	d := &ReportData{
		Subtitle:        firstNonEmpty(subtitle, "网络安全扫描与漏洞评估报告"),
		GeneratedAt:     time.Now(),
		Stats:           stats,
		Accent:          DefaultAccent,
		Footer:          DefaultFooter,
		Cover:           true,
		Sections:        DefaultSections(),
		Targets:         []string{},
	}
	if pack != nil {
		d.Logo = pack.LogoData
		if pack.Config.Accent != "" {
			d.Accent = pack.Config.Accent
		}
		if pack.Config.Footer != "" {
			d.Footer = pack.Config.Footer
		}
		if pack.Config.Client != "" {
			d.Client = pack.Config.Client
		}
		d.Cover = pack.CoverEnabled()
		d.Sections = pack.SectionOrder()
	}
	if snap == nil {
		d.Title = "Yugsight 安全扫描报告"
		d.TaskName = d.Title
		d.GeneratedAtText = d.GeneratedAt.Format("2006-01-02 15:04")
		d.SevRows = severityRows(stats)
		return d
	}
	d.Title = firstNonEmpty(snap.Title, "Yugsight 安全扫描报告")
	d.TaskName = d.Title
	d.Operator = snap.Operator
	d.Tool = snap.Tool
	d.Summary = snap.Summary
	if !snap.CreatedAt.IsZero() {
		d.GeneratedAt = snap.CreatedAt
	}
	d.GeneratedAtText = d.GeneratedAt.Format("2006-01-02 15:04")
	d.Assets = snap.Assets
	d.Vulns = snap.Vulns
	d.Targets = collectTargets(snap)
	d.SevRows = severityRows(stats)
	d.ScansView = snap.Scans
	d.TopoRows = topoRowsOf(snap)
	return d
}

// topoRowsOf 取快照拓扑并摊成表格行(快照没带拓扑时按资产+漏洞现算)。
func topoRowsOf(snap *Snapshot) []TopoRow {
	topo := snap.Topology
	if topo == nil && (len(snap.Assets) > 0 || len(snap.Vulns) > 0) {
		topo = BuildTopology(snap.Assets, snap.Vulns)
	}
	if topo == nil {
		return nil
	}
	kindNames := map[string]string{
		"asset": "资产", "port": "端口", "service": "服务", "probe": "探针",
	}
	rows := make([]TopoRow, 0, len(topo.Nodes))
	for _, n := range topo.Nodes {
		addr := n.IP
		if n.Port > 0 {
			addr = n.IP + ":" + fmt.Sprint(n.Port)
		}
		name := kindNames[n.Kind]
		if name == "" {
			name = n.Kind
		}
		rows = append(rows, TopoRow{
			Label: n.Label, KindName: name, Addr: addr,
			Service: n.Service, Risk: n.Risk, VulnCount: n.VulnCount,
		})
		if len(rows) >= 200 { // 报告不是拓扑浏览器, 200 行足够
			break
		}
	}
	return rows
}

// severityRows 把统计里的等级数字摊成有顺序的行。
func severityRows(s SnapshotStats) []SevRow {
	counts := map[string]int{
		"critical": s.Critical, "high": s.High, "medium": s.Medium,
		"low": s.Low, "info": s.Info,
	}
	rows := make([]SevRow, 0, len(sevLabels))
	for _, l := range sevLabels {
		rows = append(rows, SevRow{Key: l.Key, Label: l.Label, Count: counts[l.Key]})
	}
	return rows
}

// collectTargets 汇总报告涉及的目标(资产 IP 优先, 补任务目标), 去重限 200。
//
// 为什么两者都要: 纯资产视角会漏掉"扫了但没发现资产"的目标(那也是扫描范围),
// 只有任务视角又会在资产表为空时给出一份没有目标的报告。
func collectTargets(snap *Snapshot) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] || len(out) >= 200 {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, a := range snap.Assets {
		if a != nil {
			add(a.IP)
		}
	}
	for _, sc := range snap.Scans {
		add(sc.Target)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// firstNonEmpty 返回第一个非空字符串(都为空返回空)。
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
