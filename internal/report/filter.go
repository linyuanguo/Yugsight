package report

import (
	"errors"
	"net"
	"strings"
	"time"

	"yugsight/internal/models"
)

// errNilDiff 对比数据缺失。
var errNilDiff = errors.New("report: 对比数据为空")

// Apply 对快照按筛选条件过滤资产与漏洞, 返回过滤后的副本与统计。
//
// 为什么不就地修改:
//
//	快照可能来自 db(同一批对象被多处引用), 就地过滤会污染调用方的数据
//	(典型症状: 生成一次"仅高危"报告后, 后续所有报告都只剩高危)。
//	因此这里始终返回新切片, 原快照保持不变。
func (f Filter) Apply(s *Snapshot) (*Snapshot, SnapshotStats) {
	if s == nil {
		return nil, SnapshotStats{}
	}
	out := &Snapshot{
		Title:     s.Title,
		Operator:  s.Operator,
		Tool:      s.Tool,
		CreatedAt: s.CreatedAt,
		Filter:    f,
		Scans:     s.Scans,
		Summary:   s.Summary,
	}

	// ---- 时间窗口提前解析(避免在循环里反复 parse) ----
	from, to := f.TimeFrom, f.TimeTo
	hasTime := !from.IsZero() || !to.IsZero()

	// ---- CIDR 预解析 ----
	var ipNet *net.IPNet
	if strings.TrimSpace(f.CIDR) != "" {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(f.CIDR)); err == nil {
			ipNet = n
		}
		// 非法 CIDR 静默忽略: 报告不出结果比直接报错更让人困惑,
		// 但也不能把用户输入的错别字当成"过滤掉全部数据"。
	}
	excludeFP := f.ExcludeFalsePositive == nil || *f.ExcludeFalsePositive

	// ---- 漏洞过滤 ----
	vulnRules := make([]*models.Vuln, 0, len(s.Vulns))
	fpExcluded := 0
	for _, v := range s.Vulns {
		if v == nil {
			continue
		}
		if excludeFP && v.FalsePositive {
			fpExcluded++
			continue
		}
		if !f.matchVuln(v, ipNet, from, to, hasTime) {
			continue
		}
		vulnRules = append(vulnRules, v)
	}
	out.Vulns = vulnRules

	// ---- 资产过滤 ----
	// 口径: 资产是否入报告取"时间/网段/IP"三个维度, 不取风险维度 ——
	// 若按风险等级过滤资产, 选"仅高危"时资产清单会整个消失(用户看到的
	// 是"这次扫描没有资产", 那是错误结论)。风险维度只作用于漏洞与拓扑着色。
	assetRules := make([]*models.Asset, 0, len(s.Assets))
	for _, a := range s.Assets {
		if a == nil {
			continue
		}
		if !f.matchAsset(a, ipNet, from, to, hasTime) {
			continue
		}
		assetRules = append(assetRules, a)
	}
	out.Assets = assetRules

	// ---- 渗透验证(阶段 5): 与资产同口径(时间/网段/IP 维度) ----
	// 不按风险等级过滤 —— 与资产口径一致(选"仅高危"时渗透记录不应整体消失,
	// 否则"高危资产没有渗透验证记录"会被误读成"没做渗透")。
	pentaRules := make([]PentaEntry, 0, len(s.Penta))
	for _, p := range s.Penta {
		if strings.TrimSpace(f.IP) != "" && models.NormIP(p.Target) != models.NormIP(f.IP) {
			continue
		}
		if ipNet != nil && !ipNet.Contains(net.ParseIP(models.NormIP(p.Target))) {
			continue
		}
		if hasTime && !inWindow(p.VerifiedAt, from, to) {
			continue
		}
		pentaRules = append(pentaRules, p)
	}
	out.Penta = pentaRules

	// ---- 拓扑: 以过滤后的资产+漏洞重建(保证拓扑与报告口径一致) ----
	out.Topology = BuildTopology(out.Assets, out.Vulns)

	stats := ComputeStats(out)
	stats.FalsePos = fpExcluded
	return out, stats
}

// matchVuln 单条漏洞是否命中筛选条件。
func (f Filter) matchVuln(v *models.Vuln, ipNet *net.IPNet, from, to time.Time, hasTime bool) bool {
	if len(f.Severity) > 0 && !containsFold(f.Severity, models.NormalizeSeverity(v.Severity)) {
		return false
	}
	if strings.TrimSpace(f.IP) != "" && models.NormIP(v.AssetIP) != models.NormIP(f.IP) {
		return false
	}
	if ipNet != nil && !ipNet.Contains(net.ParseIP(models.NormIP(v.AssetIP))) {
		return false
	}
	if cve := strings.ToUpper(strings.TrimSpace(f.CVE)); cve != "" {
		vc := models.NormalizeCVE(v.CVE)
		if vc == "" || !strings.HasPrefix(vc, cve) {
			return false
		}
	}
	if strings.TrimSpace(f.ProbeNode) != "" && !matchNode(v.Source, nodeOfVuln(v), f.ProbeNode, f.IncludeLocal) {
		return false
	}
	if strings.TrimSpace(f.Status) != "" && v.Status != strings.TrimSpace(f.Status) {
		return false
	}
	if f.OnlyWithEvidence && strings.TrimSpace(v.Evidence) == "" && len(v.EvidenceRecords) == 0 {
		return false
	}
	if kw := strings.TrimSpace(f.Keywords); kw != "" && !strings.Contains(strings.ToLower(v.Title), strings.ToLower(kw)) {
		return false
	}
	if hasTime {
		t := v.FoundAt
		if t.IsZero() {
			t = v.LastSeenAt
		}
		if !inWindow(t, from, to) {
			return false
		}
	}
	return true
}

// matchAsset 单条资产是否命中筛选条件(仅时间/网段/IP 维度)。
func (f Filter) matchAsset(a *models.Asset, ipNet *net.IPNet, from, to time.Time, hasTime bool) bool {
	if strings.TrimSpace(f.IP) != "" && models.NormIP(a.IP) != models.NormIP(f.IP) {
		return false
	}
	if ipNet != nil && !ipNet.Contains(net.ParseIP(models.NormIP(a.IP))) {
		return false
	}
	if strings.TrimSpace(f.ProbeNode) != "" && !matchNode("", a.ProbeNode, f.ProbeNode, f.IncludeLocal) {
		return false
	}
	if hasTime && !inWindow(a.FoundAt, from, to) {
		return false
	}
	return true
}

// nodeOfVuln 取漏洞的来源节点 ID(空 = 无节点信息)。
//
// 现状说明: models.Vuln 没有 ProbeNode 字段(来源节点记录在 models.Asset 上),
// 装配层会把节点信息规范化写进 Source(见 report_api.go 的 reportSourceLabel):
//
//	probe:<节点ID>   探针上报
//	<engine>@<节点>  该节点上的内置引擎发现
//	local / builtin  本地
//
// 这里按同一口径拆解, 与 matchNode 保持一致 —— 两处口径不一致会导致
// "按节点筛选"结果与报告里显示的来源对不上。
func nodeOfVuln(v *models.Vuln) string {
	if v == nil {
		return ""
	}
	src := strings.TrimSpace(v.Source)
	if src == "" {
		return ""
	}
	if strings.HasPrefix(src, "probe:") {
		return strings.TrimPrefix(src, "probe:")
	}
	if i := strings.Index(src, "@"); i >= 0 {
		return src[i+1:]
	}
	if strings.EqualFold(src, LocalNode) || strings.EqualFold(src, "builtin") {
		return ""
	}
	return ""
}

// matchNode 节点匹配: want 为空不过滤; want="local" 匹配本地(非探针)条目。
//
// 节点信息的两个来源(优先精确, 其次回落到 Source 字段):
//
//	1. node 参数(由装配层用资产表的 ProbeNode 填充, 形如 "probe-a");
//	2. 规范化的 Source 字段(装配层把探针来的写成 "probe:<节点ID>",
//	   本地的写成 "local", 内置引擎的写成 "builtin" / "builtin@<节点>")。
//
// 为什么必须两条都判: 只判 node 时, 本地条目(node="")会被任何非空 want
// 误判为"不匹配"; 只判 Source 时, 资产表里精确的节点归属被浪费掉。
func matchNode(source, node, want string, includeLocal bool) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return true
	}
	src := strings.TrimSpace(source)
	// 从 Source 里拆出节点(probe:<id> / <engine>@<id>)
	srcNode := ""
	switch {
	case strings.HasPrefix(src, "probe:"):
		srcNode = strings.TrimPrefix(src, "probe:")
	case strings.Contains(src, "@"):
		srcNode = src[strings.Index(src, "@")+1:]
	}
	local := strings.TrimSpace(node) == "" && srcNode == "" && !strings.EqualFold(src, "probe")

	if strings.EqualFold(want, LocalNode) || includeLocal {
		// 本地 = 既无节点归属, 也不是探针上报的
		return local
	}
	if strings.EqualFold(node, want) || strings.EqualFold(srcNode, want) {
		return true
	}
	// 回落到 Source 直比(兼容非探针来源标识)
	return strings.EqualFold(src, want)
}

// inWindow 时间是否落在 [from, to] 内(零值边界表示该侧不限)。
func inWindow(t time.Time, from, to time.Time) bool {
	if t.IsZero() {
		// 无时间的条目: 只在"两侧都不限"时保留, 否则过滤掉
		// (用户设了时间窗就是要看这段时间的东西, 塞进无时间的条目会让人困惑)
		return from.IsZero() && to.IsZero()
	}
	if !from.IsZero() && t.Before(from) {
		return false
	}
	if !to.IsZero() && t.After(to) {
		return false
	}
	return true
}

// containsFold 大小写不敏感包含判断。
func containsFold(list []string, s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, x := range list {
		if strings.ToLower(strings.TrimSpace(x)) == s {
			return true
		}
	}
	return false
}

// ParseSeverityList 解析逗号分隔的等级串("high,critical" -> [high critical])。
// 空串返回 nil(不过滤); 值会被归一化(未知值退化为 low, 与 models 口径一致)。
func ParseSeverityList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		out = append(out, models.NormalizeSeverity(part))
	}
	return out
}
