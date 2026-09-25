package report

import (
	"sort"
	"strings"
	"time"

	"yugsight/internal/models"
)

// 差异条目状态。
const (
	DiffNew       = "new"       // 新增漏洞(基线没有, 目标有)
	DiffFixed     = "fixed"     // 已修复漏洞(基线有, 目标没有)
	DiffPersisted = "persisted" // 仍然存在(两次都有)
)

// Compare 对比两次扫描的漏洞集合, 识别新增 / 已修复 / 仍然存在。
//
// 对比口径(关键设计决策):
//
//  1. 匹配键用 models.Vuln.MergeKey() —— 与归一化层、误报管理(scanctl.FPSKey)
//     完全一致: "同资产 IP + 同 CVE"(无 CVE 时退化为"资产 + 协议:端口 + 标题")。
//     复用同一口径是本功能能成立的前提: 若这里自造一套键, 就会出现
//     "漏洞管理页显示去重 1 条、对比报告却说是新增 2 条"的自相矛盾。
//
//  2. 已修复的判定是"基线有而目标无", 不做时间推断 —— 时间戳在分布式扫描
//     (多探针时区/时钟偏差)场景下不可靠, 集合差集是唯一稳的判定。
//
//  3. 误报不参与对比: 人工已确认的误报在两次快照里都应被排除, 否则会把
//     "误报消失"误读为"漏洞已修复"(给客户虚报修复成果是最严重的可信度问题)。
//     这里对入参做兜底过滤, 即使装配层忘记过滤也不会出错。
func Compare(base, target *Snapshot, baseID, targetID string) *Diff {
	d := &Diff{
		BaseID:     baseID,
		TargetID:   targetID,
		ComparedAt: time.Now(),
		New:        []*DiffItem{},
		Fixed:      []*DiffItem{},
		Persisted:  []*DiffItem{},
		NewAssets:  []string{},
		FixedAssets: []string{},
	}
	if base != nil {
		d.BaseName = base.Title
	}
	if target != nil {
		d.TargetName = target.Title
	}

	baseMap := indexVulns(base)
	targetMap := indexVulns(target)

	// ---- 漏洞差异 ----
	for key, tv := range targetMap {
		if bv, ok := baseMap[key]; ok {
			d.Persisted = append(d.Persisted, makeItem(key, DiffPersisted, bv, tv))
			continue
		}
		d.New = append(d.New, makeItem(key, DiffNew, nil, tv))
	}
	for key, bv := range baseMap {
		if _, ok := targetMap[key]; ok {
			continue
		}
		d.Fixed = append(d.Fixed, makeItem(key, DiffFixed, bv, nil))
	}

	// ---- 资产差异(同口径: 归一化 IP) ----
	baseAssets := indexAssets(base)
	targetAssets := indexAssets(target)
	for ip := range targetAssets {
		if _, ok := baseAssets[ip]; !ok {
			d.NewAssets = append(d.NewAssets, ip)
		}
	}
	for ip := range baseAssets {
		if _, ok := targetAssets[ip]; !ok {
			d.FixedAssets = append(d.FixedAssets, ip)
		}
	}

	// ---- 排序: 高危在前, 便于用户第一眼看到要紧的 ----
	sortDiffItems(d.New)
	sortDiffItems(d.Fixed)
	sortDiffItems(d.Persisted)
	sort.Strings(d.NewAssets)
	sort.Strings(d.FixedAssets)

	d.Stats = DiffStats{
		BaseTotal:        len(baseMap),
		TargetTotal:      len(targetMap),
		NewCount:         len(d.New),
		FixedCount:       len(d.Fixed),
		PersistedCount:   len(d.Persisted),
		BaseAssetTotal:   len(baseAssets),
		TargetAssetTotal: len(targetAssets),
		NewAssetCount:    len(d.NewAssets),
		FixedAssetCount:  len(d.FixedAssets),
	}
	d.Stats.Delta = d.Stats.TargetTotal - d.Stats.BaseTotal
	for _, it := range d.New {
		switch it.TargetSeverity {
		case models.SeverityCritical:
			d.Stats.NewCritical++
		case models.SeverityHigh:
			d.Stats.NewHigh++
		}
	}
	return d
}

// indexVulns 构建 合并键 -> 漏洞 索引(误报与空条目被排除)。
func indexVulns(s *Snapshot) map[string]*models.Vuln {
	out := map[string]*models.Vuln{}
	if s == nil {
		return out
	}
	for _, v := range s.Vulns {
		if v == nil || v.FalsePositive {
			continue
		}
		out[v.MergeKey()] = v
	}
	return out
}

// indexAssets 构建 归一化 IP 集合。
//
// 兜底口径(重要): 调用方可能只填了 Vulns 而没填 Assets(装配层按任务目标
// 推导资产集合时就是这样)。此时若只看 Assets, 资产差异会永远为空 ——
// 用户看到"新增了 20 个漏洞"却是"0 个新增资产", 是不合理的。
// 因此漏洞涉及的 IP 也计入资产集合(与 BuildTopology 的"孤儿资产"补漏同思路)。
func indexAssets(s *Snapshot) map[string]*models.Asset {
	out := map[string]*models.Asset{}
	if s == nil {
		return out
	}
	for _, a := range s.Assets {
		if a == nil {
			continue
		}
		if ip := models.NormIP(a.IP); ip != "" {
			out[ip] = a
		}
	}
	for _, v := range s.Vulns {
		if v == nil {
			continue
		}
		ip := models.NormIP(v.AssetIP)
		if ip == "" {
			continue
		}
		if _, ok := out[ip]; !ok {
			out[ip] = &models.Asset{IP: ip}
		}
	}
	return out
}

// makeItem 构造差异条目(两侧任一可为 nil)。
func makeItem(key, status string, bv, tv *models.Vuln) *DiffItem {
	it := &DiffItem{Key: key, Status: status}
	// 详情取自"更完整的一侧": 新增/仍然存在取目标侧(最新证据), 已修复取基线侧
	ref := tv
	if ref == nil {
		ref = bv
	}
	if ref != nil {
		it.CVE = CVEOf(ref)
		it.Title = ref.Title
		it.AssetIP = models.NormIP(ref.AssetIP)
		it.Port = ref.Port
		it.Protocol = ref.Protocol
		it.Vuln = ref
	}
	if bv != nil {
		it.BaseSeverity = models.NormalizeSeverity(bv.Severity)
		it.BaseConfidence = bv.Confidence
		it.BaseFoundAt = bv.FoundAt
	}
	if tv != nil {
		it.TargetSeverity = models.NormalizeSeverity(tv.Severity)
		it.TargetConfidence = tv.Confidence
		it.TargetFoundAt = tv.FoundAt
	}
	// 等级变化: 只在两次都有且确实不同时标注(新增/已修复没有"变化"语义)
	if bv != nil && tv != nil && it.BaseSeverity != it.TargetSeverity {
		it.SeverityChange = it.BaseSeverity + " -> " + it.TargetSeverity
	}
	return it
}

// sortDiffItems 按 风险等级降序 -> 资产 IP -> 端口 排序。
func sortDiffItems(items []*DiffItem) {
	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := models.SeverityRank(diffSeverity(items[i])), models.SeverityRank(diffSeverity(items[j]))
		if ri != rj {
			return ri > rj
		}
		if items[i].AssetIP != items[j].AssetIP {
			return items[i].AssetIP < items[j].AssetIP
		}
		return items[i].Port < items[j].Port
	})
}

// diffSeverity 差异条目的代表等级(优先目标侧)。
func diffSeverity(it *DiffItem) string {
	if it == nil {
		return ""
	}
	if it.TargetSeverity != "" {
		return it.TargetSeverity
	}
	return it.BaseSeverity
}

// SnapshotFromVulns 用一批漏洞构造轻量快照(供"以某次扫描为基线"的场景)。
func SnapshotFromVulns(id, title string, vulns []*models.Vuln) *Snapshot {
	return &Snapshot{
		Title:     title,
		CreatedAt: time.Now(),
		Vulns:     vulns,
		Scans:     []ScanInfo{{ID: id, Type: "snapshot", Target: title, Status: "success"}},
	}
}

// MatchAny 判断文本是否包含任一关键字(大小写不敏感); 空关键字列表返回 true。
func MatchAny(text string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	text = strings.ToLower(text)
	for _, kw := range keywords {
		if kw = strings.ToLower(strings.TrimSpace(kw)); kw != "" && strings.Contains(text, kw) {
			return true
		}
	}
	return false
}
