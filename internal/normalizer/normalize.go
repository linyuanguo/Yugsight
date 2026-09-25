package normalizer

import (
	"encoding/json"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"time"

	"yugsight/internal/models"
)

// Options 归一化选项。
type Options struct {
	// ScanID 本轮扫描标识（空则自动生成）
	ScanID string
	// Baseline 上一轮扫描基线（nil = 无基线，全部漏洞标记为 new）
	Baseline *Baseline
	// Now 时间基准（零值取当前时间，供测试注入）
	Now time.Time
}

// Stats 归一化结果统计（供大屏查询）。
type Stats struct {
	AssetCount     int            `json:"assetCount"`
	VulnCount      int            `json:"vulnCount"`
	NewCount       int            `json:"newCount"`
	DuplicateCount int            `json:"duplicateCount"`
	FixedCount     int            `json:"fixedCount"`
	BySeverity     map[string]int `json:"bySeverity"`
	BySource       map[string]int `json:"bySource"`
}

// Result 归一化输出：标准化资产 + 漏洞 + 统计。
// Vulns 为本轮命中（new + duplicate），Fixed 为历史已修复（基线有、本轮无）。
type Result struct {
	ScanID      string          `json:"scanId"`
	GeneratedAt time.Time       `json:"generatedAt"`
	Sources     []string        `json:"sources"`
	Assets      []*models.Asset `json:"assets"`
	Vulns       []*models.Vuln  `json:"vulns"`
	Fixed       []*models.Vuln  `json:"fixed,omitempty"`
	Stats       Stats           `json:"stats"`
}

// Normalize 归一化统一入口：接收任意来源的原始结果批次，
// 输出标准化资产与漏洞（去重合并、标记新发现 / 重复）。
func Normalize(batches ...*RawBatch) *Result {
	return NormalizeWithOptions(Options{}, batches...)
}

// NormalizeWithOptions 带选项归一化（支持基线对比与时间注入）。
func NormalizeWithOptions(opts Options, batches ...*RawBatch) *Result {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	scanID := strings.TrimSpace(opts.ScanID)
	if scanID == "" {
		scanID = "scan-" + now.UTC().Format("20060102-150405")
	}

	assetMap := make(map[string]*models.Asset)
	vulnMap := make(map[string]*models.Vuln)
	sourceSet := make(map[string]bool)

	for _, b := range batches {
		if b == nil {
			continue
		}
		src := strings.ToLower(strings.TrimSpace(b.Source))
		if src == "" {
			src = SourceUnknown
			slog.Debug("normalizer: 批次来源为空, 按未知来源处理")
		}
		sourceSet[src] = true
		for _, ra := range b.Assets {
			mergeRawAsset(assetMap, ra, now)
		}
		for _, rv := range b.Vulns {
			mergeRawVuln(vulnMap, assetMap, rv, src, now)
		}
	}

	vulns, fixed := markStatus(sortedVulns(vulnMap), opts.Baseline, now)
	assets := sortedAssets(assetMap)

	res := &Result{
		ScanID:      scanID,
		GeneratedAt: now,
		Sources:     sortedKeys(sourceSet),
		Assets:      assets,
		Vulns:       vulns,
		Fixed:       fixed,
	}
	res.Stats = computeStats(res)
	return res
}

// ===== 资产合并 =====

// mergeRawAsset 合并原始资产到资产表（同 IP = 同一资产：
// 字段取首个非空，端口 / 标签取并集，保留最早发现时间）。
func mergeRawAsset(m map[string]*models.Asset, ra RawAsset, now time.Time) {
	ip := models.NormIP(ra.IP)
	if ip == "" {
		return
	}
	foundAt := ra.FoundAt
	if foundAt.IsZero() {
		foundAt = now
	}
	a, ok := m[ip]
	if !ok {
		a = &models.Asset{
			IP:        ip,
			MAC:       normMAC(ra.MAC),
			Hostname:  strings.TrimSpace(ra.Hostname),
			OS:        strings.TrimSpace(ra.OS),
			Service:   strings.TrimSpace(ra.Service),
			Version:   strings.TrimSpace(ra.Version),
			Banner:    strings.TrimSpace(ra.Banner),
			ProbeNode: strings.TrimSpace(ra.ProbeNode),
			FoundAt:   foundAt,
			// Ports 必须在新建分支就落上: 只在"同 IP 二次合并"分支 unionInts 的话,
			// 单批次首次出现的资产会丢掉全部端口(探针/本地扫描落库后资产页看不到端口)
			Ports: unionInts(nil, ra.Ports),
			Tags:  dedupStrings(ra.Tags),
		}
		a.ID = a.StableID()
		m[ip] = a
		return
	}
	if a.MAC == "" {
		a.MAC = normMAC(ra.MAC)
	}
	if a.Hostname == "" {
		a.Hostname = strings.TrimSpace(ra.Hostname)
	}
	if a.OS == "" {
		a.OS = strings.TrimSpace(ra.OS)
	}
	if a.Service == "" {
		a.Service = strings.TrimSpace(ra.Service)
		a.Version = strings.TrimSpace(ra.Version)
		a.Banner = strings.TrimSpace(ra.Banner)
	}
	if a.ProbeNode == "" {
		a.ProbeNode = strings.TrimSpace(ra.ProbeNode)
	}
	a.Ports = unionInts(a.Ports, ra.Ports)
	a.Tags = unionStrings(a.Tags, ra.Tags)
	if foundAt.Before(a.FoundAt) {
		a.FoundAt = foundAt
	}
}

// ===== 漏洞去重合并 =====

// mergeRawVuln 合并原始漏洞到漏洞表（同资产+同 CVE 合并，保留全部证据）。
// 漏洞隐含资产存在：同时注册/合并最小资产（IP + 端口），保证仅漏洞来源时资产可查。
func mergeRawVuln(m map[string]*models.Vuln, assetMap map[string]*models.Asset, rv RawVuln, src string, now time.Time) {
	v := toVuln(rv, src, now)
	if v == nil {
		return
	}
	ports := make([]int, 0, 1)
	if rv.Port > 0 {
		ports = append(ports, rv.Port)
	}
	mergeRawAsset(assetMap, RawAsset{IP: v.AssetIP, Ports: ports}, now)
	key := v.MergeKey()
	if dst, ok := m[key]; ok {
		mergeVuln(dst, v)
	} else {
		m[key] = v
	}
}

// toVuln 原始漏洞 → 统一模型（自动填充 ID / 风险等级 / 置信度）。
func toVuln(rv RawVuln, src string, now time.Time) *models.Vuln {
	ip := models.NormIP(rv.AssetIP)
	if ip == "" {
		return nil
	}
	foundAt := rv.FoundAt
	if foundAt.IsZero() {
		foundAt = now
	}
	cve := models.NormalizeCVE(rv.CVE)
	title := strings.TrimSpace(rv.Title)
	if title == "" {
		if cve != "" {
			title = cve
		} else {
			title = "未知漏洞"
		}
	}
	conf := rv.Confidence
	if conf <= 0 {
		conf = defaultConfidence(rv)
	}
	if conf > 100 {
		conf = 100
	}
	v := &models.Vuln{
		CVE:         cve,
		AssetIP:     ip,
		Port:        rv.Port,
		Protocol:    strings.ToLower(strings.TrimSpace(rv.Protocol)),
		Severity:    normalizeVulnSeverity(rv),
		Title:       title,
		Description: strings.TrimSpace(rv.Description),
		Evidence:    strings.TrimSpace(rv.Evidence),
		Request:     rv.Request,
		Response:    rv.Response,
		Confidence:  conf,
		Source:      src,
		Sources:     []string{src},
		CVSS:        rv.CVSS,
		PcapFile:    strings.TrimSpace(rv.PcapFile),
		FoundAt:     foundAt,
		LastSeenAt:  foundAt,
	}
	if rv.Request != "" || rv.Response != "" || strings.TrimSpace(rv.Evidence) != "" {
		v.EvidenceRecords = append(v.EvidenceRecords, models.EvidenceRecord{
			Source:   src,
			Evidence: strings.TrimSpace(rv.Evidence),
			Request:  rv.Request,
			Response: rv.Response,
			FoundAt:  foundAt,
		})
	}
	v.ID = v.StableID()
	return v
}

// normalizeVulnSeverity 确定最终风险等级：
// 来源显式等级优先（与 CVSS 不一致时取高者）；
// 等级缺失时按 CVSS 分值推导；两者皆无默认 low。
func normalizeVulnSeverity(rv RawVuln) string {
	raw := strings.TrimSpace(rv.Severity)
	if raw == "" || strings.EqualFold(raw, "unknown") || strings.EqualFold(raw, "none") {
		if rv.CVSS > 0 {
			return models.CVSSSeverity(rv.CVSS)
		}
		return models.SeverityLow
	}
	sev := models.NormalizeSeverity(raw)
	if rv.CVSS > 0 {
		if byCvss := models.CVSSSeverity(rv.CVSS); models.SeverityRank(byCvss) > models.SeverityRank(sev) {
			return byCvss
		}
	}
	return sev
}

// defaultConfidence 来源未提供置信度时的默认值（0-100）：
// 请求+响应成对 = 主动验证 85；有证据 70；已知 CVE 55；其他 40。
func defaultConfidence(rv RawVuln) int {
	switch {
	case rv.Request != "" && rv.Response != "":
		return 85
	case strings.TrimSpace(rv.Evidence) != "":
		return 70
	case models.IsCVE(rv.CVE):
		return 55
	default:
		return 40
	}
}

// mergeVuln 来源漏洞合并进目标漏洞（同键）：
// 来源取并集、证据记录全保留、等级 / CVSS / 置信度取最高，
// 保留最早发现时间并延长最近出现时间。
func mergeVuln(dst, src *models.Vuln) {
	dst.Sources = unionStrings(dst.Sources, src.Sources)
	dst.EvidenceRecords = append(dst.EvidenceRecords, src.EvidenceRecords...)
	if models.SeverityRank(src.Severity) > models.SeverityRank(dst.Severity) {
		dst.Severity = src.Severity
	}
	if src.CVSS > dst.CVSS {
		dst.CVSS = src.CVSS
	}
	if src.Confidence > dst.Confidence {
		dst.Confidence = src.Confidence
	}
	if dst.Evidence == "" {
		dst.Evidence = src.Evidence
	}
	if dst.Request == "" {
		dst.Request = src.Request
	}
	if dst.Response == "" {
		dst.Response = src.Response
	}
	if dst.Description == "" {
		dst.Description = src.Description
	}
	if dst.PcapFile == "" {
		dst.PcapFile = src.PcapFile
	}
	if dst.Port == 0 && src.Port != 0 {
		dst.Port = src.Port
	}
	if dst.Protocol == "" {
		dst.Protocol = src.Protocol
	}
	if src.FoundAt.Before(dst.FoundAt) {
		dst.FoundAt = src.FoundAt
	}
	if src.LastSeenAt.After(dst.LastSeenAt) {
		dst.LastSeenAt = src.LastSeenAt
	}
}

// ===== 漏洞状态标记 =====

// markStatus 依据上一轮基线标记漏洞状态：
//   - 无基线：全部 new
//   - 本轮命中且基线存在：duplicate（重复出现），继承基线最早发现时间
//   - 基线存在但本轮未命中：fixed（历史已修复），置 FixedAt
func markStatus(vulns []*models.Vuln, baseline *Baseline, now time.Time) (cur, fixed []*models.Vuln) {
	cur = vulns
	if baseline == nil || len(baseline.Vulns) == 0 {
		for _, v := range cur {
			v.Status = models.VulnStatusNew
		}
		return cur, nil
	}
	baseMap := make(map[string]*models.Vuln, len(baseline.Vulns))
	for _, b := range baseline.Vulns {
		if b == nil || b.Status == models.VulnStatusFixed {
			continue
		}
		baseMap[b.MergeKey()] = b
	}
	curKeys := make(map[string]bool, len(cur))
	for _, v := range cur {
		curKeys[v.MergeKey()] = true
		if prev, ok := baseMap[v.MergeKey()]; ok {
			v.Status = models.VulnStatusDuplicate
			if prev.FoundAt.Before(v.FoundAt) {
				v.FoundAt = prev.FoundAt
			}
		} else {
			v.Status = models.VulnStatusNew
		}
	}
	for k, prev := range baseMap {
		if curKeys[k] {
			continue
		}
		f := *prev
		f.Status = models.VulnStatusFixed
		f.FixedAt = &now
		fixed = append(fixed, &f)
	}
	sort.Slice(fixed, func(i, j int) bool {
		if fixed[i].Severity != fixed[j].Severity {
			return models.SeverityRank(fixed[i].Severity) > models.SeverityRank(fixed[j].Severity)
		}
		return fixed[i].CVE < fixed[j].CVE
	})
	return cur, fixed
}

// ===== 排序与统计 =====

// sortedVulns 漏洞排序：严重度降序 → CVSS 降序 → 标题升序。
func sortedVulns(m map[string]*models.Vuln) []*models.Vuln {
	out := make([]*models.Vuln, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Severity != b.Severity {
			return models.SeverityRank(a.Severity) > models.SeverityRank(b.Severity)
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return a.Title < b.Title
	})
	return out
}

// sortedAssets 资产按 IP 升序（IP 数字段比较，非 IP 退化为字典序）。
func sortedAssets(m map[string]*models.Asset) []*models.Asset {
	out := make([]*models.Asset, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out
}

func ipLess(a, b string) bool {
	ia, errA := netip.ParseAddr(a)
	ib, errB := netip.ParseAddr(b)
	switch {
	case errA == nil && errB == nil:
		return ia.Compare(ib) < 0
	case errA == nil:
		return true
	case errB == nil:
		return false
	default:
		return a < b
	}
}

func computeStats(r *Result) Stats {
	s := Stats{
		AssetCount: len(r.Assets),
		VulnCount:  len(r.Vulns),
		BySeverity: make(map[string]int),
		BySource:   make(map[string]int),
	}
	for _, v := range r.Vulns {
		s.BySeverity[v.Severity]++
		switch v.Status {
		case models.VulnStatusNew:
			s.NewCount++
		case models.VulnStatusDuplicate:
			s.DuplicateCount++
		}
		for _, src := range v.Sources {
			s.BySource[src]++
		}
	}
	s.FixedCount = len(r.Fixed)
	return s
}

// ===== 查询辅助（Web API / 报告 / 大屏调用） =====

// JSON 序列化结果（可直接作为 API 响应体）。
func (r *Result) JSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.Marshal(r)
}

// AssetByIP 按 IP 查资产。
func (r *Result) AssetByIP(ip string) *models.Asset {
	if r == nil {
		return nil
	}
	key := models.NormIP(ip)
	for _, a := range r.Assets {
		if a.Key() == key {
			return a
		}
	}
	return nil
}

// VulnsByAsset 按资产查本轮漏洞（含重复，不含已修复）。
func (r *Result) VulnsByAsset(ip string) []*models.Vuln {
	if r == nil {
		return nil
	}
	key := models.NormIP(ip)
	var out []*models.Vuln
	for _, v := range r.Vulns {
		if v.AssetIP == key {
			out = append(out, v)
		}
	}
	return out
}

// VulnsBySeverity 按风险等级查本轮漏洞。
func (r *Result) VulnsBySeverity(sev string) []*models.Vuln {
	if r == nil {
		return nil
	}
	want := models.NormalizeSeverity(sev)
	var out []*models.Vuln
	for _, v := range r.Vulns {
		if v.Severity == want {
			out = append(out, v)
		}
	}
	return out
}

// VulnsByStatus 按状态查漏洞（new / duplicate / fixed，fixed 在 Fixed 列表中）。
func (r *Result) VulnsByStatus(status string) []*models.Vuln {
	if r == nil {
		return nil
	}
	all := make([]*models.Vuln, 0, len(r.Vulns)+len(r.Fixed))
	all = append(all, r.Vulns...)
	all = append(all, r.Fixed...)
	var out []*models.Vuln
	for _, v := range all {
		if v.Status == status {
			out = append(out, v)
		}
	}
	return out
}

// VulnsByCVE 按 CVE 查漏洞（含已修复）。
func (r *Result) VulnsByCVE(cve string) []*models.Vuln {
	if r == nil {
		return nil
	}
	want := models.NormalizeCVE(cve)
	if want == "" {
		return nil
	}
	all := make([]*models.Vuln, 0, len(r.Vulns)+len(r.Fixed))
	all = append(all, r.Vulns...)
	all = append(all, r.Fixed...)
	var out []*models.Vuln
	for _, v := range all {
		if v.CVE == want {
			out = append(out, v)
		}
	}
	return out
}

// ===== 小工具 =====

// normMAC MAC 归一化：大写 + 统一冒号分隔（XX:XX:XX:XX:XX:XX）；
// 长度非 12 位时原样返回（不破坏未知格式）。
func normMAC(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "-", ":")
	compact := strings.ReplaceAll(s, ":", "")
	if len(compact) != 12 {
		return s
	}
	out := compact[:2]
	for i := 2; i < 12; i += 2 {
		out += ":" + compact[i : i+2]
	}
	return out
}

// unionInts 端口并集（去重、去非正数、升序）。
func unionInts(dst, src []int) []int {
	seen := make(map[int]bool, len(dst))
	out := make([]int, 0, len(dst)+len(src))
	for _, v := range dst {
		if v <= 0 || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, v := range src {
		if v <= 0 || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// unionStrings 字符串并集（去空白项、去重、保持先后顺序）。
func unionStrings(dst, src []string) []string {
	seen := make(map[string]bool, len(dst))
	out := make([]string, 0, len(dst)+len(src))
	for _, v := range dst {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, v := range src {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func dedupStrings(in []string) []string {
	return unionStrings(nil, in)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
