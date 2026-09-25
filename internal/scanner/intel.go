//go:build !windows || windows

// intel.go 威胁情报基础集(KEV 标记 + EPSS 分值)与模板优先级排序。
//
// 能力:
//   - 内置基础情报集 intel_builtin.json(gzip 无, 体积小直接 embed):
//     KEV = CISA 已知被利用漏洞目录精选子集(全量 1710 条的基线, 2026-09 目录),
//     EPSS = FIRST 利用可能性分值基线快照(近似值, 仅用于优先级排序)
//   - 外部热更新: exe 同目录 vuln/intel/*.json(同格式, 按 CVE 号覆盖内置条目),
//     目录不存在无缝降级, 只读; 与规则库 rules-manifest / CPE cpe-manifest
//     的在线更新机制(rule_updater.go)相互独立, 本文件不发起网络请求
//   - 模板优先级排序: PrioritizeRules 按 "KEV(已知被利用)优先 -> EPSS 分值降序
//     -> 严重级别降序 -> ID 升序" 对规则列表重排序, 供执行器"高危漏洞优先
//     验证"(nuclei_runner.go 的 RunnerConfig.PriorityOrder, 默认关闭)
//   - IsKEV / EPSSScore 供统一漏洞模型(model.go)自动填充 KeV/Epss 字段
//
// 说明: 任务书提及 "SQLite 存储规则库、CPE 字典" —— 本项目硬约束为纯 Go
// 标准库、零第三方依赖(单二进制跨平台), SQLite(cgo 或 modernc)均违反该
// 约束; 规则库/CPE 字典采用等效的本地文件存储(rules/ + checksum.sha256 +
// .commit、cpe/ + .commit, 见 ruleset.go / rule_updater.go / cpe_engine.go),
// 具备持久化、完整性校验、版本化(commit)、热更新四要素, 语义等价。
//
// 依赖: 仅 Go 标准库。
package scanner

import (
	_ "embed"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// intelLog 组件日志
var intelLog = slog.Default().With("component", "intel")

//go:embed intel_builtin.json
var builtinIntelJSON []byte

// KEVEntry CISA 已知被利用漏洞目录(KEV)条目
type KEVEntry struct {
	CVE        string `json:"cve"`
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	Name       string `json:"name"`
	DateAdded  string `json:"dateAdded"`
	Ransomware bool   `json:"ransomware,omitempty"` // 已知被勒索软件利用
}

// EPSSEntry FIRST EPSS(Exploit Prediction Scoring System)分值条目
type EPSSEntry struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"score"`      // 0-1, 未来 30 天被利用概率预测
	Percentile float64 `json:"percentile"` // 0-1, 分位
}

type intelFile struct {
	Version string      `json:"version"`
	Note    string      `json:"note,omitempty"`
	KEV     []KEVEntry  `json:"kev"`
	EPSS    []EPSSEntry `json:"epss"`
}

var (
	intelMu      sync.RWMutex
	intelKEV     = map[string]KEVEntry{}
	intelEPSS    = map[string]float64{}
	intelVersion string
	intelLoaded  bool
)

// intelExternalDir 测试用目录覆盖(空 = exe 同目录 vuln/intel/)
var intelExternalDir = ""

// intelDir 外部情报目录(默认 exe 同目录 vuln/intel/, 可选, 不存在则只用内置)。
// 2026-09-24 dist 目录整理: 规则库统一收进 vuln/(旧 "exe 同目录 intel/" 由
// main.go 的 migrateLegacyDirs 启动时一次性迁移)。
func intelDir() string {
	if intelExternalDir != "" {
		return intelExternalDir
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "vuln", "intel")
	}
	return "vuln/intel"
}

// normCVE 归一化 CVE 号(去空白 + 大写)
func normCVE(c string) string {
	return strings.ToUpper(strings.TrimSpace(c))
}

// loadIntelLocked 加载/刷新情报集(调用方需持有 intelMu 写锁)。
// 内置嵌入优先, 外部 intel/*.json 按 CVE 号覆盖; 非法条目只记告警不中断。
func loadIntelLocked() {
	kev := map[string]KEVEntry{}
	epss := map[string]float64{}
	version := ""

	var bf intelFile
	if err := json.Unmarshal(builtinIntelJSON, &bf); err != nil {
		intelLog.Error("内置情报集解析失败(降级为空集, 仅影响优先级标记)", "err", err)
	} else {
		version = bf.Version
		for i := range bf.KEV {
			c := normCVE(bf.KEV[i].CVE)
			if c == "" {
				continue
			}
			bf.KEV[i].CVE = c
			kev[c] = bf.KEV[i]
		}
		for i := range bf.EPSS {
			c := normCVE(bf.EPSS[i].CVE)
			if c == "" {
				continue
			}
			epss[c] = bf.EPSS[i].Score
		}
	}

	// 外部 intel/ 目录(可选, 同 CVE 覆盖内置)
	if files, err := os.ReadDir(intelDir()); err == nil {
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
				continue
			}
			data, rerr := os.ReadFile(filepath.Join(intelDir(), f.Name()))
			if rerr != nil {
				intelLog.Warn("外部情报文件读取失败, 跳过", "file", f.Name(), "err", rerr)
				continue
			}
			var ef intelFile
			if uerr := json.Unmarshal(data, &ef); uerr != nil {
				intelLog.Warn("外部情报文件 JSON 非法, 跳过", "file", f.Name(), "err", uerr)
				continue
			}
			if ef.Version != "" {
				version = ef.Version
			}
			for i := range ef.KEV {
				c := normCVE(ef.KEV[i].CVE)
				if c == "" {
					continue
				}
				ef.KEV[i].CVE = c
				kev[c] = ef.KEV[i]
			}
			for i := range ef.EPSS {
				c := normCVE(ef.EPSS[i].CVE)
				if c == "" {
					continue
				}
				epss[c] = ef.EPSS[i].Score
			}
			intelLog.Info("外部情报文件已合并", "file", f.Name(), "kev", len(ef.KEV), "epss", len(ef.EPSS))
		}
	}

	intelKEV, intelEPSS, intelVersion, intelLoaded = kev, epss, version, true
}

// ensureIntel 确保情报集已加载(首次调用自动加载, 只加载一次)
func ensureIntel() {
	intelMu.Lock()
	if !intelLoaded {
		loadIntelLocked()
	}
	intelMu.Unlock()
}

// RefreshIntel 强制重新加载情报集(内置 + 外部 intel/ 目录), 返回
// (KEV 条数, EPSS 条数), 供外部目录更新后手动热刷新。
func RefreshIntel() (int, int) {
	intelMu.Lock()
	loadIntelLocked()
	n, m := len(intelKEV), len(intelEPSS)
	intelMu.Unlock()
	return n, m
}

// IsKEV 查询 CVE 是否在 KEV(已知被利用漏洞)目录中。
func IsKEV(cve string) (KEVEntry, bool) {
	ensureIntel()
	intelMu.RLock()
	defer intelMu.RUnlock()
	e, ok := intelKEV[normCVE(cve)]
	return e, ok
}

// KEVCount 返回 KEV 条目数
func KEVCount() int {
	ensureIntel()
	intelMu.RLock()
	defer intelMu.RUnlock()
	return len(intelKEV)
}

// KEVList 返回全部 KEV 条目(副本)
func KEVList() []KEVEntry {
	ensureIntel()
	intelMu.RLock()
	defer intelMu.RUnlock()
	out := make([]KEVEntry, 0, len(intelKEV))
	for _, e := range intelKEV {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DateAdded > out[j].DateAdded })
	return out
}

// EPSSScore 查询 CVE 的 EPSS 分值(0-1); 未知 CVE 返回 (0, false)
func EPSSScore(cve string) (float64, bool) {
	ensureIntel()
	intelMu.RLock()
	defer intelMu.RUnlock()
	s, ok := intelEPSS[normCVE(cve)]
	return s, ok
}

// EPSSList 返回全部 EPSS 分值条目(按分值降序, 副本)
func EPSSList() []EPSSEntry {
	ensureIntel()
	intelMu.RLock()
	defer intelMu.RUnlock()
	out := make([]EPSSEntry, 0, len(intelEPSS))
	for c, s := range intelEPSS {
		out = append(out, EPSSEntry{CVE: c, Score: s})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// IntelVersion 返回情报集版本(内置/外部)
func IntelVersion() string {
	ensureIntel()
	intelMu.RLock()
	defer intelMu.RUnlock()
	return intelVersion
}

// ===== 模板优先级(KEV 标记 + EPSS 分值) =====

// SeverityRank 严重级别排序权重(大 = 高)
func SeverityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// TemplateCVEs 提取模板关联的 CVE 号集合(info.cve / info.cves, 大写去重)
func TemplateCVEs(r *Rule) []string {
	if r == nil || r.Info == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range append(append([]string(nil), r.Info.Cve...), r.Info.Cves...) {
		c = normCVE(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// RulePriorityInfo 单条模板的优先级画像(KEV 标记 + EPSS + 严重级别)
type RulePriorityInfo struct {
	KEV      bool    `json:"kev"`                 // 是否命中 KEV(已知被利用)
	KEVCVE   string  `json:"kevcve,omitempty"`    // 命中的 KEV CVE(按 EPSS 降序取第一个)
	KEVDate  string  `json:"kevedate,omitempty"`  // KEV 目录收录日期
	EPSS     float64 `json:"epss"`                // 模板全部 CVE 的最高 EPSS 分值
	Severity string  `json:"severity"`            // 模板声明的严重级别
}

// RulePriorityInfoOf 计算单条模板的优先级画像(nil 安全)
func RulePriorityInfoOf(r *Rule) RulePriorityInfo {
	info := RulePriorityInfo{Severity: ""}
	if r == nil {
		return info
	}
	if r.Info != nil {
		info.Severity = r.Info.Severity
	}
	var maxEPSS float64
	var bestKEV KEVEntry
	foundKEV := false
	for _, c := range TemplateCVEs(r) {
		if s, ok := EPSSScore(c); ok && s > maxEPSS {
			maxEPSS = s
		}
		if e, ok := IsKEV(c); ok {
			if !foundKEV || sGreater(e, bestKEV) {
				bestKEV, foundKEV = e, true
			}
		}
	}
	if foundKEV {
		info.KEV, info.KEVCVE, info.KEVDate = true, bestKEV.CVE, bestKEV.DateAdded
	}
	info.EPSS = maxEPSS
	return info
}

// sGreater 两个 KEV 条目按 EPSS 分值比较(分值高者优先; 无 EPSS 按收录日期)
func sGreater(a, b KEVEntry) bool {
	as, aok := EPSSScore(a.CVE)
	bs, bok := EPSSScore(b.CVE)
	if aok || bok {
		if aok && bok && as != bs {
			return as > bs
		}
		if aok != bok {
			return aok
		}
	}
	return a.DateAdded > b.DateAdded
}

// PrioritizeRules 返回按优先级重排序后的规则列表副本(不修改入参):
//
//	1. KEV(已知被利用)模板排在最前 —— 高危漏洞优先执行验证
//	2. EPSS 分值降序(利用可能性高的优先)
//	3. 严重级别降序(critical > high > medium > low > info)
//	4. ID 升序(同分稳定可复现)
//
// 空列表/nil 原样返回; 排序是纯函数, 不影响规则集缓存。
func PrioritizeRules(rules []Rule) []Rule {
	if len(rules) <= 1 {
		return rules
	}
	// 规则与优先级 key 绑定为对后整体排序(key 随元素移动, 不能按索引分离)
	type item struct {
		rule Rule
		kev  int     // 0 = KEV, 1 = 非 KEV
		eps  float64 // 最高 EPSS
		sev  int     // 严重级别权重
	}
	items := make([]item, len(rules))
	for i, r := range rules {
		pi := RulePriorityInfoOf(&r)
		it := item{rule: r, kev: 1, eps: pi.EPSS, sev: SeverityRank(pi.Severity)}
		if pi.KEV {
			it.kev = 0
		}
		items[i] = it
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.kev != b.kev {
			return a.kev < b.kev
		}
		if a.eps != b.eps {
			return a.eps > b.eps
		}
		if a.sev != b.sev {
			return a.sev > b.sev
		}
		return a.rule.ID < b.rule.ID
	})
	out := make([]Rule, len(items))
	for i := range items {
		out[i] = items[i].rule
	}
	return out
}
