//go:build !windows || windows

// cpe.go CPE 版本比对模块(vuln.go 漏洞引擎增强, 用于主机漏洞检测)。
//
// 设计:
//   - CPE 字典 = "产品 -> CVE 列表(版本约束 + CVSS)", 源自 NVD CPE 字典与 CVE 数据的精选子集
//   - 内置 cpe_builtin.json 编译进 exe(//go:embed)作兜底; exe 同目录 cpe/*.json 热更新:
//     重跑 LoadCPEDictionary 即生效, 同 CPE 外部条目覆盖内置
//   - 版本比较 CompareVersions 为语义版本(预发布/构建元数据/缺省段);
//     版本约束支持 < <= > >= 子句(逗号内 AND), 多条约束之间 OR
//   - MatchCPE(product, version) 返回命中 CVE 列表与 CVSS, 结果兼容 Finding,
//     可直接并入漏洞列表; 与 vuln.go 的 vuln_builtin.json 规则共存
//     (LoadVulnLibrary 联动加载, 原规则逻辑零改动)
package scanner

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

//go:embed cpe_builtin.json
var builtinCPEJSON []byte

// ===== CPE 字典数据模型 =====

// CPEProduct CPE 字典中的一个产品条目(对应 NVD CPE 字典的 vendor:product)
type CPEProduct struct {
	CPE     string    `json:"cpe"`     // cpe:2.3:a:nginx:nginx
	Vendor  string    `json:"vendor"`  // nginx
	Product string    `json:"product"` // nginx
	Aliases []string  `json:"aliases,omitempty"`
	CVEs    []CPEVuln `json:"cves"` // 该产品的 CVE 列表
}

// CPEVuln CPE 字典中的一条 CVE(版本约束 + CVSS)
type CPEVuln struct {
	CVE         string   `json:"cve"`
	Title       string   `json:"title,omitempty"`
	CVSS        float64  `json:"cvss"`                  // CVSS v3 基础分 (0-10)
	Constraints []string `json:"constraints,omitempty"` // 约束 OR; 每条为子句 AND(如 ">= 2.4.49, < 2.4.50"); 空=全部版本受影响

	parsed []*VersionConstraint // 非 JSON 字段: 预解析的约束
}

// CPEMatch 单个产品的 CPE 匹配结果
type CPEMatch struct {
	CPE     string    `json:"cpe"`
	Vendor  string    `json:"vendor"`
	Product string    `json:"product"`
	Version string    `json:"version"`
	CVEs    []CPEVuln `json:"cves"`
}

// ===== 语义版本比较 =====

// CompareVersions 语义版本比较, 返回 -1/0/1 (a<b / a==b / a>b)。
//
// 规则:
//   - 按 . _ 分段; 数字段按数值比较(1.9 < 1.10), 非数字段按字典序
//   - 缺省段按 0 处理(1.18 == 1.18.0)
//   - 预发布版小于同版本正式版(1.0.0-rc1 < 1.0.0); 构建元数据(+xxx)忽略
//   - 数字段优先级低于非数字段(8.2 < 8.2p1)
//   - 前导 v/V 忽略(v2.4.41 == 2.4.41)
func CompareVersions(a, b string) int {
	ca, pa := splitVer(a)
	cb, pb := splitVer(b)
	for i := 0; i < len(ca) || i < len(cb); i++ {
		var sa, sb string
		if i < len(ca) {
			sa = ca[i]
		}
		if i < len(cb) {
			sb = cb[i]
		}
		if sa == "" {
			sa = "0"
		}
		if sb == "" {
			sb = "0"
		}
		na, aNum := toIntSeg(sa)
		nb, bNum := toIntSeg(sb)
		if aNum && bNum {
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			continue
		}
		if aNum != bNum {
			// 语义化版本规则: 数字标识符优先级低于非数字标识符
			if aNum {
				return -1
			}
			return 1
		}
		if sa != sb {
			if sa < sb {
				return -1
			}
			return 1
		}
	}
	// core 相等 -> 比较预发布段: 正式版 > 预发布版; 预发布段更多者更大
	if len(pa) == 0 && len(pb) == 0 {
		return 0
	}
	if len(pa) == 0 {
		return 1
	}
	if len(pb) == 0 {
		return -1
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x == "" {
			x = "0"
		}
		if y == "" {
			y = "0"
		}
		nx, xNum := toIntSeg(x)
		ny, yNum := toIntSeg(y)
		if xNum && yNum {
			if nx != ny {
				if nx < ny {
					return -1
				}
				return 1
			}
			continue
		}
		if xNum != yNum {
			if xNum {
				return -1
			}
			return 1
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// splitVer 把版本串拆分为 core 段与预发布段
func splitVer(v string) (core, pre []string) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	// 构建元数据(+xxx)忽略
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	// 预发布: 第一个 '-' 之后的部分
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = strings.FieldsFunc(v[i+1:], func(r rune) bool { return r == '.' || r == '_' || r == '-' })
		v = v[:i]
	}
	core = strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '_' })
	return core, pre
}

// toIntSeg 尝试把段解析为整数(空串按 0)
func toIntSeg(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ===== 版本约束(< <= > >=) =====

// VersionConstraint 版本约束: 所有子句的合取(AND)。子句为空 = 匹配所有版本。
type VersionConstraint struct {
	Raw     string
	clauses []verClause
}

// verClause 单个版本子句(运算符 + 版本号)
type verClause struct {
	op  string // < <= > >=
	ver string
}

// ParseVersionConstraint 解析版本约束串。
//
// 格式: 逗号分隔的子句(子句间 AND), 每句为 "<版本" / "<=版本" / ">版本" / ">=版本"。
// 空串返回空约束(匹配所有版本)。
func ParseVersionConstraint(s string) (*VersionConstraint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return &VersionConstraint{Raw: s}, nil
	}
	vc := &VersionConstraint{Raw: s}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var op, ver string
		switch {
		case strings.HasPrefix(part, "<="):
			op, ver = "<=", strings.TrimPrefix(part, "<=")
		case strings.HasPrefix(part, ">="):
			op, ver = ">=", strings.TrimPrefix(part, ">=")
		case strings.HasPrefix(part, "<"):
			op, ver = "<", strings.TrimPrefix(part, "<")
		case strings.HasPrefix(part, ">"):
			op, ver = ">", strings.TrimPrefix(part, ">")
		default:
			return nil, fmt.Errorf("约束子句缺少运算符(< <= > >=): %q", part)
		}
		ver = strings.TrimSpace(ver)
		if ver == "" || !strings.ContainsAny(ver, "0123456789") {
			return nil, fmt.Errorf("约束子句版本号非法(须含数字): %q", part)
		}
		vc.clauses = append(vc.clauses, verClause{op: op, ver: ver})
	}
	if len(vc.clauses) == 0 {
		return &VersionConstraint{Raw: s}, nil
	}
	return vc, nil
}

// Match 判断版本是否满足约束的全部子句
func (vc *VersionConstraint) Match(v string) bool {
	for _, cl := range vc.clauses {
		cmp := CompareVersions(v, cl.ver)
		switch cl.op {
		case "<":
			if cmp >= 0 {
				return false
			}
		case "<=":
			if cmp > 0 {
				return false
			}
		case ">":
			if cmp <= 0 {
				return false
			}
		case ">=":
			if cmp < 0 {
				return false
			}
		}
	}
	return true
}

// parseConstraints 预解析约束串, 返回非法子句的错误信息(空约束 = 全部版本受影响)
func (cv *CPEVuln) parseConstraints() []string {
	var errs []string
	cv.parsed = make([]*VersionConstraint, 0, len(cv.Constraints))
	for _, c := range cv.Constraints {
		pc, err := ParseVersionConstraint(c)
		if err != nil {
			errs = append(errs, cv.CVE+": "+err.Error())
			continue
		}
		cv.parsed = append(cv.parsed, pc)
	}
	return errs
}

// MatchVersion 判断版本是否在该 CVE 的受影响范围内。
// 空约束表示全部版本受影响(如 EOL 产品); 多条约束任一命中即受影响(OR)。
func (cv *CPEVuln) MatchVersion(ver string) bool {
	if len(cv.parsed) == 0 {
		return true
	}
	for _, pc := range cv.parsed {
		if pc.Match(ver) {
			return true
		}
	}
	return false
}

// ConstraintText 受影响版本约束的可读文本
func (cv CPEVuln) ConstraintText() string {
	if len(cv.Constraints) == 0 {
		return "全部版本"
	}
	return strings.Join(cv.Constraints, " 或 ")
}

// ===== CVSS 与 Finding 兼容 =====

// CVSSSeverity 把 CVSS v3 基础分映射到报告严重级别域(critical 9.0+ 并入 high)
func CVSSSeverity(score float64) string {
	switch {
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0.0:
		return "low"
	default:
		return "info"
	}
}

// Findings 把匹配结果转成 CVE 发现列表(兼容 Finding, 可直接并入漏洞列表;
// CPE/CVE/CVSS 证据在 Detail 中, 前端可提取)
func (m CPEMatch) Findings() []Finding {
	out := make([]Finding, 0, len(m.CVEs))
	for _, cv := range m.CVEs {
		detail := fmt.Sprintf("%s %s 受影响版本约束: %s, CVSS %s",
			m.Product, m.Version, cv.ConstraintText(), strconv.FormatFloat(cv.CVSS, 'f', 1, 64))
		if cv.Title != "" {
			detail = cv.Title + " —— " + detail
		}
		out = append(out, Finding{
			Severity: CVSSSeverity(cv.CVSS),
			Title:    fmt.Sprintf("%s %s 已知漏洞 %s", m.Product, m.Version, cv.CVE),
			Detail:   detail,
			Fix:      fixCVEUpgrade,
		})
	}
	return out
}

// ===== 字典加载(内置兜底 + 外部热更新) =====

type cpeFile struct {
	Version  string       `json:"version"`
	Products []CPEProduct `json:"products"`
}

var (
	cpeMu       sync.RWMutex
	cpeProducts []CPEProduct
	cpeCVECount int
)

// cpeExternalDir 外部 CPE 字典目录覆盖(空 = exe 同目录 cpe/), 测试用
var cpeExternalDir = ""

func cpeDir() string {
	if cpeExternalDir != "" {
		return cpeExternalDir
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "cpe")
	}
	return "cpe"
}

// cpeKey 字典条目合并键(小写 CPE; 缺省时 vendor:product)
func cpeKey(p CPEProduct) string {
	if c := strings.ToLower(strings.TrimSpace(p.CPE)); c != "" {
		return c
	}
	return strings.ToLower(strings.TrimSpace(p.Vendor)) + ":" + strings.ToLower(strings.TrimSpace(p.Product))
}

// LoadCPEDictionary 加载 CPE 漏洞字典: 内置(编译进 exe) + 外部 cpe/*.json(热更新)。
//
// 合并规则: 同 CPE 时外部覆盖内置(支持字典增量/热更新, 无需重新编译);
// 新 CPE 追加。无效条目(缺 cve 号/约束非法)只记日志, 不中断加载。
// 可在任意时机调用, 再次调用即重新加载最新外部文件(热更新入口)。
// 返回 (CVE 条目数, 错误列表)。
func LoadCPEDictionary() (int, []string) {
	var errs []string
	base := map[string]CPEProduct{}
	var order []string
	add := func(prod CPEProduct) {
		k := cpeKey(prod)
		if _, ok := base[k]; !ok {
			order = append(order, k)
		}
		base[k] = prod
	}

	// 1. 内置字典(兜底)
	var bf cpeFile
	if err := json.Unmarshal(builtinCPEJSON, &bf); err != nil {
		errs = append(errs, "内置 CPE 字典解析失败: "+err.Error())
	} else {
		for _, p := range bf.Products {
			add(p)
		}
	}

	// 2. 外部 cpe/ 目录(热更新, 覆盖内置)
	if files, err := os.ReadDir(cpeDir()); err == nil {
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
				continue
			}
			data, rerr := os.ReadFile(filepath.Join(cpeDir(), f.Name()))
			if rerr != nil {
				errs = append(errs, f.Name()+": 读取失败 "+rerr.Error())
				continue
			}
			var ef cpeFile
			if uerr := json.Unmarshal(data, &ef); uerr != nil {
				errs = append(errs, f.Name()+": JSON 解析失败 "+uerr.Error())
				continue
			}
			for _, p := range ef.Products {
				add(p)
			}
		}
	}

	// 3. 预解析约束 + 过滤无效条目
	var prods []CPEProduct
	total := 0
	for _, k := range order {
		prod := base[k]
		if strings.TrimSpace(prod.Product) == "" {
			errs = append(errs, "CPE 条目缺少 product: "+k)
			continue
		}
		var valid []CPEVuln
		for i := range prod.CVEs {
			if strings.TrimSpace(prod.CVEs[i].CVE) == "" {
				errs = append(errs, k+": CVE 条目缺少 cve 号")
				continue
			}
			errs = append(errs, prod.CVEs[i].parseConstraints()...)
			valid = append(valid, prod.CVEs[i])
		}
		if len(valid) == 0 {
			continue
		}
		prod.CVEs = valid
		total += len(valid)
		prods = append(prods, prod)
	}

	cpeMu.Lock()
	cpeProducts = prods
	cpeCVECount = total
	cpeMu.Unlock()
	return total, errs
}

// CPEProductCount 已加载的 CPE 产品数
func CPEProductCount() int {
	cpeMu.RLock()
	defer cpeMu.RUnlock()
	return len(cpeProducts)
}

// CPEVulnCount 已加载的 CPE CVE 条目数
func CPEVulnCount() int {
	cpeMu.RLock()
	defer cpeMu.RUnlock()
	return cpeCVECount
}

// ===== 匹配入口 =====

// cpeProductMatch 归一化产品键是否命中 CPE 产品(产品名或别名, 大小写不敏感)
func cpeProductMatch(p CPEProduct, key string) bool {
	if strings.EqualFold(strings.TrimSpace(p.Product), key) {
		return true
	}
	for _, a := range p.Aliases {
		if strings.EqualFold(strings.TrimSpace(a), key) {
			return true
		}
	}
	return false
}

// MatchCPE 按服务产品 + 版本匹配 CPE 条目, 返回命中的产品及其 CVE 列表(含 CVSS)。
//
// product 会经 productKey 归一化(如 "Apache httpd" -> "apache");
// version 为纯版本号(如 "1.18.0", 与 BuildServiceAssets 输出一致)。
// 任一输入为空返回 nil。
func MatchCPE(product, version string) []CPEMatch {
	p := productKey(strings.TrimSpace(product))
	v := strings.TrimSpace(version)
	if p == "" || v == "" {
		return nil
	}
	cpeMu.RLock()
	prods := cpeProducts
	cpeMu.RUnlock()

	var out []CPEMatch
	for _, cp := range prods {
		if !cpeProductMatch(cp, p) {
			continue
		}
		var hits []CPEVuln
		for _, cv := range cp.CVEs {
			if cv.MatchVersion(v) {
				hits = append(hits, cv)
			}
		}
		if len(hits) > 0 {
			out = append(out, CPEMatch{CPE: cp.CPE, Vendor: cp.Vendor, Product: cp.Product, Version: v, CVEs: hits})
		}
	}
	return out
}
