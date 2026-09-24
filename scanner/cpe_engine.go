//go:build !windows || windows

// cpe_engine.go CPE 主机漏洞引擎(版本匹配型检测 + 体积优化)。
//
// 设计(不改动 cpe.go 核心逻辑):
//   - 版本比较与字典核心在 cpe.go: 双模式 CPE 库 = 内置精简版 + 外部完整版
//     (cpe/ 目录, 热更新, 同 CPE 外部覆盖内置)。
//   - 内置精简版体积优化: cpe_builtin.json.gz(gzip 压缩嵌入, 只保留核心字段
//     cpe/vendor/product/aliases/cve/title/cvss/constraints, 无冗余字段),
//     启动时内存解压(不生成临时文件); 压缩包不可用时降级为 cpe.go 的原始嵌入。
//   - 外部 cpe/ 目录按需加载: 仅在 RefreshCPE / LoadExternalCPE 调用时读取,
//     目录不存在则只用内置资源, 无缝降级。
//   - 本文件提供引擎门面: 统一结构化结果(CPEEngineMatch)、"版本匹配型"标记、
//     逐 CVE 描述与修复建议、扩展约束语法(在 cpe.go 四元比较运算符基础上增加 ==)、
//     体积统计(CPEBuiltinSize)。
//   - 版本匹配型(MatchTypeVersion): CVE 命中仅依据"产品版本落在受影响范围",
//     未做主动验证 —— 报告/前端须与实际验证型(MatchTypeVerified, 由 host.go
//     主动探测产出, 如 Redis 未授权 PING 通)明确区分。
//   - 产品别名映射: 复用 cpe.go 的 Aliases(aliases 字段)与 host.go 的
//     productKeyMap(同包直接复用, 不重复维护)。
//   - MatchCPE(product, version) 已在 cpe.go 中定义(同包不可重复声明),
//     本模块的入口为 MatchCPEEngine: 内部调用 MatchCPE 并转结构化结果。
//
// 依赖: 仅 Go 标准库。
package scanner

import (
	_ "embed" // go:embed cpe_builtin.json.gz -> builtinCPEGZ
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// cpeEngineLog 组件日志
var cpeEngineLog = slog.Default().With("component", "cpe-engine")

//go:embed cpe_builtin.json.gz
var builtinCPEGZ []byte

// 匹配类型标记(与 host.go 的"实际验证型"发现区分)
const (
	// MatchTypeVersion 版本匹配型: 依据版本约束命中, 未主动验证(CPE 引擎输出均为此类型)
	MatchTypeVersion = "version"
	// MatchTypeVerified 实际验证型: 扫描引擎主动探测确认(由 host.go 等模块单独产出)
	MatchTypeVerified = "verified"
)

// CPEEngineCVE 引擎结果中的单条 CVE(编号、CVSS、描述、修复建议)
type CPEEngineCVE struct {
	ID             string  `json:"id"`             // CVE 编号, 如 CVE-2021-23017
	Description    string  `json:"description"`    // 漏洞描述(标题 + 受影响版本约束 + CVSS)
	CVSS           float64 `json:"cvss"`           // CVSS v3 基础分 (0-10)
	Fix            string  `json:"fix"`            // 修复建议(缺省: 升级到官方修复版本)
	VersionMatched bool    `json:"versionMatched"` // 版本匹配型标记: true = 基于版本约束命中, 未实际验证
}

// CPEEngineMatch 引擎对单个产品的匹配结果
type CPEEngineMatch struct {
	Product   string         `json:"product"`   // 产品名(字典内规范名)
	Vendor    string         `json:"vendor"`    // 厂商
	Version   string         `json:"version"`   // 输入的版本号
	MatchType string         `json:"matchType"` // MatchTypeVersion / MatchTypeVerified
	CVEs      []CPEEngineCVE `json:"cves"`      // 命中的 CVE 列表
}

// cpeCVEDescription 构造 CVE 描述文本: 标题(若有) + 受影响版本约束 + CVSS
func cpeCVEDescription(cv CPEVuln) string {
	base := fmt.Sprintf("受影响版本约束: %s, CVSS %s",
		cv.ConstraintText(), strconv.FormatFloat(cv.CVSS, 'f', 1, 64))
	if strings.TrimSpace(cv.Title) != "" {
		return cv.Title + " (" + base + ")"
	}
	return fmt.Sprintf("%s %s", cv.CVE, base)
}

// MatchCPEEngine 按产品 + 版本匹配 CPE 引擎, 返回结构化结果。
//
// product 先经 NormalizeProduct 归一化(别名映射, 如 "Apache httpd" -> "apache");
// version 为纯版本号(如 "1.18.0")。任一输入为空返回 nil。
// 所有输出均标记 MatchTypeVersion(版本匹配型): 表示"该版本落在已知 CVE 受影响范围",
// 未做主动验证; 需并入主机扫描结果时用 Findings() 转 Finding(标题/详情已注明类型)。
func MatchCPEEngine(product, version string) []CPEEngineMatch {
	ms := MatchCPE(product, version)
	if len(ms) == 0 {
		return nil
	}
	out := make([]CPEEngineMatch, 0, len(ms))
	for _, m := range ms {
		em := CPEEngineMatch{
			Product:   m.Product,
			Vendor:    m.Vendor,
			Version:   m.Version,
			MatchType: MatchTypeVersion,
			CVEs:      make([]CPEEngineCVE, 0, len(m.CVEs)),
		}
		for _, cv := range m.CVEs {
			em.CVEs = append(em.CVEs, CPEEngineCVE{
				ID:             cv.CVE,
				Description:    cpeCVEDescription(cv),
				CVSS:           cv.CVSS,
				Fix:            fixCVEUpgrade,
				VersionMatched: true,
			})
		}
		out = append(out, em)
	}
	return out
}

// Findings 把引擎匹配结果转为 Finding 列表(可直接并入主机扫描结果)。
// 标题与详情显式标注"版本匹配型", 与实际验证型发现区分。
func (m CPEEngineMatch) Findings() []Finding {
	out := make([]Finding, 0, len(m.CVEs))
	for _, cv := range m.CVEs {
		out = append(out, NewFinding(
			CVSSSeverity(cv.CVSS),
			fmt.Sprintf("[%s %s] 已知漏洞 %s (版本匹配型, 未实际验证)", m.Product, m.Version, cv.ID),
			cv.Description,
			cv.Fix,
		))
	}
	return out
}

// ===== 版本约束(支持 < <= > >= ==) =====

// CPEConstraint 版本约束: 全部子句的合取(AND)。
// 相比 cpe.go 的 VersionConstraint(仅 < <= > >=), 扩展支持 == 精确版本匹配;
// 不使用 == 时可直接用 cpe.go 的 ParseVersionConstraint。
type CPEConstraint struct {
	Raw     string
	clauses []cpeClause
}

// cpeClause 单个版本子句(运算符 + 版本号)
type cpeClause struct {
	op  string // < <= > >= ==
	ver string
}

// ParseCPEConstraint 解析版本约束串。
//
// 格式: 逗号分隔的子句(子句间 AND), 每句为 "<版本" / "<=版本" / ">版本" /
// ">=版本" / "==版本"。空串返回空约束(匹配所有版本)。
// 版本号比较复用 cpe.go 的 CompareVersions(语义版本: 缺省段/预发布/构建元数据/
// 前导 v 等主流版本格式)。
func ParseCPEConstraint(s string) (*CPEConstraint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return &CPEConstraint{Raw: s}, nil
	}
	c := &CPEConstraint{Raw: s}
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
		case strings.HasPrefix(part, "=="):
			op, ver = "==", strings.TrimPrefix(part, "==")
		case strings.HasPrefix(part, "<"):
			op, ver = "<", strings.TrimPrefix(part, "<")
		case strings.HasPrefix(part, ">"):
			op, ver = ">", strings.TrimPrefix(part, ">")
		default:
			return nil, fmt.Errorf("约束子句缺少运算符(< <= > >= ==): %q", part)
		}
		ver = strings.TrimSpace(ver)
		if ver == "" || !strings.ContainsAny(ver, "0123456789") {
			return nil, fmt.Errorf("约束子句版本号非法(须含数字): %q", part)
		}
		c.clauses = append(c.clauses, cpeClause{op: op, ver: ver})
	}
	if len(c.clauses) == 0 {
		return &CPEConstraint{Raw: s}, nil
	}
	return c, nil
}

// Match 判断版本是否满足约束的全部子句(AND)
func (c *CPEConstraint) Match(v string) bool {
	for _, cl := range c.clauses {
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
		case "==":
			if cmp != 0 {
				return false
			}
		}
	}
	return true
}

// MatchAnyConstraint 判断版本是否命中任一条约束(OR 语义)。
// 约束列表为空表示全部版本受影响, 返回 true; 非法约束子句忽略(按未命中处理)。
func MatchAnyConstraint(v string, constraints []string) bool {
	if len(constraints) == 0 {
		return true
	}
	for _, cs := range constraints {
		c, err := ParseCPEConstraint(cs)
		if err != nil {
			continue
		}
		if c.Match(v) {
			return true
		}
	}
	return false
}

// ===== 双模式 CPE 库: 内置精简版(embed) + 外部完整版(cpe/ 目录) =====

// LoadExternalCPE 读取并解析外部完整版 CPE 库(cpe/*.json, 默认 exe 同目录)。
//
// 只读操作: 不修改全局字典状态(全局状态由 cpe.go 的 LoadCPEDictionary 管理);
// 返回值可独立用于预校验、对比或外部库检查。
// dir 为空使用默认 cpe/ 目录; 返回 (产品列表, 告警列表);
// 无效条目(缺 product / 缺 cve 号 / 约束非法)只记告警, 不中断加载。
func LoadExternalCPE(dir string) ([]CPEProduct, []string) {
	if strings.TrimSpace(dir) == "" {
		dir = cpeDir()
	}
	var prods []CPEProduct
	var warns []string
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, []string{"外部 CPE 目录不存在或不可读: " + dir}
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, f.Name()))
		if rerr != nil {
			warns = append(warns, f.Name()+": 读取失败 "+rerr.Error())
			continue
		}
		var ef cpeFile
		if uerr := json.Unmarshal(data, &ef); uerr != nil {
			warns = append(warns, f.Name()+": JSON 解析失败 "+uerr.Error())
			continue
		}
		for _, p := range ef.Products {
			if strings.TrimSpace(p.Product) == "" {
				warns = append(warns, f.Name()+": CPE 条目缺少 product, 跳过")
				continue
			}
			var valid []CPEVuln
			for i := range p.CVEs {
				if strings.TrimSpace(p.CVEs[i].CVE) == "" {
					warns = append(warns, f.Name()+": CVE 条目缺少 cve 号, 跳过")
					continue
				}
				warns = append(warns, p.CVEs[i].parseConstraints()...)
				valid = append(valid, p.CVEs[i])
			}
			if len(valid) == 0 {
				continue
			}
			p.CVEs = valid
			prods = append(prods, p)
		}
	}
	return prods, warns
}

// ===== 内置精简版: gzip 压缩嵌入(内存解压, 不生成临时文件) =====

var (
	cpeGZOnce  sync.Once
	cpeGZData  []byte      // 解压后的内置 JSON 原文(体积统计用)
	cpeGZProds []CPEProduct // 校验后的内置产品列表
	cpeGZErrs  []string
	cpeGZValid bool
)

// cpeBuiltinGZ 解压(内存, 无临时文件)并解析 gzip 压缩的内置精简 CPE 库, 结果缓存。
// 嵌入缺失/损坏时返回 ok=false, 由 RefreshCPE 降级处理。
func cpeBuiltinGZ() ([]CPEProduct, []string, bool) {
	cpeGZOnce.Do(func() {
		data, err := gunzipBytes(builtinCPEGZ)
		if err != nil {
			cpeGZErrs = []string{"内置 CPE gzip 库解压失败: " + err.Error()}
			return
		}
		var ef cpeFile
		if err := json.Unmarshal(data, &ef); err != nil {
			cpeGZErrs = []string{"内置 CPE gzip 库 JSON 解析失败: " + err.Error()}
			return
		}
		var warns []string
		for _, p := range ef.Products {
			if strings.TrimSpace(p.Product) == "" {
				warns = append(warns, "内置 CPE 条目缺少 product, 跳过")
				continue
			}
			var valid []CPEVuln
			for i := range p.CVEs {
				if strings.TrimSpace(p.CVEs[i].CVE) == "" {
					warns = append(warns, "内置 CPE CVE 条目缺少 cve 号, 跳过")
					continue
				}
				warns = append(warns, p.CVEs[i].parseConstraints()...)
				valid = append(valid, p.CVEs[i])
			}
			if len(valid) == 0 {
				continue
			}
			p.CVEs = valid
			cpeGZProds = append(cpeGZProds, p)
		}
		cpeGZData, cpeGZErrs, cpeGZValid = data, warns, len(cpeGZProds) > 0
	})
	return cpeGZProds, cpeGZErrs, cpeGZValid
}

// mergeCPEToGlobal 合并内置产品列表与外部 cpe/ 目录(同 CPE 外部覆盖内置),
// 校验后写入全局字典(与 LoadCPEDictionary 数据流等价, 仅内置来源为 gzip 嵌入)。
// 写入后 MatchCPE / MatchCPEEngine 透明可用, 不改变匹配逻辑。
func mergeCPEToGlobal(builtins []CPEProduct, warns []string) (int, []string) {
	all := append([]string(nil), warns...)
	base := map[string]CPEProduct{}
	var order []string
	add := func(prod CPEProduct) {
		k := cpeKey(prod)
		if _, ok := base[k]; !ok {
			order = append(order, k)
		}
		base[k] = prod
	}
	for _, p := range builtins {
		add(p)
	}
	// 外部 cpe/ 目录(完整版热更新; 不存在则跳过, 只用内置)
	if files, err := os.ReadDir(cpeDir()); err == nil {
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
				continue // 只认 .json; .json.gz 属在线更新暂存态, 不直接生效
			}
			data, rerr := os.ReadFile(filepath.Join(cpeDir(), f.Name()))
			if rerr != nil {
				all = append(all, f.Name()+": 读取失败 "+rerr.Error())
				continue
			}
			var ef cpeFile
			if uerr := json.Unmarshal(data, &ef); uerr != nil {
				all = append(all, f.Name()+": JSON 解析失败 "+uerr.Error())
				continue
			}
			for _, p := range ef.Products {
				add(p)
			}
		}
	}
	var prods []CPEProduct
	total := 0
	for _, k := range order {
		prod := base[k]
		if strings.TrimSpace(prod.Product) == "" {
			all = append(all, "CPE 条目缺少 product: "+k)
			continue
		}
		var valid []CPEVuln
		for i := range prod.CVEs {
			if strings.TrimSpace(prod.CVEs[i].CVE) == "" {
				all = append(all, k+": CVE 条目缺少 cve 号")
				continue
			}
			all = append(all, prod.CVEs[i].parseConstraints()...)
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
	return total, all
}

// BuiltinCPESize 内置精简 CPE 库体积统计
type BuiltinCPESize struct {
	GzipBytes int64 `json:"gzipBytes"` // gzip 压缩后大小(exe 内嵌形态)
	RawBytes  int64 `json:"rawBytes"`  // 解压后大小
	Products  int   `json:"products"`  // 产品数
	InMemory  bool  `json:"inMemory"`  // 是否内存解压(不生成临时文件)
}

// CPEBuiltinSize 返回内置精简 CPE 库体积统计(核心字段, 无冗余)
func CPEBuiltinSize() BuiltinCPESize {
	_, _, ok := cpeBuiltinGZ()
	st := BuiltinCPESize{GzipBytes: int64(len(builtinCPEGZ)), InMemory: true}
	if ok {
		st.RawBytes = int64(len(cpeGZData))
		st.Products = len(cpeGZProds)
	}
	return st
}

// RefreshCPE 强制重新加载 CPE 字典, 返回 (CVE 条目数, 告警列表)。
//
// 来源优先级: gzip 压缩内置精简库(embed, 内存解压, 不生成临时文件) +
// 外部 cpe/ 目录(同 CPE 外部覆盖内置, 兼容完整版文件);
// gzip 内置库不可用(为空/损坏)时自动降级为 LoadCPEDictionary(原始嵌入),
// 不影响现有匹配逻辑; cpe/ 文件更新后调用本函数立即热更新, 无需重启。
func RefreshCPE() (int, []string) {
	builtins, gzErrs, ok := cpeBuiltinGZ()
	if !ok {
		cpeEngineLog.Warn("内置 CPE gzip 库不可用, 降级为原始嵌入", "errs", gzErrs)
		return LoadCPEDictionary()
	}
	return mergeCPEToGlobal(builtins, gzErrs)
}

// ===== 产品别名映射 =====

// NormalizeProduct 归一化产品名(别名映射入口): 小写 + productKeyMap 映射
// (如 "Apache httpd" -> "apache", "Microsoft IIS" -> "iis", "OpenResty" -> "openresty");
// 未知产品原样小写返回。CPE 字典匹配时还会叠加每个产品自身的
// Aliases(cpe_builtin.json / cpe/*.json 的 aliases 字段, 如 "ssh" -> openssh)。
func NormalizeProduct(name string) string {
	return productKey(name)
}
