//go:build !windows || windows

// ruleset.go 规则包管理器(三级规则体系 + 体积优化)。
//
// 三级体系(优先级递增, ID 冲突时高优先级覆盖低优先级):
//   1. 内置核心包(builtin): gzip 压缩嵌入 templates_builtin_gz, 启动时内存解压
//      (不生成临时文件, 减小 exe 体积); 压缩包不可用时自动降级为原始嵌入 templates_builtin
//   2. 官方扩展包(official): exe 同目录 vuln/rules/ 目录(递归, 不含 custom/.staging 子目录)
//   3. 用户自定义包(custom): exe 同目录 vuln/rules/custom/ 目录(优先级最高)
//
// 核心行为:
//   - 自动过滤跳过 headless / javascript / network / 非 HTTP 模板, 记录跳过原因, 不中断加载
//   - 读取 rules/ 下 checksum.sha256 做完整性校验(兼容旧格式 templates-checksum.txt),
//     校验失败跳过并告警; 未登记的文件不校验
//   - 提取模板 product 标签(ProductTags), FilterRulesByFingerprint 按服务指纹筛选
//   - 外部资源按需加载: 启动时不扫描、不驻留内存, 首次查询/刷新才读取;
//     外部目录不存在则只用内置资源, 无缝降级
//   - 与原有 vuln_builtin.json 正则规则体系(见 vuln.go)两套并行, 互不干扰:
//     本模块管理 Nuclei 风格模板规则, vuln.go 管理内置正则规则
//   - 体积统计: BuiltinRulesSize 返回内置核心包压缩/解压体积对比
//
// 不修改 nuclei_parser.go / nuclei_builtins.go 的任何逻辑: 复用其 ParseNucleiTemplate、
// LoadBuiltinTemplates、dirFingerprintOf、FilterTemplatesByFingerprint 等同包能力。
package scanner

import (
	"bytes"
	"compress/gzip"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"yugsight/internal/pathrel"
)

// ruleLog 组件日志
var ruleLog = slog.Default().With("component", "ruleset")

// Rule 模板规则(复用 nuclei_parser.go 的 Template 结构, 不重复定义)
type Rule = Template

// 规则来源层级(优先级递增)
const (
	RuleTierBuiltin  = "builtin"  // 一级: 内置核心包(go:embed, 编译进 exe)
	RuleTierOfficial = "official" // 二级: 官方扩展包(exe 同目录 vuln/rules/)
	RuleTierCustom   = "custom"   // 三级: 用户自定义包(exe 同目录 vuln/rules/custom/, 最高优先级)
)

// ===== 目录定位(测试可覆盖) =====

// rulesExternalDir 测试用目录覆盖(空 = exe 同目录 vuln/rules/)
var rulesExternalDir = ""

// rulesOfficialDir 官方扩展包目录。
// 2026-09-24 dist 目录整理: 规则库统一收进 vuln/(旧 "exe 同目录 rules/" 由
// main.go 的 migrateLegacyDirs 启动时一次性迁移)。
func rulesOfficialDir() string {
	if rulesExternalDir != "" {
		return rulesExternalDir
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "vuln", "rules")
	}
	return "vuln/rules"
}

// rulesCustomDir 用户自定义包目录(官方目录下的 custom/ 子目录)
func rulesCustomDir() string {
	return filepath.Join(rulesOfficialDir(), "custom")
}

// relSlash 计算 path 相对 base 的斜杠分隔相对路径; 失败时兜底用文件名
func relSlash(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}

// ===== 完整性校验 =====

// loadRuleChecksums 解析规则包目录下的完整性校验表。
// 优先读取 checksum.sha256(新规范), 缺失时兼容旧格式 templates-checksum.txt。
// 格式(每行): "<64位hex>  <相对路径>", 支持 # 注释行; 文件缺失返回空表(即不校验)。
func loadRuleChecksums(dir string) map[string]string {
	m := make(map[string]string)
	for _, name := range []string{"checksum.sha256", "templates-checksum.txt"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				m[filepath.ToSlash(parts[1])] = strings.ToLower(parts[0])
			}
		}
		if len(m) > 0 {
			break // 取第一个有内容的校验表
		}
	}
	return m
}

// skipReason 判定被跳过模板的原因(headless / javascript / network / 非 HTTP)。
// 仅用于记录原因, 不影响加载流程。
func skipReason(data []byte) string {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil ||
		root.Kind != yaml.DocumentNode || len(root.Content) == 0 ||
		root.Content[0].Kind != yaml.MappingNode {
		return "非 HTTP 模板(无顶层映射), 跳过"
	}
	keys := topLevelKeys(root.Content[0])
	switch {
	case keys["headless"]:
		return "headless 模板, 需浏览器引擎, 本引擎不支持, 跳过"
	case keys["javascript"]:
		return "javascript 模板, 本引擎不支持, 跳过"
	case keys["network"]:
		return "network 模板, 本引擎仅支持 HTTP, 跳过"
	default:
		return "非 HTTP 模板(无 request/requests), 跳过"
	}
}

// ===== 内置核心包: gzip 压缩嵌入(内存解压, 不生成临时文件) =====

//go:embed templates_builtin_gz
var builtinRulesGZFS embed.FS

var (
	builtinGZOnce  sync.Once
	builtinGZCache []Rule
	builtinGZErrs  []string
)

// gunzipBytes 在内存中解压 gzip 字节(不写盘, 不生成临时文件)
func gunzipBytes(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// loadBuiltinRulesGZ 从 gzip 压缩嵌入加载内置核心规则包:
// 逐个 .gz 内存解压后解析, 全程不写盘。返回 (规则列表, 错误列表);
// 嵌入为空或全部失败时返回空列表, 由 LoadBuiltinRules 降级处理。
func loadBuiltinRulesGZ() ([]Rule, []string) {
	var rules []Rule
	var errs []string
	_ = fs.WalkDir(builtinRulesGZFS, "templates_builtin_gz", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".gz") {
			return nil
		}
		data, rerr := builtinRulesGZFS.ReadFile(path)
		if rerr != nil {
			errs = append(errs, path+": 读取失败 "+rerr.Error())
			return nil
		}
		raw, gerr := gunzipBytes(data)
		if gerr != nil {
			errs = append(errs, path+": gzip 解压失败 "+gerr.Error())
			return nil
		}
		tpl, perr := ParseNucleiTemplate(raw)
		if perr != nil {
			errs = append(errs, path+": 解析失败 "+perr.Error())
			return nil
		}
		if tpl == nil {
			errs = append(errs, path+": 非 HTTP 模板, 跳过")
			return nil
		}
		tpl.Builtin = true
		tpl.SHA256 = sha256Hex(raw)
		for _, p := range validateTemplate(tpl) {
			errs = append(errs, path+": matcher 无效: "+p)
		}
		rules = append(rules, *tpl)
		return nil
	})
	return rules, errs
}

// BuiltinSizeStat 内置核心规则包体积统计
type BuiltinSizeStat struct {
	Files          int     `json:"files"`          // 模板数
	RawBytes       int64   `json:"rawBytes"`       // 解压后总字节
	GzipBytes      int64   `json:"gzipBytes"`      // gzip 压缩后总字节(exe 内嵌形态)
	CompressionPct float64 `json:"compressionPct"` // 压缩率(0-1, 压缩掉的比例)
	InMemory       bool    `json:"inMemory"`       // 是否内存解压(不生成临时文件)
}

// BuiltinRulesSize 返回内置核心规则包体积统计(压缩 vs 解压), 供 /api 展示
func BuiltinRulesSize() BuiltinSizeStat {
	st := BuiltinSizeStat{InMemory: true}
	_ = fs.WalkDir(builtinRulesGZFS, "templates_builtin_gz", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".gz") {
			return nil
		}
		b, rerr := builtinRulesGZFS.ReadFile(path)
		if rerr != nil {
			return nil
		}
		st.GzipBytes += int64(len(b))
		if raw, gerr := gunzipBytes(b); gerr == nil {
			st.RawBytes += int64(len(raw))
		}
		st.Files++
		return nil
	})
	if st.RawBytes > 0 {
		st.CompressionPct = float64(st.RawBytes-st.GzipBytes) / float64(st.RawBytes)
	}
	return st
}

// ===== 外部规则包加载 =====

// loadExternalTiers 加载二级(official)与三级(custom)规则包, 结果写入包级变量
// (调用方需持有 rulesMu)。每个文件独立处理: 校验 -> 类型过滤 -> 解析,
// 任一环节失败只记录告警, 不中断整体加载。
func loadExternalTiers() {
	officialDir := rulesOfficialDir()
	customDir := rulesCustomDir()
	checksums := loadRuleChecksums(officialDir)

	if st, err := os.Stat(officialDir); err != nil || !st.IsDir() {
		extWarns = append(extWarns, fmt.Sprintf("官方扩展包目录不存在: %s (降级为仅内置规则)", officialDir))
		// dir 走 pathrel.Short: slog 属性不经过 logLine 的相对化兜底
		ruleLog.Warn("官方扩展包目录不存在, 降级为仅内置规则", "dir", pathrel.Short(officialDir))
		return
	}

	handle := func(path, rel, tier string) {
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			extWarns = append(extWarns, rel+": 读取失败 "+rerr.Error())
			ruleLog.Error("规则读取失败, 跳过", "file", rel, "tier", tier, "err", rerr)
			return
		}
		// sha256 完整性校验(仅当校验表登记了该文件时)
		if want, ok := checksums[rel]; ok {
			if got := sha256Hex(data); got != want {
				extWarns = append(extWarns, rel+": checksum.sha256 校验失败, 跳过(可能已被篡改)")
				ruleLog.Error("规则完整性校验失败, 跳过", "file", rel, "tier", tier, "want", want, "got", got)
				return
			}
		}
		tpl, perr := ParseNucleiTemplate(data)
		if perr != nil {
			extWarns = append(extWarns, rel+": 解析失败 "+perr.Error())
			ruleLog.Error("规则解析失败, 跳过", "file", rel, "tier", tier, "err", perr)
			return
		}
		if tpl == nil {
			reason := skipReason(data)
			extWarns = append(extWarns, rel+": "+reason)
			ruleLog.Info("规则跳过", "file", rel, "tier", tier, "reason", reason)
			return
		}
		tpl.Path = path // 绝对路径: 分级加载按需模板懒加载时据此从磁盘重新解析
		tpl.SHA256 = sha256Hex(data)
		tpl.Builtin = tier == RuleTierBuiltin
		for _, p := range validateTemplate(tpl) {
			extWarns = append(extWarns, rel+": matcher 无效: "+p)
		}
		if tier == RuleTierOfficial {
			extOfficial = append(extOfficial, *tpl)
		} else {
			extCustom = append(extCustom, *tpl)
		}
	}

	// 二级: rules/ 递归(跳过 custom 子目录, 三级单独加载)
	_ = filepath.Walk(officialDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 不中断
		}
		if info.IsDir() {
			base := filepath.Base(path)
			// custom 子目录 = 三级单独加载; .staging 是在线更新的暂存目录, 不并入规则集
			if (path != officialDir && base == "custom") || base == ".staging" {
				return filepath.SkipDir
			}
			return nil
		}
		handle(path, relSlash(officialDir, path), RuleTierOfficial)
		return nil
	})
	// 三级: rules/custom/ 递归(校验表相对路径仍以 rules/ 为基准)
	_ = filepath.Walk(customDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil // 不中断
		}
		handle(path, relSlash(officialDir, path), RuleTierCustom)
		return nil
	})
}

// mergeRules 按优先级合并规则集(custom > official > builtin):
// ID 冲突时高优先级覆盖低优先级, tierOf 记录每个 ID 的最终胜出层级。
func mergeRules(builtin, official, custom []Rule) ([]Rule, map[string]string) {
	out := make([]Rule, 0, len(builtin)+len(official)+len(custom))
	idx := make(map[string]int, len(builtin)+len(official)+len(custom))
	tierOf := make(map[string]string, len(builtin)+len(official)+len(custom))
	add := func(r Rule, tier string) {
		r.Builtin = tier == RuleTierBuiltin
		if i, ok := idx[r.ID]; ok {
			out[i] = r
			tierOf[r.ID] = tier
			return
		}
		idx[r.ID] = len(out)
		tierOf[r.ID] = tier
		out = append(out, r)
	}
	for _, r := range builtin {
		add(r, RuleTierBuiltin)
	}
	for _, r := range official {
		add(r, RuleTierOfficial)
	}
	for _, r := range custom {
		add(r, RuleTierCustom)
	}
	return out, tierOf
}

// ===== 进程级缓存(外部目录指纹热更新) =====

var (
	rulesMu     sync.Mutex
	extLoaded   bool
	extFP       dirFingerprint // 外部目录状态指纹(rules/ 递归, 含 custom/)
	extOfficial []Rule
	extCustom   []Rule
	extMerged   []Rule // 外部两路合并后(custom 覆盖 official), 供 LoadExternalRules
	extWarns    []string
	merged      []Rule               // 三级合并后的完整规则集
	mergedByID  map[string]Rule      // id -> 规则(合并后快照)
	tierOf      map[string]string    // id -> 胜出层级
)

// Rules 返回三级合并后的完整规则集(builtin + official + custom, ID 冲突高优先级胜出)。
// 外部目录状态未变化时命中指纹缓存; 目录增删改后自动重新加载(热更新)。
// 分级加载开启时返回"有效规则集" = 常驻 + 已加载的按需模板(见 ruleset_tiered.go)。
func Rules() ([]Rule, []string) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rulesLocked(false)
	return effectiveRulesLocked(), extWarns
}

// RefreshRules 强制重新加载外部规则包(绕过指纹缓存)并重建合并集,
// 供规则包更新后手动刷新(如 /api 端点), 无需重启程序。
func RefreshRules() ([]Rule, []string) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	return rulesLocked(true)
}

// rulesLocked 加载/刷新三级规则集(调用方需持有 rulesMu):
// force=false 时先比对目录指纹, 未变化直接返回缓存; 变化或强制时重新读盘。
// 目录不存在不写缓存(用户可能稍后放置), 下次调用重试。
func rulesLocked(force bool) ([]Rule, []string) {
	officialDir := rulesOfficialDir()
	fp, okDir := dirFingerprintOf(officialDir)
	if !force && extLoaded && okDir && fp == extFP {
		return merged, extWarns
	}
	if okDir && extLoaded {
		ruleLog.Info("规则包目录状态变化, 热更新重新加载", "dir", pathrel.Short(officialDir))
	}

	extOfficial = nil
	extCustom = nil
	extMerged = nil
	extWarns = nil
	loadExternalTiers()

	builtin, bErrs := LoadBuiltinRules()
	var warns []string
	warns = append(warns, bErrs...)
	warns = append(warns, extWarns...)

	extMerged, _ = mergeRules(nil, extOfficial, extCustom)
	merged, tierOf = mergeRules(builtin, extOfficial, extCustom)
	mergedByID = make(map[string]Rule, len(merged))
	for i := range merged {
		mergedByID[merged[i].ID] = merged[i]
	}
	// 体积分级加载(默认关闭, 见 ruleset_tiered.go): 开启时按需模板解析对象
	// 从常驻集剔除, 仅保留轻量元数据, 扫描时经 LoadOnDemand 按需加载
	splitTiered(&merged, &mergedByID, tierOf)

	if okDir {
		extFP, extLoaded = fp, true
	} else {
		extLoaded = false // 目录缺失: 不缓存, 保留下次重试机会
	}
	return merged, warns
}

// ===== 对外接口 =====

// LoadBuiltinRules 返回一级内置核心包规则(解析一次后缓存)。
// 优先 gzip 压缩嵌入 templates_builtin_gz(启动内存解压, 不生成临时文件,
// 减小 exe 体积); 压缩包不可用(为空/损坏)时自动降级为原始嵌入
// templates_builtin(LoadBuiltinTemplates), 对上层透明, 不影响原有匹配。
// 返回 (规则列表, 错误列表); 单文件失败只记日志不中断整体加载。
func LoadBuiltinRules() ([]Rule, []string) {
	builtinGZOnce.Do(func() {
		rules, errs := loadBuiltinRulesGZ()
		if len(rules) > 0 {
			builtinGZCache, builtinGZErrs = rules, errs
			ruleLog.Info("内置核心规则包加载完成(gzip 内存解压, 无临时文件)",
				"count", len(rules), "gzipBytes", BuiltinRulesSize().GzipBytes)
			return
		}
		ruleLog.Warn("内置 gzip 规则包不可用, 降级为原始嵌入模板", "errs", errs)
		builtinGZCache, builtinGZErrs = LoadBuiltinTemplates()
	})
	return builtinGZCache, builtinGZErrs
}

// LoadExternalRules 返回外部规则包(二级官方 rules/ + 三级自定义 rules/custom/,
// 自定义覆盖官方)。含 checksum.sha256 完整性校验与类型过滤
// (headless/javascript/network/非 HTTP 跳过并记录原因)。
// 目录状态指纹缓存: 未变化命中缓存, 变化自动重新加载(热更新)。
// 返回 (规则列表, 告警列表, 跳过原因也在告警列表中)。
func LoadExternalRules() ([]Rule, []string) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rulesLocked(false)
	out := make([]Rule, len(extMerged))
	copy(out, extMerged)
	return out, extWarns
}

// RuleCount 返回三级合并后的规则总数(分级加载开启时 = 常驻 + 按需模板数)
func RuleCount() int {
	rulesMu.Lock()
	rulesLocked(false)
	n := len(merged) + ondemandMetaCountLocked()
	rulesMu.Unlock()
	return n
}

// GetRuleByID 按 ID 在三级合并规则集中查找规则。
// 首次调用自动触发加载; 未找到返回 (nil, false)。
// 分级加载开启时, 按需模板在首次访问时自动从磁盘懒加载(见 ruleset_tiered.go)。
func GetRuleByID(id string) (*Rule, bool) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rulesLocked(false)
	if r, ok := mergedByID[id]; ok {
		return &r, true
	}
	if n, _ := loadOnDemandLocked(id); n > 0 {
		tierMu.Lock()
		defer tierMu.Unlock()
		if r, ok := working[id]; ok {
			return &r, true
		}
	}
	return nil, false
}

// RuleTier 返回规则 ID 的最终来源层级(builtin / official / custom); 未知 ID 返回空串
func RuleTier(id string) string {
	rulesMu.Lock()
	rulesLocked(false)
	t := tierOf[id]
	rulesMu.Unlock()
	return t
}

// FilterRulesBySeverity 按严重级别筛选规则(不区分大小写, 多值 = 任一命中)。
// sevs 为空表示不过滤, 原样返回。
func FilterRulesBySeverity(rules []Rule, sevs ...string) []Rule {
	want := normTagSet(sevs)
	if len(want) == 0 {
		return rules
	}
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.Info != nil && want[strings.ToLower(strings.TrimSpace(r.Info.Severity))] {
			out = append(out, r)
		}
	}
	return out
}

// FilterRulesByFingerprint 按服务指纹(产品 + 版本)筛选应执行的规则。
// 委托 FilterTemplatesByFingerprint: 通用规则(无产品标签)保留; 产品规则须 product 命中;
// 提供版本且规则带版本约束时, 版本需出现在约束中。
func FilterRulesByFingerprint(rules []Rule, product, ver string) []Rule {
	return FilterTemplatesByFingerprint(rules, product, ver)
}

// ProductTags 提取规则的"产品类"标签(小写, 如 nginx / apache), 用于指纹筛选与统计。
// 通用词(cve / xss / misconfig 等, 见 nuclei_parser.go genericTagWords)不视为产品标记;
// 空切片表示通用规则。
func ProductTags(r *Rule) []string {
	if r == nil {
		return nil
	}
	return r.productTags()
}

// RuleStat 规则集统计(模板三级 + vuln_builtin.json 正则规则, 两套体系并行计数)
type RuleStat struct {
	Builtin   int `json:"builtin"`   // 一级: 内置核心包(合并后胜出计数)
	Official  int `json:"official"`  // 二级: 官方扩展包
	Custom    int `json:"custom"`    // 三级: 用户自定义包
	Total     int `json:"total"`     // 三级合并总数(按 ID 去重)
	VulnRules int `json:"vulnRules"` // vuln_builtin.json + vuln/ 正则规则数(并行体系, 见 vuln.go)
}

// RulesStat 返回当前规则集统计。模板规则(本模块)与正则规则(vuln.go)
// 两套体系并行加载、独立计数, 互不干扰。
func RulesStat() RuleStat {
	rulesMu.Lock()
	rulesLocked(false)
	st := RuleStat{Total: len(merged) + ondemandMetaCountLocked()}
	for _, t := range tierOf {
		switch t {
		case RuleTierBuiltin:
			st.Builtin++
		case RuleTierOfficial:
			st.Official++
		default:
			st.Custom++
		}
	}
	rulesMu.Unlock()
	st.VulnRules = VulnRuleCount()
	return st
}
