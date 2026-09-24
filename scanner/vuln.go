package scanner

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed vuln_builtin.json
var builtinVulnJSON []byte

// 规则适用范围(scope)取值。用于把规则库按打击面归位:
//   - ScopeWeb:  Web 面规则, 只对 HTTP 响应体/响应头/敏感路径生效, 由 web.go 的
//     MatchRules / PathRules 消费
//   - ScopeHost: 主机面规则, 面向端口/服务/版本类检测, 由主机扫描与 CPE 引擎消费
//
// 【为什么需要显式字段而不是靠 type 推导】type(body/header/path) 描述的是"匹配方式",
// 不是"打击面"。同一条 path 规则既可能是 Web 敏感文件, 也可能是主机侧服务路径,
// 两者在漏洞管理里应归入不同列表。用一个独立字段表达, 前端才能按适用范围分组展示。
//
// 约定: 空值不视为"未知", 而是按"未声明 -> 由 type 推导"处理(见 EffectiveScope)。
// 这样既有外部规则文件(vuln/*.json)不改一行也能正常加载, 不需要用户批量补字段。
const (
	ScopeWeb  = "web"  // Web 应用漏洞
	ScopeHost = "host" // 主机/服务漏洞
)

// VulnRule 漏洞规则。type 取值:
//   - body:   Pattern 为正则, 匹配主页面响应体
//   - header: Pattern 为正则, 匹配响应头(格式 "Key: Value\n")
//   - path:   Pattern 为探测路径, 非 404 即视为命中(并入敏感路径探测)
type VulnRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"` // high / medium / low / info
	Type     string `json:"type"`
	Pattern  string `json:"pattern"`
	Detail   string `json:"detail"`
	// Scope 适用范围: web / host(见 ScopeWeb / ScopeHost)。
	// 留空 = 未声明, 加载时由 DefaultScopeForType 按 type 推导后写回本字段,
	// 因此从 /api/vuln/rules 读到的永远是已归一化的值, 不会出现空串。
	Scope string `json:"scope,omitempty"`
	// Source 规则来源: "builtin" = 内置规则(vuln_builtin.json); 其余为外部导入文件名。
	// 不序列化进导入文件(omitempty), 仅用于前端展示"这条规则从哪来"。
	Source string `json:"source,omitempty"`
	// Status 规则验证状态: "" / RuleStatusVerified = 已验证(参与扫描);
	// RuleStatusPending = 待验证(仅文件显式声明该值时: 暂存规则, 靶机测试通过并手动
	// 确认前不参与扫描)。内置规则恒为已验证(可信内置集); 外部/导入/自动转换的规则
	// 默认为已验证(导入即生效, 2026-09-22 口径变更), 显式 pending 的规则可由
	// vuln/verified.json 的已验证 ID 覆盖集提升为已验证。omitempty: 已验证不写文件保持简洁。
	Status string `json:"status,omitempty"`

	re *regexp.Regexp
}

// 规则验证状态取值。
const (
	RuleStatusVerified = "verified" // 已验证: 参与扫描
	RuleStatusPending  = "pending"  // 待验证: 外部来源未经靶机测试, 暂不参与扫描
)

// IsActive 返回该规则是否参与扫描(待验证规则不参与, 避免未验证规则产生误报)。
func (r VulnRule) IsActive() bool { return r.Status != RuleStatusPending }

// EffectiveStatus 归一化展示用的状态: 空串(老文件)按已验证处理, 保持与 IsActive 口径一致。
func (r VulnRule) EffectiveStatus() string {
	if r.Status == RuleStatusPending {
		return RuleStatusPending
	}
	return RuleStatusVerified
}

// DefaultScopeForType 按匹配方式推导默认适用范围(仅用于规则未显式声明 scope 时):
// body / header 只能匹配 HTTP 响应, 天然属 Web 面; path 是路径探测, 归 Web 面。
// 主机面规则(端口/服务/版本)由 CPE 引擎与主机扫描产出, 不来自本规则库,
// 若用户确实要在此声明主机规则, 显式写 "scope":"host" 即可覆盖本推导。
func DefaultScopeForType(typ string) string {
	switch typ {
	case "body", "header", "path":
		return ScopeWeb
	default:
		return ScopeWeb
	}
}

// EffectiveScope 返回规则最终生效的适用范围(已声明优先, 未声明按 type 推导)。
func (r VulnRule) EffectiveScope() string {
	if s := normalizeScope(r.Scope); s != "" {
		return s
	}
	return DefaultScopeForType(r.Type)
}

// normalizeScope 归一化 scope 取值(大小写/空白容错), 非法值返回空串由调用方决定兜底口径。
// 外部规则文件由用户手工编写, 出现 "Web" / " WEB " 这类写法是常态, 这里统一容错,
// 避免"写了 scope 但不生效"这种无从排查的现象。
func normalizeScope(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case ScopeWeb:
		return ScopeWeb
	case ScopeHost:
		return ScopeHost
	default:
		return ""
	}
}

type vulnFile struct {
	Rules []VulnRule `json:"rules"`
}

var (
	vulnMu    sync.RWMutex
	vulnRules []VulnRule
)

// LoadVulnLibrary 加载漏洞库: 内置规则 + exe 同目录 vuln/ 下所有 *.json。
// 返回有效规则数与错误信息列表。重复 ID 以先加载者为准(内置优先)。
func LoadVulnLibrary() (int, []string) {
	var raw []VulnRule
	var errs []string
	// 已验证规则 ID 覆盖集: 用于把显式声明 pending 的暂存规则提升为已验证;
	// 其余外部规则默认已验证(导入即生效)。
	verifiedSet := loadVerifiedSet()
	var bf vulnFile
	if err := json.Unmarshal(builtinVulnJSON, &bf); err != nil {
		errs = append(errs, "内置漏洞库解析失败: "+err.Error())
	} else {
		for i := range bf.Rules {
			bf.Rules[i].Source = "builtin"
		}
		raw = append(raw, bf.Rules...)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exe), "vuln")
		if files, err := os.ReadDir(dir); err == nil {
			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
					continue
				}
				p := filepath.Join(dir, f.Name())
				data, err := os.ReadFile(p)
				if err != nil {
					errs = append(errs, f.Name()+": 读取失败 "+err.Error())
					continue
				}
				var vf vulnFile
				if err := json.Unmarshal(data, &vf); err != nil {
					errs = append(errs, f.Name()+": JSON 解析失败 "+err.Error())
					continue
				}
				for i := range vf.Rules {
					vf.Rules[i].Source = f.Name() // 记录外部来源文件名
				}
				raw = append(raw, vf.Rules...)
			}
		}
	}

	seen := map[string]bool{}
	var valid []VulnRule
	for _, r := range raw {
		if r.ID == "" || r.Name == "" || r.Pattern == "" || r.Type == "" {
			continue
		}
		if r.Severity == "" {
			r.Severity = "info"
		}
		// 适用范围归一化: 未声明按 type 推导后写回, 保证 /api/vuln/rules 永远返回明确值。
		// 显式写了非法值(如 "wang")时记一条告警并按 type 推导, 不整条丢弃 ——
		// scope 只是展示/分组维度, 不是安全判定依据, 不该因为一个展示字段让规则失效。
		if raw := strings.TrimSpace(r.Scope); raw != "" && normalizeScope(raw) == "" {
			errs = append(errs, r.ID+": 未知 scope: "+raw+" (仅支持 web/host, 已按 type 推导)")
		}
		r.Scope = r.EffectiveScope()
		// 验证状态(2026-09-22 口径变更, 用户确认): 内置恒已验证(可信内置集); 外部/导入
		// 规则默认已验证(导入即生效, 加载后直接参与扫描); 仅文件显式声明 status=pending
		// 且尚未人工确认(未命中已验证集)时保持待验证 —— 显式 pending 是"先暂存"的
		// 显式动作, 不再是默认值(旧口径会让所有外部规则静默失效)。
		if r.Source != "builtin" && r.Status == RuleStatusPending && !verifiedSet[r.ID] {
			// 显式待验证且未人工确认: 保持待验证(不参与扫描)
		} else {
			r.Status = RuleStatusVerified
		}
		switch r.Type {
		case "body", "header":
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				errs = append(errs, r.ID+": 正则无效 "+err.Error())
				continue
			}
			r.re = re
		case "path":
			// 路径规则无需编译正则
		default:
			errs = append(errs, r.ID+": 未知 type: "+r.Type)
			continue
		}
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		valid = append(valid, r)
	}

	// CPE 版本比对字典(与漏洞库共存, 供主机漏洞检测):
	// 内置编译进 exe 兜底 + exe 同目录 cpe/*.json 热更新; 加载失败只记日志
	if _, cpeErrs := LoadCPEDictionary(); len(cpeErrs) > 0 {
		errs = append(errs, cpeErrs...)
	}

	vulnMu.Lock()
	vulnRules = valid
	vulnMu.Unlock()
	return len(valid), errs
}

// VulnRuleCount 返回已加载的漏洞规则数量
func VulnRuleCount() int {
	vulnMu.RLock()
	defer vulnMu.RUnlock()
	return len(vulnRules)
}

// PathRules 返回 path 类型规则, 转换为敏感路径探测目标(全量, 不受规则选择影响)
func PathRules() []pathTarget {
	return PathRulesFiltered(nil)
}

// PathRulesFiltered 返回 path 类型规则(受 sel 过滤), 转换为敏感路径探测目标。
// sel 为 nil 时等同于 PathRules(全量); 非 nil 时只保留 ID 在 sel 中的规则。
//
// 【为什么用 map 而非切片】sel 是"本次扫描启用的规则 ID 集合"(见 WebScan 的
// ruleFilter), map 查询 O(1), 规则增多不影响匹配耗时。nil 与"空集"的语义区分
// 由调用方保证: nil = 全启用, 空集 = 不启用任何规则。
func PathRulesFiltered(sel map[string]bool) []pathTarget {
	vulnMu.RLock()
	defer vulnMu.RUnlock()
	var out []pathTarget
	for _, r := range vulnRules {
		if r.Type != "path" || !r.IsActive() {
			continue
		}
		if sel != nil && !sel[r.ID] {
			continue
		}
		out = append(out, pathTarget{path: r.Pattern, sev: r.Severity, desc: "[" + r.ID + "] " + r.Name})
	}
	return out
}

// MatchRules 用 body/header 类型规则匹配主页面响应, 返回命中的规则(全量)
func MatchRules(body, header string) []VulnRule {
	return MatchRulesFiltered(body, header, nil)
}

// MatchRulesFiltered 用 body/header 类型规则匹配主页面响应(受 sel 过滤), 返回命中的规则。
// sel 为 nil 时等同于 MatchRules(全量匹配); 非 nil 时只匹配 ID 在 sel 中的规则。
func MatchRulesFiltered(body, header string, sel map[string]bool) []VulnRule {
	vulnMu.RLock()
	rules := vulnRules
	vulnMu.RUnlock()
	var hits []VulnRule
	for _, r := range rules {
		if r.re == nil || !r.IsActive() {
			continue
		}
		if sel != nil && !sel[r.ID] {
			continue
		}
		if r.Type == "body" && r.re.MatchString(body) {
			hits = append(hits, r)
		} else if r.Type == "header" && r.re.MatchString(header) {
			hits = append(hits, r)
		}
	}
	return hits
}

// AllRules 返回当前已加载的全部规则(内置 + 外部, 含来源标记), 供前端"漏洞库管理"展示。
// re 字段不序列化(无 json tag 的私有字段), 不会外泄。
func AllRules() []VulnRule {
	vulnMu.RLock()
	defer vulnMu.RUnlock()
	out := make([]VulnRule, len(vulnRules))
	copy(out, vulnRules)
	return out
}

// BuiltinRulesJSON 返回内置规则(vuln_builtin.json)的原始 JSON 文本,
// 让用户能直接查看"自带的规则长什么样"(问题: 原来的规则能不能看)。
func BuiltinRulesJSON() string {
	return string(builtinVulnJSON)
}

// VulnerableDir 返回 exe 同目录的 vuln/ 规则目录(不存在则创建), 供前端展示/定位。
func VulnerableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "vuln"
	}
	dir := filepath.Join(filepath.Dir(exe), "vuln")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// ImportVulnRules 把一段规则 JSON 校验后写入 vuln/ 目录并热重载。
// 返回 (有效规则数, 告警列表, 错误)。校验通过的规则立即生效, 无需重启。
// 文件命名: filename 为空时用时间戳; 已存在同名文件会被覆盖(避免同名 ID 冲突)。
func ImportVulnRules(jsonContent, filename string) (int, []string, error) {
	var vf vulnFile
	if err := json.Unmarshal([]byte(jsonContent), &vf); err != nil {
		return 0, nil, fmt.Errorf("JSON 解析失败: %s (请确认是 {\"rules\":[...]} 结构)", err)
	}
	if len(vf.Rules) == 0 {
		return 0, nil, fmt.Errorf("rules 数组为空, 没有可导入的规则")
	}

	var valid []VulnRule
	var errs []string
	for i, r := range vf.Rules {
		if r.ID == "" || r.Name == "" || r.Pattern == "" || r.Type == "" {
			errs = append(errs, fmt.Sprintf("第 %d 条缺少必填字段 (id/name/pattern/type 均不能为空)", i+1))
			continue
		}
		if r.Severity == "" {
			r.Severity = "info"
		}
		// 与 LoadVulnLibrary 同口径: 非法 scope 只告警不拒绝, 落盘前归一化为明确值,
		// 使导入文件里也带显式 scope(用户后续手改文件时能直接看到可用取值)。
		if raw := strings.TrimSpace(r.Scope); raw != "" && normalizeScope(raw) == "" {
			errs = append(errs, r.ID+": 未知 scope: "+raw+" (仅支持 web/host, 已按 type 推导)")
		}
		r.Scope = r.EffectiveScope()
		// 导入即生效(默认已验证): 校验通过即参与扫描(2026-09-22 口径变更, 用户确认);
		// 导入内容显式声明 status=pending 时尊重显式意图(想先暂存的规则可显式声明,
		// 之后在页面"标记已验证"再生效)。
		if r.Status != RuleStatusPending {
			r.Status = RuleStatusVerified
		}
		switch r.Type {
		case "body", "header":
			if _, e := regexp.Compile(r.Pattern); e != nil {
				errs = append(errs, r.ID+": 正则无效 "+e.Error())
				continue
			}
		case "path":
		default:
			errs = append(errs, r.ID+": 未知 type: "+r.Type+" (仅支持 body/header/path)")
			continue
		}
		valid = append(valid, r)
	}
	if len(valid) == 0 {
		return 0, errs, fmt.Errorf("没有一条有效规则, 未导入")
	}

	fname := strings.TrimSpace(filename)
	if fname == "" {
		fname = "custom_" + time.Now().Format("20060102_150405") + ".json"
	}
	if !strings.HasSuffix(strings.ToLower(fname), ".json") {
		fname += ".json"
	}
	vf.Rules = valid
	out, _ := json.MarshalIndent(vf, "", "  ")
	p := filepath.Join(VulnerableDir(), fname)
	if err := os.WriteFile(p, out, 0o644); err != nil {
		return 0, errs, fmt.Errorf("写入文件失败: %s", err)
	}
	// 热重载: 立即生效(与内置规则合并, 同 ID 内置优先)
	LoadVulnLibrary()
	return len(valid), errs, nil
}

// ===== 规则验证状态(待验证 -> 已验证) =====

// verifiedFileName 已验证规则 ID 覆盖集文件名(exe 同目录 vuln/ 下)。
//
// 用独立文件而非回写各来源文件: 导入/自动转换的规则分散在多个 vuln/*.json 里,
// 逐个回写既低效又易漏; 集中一个"已验证 ID 名单"最简, 天然幂等, 也便于审计。
const verifiedFileName = "verified.json"

type verifiedFile struct {
	Verified []string `json:"verified"`
}

// vulnVerifiedPath 已验证集文件绝对路径(VulnerableDir 不存在时会先创建)。
func vulnVerifiedPath() string {
	return filepath.Join(VulnerableDir(), verifiedFileName)
}

// loadVerifiedSet 读已验证规则 ID 集; 文件缺失/损坏返回空集(显式待验证的规则保持待验证, 不报错)。
func loadVerifiedSet() map[string]bool {
	set := map[string]bool{}
	data, err := os.ReadFile(vulnVerifiedPath())
	if err != nil {
		return set
	}
	var vf verifiedFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return set
	}
	for _, id := range vf.Verified {
		if id = strings.TrimSpace(id); id != "" {
			set[id] = true
		}
	}
	return set
}

// MarkRulesVerified 把指定 ID 的规则标记为已验证并热重载(立即参与扫描)。
// 幂等: 重复标记不产生副作用。返回新增(受影响)的规则数与错误。
//
// 语义: 导入规则默认已验证(导入即生效), 本确认动作只针对"显式声明 status=pending
// 的暂存规则" —— 靶机测试通过后人工确认, 确认后进入扫描。
func MarkRulesVerified(ids []string) (int, error) {
	set := loadVerifiedSet()
	added := 0
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || set[id] {
			continue
		}
		set[id] = true
		added++
	}
	list := make([]string, 0, len(set))
	for id := range set {
		list = append(list, id)
	}
	sort.Strings(list) // 稳定输出, 便于 diff 与审查
	out, _ := json.MarshalIndent(verifiedFile{Verified: list}, "", "  ")
	if err := os.WriteFile(vulnVerifiedPath(), out, 0o644); err != nil {
		return 0, err
	}
	if added > 0 {
		LoadVulnLibrary()
	}
	return added, nil
}

// RuleStatusStats 已加载规则的验证状态计数(供前端统计卡展示)。
func RuleStatusStats() (verified, pending int) {
	vulnMu.RLock()
	defer vulnMu.RUnlock()
	for _, r := range vulnRules {
		if r.IsActive() {
			verified++
		} else {
			pending++
		}
	}
	return
}

// RuleSeverityStats 已加载规则按严重级别计数(供前端统计卡展示)。
// 归一化与展示口径一致: 未知值归入 info(与前端"信息"档一致), 大小写容错。
func RuleSeverityStats() map[string]int {
	stats := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	vulnMu.RLock()
	rules := vulnRules
	vulnMu.RUnlock()
	for _, r := range rules {
		switch strings.ToLower(strings.TrimSpace(r.Severity)) {
		case "critical", "crit":
			stats["critical"]++
		case "high":
			stats["high"]++
		case "medium", "med":
			stats["medium"]++
		case "low":
			stats["low"]++
		default:
			stats["info"]++
		}
	}
	return stats
}
