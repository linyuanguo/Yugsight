//go:build ignore

// nuclei2json.go Nuclei 模板 -> 本项目漏洞规则(JSON) 转换器(go generate 工具)。
//
// 把 Nuclei 官方模板里"内置引擎能执行的子集"转换成 vuln/*.json 规则格式,
// 供"规则库自动扩充"落地: 只转能被本项目漏洞库正则引擎(body/header 匹配)表达的部分,
// 复杂逻辑(DSL/多请求链/状态机/headless/network)一律跳过 —— 宁可少转, 不可错转(错转会
// 产生大量误报, 比缺规则更糟)。
//
// 用法:
//
//	go run scripts/nuclei2json.go -dir <nuclei-templates 目录> -out vuln/nuclei.json
//	go run scripts/nuclei2json.go -dir ./tpl -out ./out.json -min-sev low -max 200
//	go generate ./scanner   # 自动转换链: 模板目录按 NUCLEI_TEMPLATES_DIR/当前目录/
//	                        # 上级目录解析, 输出 dist/vuln/nuclei.json(运行目录)
//
// 转换口径(与 scanner/vuln.go 的 VulnRule 对齐):
//   - 只处理 http 类型且**单请求**的模板(http / request / requests 块存在, 且非 workflow);
//     多请求模板整体跳过(matcher 对应不同响应, 单条正则无法归属到哪个响应 —— 宁可少转, 不可错转);
//   - matchers 从请求块内部读取(Nuclei 的 http 匹配器在请求内, 不在顶层); 请求内没有时
//     回退顶层;
//   - 每个正向 matcher 出一条规则(regex/word, part=body/header): Nuclei 同请求内多
//     matcher 默认 AND, 拆成多规则放宽为 OR(每条规则是模板的一个必要条件, 误报率略高于
//     原模板) —— 与"导入即生效"口径配套(2026-09-22 用户确认接受该误报风险);
//   - 两类死规则过滤(2026-09-22 真机 14k 模板漏斗诊断后确定, 14054 文件 -> ~7k 规则):
//     ① OOB/变量模式(interactsh/oast 回调域、{{...}} 占位符)—— 内置引擎无带外回调
//     能力, 这些模式在真实扫描中永远不会命中, 是死规则; ② 通用 content-type 守卫
//     (text/html 等)—— 拆成独立规则会命中几乎每个响应, 是原模板里的 AND 定位条件,
//     单独拿出去是误报源;
//   - negative matcher / DSL / condition:and(多词 AND, RE2 无前瞻表达不了) 逐条跳过;
//   - regex 直接作 pattern; word 多条用 "|"(OR)连接并逐条转义后作 pattern;
//   - 产出规则一律 status="verified"(导入即生效): 与导入规则同一口径(2026-09-22 变更),
//     程序加载后直接参与扫描; 若个别规则想先暂存, 在产出文件里把该条 status 改为 "pending";
//   - 单条失败(缺必填字段 / 正则不可编译 / 无法解析)只跳过并计数, 不中断整体转换;
//   - 去重: 同一 id + pattern 只保留一条, 避免不同目录重复模板产生重复规则。
//
// 校验(与 ImportVulnRules 同口径): id/name/pattern/type 均必填; body/header 的正则必须
// 可编译; 任一条不满足即跳过该条(单条失败不影响其余)。
//
// 依赖: 标准库 + gopkg.in/yaml.v3(项目已有, 不新增依赖)。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ===== 最小模板结构(只取转换需要的字段, 不与 scanner 包耦合) =====

type strList []string

func (s *strList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var str string
		if err := node.Decode(&str); err != nil {
			return err
		}
		*s = splitCSV(str)
		return nil
	case yaml.SequenceNode:
		var items []string
		if err := node.Decode(&items); err != nil {
			return err
		}
		*s = items
		return nil
	default:
		return fmt.Errorf("不支持的 YAML 节点类型: %v", node.Kind)
	}
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type req struct {
	Method string    `yaml:"method"`
	Paths  strList   `yaml:"path"`
	// Nuclei 的 http 匹配器位于每个请求块内部(顶层 matchers 只用于 dns/whois 等非 http 协议),
	// 早期版本把该字段放在顶层导致真实模板全部漏转 —— 2026-09-22 真机 14k 模板转出 0 条的根因。
	Matchers []matcher `yaml:"matchers"`
}

type httpBlock struct {
	Present bool
	Items   []req
}

// UnmarshalYAML 记录 http 块是否存在(映射或序列形态都算存在), 供"是否 http 模板"判定。
func (h *httpBlock) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		if err := node.Decode(&h.Items); err != nil {
			return err
		}
		h.Present = true
	case yaml.MappingNode:
		var one req
		if err := node.Decode(&one); err != nil {
			return err
		}
		h.Items = []req{one}
		h.Present = true
	}
	return nil
}

type matcher struct {
	Type      string  `yaml:"type"`
	Part      string  `yaml:"part"`
	Negative  bool    `yaml:"negative"`
	Words     strList `yaml:"words"`
	Regexes   strList `yaml:"regex"`
	DSL       strList `yaml:"dsl"`
	// condition: and/or —— 同一 matcher 内多 word/regex 的聚合方式(缺省 = OR)。
	// and 表示必须全部命中, RE2 无前瞻无法表达, 故 and 时整个请求跳过。
	Condition string `yaml:"condition"`
}

type info struct {
	Name        string  `yaml:"name"`
	Severity    string  `yaml:"severity"`
	Description string  `yaml:"description"`
}

type tmpl struct {
	ID       string     `yaml:"id"`
	Info     *info      `yaml:"info"`
	HTTP     httpBlock  `yaml:"http"`
	Request  *req       `yaml:"request"`
	Requests []req      `yaml:"requests"`
	Matchers []matcher  `yaml:"matchers"`
	Flow     strList    `yaml:"flow"` // workflow 依赖, 存在即视为 workflow(不转换)
}

// ===== 输出规则结构(与 scanner.VulnRule 对齐) =====

type outRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Type     string `json:"type"`
	Pattern  string `json:"pattern"`
	Detail   string `json:"detail"`
	Scope    string `json:"scope"`
	Status   string `json:"status"`
}

type outFile struct {
	Rules []outRule `json:"rules"`
}

// ===== 工具函数 =====

// sanitizeID 把 Nuclei 模板 id 归一化为规则 id 前缀(大写 + 仅 [A-Z0-9-])。
func sanitizeID(id string) string {
	var b strings.Builder
	for _, c := range strings.ToUpper(id) {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else if c == '-' || c == '_' {
			b.WriteRune('-')
		}
	}
	s := b.String()
	// 去掉首尾 '-'
	s = strings.Trim(s, "-")
	if s == "" {
		s = "NUCLEI"
	}
	return s
}

// wordPattern 把多条 word 用 OR 连接成一条可编译正则(逐条转义, 避免 word 里的
// 正则特殊字符破坏 pattern)。空返回 false。
func wordPattern(words []string) (string, bool) {
	var parts []string
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		parts = append(parts, regexp.QuoteMeta(w))
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "|"), true
}

// isOOBJunk 判断模式是否依赖 Nuclei 带外(OOB)回调基础设施或变量插值 —— 内置引擎没有
// OOB 回调能力, 这类模式在真实扫描中永远不会命中, 属死规则(如 interactsh 回调域、
// {{md5(num)}} 占位符)。正则形式下变量占位写作 \{\{...\}\}、oast 域写作 oast\.,
// 故先剥反斜杠再判断。
func isOOBJunk(p string) bool {
	plain := strings.ReplaceAll(strings.ToLower(p), `\`, "")
	if strings.Contains(plain, "{{") || strings.Contains(plain, "}}") {
		return true
	}
	for _, k := range []string{"interactsh", "oast.", "oastify", "burpcollaborator", "canarytokens", "reqbin.com", "webhook.site", "iplogger", "dnslog"} {
		if strings.Contains(plain, k) {
			return true
		}
	}
	return false
}

// genericWordSet 通用 content-type 字面量。这类 word matcher 拆成独立规则会命中几乎
// 每个响应(text/html 命中每个 HTML 页面), 是"逐 matcher 出规则"口径下的主要误报源。
var genericWordSet = map[string]bool{
	"text/html": true, "application/json": true, "application/xml": true,
	"text/plain": true, "text/xml": true, "text/css": true,
	"application/javascript": true, "text/javascript": true, "application/x-javascript": true,
	"application/xml-dtd": true, "application/octet-stream": true,
	"application/x-www-form-urlencoded": true, "multipart/form-data": true,
	"application/pdf": true, "application/zip": true, "application/gzip": true,
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/svg+xml": true,
	"image/webp": true, "image/bmp": true, "image/ico": true,
	"font/woff": true, "font/woff2": true,
	"application/vnd.ms-excel": true, "application/msword": true,
	"application/x-protobuf": true, "application/grpc": true,
}

// isGenericGuard 判断是否为"通用守卫"模式: 纯字面量(无正则元字符, 即 word 未转义原样)
// 且恰是或包含通用 content-type(如 word "Content-Type: text/html")。
func isGenericGuard(p string) bool {
	if strings.ContainsAny(p, "^$.*+?()[]{}|\\") {
		return false
	}
	lower := strings.ToLower(p)
	for w := range genericWordSet {
		if lower == w || strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// severityRank 严重级别权重(用于 -min-sev 过滤), 未知按 0。
func severityRank(sev string) int {
	switch strings.ToLower(sev) {
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

// convert 把一个模板转成 0..n 条规则(每个可转换的正向 matcher 一条, 不满足口径时返回空)。
// 多 matcher 的 AND->OR 放宽与死规则过滤的理由见文件头"转换口径"。
func convert(t *tmpl, minSev int) []outRule {
	if t == nil {
		return nil
	}
	// workflow 不转换(依赖其它模板, 非独立 http 探测)
	if len(t.Flow) > 0 {
		return nil
	}
	// 非 http 模板(无 http/request/requests 块)不转换
	isHTTP := t.HTTP.Present || t.Request != nil || len(t.Requests) > 0
	if !isHTTP {
		return nil
	}
	if t.Info == nil {
		return nil
	}
	if severityRank(t.Info.Severity) < minSev {
		return nil
	}

	// 收集请求块(http/requests/request 三种形态新旧版本并存)
	allReqs := make([]req, 0, 2)
	allReqs = append(allReqs, t.HTTP.Items...)
	if t.Request != nil {
		allReqs = append(allReqs, *t.Request)
	}
	allReqs = append(allReqs, t.Requests...)
	if len(allReqs) != 1 {
		// 多请求(或无请求): matcher 归属不到唯一响应, 转出来语义是错的, 整体跳过
		return nil
	}
	// matchers 从请求块内读; 请求内没有时回退顶层(极少数旧模板写法)
	matchers := allReqs[0].Matchers
	if len(matchers) == 0 {
		matchers = t.Matchers
	}
	if len(matchers) == 0 {
		return nil
	}

	name := strings.TrimSpace(t.Info.Name)
	if name == "" {
		return nil // 缺 name(必填)
	}

	var out []outRule
	base := "NUCLEI-" + sanitizeID(t.ID)
	emitted := 0
	for _, m := range matchers {
		if m.Negative {
			continue // negative matcher 用于压制误报; 拆成独立规则后失效, 每条正向规则只是模板的一个必要条件
		}
		if len(m.DSL) > 0 {
			continue // DSL 逻辑无法用单条正则表达
		}
		if strings.ToLower(strings.TrimSpace(m.Condition)) == "and" {
			continue // 多 word/regex 的 AND, RE2 无前瞻无法表达
		}
		part := strings.ToLower(strings.TrimSpace(m.Part))
		if part == "" {
			part = "body" // nuclei 默认 part=body
		}
		if part != "body" && part != "header" {
			continue // status_code 等其它 part 不转
		}
		var pattern string
		switch strings.ToLower(m.Type) {
		case "regex":
			if len(m.Regexes) == 0 {
				continue
			}
			pattern = strings.Join(m.Regexes, "|") // 同一 matcher 内多 regex 是 OR, 与 nuclei 一致
		case "word":
			p, ok := wordPattern(m.Words) // 同一 matcher 内多 word 缺省即 OR, 与 nuclei 一致
			if !ok {
				continue
			}
			pattern = p
		default:
			continue // status 等不转
		}
		// 校验: 正则必须可编译, 否则跳过该条(单条失败不影响其余)
		if _, err := regexp.Compile(pattern); err != nil {
			continue
		}
		if isOOBJunk(pattern) {
			continue // 死规则: OOB 回调域/变量占位符, 本引擎永远不会命中
		}
		if isGenericGuard(pattern) {
			continue // 死规则: 通用 content-type 守卫, 拆出去即误报源
		}
		emitted++
		id := base
		if emitted > 1 {
			id = fmt.Sprintf("%s-%d", base, emitted)
		}
		out = append(out, outRule{
			ID:       id,
			Name:     name,
			Severity: normalizeSev(t.Info.Severity),
			Type:     part, // body / header
			Pattern:  pattern,
			Detail:   truncate(t.Info.Description, 200),
			Scope:    "web",
			Status:   "verified", // 导入即生效(默认已验证), 程序加载后直接参与扫描
		})
	}
	return out
}

func normalizeSev(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// resolveTemplateDir 默认模板目录解析(按序): NUCLEI_TEMPLATES_DIR 环境变量 ->
// 当前目录/nuclei-templates -> 上两级目录/nuclei-templates(go:generate 在包目录
// internal/scanner/ 下执行, 上两级即仓库根; 手动 go run 在仓库根执行时当前目录即命中)。
// 找不到返回空串。
func resolveTemplateDir() string {
	if d := strings.TrimSpace(os.Getenv("NUCLEI_TEMPLATES_DIR")); d != "" {
		return d
	}
	for _, cand := range []string{"nuclei-templates", "../nuclei-templates", "../../nuclei-templates"} {
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	return ""
}

// ===== 主流程 =====

func main() {
	dir := flag.String("dir", "", "Nuclei 模板目录(递归查找 *.yaml/*.yml)")
	out := flag.String("out", "vuln/nuclei.json", "输出规则 JSON 文件")
	minSevStr := flag.String("min-sev", "info", "最低严重级别: info/low/medium/high/critical")
	maxRules := flag.Int("max", 0, "最多转换的规则数(0=不限)")
	flag.Parse()

	if *dir == "" {
		*dir = resolveTemplateDir()
		if *dir == "" {
			fmt.Fprintln(os.Stderr, `未指定模板目录, 默认位置也未找到。可选:
  - 显式指定: -dir <nuclei-templates 目录>
  - 环境变量: NUCLEI_TEMPLATES_DIR=<nuclei-templates 目录>
  - 约定位置: 当前目录或上级目录下的 nuclei-templates/(go generate 场景)
模板仓库获取: git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git`)
			os.Exit(2)
		}
	}

	minSev := severityRank(*minSevStr)
	if minSev == 0 {
		minSev = 1
	}

	var rules []outRule
	seen := map[string]bool{} // id|pattern 去重
	stats := map[string]int{"files": 0, "http": 0, "multi": 0, "converted": 0, "skipped": 0}

	filepath.WalkDir(*dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 单文件读取失败不影响整体(降级不中断)
		}
		if d.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			stats["skipped"]++
			return nil
		}
		var t tmpl
		if uerr := yaml.Unmarshal(data, &t); uerr != nil {
			stats["skipped"]++ // 解析失败: 跳过该文件
			return nil
		}
		stats["files"]++
		isHTTP := t.HTTP.Present || t.Request != nil || len(t.Requests) > 0
		nReqs := len(t.HTTP.Items) + len(t.Requests)
		if t.Request != nil {
			nReqs++
		}
		if isHTTP && len(t.Flow) == 0 && t.Info != nil {
			stats["http"]++
			if nReqs > 1 {
				stats["multi"]++ // 多请求模板: 可转换但按口径跳过, 单独计数便于评估损失
			}
		}
		if *maxRules > 0 && stats["converted"] >= *maxRules {
			return nil // 总上限已到: 继续走目录但跳过处理(提前 break 不了 WalkDir)
		}
		for _, r := range convert(&t, minSev) {
			key := r.ID + "|" + r.Pattern
			if seen[key] {
				continue
			}
			seen[key] = true
			rules = append(rules, r)
			stats["converted"]++
		}
		return nil
	})

	// 落盘: 顶层 {"rules":[...]}(与 vuln/*.json 一致), 放入 vuln/ 后热加载即生效。
	if len(rules) == 0 {
		fmt.Fprintf(os.Stderr, "未转换出任何规则(目录 %s, min-sev=%s)。请确认目录含 http 类型且带 body/header regex/word 匹配器的模板。\n", *dir, *minSevStr)
		os.Exit(1)
	}
	data, _ := json.MarshalIndent(outFile{Rules: rules}, "", "  ")
	if dir := filepath.Dir(*out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil { // 输出目录可能尚不存在(如 dist/vuln/)
			fmt.Fprintln(os.Stderr, "创建输出目录失败:", err)
			os.Exit(1)
		}
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写入失败:", err)
		os.Exit(1)
	}
	fmt.Printf("转换完成: %d 个 YAML 文件, %d 个 http 模板(多请求跳过 %d), 产出 %d 条规则 -> %s\n",
		stats["files"], stats["http"], stats["multi"], len(rules), *out)
	fmt.Printf("提示: 产出规则 status=verified(导入即生效), 程序启动/重载后即参与扫描。\n")
}
