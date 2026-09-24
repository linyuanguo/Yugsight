//go:build !windows || windows

// nuclei_parser.go 轻量 Nuclei YAML 模板解析器。
//
// 设计要点(与 nuclei 官方包无关, 完全自主实现):
//   - 只支持 http 类型模板; headless / javascript / network 模板直接跳过不加载
//   - workflow 模板仅提取其依赖的模板 ID(flow 列表), 不执行 workflow
//   - 模板完整性用 sha256 校验(读取 templates-checksum.txt), 校验失败跳过并记日志
//   - 任何单文件解析/IO 错误只记录日志, 不中断整体加载
//   - 结果结构 Template 供 nuclei_runner 执行, 命中经 Finding 统一汇入现有结果集
//
// 依赖: 标准库 + gopkg.in/yaml.v3 (仅此一项第三方, 不引入 projectdiscovery/nuclei)。
package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"yugsight/pathrel"
)

// nucleiLog 组件日志。slog 是标准库, 与 yugsight 运行日志分离(这里走默认 handler)。
var nucleiLog = slog.Default().With("component", "nuclei")

// stringOrList 兼容 YAML 中"标量字符串"(如 "a, b, c")与"序列"([a, b, c])两种写法。
// Nuclei 模板的 tags / words / reference / path 等字段两种写法都很常见。
type stringOrList []string

// UnmarshalYAML 实现 yaml.v3 自定义解码
func (s *stringOrList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var str string
		if err := node.Decode(&str); err != nil {
			return err
		}
		*s = splitCSV(str)
	case yaml.SequenceNode:
		var items []string
		if err := node.Decode(&items); err != nil {
			return err
		}
		*s = items
	default:
		return fmt.Errorf("不支持的 YAML 节点类型: %v", node.Kind)
	}
	return nil
}

// splitCSV 按逗号切分并去空白; 空串返回 nil
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

// Request 对应 Nuclei 的 http: / request: / requests: 块(单个请求定义)。
//
// 【三种键名的由来】Nuclei 模板格式演进过两代: 早期多请求列表用 `requests:`,
// 后来单请求用 `request:`, 当前官方仓库统一用 `http:`(既承载单请求也承载列表)。
// 三者语义等价, 都解码到本结构, 由 Template.AllRequests 统一汇总。
type Request struct {
	Method  string            `yaml:"method"`  // GET/POST/... 默认 GET
	Paths   stringOrList      `yaml:"path"`    // 请求路径(可含 {{BaseURL}} 变量)
	Headers map[string]string `yaml:"headers"` // 请求头
	Cookies map[string]string `yaml:"cookies"` // 请求 Cookie
	Body    string            `yaml:"body"`    // 请求体(可含变量)
}

// httpBlock 解码当前官方键名 `http:` 的内容。
//
// 【为什么需要自定义解码】官方 `http:` 有两种合法写法, 同一个键名承载两种 YAML 形态:
//
//	http:                    # 单请求(映射)
//	  method: GET
//	  path:
//	    - "{{BaseURL}}/x"
//
//	http:                    # 多请求(序列)
//	  - method: GET
//	    path: ["{{BaseURL}}/a"]
//	  - method: POST
//	    path: ["{{BaseURL}}/b"]
//
// 用 []Request 直接解码会在"单请求映射"形态上报类型错误(expect sequence);
// 用 Request 直接解码会在"多请求序列"形态上同样报错。二者都是官方真实存在的写法,
// 所以按 yaml.Node 的 Kind 分派, 两种都能吃下。
type httpBlock struct {
	Items []Request
}

// UnmarshalYAML 按节点类型分派: 序列 -> 多个请求; 映射 -> 单个请求。
// 其它类型(Null/标量)视为空, 不报错 —— 由 AllRequests 返回空切片,
// 上游据此走"无可执行请求"分支正常跳过, 不产生解析噪音。
func (h *httpBlock) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		return node.Decode(&h.Items)
	case yaml.MappingNode:
		var one Request
		if err := node.Decode(&one); err != nil {
			return err
		}
		h.Items = []Request{one}
		return nil
	default:
		h.Items = nil
		return nil
	}
}

// Matcher 对应 matchers: 列表的单个元素。按 Type 取对应字段:
// status->Status, word->Words, regex->Regexes, dsl->DSL。
type Matcher struct {
	Type      string       `yaml:"type"`      // status / word / regex / dsl
	Part      string       `yaml:"part"`      // body / header / status_code (默认 body)
	Condition string       `yaml:"condition"` // and / or (默认 or)
	Negative  bool         `yaml:"negative"`  // 是否取反
	Status    []int        `yaml:"status"`    // type=status
	Words     stringOrList `yaml:"words"`     // type=word
	Regexes   stringOrList `yaml:"regex"`     // type=regex
	DSL       stringOrList `yaml:"dsl"`       // type=dsl
}

// Info 对应 info: 块
type Info struct {
	Name        string       `yaml:"name"`
	Severity    string       `yaml:"severity"` // info/low/medium/high/critical
	Tags        stringOrList `yaml:"tags"`
	Cve         stringOrList `yaml:"cve"`  // 单个 cve
	Cves        stringOrList `yaml:"cves"` // 多个 cve
	Reference   stringOrList `yaml:"reference"`
	References  stringOrList `yaml:"references"`
	Description string       `yaml:"description"`
	Author      string       `yaml:"author"`
}

// Template 一个 Nuclei 模板(http 或 workflow)。
//
// HTTP 字段是当前官方键名(`http:`), 既可能是单个请求也可能是请求列表,
// 因此用 stringOrList 之外的自定义解码(见 HTTPRequests); Request/Requests 为
// 兼容旧两代键名保留。
type Template struct {
	ID       string       `yaml:"id"`
	Info     *Info        `yaml:"info"`
	HTTP     httpBlock    `yaml:"http"`     // 当前官方键名: http 请求(单个或列表)
	Request  *Request     `yaml:"request"`  // 旧键名: http 单请求
	Requests []Request    `yaml:"requests"` // 更旧键名: http 多请求
	Matchers []Matcher    `yaml:"matchers"`
	Flow     stringOrList `yaml:"flow"` // workflow 依赖的模板 ID 列表

	// 非 YAML 字段
	IsWorkflow bool   `yaml:"-"` // 是否 workflow(仅提取依赖, 不执行)
	Builtin    bool   `yaml:"-"` // 是否内置模板(exe 内打包, 见 nuclei_builtins.go)
	Path       string `yaml:"-"` // 来源文件绝对路径(内置模板为 embed 内相对路径)
	SHA256     string `yaml:"-"` // 文件 sha256
}

// AllRequests 合并 http / request / requests 三种键名的请求, 供执行器统一遍历。
//
// 顺序: http 优先(当前官方格式), 其次是两个旧键名。空模板返回 nil,
// 调用方(FilterTemplatesByFingerprint)据 len==0 判定"无可执行请求"并跳过。
func (t *Template) AllRequests() []Request {
	var rs []Request
	rs = append(rs, t.HTTP.Items...)
	if t.Request != nil {
		rs = append(rs, *t.Request)
	}
	return append(rs, t.Requests...)
}

// AllTags 返回 info.tags
func (t *Template) AllTags() []string {
	if t.Info == nil {
		return nil
	}
	return t.Info.Tags
}

// CveIDs 合并 cve 与 cves
func (t *Template) CveIDs() []string {
	if t.Info == nil {
		return nil
	}
	out := make([]string, 0, len(t.Info.Cve)+len(t.Info.Cves))
	out = append(out, t.Info.Cve...)
	return append(out, t.Info.Cves...)
}

// genericTagWords 通用标签词表(不代表具体产品)。
// 一个标签若命中此表, 则不视为"产品标记", 用于指纹过滤时判断模板是否通用。
var genericTagWords = map[string]bool{
	"cve": true, "exposures": true, "exposure": true, "exposed": true,
	"xss": true, "sqli": true, "rce": true, "lfi": true, "rfi": true,
	"info": true, "scan": true, "scans": true, "detection": true,
	"default": true, "misconfiguration": true, "misconfig": true,
	"vuln": true, "vulnerability": true, "vulnerabilities": true,
	"fuzz": true, "dos": true, "injection": true, "disclosure": true,
	"takeover": true, "subdomain": true, "subdomains": true, "tech": true,
	"exploit": true, "bypass": true, "auth-bypass": true, "auth": true,
	"idor": true, "csrf": true, "ssrf": true, "redirect": true,
	"file": true, "files": true, "config": true, "configs": true,
	"leak": true, "leaks": true, "enum": true, "credentials": true,
	"weak": true, "weak-password": true, "default-credentials": true,
	"default-login": true, "ssl": true, "tls": true, "headers": true,
	"header": true, "cve-2020": true, "cve-2021": true, "cve-2022": true,
	"cve-2023": true, "cve-2024": true,
}

// productTags 从 tags 中提取"产品类"标签(小写), 用于指纹过滤。
// Nuclei 惯例: 产品名作为 tag(如 nginx / apache / iis); 通用词(见 genericTagWords)不算产品。
// 无产品标签 => 空切片, 表示"通用模板"。
func (t *Template) productTags() []string {
	var ps []string
	seen := map[string]bool{}
	for _, tag := range t.AllTags() {
		s := strings.ToLower(strings.TrimSpace(tag))
		if s == "" || seen[s] || genericTagWords[s] {
			continue
		}
		seen[s] = true
		ps = append(ps, s)
	}
	return ps
}

// versionConstraint 返回模板中形如带版本的 tag(如 "apache-2.4.49"); 无则返回空串。
// 用于"版本过滤": 仅当提供了 ver 且模板确实约束了版本时才收窄。
func (t *Template) versionConstraint() string {
	for _, tag := range t.AllTags() {
		if strings.Contains(tag, ".") && strings.ContainsAny(tag, "0123456789") {
			return tag
		}
	}
	return ""
}

// FilterTemplatesByFingerprint 依据服务指纹(Product+Version)筛选应执行的模板,
// 避免对每个目标无脑跑全部模板(减少无效扫描)。
//
// 规则:
//   - workflow 模板 / 无任何请求的模板: 跳过(不作为 http 扫描目标)
//   - 通用模板(无产品标签): 保留(对任何 http 目标都适用)
//   - 产品模板: 其 productTags 必须包含 product(小写)才保留
//   - 版本: 提供了 ver 且模板带版本约束时, ver 需出现在约束中, 否则剔除
func FilterTemplatesByFingerprint(tpls []Template, product, ver string) []Template {
	p := strings.ToLower(strings.TrimSpace(product))
	v := strings.ToLower(strings.TrimSpace(ver))
	out := make([]Template, 0, len(tpls))
	for i := range tpls {
		t := tpls[i]
		if t.IsWorkflow || len(t.AllRequests()) == 0 {
			continue
		}
		prods := t.productTags()
		if len(prods) == 0 {
			out = append(out, t) // 通用模板
			continue
		}
		if p == "" || !containsStr(prods, p) {
			continue
		}
		if v != "" {
			if vc := strings.ToLower(t.versionConstraint()); vc != "" && !strings.Contains(vc, v) {
				continue
			}
		}
		out = append(out, t)
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// sha256Hex 计算字节串的 sha256(十六进制小写)
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ParseNucleiTemplate 解析单个模板 YAML。
//
// 返回值:
//   - (*Template, nil): 成功解析(http 模板或 workflow 模板)
//   - (nil, nil):       非 http 类型(headless/javascript/network 等), 应跳过
//   - (nil, error):     YAML 解析错误, 由调用方记录日志并跳过
func ParseNucleiTemplate(data []byte) (*Template, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, fmt.Errorf("模板内容为空")
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("模板顶层不是映射")
	}
	keys := topLevelKeys(top)

	// 跳过非 http 类型模板
	switch {
	case keys["headless"], keys["javascript"], keys["network"]:
		return nil, nil
	}

	// workflow: 仅提取依赖的模板 ID(flow), 不执行
	if keys["flow"] {
		var tpl Template
		if err := top.Decode(&tpl); err != nil {
			return nil, err
		}
		tpl.IsWorkflow = true
		return &tpl, nil
	}

	// http 模板: 必须有 http / request / requests(见 Request 注释的键名演进说明)。
	// 三者缺一即视为非 HTTP 类型模板(如只声明 matchers 的片段), 静默跳过。
	if !keys["http"] && !keys["request"] && !keys["requests"] {
		return nil, nil
	}
	var tpl Template
	if err := top.Decode(&tpl); err != nil {
		return nil, err
	}
	if tpl.ID == "" {
		tpl.ID = strings.TrimSuffix(filepath.Base(extractIDFallback(data)), ".yaml")
	}
	return &tpl, nil
}

// topLevelKeys 返回顶层映射的所有键(用于判断模板类型)
func topLevelKeys(node *yaml.Node) map[string]bool {
	keys := make(map[string]bool, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keys[node.Content[i].Value] = true
	}
	return keys
}

// extractIDFallback 从原始 YAML 文本里粗提取 id 行, 作为 ID 缺省兜底
func extractIDFallback(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id:") {
			id := strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			id = strings.Trim(id, `"'`)
			if id != "" {
				return id
			}
		}
	}
	return "unknown"
}

// validateTemplate 在加载期校验模板 matcher 的静态合法性(正则可编译 / DSL 可分词),
// 返回问题列表, 空表示全部通过。调用方按文件上下文记 Warn 日志, 错误不在运行时静默消失;
// 单个 matcher 无效不影响同模板其他 matcher 使用(运行时走负缓存, 该 matcher 不会命中)。
func validateTemplate(tpl *Template) []string {
	var problems []string
	for i, m := range tpl.Matchers {
		switch m.Type {
		case "regex":
			for _, re := range m.Regexes {
				if _, err := regexp.Compile(re); err != nil {
					problems = append(problems, fmt.Sprintf("matcher[%d] 正则无效: %s (%v)", i, re, err))
				}
			}
		case "dsl":
			for _, expr := range m.DSL {
				if toks, err := dslTokenize(expr); err != nil || len(toks) == 0 {
					problems = append(problems, fmt.Sprintf("matcher[%d] dsl 表达式无效: %s (%v)", i, expr, err))
				}
			}
		}
	}
	return problems
}

// loadChecksums 解析 templates-checksum.txt 为 map[相对路径]sha256。
// 文件格式(每行): "<64位hex>  <相对路径>", 支持 # 注释行; 文件缺失返回空表(即跳过校验)。
func loadChecksums(dir string) map[string]string {
	m := make(map[string]string)
	data, err := os.ReadFile(filepath.Join(dir, "templates-checksum.txt"))
	if err != nil {
		// dir 走 pathrel.Short: slog 属性不经过 logLine 的相对化兜底
		nucleiLog.Warn("未找到 templates-checksum.txt, 跳过完整性校验", "dir", pathrel.Short(dir))
		return m
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
	return m
}

// LoadNucleiTemplates 从本地目录递归加载所有 .yaml/.yml 模板。
//
// 每个文件独立处理: sha256 校验 -> 类型过滤 -> 解析。任一环节失败只记录日志,
// 不中断整体加载。返回有效 http/workflow 模板列表与错误/跳过原因列表。
func LoadNucleiTemplates(dir string) ([]Template, []string) {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		msg := fmt.Sprintf("模板目录不存在或不可读: %s", dir)
		nucleiLog.Warn(msg)
		return nil, []string{msg}
	}
	checksums := loadChecksums(dir)

	var tpls []Template
	var errs []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 不中断
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			rel = filepath.Base(path) // 兜底: 相对路径计算失败时用文件名
		}
		rel = filepath.ToSlash(rel)

		data, rerr := os.ReadFile(path)
		if rerr != nil {
			nucleiLog.Error("模板读取失败, 跳过", "file", rel, "err", rerr)
			errs = append(errs, rel+": 读取失败 "+rerr.Error())
			return nil
		}

		// sha256 完整性校验(仅在 checksum 文件记录了该文件时)
		if want, ok := checksums[rel]; ok {
			if got := sha256Hex(data); got != want {
				nucleiLog.Error("模板 sha256 校验失败, 跳过(可能已被篡改)",
					"file", rel, "want", want, "got", got)
				errs = append(errs, rel+": sha256 不匹配")
				return nil
			}
		}

		tpl, perr := ParseNucleiTemplate(data)
		if perr != nil {
			nucleiLog.Error("模板解析失败, 跳过", "file", rel, "err", perr)
			errs = append(errs, rel+": 解析失败 "+perr.Error())
			return nil
		}
		if tpl == nil {
			return nil // 非 http 类型, 静默跳过
		}
		tpl.Path = path
		tpl.SHA256 = sha256Hex(data)
		if ps := validateTemplate(tpl); len(ps) > 0 {
			for _, p := range ps {
				nucleiLog.Warn("模板 matcher 无效, 对应 matcher 不会命中",
					"tpl", tpl.ID, "file", rel, "problem", p)
			}
		}
		tpls = append(tpls, *tpl)
		return nil
	})

	nucleiLog.Info("nuclei 模板加载完成", "dir", pathrel.Short(dir), "loaded", len(tpls), "skipped", len(errs))
	return tpls, errs
}

// ===== 模板预加载缓存 =====
//
// 性能优化: 模板 YAML 解析(尤其数千模板时)开销不小, 但一次加载即可长期复用。
// 进程级缓存, 首次调用 LoadTemplateCache 时读盘解析, 之后同目录调用直接复用,
// 扫描任务之间不再重复读取/解析 yaml 文件。
//
// 失败(目录不存在等)不写入缓存: 用户可能在启动后才放置模板目录, 下次调用重试。

var (
	tplMu    sync.Mutex
	tplCache []Template
	tplDir   string
	tplFP    dirFingerprint // 缓存时的目录状态, 用于热更新检测
	tplOK    bool           // 是否已成功缓存过一次
)

// dirFingerprint 外部模板目录的轻量指纹(文件数 + 总大小 + 最新修改时间),
// 用于热更新检测: 目录状态未变化时扫描任务直接复用缓存(不重读/解析 yaml),
// 用户新增/删除/修改模板文件后下一次调用自动感知并重新加载。
type dirFingerprint struct {
	files  int
	size   int64
	newest int64 // 最新文件修改时间(unix 纳秒, 用 int64 保证结构体可直接比较)
}

// dirFingerprintOf 遍历目录计算指纹(只统计 .yaml/.yml 文件)。
// ok=false 表示目录不存在或不可读。
func dirFingerprintOf(dir string) (dirFingerprint, bool) {
	var fp dirFingerprint
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // 不中断
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		fp.files++
		fp.size += info.Size()
		if t := info.ModTime().UnixNano(); t > fp.newest {
			fp.newest = t
		}
		return nil
	})
	if err != nil {
		return dirFingerprint{}, false
	}
	return fp, true
}

// LoadTemplateCache 从 dir 加载外部模板并写入进程级缓存(支持热更新):
// 目录状态未变化时命中缓存, 不重读 yaml; 目录变化(文件增删改)自动重新加载。
// 返回 (模板列表, 错误列表); 调用方不得修改返回列表(缓存共享)。
func LoadTemplateCache(dir string) ([]Template, []string) {
	tplMu.Lock()
	defer tplMu.Unlock()
	return loadExternalLocked(dir, false)
}

// RefreshTemplateCache 强制重新加载外部模板目录(绕过热更新检测),
// 供 /api/nuclei/reload 手动刷新: 模板库更新后无需重启程序。
func RefreshTemplateCache(dir string) ([]Template, []string) {
	tplMu.Lock()
	defer tplMu.Unlock()
	return loadExternalLocked(dir, true)
}

// loadExternalLocked 加载外部模板目录(调用方需持有 tplMu):
// force=false 时先比对目录指纹, 未变化直接返回缓存; 变化或强制时重新读盘解析。
// 失败(目录不存在等)不写入缓存: 用户可能在启动后才放置模板目录, 下次调用重试。
func loadExternalLocked(dir string, force bool) ([]Template, []string) {
	fp, ok := dirFingerprintOf(dir)
	if !ok {
		msg := fmt.Sprintf("模板目录不存在或不可读: %s", dir)
		nucleiLog.Warn(msg)
		return nil, []string{msg}
	}
	if !force && tplOK && tplDir == dir && fp == tplFP {
		return tplCache, nil // 命中缓存, 不重读 yaml
	}
	if tplOK && tplDir == dir {
		nucleiLog.Info("模板目录状态变化, 热更新重新加载", "dir", pathrel.Short(dir))
	}
	tpls, errs := LoadNucleiTemplates(dir)
	if len(errs) == 0 {
		// 目录存在(即使为空目录)才缓存; 失败保留下次重试的机会
		tplCache, tplDir, tplFP, tplOK = tpls, dir, fp, true
	}
	return tpls, errs
}

// TemplateCount 返回已缓存模板数量(0 表示尚未加载或目录为空), 供 /api/info 展示
func TemplateCount() int {
	tplMu.Lock()
	defer tplMu.Unlock()
	return len(tplCache)
}

// ResetTemplateCache 清空外部模板缓存(测试用; 内置模板为 embed 常量, 不可重置)
func ResetTemplateCache() {
	tplMu.Lock()
	tplCache, tplDir, tplFP, tplOK = nil, "", dirFingerprint{}, false
	tplMu.Unlock()
}

// ===== tag 黑白名单过滤 =====

// FilterTemplatesByTags 按 tag 黑白名单筛选模板(条件不区分大小写)。
//
// 条件词可以是 tag, 也可以是 severity 名称(critical/high/medium/low/info) ——
// 用户习惯说"只加载 critical/high 模板", 实际 severity 是独立字段, 这里一并匹配。
//
//   - includeTags 非空: 仅保留 tag 或 severity 与白名单有交集的模板
//   - excludeTags 非空: 剔除 tag 或 severity 与黑名单有交集的模板
//   - 两者可叠加: 先白名单后黑名单
func FilterTemplatesByTags(tpls []Template, includeTags, excludeTags []string) []Template {
	inc := normTagSet(includeTags)
	exc := normTagSet(excludeTags)
	if len(inc) == 0 && len(exc) == 0 {
		return tpls
	}
	out := make([]Template, 0, len(tpls))
	for _, t := range tpls {
		mark := templateTagMarks(&t)
		if len(inc) > 0 && !setIntersects(mark, inc) {
			continue
		}
		if setIntersects(mark, exc) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// templateTagMarks 模板的 "tag + severity" 标记集合(小写)
func templateTagMarks(t *Template) map[string]bool {
	m := map[string]bool{}
	if t.Info == nil {
		return m
	}
	for _, tag := range t.Info.Tags {
		if s := strings.ToLower(strings.TrimSpace(tag)); s != "" {
			m[s] = true
		}
	}
	if s := strings.ToLower(strings.TrimSpace(t.Info.Severity)); s != "" {
		m[s] = true
	}
	return m
}

func normTagSet(list []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range list {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			m[s] = true
		}
	}
	return m
}

func setIntersects(a, b map[string]bool) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}
