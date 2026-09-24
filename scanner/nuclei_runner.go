//go:build !windows || windows

// nuclei_runner.go Nuclei 模板执行引擎(可选插件, 不改变 web.go 原有扫描逻辑)。
//
// 三层架构(模块解耦, 便于替换主机漏洞规则):
//   - 解析层 nuclei_parser.go:     YAML -> Template, 目录加载/缓存/热更新, tag 与指纹过滤
//   - 匹配判定层 nuclei_matcher.go: matcher / DSL 判定(纯函数, 无网络)
//   - 执行层(本文件):              并发请求、超时、响应截断与释放、降噪、去重、SSE 推送
//
// 定位: 接在主机扫描流水线之后 —— host 指纹(产品+版本)输出后, 用
// FilterTemplatesByFingerprint 筛出适用模板, 本执行器逐模板发请求、
// 跑 matcher, 命中经 emit("finding", ...) 走现有 SSE 并入漏洞列表。
//
// 并发与安全:
//   - 全局并发池(跨所有目标) + 单目标最大并发 + 单模板执行超时, 防止压垮业务
//   - 响应按 MaxResponseBytes 截断, 结果证据只保留前 20KB, 防大响应内存膨胀
//   - 每次请求读完即有界排空并 Close 响应体, 不让 http body 滞留
//   - 目标协议仅允许 http/https(复用 web.go 的 normalizeURL), 并拦截云元数据地址;
//     模板经 nuclei_parser 静态映射为结构体, 无任何代码执行/系统命令调用路径
//
// 降噪:
//   - 同一 IP+Port+CVE(无 CVE 则模板 ID)整个进程只上报一次
//   - 404 响应不报(基线误报过滤)
//   - 响应相似度: 同一目标返回过相同响应体(如 WAF 拦截页/统一错误页)时,
//     后续仅由 body 类 matcher(word/regex/dsl) 命中的结果被抑制,
//     status/header 类结构性命中仍然上报
//
// SSE:
//   - 每个模板命中立即 emit("finding", NucleiFinding) 实时推送,
//     与内置规则(vuln_builtin.json)的 finding 事件格式完全统一
//   - NucleiFinding 带 source 字段, 前端可区分规则来源:
//     "nuclei"=外部模板 / "nuclei-builtin"=内置模板(exe 打包) / 空=内置规则
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServiceAsset 服务资产(主机指纹的输出单元): 一台主机的一个服务端口 + 产品版本。
// 由流水线在 host 指纹阶段产出(见 BuildServiceAssets), 作为本执行器的输入。
type ServiceAsset struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Scheme  string `json:"scheme"`  // http / https
	Product string `json:"product"` // 产品键(nginx/apache/iis/tomcat...), 与 nuclei tag 对齐
	Version string `json:"version"` // 版本号(可能为空)
	Banner  string `json:"banner"`
}

// HostPort 返回 "ip:port"; 默认端口(http 80 / https 443)省略
func (a ServiceAsset) HostPort() string {
	if (a.Scheme == "http" && a.Port == 80) || (a.Scheme == "https" && a.Port == 443) {
		return a.IP
	}
	return net.JoinHostPort(a.IP, strconv.Itoa(a.Port))
}

// buildURL 把模板中的 path 拼成完整 URL(path 允许直接写完整 URL)
func (a ServiceAsset) buildURL(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		p = "/"
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return a.Scheme + "://" + a.HostPort() + p
}

// RunnerConfig 执行器配置(保守默认值, 防止压垮目标)
type RunnerConfig struct {
	GlobalConcurrency   int           // 全局并发池(跨所有目标/模板), 默认 16
	TargetConcurrency   int           // 单目标最大并发, 默认 4
	TemplateTimeout     time.Duration // 单模板执行总超时(覆盖其全部请求), 默认 10s
	MaxResponseBytes    int           // 单响应最大读取字节(防大响应内存膨胀), 默认 512KB
	MaxRequestBodyBytes int           // 单请求体最大字节, 默认 1MB
	// 关闭"重复响应页"降噪(默认开启): 同目标相同响应体再次命中、
	// 且仅 body 类 matcher 参与时抑制, 防统一错误页造成正则误报刷屏
	DisableRepeatDenoise bool
	// PriorityOrder 按 KEV 标记 / EPSS 分值 / 严重级别对模板列表重排序后再执行
	// (高危漏洞优先占用并发池, 见 intel.go PrioritizeRules);
	// 默认 false = 保持原模板顺序, 行为不变
	PriorityOrder bool
}

// DefaultRunnerConfig 返回保守默认配置
func DefaultRunnerConfig() RunnerConfig {
	return RunnerConfig{
		GlobalConcurrency:   16,
		TargetConcurrency:   4,
		TemplateTimeout:     10 * time.Second,
		MaxResponseBytes:    512 * 1024,
		MaxRequestBodyBytes: 1 << 20,
	}
}

// NucleiFinding 模板命中结果。内嵌 Finding 保证与现有漏洞结构完全兼容
// (SSE "finding" 事件、report.html 按 severity/title/detail 渲染, 零改动);
// 其余字段是证据与溯源, 供前端按需展示 raw 请求/响应包。
//
// Source 标记规则来源, 与内置规则(vuln_builtin.json, 无该字段)区分:
//   - "nuclei"         外部 Nuclei 模板(exe 同目录 templates/)
//   - "nuclei-builtin" 内置 Nuclei 模板(exe 内打包, templates_builtin/)
type NucleiFinding struct {
	Finding
	Source      string   `json:"source,omitempty"`
	TemplateID  string   `json:"templateId"`
	CVE         string   `json:"cve,omitempty"`
	References  []string `json:"references,omitempty"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	RawRequest  string   `json:"rawRequest,omitempty"`
	RawResponse string   `json:"rawResponse,omitempty"`
}

// evidenceLimit 结果中 raw 证据的最大长度: 大响应只保留前 20KB 作为证据,
// 防 SSE 流/报告被巨大响应撑爆(matcher 判定用全量 body, 证据留存限量)
const evidenceLimit = 20 * 1024

// NucleiRunner 模板执行引擎。Transport 全进程一份(与 web.go 同参数:
// InsecureSkipVerify + 系统代理), 所有模板请求共享同一连接池。
// 单目标并发池每次 RunNucleiTemplates 调用内新建(按目标隔离)。
type NucleiRunner struct {
	cfg      RunnerConfig
	client   *http.Client
	sem      chan struct{} // 全局并发池
	dMu      sync.Mutex
	dedup    map[string]bool // 去重键: ip:port:cve(或模板 ID)
	respMu   sync.Mutex
	respSeen map[string]struct{} // 重复响应页降噪: "ip:port|状态码|响应体指纹"
}

// NewNucleiRunner 创建执行器。零值配置字段按默认值补齐。
func NewNucleiRunner(cfg RunnerConfig) *NucleiRunner {
	d := DefaultRunnerConfig()
	if cfg.GlobalConcurrency <= 0 {
		cfg.GlobalConcurrency = d.GlobalConcurrency
	}
	if cfg.TargetConcurrency <= 0 {
		cfg.TargetConcurrency = d.TargetConcurrency
	}
	if cfg.TemplateTimeout <= 0 {
		cfg.TemplateTimeout = d.TemplateTimeout
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = d.MaxResponseBytes
	}
	if cfg.MaxRequestBodyBytes <= 0 {
		cfg.MaxRequestBodyBytes = d.MaxRequestBodyBytes
	}
	return &NucleiRunner{
		cfg: cfg,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 16,
				IdleConnTimeout:     30 * time.Second,
			},
			// 不做整体 Timeout: 超时由单模板 context 控制(覆盖模板内全部请求)
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		sem:      make(chan struct{}, cfg.GlobalConcurrency),
		dedup:    make(map[string]bool),
		respSeen: make(map[string]struct{}),
	}
}

// markRespSeen 记录一次响应指纹, 返回"此前是否见过相同响应"(同目标+同状态码+同响应体)。
// 带上限保护, 防止超长扫描中该表无限增长。
func (r *NucleiRunner) markRespSeen(hostPort string, code int, body string) bool {
	if r.cfg.DisableRepeatDenoise {
		return false // 降噪关闭时不做指纹计算与记录, 直接放行
	}
	key := fmt.Sprintf("%s|%d|%s", hostPort, code, respFingerprint(body))
	r.respMu.Lock()
	defer r.respMu.Unlock()
	if len(r.respSeen) > 50000 {
		r.respSeen = make(map[string]struct{}, 4096) // 超限整体重置(降噪是概率性收益, 不值得无限内存)
	}
	if _, seen := r.respSeen[key]; seen {
		return true
	}
	r.respSeen[key] = struct{}{}
	return false
}

// RunNucleiTemplates 对单个资产执行一组模板(内部再按指纹过滤一次, 幂等)。
// 并发: 全局池 + 单目标池; 每个模板独立超时。
// 命中经 emit("finding", NucleiFinding) 实时推给前端; 返回值是去重后的完整列表,
// 供流水线合并进原漏洞结果集/报告。
func (r *NucleiRunner) RunNucleiTemplates(a ServiceAsset, tpls []Template, emit Emit) []NucleiFinding {
	tpls = FilterTemplatesByFingerprint(tpls, a.Product, a.Version)
	if r.cfg.PriorityOrder {
		tpls = PrioritizeRules(tpls) // KEV -> EPSS -> 严重级别: 高危漏洞优先执行验证
	}
	if len(tpls) == 0 {
		if emit != nil {
			emit("status", map[string]any{"msg": fmt.Sprintf("nuclei: %s 无适用模板(产品 %s), 跳过", a.HostPort(), a.Product)})
		}
		return nil
	}
	if emit != nil {
		emit("status", map[string]any{"msg": fmt.Sprintf("nuclei 模板扫描: %s (%s %s), %d 个模板",
			a.HostPort(), a.Product, a.Version, len(tpls))})
	}

	tsem := make(chan struct{}, r.cfg.TargetConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []NucleiFinding

	for _, tpl := range tpls {
		tpl := tpl
		if tpl.IsWorkflow || len(tpl.AllRequests()) == 0 || len(tpl.Matchers) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.sem <- struct{}{} // 全局并发池
			defer func() { <-r.sem }()
			tsem <- struct{}{} // 单目标并发池
			defer func() { <-tsem }()

			// 命中在 RunTemplate 内部逐条 emit("finding") 实时推送(SSE),
			// 与内置规则的事件格式完全一致; 返回值供流水线合并进报告
			hits := r.RunTemplate(a, tpl, emit)
			if len(hits) == 0 {
				return
			}
			mu.Lock()
			out = append(out, hits...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if emit != nil {
		emit("status", map[string]any{"msg": fmt.Sprintf("nuclei 模板扫描完成: %s, 命中 %d 条(已去重)", a.HostPort(), len(out))})
	}
	return out
}

// RunTemplate 执行单个模板: 渲染 -> 请求 -> matcher 判定(判定层) -> 组装结果。
// 单模板超时; 单个请求失败只记日志, 不影响模板内其他请求。
// 每产生一条命中立即经 emit("finding") 实时推送(SSE 流式), 不再等模板跑完。
func (r *NucleiRunner) RunTemplate(a ServiceAsset, tpl Template, emit Emit) []NucleiFinding {
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.TemplateTimeout)
	defer cancel()
	// 变量替换器: 同一模板的全部请求共享一个(替代每请求新建 strings.Replacer)
	rep := newTargetReplacer(a)

	var out []NucleiFinding
	for _, req := range tpl.AllRequests() {
		paths := req.Paths
		if len(paths) == 0 {
			paths = []string{"/"}
		}
		for _, path := range paths {
			snap, err := r.doRequest(ctx, a, req, path, rep)
			if err != nil {
				if ctx.Err() == context.DeadlineExceeded {
					nucleiLog.Warn("模板执行超时, 跳过剩余请求", "tpl", tpl.ID, "target", a.HostPort())
					return out
				}
				nucleiLog.Debug("模板请求失败", "tpl", tpl.ID, "path", path, "err", err)
				continue
			}
			// 404 误报过滤: 命中 404 多为站点基线响应
			if snap.code == 404 {
				continue
			}
			// 重复响应页降噪: 记录响应指纹(同目标+同状态码+同响应体)
			repeatResp := r.markRespSeen(a.HostPort(), snap.code, snap.body)
			mctx := &matchCtx{statusCode: snap.code, body: snap.body, header: snap.header, cookies: snap.cookies}
			hit, matchedIdx := evalTemplateMatchersDetail(tpl.Matchers, mctx)
			if !hit {
				continue
			}
			if repeatResp && !r.cfg.DisableRepeatDenoise && !hasStructuralMatch(tpl.Matchers, matchedIdx) {
				// 该响应体此前出现过(如统一错误页/WAF 拦截页), 且本次命中
				// 全部来自 body 类 matcher(word/regex/dsl) => 大概率是同一错误页
				// 被不同模板/路径反复命中, 抑制以避免正则误报刷屏
				nucleiLog.Debug("重复响应页降噪: 抑制命中",
					"tpl", tpl.ID, "target", a.HostPort(), "path", path, "code", snap.code)
				continue
			}
			if f, ok := r.newFinding(a, tpl, snap, path); ok {
				out = append(out, f)
				if emit != nil {
					emit("finding", f) // 实时推送, 事件格式与内置规则统一
				}
			}
		}
	}
	return out
}

// respFingerprint 响应体指纹(重复响应页降噪用):
// 规范化(小写 + 空白压缩) + 截断前 64KB 后取 sha256。
// 同一错误页在多次响应中的空白/换行差异被消除, 大响应只取头部(错误页关键内容都在前部)。
func respFingerprint(body string) string {
	const fpLimit = 64 * 1024
	if len(body) > fpLimit {
		body = body[:fpLimit]
	}
	return sha256Hex([]byte(normalizeForFingerprint(body)))
}

// normalizeForFingerprint 小写 + 连续空白压缩为单空格
func normalizeForFingerprint(s string) string {
	var b strings.Builder
	b.Grow(len(s)/2 + 64)
	prevSpace := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		default:
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			b.WriteByte(c)
			prevSpace = false
		}
	}
	return b.String()
}

// respSnapshot 一次请求的响应快照(供 matcher 判定与证据留存)
type respSnapshot struct {
	code      int
	body      string
	header    string // "Key: Value\n" 格式, 与 vuln.go MatchRules 一致
	cookies   string
	rawReq    string
	rawResp   string
	truncated bool
}

// doRequest 渲染并发送单个请求, 返回响应快照。
// 安全限制: 目标必须通过 safeTarget 校验; 响应/请求体超限截断。
func (r *NucleiRunner) doRequest(ctx context.Context, a ServiceAsset, req Request, path string, rep *strings.Replacer) (*respSnapshot, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}
	urlStr, err := safeTarget(a.buildURL(rep.Replace(path)))
	if err != nil {
		return nil, err
	}
	body := rep.Replace(req.Body)
	if len(body) > r.cfg.MaxRequestBodyBytes {
		return nil, fmt.Errorf("请求体超过 %d 字节限制, 已放弃", r.cfg.MaxRequestBodyBytes)
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, urlStr, reader)
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Yugsight/1.0)")
	hreq.Header.Set("Accept", "*/*")
	for k, v := range req.Headers {
		if k == "" {
			continue
		}
		hreq.Header.Set(k, rep.Replace(v))
	}
	for k, v := range req.Cookies {
		if k == "" {
			continue
		}
		hreq.AddCookie(&http.Cookie{Name: k, Value: rep.Replace(v)})
	}

	resp, err := r.client.Do(hreq)
	if err != nil {
		return nil, err
	}
	// 读完即释放: 有界排空剩余字节(允许连接池复用)后 Close, 不让 http body 滞留
	truncated := false
	defer func() {
		closeResp(resp, truncated)
	}()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, int64(r.cfg.MaxResponseBytes)))
	truncated = len(raw) >= r.cfg.MaxResponseBytes
	var hb, cb strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			hb.WriteString(k + ": " + v + "\n")
		}
	}
	for _, v := range resp.Header["Set-Cookie"] {
		if cb.Len() > 0 {
			cb.WriteString(" ")
		}
		cb.WriteString(v)
	}
	return &respSnapshot{
		code:      resp.StatusCode,
		body:      string(raw),
		header:    hb.String(),
		cookies:   cb.String(),
		rawReq:    rawRequestText(hreq, body),
		rawResp:   rawResponseText(resp, raw, truncated),
		truncated: truncated,
	}, nil
}

// closeResp 释放响应: truncated 时先有界排空(最多 256KB, 允许 keep-alive 连接复用),
// 再 Close。响应体在快照构建期间被引用, 函数返回即随 GC 回收, 不跨请求滞留。
func closeResp(resp *http.Response, truncated bool) {
	if resp == nil || resp.Body == nil {
		return
	}
	if truncated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
	}
	_ = resp.Body.Close()
}

// renderTarget 替换模板文本中的 {{BaseURL}} / {{Host}} / {{Port}} / {{Scheme}} 变量
// (单次调用/测试用; 执行热路径用 newTargetReplacer, 同一目标共享一个替换器)
func renderTarget(s string, a ServiceAsset) string {
	return newTargetReplacer(a).Replace(s)
}

// newTargetReplacer 构建单目标的模板变量替换器, 由 RunTemplate 创建并
// 供该模板的全部请求共享, 避免每请求重复构造
func newTargetReplacer(a ServiceAsset) *strings.Replacer {
	return strings.NewReplacer(
		"{{BaseURL}}", a.Scheme+"://"+a.HostPort(),
		"{{Host}}", a.IP,
		"{{Port}}", strconv.Itoa(a.Port),
		"{{Scheme}}", a.Scheme,
	)
}

// safeTarget 校验渲染后的目标 URL:
//  1. 仅允许 http/https(复用 web.go normalizeURL, 拒绝 file:// gopher:// 等)
//  2. 拦截云元数据服务地址(169.254.169.254 等), 防 SSRF 拖取实例凭据
func safeTarget(raw string) (string, error) {
	u, err := normalizeURL(raw)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	switch host {
	case "169.254.169.254", "metadata.google.internal":
		return "", fmt.Errorf("禁止访问云元数据地址: %s", host)
	}
	return u.String(), nil
}

// rawRequestText 组装原始请求包文本(作为证据留存)
func rawRequestText(req *http.Request, body string) string {
	var b strings.Builder
	b.WriteString(req.Method + " " + req.URL.RequestURI() + " HTTP/1.1\r\n")
	b.WriteString("Host: " + req.URL.Host + "\r\n")
	for k, vs := range req.Header {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	for _, c := range req.Cookies() {
		b.WriteString("Cookie: " + c.Name + "=" + c.Value + "\r\n")
	}
	b.WriteString("\r\n")
	if body != "" {
		b.WriteString(body)
	}
	return b.String()
}

// rawResponseText 组装原始响应包文本(作为证据留存)
func rawResponseText(resp *http.Response, body []byte, truncated bool) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + resp.Status + "\r\n")
	for k, vs := range resp.Header {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	if truncated {
		b.WriteString("\n... (响应超出限制, 已截断)")
	}
	return b.String()
}

// clipEvidence 截断证据到 evidenceLimit
func clipEvidence(s string) string {
	if len(s) <= evidenceLimit {
		return s
	}
	return s[:evidenceLimit] + "\n... (证据已截断)"
}

// findingSource 按模板来源返回 finding 的 Source 标记
func findingSource(tpl Template) string {
	if tpl.Builtin {
		return "nuclei-builtin" // 内置模板(exe 打包)
	}
	return "nuclei" // 外部模板
}

// newFinding 组装命中结果并做去重: 同一 IP+Port+CVE(无 CVE 用模板 ID)只报一次。
// 返回 (结果, false) 表示已去重, 不应再次上报。
func (r *NucleiRunner) newFinding(a ServiceAsset, tpl Template, snap *respSnapshot, path string) (NucleiFinding, bool) {
	cves := tpl.CveIDs()
	cve := ""
	if len(cves) > 0 {
		cve = strings.Join(cves, ",")
	}
	key := fmt.Sprintf("%s:%d:%s", a.IP, a.Port, cve)
	if cve == "" {
		key = fmt.Sprintf("%s:%d:%s", a.IP, a.Port, tpl.ID)
	}
	r.dMu.Lock()
	if r.dedup[key] {
		r.dMu.Unlock()
		return NucleiFinding{}, false
	}
	r.dedup[key] = true
	r.dMu.Unlock()

	name := tpl.ID
	if tpl.Info != nil && tpl.Info.Name != "" {
		name = tpl.Info.Name
	}
	sev := "info"
	if tpl.Info != nil && tpl.Info.Severity != "" {
		sev = normalizeSeverity(tpl.Info.Severity)
	}
	var refs []string
	if tpl.Info != nil {
		refs = append(append([]string{}, tpl.Info.Reference...), tpl.Info.References...)
	}
	reqLine := path
	if i := strings.IndexByte(snap.rawReq, ' '); i > 0 {
		if j := strings.IndexByte(snap.rawReq, '\n'); j > i {
			reqLine = snap.rawReq[i+1 : j]
		}
	}
	detail := fmt.Sprintf("模板 %s 命中: %s 返回 %d", tpl.ID, reqLine, snap.code)
	if tpl.Info != nil && tpl.Info.Description != "" {
		detail = tpl.Info.Description + " —— " + detail
	}
	return NucleiFinding{
		Finding:     Finding{Severity: sev, Title: "[" + tpl.ID + "] " + name, Detail: detail},
		Source:      findingSource(tpl), // 规则来源标记(与内置规则 vuln_builtin.json 区分)
		TemplateID:  tpl.ID,
		CVE:         cve,
		References:  refs,
		Host:        a.IP,
		Port:        a.Port,
		RawRequest:  clipEvidence(snap.rawReq),
		RawResponse: clipEvidence(snap.rawResp),
	}, true
}

// normalizeSeverity 把 nuclei 的 severity 归一化到 Finding 的取值域
// (critical 在现有报告中无对应档, 映射为 high)
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "high"
	case "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "info"
	}
}

// ===== 流水线集成: 指纹 -> 资产 -> 模板执行 =====

// BuildServiceAssets 从端口扫描结果构建服务资产(与 host.go 指纹阶段等价:
// 开放端口 + 服务名 + 横幅版本提取), 可在流水线 host 指纹输出后直接调用。
func BuildServiceAssets(ip string, results []PortResult) []ServiceAsset {
	var out []ServiceAsset
	for _, p := range results {
		if p.State != "open" {
			continue
		}
		scheme := "http"
		if p.Port == 443 || p.Port == 8443 {
			scheme = "https"
		}
		// versionFromBanner 返回 "组件 版本"(如 "Apache 2.4.41"),
		// 这里只取版本号部分, 与 nuclei 版本 tag 格式(如 apache-2.4.41)对齐
		ver := versionFromBanner(p.Banner)
		if i := strings.LastIndex(ver, " "); i >= 0 {
			ver = ver[i+1:]
		}
		out = append(out, ServiceAsset{
			IP:      ip,
			Port:    p.Port,
			Scheme:  scheme,
			Product: productKey(p.Service),
			Version: ver,
			Banner:  p.Banner,
		})
	}
	return out
}

// productKeyMap 服务名 -> nuclei 产品 tag(小写)
var productKeyMap = map[string]string{
	"nginx":         "nginx",
	"apache httpd":  "apache",
	"microsoft iis": "iis",
	"apache tomcat": "tomcat",
	"jetty":         "jetty",
	"weblogic":      "weblogic",
	"openresty":     "openresty",
	"cloudflare":    "cloudflare",
	"spring boot":   "springboot",
	"nacos":         "nacos",
	"jenkins":       "jenkins",
	"httpd":         "apache",
}

// productKey 归一化服务名为产品键; 未知服务原样小写(通用模板仍会命中)
func productKey(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if k, ok := productKeyMap[n]; ok {
		return k
	}
	return n
}

// ===== 使用示例: 扫描流水线集成 =====
//
// main.go handleScan 的 "host" 分支(不改 web.go, nuclei 为可选插件):
//
//	case "host":
//	    ...
//	    // HostScan 指纹阶段直接输出服务资产(产品+版本), 无需重复端口探测
//	    assets := scanner.HostScan(ip, ports, timeout, conc, emit)
//
//	    // 可选插件: 全局开关(-nuclei) + 前端任务开关(enableNuclei) 同时开启才执行。
//	    // 与内置规则(vuln_builtin.json)是两套独立规则: 内置规则始终生效,
//	    // nuclei 为外部模板增强, 命中带 source 字段便于区分。
//	    if nucleiOn && req.EnableNuclei && len(assets) > 0 {
//	        // 1) 模板集: 内置(exe 打包) + 外部(预加载缓存/热更新), 不重复解析 yaml
//	        allTpls, loadErrs := scanner.LoadAllTemplates(nucleiDir())
//	        // 2) tag 黑白名单(前端可配置, 如 "cisa-kev,critical,high")
//	        tpls := scanner.FilterTemplatesByTags(allTpls,
//	            splitTags(req.NucleiTags), splitTags(req.NucleiTagsExclude))
//	        runner := scanner.NewNucleiRunner(scanner.DefaultRunnerConfig())
//	        for _, a := range assets {
//	            if !scanner.IsWebPort(a.Port) {
//	                continue // 只对 Web 端口跑 HTTP 模板, 避免向 SSH 等非 Web 服务发请求
//	            }
//	            // 3) 内部再按 a.Product/a.Version 指纹过滤; 每条命中实时
//	            //    emit("finding") 推送(SSE, 与内置规则事件格式统一)
//	            runner.RunNucleiTemplates(a, tpls, emit)
//	        }
//	    }
//
// 前端: scanReq 增加 enableNuclei(bool) / nucleiTags(string, 白名单逗号分隔) /
// nucleiTagsExclude(string, 黑名单逗号分隔) 三个字段; UI 在主机扫描页加
// 复选框 + 两个输入框, 默认关闭(不影响原有扫描行为)。
