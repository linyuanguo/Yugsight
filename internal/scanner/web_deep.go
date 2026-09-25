package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ===== Web 深度扫描 =====
//
// 与 WebScan 的分工: WebScan 是"单 URL 固定脚本"(敏感路径清单 + 1 条 SQLi 错误回显
// + 1 条 XSS 参数回显 + 路径穿越 + 安全头/Cookie/TLS 基线), 无爬虫、不区分注入类型、
// 也不提交表单。本文件在其之上补"同源轻量爬虫 + POST + 多类型注入", 两者由开关分离:
//
//	webdeep=false(默认) → 只跑 WebScan, 行为与输出完全不变;
//	webdeep=true        → WebScan 跑完后再跑 WebScanDeep(本文件)。
//
// 必须显式开启的原因: 爬虫会按页面上限发起数十倍于单 URL 的请求, 时间盲注还要等
// 服务端延时 —— 默认打开会把"点一下扫描"变成"把一个站打挂"(项目规则 5)。

// 深度扫描的可调上限。用包级变量而非常量, 便于离线用例按本地 httptest 服务器调整。
var (
	webDeepMaxDepth      = 2               // 爬取深度上限(首页为 0)
	webDeepMaxPages      = 50              // 爬取页面数上限
	webDeepConcurrency   = 8               // 爬取并发
	webDeepMaxPoints     = 12              // 注入点上限(页面 × 参数组合可能非常多)
	webDeepMaxTimeProbes = 5               // 时间盲注目标上限(每个目标要等服务端延时, 最贵)
	webDeepSleepSec      = 3               // 时间盲注载荷的睡眠秒数
	webDeepTimeDelta     = 2 * time.Second // 判定"确实睡了"的延时差阈值
)

// webDeepBodyLimit 单响应读取上限(与 WebScan 同样 1MB, 防大响应吃内存)。
const webDeepBodyLimit = 1 << 20

// newWebDeepClient 深度扫描的 HTTP 客户端。
//
// 配置与 WebScan 内的 client 逐项一致(跳过证书校验 / 走环境代理 / 重定向上限 5 /
// 15s 超时), 保证同一目标在两种模式下的网络行为可比 —— 不一致会让"深度扫描能爬到、
// 普通扫描却连不上"这种差异变成排查迷宫。
func newWebDeepClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// webResp 一次请求的可比较快照。
//
// 注入判定全部建立在"与基线响应比较"之上, 所以必须同时留下状态码/正文/耗时:
// 只有正文能判回显, 只有耗时尚能判时间盲注。
type webResp struct {
	status  int
	body    string
	hdr     string
	elapsed time.Duration
}

// sameResp 判定两次响应是否"一致"(状态码 + 正文完全相等)。
//
// 刻意不用长度/哈希近似: 布尔盲注的判据是"真条件与基线逐字节相同、假条件不同",
// 用近似值会把带时间戳、CSRF token 的动态页面全部算成"不同", 直接漏报。
func sameResp(a, b webResp) bool { return a.status == b.status && a.body == b.body }

// webForm 页面上解析出的一个表单。
type webForm struct {
	Action    string   // 绝对 URL
	Method    string   // GET / POST
	Fields    []string // 可提交的字段名(已剔除 submit/button 之类)
	Multipart bool     // enctype="multipart/form-data"(文件上传表单)
}

// webPoint 一个注入点(带参数的目标)。
type webPoint struct {
	Method    string   // GET / POST
	Target    string   // 完整 URL
	Fields    []string // 参数名/字段名
	Multipart bool     // multipart 上传表单(文件上传探测用)
}

// webDeep 一次深度扫描的运行时状态。
type webDeep struct {
	client      *http.Client
	base        *url.URL
	emit        Emit
	ruleFilter  map[string]bool
	baseline404 int

	emitMu sync.Mutex // 爬虫是并发的, emit 必须串行
	mu     sync.Mutex // 保护以下共享状态
	seen   map[string]bool
	pages  int
	points []webPoint
}

// WebScanDeep 深度 Web 扫描入口(webdeep 开关打开时调用)。
//
// 只做"WebScan 没有的那一半": 同源爬虫 → 表单/参数发现 → 注入探测。
// WebScan 的基线能力由调用方先行执行(main.go 的 case "web"), 因此这里不重复
// 敏感路径/安全头/TLS 探测 —— 重复只会让同一条发现上报两次。
func WebScanDeep(rawURL string, emit Emit, ruleFilter map[string]bool) {
	u, err := normalizeURL(rawURL)
	if err != nil {
		return // URL 无效时 WebScan 已给出提示, 不重复报错
	}
	d := &webDeep{
		client:     newWebDeepClient(),
		base:       u,
		emit:       emit,
		ruleFilter: ruleFilter,
		seen:       map[string]bool{},
	}
	d.baseline404 = d.probe404()

	d.emitf("status", map[string]any{
		"msg": fmt.Sprintf("深度扫描: 同源爬虫启动 (深度≤%d, 页面≤%d, 并发 %d)",
			webDeepMaxDepth, webDeepMaxPages, webDeepConcurrency),
	})
	d.crawl()

	d.mu.Lock()
	nPoints, nPages := len(d.points), d.pages
	d.mu.Unlock()
	d.emitf("status", map[string]any{
		"msg": fmt.Sprintf("深度扫描: 爬取 %d 个页面, 发现 %d 个注入点", nPages, nPoints),
	})
	if nPoints == 0 {
		d.emitf("status", map[string]any{"msg": "深度扫描: 未发现带参数的表单/链接, 跳过注入探测"})
		d.emitf("status", map[string]any{"msg": "Web 深度扫描完成"})
		return
	}

	d.emitf("status", map[string]any{"msg": "注入探测 (SQLi: union / 布尔 / 时间盲注; XSS: 参数 / POST / body)..."})
	d.emitf("info", map[string]any{"key": "深度扫描", "value": fmt.Sprintf("注入点 %d 个", nPoints)})
	for i, p := range d.pointsSnapshot() {
		d.probeSQLi(p)
		if i < webDeepMaxTimeProbes {
			d.probeTimeSQLi(p)
		}
		d.probeXSS(p)
	}
	d.emitf("status", map[string]any{"msg": "Web 深度扫描完成"})
}

// emitf 串行上报事件(爬虫并发调用 emit, 必须加锁)。
func (d *webDeep) emitf(event string, data any) {
	d.emitMu.Lock()
	defer d.emitMu.Unlock()
	d.emit(event, data)
}

// probe404 取 404 基线状态码。
//
// 很多站点把 404 配成 200(自定义错误页)或 302(跳首页), 用"状态码==404"去重会
// 把这些页面全部当成有效页面继续爬, 深度扫描的请求量立刻失控。
func (d *webDeep) probe404() int {
	base := *d.base
	base.Path = "/" + randomHex(12)
	base.RawQuery = ""
	base.Fragment = ""
	r, err := d.client.Get(base.String())
	if err != nil {
		return 404
	}
	defer r.Body.Close()
	return r.StatusCode
}

// crawl BFS 爬取同源页面: 逐层展开, 每层并发, 受页面上限约束。
func (d *webDeep) crawl() {
	frontier := []string{d.base.String()}
	d.seen[d.base.String()] = true
	for depth := 0; depth <= webDeepMaxDepth && len(frontier) > 0; depth++ {
		var next []string
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, webDeepConcurrency)
		for _, raw := range frontier {
			if d.pageFull() {
				break
			}
			wg.Add(1)
			go func(raw string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				links := d.visit(raw)
				mu.Lock()
				next = append(next, links...)
				mu.Unlock()
			}(raw)
		}
		wg.Wait()
		frontier = next
	}
}

// visit 抓取并解析一个页面, 返回待爬的同源链接。
func (d *webDeep) visit(raw string) []string {
	r := d.doGet(raw)
	if r == nil || r.status == d.baseline404 {
		return nil
	}
	d.mu.Lock()
	d.pages++
	d.mu.Unlock()

	pageURL, err := url.Parse(raw)
	if err != nil {
		return nil
	}

	// 表单 → 注入点(POST 为主, 也有 method=GET 的搜索表单)
	for _, f := range parseForms(raw, r.body) {
		d.addPoint(webPoint{Method: f.Method, Target: f.Action, Fields: f.Fields, Multipart: f.Multipart})
	}
	// URL 自带查询参数 → GET 注入点
	if q := pageURL.Query(); len(q) > 0 {
		names := make([]string, 0, len(q))
		for k := range q {
			names = append(names, k)
		}
		sort.Strings(names)
		d.addPoint(webPoint{Method: "GET", Target: raw, Fields: names})
	}

	// 漏洞库规则匹配(与 WebScan 同口径: 受 ruleFilter 约束, 首页已由 WebScan 跑过)
	if hits := MatchRulesFiltered(r.body, r.hdr, d.ruleFilter); len(hits) > 0 {
		for _, hit := range hits {
			fix := FixFor(hit.Name + " " + hit.Detail)
			if fix == "" {
				fix = fixGenericVuln
			}
			d.emitf("finding", NewFinding(hit.Severity, "["+hit.ID+"] "+hit.Name,
				fmt.Sprintf("%s (页面 %s)", hit.Detail, raw), fix))
		}
	}

	var links []string
	for _, m := range reHref.FindAllStringSubmatch(r.body, -1) {
		abs := resolveURL(pageURL, m[1])
		if abs == "" || !sameOrigin(d.base, abs) {
			continue
		}
		d.mu.Lock()
		if d.seen[abs] || d.pages >= webDeepMaxPages {
			d.mu.Unlock()
			continue
		}
		d.seen[abs] = true
		d.mu.Unlock()
		links = append(links, abs)
	}
	return links
}

func (d *webDeep) pageFull() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pages >= webDeepMaxPages
}

func (d *webDeep) pointsSnapshot() []webPoint {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]webPoint, len(d.points))
	copy(out, d.points)
	return out
}

// addPoint 登记注入点(去重 + 上限)。
func (d *webDeep) addPoint(p webPoint) {
	if p.Method == "" {
		p.Method = "GET"
	}
	p.Method = strings.ToUpper(p.Method)
	if p.Method != "POST" {
		p.Method = "GET"
	}
	if len(p.Fields) == 0 || p.Target == "" {
		return
	}
	key := p.Method + " " + p.Target
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.points) >= webDeepMaxPoints {
		return
	}
	for _, e := range d.points {
		if e.Method+" "+e.Target == key {
			return
		}
	}
	d.points = append(d.points, p)
}

// ===== 请求 =====

func (d *webDeep) doGet(raw string) *webResp {
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return nil
	}
	return d.do(req)
}

// request 按注入点发一次请求: 除 field 用 value 外, 其余参数填良性值 "1"。
//
// 其它参数也必须带上 —— 只发单个参数会被应用判为"参数缺失"直接 400/跳首页,
// 响应与基线毫无可比性, 三类注入判定会同时失效。
func (d *webDeep) request(p webPoint, field, value string) *webResp {
	kv := make([]string, 0, len(p.Fields)*2)
	for _, f := range p.Fields {
		v := "1"
		if f == field {
			v = value
		}
		kv = append(kv, f, v)
	}
	return d.send(p.Method, p.Target, kv)
}

// send 按 method 组装请求(kv 为有序的 key,value 交替切片)。
func (d *webDeep) send(method, target string, kv []string) *webResp {
	if method == "POST" {
		form := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			form.Set(kv[i], kv[i+1])
		}
		req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		if err != nil {
			return nil
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return d.do(req)
	}
	u := target
	for i := 0; i+1 < len(kv); i += 2 {
		u = withParam(u, kv[i], kv[i+1])
	}
	return d.doGet(u)
}

// do 执行请求并取快照。任何错误都返回 nil(网络异常不等于有漏洞, 静默跳过)。
func (d *webDeep) do(req *http.Request) *webResp {
	start := time.Now()
	resp, err := d.client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, webDeepBodyLimit))
	var hb strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			hb.WriteString(k)
			hb.WriteString(": ")
			hb.WriteString(v)
			hb.WriteString("\n")
		}
	}
	return &webResp{status: resp.StatusCode, body: string(b), hdr: hb.String(), elapsed: elapsed}
}

// postRaw 发一个自定义 content-type 的 POST(用于 JSON body 位置的 XSS 探测)。
func (d *webDeep) postRaw(target, contentType, payload string) *webResp {
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", contentType)
	return d.do(req)
}

// ===== SQL 注入探测 =====

// probeSQLi union/错误回显 + 布尔盲注两类(时间盲注另计, 见 probeTimeSQLi)。
func (d *webDeep) probeSQLi(p webPoint) {
	for _, field := range p.Fields {
		base := d.request(p, field, "1")
		if base == nil {
			continue
		}
		d.probeUnionSQLi(p, field, *base)
		d.probeBooleanSQLi(p, field, *base)
	}
}

// probeUnionSQLi union / 错误回显类。
//
// 判据: 基线响应不含 SQL 错误特征, 而注入响应含有 —— "基线比较"是防误报的关键,
// 站点自身就带 "SQLSTATE" 字样(如错误页模板)时不能算漏洞。
func (d *webDeep) probeUnionSQLi(p webPoint, field string, base webResp) {
	if sqlSignatureIn(base.body) != "" {
		return
	}
	payloads := []string{"1'", "1' UNION SELECT NULL-- ", "1 UNION SELECT NULL-- "}
	for _, pl := range payloads {
		r := d.request(p, field, pl)
		if r == nil {
			continue
		}
		if sig := sqlSignatureIn(r.body); sig != "" {
			d.emitf("finding", NewFinding("high", "疑似 SQL 注入 (UNION/错误回显)",
				fmt.Sprintf("%s %s 参数 %s 注入 %q 后响应出现 SQL 错误特征 %q",
					p.Method, p.Target, field, pl, sig), fixSQLi))
			return
		}
	}
}

// probeBooleanSQLi 布尔盲注。
//
// 判据: 真条件响应与基线一致, 且假条件响应与基线不一致。两个条件同时成立才报 ——
// 只看"假条件不同"会把任何对未知参数敏感的页面(如参数校验失败跳首页)误判成注入。
func (d *webDeep) probeBooleanSQLi(p webPoint, field string, base webResp) {
	pairs := [][2]string{
		{"1 AND 1=1", "1 AND 1=2"},
		{"1' AND '1'='1", "1' AND '1'='2"},
	}
	for _, pair := range pairs {
		rt := d.request(p, field, pair[0])
		rf := d.request(p, field, pair[1])
		if rt == nil || rf == nil {
			continue
		}
		// 404 基线去重: 参数被判非法而跳到错误页时, 状态码变化与注入无关
		if rt.status == d.baseline404 || rf.status == d.baseline404 {
			continue
		}
		if sameResp(*rt, base) && !sameResp(*rf, base) {
			d.emitf("finding", NewFinding("high", "疑似 SQL 注入 (布尔盲注)",
				fmt.Sprintf("%s %s 参数 %s: 真条件 %q 与基线一致, 假条件 %q 响应不同",
					p.Method, p.Target, field, pair[0], pair[1]), fixSQLi))
			return
		}
	}
}

// probeTimeSQLi 时间盲注。
//
// 判据: 睡眠载荷耗时显著超过"零睡眠"对照请求, 同时也超过基线 —— 双基线是为了排除
// 网络抖动与服务端偶发慢查询(只看绝对值会把一次 GC 停顿报成漏洞)。
func (d *webDeep) probeTimeSQLi(p webPoint) {
	if len(p.Fields) == 0 {
		return
	}
	field := p.Fields[0]
	base := d.request(p, field, "1")
	if base == nil {
		return
	}
	sleep := fmt.Sprintf("1 AND SLEEP(%d)", webDeepSleepSec)
	sleepQ := fmt.Sprintf("1' AND SLEEP(%d)-- ", webDeepSleepSec)
	control := "1 AND SLEEP(0)"
	for _, pl := range []string{sleep, sleepQ} {
		rc := d.request(p, field, control)
		rs := d.request(p, field, pl)
		if rs == nil || rc == nil {
			continue
		}
		if rs.elapsed-rc.elapsed >= webDeepTimeDelta && rs.elapsed-base.elapsed >= webDeepTimeDelta {
			d.emitf("finding", NewFinding("high", "疑似 SQL 注入 (时间盲注)",
				fmt.Sprintf("%s %s 参数 %s 注入 %q 后响应耗时 %v, 对照 %q 耗时 %v (基线 %v)",
					p.Method, p.Target, field, pl, rs.elapsed.Round(time.Millisecond),
					control, rc.elapsed.Round(time.Millisecond), base.elapsed.Round(time.Millisecond)),
				fixSQLi))
			return
		}
	}
}

// sqlSignatureIn 返回正文中出现的 SQL 错误特征(无则返回空串)。
func sqlSignatureIn(body string) string {
	lb := strings.ToLower(body)
	for _, sig := range sqliSignatures {
		if strings.Contains(lb, sig) {
			return sig
		}
	}
	return ""
}

// ===== XSS 探测 =====

// probeXSS 多位置回显探测: GET 参数 / POST 表单 / JSON body。
func (d *webDeep) probeXSS(p webPoint) {
	if p.Method == "POST" {
		d.probeXSSPostForm(p)
		d.probeXSSPostJSON(p)
		return
	}
	// GET: 逐参数打各自的标记, 这样才能指出"是哪个参数回显了"
	for _, field := range p.Fields {
		marker := xssMarker(field)
		r := d.request(p, field, marker)
		if r == nil || !strings.Contains(r.body, marker) {
			continue
		}
		d.emitf("finding", NewFinding("medium", "查询参数原样回显 (潜在 XSS)",
			fmt.Sprintf("GET %s 的参数 %s 原样出现在响应中(未转义)", p.Target, field), fixXSS))
	}
}

// probeXSSPostForm 表单 POST(urlencoded): 一次请求给每个字段打不同标记,
// 命中哪些标记就说明哪些字段回显 —— "多字段回显"一次请求即可定位。
func (d *webDeep) probeXSSPostForm(p webPoint) {
	marks := make(map[string]string, len(p.Fields))
	kv := make([]string, 0, len(p.Fields)*2)
	for _, f := range p.Fields {
		m := xssMarker(f)
		marks[f] = m
		kv = append(kv, f, m)
	}
	r := d.send("POST", p.Target, kv)
	if r == nil {
		return
	}
	if hit := reflectedFields(r.body, marks); len(hit) > 0 {
		d.emitf("finding", NewFinding("medium", "POST 表单参数原样回显 (潜在 XSS)",
			fmt.Sprintf("POST %s 的字段 %s 原样出现在响应中(未转义)",
				p.Target, strings.Join(hit, ", ")), fixXSS))
	}
}

// probeXSSPostJSON JSON body: 只拼表单的回显不算完 —— 很多接口根本不读
// urlencoded, 只在 JSON 反序列化后把字段拼进响应/邮件/日志页。
func (d *webDeep) probeXSSPostJSON(p webPoint) {
	marks := make(map[string]string, len(p.Fields))
	var b strings.Builder
	b.WriteByte('{')
	for i, f := range p.Fields {
		m := xssMarker(f)
		marks[f] = m
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(jsonEscape(f))
		b.WriteString(`":"`)
		b.WriteString(jsonEscape(m))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	r := d.postRaw(p.Target, "application/json", b.String())
	if r == nil {
		return
	}
	if hit := reflectedFields(r.body, marks); len(hit) > 0 {
		d.emitf("finding", NewFinding("medium", "JSON body 字段原样回显 (潜在 XSS)",
			fmt.Sprintf("POST %s (application/json) 的字段 %s 原样出现在响应中(未转义)",
				p.Target, strings.Join(hit, ", ")), fixXSS))
	}
}

// reflectedFields 找出响应里被原样回显的字段(按字段顺序返回, 输出稳定)。
func reflectedFields(body string, marks map[string]string) []string {
	var hit []string
	for _, f := range sortedKeys(marks) {
		if strings.Contains(body, marks[f]) {
			hit = append(hit, f)
		}
	}
	return hit
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// xssMarker 生成与字段绑定的唯一标记。
//
// 带字段名是为了让"哪个参数回显了"自解释; 带随机后缀是为了避免与页面固有文本
// (或上一次请求的缓存响应)撞上导致误报。
func xssMarker(field string) string {
	var b strings.Builder
	for _, r := range field {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return "netscanxss" + b.String() + randomHex(4)
}

func jsonEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// ===== 解析 =====

var (
	reHref  = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	reForm  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	reInput = regexp.MustCompile(`(?is)<(?:input|textarea|select)\b([^>]*)>`)
	reAttr  = regexp.MustCompile(`(?i)([a-zA-Z_:.-]+)\s*=\s*"([^"]*)"`)
)

// parseForms 从页面正文解析表单(动作 + 方法 + 字段名)。
func parseForms(pageURL, body string) []webForm {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	var out []webForm
	for _, m := range reForm.FindAllStringSubmatch(body, -1) {
		method := strings.ToUpper(strings.TrimSpace(attrVal(m[1], "method")))
		if method == "" {
			method = http.MethodGet
		}
		if method != http.MethodPost {
			method = http.MethodGet // 其它方法(PUT 等)按 GET 参数处理, 不额外发非常规请求
		}
		action := resolveURL(base, attrVal(m[1], "action"))
		if action == "" {
			action = pageURL
		}
		var fields []string
		for _, im := range reInput.FindAllStringSubmatch(m[2], -1) {
			name := strings.TrimSpace(attrVal(im[1], "name"))
			if name == "" {
				continue
			}
			typ := strings.ToLower(attrVal(im[1], "type"))
			if typ == "submit" || typ == "button" || typ == "reset" || typ == "image" {
				continue
			}
			fields = append(fields, name)
		}
		if len(fields) == 0 {
			continue
		}
		out = append(out, webForm{
			Action:    action,
			Method:    method,
			Fields:    fields,
			Multipart: strings.Contains(strings.ToLower(attrVal(m[1], "enctype")), "multipart/form-data"),
		})
	}
	return out
}

// attrVal 取标签属性串里某个属性的值(只认双引号写法, 够用且不会跨标签误匹配)。
func attrVal(tag, name string) string {
	for _, m := range reAttr.FindAllStringSubmatch(tag, -1) {
		if strings.EqualFold(m[1], name) {
			return m[2]
		}
	}
	return ""
}

// resolveURL 把页面里的相对链接解析为绝对 URL, 非 http(s)/锚点/伪协议返回空串。
func resolveURL(page *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") {
		return ""
	}
	low := strings.ToLower(href)
	if strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "mailto:") ||
		strings.HasPrefix(low, "tel:") || strings.HasPrefix(low, "data:") {
		return ""
	}
	u, err := page.Parse(href)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	u.Fragment = ""
	return u.String()
}

// sameOrigin 同源判定(协议 + 主机相同)。跨域链接一律不爬 —— 深度扫描的授权
// 范围就是用户填的那一个站, 顺着外链爬出去等于未经许可扫别人。
func sameOrigin(base *url.URL, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == base.Scheme && strings.EqualFold(u.Host, base.Host)
}

// withParam 设置/替换 URL 上的查询参数, 返回新 URL。
func withParam(rawURL, key, val string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, val)
	u.RawQuery = q.Encode()
	return u.String()
}
