package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// ===== 离线验证替身 =====
//
// 沙箱回环与外网出站均被拦, 深度扫描只能靠 httptest 本地服务器验证。
// 每个用例都让服务端"按载荷内容改变响应", 从而把爬虫 / SQLi 三类 / XSS 多位置的
// 判定逻辑与真实脆弱行为解耦 —— 判据被改坏(比如丢掉基线比较)时用例就会红。

// deepRec 收集 WebScanDeep 的事件(并发安全: 爬虫会多 goroutine 上报)。
type deepRec struct {
	mu       sync.Mutex
	findings []Finding
	status   []string
}

func (r *deepRec) emit(event string, data any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch v := data.(type) {
	case Finding:
		r.findings = append(r.findings, v)
	case map[string]any:
		if event == "status" {
			r.status = append(r.status, fmt.Sprint(v["msg"]))
		}
	}
}

func (r *deepRec) hasTitle(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.findings {
		if strings.Contains(f.Title, sub) {
			return true
		}
	}
	return false
}

func (r *deepRec) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.findings)
}

// webDeepServer 起一个 httptest 服务器: routes 未命中的路径一律 404。
//
// 404 兜底是必须的 —— 深度扫描先探 404 基线, 若服务端对任意路径都回 200,
// 基线就成了 200, 所有页面会被当成"与 404 一致"而跳过, 用例会假绿。
func webDeepServer(t *testing.T, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func htmlPage(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, body)
	}
}

// newTestDeep 构造一个只跑爬虫的 webDeep(绕过注入探测, 用于断言爬取状态)。
func newTestDeep(raw string, rec *deepRec) *webDeep {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	d := &webDeep{client: newWebDeepClient(), base: u, emit: rec.emit, seen: map[string]bool{}}
	d.baseline404 = d.probe404()
	return d
}

// TestWebDeepCrawlSameOriginAndForms 守卫爬虫契约: 同源链接逐层展开、表单与
// 字段被正确解析、跨域/伪协议链接一律不爬。爬虫若爬出授权范围, 一次"扫一个站"
// 就变成扫整个互联网 —— 属必须锁定的边界。
func TestWebDeepCrawlSameOriginAndForms(t *testing.T) {
	var mu sync.Mutex
	var got []string
	ts := webDeepServer(t, map[string]http.HandlerFunc{
		"/": htmlPage(`<html><a href="/a">a</a>` +
			`<a href="http://other.example/x">外链</a>` +
			`<a href="mailto:a@b.c">邮件</a><a href="#top">锚点</a></html>`),
		"/a": htmlPage(`<html><form action="/login" method="post">` +
			`<input name="user"><input name="pass"><input type="submit" name="go">` +
			`</form></html>`),
		"/login": htmlPage("ok"),
	})
	// 记录所有请求, 用于断言跨域/伪协议没有被请求
	wrap := ts.Config.Handler
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.URL.Path)
		mu.Unlock()
		wrap.ServeHTTP(w, r)
	})

	rec := &deepRec{}
	d := newTestDeep(ts.URL+"/", rec)
	d.crawl()

	if d.pages != 2 {
		t.Fatalf("爬取页面数 = %d, 期望 2(首页 + /a)", d.pages)
	}
	if len(d.points) != 1 {
		t.Fatalf("注入点数 = %d, 期望 1(仅 /login 表单), 实际 %+v", len(d.points), d.points)
	}
	p := d.points[0]
	if p.Method != "POST" || !strings.HasSuffix(p.Target, "/login") {
		t.Errorf("注入点 = %+v, 期望 POST /login", p)
	}
	if strings.Join(p.Fields, ",") != "user,pass" {
		t.Errorf("字段 = %v, 期望 [user pass](submit 类按钮须剔除)", p.Fields)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range got {
		if path == "/x" {
			t.Errorf("跨域链接被请求了: %v", got)
		}
	}
}

// TestWebDeepCrawlDepthLimit 守卫深度上限: 深度改成 1 时只抓第一层链接,
// 第二层(/c)不得被抓取。上限被改坏不会报错, 只会让请求量按指数膨胀 ——
// 静默失效, 必须锁定。
func TestWebDeepCrawlDepthLimit(t *testing.T) {
	old := webDeepMaxDepth
	webDeepMaxDepth = 1
	defer func() { webDeepMaxDepth = old }()

	var mu sync.Mutex
	var got []string
	ts := webDeepServer(t, map[string]http.HandlerFunc{
		"/":  htmlPage(`<a href="/b">b</a>`),
		"/b": htmlPage(`<a href="/c">c</a>`),
		"/c": htmlPage(`<a href="/d">d</a>`),
		"/d": htmlPage("deep"),
	})
	wrap := ts.Config.Handler
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.URL.Path)
		mu.Unlock()
		wrap.ServeHTTP(w, r)
	})

	rec := &deepRec{}
	d := newTestDeep(ts.URL+"/", rec)
	d.crawl()

	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(strings.Join(got, " "), "/c") {
		t.Errorf("深度上限失效, 抓到了第二层 /c: %v", got)
	}
	if !strings.Contains(strings.Join(got, " "), "/b") {
		t.Errorf("第一层 /b 应当被抓取, 实际: %v", got)
	}
}

// TestWebDeepSQLiUnion 联合/错误回显式注入: 基线无 SQL 特征, 注入后出现即报。
func TestWebDeepSQLiUnion(t *testing.T) {
	ts := webDeepServer(t, map[string]http.HandlerFunc{
		"/item": func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.FormValue("id"), "'") {
				fmt.Fprint(w, "You have an error in your SQL syntax")
				return
			}
			fmt.Fprint(w, "<html>OK</html>")
		},
	})
	rec := &deepRec{}
	WebScanDeep(ts.URL+"/item?id=1", rec.emit, nil)
	if !rec.hasTitle("UNION") {
		t.Fatalf("未报出 union/错误回显式 SQL 注入, findings=%+v", rec.findings)
	}
}

// TestWebDeepSQLiBoolean 布尔盲注: 真条件与基线一致、假条件不同才报。
func TestWebDeepSQLiBoolean(t *testing.T) {
	ts := webDeepServer(t, map[string]http.HandlerFunc{
		"/item": func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.FormValue("id"), "1=2") {
				fmt.Fprint(w, "<html>empty</html>")
				return
			}
			fmt.Fprint(w, "<html>list</html>")
		},
	})
	rec := &deepRec{}
	WebScanDeep(ts.URL+"/item?id=1", rec.emit, nil)
	if !rec.hasTitle("布尔盲注") {
		t.Fatalf("未报出布尔盲注, findings=%+v", rec.findings)
	}
	if rec.hasTitle("UNION") {
		t.Errorf("响应无 SQL 错误特征时不该报 union 类: %+v", rec.findings)
	}
}

// TestWebDeepSQLiTime 时间盲注: 睡眠载荷耗时显著高于零睡眠对照才报。
func TestWebDeepSQLiTime(t *testing.T) {
	oldSec, oldDelta := webDeepSleepSec, webDeepTimeDelta
	webDeepSleepSec = 1
	webDeepTimeDelta = 400 * time.Millisecond
	defer func() { webDeepSleepSec, webDeepTimeDelta = oldSec, oldDelta }()

	re := regexp.MustCompile(`sleep\((\d+)\)`)
	ts := webDeepServer(t, map[string]http.HandlerFunc{
		"/item": func(w http.ResponseWriter, r *http.Request) {
			m := re.FindStringSubmatch(strings.ToLower(r.FormValue("id")))
			if m != nil {
				time.Sleep(time.Duration(atoiOrZero(m[1])) * time.Second)
			}
			fmt.Fprint(w, "<html>OK</html>")
		},
	})
	rec := &deepRec{}
	WebScanDeep(ts.URL+"/item?id=1", rec.emit, nil)
	if !rec.hasTitle("时间盲注") {
		t.Fatalf("未报出时间盲注, findings=%+v", rec.findings)
	}
	if rec.hasTitle("布尔盲注") {
		t.Errorf("响应体恒定时不该报布尔盲注: %+v", rec.findings)
	}
}

func atoiOrZero(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// TestWebDeepXSSPostFormAndJSON 守卫 XSS 多位置契约: 同一组字段要在表单
// (urlencoded) 与 JSON body 两个位置分别定位回显。只测表单会让"接口只读 JSON"
// 的应用整类漏报。
func TestWebDeepXSSPostFormAndJSON(t *testing.T) {
	ts := webDeepServer(t, map[string]http.HandlerFunc{
		"/": htmlPage(`<html><a href="/login">login</a></html>`),
		"/login": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				b := make([]byte, 4096)
				n, _ := r.Body.Read(b)
				fmt.Fprint(w, string(b[:n])) // 原样回显请求体 = 最典型的未转义输出
				return
			}
			htmlPage(`<html><form action="/login" method="post">`+
				`<input name="user"><input name="pass"></form></html>`)(w, r)
		},
	})
	rec := &deepRec{}
	WebScanDeep(ts.URL+"/", rec.emit, nil)
	if !rec.hasTitle("POST 表单参数") {
		t.Fatalf("未报出 POST 表单回显, findings=%+v", rec.findings)
	}
	if !rec.hasTitle("JSON body") {
		t.Fatalf("未报出 JSON body 回显, findings=%+v", rec.findings)
	}
}

// TestWebDeepNoFalsePositiveOnStaticSite 最重要的防误报守卫: 一个对任何输入都
// 返回同样响应的站点, 三类 SQLi 与 XSS 全部不得报警。
// 只要有一类探测丢掉"与基线比较", 这个用例就会红 —— 误报会把报告淹没,
// 与漏报同样是产品缺陷。
func TestWebDeepNoFalsePositiveOnStaticSite(t *testing.T) {
	withRules(t, nil) // 隔离全局漏洞库规则, 只观察本文件的探测逻辑
	page := "<html><body><h1>hello</h1></body></html>"
	ts := webDeepServer(t, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			htmlPage(page+`<form action="/search" method="post"><input name="q"></form>`)(w, r)
		},
		"/search": htmlPage(page),
	})
	rec := &deepRec{}
	WebScanDeep(ts.URL+"/", rec.emit, nil)
	if n := rec.count(); n != 0 {
		t.Fatalf("静态站点应零发现, 实际 %d 条: %+v", n, rec.findings)
	}
}
