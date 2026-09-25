package scanner

import (
	"testing"
)

// 沙箱回环被拦截, 故单测只覆盖纯逻辑: URL 渲染/安全校验/DSL/matcher/去重/资产构建,
// 不发起真实网络请求。

// TestAssetBuildURL 资产 URL 拼装与模板变量替换
func TestAssetBuildURL(t *testing.T) {
	a := ServiceAsset{IP: "192.168.1.5", Port: 8080, Scheme: "http", Product: "nginx"}
	if got := a.buildURL("/test"); got != "http://192.168.1.5:8080/test" {
		t.Errorf("buildURL(/test) = %q", got)
	}
	if got := a.buildURL(""); got != "http://192.168.1.5:8080/" {
		t.Errorf("buildURL(空) = %q", got)
	}
	if got := a.buildURL("x/y"); got != "http://192.168.1.5:8080/x/y" {
		t.Errorf("buildURL(无斜杠) = %q", got)
	}
	if got := a.buildURL("https://example.com/a"); got != "https://example.com/a" {
		t.Errorf("buildURL(完整 URL) = %q", got)
	}

	b := ServiceAsset{IP: "192.168.1.5", Port: 80, Scheme: "http"}
	if got := b.HostPort(); got != "192.168.1.5" {
		t.Errorf("默认端口 80 应省略端口, got %q", got)
	}
	c := ServiceAsset{IP: "192.168.1.5", Port: 443, Scheme: "https"}
	if got := c.HostPort(); got != "192.168.1.5" {
		t.Errorf("默认端口 443 应省略端口, got %q", got)
	}

	if got := renderTarget("{{BaseURL}}/vuln?id={{Port}}&h={{Host}}", a); got != "http://192.168.1.5:8080/vuln?id=8080&h=192.168.1.5" {
		t.Errorf("renderTarget = %q", got)
	}
}

// TestSafeTarget 协议白名单与云元数据拦截
func TestSafeTarget(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"file:///etc/passwd", "", true},
		{"gopher://127.0.0.1:25/", "", true},
		{"ftp://10.0.0.1/", "", true},
		{"http://169.254.169.254/latest/meta-data/", "", true},
		{"http://metadata.google.internal/", "", true},
		{"http://192.168.1.5:8080/x", "http://192.168.1.5:8080/x", false},
		{"192.168.1.5:8080/x", "http://192.168.1.5:8080/x", false}, // 无协议前缀自动补 http
	}
	for _, c := range cases {
		got, err := safeTarget(c.in)
		if c.err {
			if err == nil {
				t.Errorf("safeTarget(%q) 应报错, got %q", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("safeTarget(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// TestDSLEval 基础 DSL 表达式: 比较/逻辑/函数/错误
func TestDSLEval(t *testing.T) {
	env := dslEnv{
		statusCode: 200,
		body:       "Welcome to nginx 1.18.0",
		header:     "Server: nginx/1.18.0\nContent-Type: text/html\n",
		cookies:    "sid=abc",
	}
	cases := []struct {
		expr string
		want bool
		err  bool
	}{
		{"status_code == 200", true, false},
		{"status_code != 200", false, false},
		{"status_code == 200 && contains(body, \"nginx\")", true, false},
		{"status_code == 200 && contains(body, \"apache\")", false, false},
		{"contains(body, \"NGINX\")", true, false}, // 大小写不敏感
		{"len(body) > 10 && len(body) < 100", true, false},
		{"len(body) > 100", false, false},
		{"contains(header, \"server: nginx\")", true, false},
		{"!contains(body, \"apache\")", true, false},
		{"status_code == 404 || len(body) > 10", true, false},
		{"(status_code == 200) && (contains(body, \"1.18.0\"))", true, false},
		{"starts_with(body, \"welcome\") && ends_with(body, \"1.18.0\")", true, false},
		{"upper(body) == upper(\"welcome to NGINX 1.18.0\")", true, false},
		{"len(cookies) > 0", true, false},
		{"unknownvar == 1", false, true},
		{"foo(1)", false, true},
		{"(1", false, true},
		{"status_code == \"200\"", false, true}, // int 与 string 类型不匹配
		{"contains(1, 2)", false, true},         // 参数类型错误
	}
	for _, c := range cases {
		got, err := dslEval(c.expr, env)
		if c.err {
			if err == nil {
				t.Errorf("expr %q 应报错, got %v", c.expr, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("expr %q = %v, %v; want %v", c.expr, got, err, c.want)
		}
	}
}

// TestEvalMatcher 单 matcher: status / word(or+and+negative) / regex / dsl / header 部分
func TestEvalMatcher(t *testing.T) {
	ctx := &matchCtx{
		statusCode: 200,
		body:       "hello world, nginx here",
		header:     "Server: nginx/1.18.0\nContent-Type: text/html\n",
	}
	cases := []struct {
		name string
		m    Matcher
		want bool
	}{
		{"status 命中", Matcher{Type: "status", Status: []int{200, 204}}, true},
		{"status 未命中", Matcher{Type: "status", Status: []int{403}}, false},
		{"status 取反", Matcher{Type: "status", Status: []int{403}, Negative: true}, true},
		{"word or", Matcher{Type: "word", Words: stringOrList{"hello", "nginx"}}, true},
		{"word and 全命中", Matcher{Type: "word", Condition: "and", Words: stringOrList{"hello", "nginx"}}, true},
		{"word and 缺一", Matcher{Type: "word", Condition: "and", Words: stringOrList{"hello", "apache"}}, false},
		{"word 大小写不敏感", Matcher{Type: "word", Words: stringOrList{"WORLD"}}, true},
		{"word 取反", Matcher{Type: "word", Words: stringOrList{"WORLD"}, Negative: true}, false},
		{"header 部分", Matcher{Type: "word", Part: "header", Words: stringOrList{"nginx/1.18.0"}}, true},
		{"header 未命中", Matcher{Type: "word", Part: "header", Words: stringOrList{"apache"}}, false},
		{"regex 命中(header)", Matcher{Type: "regex", Part: "header", Regexes: stringOrList{`nginx/(\d+\.\d+\.\d+)`}}, true},
		{"regex 未命中", Matcher{Type: "regex", Regexes: stringOrList{`apache/\d+`}}, false},
		{"dsl 命中", Matcher{Type: "dsl", DSL: stringOrList{"status_code == 200 && contains(body, \"nginx\")"}}, true},
		{"dsl 未命中", Matcher{Type: "dsl", DSL: stringOrList{"status_code == 404"}}, false},
		{"未知类型不命中", Matcher{Type: "binary", Words: stringOrList{"x"}}, false},
	}
	for _, c := range cases {
		if got := evalMatcher(c.m, ctx); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestEvalTemplateMatchers 多 matcher 联合: OR 默认 / AND 需全部命中 / 空列表
func TestEvalTemplateMatchers(t *testing.T) {
	ctx := &matchCtx{statusCode: 200, body: "hello nginx", header: "Server: x\n"}

	// 默认 OR: 任一命中即可
	ms := []Matcher{
		{Type: "word", Words: stringOrList{"apache"}},
		{Type: "word", Words: stringOrList{"nginx"}},
	}
	if !evalTemplateMatchers(ms, ctx) {
		t.Error("OR: 应命中")
	}

	// AND: 任一 matcher 声明 condition=and => 全部必须命中
	ms = []Matcher{
		{Type: "word", Condition: "and", Words: stringOrList{"nginx"}},
		{Type: "word", Words: stringOrList{"apache"}},
	}
	if evalTemplateMatchers(ms, ctx) {
		t.Error("AND: 应不命中(apache 缺失)")
	}
	ms = []Matcher{
		{Type: "status", Condition: "and", Status: []int{200}},
		{Type: "word", Words: stringOrList{"nginx"}},
	}
	if !evalTemplateMatchers(ms, ctx) {
		t.Error("AND: 应命中(全部满足)")
	}

	if evalTemplateMatchers(nil, ctx) {
		t.Error("无 matcher 应不命中")
	}
}

// TestFindingDedup 去重: 同 IP+Port+CVE 只报一次; 不同端口/无 CVE 用模板 ID
func TestFindingDedup(t *testing.T) {
	r := NewNucleiRunner(DefaultRunnerConfig())
	a := ServiceAsset{IP: "192.168.1.10", Port: 80, Scheme: "http", Product: "nginx"}
	tpl := Template{ID: "tpl-x", Info: &Info{
		Name: "X 漏洞", Severity: "critical", Cve: stringOrList{"CVE-2024-1234"},
		Reference: stringOrList{"https://example.com/ref"},
	}}
	snap := &respSnapshot{
		code:     200,
		body:     "ok",
		header:   "Server: nginx\n",
		rawReq:   "GET / HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n",
		rawResp:  "HTTP/1.1 200 OK\r\n\r\nok",
	}
	f1, ok1 := r.newFinding(a, tpl, snap, "/")
	if !ok1 {
		t.Fatal("首次上报应成功")
	}
	if f1.CVE != "CVE-2024-1234" || f1.Severity != "high" || f1.Host != a.IP || f1.Port != 80 {
		t.Errorf("finding 字段 = %+v", f1)
	}
	if f1.Title != "[tpl-x] X 漏洞" {
		t.Errorf("Title = %q", f1.Title)
	}
	if len(f1.References) != 1 || f1.References[0] != "https://example.com/ref" {
		t.Errorf("References = %v", f1.References)
	}
	if f1.RawRequest == "" || f1.RawResponse == "" {
		t.Error("raw 证据应保留")
	}
	if _, ok2 := r.newFinding(a, tpl, snap, "/"); ok2 {
		t.Error("同 IP+Port+CVE 应去重")
	}
	a2 := a
	a2.Port = 8080
	if _, ok3 := r.newFinding(a2, tpl, snap, "/"); !ok3 {
		t.Error("不同端口不应去重")
	}
	// 无 CVE 模板: 按 IP+Port+模板ID 去重
	tpl2 := Template{ID: "tpl-y", Info: &Info{Name: "Y"}}
	if _, ok := r.newFinding(a, tpl2, snap, "/"); !ok {
		t.Fatal("tpl-y 首次应上报")
	}
	if _, ok := r.newFinding(a, tpl2, snap, "/x"); ok {
		t.Error("同 IP+Port+模板ID 应去重")
	}
}

// TestClipEvidence 证据截断
func TestClipEvidence(t *testing.T) {
	short := "abc"
	if got := clipEvidence(short); got != short {
		t.Errorf("短证据不应被截断: %q", got)
	}
	long := string(make([]byte, evidenceLimit+1000))
	if got := clipEvidence(long); len(got) > evidenceLimit+64 {
		t.Errorf("长证据应被截断, 长度 %d", len(got))
	}
}

// TestBuildServiceAssets 端口扫描结果 -> 服务资产(产品键 + 纯版本号), 并验证指纹过滤衔接
func TestBuildServiceAssets(t *testing.T) {
	results := []PortResult{
		{IP: "1.2.3.4", Port: 80, State: "open", Service: "Apache httpd", Banner: "Server: Apache/2.4.41 (Ubuntu)"},
		{IP: "1.2.3.4", Port: 443, State: "open", Service: "https"},
		{IP: "1.2.3.4", Port: 22, State: "open", Service: "ssh", Banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu"},
		{IP: "1.2.3.4", Port: 9999, State: "closed", Service: ""},
	}
	assets := BuildServiceAssets("1.2.3.4", results)
	if len(assets) != 3 {
		t.Fatalf("资产数量 = %d, want 3(仅开放端口)", len(assets))
	}
	if assets[0].Product != "apache" || assets[0].Version != "2.4.41" {
		t.Errorf("asset[0] = %+v", assets[0])
	}
	if assets[0].Scheme != "http" || assets[1].Scheme != "https" {
		t.Errorf("scheme = %s / %s", assets[0].Scheme, assets[1].Scheme)
	}
	if assets[2].Version != "8.2" {
		t.Errorf("asset[2].Version = %q, want 8.2", assets[2].Version)
	}

	// 与指纹过滤衔接: 通用模板保留, 版本不匹配的 apache 模板剔除
	tpls := []Template{
		{ID: "generic", Request: &Request{Paths: stringOrList{"/"}}, Info: &Info{Tags: stringOrList{"xss"}}},
		{ID: "apache-2.4.41-rce", Request: &Request{Paths: stringOrList{"/"}}, Info: &Info{Tags: stringOrList{"apache", "apache-2.4.41"}}},
		{ID: "apache-2.4.49-rce", Request: &Request{Paths: stringOrList{"/"}}, Info: &Info{Tags: stringOrList{"apache", "apache-2.4.49"}}},
	}
	got := FilterTemplatesByFingerprint(tpls, assets[0].Product, assets[0].Version)
	var ids []string
	for _, x := range got {
		ids = append(ids, x.ID)
	}
	if len(ids) != 2 || ids[0] != "generic" || ids[1] != "apache-2.4.41-rce" {
		t.Errorf("过滤结果 = %v", ids)
	}
}
