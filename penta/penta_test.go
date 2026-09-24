// penta 包单测: 全部离线(无真实网络)。
//
// 测试判定原则(项目规则 8): 只守"改坏会静默失效"的契约 ——
//
//   - 结论三态映射(全命中/部分命中/无命中/全失败)是业务语义核心, 错向比错值更危险;
//   - 占位符展开与目标解析错了 = 打到错误目标, 必须守;
//   - 模板导入的 ID 白名单是路径穿越防护, 必须守;
//   - http/tcp/weakpass 三类探针的命中判定语义(断言通过/不通过)。
//
// 网络替身: tcp/weakpass 用 net.Pipe(与 weakpass 包测试同口径),
// http 用注入的假 Doer(本沙箱拦截回环 TCP, httptest 不可用)。
package penta

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ===== 测试基建 =====

// dialerFn 与 Engine.Dial 同签名的测试替身类型。
type dialerFn = func(ctx context.Context, network, addr string) (net.Conn, error)

// prefixDialer 基于 net.Pipe 的 TCP 替身: 按"请求前缀 -> 响应"应答。
// 每次拨号新建一对 pipe(避免跨用例串流)。
func prefixDialer(responses map[string]string) dialerFn {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c1.Close()
			buf := make([]byte, 256)
			n, _ := c1.Read(buf)
			req := string(buf[:n])
			resp := "-ERR unknown command\r\n"
			for k, v := range responses {
				if strings.HasPrefix(req, k) {
					resp = v
					break
				}
			}
			c1.Write([]byte(resp))
		}()
		return c2, nil
	}
}

// nopBody 假响应体(实现 io.ReadCloser)。
type nopBody struct{ r io.Reader }

func (n nopBody) Read(p []byte) (int, error) { return n.r.Read(p) }
func (n nopBody) Close() error               { return nil }

// fakeHTTP 假 HTTP 传输层: 固定应答 + 记录调用。
type fakeHTTP struct {
	status int
	body   string
	header map[string]string
	mu     sync.Mutex
	calls  []string
}

func (f *fakeHTTP) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req.URL.String())
	f.mu.Unlock()
	h := http.Header{}
	for k, v := range f.header {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: f.status,
		Status:     fmt.Sprintf("%d OK", f.status),
		Header:     h,
		Body:       nopBody{strings.NewReader(f.body)},
		Request:    req,
	}, nil
}

func testTask() *Task {
	return &Task{
		ID: "pt_test", Target: "10.0.0.5", Port: 6379, Protocol: "tcp",
		CVE: "CVE-2022-0543", Title: "测试漏洞", Status: TaskPending,
	}
}

// ===== 结论三态映射 =====

func TestRunConclusionMapping(t *testing.T) {
	tpl := &Template{ID: "t", Steps: []StepSpec{
		{Name: "a", Type: StepTCP, Send: "PING\r\n", Expect: `\+PONG`},
		{Name: "b", Type: StepTCP, Send: "PING\r\n", Expect: `\+PONG`},
	}}

	// 替身服务不认 PING(统一回 -ERR) -> 两步均未命中 = 不可利用
	eng := &Engine{Now: time.Now, Dial: prefixDialer(nil)}
	out := eng.Run(context.Background(), testTask(), tpl, nil)
	if !out.OK || out.Exploitability != NotExploitable {
		t.Fatalf("无命中应=不可利用: ok=%v exp=%s", out.OK, out.Exploitability)
	}

	// PING -> +PONG, 全命中 = 可利用
	eng2 := &Engine{Now: time.Now, Dial: prefixDialer(map[string]string{"PING": "+PONG\r\n"})}
	out = eng2.Run(context.Background(), testTask(), tpl, nil)
	if out.Exploitability != Exploitable {
		t.Fatalf("全命中应=可利用: %s (%s)", out.Exploitability, out.Summary)
	}

	// 一步命中一步不 = 部分利用
	mix := &Template{ID: "m", Steps: []StepSpec{
		{Name: "a", Type: StepTCP, Send: "PING\r\n", Expect: `\+PONG`},
		{Name: "b", Type: StepTCP, Send: "PING\r\n", Expect: `\+NEVER`},
	}}
	out = eng2.Run(context.Background(), testTask(), mix, nil)
	if out.Exploitability != Partial {
		t.Fatalf("部分命中应=部分利用: %s", out.Exploitability)
	}
	if out.Steps[0].Hit != true || out.Steps[1].Hit != false {
		t.Fatalf("步骤命中标记: %+v", out.Steps)
	}
}

// ===== 占位符与目标解析 =====

func TestSubstituteAndTarget(t *testing.T) {
	tk := &Task{Target: "192.168.1.10", Port: 8080, CVE: "CVE-2021-44228"}
	if got := tk.substitute("{target}:{port} {cve}"); got != "192.168.1.10:8080 CVE-2021-44228" {
		t.Fatalf("substitute: %s", got)
	}
	h, p := targetOf(tk, "", 0)
	if h != "192.168.1.10" || p != 8080 {
		t.Fatalf("空步骤值应回退任务目标: %s %d", h, p)
	}
	h, p = targetOf(tk, "{target}", 6379)
	if h != "192.168.1.10" || p != 6379 {
		t.Fatalf("步骤端口应优先于任务端口: %s %d", h, p)
	}
}

// ===== 模板解析与导入 =====

func TestParseAndValidateTemplate(t *testing.T) {
	yaml := `
id: my-check
name: 自检模板
tags: [http, test]
steps:
  - name: s1
    type: http
    path: /
    expectStatus: 200
  - name: s2
    type: tcp
    port: 6379
    send: "PING\r\n"
    expect: "\\+PONG"
`
	tpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("parse yaml: %v", err)
	}
	if tpl.ID != "my-check" || len(tpl.Steps) != 2 {
		t.Fatalf("tpl: %+v", tpl)
	}
	if err := ValidateTemplate(tpl); err != nil {
		t.Fatalf("validate: %v", err)
	}

	jsonStr := `{"id":"my-json","name":"JSON 模板","steps":[{"name":"s","type":"http","path":"/"}]}`
	if _, err := ParseTemplate([]byte(jsonStr)); err != nil {
		t.Fatalf("parse json: %v", err)
	}

	// 非法 ID(路径穿越/大写/过短/含空格)是安全边界
	for _, bad := range []string{"../evil", "UPPER", "x", "a/b", "has space"} {
		if err := ValidateTemplate(&Template{ID: bad, Name: "n",
			Steps: []StepSpec{{Name: "s", Type: StepTCP}}}); err == nil {
			t.Fatalf("非法 ID %q 应被拒绝", bad)
		}
	}
	// 未知步骤类型(防止将来有人加 shell 类型绕过安全口径)
	if err := ValidateTemplate(&Template{ID: "ok-id", Name: "n",
		Steps: []StepSpec{{Name: "s", Type: "shell"}}}); err == nil {
		t.Fatal("未知步骤类型应被拒绝")
	}
	// 弱口令超上限(验证场景不是爆破)
	over := make([]string, 11)
	if err := ValidateTemplate(&Template{ID: "ok-id", Name: "n",
		Steps: []StepSpec{{Name: "s", Type: StepWeakPass, Passwords: over}}}); err == nil {
		t.Fatal("口令超 10 应被拒绝")
	}
	if err := ValidateTemplate(&Template{ID: "ok-id", Name: "n"}); err == nil {
		t.Fatal("空步骤应被拒绝")
	}
}

func TestImportCustomRoundtrip(t *testing.T) {
	dir := t.TempDir()
	content := "id: custom-x\nname: 自定义\nsteps:\n  - name: s\n    type: tcp\n    expect: '.'\n"
	tpl, path, err := ImportCustom(dir, []byte(content))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if tpl.ID != "custom-x" || !strings.HasSuffix(path, "custom-x.yaml") {
		t.Fatalf("文件名应与 ID 绑定: tpl=%s path=%s", tpl.ID, path)
	}
	got := LoadCustom(dir)
	if len(got) != 1 || got[0].ID != "custom-x" || got[0].BuiltIn {
		t.Fatalf("LoadCustom: %+v", got)
	}
	// 与内置同 ID 必须拒绝(内置是可信基线, 不允许覆盖)
	if _, _, err := ImportCustom(dir, []byte("id: redis-unauth\nname: x\nsteps:\n  - {name: s, type: tcp}\n")); err == nil {
		t.Fatal("内置 ID 冲突应被拒绝")
	}
	// 目录不存在 = 空列表(降级不报错)
	if got := LoadCustom(t.TempDir()); got != nil {
		t.Fatalf("空目录应返回 nil: %+v", got)
	}
}

// ===== HTTP 步骤(假 Doer 离线) =====

func TestHTTPStepHitAndMiss(t *testing.T) {
	fh := &fakeHTTP{status: 200, body: "<html><title>Index of /</title></html>",
		header: map[string]string{"Server": "Apache/2.4.41"}}
	eng := &Engine{Now: time.Now, Doer: fh.Do}
	tk := &Task{ID: "pt", Target: "10.0.0.9", Port: 80, Protocol: "http", Status: TaskPending}

	tpl := &Template{ID: "t", Steps: []StepSpec{
		{Name: "listing", Type: StepHTTP, Path: "/", ExpectStatus: 200, ExpectBody: `Index of /`},
		{Name: "verserve", Type: StepHTTP, Path: "/x",
			ExpectHeader: map[string]string{"Server": `\d+\.\d+`}},
	}}
	out := eng.Run(context.Background(), tk, tpl, nil)
	if out.Exploitability != Exploitable {
		t.Fatalf("应全命中: %s (%s)", out.Exploitability, out.Summary)
	}
	if len(fh.calls) != 2 || fh.calls[0] != "http://10.0.0.9:80/" {
		t.Fatalf("URL 构造/调用次数错误: %v", fh.calls)
	}
	if out.Steps[0].Evidence == "" {
		t.Fatal("HTTP 证据(请求行+状态)不能为空")
	}

	// 状态码不符 = 未命中
	fh2 := &fakeHTTP{status: 404, body: "not found"}
	eng2 := &Engine{Now: time.Now, Doer: fh2.Do}
	out2 := eng2.Run(context.Background(), tk, &Template{ID: "t2", Steps: []StepSpec{
		{Name: "listing", Type: StepHTTP, Path: "/", ExpectStatus: 200, ExpectBody: `Index of /`},
	}}, nil)
	if out2.Exploitability != NotExploitable {
		t.Fatalf("状态码不符应=不可利用: %s", out2.Exploitability)
	}
}

// ExpectHeader 是 OR 语义: Server 与 X-Powered-By 只出现其一也应命中。
func TestHTTPExpectHeaderOrSemantics(t *testing.T) {
	fh := &fakeHTTP{status: 200, body: "ok",
		header: map[string]string{"X-Powered-By": "PHP/7.4"}}
	eng := &Engine{Now: time.Now, Doer: fh.Do}
	tk := &Task{ID: "pt", Target: "10.0.0.9", Port: 80, Protocol: "http", Status: TaskPending}
	out := eng.Run(context.Background(), tk, &Template{ID: "t", Steps: []StepSpec{
		{Name: "v", Type: StepHTTP, Path: "/",
			ExpectHeader: map[string]string{"Server": `\d+\.\d+`, "X-Powered-By": `PHP`}},
	}}, nil)
	if out.Exploitability != Exploitable {
		t.Fatalf("OR 语义: 单头匹配应命中: %s", out.Summary)
	}
}

// ===== TCP 步骤(net.Pipe) =====

func TestTCPStepRedisUnauth(t *testing.T) {
	tpl := FindBuiltin("redis-unauth")
	if tpl == nil {
		t.Fatal("内置模板 redis-unauth 缺失")
	}

	// 替身服务 PING -> +PONG(模拟未授权 Redis)
	eng := &Engine{Now: time.Now, Dial: prefixDialer(map[string]string{"PING": "+PONG\r\n"})}
	out := eng.Run(context.Background(), testTask(), tpl, nil)
	if out.Exploitability != Exploitable {
		t.Fatalf("PING->PONG 应判可利用: %s %s", out.Exploitability, out.Summary)
	}
	if out.Steps[0].Evidence == "" {
		t.Fatal("证据不能为空(合规要求留存命令日志)")
	}

	// 要求认证的服务 = 未命中
	eng.Dial = prefixDialer(map[string]string{"PING": "-NOAUTH Authentication required.\r\n"})
	out = eng.Run(context.Background(), testTask(), tpl, nil)
	if out.Exploitability != NotExploitable {
		t.Fatalf("NOAUTH 应答应判不可利用: %s", out.Exploitability)
	}
}

// ===== weakpass 步骤(net.Pipe 替身 FTP, 与 weakpass 包同口径) =====

// ftpStub 假 FTP 服务: 仅口令命中时回 230, 其余 530。
func ftpStub(goodPass string) dialerFn {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c1.Close()
			io.WriteString(c1, "220 test FTP\r\n")
			buf := make([]byte, 256)
			for {
				n, err := c1.Read(buf)
				if err != nil || n == 0 {
					return
				}
				line := string(buf[:n])
				switch {
				case strings.HasPrefix(line, "USER"):
					io.WriteString(c1, "331 need password\r\n")
				case strings.HasPrefix(line, "PASS "):
					if strings.TrimSpace(line[5:]) == goodPass {
						io.WriteString(c1, "230 login ok\r\n")
						return
					}
					io.WriteString(c1, "530 login failed\r\n")
				}
			}
		}()
		return c2, nil
	}
}

func TestWeakPassStepHitAndMiss(t *testing.T) {
	tpl := &Template{ID: "wp", Steps: []StepSpec{
		{Name: "login", Type: StepWeakPass, Service: "ftp", Port: 21,
			User: "admin", Passwords: []string{"weakpass"}, TimeoutMs: 5000},
	}}
	tk := &Task{ID: "pt", Target: "10.0.0.7", Port: 21, Protocol: "tcp", Status: TaskPending}

	// 口令正确 = 命中, 证据含口令(命中才展示, 与 weakpass 审计口径一致)
	eng := &Engine{Now: time.Now, Dial: ftpStub("weakpass")}
	out := eng.Run(context.Background(), tk, tpl, nil)
	if out.Exploitability != Exploitable {
		t.Fatalf("弱口令命中应=可利用: %s %s", out.Exploitability, out.Summary)
	}
	if !strings.Contains(out.Steps[0].Evidence, "weakpass") {
		t.Fatalf("命中证据应含口令: %s", out.Steps[0].Evidence)
	}

	// 口令错误 = 未命中
	eng.Dial = ftpStub("correct-horse")
	out = eng.Run(context.Background(), tk, tpl, nil)
	if out.Exploitability != NotExploitable {
		t.Fatalf("口令错误应=不可利用: %s", out.Exploitability)
	}
}

// ===== 目标不可达 = 无结论(failed, 不是"不可利用") =====

func TestRunUnreachableIsInconclusive(t *testing.T) {
	eng := &Engine{Now: time.Now, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}}
	tpl := FindBuiltin("redis-unauth")
	out := eng.Run(context.Background(), testTask(), tpl, nil)
	if out.OK {
		t.Fatal("全步骤失败时 OK 应为 false(任务应记失败)")
	}
	if out.Exploitability != "" {
		t.Fatalf("目标不可达不应给出利用结论: %s", out.Exploitability)
	}
}

// ctx 取消 = 中止(不给出结论)。
func TestRunCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	eng := &Engine{Now: time.Now, Dial: prefixDialer(map[string]string{"PING": "+PONG\r\n"})}
	out := eng.Run(ctx, testTask(), FindBuiltin("redis-unauth"), nil)
	if out.OK || out.Exploitability != "" {
		t.Fatalf("已取消的 ctx 不应产生结论: %+v", out)
	}
}

// ===== 模板推荐启发式 =====

func TestSuggestTemplate(t *testing.T) {
	cases := []struct {
		proto string
		port  int
		title string
		want  string
	}{
		{"tcp", 6379, "Redis 未授权", "redis-unauth"},
		{"http", 80, "目录列举", "http-dir-listing"},
		{"tcp", 21, "弱口令", "weakpass-verify"},
		{"https", 443, "TLS 证书问题", "http-tls-info"},
		{"tcp", 3306, "其他", "tcp-banner-grab"},
	}
	for _, c := range cases {
		if got := SuggestTemplate(c.proto, c.port, c.title); got != c.want {
			t.Fatalf("suggest(%s,%d,%s)=%s 期望 %s", c.proto, c.port, c.title, got, c.want)
		}
	}
}
