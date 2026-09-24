package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// http 类型的简单 nuclei 模板: 覆盖 id/info/request/matchers 全部关键字段
const testHTTPYAML = `id: test-http-8080
info:
  name: Test HTTP Template
  severity: high
  tags: [nginx, xss]
  cve: CVE-2021-23017
  cves: CVE-2021-23018
  reference: https://example.com/ref1
  references:
    - https://example.com/ref2
  description: 单元测试用模板
  author: yugo
request:
  method: POST
  path: /test
  headers:
    X-Test: "1"
  body: a=1
matchers:
  - type: status
    status: [200, 204]
  - type: word
    part: body
    condition: and
    words: [hello, world]
  - type: regex
    regex: '<b>.*</b>'
  - type: word
    negative: true
    words: Forbidden
`

// TestParseNucleiHTTPTemplate 解析一个完整 http 模板, 逐字段断言
func TestParseNucleiHTTPTemplate(t *testing.T) {
	tpl, err := ParseNucleiTemplate([]byte(testHTTPYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tpl == nil {
		t.Fatal("http 模板不应被跳过")
	}
	if tpl.ID != "test-http-8080" {
		t.Errorf("ID = %q, 期望 test-http-8080", tpl.ID)
	}
	if tpl.Info == nil {
		t.Fatal("info 不应为空")
	}
	if tpl.Info.Name != "Test HTTP Template" || tpl.Info.Severity != "high" {
		t.Errorf("name/severity = %q/%q", tpl.Info.Name, tpl.Info.Severity)
	}
	if len(tpl.AllTags()) != 2 || tpl.AllTags()[0] != "nginx" || tpl.AllTags()[1] != "xss" {
		t.Errorf("tags = %v", tpl.AllTags())
	}
	cves := tpl.CveIDs()
	if len(cves) != 2 || cves[0] != "CVE-2021-23017" || cves[1] != "CVE-2021-23018" {
		t.Errorf("cves = %v", cves)
	}
	refs := append(append([]string{}, tpl.Info.Reference...), tpl.Info.References...)
	if len(refs) != 2 || refs[0] != "https://example.com/ref1" || refs[1] != "https://example.com/ref2" {
		t.Errorf("references = %v", refs)
	}

	reqs := tpl.AllRequests()
	if len(reqs) != 1 {
		t.Fatalf("requests 数量 = %d, 期望 1", len(reqs))
	}
	r := reqs[0]
	if r.Method != "POST" || len(r.Paths) != 1 || r.Paths[0] != "/test" || r.Body != "a=1" {
		t.Errorf("request = %+v", r)
	}
	if r.Headers["X-Test"] != "1" {
		t.Errorf("headers = %v", r.Headers)
	}

	if len(tpl.Matchers) != 4 {
		t.Fatalf("matchers 数量 = %d, 期望 4", len(tpl.Matchers))
	}
	m0, m1, m2, m3 := tpl.Matchers[0], tpl.Matchers[1], tpl.Matchers[2], tpl.Matchers[3]
	if m0.Type != "status" || len(m0.Status) != 2 || m0.Status[0] != 200 || m0.Status[1] != 204 {
		t.Errorf("matcher[0] = %+v", m0)
	}
	if m1.Type != "word" || m1.Part != "body" || m1.Condition != "and" ||
		len(m1.Words) != 2 || m1.Words[0] != "hello" || m1.Words[1] != "world" {
		t.Errorf("matcher[1] = %+v", m1)
	}
	if m2.Type != "regex" || len(m2.Regexes) != 1 || m2.Regexes[0] != "<b>.*</b>" {
		t.Errorf("matcher[2] = %+v", m2)
	}
	if m3.Type != "word" || !m3.Negative || len(m3.Words) != 1 || m3.Words[0] != "Forbidden" {
		t.Errorf("matcher[3] = %+v", m3)
	}
}

// TestParseNucleiSkipTypes headless / javascript / 无请求的模板应被跳过(返回 nil, nil)
func TestParseNucleiSkipTypes(t *testing.T) {
	headless := `id: t1
info:
  name: headless test
headless:
  - steps:
      - visit:
          url: "https://{{BaseURL}}/"
`
	js := `id: t2
info:
  name: js test
javascript:
  - |
    if (1) {}
`
	noReq := `id: t3
info:
  name: 无请求块
`
	for name, yamlStr := range map[string]string{
		"headless": headless, "javascript": js, "no-request": noReq,
	} {
		tpl, err := ParseNucleiTemplate([]byte(yamlStr))
		if err != nil {
			t.Errorf("%s: 不应报错, got %v", name, err)
		}
		if tpl != nil {
			t.Errorf("%s: 应被跳过, got %+v", name, tpl.ID)
		}
	}
}

// TestParseNucleiWorkflow workflow 仅提取依赖模板 ID(flow), 标记 IsWorkflow
func TestParseNucleiWorkflow(t *testing.T) {
	wf := `id: wf-1
info:
  name: test workflow
flow:
  - tpl-a
  - tpl-b
`
	tpl, err := ParseNucleiTemplate([]byte(wf))
	if err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	if tpl == nil || !tpl.IsWorkflow {
		t.Fatalf("workflow 应被识别, got %+v", tpl)
	}
	if tpl.ID != "wf-1" || len(tpl.Flow) != 2 || tpl.Flow[0] != "tpl-a" || tpl.Flow[1] != "tpl-b" {
		t.Errorf("workflow = %+v", tpl)
	}
}

// TestParseNucleiErrors 非法 YAML 应返回 error(由调用方记日志跳过); 缺 id 走兜底
func TestParseNucleiErrors(t *testing.T) {
	if _, err := ParseNucleiTemplate([]byte("id: [unclosed")); err == nil {
		t.Fatal("非法 YAML 应报错")
	}
	noID := "request:\n  path: /x\n"
	tpl, err := ParseNucleiTemplate([]byte(noID))
	if err != nil {
		t.Fatalf("缺 id 不应报错: %v", err)
	}
	if tpl == nil || tpl.ID != "unknown" {
		t.Errorf("缺 id 兜底 = %q", tpl.ID)
	}
}

// TestParseNucleiIDLineFallback 有 id: 行但缺省字段名不匹配时按 id 行兜底
func TestParseNucleiIDLineFallback(t *testing.T) {
	y := "id: my-template-id\nrequest:\n  path: /\n"
	tpl, err := ParseNucleiTemplate([]byte(y))
	if err != nil || tpl == nil {
		t.Fatalf("parse: %v", err)
	}
	if tpl.ID != "my-template-id" {
		t.Errorf("ID = %q, 期望 my-template-id", tpl.ID)
	}
}

// TestStringOrList 标量 CSV 与序列两种写法都能解码
func TestStringOrList(t *testing.T) {
	var s struct {
		A stringOrList `yaml:"a"`
		B stringOrList `yaml:"b"`
	}
	if err := yaml.Unmarshal([]byte("a: x, y, z\nb:\n  - p\n  - q\n"), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(s.A) != 3 || s.A[0] != "x" || s.A[1] != "y" || s.A[2] != "z" {
		t.Errorf("CSV 标量 = %v", s.A)
	}
	if len(s.B) != 2 || s.B[0] != "p" || s.B[1] != "q" {
		t.Errorf("序列 = %v", s.B)
	}
}

// TestLoadNucleiTemplates 目录遍历 + sha256 校验 + 错误不中断整体加载
func TestLoadNucleiTemplates(t *testing.T) {
	dir := t.TempDir()
	okPath := filepath.Join(dir, "ok.yaml")
	headlessPath := filepath.Join(dir, "headless.yaml")
	badPath := filepath.Join(dir, "bad.yaml")
	tamperedPath := filepath.Join(dir, "tampered.yaml")
	okData := []byte(testHTTPYAML)
	writeFile := func(p string, data []byte) {
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatalf("写 %s: %v", p, err)
		}
	}
	writeFile(okPath, okData)
	writeFile(headlessPath, []byte("id: h1\nheadless:\n  - steps: []\n"))
	writeFile(badPath, []byte("id: [broken\n"))
	tamperedData := []byte("id: tampered\nrequest:\n  path: /\n")
	writeFile(tamperedPath, tamperedData)

	// checksum 文件: ok 正确 / tampered 故意写错 / headless 与 bad 未收录(不校验)
	sums := sha256Hex(okData) + "  ok.yaml\n" +
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  tampered.yaml\n" +
		"# 注释行应被忽略\n"
	if err := os.WriteFile(filepath.Join(dir, "templates-checksum.txt"), []byte(sums), 0o644); err != nil {
		t.Fatalf("写 checksum: %v", err)
	}

	tpls, errs := LoadNucleiTemplates(dir)
	if len(tpls) != 1 {
		t.Fatalf("加载数量 = %d, 期望 1 (仅 ok.yaml): %v", len(tpls), errs)
	}
	tpl := tpls[0]
	if tpl.ID != "test-http-8080" || tpl.SHA256 != sha256Hex(okData) || !strings.HasSuffix(tpl.Path, "ok.yaml") {
		t.Errorf("模板字段 = %+v", tpl)
	}
	joined := strings.Join(errs, "; ")
	if !strings.Contains(joined, "bad.yaml") {
		t.Errorf("错误列表应含 bad.yaml: %v", errs)
	}
	if !strings.Contains(joined, "tampered.yaml") {
		t.Errorf("错误列表应含 tampered.yaml(sha256 不匹配): %v", errs)
	}
	if strings.Contains(joined, "headless.yaml") {
		t.Errorf("headless 静默跳过, 不应出现在错误列表: %v", errs)
	}
}

// TestLoadNucleiTemplatesChecksumVariants 无 checksum 文件 / 空表 / 目录不存在
func TestLoadNucleiTemplatesChecksumVariants(t *testing.T) {
	dir1 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir1, "a.yaml"), []byte(testHTTPYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	// 无 checksum 文件 => 全部不校验, 正常加载
	if tpls, _ := LoadNucleiTemplates(dir1); len(tpls) != 1 {
		t.Errorf("无 checksum 文件应加载 1 个, got %d", len(tpls))
	}

	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "a.yaml"), []byte(testHTTPYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	// 空 checksum 表 => 同上
	if err := os.WriteFile(filepath.Join(dir2, "templates-checksum.txt"), []byte("# 空表\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if tpls, _ := LoadNucleiTemplates(dir2); len(tpls) != 1 {
		t.Errorf("空 checksum 表应加载 1 个, got %d", len(tpls))
	}

	// 目录不存在 => 返回错误, 不 panic
	tpls, errs := LoadNucleiTemplates(filepath.Join(t.TempDir(), "no-such-dir"))
	if len(tpls) != 0 || len(errs) != 1 {
		t.Errorf("目录不存在应返回 0 个模板 + 1 条错误, got %d/%d", len(tpls), len(errs))
	}
}

// TestFilterTemplatesByFingerprint 按服务指纹(产品+版本)过滤模板
func TestFilterTemplatesByFingerprint(t *testing.T) {
	generic := Template{ID: "g", Info: &Info{Name: "generic", Tags: stringOrList{"xss", "sqli"}}}
	generic.Request = &Request{Method: "GET", Paths: stringOrList{"/"}}
	nginx := Template{ID: "n", Info: &Info{Name: "nginx", Tags: stringOrList{"nginx", "xss"}}}
	nginx.Request = &Request{Method: "GET", Paths: stringOrList{"/"}}
	apache2449 := Template{ID: "a", Info: &Info{Name: "apache", Tags: stringOrList{"apache", "apache-2.4.49"}}}
	apache2449.Request = &Request{Method: "GET", Paths: stringOrList{"/"}}
	iis := Template{ID: "i", Info: &Info{Name: "iis", Tags: stringOrList{"iis"}}}
	iis.Request = &Request{Method: "GET", Paths: stringOrList{"/"}}
	wf := Template{ID: "w", Info: &Info{Name: "wf"}, IsWorkflow: true}
	empty := Template{ID: "e", Info: &Info{Name: "no-req"}}

	tpls := []Template{generic, nginx, apache2449, iis, wf, empty}
	cases := []struct {
		name, product, ver string
		want               []string
	}{
		{"nginx 无版本", "nginx", "", []string{"g", "n"}},
		{"nginx 有版本", "nginx", "1.20.1", []string{"g", "n"}},
		{"apache 版本匹配", "apache", "2.4.49", []string{"g", "a"}},
		{"apache 版本不匹配", "apache", "2.4.41", []string{"g"}},
		{"产品不匹配", "tomcat", "", []string{"g"}},
		{"无产品", "", "", []string{"g"}},
	}
	for _, c := range cases {
		got := FilterTemplatesByFingerprint(tpls, c.product, c.ver)
		var ids []string
		for _, x := range got {
			ids = append(ids, x.ID)
		}
		if !eqStr(ids, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, ids, c.want)
		}
	}
}

// TestFilterTemplatesNilInput 空输入返回空结果, 不 panic
func TestFilterTemplatesNilInput(t *testing.T) {
	if got := FilterTemplatesByFingerprint(nil, "nginx", "1.0"); len(got) != 0 {
		t.Errorf("nil 输入应返回空, got %d", len(got))
	}
}

func eqStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
