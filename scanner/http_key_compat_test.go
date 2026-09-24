package scanner

import (
	"testing"
)

// ===== 单元测试: Nuclei 模板三种请求键名的兼容性 =====
//
// 背景(实测踩坑, 曾导致"一键更新官方模板"100% 失败):
// Nuclei 模板格式演进过两代键名 —— 早期多请求列表用 `requests:`, 后来单请求用
// `request:`, 当前官方仓库统一用 **`http:`**。解析器与直连过滤器原先都只认前两种,
// 于是官方 zipball 里 12000+ 个模板被逐条判为"非 HTTP 类型"全部过滤掉,
// 直连更新在下载完几十 MB 后必然报"未找到符合条件的模板"。
//
// 这组用例把三种键名 + 两种 http 形态(单请求映射 / 多请求列表)全部锁死,
// 防止日后再改键名判定时把兼容性弄丢。

// officialFormYAML 当前官方格式 `http:` 的单请求映射写法(取自真实模板结构)
const officialFormYAML = `id: CVE-2024-27348
info:
  name: Apache HugeGraph-Server - Remote Command Execution
  author: DhiyaneshDK
  severity: high
  tags: cve,cve2024,apache,rce
http:
  - method: GET
    path:
      - "{{BaseURL}}/gremlin"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "hugegraph"
`

// officialSingleMapYAML `http:` 直接写映射(非列表)的写法 —— 官方两种形态都存在,
// 用 []Request 直接解码这种形态会报 "expect sequence", 必须靠 httpBlock 分派
const officialSingleMapYAML = `id: single-map-form
info:
  name: Single Map Form
  severity: medium
http:
  method: GET
  path:
    - "{{BaseURL}}/admin"
  matchers:
    - type: status
      status: [200]
`

// legacyRequestsYAML 最早的 `requests:` 列表写法
const legacyRequestsYAML = `id: legacy-requests
info:
  name: Legacy Requests
  severity: low
requests:
  - method: GET
    path: /legacy
`

// TestParseHTTPKeyForms 三种键名都要能解析出请求, 且请求数正确。
// 这是"官方模板能被内置引擎执行"的前提条件。
func TestParseHTTPKeyForms(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantReqs  int
		wantFirst string // 第一个请求的原始 path(解析器保留 {{BaseURL}} 变量, 替换在执行期)
	}{
		{"http 单请求映射", officialSingleMapYAML, 1, "{{BaseURL}}/admin"},
		{"http 请求列表", officialFormYAML, 1, "{{BaseURL}}/gremlin"},
		{"旧键名 requests 列表", legacyRequestsYAML, 1, "/legacy"},
	}
	for _, c := range cases {
		tpl, err := ParseNucleiTemplate([]byte(c.yaml))
		if err != nil {
			t.Errorf("%s: 解析失败 %v", c.name, err)
			continue
		}
		if tpl == nil {
			t.Errorf("%s: 被判定为非 HTTP 模板而跳过(键名兼容性回归!)", c.name)
			continue
		}
		reqs := tpl.AllRequests()
		if len(reqs) != c.wantReqs {
			t.Errorf("%s: 请求数=%d, 期望 %d", c.name, len(reqs), c.wantReqs)
			continue
		}
		paths := reqs[0].Paths
		if len(paths) == 0 || paths[0] != c.wantFirst {
			t.Errorf("%s: 首个 path=%v, 期望 %q", c.name, paths, c.wantFirst)
		}
	}
}

// TestParseHTTPListMultipleRequests `http:` 写列表且含多个请求时, 请求要全部收齐
// 而不是只取第一个 —— 多请求模板靠顺序依赖完成判定, 丢请求会让模板静默失效。
func TestParseHTTPListMultipleRequests(t *testing.T) {
	const y = `id: multi
info:
  name: Multi Request
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/a"]
  - method: POST
    path: ["{{BaseURL}}/b"]
  - method: GET
    path: ["{{BaseURL}}/c"]
`
	tpl, err := ParseNucleiTemplate([]byte(y))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if tpl == nil {
		t.Fatal("多请求 http 模板被跳过")
	}
	if got := len(tpl.AllRequests()); got != 3 {
		t.Fatalf("请求数=%d, 期望 3", got)
	}
	if got := tpl.AllRequests()[2].Paths[0]; got != "{{BaseURL}}/c" {
		t.Errorf("第 3 个请求 path=%q, 期望 {{BaseURL}}/c", got)
	}
}

// TestIsExecutableHTTPTemplateKeyForms 直连通道过滤器必须与解析器同口径,
// 否则会出现"收进来了但加载阶段全被跳过"的假成功。
func TestIsExecutableHTTPTemplateKeyForms(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want bool
	}{
		{"http 映射形态", officialSingleMapYAML, true},
		{"http 列表形态", officialFormYAML, true},
		{"requests 旧写法", legacyRequestsYAML, true},
		{"request 中间写法", "id: x\nrequest:\n  path: /\n", true},
		// 反向断言: 内置引擎跑不了的类型必须继续被拒, 不能因为放宽键名而误收
		{"network 模板", "id: n\nnetwork:\n  - host: [\"{{Hostname}}\"]\n", false},
		{"headless 模板", "id: h\nheadless:\n  - steps: []\n", false},
		{"javascript 模板", "id: j\njavascript:\n  - code: 1\n", false},
		{"workflow 模板", "id: w\nflow: other-template\n", false},
		{"仅 matchers 无请求", "id: m\ninfo:\n  name: m\nmatchers:\n  - type: status\n", false},
	}
	for _, c := range cases {
		if got := isExecutableHTTPTemplate([]byte(c.yaml)); got != c.want {
			t.Errorf("%s: isExecutableHTTPTemplate=%v, 期望 %v", c.name, got, c.want)
		}
	}
}

// TestExtractOfficialFormTemplates 直连通道端到端解包: 官方格式的模板必须能被提取出来。
//
// 这是对"一键更新官方模板"按钮的直接回归 —— 修复前本用例会返回 0 个模板。
func TestExtractOfficialFormTemplates(t *testing.T) {
	z := makeTemplatesZip(t, map[string]string{
		// 官方格式(本次修复的目标): 修复前这 2 个都会被过滤掉
		"http/cves/2024/CVE-2024-27348.yaml": officialFormYAML,
		"http/exposures/configs/actuator.yaml": `id: spring-actuator
info:
  name: Spring Actuator
  severity: medium
http:
  - method: GET
    path: ["{{BaseURL}}/actuator/env"]
`,
		// 非 HTTP 类型: 必须继续被跳过
		"http/network/dns.yaml":      "id: dns-tpl\nnetwork:\n  - host: [\"{{Hostname}}\"]\n",
		"http/headless/browser.yaml": "id: hl-tpl\nheadless:\n  - steps: []\n",
		// 下划线前缀的共享片段: 必须跳过
		"http/helpers/_shared.yaml": "id: shared\nhttp:\n  - method: GET\n    path: /\n",
	})
	tpls, skipped, err := extractTemplates(z, DirectOptions{})
	if err != nil {
		t.Fatalf("解包失败: %v", err)
	}
	if len(tpls) != 2 {
		ids := make([]string, 0, len(tpls))
		for _, tp := range tpls {
			ids = append(ids, tp.rel)
		}
		t.Fatalf("提取到 %d 个模板 %v, 期望 2 个(官方 http: 格式必须被识别)", len(tpls), ids)
	}
	if skipped == 0 {
		t.Error("skipped=0: network/headless/_ 前缀的模板应被计入跳过数")
	}
}
