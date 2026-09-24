package scanner

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 性能优化与误报降噪相关测试: tag 黑白名单 / 模板预加载缓存 / 重复响应页降噪 / 证据截断。
// 沙箱回环被拦截, 不发起真实网络请求。

// TestFilterTemplatesByTags tag 黑白名单: 白名单交集 / 黑名单剔除 / severity 名称 / 大小写不敏感
func TestFilterTemplatesByTags(t *testing.T) {
	mk := func(id string, tags []string, sev string) Template {
		return Template{ID: id, Info: &Info{Tags: stringOrList(tags), Severity: sev},
			Request: &Request{Paths: stringOrList{"/"}}}
	}
	tpls := []Template{
		mk("t-kev", []string{"cisa-kev", "rce"}, "critical"),
		mk("t-high", []string{"xss"}, "high"),
		mk("t-tech", []string{"tech", "nginx"}, "info"),
		mk("t-expo", []string{"exposure"}, "low"),
	}
	// 白名单: 只保留 cisa-kev 或 high(严重级名称)
	got := FilterTemplatesByTags(tpls, []string{"cisa-kev", "high"}, nil)
	if !eqStr(idsOf(got), []string{"t-kev", "t-high"}) {
		t.Errorf("白名单 = %v, want [t-kev t-high]", idsOf(got))
	}
	// 黑名单: 剔除 tech / exposure
	got = FilterTemplatesByTags(tpls, nil, []string{"tech", "exposure"})
	if !eqStr(idsOf(got), []string{"t-kev", "t-high"}) {
		t.Errorf("黑名单 = %v", idsOf(got))
	}
	// 白名单 + 黑名单叠加: critical 且非 tech
	got = FilterTemplatesByTags(tpls, []string{"CRITICAL"}, []string{"TECH"})
	if !eqStr(idsOf(got), []string{"t-kev"}) {
		t.Errorf("叠加 = %v, want [t-kev](大小写不敏感)", idsOf(got))
	}
	// 空条件: 原样返回
	if len(FilterTemplatesByTags(tpls, nil, nil)) != 4 {
		t.Error("空条件应返回全部")
	}
	if len(FilterTemplatesByTags(nil, []string{"x"}, nil)) != 0 {
		t.Error("nil 输入应返回空")
	}
}

func idsOf(tpls []Template) []string {
	var out []string
	for _, x := range tpls {
		out = append(out, x.ID)
	}
	return out
}

// TestTemplateCache 预加载缓存: 同目录复用不重读 / 目录缺失可重试 / 重置
func TestTemplateCache(t *testing.T) {
	t.Cleanup(ResetTemplateCache)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(testHTTPYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	// 首次: 读盘加载
	tpls1, errs := LoadTemplateCache(dir)
	if len(tpls1) != 1 || len(errs) != 0 {
		t.Fatalf("首次加载 = %d/%v", len(tpls1), errs)
	}
	if TemplateCount() != 1 {
		t.Errorf("TemplateCount = %d, want 1", TemplateCount())
	}
	// 缓存后修改目录内容: 目录状态变化 => 自动热更新重新加载(新行为)
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("id: b\nrequest:\n  path: /\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tpls2, errs := LoadTemplateCache(dir)
	if len(tpls2) != 2 || len(errs) != 0 {
		t.Errorf("目录变化应热更新为 2, got %d/%v", len(tpls2), errs)
	}
	// 目录未变: 命中缓存, 不重读 yaml
	if tpls2b, errs := LoadTemplateCache(dir); len(tpls2b) != 2 || len(errs) != 0 {
		t.Errorf("未变化应命中缓存(不重读), got %d/%v", len(tpls2b), errs)
	}
	// 重置后可重新加载
	ResetTemplateCache()
	tpls3, _ := LoadTemplateCache(dir)
	if len(tpls3) != 2 {
		t.Errorf("重置后重新加载 = %d, want 2", len(tpls3))
	}

	// 目录不存在: 不缓存, 之后目录出现可重试成功
	dir2 := t.TempDir()
	sub := filepath.Join(dir2, "late")
	if _, errs := LoadTemplateCache(sub); len(errs) != 1 {
		t.Errorf("目录不存在应返回 1 条错误: %v", errs)
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "c.yaml"), []byte("id: c\nrequest:\n  path: /\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tpls4, errs := LoadTemplateCache(sub)
	if len(tpls4) != 1 || len(errs) != 0 {
		t.Errorf("目录出现后重试应加载成功, got %d/%v", len(tpls4), errs)
	}
}

// TestMarkRespSeen 重复响应指纹: 首次 false, 相同响应 true; 状态码不同不判重
func TestMarkRespSeen(t *testing.T) {
	r := NewNucleiRunner(DefaultRunnerConfig())
	if r.markRespSeen("1.2.3.4:80", 200, "error page body") {
		t.Error("首次响应不应判为重复")
	}
	// 空白/大小写差异不影响指纹(同一错误页的响应抖动)
	if !r.markRespSeen("1.2.3.4:80", 200, "Error  Page   BODY") {
		t.Error("规范化后相同的响应体应判为重复")
	}
	if r.markRespSeen("1.2.3.4:80", 403, "error page body") {
		t.Error("状态码不同不应判为重复")
	}
	if r.markRespSeen("5.6.7.8:80", 200, "error page body") {
		t.Error("不同目标不应判为重复")
	}
}

// TestNormalizeForFingerprint 指纹规范化: 小写 + 空白压缩
func TestNormalizeForFingerprint(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Hello   World", "hello world"},
		{"A\tB\nC\rD", "a b c d"},
		{"  leading", "leading"}, // 首部空白被跳过
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeForFingerprint(c.in); got != c.want {
			t.Errorf("normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if respFingerprint("ABC def") != respFingerprint("abc   DEF") {
		t.Error("规范化后相同内容指纹应一致")
	}
	if respFingerprint("one") == respFingerprint("two") {
		t.Error("不同内容指纹应不同")
	}
}

// TestHasStructuralMatch 结构性命中判定: status/header 部分命中不被降噪抑制
func TestHasStructuralMatch(t *testing.T) {
	ms := []Matcher{
		{Type: "word", Part: "body", Words: stringOrList{"x"}},
		{Type: "status", Part: "status_code", Status: []int{403}},
		{Type: "regex", Part: "header", Regexes: stringOrList{"X-Blocked"}},
	}
	if hasStructuralMatch(ms, []int{0}) {
		t.Error("仅 body 命中不应视为结构性")
	}
	if !hasStructuralMatch(ms, []int{0, 1}) {
		t.Error("含 status_code 命中应视为结构性")
	}
	if !hasStructuralMatch(ms, []int{2}) {
		t.Error("含 header 命中应视为结构性")
	}
	if hasStructuralMatch(ms, nil) {
		t.Error("空命中列表不应视为结构性")
	}
}

// TestEvalTemplateMatchersDetail 多 matcher 联合判定返回命中索引: OR 返回命中的, AND 返回全部
func TestEvalTemplateMatchersDetail(t *testing.T) {
	ctx := &matchCtx{statusCode: 200, body: "hello nginx", header: "Server: x\n"}
	// OR: 第一个不命中, 第二个命中
	hit, idx := evalTemplateMatchersDetail([]Matcher{
		{Type: "word", Words: stringOrList{"apache"}},
		{Type: "word", Words: stringOrList{"nginx"}},
	}, ctx)
	if !hit || len(idx) != 1 || idx[0] != 1 {
		t.Errorf("OR: hit=%v idx=%v, want true/[1]", hit, idx)
	}
	// AND: 全部命中
	hit, idx = evalTemplateMatchersDetail([]Matcher{
		{Type: "status", Condition: "and", Status: []int{200}},
		{Type: "word", Words: stringOrList{"nginx"}},
	}, ctx)
	if !hit || len(idx) != 2 {
		t.Errorf("AND: hit=%v idx=%v, want true/[0 1]", hit, idx)
	}
	// AND: 缺一个
	hit, _ = evalTemplateMatchersDetail([]Matcher{
		{Type: "status", Condition: "and", Status: []int{200}},
		{Type: "word", Words: stringOrList{"apache"}},
	}, ctx)
	if hit {
		t.Error("AND 缺一不应命中")
	}
}

// TestCloseResp 响应释放: 无 body / 截断排空 / 未截断直接 Close, 均不 panic
func TestCloseResp(t *testing.T) {
	closeResp(nil, false)              // nil 安全
	closeResp(&http.Response{}, false) // Body nil
	r1 := &http.Response{Body: io.NopCloser(strings.NewReader("abc"))}
	closeResp(r1, false)
	r2 := &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 1<<20)))}
	closeResp(r2, true) // 截断: 有界排空
}

// TestEvidenceLimit20KB 证据截断上限为 20KB
func TestEvidenceLimit20KB(t *testing.T) {
	if evidenceLimit != 20*1024 {
		t.Errorf("evidenceLimit = %d, want %d", evidenceLimit, 20*1024)
	}
	long := strings.Repeat("a", 20*1024+1000)
	if got := clipEvidence(long); len(got) > 20*1024+64 {
		t.Errorf("长证据应截断到 20KB 附近, got %d", len(got))
	}
}

// TestCachedRegex 正则预编译缓存: 同 pattern 全进程同一实例 / 非法负缓存 / 内存上限
func TestCachedRegex(t *testing.T) {
	r1, ok1 := cachedRegex(`nginx/(\d+\.\d+)`)
	r2, ok2 := cachedRegex(`nginx/(\d+\.\d+)`)
	if !ok1 || !ok2 || r1 == nil || r1 != r2 {
		t.Fatalf("同一正则应命中缓存且返回同一实例: ok=%v/%v", ok1, ok2)
	}
	if _, ok := cachedRegex(`([invalid`); ok {
		t.Error("非法正则应返回 false")
	}
	if _, ok := cachedRegex(`([invalid`); ok {
		t.Error("非法正则应经负缓存保持 false(不重复试编译)")
	}
	// 上限保护: 超过 matcherCacheLimit 后缓存被重置, 不无界增长
	for i := 0; i < matcherCacheLimit+100; i++ {
		cachedRegex(fmt.Sprintf("key-%d-%s", i, strings.Repeat("a", i%5)))
	}
	reMu.Lock()
	n := len(reCache)
	reMu.Unlock()
	if n > matcherCacheLimit {
		t.Errorf("缓存规模 %d 超过上限 %d", n, matcherCacheLimit)
	}
}

// TestCachedDslTokens DSL 分词缓存: 同表达式复用同一 token 序列 / 非法表达式返回 false
func TestCachedDslTokens(t *testing.T) {
	e1, ok1 := cachedDslTokens(`status_code == 200 && contains(body, "nginx")`)
	e2, ok2 := cachedDslTokens(`status_code == 200 && contains(body, "nginx")`)
	if !ok1 || !ok2 || e1 == nil || len(e1) == 0 || &e1[0] != &e2[0] {
		t.Fatalf("同一表达式应命中缓存且返回同一 token 序列: ok=%v/%v", ok1, ok2)
	}
	if _, ok := cachedDslTokens(`"(abc`); ok {
		t.Error("分词非法的表达式(字符串未闭合)应返回 false")
	}
	// dslEval 走缓存后语义应与直接求值一致
	env := dslEnv{statusCode: 200, body: "nginx 1.18"}
	if hit, err := dslEval(`status_code == 200 && contains(body, "nginx")`, env); err != nil || !hit {
		t.Errorf("dslEval(缓存路径) = %v, %v; want true, nil", hit, err)
	}
}

// TestNewTargetReplacer 单目标共享替换器: 与逐次 renderTarget 行为一致
func TestNewTargetReplacer(t *testing.T) {
	a := ServiceAsset{IP: "10.0.0.9", Port: 9000, Scheme: "https", Product: "nginx"}
	rep := newTargetReplacer(a)
	if got := rep.Replace(`{{BaseURL}}/a?x={{Port}}-{{Host}}-{{Scheme}}`); got != "https://10.0.0.9:9000/a?x=9000-10.0.0.9-https" {
		t.Errorf("replacer 替换 = %q", got)
	}
	if got := renderTarget("{{BaseURL}}", a); got != "https://10.0.0.9:9000" {
		t.Errorf("renderTarget = %q", got)
	}
}

// TestTemplateHotReload 外部模板热更新: 目录文件增删改自动感知重新加载; 状态未变命中缓存
func TestTemplateHotReload(t *testing.T) {
	t.Cleanup(ResetTemplateCache)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(testHTTPYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	tpls1, errs := LoadTemplateCache(dir)
	if len(tpls1) != 1 || len(errs) != 0 {
		t.Fatalf("首次加载 = %d/%v", len(tpls1), errs)
	}
	// 目录状态未变: 命中缓存
	if tpls2, _ := LoadTemplateCache(dir); len(tpls2) != 1 {
		t.Errorf("未变化应命中缓存, got %d", len(tpls2))
	}
	// 新增模板文件(内容大小变化 => 指纹变化): 下次调用自动热更新
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"),
		[]byte("id: b\ninfo:\n  name: b\nrequest:\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tpls3, errs := LoadTemplateCache(dir)
	if len(tpls3) != 2 || len(errs) != 0 {
		t.Fatalf("新增文件后应热更新为 2, got %d/%v", len(tpls3), errs)
	}
	// 删除文件: 同样感知
	if err := os.Remove(filepath.Join(dir, "b.yaml")); err != nil {
		t.Fatal(err)
	}
	if tpls4, _ := LoadTemplateCache(dir); len(tpls4) != 1 {
		t.Errorf("删除文件后应热更新为 1, got %d", len(tpls4))
	}
	// 强制刷新: 目录未变也重新加载, 结果一致
	if tpls5, errs := RefreshTemplateCache(dir); len(tpls5) != 1 || len(errs) != 0 {
		t.Errorf("强制刷新 = %d/%v, want 1/nil", len(tpls5), errs)
	}
}

// TestBuiltinTemplates 内置模板(exe 打包): 非空 / Builtin 标记 / 与外部合并时外部覆盖
func TestBuiltinTemplates(t *testing.T) {
	tpls, errs := LoadBuiltinTemplates()
	if len(tpls) == 0 {
		t.Fatalf("内置模板不应为空: %v", errs)
	}
	for _, tp := range tpls {
		if !tp.Builtin {
			t.Errorf("内置模板 %s 的 Builtin 标记应为 true", tp.ID)
		}
		if tp.ID == "" {
			t.Error("内置模板 ID 不应为空")
		}
	}
	if BuiltinTemplateCount() != len(tpls) {
		t.Errorf("BuiltinTemplateCount = %d, want %d", BuiltinTemplateCount(), len(tpls))
	}
	// 合并: 外部模板同 ID 覆盖内置
	merged := mergeTemplates(tpls, []Template{{ID: tpls[0].ID, Request: &Request{Paths: stringOrList{"/"}}}})
	if len(merged) != len(tpls) {
		t.Fatalf("同 ID 合并不应增加数量: got %d, want %d", len(merged), len(tpls))
	}
	for _, tp := range merged {
		if tp.ID == tpls[0].ID && tp.Builtin {
			t.Errorf("同 ID 合并后 %s 应被外部覆盖(Builtin=false)", tp.ID)
		}
	}
}

// TestFindingSource finding 来源标记: 外部模板 nuclei / 内置模板 nuclei-builtin
func TestFindingSource(t *testing.T) {
	r := NewNucleiRunner(DefaultRunnerConfig())
	snap := &respSnapshot{
		code:    200,
		body:    "ok",
		header:  "Server: x\n",
		rawReq:  "GET / HTTP/1.1\r\nHost: h\r\n\r\n",
		rawResp: "HTTP/1.1 200 OK\r\n\r\nok",
	}
	a1 := ServiceAsset{IP: "10.9.9.1", Port: 80, Scheme: "http"}
	a2 := ServiceAsset{IP: "10.9.9.2", Port: 80, Scheme: "http"}
	f1, ok1 := r.newFinding(a1, Template{ID: "src-ext", Info: &Info{Name: "x"}}, snap, "/")
	if !ok1 || f1.Source != "nuclei" {
		t.Errorf("外部模板 Source = %q, want nuclei", f1.Source)
	}
	f2, ok2 := r.newFinding(a2, Template{ID: "src-builtin", Builtin: true, Info: &Info{Name: "y"}}, snap, "/")
	if !ok2 || f2.Source != "nuclei-builtin" {
		t.Errorf("内置模板 Source = %q, want nuclei-builtin", f2.Source)
	}
}

// TestValidateTemplate 加载期 matcher 静态校验: 非法正则/DSL 被报告, 合法模板通过
func TestValidateTemplate(t *testing.T) {
	ps := validateTemplate(&Template{Matchers: []Matcher{
		{Type: "regex", Regexes: stringOrList{`([invalid`}},
		{Type: "dsl", DSL: stringOrList{`"(unclosed`}},
	}})
	if len(ps) != 2 {
		t.Errorf("应报告 2 个问题, got %v", ps)
	}
	if ps := validateTemplate(&Template{Matchers: []Matcher{
		{Type: "regex", Regexes: stringOrList{`nginx/(\d+\.\d+)`}},
		{Type: "dsl", DSL: stringOrList{`status_code == 200 && contains(body, "x")`}},
	}}); len(ps) != 0 {
		t.Errorf("合法模板应无问题, got %v", ps)
	}
}
