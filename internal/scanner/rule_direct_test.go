package scanner

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ===== 测试辅助 =====

// makeTemplatesZip 构造一个"官方源码包"形状的 zip:
// 顶层目录 <repo>-<sha>/http/..., 内容即 templates 映射(相对 http/ 的路径 -> 内容)
func makeTemplatesZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "templates.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, data := range entries {
		w, err := zw.Create("nuclei-templates-abc1234/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// httpTemplate 生成一个最小的合法 HTTP 模板 YAML。
//
// 【两个必须记住的坑, 都踩过】
//  1. 块名是单数 request:(不是 http:)。本项目内置引擎的解析口径见 nuclei_parser.go
//     —— 它找的是顶层 request / requests 键, 官方模板里也普遍是这两个; 写成 http: 会被
//     isExecutableHTTPTemplate 判为"非 HTTP 模板"而被过滤掉, 现象是"测试数据明明是
//     高危模板却一个都提取不到"。
//  2. request: 的值是**映射**(scanner.Request), 不是序列; 只有它内部的 path 才是序列。
//     写成 "- method: ..." 会让热加载报 "cannot unmarshal !!seq into scanner.Request"。
//     注意 isExecutableHTTPTemplate 只做文本级顶层键判定, 所以形状写错时**提取阶段会
//     通过、加载阶段才报错** —— 断言用例若只看提取结果就会漏掉。
func httpTemplate(id, severity string) string {
	return "id: " + id + "\n" +
		"info:\n" +
		"  name: Test Template " + id + "\n" +
		"  author: test\n" +
		"  severity: " + severity + "\n" +
		"  tags: " + severity + "\n" +
		"request:\n" +
		"  method: GET\n" +
		"  path:\n" +
		"    - \"{{BaseURL}}/\"\n" +
		"matchers:\n" +
		"  - type: status\n" +
		"    status:\n" +
		"      - 200\n"
}

// TestHTTPTemplateFixtureParses 守住上面那条测试夹心数据自身的正确性。
//
// 为什么值得单独测夹具: 夹具形状写错时提取阶段照样通过(文本级判定), 于是"提取用例全绿"
// 但规则实际加载不进来 —— 这类假绿最难发现, 用真实的解析器把夹具钉死最省事。
func TestHTTPTemplateFixtureParses(t *testing.T) {
	tpl, err := ParseNucleiTemplate([]byte(httpTemplate("fixture-check", "high")))
	if err != nil {
		t.Fatalf("夹具模板应能被内置解析器解析: %v", err)
	}
	if tpl == nil {
		t.Fatal("夹具模板被判定为非 HTTP 模板(形状写错了)")
	}
	if tpl.ID != "fixture-check" {
		t.Errorf("ID = %q", tpl.ID)
	}
	if tpl.Info == nil || tpl.Info.Severity != "high" {
		t.Errorf("severity 解析异常: %+v", tpl.Info)
	}
	if tpl.Request == nil || len(tpl.Request.Paths) == 0 {
		t.Fatal("request/path 未解析出来(检查 request 是否为映射而非序列)")
	}
}

// blockedTemplate 生成一个"内置引擎跑不了"的其它协议模板
// (kind 如 network/dns/ssl/headless/javascript/websocket)
func blockedTemplate(id, kind, severity string) string {
	return "id: " + id + "\n" +
		"info:\n" +
		"  name: Blocked " + id + "\n" +
		"  severity: " + severity + "\n" +
		kind + ":\n" +
		"  - x: y\n"
}

// ===== 配置 =====

// TestDirectConfigDefaults 默认必须关闭(项目规则 5: 新增功能默认关闭)
func TestDirectConfigDefaults(t *testing.T) {
	c := DirectConfig()
	if c.Enabled {
		t.Fatal("直连通道默认必须关闭")
	}
	if c.TemplatesRepo != defaultTemplatesRepo {
		t.Fatalf("默认仓库应为 %s, 实得 %s", defaultTemplatesRepo, c.TemplatesRepo)
	}
	if len(c.Severities) == 0 {
		t.Fatal("默认应有严重级过滤(全量拉取会拖慢单次更新)")
	}
	if c.MaxTemplates <= 0 {
		t.Fatal("默认必须有模板数量上限(防内存与耗时失控)")
	}
}

// TestSetDirectOptions 归一化: 空仓库回默认 / 斜杠裁剪 / 严重级副本隔离
func TestSetDirectOptions(t *testing.T) {
	old := DirectConfig()
	t.Cleanup(func() { SetDirectOptions(old) })

	SetDirectOptions(DirectOptions{Enabled: true, TemplatesRepo: "  owner/repo/  ", TemplatesRef: " main "})
	c := DirectConfig()
	if c.TemplatesRepo != "owner/repo" {
		t.Errorf("仓库名应裁剪空白与末尾斜杠, 实得 %q", c.TemplatesRepo)
	}
	if c.TemplatesRef != "main" {
		t.Errorf("ref 应裁剪空白, 实得 %q", c.TemplatesRef)
	}
	if !c.Enabled {
		t.Error("Enabled 未生效")
	}
	// 空仓库必须回落默认, 否则会拼出 https://api.github.com/repos//commits
	SetDirectOptions(DirectOptions{Enabled: true, TemplatesRepo: ""})
	if got := DirectConfig().TemplatesRepo; got != defaultTemplatesRepo {
		t.Errorf("空仓库应回默认, 实得 %q", got)
	}
	// 返回的是副本: 外部改切片不得影响内部配置
	SetDirectOptions(DirectOptions{Severities: []string{"high"}})
	c1 := DirectConfig()
	c1.Severities[0] = "mutated"
	if DirectConfig().Severities[0] != "high" {
		t.Error("DirectConfig 返回值未与内部隔离(切片共享)")
	}
}

// TestDirectDisabledRejectsUpdate 未启用时两个入口都必须明确拒绝(不发网络)
func TestDirectDisabledRejectsUpdate(t *testing.T) {
	old := DirectConfig()
	t.Cleanup(func() { SetDirectOptions(old) })
	SetDirectOptions(DirectOptions{Enabled: false})

	if _, err := CheckDirect(); err == nil {
		t.Fatal("未启用时 CheckDirect 应返回错误")
	}
	if _, err := DirectUpdate(nil); err == nil {
		t.Fatal("未启用时 DirectUpdate 应返回错误")
	}
}

// ===== 模板过滤(最关键: 决定哪些模板会进入规则库) =====

// TestExtractTemplatesFiltering 只保留内置引擎能跑的高危档 HTTP 模板
func TestExtractTemplatesFiltering(t *testing.T) {
	zipPath := makeTemplatesZip(t, map[string]string{
		// 应被保留
		"http/cves/2024/CVE-2024-1111.yaml": httpTemplate("CVE-2024-1111", "critical"),
		"http/misconfiguration/redis.yaml":  httpTemplate("redis-exposed", "high"),
		"http/exposures/config.yaml":        httpTemplate("config-leak", "medium"),
		// 应被严重级过滤掉
		"http/exposures/info-only.yaml": httpTemplate("info-tpl", "info"),
		"http/exposures/low-tpl.yaml":   httpTemplate("low-tpl", "low"),
		// 应被类型过滤掉(内置引擎是 HTTP-only)
		"network/dns/dns-detect.yaml": blockedTemplate("dns-tpl", "network", "high"),
		"http/headless/browser.yaml":  blockedTemplate("headless-tpl", "headless", "high"),
		"http/javascript/js.yaml":     blockedTemplate("js-tpl", "javascript", "high"),
		"http/ssl/cert.yaml":          blockedTemplate("ssl-tpl", "ssl", "high"),
		// 共享片段(下划线前缀)应被跳过
		"http/helpers/_shared.yaml": httpTemplate("shared", "high"),
		// 非模板文件应被跳过
		"http/README.md":                  "# readme",
		"http/cves/2024/CVE-2024-2222.json": "{}",
		// 目录穿越条目必须被拒绝
		"http/../../../evil.yaml": httpTemplate("evil", "high"),
	})
	cfg := DirectOptions{Severities: []string{"critical", "high", "medium"}, MaxTemplates: 100}
	out, skipped, err := extractTemplates(zipPath, cfg)
	if err != nil {
		t.Fatalf("提取失败: %v", err)
	}
	gotIDs := map[string]bool{}
	for _, x := range out {
		if !strings.HasPrefix(x.rel, "cves/") && !strings.HasPrefix(x.rel, "misconfiguration/") &&
			!strings.HasPrefix(x.rel, "exposures/") {
			t.Errorf("提取出了非 http/ 相对路径: %q", x.rel)
		}
		if strings.Contains(x.rel, "..") {
			t.Errorf("提取出了穿越路径: %q", x.rel)
		}
		gotIDs[filepath.Base(x.rel)] = true
	}
	want := []string{"CVE-2024-1111.yaml", "redis.yaml", "config.yaml"}
	for _, w := range want {
		if !gotIDs[w] {
			t.Errorf("应保留 %s 但没保留", w)
		}
	}
	unwanted := []string{"info-only.yaml", "low-tpl.yaml", "dns-detect.yaml", "browser.yaml", "js.yaml", "cert.yaml", "_shared.yaml", "README.md", "evil.yaml"}
	for _, u := range unwanted {
		if gotIDs[u] {
			t.Errorf("不应保留 %s", u)
		}
	}
	if skipped == 0 {
		t.Error("跳过的文件数应被统计(供结果展示)")
	}
}

// TestExtractTemplatesMaxLimit 数量上限必须生效
func TestExtractTemplatesMaxLimit(t *testing.T) {
	entries := map[string]string{}
	for i := 0; i < 20; i++ {
		entries["http/exposures/t"+string(rune('a'+i))+".yaml"] = httpTemplate("tpl-"+string(rune('a'+i)), "high")
	}
	zipPath := makeTemplatesZip(t, entries)
	out, _, err := extractTemplates(zipPath, DirectOptions{Severities: []string{"high"}, MaxTemplates: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 5 {
		t.Fatalf("上限 5 应只提取 5 个, 实得 %d", len(out))
	}
	// 0 表示不限制(回落默认上限)
	out2, _, err := extractTemplates(zipPath, DirectOptions{Severities: []string{"high"}, MaxTemplates: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(out2) != 20 {
		t.Fatalf("MaxTemplates=0 应回落默认上限(20 个全部提取), 实得 %d", len(out2))
	}
}

// TestExtractTemplatesInvalidZip 非法 zip 必须报错而不是静默返回空
func TestExtractTemplatesInvalidZip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.zip")
	if err := os.WriteFile(p, []byte("this is not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := extractTemplates(p, DirectOptions{}); err == nil {
		t.Fatal("非法 zip 应返回错误")
	}
}

// TestSeverityAllowed 严重级判定
func TestSeverityAllowed(t *testing.T) {
	sevs := normalizeSeverities([]string{"critical", "high"})
	yes := []string{
		httpTemplate("a", "critical"),
		httpTemplate("b", "high"),
	}
	no := []string{
		httpTemplate("c", "low"),
		httpTemplate("d", "info"),
		"id: x\ninfo:\n  name: y\n",
	}
	for _, s := range yes {
		if !severityAllowed([]byte(s), sevs) {
			t.Errorf("应判定为允许: %s", s)
		}
	}
	for _, s := range no {
		if severityAllowed([]byte(s), sevs) {
			t.Errorf("应判定为不允许: %s", s)
		}
	}
	// 空过滤集合 = 不限制
	if !severityAllowed([]byte(httpTemplate("e", "info")), map[string]bool{}) {
		t.Error("空严重级集合应表示不限制")
	}
}

// TestHasTopLevelKey 顶层键判定: 缩进的同名子键不算
func TestHasTopLevelKey(t *testing.T) {
	s := "id: a\ninfo:\n  name: x\n  requests:\n    - method: GET\nhttp:\n  - method: GET\n"
	if hasTopLevelKey(s, "requests:") {
		t.Error("缩进的 requests 是子键, 不应判为顶层键")
	}
	if !hasTopLevelKey(s, "http:") {
		t.Error("行首的 http: 应判为顶层键")
	}
	if hasTopLevelKey(s, "  name:") {
		t.Error("带缩进的键名不应匹配(我们只查行首)")
	}
	if hasTopLevelKey(s, "# http:") {
		t.Error("注释行不应算作顶层键")
	}
}

// TestIsExecutableHTTPTemplate 类型判定: headless/javascript/network/ssl/dns 一律排除
func TestIsExecutableHTTPTemplate(t *testing.T) {
	if !isExecutableHTTPTemplate([]byte(httpTemplate("ok", "high"))) {
		t.Error("标准 HTTP 模板应判定为可执行")
	}
	bad := map[string]string{
		"headless":   blockedTemplate("a", "headless", "high"),
		"javascript": blockedTemplate("b", "javascript", "high"),
		"network":    blockedTemplate("c", "network", "high"),
		"code":       blockedTemplate("d", "code", "high"),
		"dns":        blockedTemplate("e", "dns", "high"),
		"ssl":        blockedTemplate("f", "ssl", "high"),
		"websocket":  blockedTemplate("g", "websocket", "high"),
		"no-http":    "id: h\ninfo:\n  name: h\nseverity: high\n",
		// workflow: 只声明依赖不直接执行, 也排除
		"workflow": "id: w\ninfo:\n  name: w\nflow: a.yaml\n",
	}
	for name, s := range bad {
		if isExecutableHTTPTemplate([]byte(s)) {
			t.Errorf("%s 类型不应判定为可执行 HTTP 模板", name)
		}
	}
	// requests: 复数形式同样应当接受(官方两种写法并存)
	plural := "id: p\ninfo:\n  name: p\n  severity: high\nrequests:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
	if !isExecutableHTTPTemplate([]byte(plural)) {
		t.Error("requests: 复数形式应判定为可执行")
	}
}

// TestHasTopLevelKeyIgnoresIndentedKeys 缩进的 requests/matchers 不能算数
// (否则一个纯 network 模板只要在 payload 里提到 requests 就会被误收)
func TestIndentedKeysNotCounted(t *testing.T) {
	s := "id: a\ninfo:\n  name: a\nnetwork:\n  - host: []\n    payloads:\n      requests: x\n"
	if isExecutableHTTPTemplate([]byte(s)) {
		t.Error("network 模板不应因为缩进处出现 requests 而被误判为 HTTP 模板")
	}
}

// ===== 相对路径安全 =====

// TestArchiveSafeRel 路径安全校验
func TestArchiveSafeRel(t *testing.T) {
	bad := []string{"", "..", "../x.yaml", "a/../../x.yaml", "/abs/x.yaml", "\\abs\\x.yaml",
		"a/b/c/d/e/f/g.yaml"} // 层级过深
	for _, b := range bad {
		if got := archiveSafeRel(b); got != "" {
			t.Errorf("archiveSafeRel(%q) = %q, 期望拒绝", b, got)
		}
	}
	good := map[string]string{
		"cves/2024/CVE-2024-1111.yaml": "cves/2024/CVE-2024-1111.yaml",
		"x.yaml":                       "x.yaml",
		"./x.yaml":                     "x.yaml",
		"a/b/../c.yaml":                "a/c.yaml",
	}
	for in, want := range good {
		if got := archiveSafeRel(in); got != want {
			t.Errorf("archiveSafeRel(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// ===== 修订标记 =====

// TestDirectRevRoundTrip 修订标记读写(直连通道的"已是最新"依据)
func TestDirectRevRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if got := readDirectRev(dir); got != "" {
		t.Fatalf("空目录应返回空串, 实得 %q", got)
	}
	if err := writeDirectRev(dir, "abc123"); err != nil {
		t.Fatal(err)
	}
	if got := readDirectRev(dir); got != "abc123" {
		t.Fatalf("读取到的修订标识应为 abc123, 实得 %q", got)
	}
	// 目录不存在时写入应自动建目录(首次更新场景)
	dir2 := filepath.Join(t.TempDir(), "rules")
	if err := writeDirectRev(dir2, "def456"); err != nil {
		t.Fatalf("目录不存在时应自动创建: %v", err)
	}
	if got := readDirectRev(dir2); got != "def456" {
		t.Fatalf("实得 %q", got)
	}
}

// TestDirectRevFileIsNotTemplate ruleset 加载时不能把 .direct-rev 当模板
// (它以点开头的隐藏文件, 且不是 .yaml)
func TestDirectRevFileIsNotTemplate(t *testing.T) {
	dir := t.TempDir()
	if err := writeDirectRev(dir, "rev"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
			t.Fatalf("修订标记不应是 YAML 文件: %s", e.Name())
		}
	}
}

// ===== zipball URL =====

// TestZipballURL 有修订号时必须走 codeload 直连(避免 api.github.com 的限速与 302)
func TestZipballURL(t *testing.T) {
	cfg := DirectOptions{TemplatesRepo: "projectdiscovery/nuclei-templates"}
	got := zipballURL(cfg, "abc123")
	want := "https://codeload.github.com/projectdiscovery/nuclei-templates/zip/abc123"
	if got != want {
		t.Fatalf("zipballURL 拼错:\n got %s\nwant %s", got, want)
	}
	noRev := zipballURL(cfg, "")
	if !strings.Contains(noRev, "api.github.com") {
		t.Fatalf("无修订号时应走 API 重定向入口, 实得 %s", noRev)
	}
}

// ===== JSON 最小解析 =====

// TestJsonFirstString GitHub commits 接口是数组, 要取第一个 sha
func TestJsonFirstString(t *testing.T) {
	body := []byte(`[{"sha":"first-sha","commit":{"message":"x"}},{"sha":"second-sha"}]`)
	if got := jsonFirstString(body, "sha"); got != "first-sha" {
		t.Fatalf("应取第一个 sha, 实得 %q", got)
	}
	// 对象形态(单 commit 接口)
	obj := []byte(`{"sha":"only-sha","commit":{}}`)
	if got := jsonFirstString(obj, "sha"); got != "only-sha" {
		t.Fatalf("对象形态应取到 only-sha, 实得 %q", got)
	}
	// 缺失字段
	if got := jsonFirstString([]byte(`{"a":1}`), "sha"); got != "" {
		t.Fatalf("缺失字段应为空, 实得 %q", got)
	}
}

// ===== 合成 manifest 的落地(与既有 applyManifest 的集成) =====

// TestApplyManifestLocalStage 本地暂存模式: 不发起任何网络请求也能把文件落到 rules/
//
// 这是直连通道与既有落地流程的接缝处, 必须验证"本地拷贝分支"真的生效
// (若失效会退化成 HTTP 请求 -> 在沙箱里必然失败, 用例会红)。
func TestApplyManifestLocalStage(t *testing.T) {
	rulesDir, _ := withDirs(t)
	withUpdater(t, "https://unused.example.com/") // 配一个源, 但本地模式下不应被访问
	tpl := httpTemplate("CVE-2024-9999", "critical")
	sum := sha256Hex([]byte(tpl))

	// 本地暂存目录(模拟"官方源码包已解包"的状态)
	stage := t.TempDir()
	rel := "http/cves/2024/CVE-2024-9999.yaml"
	if err := os.MkdirAll(filepath.Join(stage, "http/cves/2024"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, filepath.FromSlash(rel)), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &RemoteManifest{
		Commit: "localstagecommit",
		Name:   "rules",
		Files:  []RemoteFile{{Path: rel, Size: int64(len(tpl)), SHA256: sum}},
	}
	res, err := applyManifest(m, "", nil, stage)
	if err != nil {
		t.Fatalf("本地暂存模式落地失败: %v", err)
	}
	if !res.Updated || res.Files != 1 {
		t.Fatalf("结果不符: %+v", res)
	}
	// 文件必须真的落到 rules/ 下, 内容与源一致。
	// 【路径口径】manifest 里的 path 是"相对 rules/ 的完整路径"(带 http/ 前缀),
	// 不是"相对 http/ 的路径" —— 别按后者断言, 会找不到文件。
	got, err := os.ReadFile(filepath.Join(rulesDir, "http/cves/2024/CVE-2024-9999.yaml"))
	if err != nil {
		t.Fatalf("目标文件未落位: %v", err)
	}
	if string(got) != tpl {
		t.Fatal("落地内容与源不一致")
	}
	// .commit 必须写入(下次检查"已是最新"的依据)
	if c := readLocalCommit(rulesDir); c != "localstagecommit" {
		t.Fatalf(".commit 应为 localstagecommit, 实得 %q", c)
	}
	// checksum.sha256 必须登记(下次加载做完整性校验)
	cs := loadRuleChecksums(rulesDir)
	if cs[rel] != sum {
		t.Fatalf("checksum.sha256 未正确登记: %v", cs)
	}
}

// TestApplyManifestHashMismatchRollsBack 本地文件被篡改 -> 校验失败 -> 回滚且不动正式文件
func TestApplyManifestHashMismatchRollsBack(t *testing.T) {
	rulesDir, _ := withDirs(t)
	stage := t.TempDir()
	rel := "http/cves/CVE-2024-8888.yaml"
	if err := os.MkdirAll(filepath.Join(stage, "http/cves"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, filepath.FromSlash(rel)), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &RemoteManifest{Commit: "x", Files: []RemoteFile{{Path: rel, Size: 8, SHA256: strings.Repeat("a", 64)}}}
	if _, err := applyManifest(m, "", nil, stage); err == nil {
		t.Fatal("sha256 不符必须报错")
	}
	// 正式文件不得出现, 暂存目录必须被清理
	if _, err := os.Stat(filepath.Join(rulesDir, "http/cves/CVE-2024-8888.yaml")); !os.IsNotExist(err) {
		t.Fatal("校验失败时不应写入正式文件")
	}
	if _, err := os.Stat(filepath.Join(rulesDir, ".staging")); !os.IsNotExist(err) {
		t.Fatal("校验失败时暂存目录应被清理")
	}
	// .commit 不应被更新
	if c := readLocalCommit(rulesDir); c != "" {
		t.Fatalf("失败时不应写 .commit, 实得 %q", c)
	}
}

// TestApplyManifestNilManifest 空清单必须返回错误(不 panic)
func TestApplyManifestNilManifest(t *testing.T) {
	if _, err := applyManifest(nil, "", nil, ""); err == nil {
		t.Fatal("空清单应返回错误")
	}
}

// TestApplyManifestFiltersNonHTTP 非 http/ 前缀的文件必须被跳过(硬过滤)
func TestApplyManifestFiltersNonHTTP(t *testing.T) {
	withDirs(t)
	stage := t.TempDir()
	// 两个文件: 一个 http/ 下, 一个不在
	good := httpTemplate("good", "high")
	for _, rel := range []string{"http/a.yaml", "network/b.yaml"} {
		p := filepath.Join(stage, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(good), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := &RemoteManifest{Commit: "c", Files: []RemoteFile{
		{Path: "http/a.yaml", Size: int64(len(good)), SHA256: sha256Hex([]byte(good))},
		{Path: "network/b.yaml", Size: int64(len(good)), SHA256: sha256Hex([]byte(good))},
	}}
	res, err := applyManifest(m, "", nil, stage)
	if err != nil {
		t.Fatalf("落地失败: %v", err)
	}
	if res.Files != 1 {
		t.Fatalf("应只应用 1 个文件, 实得 %d", res.Files)
	}
	if res.Skipped != 1 {
		t.Fatalf("应跳过 1 个文件, 实得 %d", res.Skipped)
	}
}

// TestLocalStageClientNeverHitsNetwork 本地暂存模式的客户端一旦被用于真实请求必须报错
// (防御"看起来在本地拷贝, 实际又把包拉了一遍"的回归)
func TestLocalStageClientNeverHitsNetwork(t *testing.T) {
	c := newLocalStageClient("/tmp/stage")
	if localStageOf(c) != "/tmp/stage" {
		t.Fatal("本地暂存目录未正确挂载")
	}
	if localStageOf(nil) != "" {
		t.Fatal("nil 客户端应返回空串")
	}
	// 普通客户端(网络模式)不应被误判为本地模式
	if got := localStageOf(newHTTPClient(time.Second)); got != "" {
		t.Fatalf("普通客户端不应被判为本地暂存模式, 实得 %q", got)
	}
	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(req); err == nil {
		t.Fatal("本地暂存模式不应允许发起网络请求")
	}
}

// TestCopyStagedFile 本地暂存拷贝语义: 写入带 .part 后缀, 内容一致
func TestCopyStagedFile(t *testing.T) {
	stage, staging := t.TempDir(), t.TempDir()
	rel := "http/cves/x.yaml"
	content := "id: x\n"
	p := filepath.Join(stage, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	f := RemoteFile{Path: rel, Size: int64(len(content)), SHA256: sha256Hex([]byte(content))}
	if err := copyStagedFile(stage, staging, f); err != nil {
		t.Fatalf("拷贝失败: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(staging, filepath.FromSlash(rel)) + ".part")
	if err != nil {
		t.Fatalf(".part 文件未生成: %v", err)
	}
	if string(got) != content {
		t.Fatal("拷贝内容不一致")
	}
	// 源文件缺失必须报错(而不是写出空文件后让校验阶段才发现)
	if err := copyStagedFile(filepath.Join(stage, "nope"), staging, f); err == nil {
		t.Fatal("源文件缺失应报错")
	}
}

// TestNormalizeSeverities 严重级归一化
func TestNormalizeSeverities(t *testing.T) {
	got := normalizeSeverities([]string{" HIGH ", "critical", "", "Medium"})
	if !got["high"] || !got["critical"] || !got["medium"] {
		t.Fatalf("归一化失败: %v", got)
	}
	if len(got) != 3 {
		t.Fatalf("空项应被丢弃, 实得 %d 项: %v", len(got), got)
	}
}

// ===== 断点续传(downloadDirectFile) =====
//
// 背景: 官方源码包 20-35MB, 国内直连常几十 KB/s。此前用 os.Create 截断重下,
// 任何一次中断都会把已下载的部分全部作废。这组用例把"续传真的生效"钉死。

// loopbackTCPAllowed 探测当前环境是否允许回环 TCP 连接。
//
// 【为什么需要探测而不是直接跳过】开发沙箱会拦截回环连接: 监听成功但 dial 超时
// (不是立即拒绝), 表现为"测试失败得像代码有 bug"。这是既有约定(见 engmgr /
// probe/scanner 的同名辅助), 真实网络行为由真机联调覆盖。
func loopbackTCPAllowed() bool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// rangeServer 起一个支持 Range 的测试服务端, 返回 (baseURL, 请求记录)。
// 用 httptest 而不是真实外网: 沙箱/CI 无可达外网, 且需要断言"第二次请求带了 Range"。
func rangeServer(t *testing.T, content []byte) (*httptest.Server, *sync.Mutex, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var ranges []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ranges = append(ranges, r.Header.Get("Range"))
		mu.Unlock()
		http.ServeContent(w, r, "templates.zip", time.Now(), bytes.NewReader(content))
	}))
	t.Cleanup(srv.Close)
	return srv, &mu, &ranges
}

// TestDownloadDirectFileResumesFromPartial 已有部分下载时必须带 Range 续传, 且最终内容正确。
//
// 这是本次改动的核心回归: 修复前第二次请求不带 Range(从 0 重下)。
func TestDownloadDirectFileResumesFromPartial(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("环境拦截回环 TCP 连接(沙箱), 由真机联调覆盖")
	}
	content := bytes.Repeat([]byte("yugsight-template-payload-"), 4096)
	srv, mu, ranges := rangeServer(t, content)

	dest := filepath.Join(t.TempDir(), "pkg.zip.part")
	// 预置"已下载一半"的 .part, 模拟上次中断
	half := len(content) / 2
	if err := os.WriteFile(dest, content[:half], 0o644); err != nil {
		t.Fatal(err)
	}

	var lastBytes, lastTotal int64
	if err := downloadDirectFile(dest, srv.URL, "", func(p UpdateProgress) {
		if p.Bytes > 0 {
			lastBytes, lastTotal = p.Bytes, p.TotalBytes
		}
	}); err != nil {
		t.Fatalf("续传下载失败: %v", err)
	}

	mu.Lock()
	got := append([]string(nil), *ranges...)
	mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("应只发 1 次请求, 实得 %d 次: %v", len(got), got)
	}
	if got[0] != fmt.Sprintf("bytes=%d-", half) {
		t.Fatalf("续传请求头应为 bytes=%d-, 实得 %q", half, got[0])
	}

	// 文件内容必须与源完全一致(续传写错偏移会得到拼接错位的损坏包)
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("续传后内容不一致: 实得 %d 字节, 期望 %d 字节", len(data), len(content))
	}
	// 总长度应回填为完整包大小(206 的 ContentLength 只是剩余部分, 必须加上偏移)
	if lastTotal != int64(len(content)) {
		t.Fatalf("TotalBytes 应回填完整包长 %d, 实得 %d", len(content), lastTotal)
	}
	if lastBytes != int64(len(content)) {
		t.Fatalf("最终 Bytes 应为 %d, 实得 %d", len(content), lastBytes)
	}
}

// TestDownloadDirectFileFreshWhenNoPart 无 .part 时应整包下载(不带 Range)
func TestDownloadDirectFileFreshWhenNoPart(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("环境拦截回环 TCP 连接(沙箱), 由真机联调覆盖")
	}
	content := []byte("fresh-download-payload")
	srv, mu, ranges := rangeServer(t, content)
	dest := filepath.Join(t.TempDir(), "pkg.zip.part")
	if err := downloadDirectFile(dest, srv.URL, "", nil); err != nil {
		t.Fatalf("下载失败: %v", err)
	}
	mu.Lock()
	got := append([]string(nil), *ranges...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("无断点时应整包下载(无 Range), 实得 %v", got)
	}
	data, _ := os.ReadFile(dest)
	if !bytes.Equal(data, content) {
		t.Fatal("整包下载内容不一致")
	}
}

// TestDownloadDirectFileFallsBackWhenServerIgnoresRange 源端不支持续传时必须从 0 重下。
//
// 【为什么这条必须测】若源端忽略 Range 返回 200 全量内容, 而客户端仍以 off>0 打开
// 文件追加写, 就会得到"前半段旧内容 + 完整新内容"的拼接包 —— 解压时才报错, 排查
// 方向会被完全带偏(会怀疑 zip 损坏而不是续传逻辑)。
func TestDownloadDirectFileFallsBackWhenServerIgnoresRange(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("环境拦截回环 TCP 连接(沙箱), 由真机联调覆盖")
	}
	content := []byte("0123456789abcdefghij")
	// 服务端不支持 Range: 永远返回 200 + 全量
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "pkg.zip.part")
	// 预置一段"错误的旧内容", 若代码没清零偏移, 它会被保留在文件头部
	if err := os.WriteFile(dest, []byte("STALE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := downloadDirectFile(dest, srv.URL, "", nil); err != nil {
		t.Fatalf("下载失败: %v", err)
	}
	data, _ := os.ReadFile(dest)
	if !bytes.Equal(data, content) {
		t.Fatalf("源端不支持续传时应整包覆盖, 实得以 %q 开头的 %d 字节", string(data[:min(6, len(data))]), len(data))
	}
}

// TestDownloadDirectFileTruncatedKeepsPart 下载不完整时保留 .part 供下次续传
func TestDownloadDirectFileTruncatedKeepsPart(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("环境拦截回环 TCP 连接(沙箱), 由真机联调覆盖")
	}
	content := bytes.Repeat([]byte("x"), 1000)
	// 声称 5000 字节但只发 1000, 制造"下载不完整"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "pkg.zip.part")
	err := downloadDirectFile(dest, srv.URL, "", nil)
	if err == nil {
		t.Fatal("长度不符应报错")
	}
	if !strings.Contains(err.Error(), "断点") {
		t.Fatalf("错误信息应提示断点已保留(便于用户重试), 实得: %v", err)
	}
	// .part 必须还在(留着才能续传)
	st, serr := os.Stat(dest)
	if serr != nil || st.Size() != int64(len(content)) {
		t.Fatalf(".part 应保留已下载的 %d 字节, 实得 %v (err=%v)", len(content), st, serr)
	}
}

// TestHumanBytes 进度文案的字节格式化
func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:         "0 B",
		512:       "512 B",
		2048:      "2.0 KB",
		5 << 20:   "5.0 MB",
		3 << 30:   "3.0 GB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, 期望 %q", in, got, want)
		}
	}
}

// TestSafeRevName 修订标识的文件名规整(目录穿越防护)
func TestSafeRevName(t *testing.T) {
	if got := safeRevName("abc123def456"); got != "abc123def456" {
		t.Errorf("正常 sha 应原样保留, 实得 %q", got)
	}
	// 目录穿越必须被中和: 结果里不能出现路径分隔符或 ..
	got := safeRevName("../../etc/passwd")
	if strings.ContainsAny(got, `/\`) || strings.Contains(got, "..") {
		t.Fatalf("目录穿越未被中和: %q", got)
	}
	if safeRevName("") != "unknown" {
		t.Errorf("空 rev 应回退为 unknown, 实得 %q", safeRevName(""))
	}
	// 超长 rev 截断到 64 字符(sha256 是 64 位, 留足余量)
	long := strings.Repeat("a", 200)
	if len(safeRevName(long)) != 64 {
		t.Errorf("超长 rev 应截断到 64, 实得 %d", len(safeRevName(long)))
	}
}

// TestDirectCacheDirCreatesDir 断点缓存目录应被创建(拿不到 exe 目录时降级系统临时目录)
func TestDirectCacheDirCreatesDir(t *testing.T) {
	dir := directCacheDir()
	if dir == "" {
		t.Fatal("缓存目录不应为空")
	}
	// 目录必须真实存在且可写(否则续传能力静默失效)
	p := filepath.Join(dir, "yugsight-cache-probe.tmp")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatalf("缓存目录不可写: %v", err)
	}
	os.Remove(p)
}
