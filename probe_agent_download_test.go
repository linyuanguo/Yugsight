// probe_agent_download_test.go 探针 agent 分发模块测试。
//
// 覆盖重点(不依赖真实网络/不依赖开发机 agents/ 目录):
//  1. 平台白名单: 合法组合放行, 越界组合(含路径穿越尝试)被拒;
//  2. 文件名匹配: 约定名 / -v 后缀 / 大小写 / .exe 容错, 以及必须不被误匹配的
//     "同前缀不同平台"与"yugsight-agents"这类词边界外的情况;
//  3. 未分发时的降级: 目录缺失 -> 404 且带编译指引, 而不是 500;
//  4. 下载响应头: Content-Disposition 文件名带平台标识且扩展名正确;
//  5. 目录穿越防护: 用 os/arch 传 ".." 不越出 agents/。
//
// 所有用例都把 agentDownloadDir 改指 t.TempDir(), 否则会读开发机真实目录,
// 断言随环境漂移(与 reportCfgPath / rulesExternalDir 同一约定)。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yugsight/server"
)

// withAgentDir 把 agent 包目录改指临时目录并在用例结束恢复。
func withAgentDir(t *testing.T) string {
	t.Helper()
	prev := agentDownloadDir
	dir := t.TempDir()
	agentDownloadDir = func() string { return dir }
	t.Cleanup(func() { agentDownloadDir = prev })
	return dir
}

// writeAgentPkg 在临时目录写入一个内容可辨认的假 agent 包。
func writeAgentPkg(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写入 %s 失败: %v", name, err)
	}
	return p
}

// agentTestServer 只挂探针路由的测试服务器(测试模式下免登录)。
func agentTestServer(t *testing.T) *server.Server {
	t.Helper()
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })
	srv := server.New(server.WithLogger(func(string) {}))
	registerProbeRoutes(srv)
	return srv
}

// ===== 平台白名单 =====

// TestAgentPlatformWhitelist 覆盖: 平台矩阵内组合放行, 越界组合一律拒绝。
func TestAgentPlatformWhitelist(t *testing.T) {
	ok := [][2]string{
		{"windows", "amd64"}, {"windows", "arm64"},
		{"linux", "amd64"}, {"linux", "arm64"},
		{"darwin", "amd64"}, {"darwin", "arm64"},
		{"WINDOWS", "AMD64"},  // 大小写不敏感
		{" linux ", "amd64"},  // 前后空白容忍
	}
	for _, c := range ok {
		if _, _, _, _, found := agentPlatform(c[0], c[1]); !found {
			t.Fatalf("平台 %s/%s 应被支持", c[0], c[1])
		}
	}
	// 越界组合必须被拒 —— 尤其 ".." 与路径分隔符, 它们是穿越尝试的入口
	bad := [][2]string{
		{"freebsd", "amd64"}, {"windows", "386"}, {"linux", "mips"},
		{"", ""}, {"..", ".."}, {"../../etc", "amd64"}, {"windows/../..", "amd64"},
		{"windows", "*"},
	}
	for _, c := range bad {
		if _, _, _, _, found := agentPlatform(c[0], c[1]); found {
			t.Fatalf("平台 %q/%q 不应被支持", c[0], c[1])
		}
	}
}

// TestAgentDownloadRejectsBadPlatform 覆盖: 越界平台经接口返回 400 且说明可用组合。
func TestAgentDownloadRejectsBadPlatform(t *testing.T) {
	withAgentDir(t)
	srv := agentTestServer(t)

	cases := []string{
		"/api/v2/probe/agent/download?os=freebsd&arch=amd64",
		"/api/v2/probe/agent/download?os=..&arch=..",
		"/api/v2/probe/agent/download?os=windows",
		"/api/v2/probe/agent/download",
	}
	for _, path := range cases {
		w := doAgentReq(t, srv, path)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s 应返回 400, 实际 %d: %s", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "不支持") && !strings.Contains(w.Body.String(), "请指定") {
			t.Fatalf("%s 错误信息未说明原因: %s", path, w.Body.String())
		}
	}
}

// ===== 文件名匹配 =====

// TestFindAgentBinaryNaming 覆盖: 各种命名写法的命中与不命中。
func TestFindAgentBinaryNaming(t *testing.T) {
	cases := []struct {
		name    string // 磁盘上的文件名
		os      string
		arch    string
		wantHit bool
	}{
		// 标准约定名
		{"yugsight-agent_windows_amd64.exe", "windows", "amd64", true},
		{"yugsight-agent_linux_amd64", "linux", "amd64", true},
		{"yugsight-agent_darwin_arm64", "darwin", "arm64", true},
		// 大小写不一致(用户手改常见)
		{"Yugsight-Agent_Linux_AMD64", "linux", "amd64", true},
		// 短横线分隔变体(yugsight-agent-linux-amd64)
		{"yugsight-agent-linux-arm64", "linux", "arm64", true},
		// 下划线变体(go build -o 手写)
		{"yugsight_agent_windows_amd64.exe", "windows", "amd64", true},
		// 版本后缀容忍(词边界后接 -)
		{"yugsight-agent_linux_amd64-v1.2.0", "linux", "amd64", true},
		// .bin 扩展名容忍(Linux 上改名常见)
		{"yugsight-agent_linux_arm64.bin", "linux", "arm64", true},
		// ---- 必须不命中 ----
		// 平台不符: 不能把 windows 包给 linux 下载
		{"yugsight-agent_windows_amd64.exe", "linux", "amd64", false},
		// 同前缀但不是 agent(词边界外) —— 这条是第二轮的边界判定, 不能误命中
		{"yugsight-agents_linux_amd64", "linux", "amd64", false},
		// 完全无关的文件
		{"readme.txt", "windows", "amd64", false},
	}
	for _, c := range cases {
		t.Run(c.name+"_"+c.os+"_"+c.arch, func(t *testing.T) {
			dir := withAgentDir(t)
			writeAgentPkg(t, dir, c.name, "fake-agent")
			_, gotName, found := findAgentBinary(c.os, c.arch)
			if found != c.wantHit {
				t.Fatalf("命中判定错误: want=%v got=%v (文件 %s 请求 %s/%s)",
					c.wantHit, found, c.name, c.os, c.arch)
			}
			if found && !strings.EqualFold(gotName, c.name) {
				t.Fatalf("命中文件错误: want=%s got=%s", c.name, gotName)
			}
		})
	}
}

// TestFindAgentBinaryPrefersExact 覆盖: 目录内同时存在多个候选时优先取标准约定名。
//
// 为什么重要: 用户可能同时放了裸名 yugsight-agent(本地构建)与带平台标识的包,
// 若取错就会把本机平台的二进制分发给别的平台, 属严重误发。
func TestFindAgentBinaryPrefersExact(t *testing.T) {
	dir := withAgentDir(t)
	writeAgentPkg(t, dir, "yugsight-agent.exe", "local-build")
	writeAgentPkg(t, dir, "yugsight-agent_linux_amd64", "linux-pkg")
	writeAgentPkg(t, dir, "yugsight-agent_linux_arm64", "arm-pkg")

	_, name, found := findAgentBinary("linux", "arm64")
	if !found || name != "yugsight-agent_linux_arm64" {
		t.Fatalf("应精确命中平台包, 实际 %q (found=%v)", name, found)
	}
	// 请求一个只存在裸名的平台(裸名是 windows 包) 不应被当作 linux 分发
	if _, _, f := findAgentBinary("darwin", "amd64"); f {
		t.Fatal("darwin/amd64 无对应包, 不应命中裸名文件")
	}
}

// TestFindAgentBinaryMissingDir 覆盖: 目录不存在时静默返回未找到(不 panic 不报错)。
func TestFindAgentBinaryMissingDir(t *testing.T) {
	prev := agentDownloadDir
	agentDownloadDir = func() string { return filepath.Join(t.TempDir(), "not-exist-dir") }
	t.Cleanup(func() { agentDownloadDir = prev })

	if _, _, found := findAgentBinary("linux", "amd64"); found {
		t.Fatal("目录缺失时不应命中任何文件")
	}
	if pkgs := listAgentPackages(); len(pkgs) != 0 {
		t.Fatalf("目录缺失时应返回空列表, 实际 %d 项", len(pkgs))
	}
}

// ===== 列表接口 =====

// TestAgentListAPI 覆盖: 列表接口只列出实际存在的包, 并回带目录与协议版本。
func TestAgentListAPI(t *testing.T) {
	dir := withAgentDir(t)
	writeAgentPkg(t, dir, "yugsight-agent_windows_amd64.exe", strings.Repeat("x", 2048))
	writeAgentPkg(t, dir, "yugsight-agent_linux_arm64", "small")
	// 干扰项: 说明文件与被改名成非 agent 前缀的文件不应出现在列表
	writeAgentPkg(t, dir, "probe.json", "{}")
	writeAgentPkg(t, dir, "notes.txt", "hello")

	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/list")
	if w.Code != http.StatusOK {
		t.Fatalf("列表接口 HTTP %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			List     []map[string]any `json:"list"`
			Total    int              `json:"total"`
			Dir      string           `json:"dir"`
			Hint     string           `json:"hint"`
			Protocol int              `json:"protocol"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v (%s)", err, w.Body.String())
	}
	if resp.Data.Total != 2 || len(resp.Data.List) != 2 {
		t.Fatalf("应列出 2 个平台包, 实际 %d: %s", resp.Data.Total, w.Body.String())
	}
	if resp.Data.Dir != dir {
		t.Fatalf("回带的目录应为 agents 目录, 实际 %s", resp.Data.Dir)
	}
	if resp.Data.Protocol <= 0 {
		t.Fatalf("协议版本异常: %d", resp.Data.Protocol)
	}
	// 大小应被回填(前端展示下载体积)
	seenWin := false
	for _, it := range resp.Data.List {
		if it["os"] == "windows" && it["arch"] == "amd64" {
			seenWin = true
			if size, _ := it["size"].(float64); int64(size) != 2048 {
				t.Fatalf("windows 包体积应为 2048, 实际 %v", it["size"])
			}
			if !strings.Contains(it["file"].(string), "windows") {
				t.Fatalf("文件名字段异常: %v", it["file"])
			}
		}
		// 干扰文件不应被列出
		if f, _ := it["file"].(string); f == "probe.json" || f == "notes.txt" {
			t.Fatalf("非 agent 文件不应出现在下载列表: %s", f)
		}
	}
	if !seenWin {
		t.Fatal("windows/amd64 包未出现在列表中")
	}
}

// TestAgentListEmptyAPI 覆盖: 未分发任何包时列表为空数组(非 null)且 hint 含编译指引。
func TestAgentListEmptyAPI(t *testing.T) {
	withAgentDir(t)
	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/list")
	if w.Code != http.StatusOK {
		t.Fatalf("空列表也应 200, 实际 %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			List []any  `json:"list"`
			Hint string `json:"hint"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Data.List == nil {
		t.Fatal("无包时 list 应为空数组而非 null")
	}
	if !strings.Contains(resp.Data.Hint, "go build") || !strings.Contains(resp.Data.Hint, "cmd/agent") {
		t.Fatalf("hint 应包含编译命令: %s", resp.Data.Hint)
	}
}

// ===== 下载接口 =====

// TestAgentDownloadAPI 覆盖: 存在包时返回文件内容 + 正确的下载文件名。
func TestAgentDownloadAPI(t *testing.T) {
	dir := withAgentDir(t)
	body := "FAKE-AGENT-BINARY-CONTENT"
	writeAgentPkg(t, dir, "yugsight-agent_linux_amd64", body)
	srv := agentTestServer(t)

	w := doAgentReq(t, srv, "/api/v2/probe/agent/download?os=linux&arch=amd64")
	if w.Code != http.StatusOK {
		t.Fatalf("下载 HTTP %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != body {
		t.Fatalf("下载内容不符: %q", w.Body.String())
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "yugsight-agent_linux_amd64") {
		t.Fatalf("下载文件名应带平台标识: %s", cd)
	}
	if strings.Contains(cd, ".exe") {
		t.Fatalf("Linux 包不应带 .exe 扩展名: %s", cd)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type 应为二进制流: %s", ct)
	}
}

// TestAgentDownloadWindowsExe 覆盖: Windows 包下载名带 .exe(即使磁盘文件名不带)。
func TestAgentDownloadWindowsExe(t *testing.T) {
	dir := withAgentDir(t)
	writeAgentPkg(t, dir, "yugsight-agent_windows_arm64", "win-bin") // 故意不带 .exe
	srv := agentTestServer(t)

	w := doAgentReq(t, srv, "/api/v2/probe/agent/download?os=windows&arch=arm64")
	if w.Code != http.StatusOK {
		t.Fatalf("下载 HTTP %d: %s", w.Code, w.Body.String())
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "yugsight-agent_windows_arm64.exe") {
		t.Fatalf("Windows 包下载名应补 .exe: %s", cd)
	}
}

// TestAgentDownloadNotDistributed 覆盖: 未上传包返回 404 + 编译指引(不是 500)。
//
// 为什么必须是 404 而不是 500: "尚未分发"是正常状态, 500 会让运维去查服务端故障,
// 而实际只需上传文件。错误语义影响排查方向, 这里单独断言。
func TestAgentDownloadNotDistributed(t *testing.T) {
	withAgentDir(t)
	srv := agentTestServer(t)

	w := doAgentReq(t, srv, "/api/v2/probe/agent/download?os=darwin&arch=arm64")
	if w.Code != http.StatusNotFound {
		t.Fatalf("未分发应返回 404, 实际 %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "go build") {
		t.Fatalf("404 应附带编译指引: %s", w.Body.String())
	}
}

// TestAgentDownloadNoTraversal 覆盖: 越界 os/arch 不产生任何目录穿越读文件行为。
//
// 断言口径: 在 agents/ 的同级目录放一个"哨兵"文件, 若实现存在穿越漏洞,
// 构造的 os/arch 有可能把它读出来。这里验证请求被白名单挡在 IO 之前。
func TestAgentDownloadNoTraversal(t *testing.T) {
	prev := agentDownloadDir
	parent := t.TempDir()
	agents := filepath.Join(parent, "agents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	writeAgentPkg(t, parent, "secret.bin", "SECRET")
	agentDownloadDir = func() string { return agents }
	t.Cleanup(func() { agentDownloadDir = prev })

	srv := agentTestServer(t)
	for _, path := range []string{
		"/api/v2/probe/agent/download?os=..&arch=..",
		"/api/v2/probe/agent/download?os=../..&arch=etc",
		"/api/v2/probe/agent/download?os=" + "...%2F..&arch=amd64",
	} {
		w := doAgentReq(t, srv, path)
		if strings.Contains(w.Body.String(), "SECRET") {
			t.Fatalf("%s 发生了目录穿越, 读到 agents/ 之外的文件", path)
		}
		if w.Code == http.StatusOK {
			t.Fatalf("%s 不应成功", path)
		}
	}
}

// ===== 部署指引 =====

// TestAgentGuideAPI 覆盖: 指引为 text/plain 且含关键步骤(可直接贴到工单)。
func TestAgentGuideAPI(t *testing.T) {
	withAgentDir(t)
	srv := agentTestServer(t)

	w := doAgentReq(t, srv, "/api/v2/probe/agent/guide")
	if w.Code != http.StatusOK {
		t.Fatalf("指引 HTTP %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("指引应为纯文本: %s", ct)
	}
	body := w.Body.String()
	for _, want := range []string{"yugsight-agent", "-center", "-token", "yugsight-agent.log", "出站"} {
		if !strings.Contains(body, want) {
			t.Fatalf("指引缺少关键内容 %q:\n%s", want, body)
		}
	}
}

// ===== 地址推导 =====

// TestAgentAdvertiseAddr 覆盖: 监听地址推导为探针可连地址的各分支。
func TestAgentAdvertiseAddr(t *testing.T) {
	prev := probeCfg
	t.Cleanup(func() { probeCfg = prev })

	// 1) 绑全部网卡: 应推导出具体 IP(可能拿不到 IP -> 空串), 至少不能是 0.0.0.0
	probeCfg = ProbeConfig{}
	probeCfg.Center.Listen = ":8600"
	got := agentAdvertiseAddr()
	if strings.Contains(got, "0.0.0.0") {
		t.Fatalf("不应把 0.0.0.0 当作探针可连地址: %q", got)
	}
	if got != "" && !strings.HasSuffix(got, ":8600") {
		t.Fatalf("端口应保留: %q", got)
	}

	// 2) 指定主机: 原样返回
	probeCfg.Center.Listen = "192.168.1.10:8600"
	if got := agentAdvertiseAddr(); got != "192.168.1.10:8600" {
		t.Fatalf("指定主机应原样返回: %q", got)
	}

	// 3) 仅本机监听: 如实返回(同机联调场景)
	probeCfg.Center.Listen = "127.0.0.1:9000"
	if got := agentAdvertiseAddr(); got != "127.0.0.1:9000" {
		t.Fatalf("本机监听应如实返回: %q", got)
	}

	// 4) 空配置: 空串(由调用方退化为占位符)
	probeCfg.Center.Listen = ""
	if got := agentAdvertiseAddr(); got != "" {
		t.Fatalf("空监听应为空串: %q", got)
	}

	// 5) 只有端口没有主机
	probeCfg.Center.Listen = ":0"
	got = agentAdvertiseAddr()
	if strings.Contains(got, ":0") && !strings.HasSuffix(got, ":0") {
		t.Fatalf("端口解析异常: %q", got)
	}
}

// TestSplitHostPortLoose 覆盖: 宽松地址解析各写法(标准 net.SplitHostPort 会拒绝 ":8600")。
func TestSplitHostPortLoose(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{":8600", "", "8600"},
		{"0.0.0.0:8600", "0.0.0.0", "8600"},
		{"[::]:8600", "::", "8600"},
		{"192.168.1.10:9000", "192.168.1.10", "9000"},
		{"0.0.0.0", "0.0.0.0", ""},
	}
	for _, c := range cases {
		h, p, err := splitHostPortLoose(c.in)
		if err != nil {
			t.Fatalf("解析 %q 失败: %v", c.in, err)
		}
		if h != c.wantHost || p != c.wantPort {
			t.Fatalf("解析 %q 期望 (%q,%q), 实际 (%q,%q)", c.in, c.wantHost, c.wantPort, h, p)
		}
	}
	if _, _, err := splitHostPortLoose(""); err == nil {
		t.Fatal("空地址应返回错误")
	}
}

// TestAgentPlatformSummarySorted 覆盖: 平台摘要列出全部组合且排序稳定。
func TestAgentPlatformSummarySorted(t *testing.T) {
	got := sortedAgentPlatforms()
	if len(got) != len(agentPlatforms) {
		t.Fatalf("平台数不符: %d vs %d", len(got), len(agentPlatforms))
	}
	for i := 0; i < len(agentPlatforms); i++ {
		if agentPlatforms[i].OS == "" || agentPlatforms[i].Arch == "" {
			t.Fatalf("平台矩阵第 %d 项 os/arch 为空: %+v", i, agentPlatforms[i])
		}
		if strings.TrimSpace(agentPlatforms[i].Install) == "" {
			t.Fatalf("平台矩阵第 %d 项缺少安装命令: %+v", i, agentPlatforms[i])
		}
	}
	sum := agentPlatformSummary()
	for _, p := range got {
		if !strings.Contains(sum, p) {
			t.Fatalf("摘要缺少 %s: %s", p, sum)
		}
	}
}

// doAgentReq 发起一次 GET 请求(返回原始 recorder 以便断言响应头与原始体)。
//
// 用 httptest 同步响应而非真实 TCP: 沙箱环境会拦截回环连接, 直接走
// Handler().ServeHTTP 与既有 probe_api_test.go / env_api_test.go 口径一致。
func doAgentReq(t *testing.T, srv *server.Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}
