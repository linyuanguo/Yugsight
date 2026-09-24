// probe_agent_install_test.go 探针"就地补包 + 安装落地页"测试。
//
// 覆盖重点:
//  1. 安装落地页必须真的渲染出可用内容: 地址/密钥被注入、六个平台按钮都在、
//     未分发的平台按钮置灰且给出原因(而不是从页面上消失);
//  2. 密钥/地址必须做 HTML 转义 —— 它们是配置里来的字符串, 未转义会破坏页面结构;
//  3. 补包接口: 越界平台 400、非 POST 拒绝、Windows 端明确回复"用脚本"而不是静默失败;
//  4. 列表接口新增的 build 能力字段结构完整(前端靠它决定按钮可用性)。
//
// 不依赖真实网络/开发机 agents 目录(统一改指临时目录)。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yugsight/agentpkg"
	"yugsight/server"
)

// doAgentPost 发起一次 POST(补包接口用)
func doAgentPost(t *testing.T, srv *server.Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(w, req)
	return w
}

// ===== 补包接口 =====

// TestAgentBuildRejectsBadPlatform 越界平台必须 400 且列出可用组合(与下载接口同口径)。
func TestAgentBuildRejectsBadPlatform(t *testing.T) {
	withAgentDir(t)
	srv := agentTestServer(t)

	for _, body := range []string{
		`{"os":"freebsd","arch":"amd64"}`,
		`{"os":"..","arch":".."}`,
		`{"os":"windows/../..","arch":"amd64"}`,
	} {
		w := doAgentPost(t, srv, "/api/v2/probe/agent/build", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body=%s 应 400, 实际 %d: %s", body, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "不支持") {
			t.Fatalf("错误应说明平台不支持: %s", w.Body.String())
		}
	}
}

// TestAgentBuildRequiresPost GET 不应触发构建(构建有副作用, 必须只走 POST)。
//
// 这里期望 405 而不是 400: 路由用 srv.Post 注册, Go 1.22 ServeMux 对方法不匹配
// 会自己回 405 Method Not Allowed —— 由框架拦掉比让 handler 再判一次更可靠
// (handler 里的方法判断只是双保险)。断言 405 能同时守住"必须注册为 POST"这件事。
func TestAgentBuildRequiresPost(t *testing.T) {
	withAgentDir(t)
	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/build")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET 构建接口应返回 405, 实际 %d: %s", w.Code, w.Body.String())
	}
}

// TestAgentBuildUnsupportedPlatformExplicit Windows 端(空桩)必须明确回复"怎么做",
// 而不是静默成功或空错误 —— 否则用户会反复点按钮猜原因。
func TestAgentBuildUnsupportedPlatformExplicit(t *testing.T) {
	if agentpkg.Supported() {
		t.Skip("当前平台支持就地补包, 本用例只验证空桩语义")
	}
	withAgentDir(t)
	srv := agentTestServer(t)
	w := doAgentPost(t, srv, "/api/v2/probe/agent/build", `{"os":"windows","arch":"amd64"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("空桩平台应 400, 实际 %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "build-agents.ps1") {
		t.Fatalf("应指引用户改用构建脚本, 实际: %s", w.Body.String())
	}
}

// TestAgentBuildNonHostPlatformHint 只允许补本机平台的包, 其它平台要给出明确建议,
// 而不是傻乎乎尝试交叉编译(服务器上往往没有对应工具链, 且产物无法当场验证)。
func TestAgentBuildNonHostPlatformHint(t *testing.T) {
	if !agentpkg.Supported() {
		t.Skip("空桩平台, 由上一个用例覆盖")
	}
	hostOS, hostArch := agentpkg.HostPlatform()
	other := "linux"
	if hostOS == "linux" {
		other = "darwin"
	}
	withAgentDir(t)
	srv := agentTestServer(t)
	w := doAgentPost(t, srv, "/api/v2/probe/agent/build",
		`{"os":"`+other+`","arch":"`+hostArch+`"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非本机平台应被拒, 实际 %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "本机") {
		t.Fatalf("应说明只能补本机平台: %s", w.Body.String())
	}
}

// ===== 列表能力字段 =====

// TestAgentListIncludesBuildCapability 列表接口必须回带 build 能力区块:
// 前端据此决定是否显示"在中心端补出本平台包"按钮。字段缺失会让按钮逻辑失效。
func TestAgentListIncludesBuildCapability(t *testing.T) {
	withAgentDir(t)
	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/list")
	if w.Code != http.StatusOK {
		t.Fatalf("列表 HTTP %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Build map[string]any `json:"build"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Data.Build == nil {
		t.Fatal("list 响应缺少 build 能力区块")
	}
	// supported / hostOS / hostArch / note 两端都必须有: 前端靠它们显示按钮并解释原因
	for _, k := range []string{"supported", "hostOS", "hostArch", "note"} {
		if _, ok := resp.Data.Build[k]; !ok {
			t.Errorf("build 区块缺少字段 %q: %v", k, resp.Data.Build)
		}
	}
	if resp.Data.Build["supported"].(bool) != agentpkg.Supported() {
		t.Fatalf("supported 字段与实际能力不一致: %v", resp.Data.Build["supported"])
	}
	if resp.Data.Build["hostOS"] == "" || resp.Data.Build["hostArch"] == "" {
		t.Fatalf("hostOS/hostArch 不应为空: %v", resp.Data.Build)
	}
	// note 是用户唯一能看到的"为什么不能补包", 空桩平台必须非空
	if !agentpkg.Supported() {
		if s, _ := resp.Data.Build["note"].(string); strings.TrimSpace(s) == "" {
			t.Fatal("空桩平台的 note 不应为空(用户靠它知道该怎么做)")
		}
		return // 空桩平台没有 ready/toolchain 等字段(不探测工具链)
	}
	// 支持就地补包的平台: ready 必须给出人话, canBuild 与两项探测结果自洽
	if s, _ := resp.Data.Build["ready"].(string); strings.TrimSpace(s) == "" {
		t.Fatal("ready 说明不应为空")
	}
	toolOK, _ := resp.Data.Build["toolchain"].(bool)
	repoOK, _ := resp.Data.Build["repoFound"].(bool)
	canBuild, _ := resp.Data.Build["canBuild"].(bool)
	if canBuild != (toolOK && repoOK) {
		t.Fatalf("canBuild 与探测结果不自洽: canBuild=%v toolchain=%v repoFound=%v",
			canBuild, toolOK, repoOK)
	}
}

// TestAgentListOmitsHintWhenPackagesExist 已分发到包时不得再回带"未找到安装包"的指引。
//
// 缺陷背景(冒烟实测复现): hint 原本无条件回带, 于是页面一边列出 2 个可用安装包,
// 一边在底下显示"未找到 yugsight-agent 安装包。请先编译并放入该目录..." ——
// 用户会以为分发没生效而去重新编译, 白白折腾。这条用例把"有包就不提示缺包"钉死。
func TestAgentListOmitsHintWhenPackagesExist(t *testing.T) {
	dir := withAgentDir(t)
	writeAgentPkg(t, dir, "yugsight-agent_windows_amd64.exe", "win-bin")

	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/list")
	if w.Code != http.StatusOK {
		t.Fatalf("列表 HTTP %d", w.Code)
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
	if len(resp.Data.List) == 0 {
		t.Fatal("前置条件不成立: 应已识别到 1 个包")
	}
	if strings.TrimSpace(resp.Data.Hint) != "" {
		t.Fatalf("已有安装包时不应再回带缺包指引, 实际: %q", resp.Data.Hint)
	}
}

// ===== 安装落地页 =====

// TestAgentInstallPageRenders 落地页必须渲染出: 平台按钮、注入后的地址与密钥、
// 可复制命令, 且含关键提示词。
func TestAgentInstallPageRenders(t *testing.T) {
	dir := withAgentDir(t)
	writeAgentPkg(t, dir, "yugsight-agent_windows_amd64.exe", strings.Repeat("x", 1024))
	writeAgentPkg(t, dir, "yugsight-agent_linux_amd64", "linux-bin")

	// 注入一个可辨认的地址与密钥, 断言它们出现在页面里
	prevListen, prevToken := probeCfg.Center.Listen, probeCfg.Center.Token
	probeCfg.Center.Listen = "192.168.5.20:8600"
	probeCfg.Center.Token = "TESTTOKEN123"
	t.Cleanup(func() {
		probeCfg.Center.Listen = prevListen
		probeCfg.Center.Token = prevToken
	})

	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/install")
	if w.Code != http.StatusOK {
		t.Fatalf("安装页 HTTP %d: %s", w.Code, w.Body.String())
	}
	page := w.Body.String()
	for _, want := range []string{
		"192.168.5.20:8600", // 中心端地址已注入
		"TESTTOKEN123",      // 节点密钥已注入
		"-center", "-token", // 可复制命令
		"yugsight-agent.exe", "./yugsight-agent",
		"下载探针",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("安装页缺少关键内容 %q", want)
		}
	}
	// 六个平台按钮都要在(未分发的置灰但不隐藏 —— 隐藏会让用户以为页面功能缺失)
	for _, p := range agentPlatforms {
		if !strings.Contains(page, "data-os=\""+p.OS+"\" data-arch=\""+p.Arch+"\"") {
			t.Errorf("安装页缺少平台按钮 %s/%s", p.OS, p.Arch)
		}
	}
	// 已分发的两个平台应带下载链接, 未分发的应为占位 href
	if !strings.Contains(page, "/api/v2/probe/agent/download?os=windows&arch=amd64") {
		t.Error("已分发平台应生成下载链接")
	}
	if !strings.Contains(page, "尚未产出") {
		t.Error("未分发平台应给出置灰原因(title 属性)")
	}
	// 未分发的平台链接不得指向下载接口(否则点了得到 404, 用户会以为服务坏了)
	if strings.Contains(page, "download?os=darwin&arch=arm64") {
		t.Error("未分发平台不应生成下载链接")
	}

	// 响应头: 密钥在页面里(至少是在 HTML 文本中), 必须禁掉 Referer 外泄
	if rp := w.Header().Get("Referrer-Policy"); rp != "no-referrer" {
		t.Fatalf("应设置 Referrer-Policy: no-referrer, 实际 %q", rp)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type 应为 html: %s", ct)
	}
}

// TestAgentInstallEscapesToken 地址/密钥来自配置文件, 必须 HTML 转义 ——
// 未转义会破坏页面结构(甚至形成注入面)。
func TestAgentInstallEscapesToken(t *testing.T) {
	withAgentDir(t)
	prevToken := probeCfg.Center.Token
	probeCfg.Center.Token = `a"><script>alert(1)</script>`
	t.Cleanup(func() { probeCfg.Center.Token = prevToken })

	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/install")
	page := w.Body.String()
	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Fatal("密钥中的脚本标签未被转义, 存在注入风险")
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Fatalf("期望转义后的形式, 页面片段: %s", snippetAround(page, "alert"))
	}
}

// TestAgentInstallFallsBackToGuide 模板不可用时降级为纯文本指引(不能给用户一个白屏):
// 这里通过把模板路径指到不存在的文件 + 内嵌模板仍然存在来验证"能取到内容";
// 同时验证纯文本分支本身可用(直接调 hAgentGuide)。
func TestAgentInstallFallsBackToGuide(t *testing.T) {
	withAgentDir(t)
	prev := agentInstallTemplatePath
	agentInstallTemplatePath = func() string { return "/nonexistent/does-not-exist.html" }
	t.Cleanup(func() { agentInstallTemplatePath = prev })

	srv := agentTestServer(t)
	// 磁盘模板不存在 -> 应回落到内嵌模板, 仍是 HTML
	w := doAgentReq(t, srv, "/api/v2/probe/agent/install")
	if w.Code != http.StatusOK {
		t.Fatalf("回落内嵌模板应 200, 实际 %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("应仍返回 HTML(内嵌兜底): %s", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "探针安装") {
		t.Fatalf("内嵌模板内容异常: %s", snippetAround(w.Body.String(), "探针"))
	}
	// 纯文本指引接口本身可用(它是最终降级出口)
	g := doAgentReq(t, srv, "/api/v2/probe/agent/guide")
	if g.Code != http.StatusOK || !strings.Contains(g.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("指引接口异常: %d %s", g.Code, g.Header().Get("Content-Type"))
	}
}

// snippetAround 取命中关键词附近的片段(断言失败时便于定位, 避免打印整页 HTML)
func snippetAround(s, kw string) string {
	i := strings.Index(s, kw)
	if i < 0 {
		if len(s) > 200 {
			return s[:200]
		}
		return s
	}
	start := i - 60
	if start < 0 {
		start = 0
	}
	end := i + 120
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
