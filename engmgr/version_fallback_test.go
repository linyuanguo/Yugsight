// version_fallback_test.go 上游版本查询的"限流回退"回归测试。
//
// 【缺陷背景 - 由真实用户环境暴露】
// 用户点"安装 OWASP ZAP"得到:
//
//	查询最新版本失败: HTTP 403: https://api.github.com/repos/zaproxy/zaproxy/releases/latest
//
// 实测确认根因是 **GitHub 匿名 API 配额耗尽**(X-RateLimit-Remaining=0)。
// 该配额是 60 次/小时/**IP**(不是按进程或按用户), 且走代理也一样 —— 代理只换
// 网络出口, 若代理节点本身也被用满同样 403。排查中一度误以为是代理没生效。
//
// 关键点: 这个失败**不该阻断安装** —— 真正的下载地址在 github.com(网页域),
// 不受 API 限流影响(实测 HEAD ZAP_2_17_0_windows.exe 返回 200/244MB)。
// 修复: API 失败时回退到 releases/latest 网页通道, 读 302 重定向 URL 的末段取 tag。
//
// 这组用例锁住回退逻辑, 防止日后被"顺手"简化掉导致用户又只能等配额恢复。
package engmgr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 说明: loopbackTCPAllowed 复用 mirror_probe_test.go 的既有实现(同包, 不重复声明)。

// TestGitHubEnginesHavePageFallback 三个 GitHub 引擎都必须配 LatestPageURL。
//
// 少配一个, 那个引擎在 API 限流时就完全不可安装 —— 而限流是**常态**(任何共用
// 出口 IP 的网络都可能被别人用满), 不是罕见异常。
func TestGitHubEnginesHavePageFallback(t *testing.T) {
	for _, e := range []Engine{EngineTrivy, EngineNuclei, EngineZap} {
		s, err := FindEngine(e)
		if err != nil {
			t.Fatal(err)
		}
		for i, r := range s.Releases {
			if !strings.Contains(r.LatestURL, "api.github.com") {
				continue // 非 API 源(nmap 目录页)不需要该回退
			}
			if r.LatestPageURL == "" {
				t.Errorf("%s 的 Releases[%d] 走 GitHub API 但未配 LatestPageURL, API 限流后将无法查询版本", e, i)
			}
			if !strings.Contains(r.LatestPageURL, "/releases/latest") {
				t.Errorf("%s 的 LatestPageURL 应指向 releases/latest 页面, 实际 %q", e, r.LatestPageURL)
			}
			// 回退地址必须与 API 地址指向同一个仓库, 否则会查到别的项目的版本号
			if !strings.Contains(r.LatestPageURL, "/"+r.Owner+"/"+r.Repo+"/") {
				t.Errorf("%s 的回退地址 %q 与仓库 %s/%s 不匹配", e, r.LatestPageURL, r.Owner, r.Repo)
			}
		}
	}
}

// TestParseTagFromRedirectURL 从重定向地址里提 tag(纯函数口径, 不起网络)。
//
// 覆盖真实地址形态 + 边界(带尾斜杠/带查询串/不含 tag 段)。
func TestParseTagFromRedirectURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"ZAP 实测形态", "https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0", "v2.17.0"},
		{"trivy 实测形态", "https://github.com/aquasecurity/trivy/releases/tag/v0.74.0", "v0.74.0"},
		{"nuclei 实测形态", "https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1", "v3.11.1"},
		{"尾斜杠", "https://github.com/aquasecurity/trivy/releases/tag/v0.74.0/", "v0.74.0"},
		{"镜像前缀", "https://ghfast.top/https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0", "v2.17.0"},
	}
	for _, c := range cases {
		got, err := parseTagFromReleaseURL(c.url)
		if err != nil {
			t.Errorf("%s: 意外失败 %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: 得到 %q, 期望 %q", c.name, got, c.want)
		}
	}

	// 反例: 不含 /releases/tag/ 的地址必须报错, 不能猜出个版本号
	if _, err := parseTagFromReleaseURL("https://github.com/zaproxy/zaproxy/releases"); err == nil {
		t.Error("不含 /releases/tag/ 的地址应报错, 不应返回任何 tag")
	}
	if _, err := parseTagFromReleaseURL("https://github.com/zaproxy/zaproxy/releases/tag/"); err == nil {
		t.Error("tag 为空时应报错")
	}
}

// TestLatestTagFallsBackToPageOnAPIFailure 端到端验证回退链:
// API 返回 403(模拟限流)时, 必须改走网页通道并成功拿到 tag。
//
// 【关键前提校验】用例先断言"不配回退地址时确实会失败", 否则整个用例恒真 ——
// 那样即使回退逻辑被删掉测试也会绿, 失去守护意义。
func TestLatestTagFallsBackToPageOnAPIFailure(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("沙箱拦截回环 TCP, 本用例由真机联调覆盖")
	}
	// 假 API: 恒返 403 + 限流响应体(与 GitHub 真实响应一致)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded for 1.2.3.4.","documentation_url":"https://docs.github.com/rest"}`))
	}))
	defer api.Close()

	// 假 releases/latest: 302 到 /releases/tag/v2.17.0(与 GitHub 真实行为一致)
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			http.Redirect(w, r, "/zaproxy/zaproxy/releases/tag/v2.17.0", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>release page</html>"))
	}))
	defer page.Close()

	m := &Manager{logf: func(string) {}}

	// 1) 前提校验: 只有 API、没有回退 -> 必须失败(证明该用例能捕获回退缺失)
	_, err := m.latestTag(release{LatestURL: api.URL})
	if err == nil {
		t.Fatal("前提校验失败: 无回退地址时 API 403 应当报错(否则本用例恒真)")
	}

	// 2) 配了回退 -> 应当成功拿到 tag
	got, err := m.latestTag(release{LatestURL: api.URL, LatestPageURL: page.URL + "/zaproxy/zaproxy/releases/latest"})
	if err != nil {
		t.Fatalf("API 失败时应回退到网页通道并成功, 实际失败: %v", err)
	}
	if got != "v2.17.0" {
		t.Fatalf("回退取到的 tag 应为 v2.17.0, 实际 %q", got)
	}
}

// TestLatestTagPrefersAPIWhenHealthy 两级通道都在时, 优先用 API(语义最准确)。
//
// 网页通道只是兜底: API 能拿到的是"GitHub 官方认定的 latest 非 prerelease",
// 且不受页面结构改版影响。若退化成"总是走网页", 会丢掉这层准确性。
func TestLatestTagPrefersAPIWhenHealthy(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("沙箱拦截回环 TCP, 本用例由真机联调覆盖")
	}
	var pageHit bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9"}`))
	}))
	defer api.Close()

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageHit = true
		http.Redirect(w, r, "/x/y/releases/tag/v0.0.1", http.StatusFound)
	}))
	defer page.Close()

	m := &Manager{logf: func(string) {}}
	got, err := m.latestTag(release{LatestURL: api.URL, LatestPageURL: page.URL + "/x/y/releases/latest"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "v9.9.9" {
		t.Fatalf("API 正常时应直接采用其 tag_name(v9.9.9), 实际 %q", got)
	}
	if pageHit {
		t.Error("API 正常时不应访问网页通道(多一次请求且可能被镜像改写)")
	}
}
