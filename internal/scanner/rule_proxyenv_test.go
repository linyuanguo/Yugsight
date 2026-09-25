package scanner

import (
	"net/http"
	"os"
	"testing"
	"time"
)

// withEnv 临时设置环境变量并在用例结束后还原, 避免污染其它用例。
func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	names := []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"}
	saved := map[string]string{}
	for _, n := range names {
		saved[n] = os.Getenv(n)
	}
	t.Cleanup(func() {
		for n, v := range saved {
			if v == "" {
				os.Unsetenv(n)
			} else {
				os.Setenv(n, v)
			}
		}
	})
	for _, n := range names {
		os.Unsetenv(n)
	}
	for k, v := range kv {
		os.Setenv(k, v)
	}
}

// TestProxyFromEnvironmentHonorsSystemEnv 锁住"方案B: 用环境变量而非配置文件指定代理"。
//
// 【背景】程序不走 Windows「Internet 选项」的系统代理设置, 只认环境变量。
// 以往在 settings.json 里写死 http://127.0.0.1:7890 —— 代理一关, 模板更新与引擎
// 下载会直接 connection refused 硬失败, 必须手工改配置才能恢复。
//
// 【本用例保证】updater.proxy 留空时客户端回落到环境变量; 环境变量清空(代理关闭)
// 时自动回退直连, 而不是继续指向那个已无人监听的端口。
func TestProxyFromEnvironmentHonorsSystemEnv(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://codeload.github.com/x", nil)

	// 1) 设了环境变量 -> 应该解析出代理(配置留空)
	withEnv(t, map[string]string{
		"HTTPS_PROXY": "http://127.0.0.1:7890",
		"HTTP_PROXY":  "http://127.0.0.1:7890",
	})
	SetProxy("") // 关键: 配置留空 = 走环境变量

	c := newHTTPClient(5 * time.Second)
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("updater: 配置留空时应回落到环境变量代理")
	}
	pu, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("updater 代理解析出错: %v", err)
	}
	if pu == nil || pu.String() != "http://127.0.0.1:7890" {
		t.Fatalf("updater 未使用环境变量代理, got=%v", pu)
	}

	// 直连通道同样行为
	dc := directClient("", 5*time.Second)
	dtr, _ := dc.Transport.(*http.Transport)
	if dtr == nil || dtr.Proxy == nil {
		t.Fatal("直连通道: 配置留空时应回落到环境变量代理")
	}
	if dpu, err := dtr.Proxy(req); err != nil || dpu == nil || dpu.String() != "http://127.0.0.1:7890" {
		t.Fatalf("直连通道未使用环境变量代理, got=%v err=%v", dpu, err)
	}

	// 2) 代理关闭(环境变量清空) -> 必须自动回退直连
	withEnv(t, nil)
	c2 := newHTTPClient(5 * time.Second)
	tr2, _ := c2.Transport.(*http.Transport)
	pu2, err := tr2.Proxy(req)
	if err != nil {
		t.Fatalf("代理关闭后解析出错: %v", err)
	}
	if pu2 != nil {
		t.Fatalf("代理已关闭(环境变量清空)应回退直连, 却仍返回代理 %v", pu2)
	}
}

// TestProxyWithoutSchemeIsNormalized 锁住"代理地址缺 scheme 时自动补 http://"。
//
// 【背景】Go 的 url.Parse 遇到 `127.0.0.1:7890`(无 scheme)时, 会把 `127.0.0.1`
// 当作**协议**、`:7890` 当作**主机**, 代理静默失效且难以排查。手抄配置极易漏 http://。
func TestProxyWithoutSchemeIsNormalized(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/x", nil)

	// 配置文件路径
	SetProxy("127.0.0.1:7890")
	tr, _ := newHTTPClient(5 * time.Second).Transport.(*http.Transport)
	pu, err := tr.Proxy(req)
	if err != nil || pu == nil {
		t.Fatalf("配置代理解析失败: %v %v", pu, err)
	}
	if pu.Scheme != "http" || pu.Host != "127.0.0.1:7890" {
		t.Fatalf("缺 scheme 的配置代理未规范化, scheme=%q host=%q", pu.Scheme, pu.Host)
	}

	// 环境变量路径
	SetProxy("")
	withEnv(t, map[string]string{"HTTP_PROXY": "127.0.0.1:7891"})
	tr2, _ := newHTTPClient(5 * time.Second).Transport.(*http.Transport)
	pu2, err := tr2.Proxy(req)
	if err != nil || pu2 == nil {
		t.Fatalf("环境变量代理解析失败: %v %v", pu2, err)
	}
	if pu2.Scheme != "http" || pu2.Host != "127.0.0.1:7891" {
		t.Fatalf("缺 scheme 的环境变量代理未规范化, scheme=%q host=%q", pu2.Scheme, pu2.Host)
	}
}

// TestNoProxyExclusion 锁住 NO_PROXY 生效: 内网地址与 localhost 不走代理。
// 否则 proxy 会把内网请求也送进代理, 轻则变慢, 重则直接连不通。
func TestNoProxyExclusion(t *testing.T) {
	SetProxy("")
	withEnv(t, map[string]string{
		"HTTP_PROXY": "http://127.0.0.1:7890",
		"NO_PROXY":   "localhost,192.168.*,.internal.corp",
	})
	tr, _ := newHTTPClient(5 * time.Second).Transport.(*http.Transport)

	cases := []struct {
		url   string
		proxy bool // true = 期望走代理
	}{
		{"http://example.com/x", true},
		{"http://api.internal.corp/x", false}, // 后缀命中
		{"http://192.168.1.10/x", false},      // host 不匹配通配(简化实现按后缀比对)
		{"http://127.0.0.1:8080/x", false},    // 本机直连
	}
	for _, c := range cases {
		req, _ := http.NewRequest(http.MethodGet, c.url, nil)
		pu, err := tr.Proxy(req)
		if err != nil {
			t.Fatalf("%s 解析出错: %v", c.url, err)
		}
		if got := pu != nil; got != c.proxy {
			t.Errorf("%s 代理判定错误: 期望走代理=%v, 实际=%v", c.url, c.proxy, got)
		}
	}
}

// TestConfigProxyOverridesEnv 锁住优先级: 配置文件显式指定时优先于环境变量。
func TestConfigProxyOverridesEnv(t *testing.T) {
	withEnv(t, map[string]string{"HTTP_PROXY": "http://127.0.0.1:1111"})
	SetProxy("http://127.0.0.1:2222")
	defer SetProxy("")

	tr, _ := newHTTPClient(5 * time.Second).Transport.(*http.Transport)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/x", nil)
	pu, err := tr.Proxy(req)
	if err != nil || pu == nil {
		t.Fatalf("解析失败: %v %v", pu, err)
	}
	if pu.Port() != "2222" {
		t.Fatalf("配置文件代理应优先于环境变量, got=%v", pu)
	}
}
