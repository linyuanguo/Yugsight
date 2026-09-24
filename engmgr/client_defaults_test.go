package engmgr

import (
	"net/http"
	"testing"
	"time"
)

// TestNewClientKeepsTransportDefaults 锁住"下载客户端必须保留标准库 Transport 默认值"。
//
// 【回归用例】曾经 newClient 写成 `&http.Transport{Proxy: ...}` —— Go 的字面量构造会把
// 未赋值字段全部清零, 于是 TLSHandshakeTimeout/IdleConnTimeout/ExpectContinueTimeout
// 全变成 0, 连接池参数也归零。实测后果: 37MB 的 nmap 安装包在 nmap.org 上反复于
// 4~5MB 处 `unexpected EOF`(直连脚本同网络下能稳定跑完)。
//
// 这个测试直接断言关键字段非零, 因为"清零默认值"这类退化不会让任何用例失败,
// 只会在真实慢速链路上表现为下载失败 —— 没有断言就等于没有防护。
func TestNewClientKeepsTransportDefaults(t *testing.T) {
	m := New(t.TempDir())
	c := m.newClient(0)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport 类型应为 *http.Transport, 实得 %T", c.Transport)
	}
	// 逐个检查被清零过的字段
	if tr.TLSHandshakeTimeout <= 0 {
		t.Errorf("TLSHandshakeTimeout 为 %v, 应为正数(否则握手挂起会永久卡死)", tr.TLSHandshakeTimeout)
	}
	if tr.IdleConnTimeout <= 0 {
		t.Errorf("IdleConnTimeout 为 %v, 应为正数(否则空闲连接不回收)", tr.IdleConnTimeout)
	}
	if tr.ExpectContinueTimeout <= 0 {
		t.Errorf("ExpectContinueTimeout 为 %v, 应为正数", tr.ExpectContinueTimeout)
	}
	if tr.DialContext == nil {
		t.Error("DialContext 为 nil, 说明丢了标准库的拨号器(无 keep-alive/双栈优选)")
	}
	if tr.MaxIdleConns <= 0 {
		t.Errorf("MaxIdleConns 为 %d, 应为正数", tr.MaxIdleConns)
	}
	// 下载场景的期望值: 空闲池放大到至少 4(一次安装顺序下多个引擎, 复用省握手)
	if tr.MaxIdleConnsPerHost < 4 {
		t.Errorf("MaxIdleConnsPerHost 为 %d, 期望 >= 4(顺序下载多个引擎时复用连接)", tr.MaxIdleConnsPerHost)
	}
	// timeout=0 表示不限总时长: 慢链路(50MB @ 188KB/s)需要十几分钟,
	// 设总上限会在快下完时砍断请求
	if c.Timeout != 0 {
		t.Errorf("Client.Timeout 为 %v, 下载客户端应传 0(不限总时长, 由各阶段超时约束)", c.Timeout)
	}
}

// TestNewClientProxyOverride 代理配置只覆盖 Proxy, 不破坏其它默认值。
func TestNewClientProxyOverride(t *testing.T) {
	defer SetProxy("")
	m := New(t.TempDir())

	// 显式代理
	SetProxy("http://127.0.0.1:7890")
	tr := m.newClient(0).Transport.(*http.Transport)
	u, err := tr.Proxy(&http.Request{})
	if err != nil {
		t.Fatalf("解析代理 URL 失败: %v", err)
	}
	if u == nil || u.Host != "127.0.0.1:7890" {
		t.Errorf("显式代理未生效, 实得 %v", u)
	}
	if tr.TLSHandshakeTimeout <= 0 {
		t.Error("设置代理后 TLSHandshakeTimeout 被清零")
	}

	// 代理地址非法时应忽略并退回环境代理, 且不影响其它字段
	SetProxy("://bad url")
	tr2 := m.newClient(0).Transport.(*http.Transport)
	if tr2.TLSHandshakeTimeout <= 0 {
		t.Error("非法代理后 TLSHandshakeTimeout 被清零")
	}
}

// TestClientTimeoutNotApplied 确认下载路径确实用 0 超时, 而不是某个有限值。
//
// 与上一个用例的区别: 这里从 download 的实际调用点语义出发, 断言"传 0 时
// Client.Timeout 就是 0", 防止有人为了"防止挂死"又改回 30min —— 那个值在
// 慢速链路上恰好等于"下到一半被砍"。
func TestClientTimeoutNotApplied(t *testing.T) {
	m := New(t.TempDir())
	for _, want := range []time.Duration{0, 20 * time.Second} {
		if got := m.newClient(want).Timeout; got != want {
			t.Errorf("newClient(%v).Timeout = %v, 期望原样透传", want, got)
		}
	}
}
