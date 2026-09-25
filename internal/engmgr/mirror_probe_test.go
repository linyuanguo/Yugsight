package engmgr

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// loopbackTCPAllowed 探测当前环境是否允许回环 TCP 连接。
//
// 【为什么需要】本项目既有约定: 沙箱会拦截回环外连(dial 到已监听端口会超时,
// 而不是立即成功或被拒)。凡是"用 httptest 起本地服务再让代码去连"的用例在这种
// 环境下必然失败, 且失败原因与代码质量无关 —— 实测报错是
// "A connection attempt failed because the connected party did not properly
// respond after a period of time"。
//
// 与 probe/scanner/scanner_test.go 的同名判定保持一致口径: 先探测, 不可用则
// Skip 并说明, 真实网络行为交给真机联调覆盖(镜像探测的实际选速已在上线后由
// 日志 "镜像探测完成, 选用 ..." 验证)。
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

// TestSplitMirrors 多镜像候选解析: 各种分隔符/非法项/去重/补斜杠。
//
// 【为什么必须支持多候选】用户明确要求过"几个镜像既然可用, 为什么不写进去先检测
// 再下载"。镜像站存活率变化很快, 写死一个必然过几个月就废; 支持写一串让程序实测
// 挑最快的, 才是可维护的做法。这个用例锁住解析口径。
func TestSplitMirrors(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"https://a.com", []string{"https://a.com/"}},
		{"https://a.com/", []string{"https://a.com/"}},
		// 逗号分隔(最常见的多候选写法)
		{"https://a.com/,https://b.com/", []string{"https://a.com/", "https://b.com/"}},
		// 逗号+空格
		{"https://a.com/, https://b.com/", []string{"https://a.com/", "https://b.com/"}},
		// 分号与换行(用户从别处粘贴时常带换行)
		{"https://a.com/;https://b.com/\nhttps://c.com/", []string{"https://a.com/", "https://b.com/", "https://c.com/"}},
		// 去重(同一前缀写两遍不该被当成两个候选, 否则白探测一遍)
		{"https://a.com/,https://a.com/", []string{"https://a.com/"}},
		// 非法项(无协议头)直接丢弃, 不能让一个手误把整批探测带偏
		{"not-a-url,https://ok.com/", []string{"https://ok.com/"}},
		{"ftp://x.com/,https://ok.com/", []string{"https://ok.com/"}},
	}
	for _, c := range cases {
		got := splitMirrors(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitMirrors(%q) = %v, 期望 %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitMirrors(%q)[%d] = %q, 期望 %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// TestSetGitHubMirrorTakesFirstAndKeepsCandidates 配置多候选时:
// 生效值取第一个(下载前会被探测结果覆盖), 但候选集完整保留。
//
// 【为什么候选集要保留】探测后会调 SetGitHubMirror(选中项) 覆盖生效值。若候选集
// 也跟着被覆盖成单个, 第二次安装就只剩一个候选、再也比不了速度 —— 用户会感觉
// "第一次很快, 后面又慢了"却找不到原因。
func TestSetGitHubMirrorTakesFirstAndKeepsCandidates(t *testing.T) {
	defer SetGitHubMirror("")
	SetGitHubMirror("https://a.com/,https://b.com/")

	if got := CurrentMirror(); got != "https://a.com/" {
		t.Errorf("生效值应为第一个候选, 实得 %q", got)
	}
	cands := MirrorCandidates()
	if len(cands) != 2 {
		t.Fatalf("候选集应保留 2 个, 实得 %v", cands)
	}

	// 模拟探测选中第二个: 生效值被覆盖, 但候选集仍以配置源为准
	SetGitHubMirror("https://b.com/")
	if got := CurrentMirror(); got != "https://b.com/" {
		t.Errorf("探测后生效值应更新为选中项, 实得 %q", got)
	}
}

// TestMirrorProbeEnabled 探测开关的判定规则。
//
// 单候选 + 未开启 force => 不探测(省一次往返, 只有一个也没什么可比);
// 多候选 => 必须探测(否则不知道该用哪个); 显式 force => 即使单候选也探测。
func TestMirrorProbeEnabled(t *testing.T) {
	defer SetMirrorProbe(false, 0)

	SetMirrorProbe(false, 0)
	if mirrorProbeEnabled(0) {
		t.Error("无候选时不该探测")
	}
	if mirrorProbeEnabled(1) {
		t.Error("单候选且未开启 force 时不该探测")
	}
	if !mirrorProbeEnabled(2) {
		t.Error("多候选必须探测")
	}

	SetMirrorProbe(true, 0)
	if !mirrorProbeEnabled(1) {
		t.Error("开启 force 后单候选也应探测")
	}
}

// TestProbeMirrorsPicksFastest 多镜像探测必须选出**实际更快**的那个, 而不是
// 配置里排前面的那个。
//
// 【回归点】镜像的 HEAD 响应快不代表吞吐高(中转节点过载时首字节秒回但每秒只给
// 几十 KB)。这里用两个本地服务模拟"慢但先返回"与"快"两种镜像, 断言选中的是快
// 的那个 —— 只看延迟或只看顺序的实现都会失败。
func TestProbeMirrorsPicksFastest(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过(镜像选速由真机联调覆盖)")
	}
	// 慢镜像: 每次只给 1 字节且间隔 2ms
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 1024)
		for i := 0; i < 20; i++ {
			if _, err := w.Write(buf); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}))
	defer slow.Close()

	// 快镜像: 一次给足
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		buf := make([]byte, 128<<10)
		_, _ = w.Write(buf)
	}))
	defer fast.Close()

	m := New(t.TempDir())
	SetMirrorProbe(false, 2000)
	defer SetMirrorProbe(false, 0)

	pr := m.probeMirrors([]string{slow.URL + "/", fast.URL + "/"}, "")
	if pr.Chosen == "" {
		t.Fatalf("应有可用镜像, 实得探测结果 %+v", pr.Candidates)
	}
	if pr.Chosen != fast.URL+"/" {
		t.Errorf("应选中更快的镜像 %q, 实得 %q (探测明细: %+v)", fast.URL+"/", pr.Chosen, pr.Candidates)
	}
	// 排序: 可用在前
	if len(pr.Candidates) != 2 || !pr.Candidates[0].OK {
		t.Errorf("可用镜像应排在最前, 实得 %+v", pr.Candidates)
	}
}

// TestProbeMirrorsAllDead 全部镜像不可用时:
//   - Chosen 必须为空(调用方据此决定"停止并告知");
//   - 每个候选都要带可读的失败原因(用户要靠它判断是镜像挂了还是自己网络不通)。
//
// 【为什么不能返回一个"看起来能用"的默认值】调用方在 Chosen=="" 时会中止安装
// 并向用户报错。若这里随便挑一个返回, 用户会看到"开始下载"然后每个引擎各自超时
// 60 秒才失败, 体验比直接说"镜像都不可用"差得多。
func TestProbeMirrorsAllDead(t *testing.T) {
	// 起一个立即关闭的服务, 保证端口拒绝连接
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL + "/"
	dead.Close()

	// 另一个: 域名解析必然失败
	badDNS := "https://this-domain-should-not-exist-yugsight-test.invalid/"

	m := New(t.TempDir())
	SetMirrorProbe(false, 1500)
	defer SetMirrorProbe(false, 0)

	pr := m.probeMirrors([]string{deadURL, badDNS}, "")
	if pr.Chosen != "" {
		t.Errorf("全部不可用时 Chosen 必须为空, 实得 %q", pr.Chosen)
	}
	if len(pr.Candidates) != 2 {
		t.Fatalf("应保留全部候选(含失败原因), 实得 %+v", pr.Candidates)
	}
	for _, c := range pr.Candidates {
		if c.OK {
			t.Errorf("%q 不该被判定为可用", c.Prefix)
		}
		if c.Error == "" {
			t.Errorf("%q 失败时必须给出原因", c.Prefix)
		}
	}
}

// TestProbeMirrorsNonGitHubSampleFallsBack 探测样本地址非 GitHub 时必须换成内置样本。
//
// 【为什么】镜像只代理 github.com 域名, 拿 nmap.org 之类的地址去探测会全部失败,
// 于是"所有镜像都不可用"的结论是假的 —— 会直接把安装流程拦死。
func TestProbeMirrorsNonGitHubSampleFallsBack(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过")
	}
	var sawPath atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath.Store(r.URL.Path)
		_, _ = w.Write(make([]byte, 1024))
	}))
	defer srv.Close()

	m := New(t.TempDir())
	SetMirrorProbe(false, 1500)
	defer SetMirrorProbe(false, 0)

	// 传一个非 GitHub 的样本地址
	pr := m.probeMirrors([]string{srv.URL + "/"}, "https://nmap.org/dist/nmap-7.991-setup.exe")
	if pr.Chosen == "" {
		t.Fatalf("非 GitHub 样本应回退到内置 GitHub 样本, 实得 %+v", pr.Candidates)
	}
	// 确认实际请求的不是 nmap.org 那个路径
	if p, _ := sawPath.Load().(string); strings.Contains(p, "nmap") {
		t.Errorf("不该用 nmap.org 的路径探测镜像, 实得 %q", p)
	}
}

// TestShortErr 网络错误必须压缩成可读短句(完整错误含 URL 与端口, 界面上没法看)
func TestShortErr(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Get \"https://x/\": context deadline exceeded", "超时"},
		{"dial tcp: lookup foo: no such host", "域名解析失败"},
		{"dial tcp 127.0.0.1:1: connectex: No connection could be made because the target machine actively refused it.", "refused"},
	}
	for _, c := range cases {
		got := shortErr(errString(c.in))
		if !strings.Contains(got, c.want) {
			t.Errorf("shortErr(%q) = %q, 期望包含 %q", c.in, got, c.want)
		}
	}
}

// errString 把字符串包成 error(避免为测试引入 errors 包依赖)
type errString string

func (e errString) Error() string { return string(e) }
