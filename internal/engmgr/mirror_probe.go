package engmgr

// mirror_probe.go 下载前的"镜像可用性探测"。
//
// 【为什么需要它】GitHub 镜像站的可用性变化极快(几周到几个月就换一批), 硬编码
// 一个写死的镜像会造成两种坏结果:
//   - 镜像已死: 用户点了安装, 等 60s 看门狗超时才发现失败, 白等;
//   - 镜像活着但极慢: 比直连还慢, 用户以为"配了镜像应该快", 实际更糟。
// 所以正确顺序是"先探测、再选最快、然后才开始下载", 并把探测结论展示给用户。
//
// 【设计取舍】
//  1. 探测用轻量 HEAD/Range 请求而非完整下载 —— 只取前若干字节判断"通不通 + 快不快";
//  2. 探测有总时长上限(默认 4s/个, 并发进行), 不能让"探测"本身变成新的等待来源;
//  3. 候选镜像由配置提供(engine.json 的 downloads.githubMirror 支持逗号分隔多个),
//     也允许完全关闭探测(单镜像时不必探测, 省一次往返);
//  4. 探测结果只影响"选哪个前缀", 不改写非 GitHub 地址(nmap.org 等拿不到镜像加速)。

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// MirrorCandidate 一个候选镜像的探测结果
type MirrorCandidate struct {
	Prefix string `json:"prefix"` // 镜像前缀(已规范化为以 / 结尾)
	OK     bool   `json:"ok"`
	MS     int64  `json:"ms"`     // 首字节耗时(毫秒); 失败时为 0
	Speed  int64  `json:"speed"`  // 探测窗口内的字节/秒; 失败时为 0
	Error  string `json:"error,omitempty"`
}

// probeResult 是探测的最终结论, 由装配层透出给前端展示"为什么选了这个镜像"
type probeResult struct {
	Candidates []MirrorCandidate
	Chosen     string // 选中使用的前缀(空 = 直连)
}

var (
	probeMu     sync.RWMutex
	lastProbe   *probeResult
	probeForce  bool  // 即使只配了 1 个镜像也强制探测(用户显式要求"先检测再下载")
	probeBudget int64 // 单个候选的探测时长上限(毫秒)
)

// SetMirrorProbe 配置探测行为。
//
// force=true 时即使只有一个镜像也会先探测 —— 用户明确要求"先检测再下载, 不行就
// 停止告知", 这时"探测失败"要能作为终止理由反馈出来, 不能默默直连。
func SetMirrorProbe(force bool, perCandidateMS int64) {
	probeMu.Lock()
	probeForce = force
	if perCandidateMS <= 0 {
		perCandidateMS = 4000
	}
	probeBudget = perCandidateMS
	probeMu.Unlock()
}

// mirrorProbeEnabled 是否需要对给定候选集做探测
func mirrorProbeEnabled(n int) bool {
	probeMu.RLock()
	defer probeMu.RUnlock()
	if n == 0 {
		return false
	}
	// 多候选: 必须探测(否则不知道该用哪个); 单候选: 仅在用户开启 force 时探测
	return n > 1 || probeForce
}

// MirrorProbeSnapshot 返回最近一次探测结果(供 API 展示); 未探测过返回 nil
func MirrorProbeSnapshot() []MirrorCandidate {
	probeMu.RLock()
	defer probeMu.RUnlock()
	if lastProbe == nil {
		return nil
	}
	out := make([]MirrorCandidate, len(lastProbe.Candidates))
	copy(out, lastProbe.Candidates)
	return out
}

// splitMirrors 把配置值拆成候选前缀列表。
//
// 支持逗号/分号/空白分隔的多镜像写法(如 engine.json 里
// "githubMirror": "https://gh-proxy.com/, https://ghfast.top/"), 这样用户可以在
// 配置里写多个备选, 由程序自动挑最快的 —— 比让用户自己测速友好得多。
func splitMirrors(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	var out []string
	seen := map[string]bool{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.HasPrefix(f, "http://") && !strings.HasPrefix(f, "https://") {
			continue // 非法前缀直接丢, 不让它把整批探测带偏
		}
		if !strings.HasSuffix(f, "/") {
			f += "/"
		}
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// ===== 环境变量代理 =====

// envProxyFunc 读取环境变量构造代理函数(HTTP_PROXY / HTTPS_PROXY / NO_PROXY)。
//
// 【为什么不用 http.ProxyFromEnvironment】标准库把首次解析结果缓存在 sync.Once 里
// (Go 1.25 net/http/transport.go 的 envProxyOnce), 没有公开的失效接口:
//   - 用户改了环境变量后, 程序仍用旧值, 看起来"配置没生效"
//   - 测试中改环境变量无法生效(linkname 已被 Go 1.23+ 禁用 pull 引用)
//
// 自行解析可保证"每次请求实时读环境变量", 代理开关立即生效。
//
// 【CI 环境注意】GOPROXY / GONOSUMDB 与本函数无关; 但若系统设了 HTTP_PROXY 指向
// 内网镜像, 引擎下载也会走它 —— 这是期望行为(与 curl/wget 一致)。
func envProxyFunc(log func(string)) func(*http.Request) (*url.URL, error) {
	raw := firstEnv("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
	noProxy := firstEnv("NO_PROXY", "no_proxy")
	return func(req *http.Request) (*url.URL, error) {
		if strings.TrimSpace(raw) == "" {
			return nil, nil // 未设代理 = 直连
		}
		host := req.URL.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil, nil
		}
		if matchNoProxyHost(host, noProxy) {
			return nil, nil
		}
		p := strings.TrimSpace(raw)
		// 缺 scheme 时补 http:// —— 否则 url.Parse 会把 127.0.0.1 当协议, 代理静默失效
		if !strings.Contains(p, "://") {
			p = "http://" + p
		}
		u, err := url.Parse(p)
		if err != nil || u.Host == "" {
			if log != nil {
				log("环境变量代理地址非法, 已回退直连: " + raw)
			}
			return nil, nil
		}
		return u, nil
	}
}

// firstEnv 返回首个非空环境变量的值
func firstEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// matchNoProxyHost 判断 host 是否命中 NO_PROXY(逗号分隔)。
// 支持精确匹配、".example.com"/"example.com" 后缀匹配、"*" 全放行、
// 通配写法(192.168.*)与 CIDR 网段(192.168.0.0/16)。
func matchNoProxyHost(host, noProxy string) bool {
	noProxy = strings.TrimSpace(noProxy)
	if noProxy == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	ip := net.ParseIP(host)
	for _, item := range strings.Split(noProxy, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if item == "*" {
			return true
		}
		if strings.Contains(item, "/") {
			if _, cidr, err := net.ParseCIDR(item); err == nil && ip != nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		item = strings.TrimPrefix(item, ".")
		if strings.HasSuffix(item, ".*") {
			if strings.HasPrefix(host, strings.TrimSuffix(item, "*")) {
				return true
			}
			continue
		}
		if host == item || strings.HasSuffix(host, "."+item) {
			return true
		}
	}
	return false
}

// probeMirrors 并发探测各候选镜像, 返回按"可用优先 + 速度降序 + 延迟升序"排序的结果。
//
// probeURL 是用于探测的**真实 GitHub 资产地址**(不能随便找个 URL: 镜像只代理
// github.com 域名, 拿别的地址探测会全部失败)。
func (m *Manager) probeMirrors(prefixes []string, probeURL string) *probeResult {
	res := &probeResult{}
	if len(prefixes) == 0 {
		probeMu.Lock()
		lastProbe = res
		probeMu.Unlock()
		return res
	}
	probeMu.RLock()
	budget := probeBudget
	probeMu.RUnlock()
	if budget <= 0 {
		budget = 4000
	}

	// 规范化探针地址: 确保它本身是 GitHub 地址(否则镜像前缀拼上去不成立)
	sample := probeURL
	if sample == "" || !isGitHubURL(sample) {
		// 退化为一个几乎不变的官方资产(体积小、长期存在), 仅用于连通性判定
		sample = "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_windows-64bit.zip"
	}

	cands := make([]MirrorCandidate, len(prefixes))
	var wg sync.WaitGroup
	for i, p := range prefixes {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			cands[i] = m.probeOne(p, sample, time.Duration(budget)*time.Millisecond)
		}(i, p)
	}
	wg.Wait()

	sort.SliceStable(cands, func(a, b int) bool {
		if cands[a].OK != cands[b].OK {
			return cands[a].OK // 可用的排前面
		}
		if !cands[a].OK {
			return cands[a].MS < cands[b].MS
		}
		// 都可用: 按探测速度降序; 速度相同看延迟
		if cands[a].Speed != cands[b].Speed {
			return cands[a].Speed > cands[b].Speed
		}
		return cands[a].MS < cands[b].MS
	})

	res.Candidates = cands
	for _, c := range cands {
		if c.OK {
			res.Chosen = c.Prefix
			break
		}
	}

	// 记日志: 用户从控制台就能看懂程序为什么选了这个镜像
	if len(cands) > 0 {
		var parts []string
		for _, c := range cands {
			if c.OK {
				parts = append(parts, fmt.Sprintf("%s %dms %dKB/s", c.Prefix, c.MS, c.Speed/1024))
			} else {
				parts = append(parts, fmt.Sprintf("%s 失败(%s)", c.Prefix, c.Error))
			}
		}
		if res.Chosen != "" {
			m.log("引擎下载: 镜像探测完成, 选用 " + res.Chosen + " [" + strings.Join(parts, "; ") + "]")
		} else {
			m.log("引擎下载: 镜像探测完成, 全部不可用, 将直连 [" + strings.Join(parts, "; ") + "]")
		}
	}

	probeMu.Lock()
	lastProbe = res
	probeMu.Unlock()
	return res
}

// probeOne 探测单个镜像: 取 probeURL 的前 128KB 测速。
//
// 用 Range 请求而不是 HEAD: HEAD 只能证明"能连上", 完全不反映实际吞吐 ——
// 实测有的镜像 HEAD 秒回但下载只有几十 KB/s(中转节点过载), 只看 HEAD 会选错。
// 有些镜像不支持 Range, 此时会返回 200 + 完整内容, 我们读到窗口上限就主动断开,
// 不浪费用户流量。
func (m *Manager) probeOne(prefix, probeURL string, budget time.Duration) MirrorCandidate {
	c := MirrorCandidate{Prefix: prefix}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, prefix+probeURL, nil)
	if err != nil {
		c.Error = "地址非法"
		return c
	}
	req.Header.Set("Range", "bytes=0-131071") // 只取前 128KB
	req.Header.Set("User-Agent", "Yugsight-EngMgr/1.0")

	cli := m.newClient(budget)
	start := time.Now()
	resp, err := cli.Do(req)
	if err != nil {
		c.Error = shortErr(err)
		return c
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		c.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return c
	}

	buf := make([]byte, 32<<10)
	var got int64
	// 到达窗口上限或预算耗尽即停: 探测的目的是"比出快慢", 不需要下完
	const window = 128 << 10
	for got < window {
		if ctx.Err() != nil {
			break
		}
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			got += int64(n)
		}
		if rerr != nil {
			break
		}
	}
	el := time.Since(start)
	c.MS = el.Milliseconds()
	if got <= 0 {
		// 连上了但一个字节都没读到: 判定不可用(比"慢"更糟, 属于黑洞)
		c.Error = "无数据返回"
		return c
	}
	if el > 0 {
		c.Speed = int64(float64(got) / el.Seconds())
	}
	c.OK = true
	return c
}

// shortErr 把底层网络错误压成一行可读文本(完整错误带 URL/端口, 展示给用户太长)
func shortErr(err error) string {
	s := err.Error()
	if strings.Contains(s, "context deadline exceeded") || strings.Contains(s, "Client.Timeout") {
		return "超时"
	}
	if strings.Contains(s, "no such host") {
		return "域名解析失败"
	}
	if strings.Contains(s, "connection refused") {
		return "拒绝连接"
	}
	if strings.Contains(s, "certificate") {
		return "证书错误"
	}
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}

// 保证 io 被使用(Read 的返回语义依赖它)
var _ = io.EOF
