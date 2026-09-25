package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"yugsight/internal/normalizer"
	"yugsight/internal/scanner"
)

// insecureTLSConfig TLS 配置: 内网设备普遍使用自签名证书,
// 探针的目的是识别服务与风险, 不能因证书不可信而放弃探测。
func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// ===== 目标解析 / 网络小工具 =====

// dialTCP 建立 TCP 连接(带超时)。
func dialTCP(host string, port int, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	return net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
}

// msToDuration 毫秒转 Duration(参数解析用)。
func msToDuration(ms int) time.Duration {
	if ms <= 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}

// atoiSafe 宽松整数解析(仅接受十进制, 拒绝 "+/-/空格" 等宽松输入)。
func atoiSafe(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("空值")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("非法数字: %s", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// scannerParseHosts scanner 包的主机解析(CIDR / 单 IP / 范围 / 逗号列表,
// 上限 4096 个), 单独包一层便于本包统一错误信息口径。
func scannerParseHosts(s string) ([]string, error) {
	return scanner.ParseHosts(s)
}

// ParseTargetHost 从目标串里剥离 scheme 前缀并取主机(含端口)。
//
// 两阶段顺序不可调换: 先剥 scheme 前缀(http://|https://|image:|fs:), 再切首段路径,
// 否则 http://a:8080/x 会被切成 "http:"。剥掉前缀后首字符可能是分隔符("fs:/app" -> "/app"),
// 因此先跳过开头分隔符再取首段。
func ParseTargetHost(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"http://", "https://", "image:", "fs:"} {
		if strings.HasPrefix(strings.ToLower(s), p) {
			s = s[len(p):]
			break
		}
	}
	s = strings.TrimLeft(s, "/\\")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// ExpandTargets 把目标展开为 IP 列表:
// 支持 CIDR / 单 IP / a.b.c.d-e.f.g.h / a.b.c.d-x / 逗号列表。
//
// 上限 4096 个目标(与 scanner.ParseHosts 一致): 探针跑在远端机器上,
// 一次性下发过大网段会长时间占住探针且难以取消, 因此宁可拒绝也不静默扩大范围。
func ExpandTargets(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("空目标")
	}
	if list, err := scannerParseHosts(s); err == nil && len(list) > 0 {
		return list, nil
	}
	return nil, fmt.Errorf("无法识别的目标: %s", s)
}

// tcpTimeout 归一化超时(供内部使用)。
func tcpTimeout(t time.Duration) time.Duration {
	if t <= 0 {
		return 1200 * time.Millisecond
	}
	return t
}

// ===== HTTP / 版本指纹 =====

// probeHTTP 对 Web 端口发一次 HEAD/GET 请求, 返回响应头文本
// (用于识别 Server 头里的产品与版本, 比被动横幅更准确)。
func probeHTTP(ip string, port int, timeout time.Duration) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: tcpTimeout(timeout),
		Transport: &http.Transport{
			DisableKeepAlives: true,
			// 自签名证书在内网极常见, 不能因此判定"端口不开"
			TLSClientConfig: insecureTLSConfig(),
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip, strconv.Itoa(port))), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Yugsight/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var sb strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			sb.WriteString(k + ": " + v + "\n")
		}
	}
	return truncate(sb.String(), 800)
}

// bannerVerRe 从横幅中提取 "组件/版本" 或 "组件 版本"。
//
// 例: "SSH-2.0-OpenSSH_8.2p1 Ubuntu" -> "OpenSSH 8.2"
//
//	"Server: nginx/1.18.0"           -> "nginx 1.18.0"
var bannerVerRe = regexp.MustCompile(`(?i)([A-Za-z0-9_.+-]*?([A-Za-z][A-Za-z0-9]*))\s*[/_]\s*v?(\d+\.\d+(?:\.\d+)?)`)

// versionOf 提取 "组件 版本"(无匹配返回空串)。
func versionOf(banner string) string {
	if m := bannerVerRe.FindStringSubmatch(banner); len(m) >= 4 {
		return m[2] + " " + m[3]
	}
	return ""
}

// ===== 报告构造 =====

// newProbeVuln 构造一条探针漏洞(统一填充 foundAt 与置信度默认值)。
//
// 置信度口径(与 models.Vuln.Confidence 一致): 主动验证(有请求+响应)高,
// 仅有横幅证据居中, 纯端口暴露提示较低 —— 中心端归一化时会据此排序。
func newProbeVuln(ip string, port int, severity, title, detail, evidence, reqResp string) normalizer.ProbeVuln {
	conf := 40
	switch {
	case reqResp != "":
		conf = 85
	case strings.TrimSpace(evidence) != "":
		conf = 70
	}
	v := normalizer.ProbeVuln{
		IP:          ip,
		Port:        port,
		Protocol:    protocolOf(port),
		Title:       title,
		Severity:    severity,
		Description: detail,
		Evidence:    truncate(evidence, 2000),
		Confidence:  conf,
		FoundAt:     time.Now(),
	}
	if reqResp != "" {
		v.Request = reqResp
	}
	return v
}

// protocolOf 按端口推断协议名(tcp 为主, 部分端口按 udp 语义标注)。
func protocolOf(port int) string {
	switch port {
	case 161, 53, 123, 69, 514:
		return "udp"
	case 443, 8443, 993, 995, 465:
		return "https"
	case 80, 8080, 8000, 8888, 3000, 9000:
		return "http"
	}
	return "tcp"
}

// vulnKey 漏洞去重键: 与 models.Vuln.MergeKey 同口径
// (同资产 + 同 CVE; 无 CVE 退化为 资产|协议:端口|标题)。
func vulnKey(v normalizer.ProbeVuln) string {
	ip := strings.TrimSpace(v.IP)
	if cve := strings.ToUpper(strings.TrimSpace(v.CVE)); cve != "" {
		return ip + "|" + cve
	}
	return ip + "|" + strings.ToLower(strings.TrimSpace(v.Protocol)) + ":" +
		strconv.Itoa(v.Port) + "|" + strings.TrimSpace(v.Title)
}

// ipLess IP 比较(数字段序, 非 IP 退化为字典序)。
func ipLess(a, b string) bool {
	ia, errA := netip.ParseAddr(a)
	ib, errB := netip.ParseAddr(b)
	switch {
	case errA == nil && errB == nil:
		return ia.Compare(ib) < 0
	case errA == nil:
		return true
	case errB == nil:
		return false
	default:
		return a < b
	}
}

// normalizerProbeAsset 构造一个仅带 IP 的探针资产(后续按需补字段)。
func normalizerProbeAsset(ip string) normalizer.ProbeAsset {
	return normalizer.ProbeAsset{IP: ip}
}

// ===== 外部命令执行(共用) =====

// runCmd 执行外部命令并返回合并输出(带超时与取消)。
//
// 供外部引擎增强扫描(nmapcore/trivycore)复用; 单点实现保证超时/取消语义一致。
func runCmd(ctx context.Context, timeout time.Duration, bin string, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := execCommandContext(cctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if cctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("命令执行超时(%s): %s", timeout, bin)
	}
	if ctx.Err() != nil {
		return out, ErrCanceled
	}
	if err != nil {
		return out, fmt.Errorf("命令执行失败(%s): %w", bin, err)
	}
	return out, nil
}
