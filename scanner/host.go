package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// TLSCertInfo 获取指定端口 TLS 证书信息
func TLSCertInfo(ip string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		return "", err
	}
	cs := tlsConn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return "", fmt.Errorf("无证书")
	}
	c := cs.PeerCertificates[0]
	selfSigned := c.Subject.String() == c.Issuer.String()
	days := int(time.Until(c.NotAfter).Hours() / 24)
	parts := []string{
		"CN=" + c.Subject.CommonName,
		"颁发者=" + c.Issuer.CommonName,
		fmt.Sprintf("有效期至 %s (剩余 %d 天)", c.NotAfter.Format("2006-01-02"), days),
	}
	if len(c.DNSNames) > 0 {
		parts = append(parts, "SAN="+strings.Join(c.DNSNames, ","))
	}
	if selfSigned {
		parts = append(parts, "自签名证书")
	}
	if days < 0 {
		parts = append(parts, "证书已过期")
	}
	return strings.Join(parts, "; "), nil
}

// tlsCertDetail 返回结构化证书信息, 供主机扫描判定风险
type tlsCertDetail struct {
	CN         string
	Issuer     string
	NotAfter   time.Time
	Days       int
	SelfSigned bool
	DNSNames   []string
	Version    uint16
}

func tlsCertFetch(ip string, port int) (*tlsCertDetail, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 4*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil, fmt.Errorf("无证书")
	}
	c := cs.PeerCertificates[0]
	d := &tlsCertDetail{
		CN:       c.Subject.CommonName,
		Issuer:   c.Issuer.CommonName,
		NotAfter: c.NotAfter,
		Days:     int(time.Until(c.NotAfter).Hours() / 24),
		DNSNames: c.DNSNames,
		Version:  cs.Version,
	}
	d.SelfSigned = c.Subject.String() == c.Issuer.String()
	return d, nil
}

// ===== 主机扫描: 资产识别 / 服务版本 / 配置风险 / 弱口令 / 已知漏洞 =====
//
// 与"端口扫描"的分工:
//   - 端口扫描: 只回答"哪些端口开着" (结果 = 端口清单)
//   - 主机扫描: 回答"这是什么机器 / 跑着什么服务什么版本 / 有哪些配置风险"
//     (结果 = 主机画像 + 风险清单; 关闭端口不展示, 因为无信息量)

// svcProbe 主动探测: 往端口发一段请求, 读取响应以识别服务与版本
type svcProbe struct {
	port  int
	req   string
	decis []struct{ kw, name string } // 按顺序匹配
}

var svcProbes = []svcProbe{
	{port: 80, req: "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
		decis: []struct{ kw, name string }{
			{"nginx", "nginx"}, {"apache", "Apache httpd"}, {"iis", "Microsoft IIS"},
			{"tomcat", "Apache Tomcat"}, {"jetty", "Jetty"}, {"openresty", "OpenResty"},
			{"weblogic", "WebLogic"}, {"cloudflare", "Cloudflare"}, {"httpd", "Apache httpd"},
		}},
	{port: 8080, req: "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
		decis: []struct{ kw, name string }{
			{"nginx", "nginx"}, {"apache", "Apache httpd"}, {"tomcat", "Apache Tomcat"},
			{"jetty", "Jetty"}, {"weblogic", "WebLogic"}, {"spring", "Spring Boot"},
			{"nacos", "Nacos"}, {"jenkins", "Jenkins"}, {"httpd", "Apache httpd"},
		}},
	{port: 443, req: "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
		decis: []struct{ kw, name string }{
			{"nginx", "nginx"}, {"apache", "Apache httpd"}, {"iis", "Microsoft IIS"},
		}},
}

// httpBanner 主动请求 Web 端口, 返回响应头文本(用于识别服务与版本)
func httpBanner(ip string, port int, timeout time.Duration) (string, map[string]string) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip, strconv.Itoa(port))), nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Yugsight/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	hdr := map[string]string{}
	var sb strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			hdr[strings.ToLower(k)] = v
			sb.WriteString(k + ": " + v + "\n")
		}
	}
	return sb.String(), hdr
}

// 从横幅中提取 "组件/版本" 形式(如 nginx/1.18.0、Apache/2.4.41、OpenSSH_8.2p1)
// 用 [A-Za-z0-9_.+-]* 而非 +, 允许前缀存在但在结果中只取最后一段组件名
var bannerVerRe = regexp.MustCompile(`(?i)([A-Za-z0-9_.+-]*?([A-Za-z][A-Za-z0-9]*))\s*[/_]\s*v?(\d+\.\d+(?:\.\d+)?)`)

// versionFromBanner 提取版本号, 返回 "组件 版本" 或空串
//
// 例: "SSH-2.0-OpenSSH_8.2p1 Ubuntu" -> "OpenSSH 8.2"
//     "Server: Microsoft-IIS/10.0"   -> "IIS 10.0"
// 只保留斜杠/下划线前紧邻的那一段组件名(避免把 "SSH-2.0-" 前缀带出来)
func versionFromBanner(banner string) string {
	if m := bannerVerRe.FindStringSubmatch(banner); len(m) >= 4 {
		return m[2] + " " + m[3]
	}
	return ""
}

// 已知高危组件版本库: 匹配到即报"可能存在已知漏洞", 并给出升级建议
type vulnVersionRule struct {
	component   string
	contains    string
	badVersions []string
	severity    string
	advice      string
}

var componentVulnRules = []vulnVersionRule{
	{component: "Apache httpd", contains: "apache", badVersions: []string{"2.4.49", "2.4.50"}, severity: "high",
		advice: "Apache 2.4.49/2.4.50 存在 CVE-2021-41773/CVE-2021-42013 路径穿越 RCE, 请升级到 2.4.51+"},
	{component: "OpenSSH", contains: "openssh", badVersions: []string{"7.2", "7.3", "7.4", "7.5", "7.6", "7.7", "7.8", "7.9", "8.0", "8.1", "8.2", "8.3"},
		severity: "medium", advice: "OpenSSH 8.3 及以下存在 CVE-2020-14145 等信息泄露风险, 建议升级到 9.x"},
	{component: "nginx", contains: "nginx", badVersions: []string{"1.16", "1.18", "1.20"},
		severity: "low", advice: "nginx 老版本存在多个中等风险漏洞, 建议升级到稳定版最新"},
	{component: "Microsoft IIS", contains: "iis", badVersions: []string{"6.0", "7.0", "7.5"},
		severity: "medium", advice: "IIS 6.0/7.0/7.5 已停止支持, 存在多个已知漏洞, 建议升级"},
	{component: "Apache Tomcat", contains: "tomcat", badVersions: []string{"7.", "8.0", "8.5", "9.0.0"},
		severity: "medium", advice: "Tomcat 老版本存在 CVE-2020-1938(AJP 文件包含)等漏洞, 建议升级到最新版"},
	{component: "Redis", contains: "redis", badVersions: nil, severity: "high",
		advice: "Redis 未授权访问是高危风险: 可写文件提权/写 SSH key。请设置 requirepass、bind 内网、禁止外网暴露"},
	{component: "MySQL", contains: "mysql", badVersions: nil, severity: "medium",
		advice: "建议确认 root 是否允许远程登录、是否存在弱口令, 并限制来源 IP"},
	{component: "MongoDB", contains: "mongodb", badVersions: nil, severity: "high",
		advice: "MongoDB 未授权访问可导致全库泄露, 请启用认证(authorization: enabled)并限制访问来源"},
	{component: "Elasticsearch", contains: "elasticsearch", badVersions: nil, severity: "high",
		advice: "Elasticsearch 未授权访问可导致数据泄露, 请启用 X-Pack 安全认证并限制访问来源"},
	{component: "phpMyAdmin", contains: "phpmyadmin", badVersions: nil, severity: "medium",
		advice: "管理后台暴露在公网风险较高, 建议限制访问来源并加强口令"},
	{component: "Jenkins", contains: "jenkins", badVersions: nil, severity: "high",
		advice: "Jenkins 未授权访问可执行任意命令(脚本控制台), 请启用认证并限制访问来源"},
	{component: "Docker API", contains: "docker", badVersions: nil, severity: "high",
		advice: "Docker 2375 端口暴露等于主机 root 权限, 请改用 TLS 加密端口 2376"},
	{component: "rsync", contains: "rsync", badVersions: nil, severity: "medium",
		advice: "rsync 未授权可读写同步目录, 请配置 auth users / secrets file"},
	{component: "SMB", contains: "microsoft-ds", badVersions: nil, severity: "medium",
		advice: "SMB 445 暴露请确认已修补 MS17-010(永恒之蓝), 并禁用 SMBv1"},
	{component: "RDP", contains: "ms-wbt-server", badVersions: nil, severity: "medium",
		advice: "RDP 3389 暴露存在爆破与 BlueKeep(CVE-2019-0708)风险, 建议启用 NLA 并限制来源"},
}

// serviceRisk 按端口/服务名给出配置风险提示(与版本无关的通用风险)
type serviceRisk struct {
	port     int
	severity string
	title    string
	detail   string
}

var serviceRisks = []serviceRisk{
	{23, "high", "Telnet 服务开放", "Telnet 明文传输账号口令, 建议改为 SSH"},
	{21, "medium", "FTP 服务开放", "FTP 明文传输凭据; 确认是否允许匿名登录, 建议改用 SFTP"},
	{135, "medium", "MSRPC 端口开放", "135 常被用于横向移动与信息收集, 建议防火墙限制来源"},
	{137, "low", "NetBIOS 名称服务开放", "可能泄露主机名/域信息, 非必要时关闭"},
	{139, "medium", "NetBIOS 会话服务开放", "建议禁用并仅保留 445(并确保已修补 MS17-010)"},
	{445, "high", "SMB 文件共享开放", "SMB 是勒索病毒主要入口, 请确认已修补 MS17-010 且禁用 SMBv1"},
	{1433, "high", "MSSQL 数据库端口开放", "数据库不应直接对外; 请限制来源并检查 sa 弱口令"},
	{3306, "high", "MySQL 数据库端口开放", "数据库不应直接对外; 请限制来源并检查 root 弱口令"},
	{5432, "high", "PostgreSQL 端口开放", "请确认 pg_hba.conf 未对 0.0.0.0/0 开放 trust"},
	{6379, "high", "Redis 端口开放", "Redis 未授权访问可导致服务器被控, 请设置密码并限制来源"},
	{27017, "high", "MongoDB 端口开放", "请确认已启用认证, 否则全库数据可被直接读取"},
	{9200, "high", "Elasticsearch 端口开放", "请确认已开启安全认证, 否则索引数据可被直接读取"},
	{2375, "high", "Docker 未加密 API 开放", "等同于把主机 root 权限暴露到网络, 请立即关闭或改 2376+TLS"},
	{5900, "medium", "VNC 远程桌面开放", "VNC 口令易被爆破且默认无加密, 建议改用 RDP/SSH 隧道"},
	{11211, "high", "Memcached 端口开放", "未授权访问可被用于反射放大攻击, 请限制来源并绑定内网"},
	{5000, "low", "UPnP/HTTP-Alt 服务开放", "确认是否为调试服务误暴露"},
	{7001, "high", "WebLogic 端口开放", "WebLogic 历史反序列化漏洞较多, 请确认版本已升级并限制访问"},
	{3389, "medium", "RDP 远程桌面开放", "存在爆破风险, 建议启用 NLA、限制来源并配置账户锁定"},
}

// guessOS 根据横幅/开放端口推断操作系统
func guessOS(banners []string, openPorts []int) (os string, confidence string) {
	joined := strings.ToLower(strings.Join(banners, " "))
	switch {
	case strings.Contains(joined, "iis") || strings.Contains(joined, "microsoft") ||
		strings.Contains(joined, "windows"):
		return "Windows", "高"
	case strings.Contains(joined, "ubuntu"):
		return "Linux (Ubuntu)", "高"
	case strings.Contains(joined, "centos"):
		return "Linux (CentOS)", "高"
	case strings.Contains(joined, "debian"):
		return "Linux (Debian)", "高"
	case strings.Contains(joined, "red hat") || strings.Contains(joined, "redhat"):
		return "Linux (RedHat)", "高"
	case strings.Contains(joined, "openssh"):
		return "Linux / Unix (OpenSSH)", "中"
	case strings.Contains(joined, "freebsd"):
		return "FreeBSD", "高"
	}
	// 端口特征兜底: 135/139/445/3389 是 Windows 强特征; 22 无 445 多为 Linux
	winSignals := 0
	for _, p := range openPorts {
		if p == 135 || p == 139 || p == 445 || p == 3389 || p == 5985 {
			winSignals++
		}
	}
	if winSignals >= 2 {
		return "Windows", "中"
	}
	if containsInt(openPorts, 22) && !containsInt(openPorts, 445) {
		return "Linux / Unix", "低"
	}
	return "未知", "低"
}

// IsWebPort 判断是否为常见 Web 服务端口(主动探测 / 模板执行适用)
func IsWebPort(p int) bool {
	switch p {
	case 80, 443, 8080, 8443, 8000, 8888, 9000, 3000:
		return true
	}
	return false
}

// HostScan 主机综合扫描: 存活探测 -> 服务识别 -> 版本比对 -> 配置风险 -> 弱口令线索
// 只展示"有发现"的项目: 关闭端口不输出(无信息量), 空结果明确说明。
// 返回值: 开放端口的服务资产指纹(产品+版本), 供下游(nuclei 模板执行等)直接使用,
// 流水线无需重复端口探测; 无开放端口时返回 nil。
//
// ctx 贯穿到内部 ScanPorts 的端口拨号: 任务取消时端口探测可被快速终止(见 ScanPorts)。
func HostScan(ctx context.Context, ip string, ports []int, timeout time.Duration, concurrency int, emit Emit) []ServiceAsset {
	emit("status", map[string]any{"msg": fmt.Sprintf("开始主机扫描 %s (探测 %d 个端口)", ip, len(ports))})

	// ---- 1. 基础身份 ----
	ptrName := "无记录"
	if ptrs, err := net.LookupAddr(ip); err == nil && len(ptrs) > 0 {
		ptrName = strings.Join(ptrs, ", ")
		emit("info", map[string]any{"key": "主机名 (反向 DNS)", "value": ptrName})
	}
	// NetBIOS/SMB 名称(Windows 环境可拿到计算机名); 同一次握手顺带验证 SMBv1 是否启用
	smb1 := false
	if containsInt(ports, 445) {
		name, s1 := smbProbe(ip, 2*time.Second)
		if name != "" {
			emit("info", map[string]any{"key": "计算机名 (SMB)", "value": name})
		}
		smb1 = s1
	}

	// ---- 2. 端口与服务识别(仅保留开放端口) ----
	//
	// 注意: 这里必须用"静默 emit"调 ScanPorts —— 端口逐条上报是端口扫描的职责,
	// 若透传出去, 主机扫描的表(级别/主机服务/风险依据)会混入端口行导致错位。
	results := ScanPorts(ctx, ip, ports, timeout, concurrency, func(kind string, data any) {
		if kind == "status" {
			emit(kind, data) // 只放行进度, 便于界面显示"正在探测 x/y"
		}
	})
	var openPorts []int
	svcByPort := map[int]string{}
	bannerByPort := map[int]string{}
	var banners []string
	for _, r := range results {
		if r.State != "open" {
			continue
		}
		openPorts = append(openPorts, r.Port)
		svcByPort[r.Port] = r.Service
		if r.Banner != "" {
			bannerByPort[r.Port] = r.Banner
			banners = append(banners, r.Banner)
		}
	}
	sort.Ints(openPorts)

	if len(openPorts) == 0 {
		emit("finding", NewFinding("info", "未发现开放端口",
			fmt.Sprintf("探测的 %d 个端口均未开放, 无法识别系统与服务(可扩大端口范围重试)", len(ports)), ""))
		emit("status", map[string]any{"msg": "主机扫描完成: 无开放端口"})
		return nil
	}

	// ---- 3. Web 端口主动探测(拿 Server 头, 比被动横幅更准) ----
	webPorts := []int{}
	for _, p := range openPorts {
		if IsWebPort(p) {
			webPorts = append(webPorts, p)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range webPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if hdr, _ := httpBanner(ip, p, timeout); hdr != "" {
				mu.Lock()
				bannerByPort[p] = strings.TrimSpace(hdr)
				banners = append(banners, hdr)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	// ---- 3.5 服务资产输出: 端口 + 服务 + 版本指纹 ----
	//
	// 复用本次扫描的识别结果(含 Web 端口主动探测到的 Server 头), 供下游
	// (nuclei 模板执行等) 直接消费, 流水线不必再跑一遍端口扫描。
	var assetProbes []PortResult
	for _, p := range openPorts {
		assetProbes = append(assetProbes, PortResult{
			IP: ip, Port: p, State: "open",
			Service: svcByPort[p], Banner: bannerByPort[p],
		})
	}
	assets := BuildServiceAssets(ip, assetProbes)

	// ---- 4. 系统推断 ----
	osName, conf := guessOS(banners, openPorts)
	emit("info", map[string]any{"key": "操作系统推断", "value": fmt.Sprintf("%s (置信度: %s)", osName, conf)})

	// 服务清单(带版本)
	var svcList []string
	for _, p := range openPorts {
		name := svcByPort[p]
		if name == "" {
			name = "未知服务"
		}
		ver := versionFromBanner(bannerByPort[p])
		if ver != "" {
			svcList = append(svcList, fmt.Sprintf("%d/%s %s", p, name, ver))
		} else {
			svcList = append(svcList, fmt.Sprintf("%d/%s", p, name))
		}
	}
	emit("info", map[string]any{"key": fmt.Sprintf("开放服务 (%d)", len(openPorts)), "value": strings.Join(svcList, ", ")})

	// ---- 5. TLS 证书风险 ----
	for _, p := range openPorts {
		if !(p == 443 || p == 8443 || p == 993 || p == 995 || p == 465) {
			continue
		}
		d, err := tlsCertFetch(ip, p)
		if err != nil {
			continue
		}
		info := fmt.Sprintf("CN=%s, 颁发者=%s, 有效期至 %s (剩余 %d 天)",
			d.CN, d.Issuer, d.NotAfter.Format("2006-01-02"), d.Days)
		if len(d.DNSNames) > 0 {
			info += ", SAN=" + strings.Join(d.DNSNames, ",")
		}
		emit("info", map[string]any{"key": fmt.Sprintf("TLS 证书 (端口 %d)", p), "value": info})
		switch {
		case d.Days < 0:
			emit("finding", NewFinding("high", fmt.Sprintf("端口 %d TLS 证书已过期", p),
				fmt.Sprintf("证书 %s 已于 %s 过期, 会导致客户端告警, 请立即续签", d.CN, d.NotAfter.Format("2006-01-02")), fixTLSExpired))
		case d.Days < 30:
			emit("finding", NewFinding("medium", fmt.Sprintf("端口 %d TLS 证书即将过期", p),
				fmt.Sprintf("剩余 %d 天, 请及时续签", d.Days), fixTLSExpired))
		case d.SelfSigned:
			emit("finding", NewFinding("medium", fmt.Sprintf("端口 %d 使用自签名证书", p),
				"自签名证书无法被浏览器信任, 且易被中间人替换; 建议改用受信 CA 证书", fixTLSSelfSigned))
		}
		if d.Version < tls.VersionTLS12 {
			emit("finding", NewFinding("medium", fmt.Sprintf("端口 %d TLS 协议版本过低", p),
				"协商版本低于 TLS 1.2, 存在已知攻击面, 建议禁用 TLS 1.0/1.1", fixTLSOldVersion))
		}
	}

	// ---- 6. 服务配置风险(按端口) ----
	for _, sr := range serviceRisks {
		if containsInt(openPorts, sr.port) {
			emit("finding", NewFinding(sr.severity, sr.title, sr.detail, FixFor(sr.title+" "+sr.detail)))
		}
	}

	// ---- 7. 组件版本已知漏洞比对(粗规则) + CPE 字典版本匹配(精确: 具体 CVE + CVSS) ----
	allText := strings.ToLower(strings.Join(banners, " ") + " " + strings.Join(svcList, " "))
	//
	// CPE 命中优先: 已报出具体 CVE 的产品, 压制其粗粒度"可能存在已知漏洞"提示, 避免重复报。
	cpeHitProducts := map[string]bool{}
	cpeEmitted := map[string]bool{}
	for _, a := range assets {
		if a.Version == "" {
			continue
		}
		for _, m := range MatchCPE(a.Product, a.Version) {
			cpeHitProducts[m.Product] = true
			for _, f := range m.Findings() {
				if cpeEmitted[f.Title] {
					continue // 同产品+版本+CVE 只报一次(多端口暴露时去重)
				}
				cpeEmitted[f.Title] = true
				emit("finding", f)
			}
		}
	}
	for _, vr := range componentVulnRules {
		if cpeHitProducts[vr.contains] {
			continue // CPE 已报具体 CVE
		}
		if !strings.Contains(allText, vr.contains) {
			// 端口特征兜底(如 445 = SMB)
			continue
		}
		if len(vr.badVersions) > 0 {
			hit := false
			for _, bv := range vr.badVersions {
				if strings.Contains(allText, bv) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		fix := FixFor(vr.component + " " + vr.advice)
		if fix == "" {
			fix = fixCVEUpgrade
		}
		emit("finding", NewFinding(vr.severity, "组件可能存在已知漏洞: "+vr.component, vr.advice, fix))
	}

	// ---- 7.5 EOL(停止支持)检测: "不再出补丁"这一类风险 ----
	//
	// CPE 版本匹配只覆盖"已披露的 CVE"; 而停补意味着"未来所有漏洞都没有补丁"。
	// 用户诉求(2026-09-20): "补丁没打也能扫吗" —— 网络侧对"漏扫"的完整回答就是
	// 版本匹配 + EOL 判定 + 已验证配置风险, 三段互补。
	eolEmitted := map[string]bool{}
	emitEOL := func(label, note string, high bool) {
		if eolEmitted[label] {
			return
		}
		eolEmitted[label] = true
		sev := "medium"
		if high {
			sev = "high"
		}
		emit("finding", NewFinding(sev, "已停止支持(不再发布安全补丁): "+label, note, fixEOLUpgrade))
	}
	// IIS 版本与 Windows 版本一一对应, 是"操作系统停补"最可靠的网络侧证据
	// (IIS 版本只有两段 "10.0", 走不了 versionFromBanner, 从原始 banner 单独提取)
	if iv := iisVersionFromBanners(banners); iv != "" {
		if e := matchEOL("iis", iv); e != nil {
			emitEOL(e.Label, e.Note, e.High)
		}
	}
	for _, a := range assets {
		if a.Version == "" {
			continue
		}
		if e := matchEOL(a.Product, a.Version); e != nil {
			emitEOL(e.Label, e.Note, e.High)
		}
	}

	// ---- 7.6 主动验证型探测(已验证: 探测确认, 不是推断) ----
	if smb1 {
		emit("finding", NewFinding("high", "SMBv1 协议启用(已验证)",
			"SMB 协议协商接受了 SMBv1 (NT LM 0.12) 方言。SMBv1 无加密无完整性保护, 是永恒之蓝 (CVE-2017-0144) / 永恒浪漫 (CVE-2017-0145) 等勒索蠕虫的主要攻击面, 请禁用 SMBv1",
			fixSMBv1))
	}
	if containsInt(openPorts, 21) && ftpAnonymous(ip, timeout) {
		emit("finding", NewFinding("high", "FTP 允许匿名登录(已验证)",
			"USER anonymous / PASS 匿名 收到 230 成功应答。匿名账号可读写 FTP 目录, 常被用于泄露敏感文件或植入 Webshell; 请禁用匿名登录并限制 21 端口来源",
			fixFTPAnon))
	}
	if containsInt(openPorts, 11211) {
		// 主动取版本(version 命令, 只读) -> CVE 版本匹配: 比端口开放告警更精确
		if v := memcachedVersion(ip, timeout); v != "" {
			for _, m := range MatchCPE("memcached", v) {
				for _, f := range m.Findings() {
					emit("finding", f)
				}
			}
		}
	}
	// Redis 未授权直接验证(能 ping 通说明未设密码); 未授权时顺带取版本做 CVE 匹配
	if containsInt(openPorts, 6379) {
		if unauth, ver := redisUnauthInfo(ip, timeout); unauth {
			detail := "向 6379 发送 PING 得到 PONG, 说明未设置密码。攻击者可写文件提权/写 SSH key 直接控制主机, 请立即设置 requirepass 并限制来源"
			if ver != "" {
				detail = "Redis " + ver + " 未授权访问已验证(PING->PONG, 并经 INFO 读取版本)。" + detail
				for _, m := range MatchCPE("redis", ver) {
					for _, f := range m.Findings() {
						emit("finding", f)
					}
				}
			}
			emit("finding", NewFinding("high", "Redis 未授权访问(已验证)", detail, fixRedisUnauth))
		}
	}
	// MySQL 匿名/弱口令线索(仅探测是否允许 root 空密码握手)
	if containsInt(openPorts, 3306) {
		emit("finding", NewFinding("medium", "MySQL 暴露: 建议核查弱口令",
			"3306 对外开放, 请确认 root 未使用弱口令、未允许 % 远程登录", fixMySQLWeak))
	}

	// ---- 8. 汇总 ----
	emit("info", map[string]any{"key": "主机画像",
		"value": fmt.Sprintf("%s | 主机名: %s | 操作系统: %s | 开放端口 %d 个",
			ip, strings.TrimSuffix(ptrName, "."), osName, len(openPorts))})
	emit("status", map[string]any{"msg": fmt.Sprintf("主机扫描完成: 开放 %d 个端口, 已输出风险清单", len(openPorts))})
	return assets
}

// (redisUnauthorized / smbComputerName 已移至 host_extra.go: 分别升级为
//  redisUnauthInfo(未授权+版本) 与 smbProbe(计算机名+SMBv1 验证))

// extractSMBName 从 SMB 协商响应里粗提取可打印主机名
func extractSMBName(b []byte) string {
	// SMB1 negotiate response 的 ServerName 为 ASCII, 位于固定偏移附近;
	// 这里用启发式: 找连续 2-15 个字母数字/连字符且含大写字母的串
	var best string
	cur := make([]byte, 0, 16)
	flush := func() {
		if len(cur) >= 3 && len(cur) <= 15 {
			s := string(cur)
			upper := 0
			ok := true
			for _, c := range s {
				switch {
				case c >= 'A' && c <= 'Z':
					upper++
				case c >= '0' && c <= '9', c == '-', c == '_':
				case c >= 'a' && c <= 'z':
				default:
					ok = false
				}
			}
			if ok && upper > 0 && len(s) > len(best) {
				best = s
			}
		}
		cur = cur[:0]
	}
	for _, c := range b {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			cur = append(cur, c)
		} else {
			flush()
		}
	}
	flush()
	// 过滤协议关键字
	switch strings.ToUpper(best) {
	case "SMB", "LANMAN", "NT", "LM", "PC", "":
		return ""
	}
	return best
}
