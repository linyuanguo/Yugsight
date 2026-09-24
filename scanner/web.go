package scanner

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Finding 漏洞/风险发现
type Finding struct {
	Severity string `json:"severity"` // high / medium / low / info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	// Fix 内置修复建议(可空): 扫描不只报"有问题", 还要回答"怎么处理"。
	// 由 FixFor 或具体常量给出, 前端与报告在非空时展示"修复建议"列。
	Fix string `json:"fix,omitempty"`
}

// NewFinding 构造一条发现。fix 传内置修复建议(无则传 "" 或 FixFor 的结果)。
// 统一用构造函数是因为字段增多后, 位置字面量 Finding{"low", t, d} 会因缺字段编译失败。
func NewFinding(sev, title, detail, fix string) Finding {
	return Finding{Severity: sev, Title: title, Detail: detail, Fix: fix}
}

func randomHex(n int) string {
	b := make([]byte, n/2+1)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func normalizeURL(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("URL 不能为空")
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("无效的 URL: %s", s)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("仅支持 http/https 协议")
	}
	return u, nil
}

// pathTarget 敏感路径探测目标
type pathTarget struct {
	path string
	sev  string
	desc string
}

var sensitivePaths = []pathTarget{
	{"/robots.txt", "info", "robots.txt 可访问"},
	{"/.git/HEAD", "high", ".git 目录暴露(可能泄露全部源码)"},
	{"/.svn/entries", "high", ".svn 目录暴露"},
	{"/.env", "high", ".env 配置文件暴露(可能含密钥/凭据)"},
	{"/.aws/credentials", "high", "AWS 凭据文件暴露"},
	{"/.DS_Store", "medium", ".DS_Store 文件暴露(泄露目录结构)"},
	{"/web.config", "low", "web.config 可访问(IIS 配置)"},
	{"/server-status", "high", "Apache server-status 可访问"},
	{"/server-info", "high", "Apache server-info 可访问"},
	{"/wp-login.php", "low", "WordPress 登录页存在"},
	{"/administrator/", "low", "WordPress 管理后台存在"},
	{"/phpmyadmin/", "medium", "phpMyAdmin 管理界面存在"},
	{"/admin/", "low", "疑似管理后台路径"},
	{"/manager/html", "medium", "Tomcat Manager 管理界面存在"},
	{"/jenkins/", "medium", "Jenkins 持续集成系统存在"},
	{"/grafana/", "medium", "Grafana 监控面板存在"},
	{"/kibana/", "medium", "Kibana 分析界面存在"},
	{"/nacos/", "medium", "Nacos 配置中心存在"},
	{"/actuator", "medium", "Spring Boot Actuator 端点存在"},
	{"/actuator/env", "high", "Spring Actuator env 端点(可能泄露配置)"},
	{"/swagger-ui.html", "medium", "Swagger 接口文档暴露"},
	{"/api-docs", "medium", "Swagger api-docs 暴露"},
	{"/openapi.json", "medium", "OpenAPI 接口文档暴露"},
	{"/v2/api-docs", "medium", "Swagger v2 接口文档暴露"},
	{"/.gitignore", "info", ".gitignore 可访问"},
	{"/backup.zip", "medium", "疑似备份文件"},
	{"/site.zip", "medium", "疑似站点备份"},
	{"/web.zip", "medium", "疑似站点备份"},
	{"/db.sql", "high", "疑似数据库备份文件"},
	{"/dump.sql", "high", "疑似数据库备份文件"},
	{"/database.sql", "high", "疑似数据库备份文件"},
	{"/info.php", "medium", "PHP info 页面(泄露运行环境)"},
	{"/phpinfo.php", "medium", "PHP info 页面(泄露运行环境)"},
	{"/test.php", "low", "测试文件存在"},
	{"/cgi-bin/", "low", "cgi-bin 目录可访问"},
	{"/solr/", "medium", "Solr 管理界面存在"},
}

var sqliSignatures = []string{
	"sql syntax", "syntax error", "unclosed quotation", "mysql_fetch",
	"ORA-", "SQLSTATE", "PostgreSQL", "unterminated quoted", "you have an error in your sql",
}

// WebScan 基于 URL 的 Web 漏洞扫描。
//
// ruleFilter 为本次扫描启用的漏洞库规则 ID 集合, 仅约束"漏洞库正则规则"(body/header
// 匹配 + path 路径规则):
//   - nil    = 启用全部规则(与旧行为一致, 向后兼容);
//   - 非 nil = 只启用集合内列出的规则(空集 = 不启用任何漏洞库规则)。
//
// 敏感路径清单(sensitivePaths)、安全响应头、Cookie、TLS、注入与路径穿越等"基线探测"
// 不属于漏洞库规则, 不受 ruleFilter 影响 —— 即使用户只勾选了一条规则, 这些基线探测仍
// 照常执行, 避免"选了规则就丢了基线能力"。
func WebScan(rawURL string, emit Emit, ruleFilter map[string]bool) {
	u, err := normalizeURL(rawURL)
	if err != nil {
		emit("status", map[string]any{"msg": "URL 无效: " + err.Error()})
		emit("done", map[string]any{"msg": "扫描终止"})
		return
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	emit("status", map[string]any{"msg": "目标: " + u.String()})

	// 1. 基础请求
	resp, err := client.Get(u.String())
	if err != nil {
		emit("status", map[string]any{"msg": "请求失败: " + err.Error()})
		emit("done", map[string]any{"msg": "扫描终止"})
		return
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	body := string(bodyBytes)

	emit("info", map[string]any{"key": "HTTP 状态", "value": resp.Status})
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.String() != u.String() {
		emit("info", map[string]any{"key": "重定向至", "value": resp.Request.URL.String()})
	}
	if s := resp.Header.Get("Server"); s != "" {
		emit("info", map[string]any{"key": "Server", "value": s})
		if regexp.MustCompile(`\d+\.\d+`).MatchString(s) {
			emit("finding", NewFinding("low", "Server 版本泄露", fmt.Sprintf("响应头暴露具体版本: %s", s), fixHideVersion))
		}
	}
	if v := resp.Header.Get("X-Powered-By"); v != "" {
		emit("finding", NewFinding("low", "X-Powered-By 泄露技术栈", "响应头暴露: "+v, fixHidePoweredBy))
	}

	// 1.5 漏洞库规则匹配 (body / header 类型)
	var headerBuf strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			headerBuf.WriteString(k)
			headerBuf.WriteString(": ")
			headerBuf.WriteString(v)
			headerBuf.WriteString("\n")
		}
	}
	if hits := MatchRulesFiltered(body, headerBuf.String(), ruleFilter); len(hits) > 0 {
		emit("status", map[string]any{"msg": fmt.Sprintf("漏洞库命中 %d 条规则", len(hits))})
		for _, r := range hits {
			// 建议优先按规则名/详情匹配, 匹配不到用通用处置建议(不能留空, 否则用户不知如何下手)
			fix := FixFor(r.Name + " " + r.Detail)
			if fix == "" {
				fix = fixGenericVuln
			}
			emit("finding", NewFinding(r.Severity, "["+r.ID+"] "+r.Name, r.Detail, fix))
		}
	}

	// 2. 安全响应头
	//
	// 这些响应头属于"加固建议"而非漏洞本身: 任何网站都不会全配齐,
	// 逐个报"低危"会让报告全是噪音(扫百度就有十几条)。
	// 处理: 缺失的合并为 1 条"信息"级提示并列全清单;
	//       已设置的仍单列到基本信息里, 便于核对。
	// HSTS 仅在 https 下有意义, http 站点不报。
	securityHeaders := []struct{ name, header string }{
		{"HSTS 头 (Strict-Transport-Security)", "Strict-Transport-Security"},
		{"CSP 内容安全策略 (Content-Security-Policy)", "Content-Security-Policy"},
		{"X-Frame-Options", "X-Frame-Options"},
		{"X-Content-Type-Options", "X-Content-Type-Options"},
		{"Referrer-Policy", "Referrer-Policy"},
		{"Permissions-Policy", "Permissions-Policy"},
	}
	var missingHeaders []string
	for _, c := range securityHeaders {
		if v := resp.Header.Get(c.header); v == "" {
			if c.header == "Strict-Transport-Security" && u.Scheme != "https" {
				continue // http 站点无 HSTS 是正常的
			}
			missingHeaders = append(missingHeaders, c.header)
		} else {
			emit("info", map[string]any{"key": c.name, "value": v})
		}
	}
	if len(missingHeaders) > 0 {
		emit("finding", NewFinding("info", "安全响应头缺失 (加固建议)",
			"未设置: "+strings.Join(missingHeaders, ", ")+
				" —— 属于安全加固建议, 非可直接利用的漏洞; 建议按需配置以降低点击劫持/中间人风险",
			fixSecurityHeaders))
	}

	// 3. Cookie 安全(同样合并, 避免每个 Cookie 各报一条)
	var insecureCookies, notHTTPOnly []string
	for _, c := range resp.Cookies() {
		if !c.Secure && u.Scheme == "https" {
			insecureCookies = append(insecureCookies, c.Name)
		}
		if !c.HttpOnly {
			notHTTPOnly = append(notHTTPOnly, c.Name)
		}
	}
	if len(insecureCookies) > 0 {
		emit("finding", NewFinding("medium", "Cookie 未设置 Secure 标志",
			"Cookie("+strings.Join(insecureCookies, ", ")+") 在 HTTPS 站点未加 Secure, 可能经明文传输", fixCookieFlags))
	}
	if len(notHTTPOnly) > 0 {
		emit("finding", NewFinding("low", "Cookie 未设置 HttpOnly 标志",
			"Cookie("+strings.Join(notHTTPOnly, ", ")+") 可被 JavaScript 读取, 存在 XSS 窃取风险", fixCookieFlags))
	}

	// 4. TLS 证书
	if u.Scheme == "https" {
		hostPort := u.Host
		if !strings.Contains(hostPort, ":") {
			hostPort += ":443"
		}
		conn, err := tls.Dial("tcp", hostPort, &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			defer conn.Close()
			cs := conn.ConnectionState()
			if len(cs.PeerCertificates) > 0 {
				c := cs.PeerCertificates[0]
				selfSigned := c.Subject.String() == c.Issuer.String()
				days := int(time.Until(c.NotAfter).Hours() / 24)
				info := fmt.Sprintf("CN=%s, 颁发者=%s, 有效期至 %s (剩余 %d 天)", c.Subject.CommonName, c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"), days)
				if len(c.DNSNames) > 0 {
					info += ", SAN=" + strings.Join(c.DNSNames, ",")
				}
				if selfSigned {
					info += ", 自签名证书"
				}
				emit("info", map[string]any{"key": "TLS 证书", "value": info})
				if days < 0 {
					emit("finding", NewFinding("high", "TLS 证书已过期", info, fixTLSExpired))
				} else if selfSigned {
					emit("finding", NewFinding("medium", "TLS 自签名证书", info, fixTLSSelfSigned))
				}
				if cs.Version < tls.VersionTLS12 {
					emit("finding", NewFinding("medium", "TLS 协议版本过低", "协商版本低于 TLS 1.2", fixTLSOldVersion))
				}
			}
		}
	}

	// 5. 404 基线
	base := *u
	base.Path = "/" + randomHex(12)
	base.RawQuery = ""
	base.Fragment = ""
	baseline404 := 404
	if r404, err := client.Get(base.String()); err == nil {
		baseline404 = r404.StatusCode
		r404.Body.Close()
	}

	// 6. 敏感路径探测
	emit("status", map[string]any{"msg": "敏感路径与暴露面探测..."})
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	allPaths := append(append([]pathTarget{}, sensitivePaths...), PathRulesFiltered(ruleFilter)...)
	for _, t := range allPaths {
		wg.Add(1)
		go func(t pathTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			full := u.Scheme + "://" + u.Host + t.path
			r, err := client.Get(full)
			if err != nil {
				return
			}
			defer r.Body.Close()
			rBody, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			if r.StatusCode == 404 || r.StatusCode == baseline404 {
				return
			}
			if r.StatusCode == 403 {
				emit("finding", NewFinding("low", t.desc, fmt.Sprintf("%s 返回 403(存在但受保护)", t.path), fixProtectedPath))
				return
			}
			// 建议按"路径 + 描述"匹配(路径规则来自 vuln/ 自定义库时描述形如 [ID] 名称)
			fix := FixFor(t.path + " " + t.desc)
			if fix == "" {
				fix = fixGenericPath
			}
			emit("finding", NewFinding(t.sev, t.desc, fmt.Sprintf("%s 返回 %s (%d 字节)", t.path, r.Status, len(rBody)), fix))
		}(t)
	}
	wg.Wait()

	// 7. 基础注入探测
	emit("status", map[string]any{"msg": "基础注入探测 (SQLi / XSS / 路径穿越)..."})
	root := u.Scheme + "://" + u.Host + u.Path

	// SQL 注入
	sqliURL := root + "?sqli_probe=1'"
	if r2, err := client.Get(sqliURL); err == nil {
		b2, _ := io.ReadAll(io.LimitReader(r2.Body, 1<<20))
		r2.Body.Close()
		lb2 := strings.ToLower(string(b2))
		for _, sig := range sqliSignatures {
			if strings.Contains(lb2, sig) {
				emit("finding", NewFinding("high", "疑似 SQL 注入(错误信息回显)",
					fmt.Sprintf("请求 %s 响应包含 SQL 错误特征: %s", sqliURL, sig), fixSQLi))
				break
			}
		}
	}

	// XSS 回显
	marker := "netscanxss" + randomHex(4)
	xssURL := root + "?" + marker + "=1"
	if r3, err := client.Get(xssURL); err == nil {
		b3, _ := io.ReadAll(io.LimitReader(r3.Body, 1<<20))
		r3.Body.Close()
		if strings.Contains(string(b3), marker) {
			emit("finding", NewFinding("medium", "查询参数原样回显(潜在 XSS)",
				"URL 中的参数未经转义直接回显在响应中", fixXSS))
		}
	}

	// 路径穿越
	travTargets := []struct {
		url   string
		check string
	}{
		{"/..%2f..%2f..%2f..%2fetc%2fpasswd", "root:x"},
		{"/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "root:x"},
		{"/..%2f..%2f..%2f..%2fwindows%2fwin.ini", "[versions]"},
	}
	for _, tt := range travTargets {
		r, err := client.Get(u.Scheme + "://" + u.Host + tt.url)
		if err != nil {
			continue
		}
		tBody, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if strings.Contains(string(tBody), tt.check) {
			emit("finding", NewFinding("high", "路径穿越漏洞",
				fmt.Sprintf("请求 %s 可读取敏感文件", tt.url), fixTraversal))
			break
		}
	}

	emit("status", map[string]any{"msg": "Web 扫描完成"})
}
