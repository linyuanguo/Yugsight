package scanner

// host_extra.go 主机扫描增强(2026-09-20): EOL 停补检测 + 主动验证型探测。
//
// 背景: 用户反馈"规则库太少, 主机系统漏扫呢? 补丁没打也能扫吗"。网络侧能做的
// "漏扫"上限就是: 指纹(版本) -> 已知 CVE 版本匹配 + EOL(停补)判定 + 少数可主动
// 验证的配置风险。本文件补齐后两者, 全部只发**只读探测报文**(不利用漏洞、不写
// 数据、不爆破), 与工具"安全探测"的定位一致。
//
// 判定语义沿用 cpe_engine.go 的两型区分:
//   - EOL / 版本匹配: "该版本落在已知风险范围", 未实际验证;
//   - 验证型(verified): 扫描器主动探测确认(如 SMBv1 协商成功、FTP 匿名登录成功),
//     标题带"(已验证)", 用户可直接据此处置。

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"time"
)

// ===== EOL(停止支持)检测 =====
//
// "补丁没打"在网络侧的直接对应物是"这个版本已经没有任何补丁了" —— 厂商停止支持
// (EOL)后, 新披露的 CVE 永远不会有修复版本。这类风险版本匹配 CVE 库覆盖不到
// (库只有已披露的 CVE), 必须单独判定。

// eolInfo 一条 EOL 判定结果
type eolInfo struct {
	Label string // "Apache 2.2 (2020-07-01 停止支持)"
	Note  string // 说明文本
	High  bool   // 是否为高危(生产环境出现 EOL 核心组件)
}

// eolRule 版本前缀匹配规则: major + minor(minor=-1 表示该 major 下全部)。
//
// 用 major.minor 前缀匹配而非完整版本比较的原因: 停补通常以"版本线"为单位
// (整个 2.2.x 线都停补了), 逐版本列举既冗长又容易漏。
type eolRule struct {
	product string
	major   int
	minor   int // -1 = 该 major 全部
	label   string
	note    string
	high    bool
}

var eolRules = []eolRule{
	// IIS 版本与 Windows 版本一一对应(确定性映射), 是最可靠的"操作系统停补"证据:
	// IIS 6.0=Win2003 / 7.0=Win7或2008 / 7.5=Win7或2008R2 / 8.0=Win8或2012 /
	// 8.5=Win8.1或2012R2 / 10.0=Win10或2016+
	{"iis", 6, -1, "IIS 6.0 (Windows Server 2003, 2015-07-14 停止支持)", "IIS 6.0 随 Windows Server 2003 停止支持, 此后所有安全更新均不再发布, 任何新漏洞都将永久无补丁", true},
	{"iis", 7, 0, "IIS 7.0 (Windows 7 / Server 2008, 2020-01-14 停止支持)", "IIS 7.0 对应的 Windows 7/Server 2008 已停止支持, 不再获得安全更新", true},
	{"iis", 7, 5, "IIS 7.5 (Windows 7 / Server 2008 R2, 2020-01-14 停止支持)", "IIS 7.5 对应的 Windows 7/Server 2008 R2 已停止支持, 不再获得安全更新", true},
	{"iis", 8, 0, "IIS 8.0 (Windows 8 / Server 2012, 2018-10-10 停止支持)", "IIS 8.0 对应的 Windows 8/Server 2012 已停止支持", false},
	{"iis", 8, 5, "IIS 8.5 (Windows 8.1 / Server 2012 R2, 2023-01-11 停止支持)", "IIS 8.5 对应的 Windows 8.1/Server 2012 R2 已停止支持", false},
	// Web 服务器
	{"apache", 2, 2, "Apache httpd 2.2 (2020-07-01 停止支持)", "Apache 2.2 版本线已停止支持, 后续 CVE 均无 2.2 修复版, 请升级到 2.4.x 最新版", true},
	{"nginx", 0, -1, "nginx 0.x (版本线早已停止支持)", "nginx 0.6~0.8 为 2012 年前后的版本, 存在多个已披露且无修复的远程代码执行漏洞, 请立即升级", true},
	{"tomcat", 7, -1, "Apache Tomcat 7 (2023-03-31 停止支持)", "Tomcat 7 已停止支持, 不再获得安全更新", false},
	{"tomcat", 8, 0, "Apache Tomcat 8.0 (2021-08-31 停止支持)", "Tomcat 8.0 已停止支持, 不再获得安全更新", false},
	// PHP
	{"php", 5, -1, "PHP 5.x (最迟 2018-12-31 停止支持)", "PHP 5 全系已停止支持, 存在多个未修复的远程代码执行漏洞", true},
	{"php", 7, 0, "PHP 7.0 (2018-12-31 停止支持)", "PHP 7.0 已停止支持", false},
	{"php", 7, 1, "PHP 7.1 (2019-12-31 停止支持)", "PHP 7.1 已停止支持", false},
	{"php", 7, 2, "PHP 7.2 (2020-11-30 停止支持)", "PHP 7.2 已停止支持", false},
	{"php", 7, 3, "PHP 7.3 (2021-12-08 停止支持)", "PHP 7.3 已停止支持", false},
	{"php", 7, 4, "PHP 7.4 (2022-11-28 停止支持)", "PHP 7.4 已停止支持, 存在多个未修复的安全漏洞(如 CVE-2023-38245), 请升级 8.x", false},
	// 数据库
	{"mysql", 5, 6, "MySQL 5.6 (2021-02-16 停止支持)", "MySQL 5.6 已停止支持(官方 EOL), 不再获得安全更新", false},
	{"mysql", 5, 7, "MySQL 5.7 (2023-10-31 停止支持)", "MySQL 5.7 已停止支持(官方 EOL), 不再获得安全更新", false},
	{"mongodb", 3, -1, "MongoDB 3.x (3.6 于 2020-12-31 停止支持)", "MongoDB 3.x 版本线已停止支持", false},
	{"mongodb", 4, 0, "MongoDB 4.0 (2021-04-30 停止支持)", "MongoDB 4.0 已停止支持", false},
	{"elasticsearch", 6, -1, "Elasticsearch 6.x (2024-04-30 停止支持)", "Elasticsearch 6.x 已停止支持", false},
	{"elasticsearch", 7, 6, "Elasticsearch 7.0~7.6 (2022-05-27 停止支持)", "该版本线已停止支持", false},
	{"jetty", 7, -1, "Jetty 7 (版本线早已停止支持)", "Jetty 7 已停止支持, 存在多个已披露漏洞", false},
	{"jetty", 8, -1, "Jetty 8 (2016-08-19 停止支持)", "Jetty 8 已停止支持", false},
}

// matchEOL 判断产品版本是否落在已停止支持的版本线。
// version 为纯版本号(如 "2.4.49" / "10.0"); 无法解析版本时返回 nil。
func matchEOL(product, version string) *eolInfo {
	major, minor, ok := versionMajorMinor(version)
	if !ok {
		return nil
	}
	for _, r := range eolRules {
		if r.product != product {
			continue
		}
		if r.major != major {
			continue
		}
		if r.minor != -1 && r.minor != minor {
			continue
		}
		return &eolInfo{Label: r.label, Note: r.note + "。厂商不再为该版本发布安全补丁, 新披露的漏洞将永久无修复版本, 建议升级到受支持的版本", High: r.high}
	}
	return nil
}

// versionMajorMinor 取版本的前两段数字。"10.0" -> (10,0); "7.4.3" -> (7,4)。
func versionMajorMinor(v string) (int, int, bool) {
	seg := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '_' || r == ' ' })
	if len(seg) == 0 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(seg[0])
	if err != nil {
		return 0, 0, false
	}
	minor := 0
	if len(seg) > 1 {
		if m, err := strconv.Atoi(seg[1]); err == nil {
			minor = m
		}
	}
	return major, minor, true
}

// iisVersionFromBanners 从原始 banner 中提取 IIS 版本("Microsoft-IIS/10.0")。
//
// 为什么不走 versionFromBanner: 它要求版本号至少两段数字(\d+\.\d+(\.\d+)?),
// 而 IIS 的 "10.0" 只有两段 —— 会提取失败, 导致 IIS 的 EOL 判定(最可靠的 OS
// 停补证据)失效。这里用宽松模式单独提取。
func iisVersionFromBanners(banners []string) string {
	for _, b := range banners {
		i := strings.Index(strings.ToLower(b), "microsoft-iis/")
		if i < 0 {
			continue
		}
		rest := b[i+len("microsoft-iis/"):]
		var sb strings.Builder
		for _, c := range rest {
			if (c >= '0' && c <= '9') || c == '.' {
				sb.WriteRune(c)
			} else {
				break
			}
		}
		if s := sb.String(); s != "" {
			return s
		}
	}
	return ""
}

// ===== 主动验证型探测(只读, 不利用漏洞) =====

// smbProbe 一次 SMB NEGOTIATE 同时拿到: 计算机名 + 是否支持 SMBv1。
//
// 为什么把两者合成一次探测: 原来 smbComputerName 已经发了 SMB1 NEGOTIATE 报文
// (请求方言里就带 "NT LM 0.12") —— 服务器若接受了 SMB1 方言, 响应里就会回
// "NT LM 0.12"。同一次往返既识别资产又完成 SMBv1 验证, 不多发一个包。
//
// 【安全口径】NEGOTIATE 是 SMB 协议握手的第一步, 任何客户端连 445 都会发,
// 属于纯只读探测, 不触发任何漏洞利用。
func smbProbe(ip string, timeout time.Duration) (name string, smb1 bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "445"), timeout)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// NetBIOS Session Service + SMB1 NEGOTIATE Protocol Request
	// (与历史实现同一报文: 请求方言 LANMAN1.0 + NT LM 0.12)
	pkt := []byte{
		0x00, 0x00, 0x00, 0x54, // NBSS: session message, length 0x54
		0xFF, 0x53, 0x4D, 0x42, // SMB
		0x72,                   // Negotiate Protocol
		0x00, 0x00, 0x00, 0x00, // status
		0x18,                   // flags
		0x53, 0xC8,             // flags2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,             // TID
		0x2F, 0x4B,             // PID
		0x00, 0x00,             // UID
		0xC5, 0x5E,             // MID
		0x00,                   // word count
		0x0C,                   // byte count
		0x00,                   // buffer format
		0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, // "LANMAN1.0"
		0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00, // "NT LM 0.12"
	}
	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 40 {
		return "", false
	}
	return extractSMBName(buf[:n]), smb1DialectIn(buf[:n])
}

// smb1DialectIn 判断 SMB NEGOTIATE 响应是否接受了 SMBv1 方言("NT LM 0.12")。
//
// 判据: 响应报文的方言列表段里出现 "NT LM 0.12" 字符串。SMB2/3 的 negotiate
// 响应(Dialect 0x02xx/0x03xx)不会包含该字符串, 因此无假阳性。
func smb1DialectIn(b []byte) bool {
	return bytesContains(b, []byte("NT LM 0.12"))
}

// ftpAnonymous 验证 FTP 是否允许匿名登录(只读: USER/PASS 匿名, 不列目录不下载)。
func ftpAnonymous(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "21"), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(conn)
	// 读欢迎 banner(部分服务器不回 banner 就直接等命令, 两种都要兼容)
	_, _ = r.ReadString('\n')
	if !ftpCmdOK(r, conn, "USER anonymous\r\n", []string{"331", "230", "503"}) {
		return false
	}
	// 503 = 已登录过(有些服务器对匿名直接视为已登录, 也算允许匿名)
	if ftpCmdOK(r, conn, "PASS anonymous@\r\n", []string{"230"}) {
		return true
	}
	return false
}

// ftpCmdOK 发 FTP 命令并判断响应码是否命中 want 列表(兼容 multiline 响应:
// 逐行读直到 "nnn " 结尾行)。
func ftpCmdOK(r *bufio.Reader, conn net.Conn, cmd string, want []string) bool {
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return false
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return false
		}
		code := ""
		if len(line) >= 3 {
			code = line[:3]
		}
		for _, w := range want {
			if code == w {
				return true
			}
		}
		// multiline 继续行以 "nnn-" 结尾, 最终行以 "nnn " 结尾
		if len(line) >= 4 && line[3] == ' ' {
			return false
		}
	}
}

// memcachedVersion 查询 Memcached 版本("version" 命令, 只读)。
// 返回版本号或空串(服务不可达/非 Memcached)。
func memcachedVersion(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "11211"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return ""
	}
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	return parseMemcachedVersion(string(buf[:n]))
}

// parseMemcachedVersion "VERSION 1.5.6" -> "1.5.6"(纯函数, 可单测)
func parseMemcachedVersion(resp string) string {
	i := strings.Index(strings.ToUpper(resp), "VERSION ")
	if i < 0 {
		return ""
	}
	rest := resp[i+len("VERSION "):]
	var sb strings.Builder
	for _, c := range rest {
		if (c >= '0' && c <= '9') || c == '.' {
			sb.WriteRune(c)
		} else {
			break
		}
	}
	return sb.String()
}

// redisUnauthInfo 验证 Redis 是否未授权(PING -> PONG), 未授权时顺带取版本(INFO server, 只读)。
//
// 返回 (是否未授权, 版本号)。版本用于 CVE 匹配: "未授权 + 版本落在 CVE 范围"
// 是验证型证据(不是猜测), 报告价值远高于泛泛的"建议设置密码"。
func redisUnauthInfo(ip string, timeout time.Duration) (bool, string) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "6379"), timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// RESP: inline 命令 PING
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return false, ""
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return false, ""
	}
	if !strings.Contains(string(buf[:n]), "PONG") {
		return false, ""
	}
	// 未授权: 取版本(INFO server 是只读命令; 已设密码的服务器会回 -NOAUTH, 读到的就不是版本号)
	if _, err := conn.Write([]byte("INFO server\r\n")); err != nil {
		return true, ""
	}
	b2 := make([]byte, 4096)
	n2, _ := conn.Read(b2)
	return true, parseRedisVersion(string(b2[:n2]))
}

// parseRedisVersion 从 INFO server 响应提取 "redis_version:6.2.6"(纯函数, 可单测)
func parseRedisVersion(info string) string {
	i := strings.Index(info, "redis_version:")
	if i < 0 {
		return ""
	}
	rest := info[i+len("redis_version:"):]
	var sb strings.Builder
	for _, c := range rest {
		if (c >= '0' && c <= '9') || c == '.' {
			sb.WriteRune(c)
		} else {
			break
		}
	}
	return sb.String()
}

// bytesContains 子串查找(只读遍历)
func bytesContains(b, sub []byte) bool {
	if len(sub) == 0 || len(sub) > len(b) {
		return false
	}
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
