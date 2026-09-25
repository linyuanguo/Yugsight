package report

import (
	"regexp"
	"strings"

	"yugsight/internal/models"
)

// 修复建议来源说明(任务书: 报告需含修复建议)。
//
// 现状缺口: models.Vuln 没有 Fix 字段 —— 修复建议由扫描引擎在 finding 事件里给出
// (scanner.Finding.Fix), 但没有随归一化落库。为了不改动 models.Vuln(避免影响
// 既有数据库文件格式与全部适配器), 本模块提供两级补全:
//
//	1. 精确规则库: 按标题/端口/CVE 匹配内置加固建议(覆盖常见暴露面);
//	2. 通用兜底: 按风险等级给出"立即处置/限期加固/基线优化"的处置要求。
//
// 这样报告始终有修复建议列, 且不会因为上游缺字段而出现空白 —— 空白列在
// 交付给客户的报告里是明显的质量缺陷。

// FixOf 取一条漏洞的修复建议(优先内置精确规则)。
func FixOf(v *models.Vuln) string {
	if v == nil {
		return ""
	}
	if fix := fixByRule(v); fix != "" {
		return fix
	}
	return genericFix(v.Severity)
}

// fixRule 修复建议规则。
type fixRule struct {
	// match 标题包含任一关键字(小写比较)即命中
	keywords []string
	// port 端口命中(0 = 不判端口)
	port int
	// cve 前缀命中(可选)
	cve string
	// fix 建议正文
	fix string
}

// fixRules 内置修复建议库(按"命中越精确越靠前"排列)。
var fixRules = []fixRule{
	{keywords: []string{"敏感文件", "备份文件", "bak", ".git", ".svn", "源码"}, fix: "1) 在 Web 服务器上禁止访问 .git/.svn/备份文件等敏感路径（Nginx: location ~ /\\.(git|svn|bak|sql|zip) { deny all; }）；2) 清理站点目录中的备份与源码文件，仅保留运行所需文件；3) 上线前增加目录扫描作为发布门禁。"},
	{keywords: []string{"目录遍历", "路径穿越", "path traversal"}, fix: "1) 对所有文件路径参数做白名单校验，拒绝包含 ../ 或绝对路径的输入；2) 使用 filepath.Clean 后校验结果是否仍在允许目录内；3) 升级存在该缺陷的中间件/框架版本。"},
	{keywords: []string{"sql 注入", "sql注入", "sqli"}, fix: "1) 全部数据库访问改用参数化查询（预编译语句），禁止字符串拼接 SQL；2) 对输入做类型与长度校验；3) 数据库账号遵循最小权限原则，禁止使用 root/sa 连接业务库。"},
	{keywords: []string{"xss", "跨站脚本"}, fix: "1) 输出到 HTML 的内容统一做上下文相关转义；2) 设置 Content-Security-Policy 限制脚本来源；3) Cookie 增加 HttpOnly 标记防止脚本读取。"},
	{keywords: []string{"命令执行", "命令注入", "rce", "反序列化"}, fix: "1) 禁止将用户输入拼接进系统命令/反序列化入口；2) 升级到官方已修复版本；3) 该漏洞通常可直接获取服务器权限，建议立即下线相关接口并排查入侵痕迹。"},
	{keywords: []string{"未授权访问", "未授权"}, fix: "1) 为服务启用认证并设置强口令；2) 通过防火墙/安全组限制来源 IP，仅允许受信网段访问；3) 关闭公网映射。"},
	{keywords: []string{"弱口令", "默认口令", "空密码"}, fix: "1) 立即修改为 12 位以上强口令并启用登录失败锁定；2) 禁止使用出厂默认账号；3) 对数据库/中间件等高价值服务开启双因素或来源限制。"},
	{keywords: []string{"ssl", "tls", "证书"}, fix: "1) 更换为受信 CA 签发的证书并及时续期；2) 禁用 SSLv3/TLS1.0/1.1，仅保留 TLS1.2+；3) 启用 HSTS 强制 HTTPS 访问。"},

	// ---- 端口/服务类(按端口精确匹配) ----
	{port: 23, fix: "1) 关闭 Telnet，改用 SSH 并禁用密码登录（仅密钥）；2) 若为设备管理口，请限制管理网段访问。"},
	{port: 21, fix: "1) 确认是否需要 FTP，建议改用 SFTP/SCP；2) 禁止匿名登录，限制来源 IP；3) 如必须保留，启用 FTPS 加密传输。"},
	{port: 445, fix: "1) 确认已修补 MS17-010 并禁用 SMBv1；2) 通过防火墙限制 445 端口仅对必要主机开放；3) 关闭不必要的共享目录。"},
	{port: 3389, fix: "1) 启用 NLA 网络级身份验证并限制来源 IP；2) 修改默认端口仅为辅助手段，重点在来源限制与强口令；3) 及时修补 BlueKeep(CVE-2019-0708) 等 RDP 漏洞。"},
	{port: 6379, fix: "1) 设置 requirepass 强口令并开启 protected-mode；2) 绑定内网地址或限制来源 IP；3) 以低权限账号运行 Redis，禁用危险命令（rename-command CONFIG \"\"）。"},
	{port: 27017, fix: "1) 启用 MongoDB 身份认证（authorization: enabled）并创建最小权限账号；2) 限制 bindIp 至内网；3) 及时升级到受支持版本。"},
	{port: 9200, fix: "1) 启用 Elasticsearch 安全认证（xpack.security）并配置 TLS；2) 限制访问来源；3) 禁止对公网暴露。"},
	{port: 2375, fix: "1) 立即关闭 2375 明文端口，改用 2376 + TLS 双向认证；2) 严禁将 Docker API 暴露到网络（等同 root 权限泄露）。"},
	{port: 3306, fix: "1) 数据库不应直接对业务网开放，请通过防火墙限制来源；2) 检查 root 弱口令并改用最小权限账号；3) 确认未开启 skip-grant-tables。"},
	{port: 1433, fix: "1) 限制 1433 来源 IP；2) 禁用 sa 账号或设置强口令；3) 及时安装 SQL Server 累积更新。"},
	{port: 5432, fix: "1) 检查 pg_hba.conf 是否对 0.0.0.0/0 开放 trust 认证；2) 限制 listen_addresses 与来源 IP；3) 使用强口令并定期轮换。"},
	{port: 11211, fix: "1) Memcached 应仅监听内网并限制来源；2) 启用 SASL 认证；3) 禁止对公网暴露（避免被用于 UDP 反射放大攻击）。"},
	{port: 5900, fix: "1) VNC 应通过 SSH 隧道访问，不直接暴露；2) 设置强口令；3) 或改用 RDP/SSH 等具备加密与审计能力的方案。"},
	{port: 7001, fix: "1) 确认 WebLogic 版本并升级到最新补丁（历史反序列化漏洞较多）；2) 删除控制台默认路径或限制管理网段访问；3) 关闭 T3 协议对外暴露。"},
	{port: 139, fix: "1) 关闭不必要的 NetBIOS 服务；2) 通过防火墙限制 135/139/445 仅对必要主机开放，防止横向移动与信息收集。"},
	{port: 135, fix: "1) 通过防火墙限制 RPC 端口仅对必要主机开放；2) 关闭不必要的 RPC 服务，减少横向移动面。"},

	// ---- 安全加固类 ----
	{keywords: []string{"安全响应头", "响应头缺失", "hsts", "csp"}, fix: "1) 在 Web 服务器统一添加安全响应头：Strict-Transport-Security、Content-Security-Policy、X-Content-Type-Options、X-Frame-Options；2) HTTPS 站点必须启用 HSTS；3) 通过配置模板统一管理，避免逐站点遗漏。"},
	{keywords: []string{"cookie", "httponly", "secure 标志"}, fix: "1) 为会话 Cookie 添加 HttpOnly、Secure、SameSite=Lax/Strict 标记；2) 会话 Cookie 设置合理过期时间并在登出时失效。"},
	{keywords: []string{"debug", "调试模式", "开发模式"}, fix: "1) 生产环境关闭 DEBUG/开发模式；2) 隐藏错误堆栈与版本信息；3) 上线前做配置检查清单。"},
	{keywords: []string{"端口开放", "服务开放", "暴露"}, fix: "1) 复核该服务是否为业务必需，非必需则关闭；2) 通过防火墙/安全组按最小必要原则放行来源；3) 对管理类服务限制至运维网段。"},

	// ---- 兜底: 任何带 CVE 编号的漏洞(置于规则库末尾, 仅在前两轮全未命中时生效) ----
	{cve: "CVE-", fix: "1) 核实漏洞编号对应的组件版本；2) 升级到厂商已修复版本，或按官方公告应用补丁/缓解措施；3) 修复后重新扫描确认。"},
}

// fixByRule 按规则库匹配修复建议(未命中返回空串)。
//
// 匹配优先级(两轮扫描规则库, 顺序不可颠倒):
//
//	第 1 轮 —— 只跑"关键字规则"(keywords 非空):
//	  关键字是最精确的意图表达("未授权访问" / "弱口令" / "敏感文件"),
//	  必须优先于端口规则。否则 6379 上的"Redis 未授权访问"会被端口规则
//	  抢先命中, 报告给出的是泛化的"启用认证"而不是针对未授权的处置步骤。
//
//	第 2 轮 —— 只跑"端口/服务规则"(keywords 为空):
//	  关键字都没命中时, 退化为按端口给出该服务的通用加固建议。
//
// 无条件规则(kw/port/cve 全空)直接跳过: 那是配置错误, 命中它会返回空建议,
// 把后面的规则全部屏蔽掉。
func fixByRule(v *models.Vuln) string {
	title := strings.ToLower(v.Title)
	desc := strings.ToLower(v.Description)
	cve := models.NormalizeCVE(v.CVE)
	if cve == "" {
		// 标题里可能带 CVE(内置规则引擎的惯例), 一并纳入匹配上下文
		cve = CVEOf(v)
	}

	// 第 1 轮: 关键字规则
	for _, r := range fixRules {
		if len(r.keywords) == 0 {
			continue
		}
		for _, kw := range r.keywords {
			if strings.Contains(title, kw) || (desc != "" && strings.Contains(desc, kw)) {
				return r.fix
			}
		}
	}
	// 第 2 轮: 端口/服务规则
	for _, r := range fixRules {
		if len(r.keywords) > 0 {
			continue
		}
		if r.port == 0 && r.cve == "" {
			continue
		}
		if r.port != 0 && v.Port != r.port {
			continue
		}
		if r.cve != "" && !strings.HasPrefix(cve, r.cve) {
			continue
		}
		if r.port == 0 && r.cve != "" && !strings.HasPrefix(cve, r.cve) {
			continue
		}
		return r.fix
	}
	// 第 3 轮: 仅按 CVE 前缀(如 "cve-" 通配规则在 fixRules 里的通用项)
	for _, r := range fixRules {
		if len(r.keywords) > 0 || r.port != 0 || r.cve == "" {
			continue
		}
		if strings.HasPrefix(cve, r.cve) {
			return r.fix
		}
	}
	return ""
}

// genericFix 按风险等级给出兜底处置要求。
func genericFix(severity string) string {
	switch models.NormalizeSeverity(severity) {
	case models.SeverityCritical:
		return "1) 立即评估影响范围并组织应急处置，必要时临时下线相关服务；2) 按厂商公告升级或应用缓解措施；3) 修复后复测并留存证据。"
	case models.SeverityHigh:
		return "1) 24 小时内完成核实与修复；2) 升级组件到已修复版本或关闭受影响的对外入口；3) 修复后重新扫描确认。"
	case models.SeverityMedium:
		return "1) 一周内完成加固；2) 收敛对外暴露面、更新组件版本；3) 结合安全基线排查同类问题。"
	case models.SeverityLow:
		return "1) 纳入日常安全基线逐步整改；2) 建议在下一次版本发布时一并修复；3) 关注厂商安全公告。"
	default:
		return "1) 该项为信息类提示，可结合业务需要评估是否调整；2) 建议纳入资产台账与配置基线统一管理。"
	}
}

// pcapHint 生成 PCAP 附件说明文案(无附件时返回空串, 模板据此隐藏该行)。
//
// MVP 说明: 抓包产物路径由扫描/探针侧记录(models.Vuln.PcapFile), 报告只做
// 引用展示; 中心端尚未提供 PCAP 文件下载接口(留待抓包模块二期), 因此此处
// 明确提示用户到文件所在位置获取, 不给一个点了没反应的链接。
func pcapHint(v *models.Vuln) string {
	if v == nil || strings.TrimSpace(v.PcapFile) == "" {
		return ""
	}
	return v.PcapFile
}

// cveLink 生成 CVE 查询链接(便于报告阅读者直接核实)。
func cveLink(cve string) string {
	cve = models.NormalizeCVE(cve)
	if !models.IsCVE(cve) {
		return ""
	}
	return "https://nvd.nist.gov/vuln/detail/" + cve
}

// cveRe 从任意文本里提取 CVE 编号(用于从标题补全 CVE)。
var cveRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// CVEOf 取漏洞的 CVE 编号: 优先字段值, 为空时从标题/描述里提取。
//
// 为什么需要: 内置规则引擎的 finding 不带 CVE 字段, CVE 写在标题里
// (如 "[YUGSIGHT-0001] Apache Log4j2 RCE (CVE-2021-44228)"), 直接从字段读会
// 让报告里的 CVE 列大面积空白。
func CVEOf(v *models.Vuln) string {
	if v == nil {
		return ""
	}
	if cve := models.NormalizeCVE(v.CVE); models.IsCVE(cve) {
		return cve
	}
	if m := cveRe.FindString(v.Title); m != "" {
		return models.NormalizeCVE(m)
	}
	if m := cveRe.FindString(v.Description); m != "" {
		return models.NormalizeCVE(m)
	}
	return ""
}
