package scanner

import "strings"

// 内置修复建议库
//
// 背景: 扫描结果原先只有"级别/发现/详情", 用户看到"PHP info 页面(泄露运行环境)"
// 这样的中危却不知道该怎么处理, 而 AI 修复建议要配 API Key 才可用。
// 这里为每类发现内置"可落地的处置步骤"(区分 Linux / Windows / 中间件),
// 无网络、无 AI 也能直接照做; AI 分析仍可用于深度研判。
//
// 每条建议都是导出的具名常量: web.go 直接引用, 其余走 FixFor 关键字匹配。

const (
	fixPHPInfo = "立即删除或重命名 info.php / phpinfo.php 等调试脚本(生产环境不应存在): " +
		"Linux 执行 find /var/www \\( -name '*phpinfo*' -o -name 'info.php' \\) 排查并删除; " +
		"确需保留时仅限内网访问(Nginx: location ~* (info|phpinfo)\\.php$ { allow 10.0.0.0/8; deny all; }, " +
		"IIS 用“IP 地址和域限制”); 同时 php.ini 设 expose_php=Off 并重启 PHP-FPM/Apache。验证: 再次访问应返回 404。"

	fixVCS = "删除站点根目录下的 .git / .svn(或把仓库移到 Web 目录外, 改用部署包发布); " +
		"Nginx: location ~ /\\.(git|svn) { deny all; }; IIS: 请求筛选拒绝 .git、.svn 段, 或直接删除目录。 " +
		"若已对外可访问, 视为源码泄露: 轮换代码中的密钥/数据库口令, 并排查历史提交里的敏感信息。"

	fixSecretFile = "从 Web 目录移除配置/凭据文件并加入 .gitignore; 立即轮换其中的数据库口令、AK/SK 等密钥(视为已泄露); " +
		"改为系统环境变量或密钥管理服务注入。Nginx: location ~ /\\.(env|aws) { deny all; }; " +
		"IIS: 请求筛选拒绝扩展名为空且以 . 开头的文件。"

	fixBackup = "删除 Web 目录下的备份与数据库导出文件, 备份产物改存到站点目录之外的独立存储; " +
		"Nginx: location ~* \\.(sql|zip|tar\\.gz|bak|rar)$ { deny all; }; IIS: 请求筛选拒绝这些扩展名。 " +
		"评估已泄露范围(是否含用户数据), 必要时按合规要求通报。"

	fixDSStore = "删除站点目录下的 .DS_Store(git rm --cached .DS_Store 并加入 .gitignore, " +
		"macOS 执行 defaults write com.apple.desktopservices DSDontWriteNetworkStores true); " +
		"服务器禁止访问: Nginx location ~ /\\.DS_Store { deny all; }。"

	fixApacheStatus = "限制来源 IP 或关闭: Apache <Location /server-status> Require ip 127.0.0.1 内网段 </Location>; " +
		"Nginx 仅允许内网代理访问并加认证; 不需要则注释掉 status/info 模块配置后重载服务。"

	fixAdminUI = "不要直接暴露到公网: 仅监听内网或经 VPN/网关鉴权访问, 并配置 IP 白名单; " +
		"修改默认路径与默认口令, 强制强口令 + 双因子; 升级到官方当前稳定版。 " +
		"Spring Boot 另需 management.endpoints.web.exposure.include=health,info 并给 /actuator 加认证; " +
		"Tomcat Manager 需在 conf/tomcat-users.xml 配强口令并用 RemoteAddrValve 限制来源。"

	fixAPIDoc = "生产环境关闭或加认证: Spring Boot 设 springdoc.api-docs.enabled=false / " +
		"springfox.documentation.enabled=false(或仅在非生产 profile 开启); " +
		"Nginx 对 /swagger、/api-docs 加 auth_basic 或网关鉴权; 核查文档中是否泄露内部接口与敏感字段。"

	fixRobots = "检查 robots.txt 是否泄露后台/管理路径: 敏感路径不应靠 robots 保密, 应改用访问控制(鉴权/IP 白名单); " +
		"文件本身可保留, 但需移除其中暴露的内部目录条目。"

	fixGitIgnore = "确认其中不含需保密的路径规则即可, 属低风险; 建议同时删除线上可访问的 .gitignore 副本, " +
		"并禁止以 . 开头的隐藏文件被直接下载。"

	fixWebConfig = "禁止直接访问配置文件: IIS 请求筛选拒绝 .config 扩展名, 或把配置移出 Web 目录; " +
		"确认其中的连接串已加密(aspnet_regiis -pef connectionStrings)且不出现明文口令。"

	fixTestFile = "删除生产环境的测试脚本、演示页面与临时文件; 不需要 CGI 时删除或禁用 cgi-bin " +
		"(Nginx: location /cgi-bin/ { return 404; }; Apache 移除 ScriptAlias/CGI 模块)。"

	fixHidePoweredBy = "移除该响应头: PHP 设 expose_php=Off; Nginx 追加 fastcgi_hide_header X-Powered-By; " +
		"(或 proxy_hide_header); IIS 在 web.config 的 <customHeaders><remove name=\"X-Powered-By\" /> 中移除。"

	fixHideVersion = "隐藏版本号: Nginx server_tokens off; Apache ServerTokens Prod + ServerSignature Off; " +
		"IIS 用 URL Rewrite 出站规则删除 Server 头; 也可在 CDN/网关层改写。改后重载服务并复测。"

	fixSecurityHeaders = "在 Web 服务器或网关补齐(以 Nginx 为例): " +
		"add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always; " +
		"add_header X-Frame-Options SAMEORIGIN always; add_header X-Content-Type-Options nosniff always; " +
		"add_header Referrer-Policy strict-origin-when-cross-origin always; " +
		"再按站点资源逐步加 Content-Security-Policy 与 Permissions-Policy。 " +
		"IIS 在 web.config 的 <httpProtocol><customHeaders> 添加同名响应头; Apache 用 Header always set。"

	fixCookieFlags = "给会话 Cookie 增加 Secure; HttpOnly; SameSite=Lax 属性: PHP 设 session.cookie_secure=1、" +
		"session.cookie_httponly=1; Spring Boot 设 server.servlet.session.cookie.secure=true、http-only=true; " +
		"Nginx 反向代理可用 proxy_cookie_flags ~ secure samesite=lax。改后清缓存复测响应头。"

	fixTLSExpired = "立即续期并替换证书: Let's Encrypt 执行 certbot renew(必要时 --force-renewal), " +
		"商用证书重新签发后部署; 配置自动续期(cron/systemd timer)与到期前 30 天告警; " +
		"更新后重载 Nginx/Apache 并复测有效期。"

	fixTLSSelfSigned = "更换为受信任 CA 签发的证书(公网服务必做); 内部系统则在内网下发根证书, " +
		"或在负载均衡/网关上终止 TLS 并统一证书管理。"

	fixTLSOldVersion = "仅启用 TLS1.2 及以上(推荐 1.3): Nginx ssl_protocols TLSv1.2 TLSv1.3; " +
		"Apache SSLProtocol -all +TLSv1.2 +TLSv1.3; Windows 在注册表 " +
		"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols 启用 TLS1.2 " +
		"并禁用 SSL3.0/TLS1.0/1.1 后重启。"

	fixSQLi = "改用参数化查询/预编译语句, 禁止字符串拼接 SQL; 关闭数据库错误回显(PHP display_errors=Off、" +
		"自定义 500 页面, Java 不要 printStackTrace); 数据库账号按最小权限授权; 前置 WAF 规则。 " +
		"修复后用 sqlmap 等工具复测, 确认不再回显 SQL 错误。"

	fixXSS = "输出按上下文做 HTML 实体转义, 避免 innerHTML / v-html / document.write 直接写入; " +
		"统一使用框架的自动转义模板; 增加 Content-Security-Policy 降低危害; 富文本用白名单过滤库。"

	fixTraversal = "禁止把用户输入直接拼接进文件路径: 改用 ID 白名单映射; 读取前 realpath 规范化并校验必须位于允许根目录内; " +
		"中间件/容器升级到官方修复版本; 临时缓解可在 WAF 拦截 ../ 及其 URL 编码形式。"

	// 主机扫描: 服务配置类
	fixRedisUnauth = "立即加固 Redis: 配置文件设 requirepass <强口令>、rename-command CONFIG \"\"、bind 127.0.0.1(或内网地址); " +
		"以非 root 账号运行; 防火墙/安全组仅放行业务来源 IP(云上安全组禁止 0.0.0.0/0 放行 6379); " +
		"若已被写入公钥或计划任务, 需排查 ~/.ssh/authorized_keys、crontab 与网站目录后清理。"

	fixMySQLWeak = "核查并加固 MySQL: 为 root 及业务账号设置强口令(ALTER USER ... IDENTIFIED BY); " +
		"删除 'root'@'%' 这类任意来源账号, 改为限定来源 IP; 防火墙/安全组禁止公网放行 3306; " +
		"必要时开启 SSL 连接与失败登录审计。"

	fixCVEUpgrade = "升级组件到官方修复版本(优先发行版安全源: yum update / apt upgrade, 或官网补丁), " +
		"升级前在测试环境验证兼容性; 无法立即升级时, 先用防火墙/访问控制限制该服务暴露面并关注官方公告。"

	// 主机扫描: EOL(停止支持)类
	fixEOLUpgrade = "升级到受支持的版本(这是唯一彻底解法: EOL 版本没有补丁可用): " +
		"升级前先在测试环境验证兼容性; 若短期无法升级, 用网络隔离弥补(防火墙限制暴露面、" +
		"禁止该主机访问敏感网段), 并在资产台账登记 EOL 状态, 跟踪官方安全公告。"

	// 主机扫描: SMBv1(已验证)
	fixSMBv1 = "禁用 SMBv1: Windows 10 1709 / Server 2016 起默认已禁用; 旧系统执行 " +
		"Set-SmbClientConfiguration -EnableSMB1Protocol $false(客户端) 并在 " +
		"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters 设 RequireSecuritySignature=1、" +
		"删除 SMB1 驱动注册表项后重启(服务器); 确认业务无老设备依赖(NAS/老打印机常需 SMBv1, 先摸底再禁)。" +
		"禁用后复测: 445 端口应仅接受 SMB2/3。"

	// 主机扫描: FTP 匿名(已验证)
	fixFTPAnon = "禁用 FTP 匿名登录: vsftpd 设 anonymous_enable=NO; ProFTPD 注释 <Anonymous> 段; " +
		"IIS 移除 FTP 匿名身份验证; 同时评估 FTP 是否仍必要(明文协议, 建议直接迁 SFTP/FTPS), " +
		"并用防火墙限制 21 端口来源。"

	// 兜底: 命中敏感路径但无专属规则
	fixGenericPath = "确认该路径是否应对外提供: 不需要则删除或移出 Web 目录; " +
		"需要则限制来源 IP(Nginx allow/deny、IIS IP 限制)并加认证; 修复后复测应返回 404。"

	// 兜底: 路径存在但返回 403(已受保护)
	fixProtectedPath = "该路径已受保护(403), 建议确认业务是否必需; " +
		"不需要则在网关/WAF 直接返回 404 并记录扫描行为, 避免暴露目录结构。"

	// 兜底: 漏洞库规则命中但无专属建议
	fixGenericVuln = "按命中规则核对对应组件: 升级到官方修复版本或应用补丁; " +
		"关闭调试与错误回显(PHP display_errors=Off、Django DEBUG=False、Java 关闭堆栈输出); " +
		"修复后用本工具复测确认不再命中; 若确认为测试/演示页面, 直接下线即可。"

	// 渗透探测: 利用确认类
	fixXXE = "禁用 XML 解析器的外部实体与 DTD 功能: Java 用 XXE 防护库(禁用 DOCTYPE/外部实体)、" +
		"PHP 用 libxml2 时设 LIBXML_NOENT 关闭实体展开、.NET 用 XmlReaderSettings 禁用 DTD; " +
		"必须处理 XML 时改用白名单校验 DOCTYPE 并禁止外部实体引用; 升级含已知 XXE 的解析组件到修复版。"

	fixSSRF = "对'由参数指定 URL'的功能做目标白名单校验(仅允许业务域 + 明确端口, 拒绝内网/环回/链路本地段: " +
		"10/172.16/192.168/127/169.254/::1); 禁止解析后再重定向(校验跟随后的最终地址); " +
		"统一出口代理并拒绝私有网段; 不要按字符串前缀放行(防 DNS 重绑定与十进制 IP 变体), 用解析后的 IP 判断。"

	fixUpload = "上传三重校验: ①文件头(Magic Number)与扩展名/声明类型一致, 白名单放行(图片/文档); " +
		"②重命名为随机名, 禁止用户控制文件名; ③上传目录禁止脚本执行权限(Nginx 对 /uploads/ 禁 PHP-FPM, " +
		"Apache RemoveHandler)并禁止公开直接访问(加认证或跳转代理); 大文件与速率限制防资源耗尽。"

	fixCmdi = "绝不用 shell 拼接用户输入: 用系统调用数组参数形式(exec.Command 传参列表, 不经过 shell 解释); " +
		"必须执行外部程序时对参数做严格白名单校验(字符集 + 长度); 确需 shell 时转义所有元字符(; | & $ `); " +
		"以最小权限账号运行, 防火墙限制其可执行的网络/文件操作面; 升级存在命令注入的组件到修复版本。"
)

// fixRule 关键字 → 修复建议(用于路径/规则命中这类"标题不固定"的发现)
type fixRule struct {
	keys []string // 小写关键字, 命中任一即采用
	fix  string
}

// fixRules 顺序有意义: 越具体的条目放前面(如 phpinfo 要排在通用规则之前)
var fixRules = []fixRule{
	{keys: []string{"phpinfo", "info.php", "php 信息", "php info"}, fix: fixPHPInfo},
	{keys: []string{".git/", ".git 目录", ".svn"}, fix: fixVCS},
	{keys: []string{".env", ".aws", "credentials", "配置暴露", "配置文件暴露"}, fix: fixSecretFile},
	{keys: []string{".sql", "backup.zip", "site.zip", "web.zip", "备份"}, fix: fixBackup},
	{keys: []string{".ds_store"}, fix: fixDSStore},
	{keys: []string{"server-status", "server-info"}, fix: fixApacheStatus},
	{keys: []string{"phpmyadmin", "manager/html", "jenkins", "grafana", "kibana", "nacos", "actuator", "solr",
		"admin", "administrator", "wp-login", "管理"}, fix: fixAdminUI},
	{keys: []string{"swagger", "api-docs", "openapi"}, fix: fixAPIDoc},
	{keys: []string{"robots.txt"}, fix: fixRobots},
	{keys: []string{".gitignore"}, fix: fixGitIgnore},
	{keys: []string{"web.config"}, fix: fixWebConfig},
	{keys: []string{"test.php", "cgi-bin", "测试文件"}, fix: fixTestFile},
	{keys: []string{"x-powered-by"}, fix: fixHidePoweredBy},
	{keys: []string{"server 版本泄露", "server 版本"}, fix: fixHideVersion},
	{keys: []string{"安全响应头缺失"}, fix: fixSecurityHeaders},
	{keys: []string{"cookie", "secure 标志", "httponly"}, fix: fixCookieFlags},
	{keys: []string{"证书已过期"}, fix: fixTLSExpired},
	{keys: []string{"自签名证书"}, fix: fixTLSSelfSigned},
	{keys: []string{"协议版本过低"}, fix: fixTLSOldVersion},
	{keys: []string{"sql 注入", "sqli"}, fix: fixSQLi},
	{keys: []string{"回显", "xss"}, fix: fixXSS},
	{keys: []string{"路径穿越", "traversal"}, fix: fixTraversal},
}

// FixFor 根据发现标题/路径给出内置修复建议, 无匹配返回空串(前端与报告按空隐藏该列)。
// 传参建议同时带上标题与路径(如 t.path+" "+t.desc), 提高命中率。
func FixFor(text string) string {
	low := strings.ToLower(text)
	for _, r := range fixRules {
		for _, k := range r.keys {
			if strings.Contains(low, k) {
				return r.fix
			}
		}
	}
	return ""
}
