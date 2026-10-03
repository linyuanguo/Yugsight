// probe_agent_install.go 探针"安装落地页"——面向被扫描机器上的人的可视化页面。
//
// ===== 与既有接口的分工 =====
//
//	/api/v2/probe/agent/list      给中心端使用者看的数据(JSON)
//	/api/v2/probe/agent/download  给浏览器下载用(附件流)
//	/api/v2/probe/agent/guide     纯文本指引(贴工单/邮件)
//	/api/v2/probe/agent/install   本文件: 一个能直接在目标机器上打开的 HTML 页面
//	/api/v2/probe/agent/install.sh 本文件: Linux 一键安装脚本(curl | bash 口径)
//
// 为什么还需要一个 HTML 页: 目标机器上的操作者通常不是安全运维, 让他"看 JSON 里的
// addr/token 再手拼命令行"是部署失败的主要来源(密钥抄错、地址抄漏)。落地页把
// 平台选择、下载按钮、可复制的启动命令放在一屏里, 照做即可。
//
// 为什么还要 install.sh: 落地页里"Linux 一键安装"原先是一整段多行内联命令,
// 复制粘贴容易截断; 改成 curl | bash 单行后, 地址/密钥完全由服务端渲染注入,
// 页面上不再出现密钥(泄漏面更小), 用户只需复制一行。
//
// 安全边界(2026-09-27 起):
//  1. 匿名可访问(用户要求, 登录页提供下载入口): 页面/脚本内含节点密钥, 该接口面向
//     内网部署场景 —— 拿到页面的人本来就能访问这台中心端;
//  2. 不把 token 放进 URL: 密钥进浏览器历史/代理日志/Referer 是实打实的泄漏面,
//     所以由服务端在渲染时注入, 而不是让页面自己再请求一次;
//  3. Referrer-Policy: no-referrer + 页面内禁止外链(见模板注释);
//  4. install.sh 里注入的值必须防 shell 注入: 密钥用单引号包裹(shellQuote),
//     Host 头只允许安全字符集(isSafeHost), 否则配置里的 $(...) 会被目标机器执行。
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"yugsight/internal/agentpkg"
	"yugsight/internal/server"
)

// agentInstallTemplatePath 落地页模板路径(exe 同目录 res/web/agent_install.html。
// 2026-09-24 dist 目录整理: 内置数据资源收进 res/)。
//
// 优先读磁盘、回落到内嵌版本的理由: 运维想改文案/加公司内网说明时, 直接改文件
// 重开页面即可, 不必重新编译中心端(与 report_template.html 同一约定)。
var agentInstallTemplatePath = func() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "res", "web", "agent_install.html")
	}
	return ""
}

// agentInstallTemplate 内嵌兜底模板(与 web/agent_install.html 同内容, 构建时嵌入)
func agentInstallTemplate() (string, error) {
	data, err := uiFS.ReadFile("web/agent_install.html")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// hAgentInstall GET /api/v2/probe/agent/install 渲染探针安装落地页。
//
// 同时支持两种用法:
//   - 浏览器直接打开(/api/v2/probe/agent/install) —— 中心端使用者把链接发给操作者;
//   - 目标机器浏览器打开同一个 URL(2026-09-27 起匿名可访问, 无需登录 ——
//     登录页"探针安装包下载"入口即指向本页)。
//
// 渲染失败(模板缺失且内嵌也读不到)时降级为纯文本指引: 页面坏了不该让用户完全
// 拿不到部署方法(规则 4: 失败降级不崩溃)。
func hAgentInstall(w http.ResponseWriter, r *http.Request) {
	tpl, err := loadAgentInstallTemplate()
	if err != nil {
		logLine("探针安装页模板加载失败, 降级为纯文本指引: " + err.Error())
		hAgentGuide(w, r)
		return
	}
	hostOS, hostArch := hostPlatform()
	page := renderAgentInstallPage(tpl, hostOS, hostArch)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(page))
}

// loadAgentInstallTemplate 先读磁盘(可被运维覆盖), 再回落到内嵌模板。
func loadAgentInstallTemplate() (string, error) {
	if p := agentInstallTemplatePath(); p != "" {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			return string(data), nil
		}
	}
	return agentInstallTemplate()
}

// ===== Linux 一键安装脚本(curl | bash) =====

// agentInstallScriptTemplatePath 一键安装脚本模板路径(exe 同目录 res/web/agent_install.sh,
// 与 HTML 落地页同一覆盖约定: 运维改脚本不用重编译)。
var agentInstallScriptTemplatePath = func() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "res", "web", "agent_install.sh")
	}
	return ""
}

// agentInstallScriptTemplate 内嵌兜底脚本模板(web/agent_install.sh, 构建时嵌入)
func agentInstallScriptTemplate() (string, error) {
	data, err := uiFS.ReadFile("web/agent_install.sh")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func loadAgentInstallScriptTemplate() (string, error) {
	if p := agentInstallScriptTemplatePath(); p != "" {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			return string(data), nil
		}
	}
	return agentInstallScriptTemplate()
}

// hAgentInstallScript GET /api/v2/probe/agent/install.sh
// 返回由中心端渲染好的一键安装脚本(Linux + systemd), 用法:
//
//	curl -fsSLk https://<中心端IP>:<Web端口>/api/v2/probe/agent/install.sh | bash
//
// 与 /install 同一安全口径: 匿名可访问(内网部署, 脚本内含节点密钥, 服务端注入)。
// 模板缺失(磁盘与内嵌都不可用)时降级为纯文本指引, 与 /install 一致。
func hAgentInstallScript(w http.ResponseWriter, r *http.Request) {
	tpl, err := loadAgentInstallScriptTemplate()
	if err != nil {
		logLine("探针安装脚本模板加载失败, 降级为纯文本指引: " + err.Error())
		hAgentGuide(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(renderAgentInstallScript(tpl, r)))
}

// renderAgentInstallScript 把下载源/探针通信地址/密钥注入脚本模板。
//
// 占位符与 HTML 落地页的注入值同源(agentAdvertiseAddr/probeCfg/uiPort),
// 唯一差别是下载源: 优先用**请求实际到达的 origin**(r.Host) —— 用户此刻能用
// 这个地址访问中心端, 目标机器再按它下载必然可达; 校验不通过才回落到广播地址。
func renderAgentInstallScript(tpl string, r *http.Request) string {
	webHost, webPort := "", fmt.Sprint(uiPort)
	if h := r.Host; h != "" {
		// r.Host 形如 "host:port" 或 "host"(Go 缺省补 :80/:443 的情况不会出现,
		// 但两种形态都要认)。
		if ph, pp, err := net.SplitHostPort(h); err == nil {
			ph = strings.Trim(ph, "[]")
			if ph != "" {
				webHost, webPort = ph, pp
			}
		} else if strings.TrimSpace(h) != "" {
			webHost = strings.Trim(h, "[]")
		}
	}
	if webHost == "" || !isSafeHost(webHost) {
		// Host 头来自请求方, 不满足安全字符集就不注入(防脚本注入), 回落到广播地址
		addr := agentAdvertiseAddr()
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			webHost = addr[:i]
		} else {
			webHost = "<中心端IP>"
		}
	}

	caddr := agentAdvertiseAddr()
	if caddr == "" {
		caddr = "<中心端IP>:8600" // 与落地页同口径: 未配置时给占位符, 探针连不上会明确报错
	}
	centerHost, centerPort := caddr, "8600"
	if i := strings.LastIndex(caddr, ":"); i >= 0 {
		centerHost, centerPort = caddr[:i], caddr[i+1:]
	}

	token := probeCfg.Center.Token
	if token == "" {
		token = "<节点密钥, 见中心端探针配置>"
	}

	out := tpl
	out = strings.ReplaceAll(out, "{{WEB_HOST}}", webHost)
	out = strings.ReplaceAll(out, "{{WEB_PORT}}", webPort)
	out = strings.ReplaceAll(out, "{{CENTER_HOST}}", centerHost)
	out = strings.ReplaceAll(out, "{{CENTER_PORT}}", centerPort)
	out = strings.ReplaceAll(out, "{{TOKEN}}", shellQuote(token))
	return out
}

// isSafeHost 主机只允许字母/数字/下划线/点/连字符 —— Host 头是请求方可控字符串,
// 原样注入 bash 脚本会让空格、引号、$() 等破坏脚本(甚至形成注入面)。
func isSafeHost(h string) bool {
	if h == "" {
		return false
	}
	for _, c := range h {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '-':
		default:
			return false
		}
	}
	return true
}

// shellQuote 单引号包裹 + 单引号转义: bash 单引号内**没有任何转义**, 唯一特殊
// 字符是单引号本身, 标准写法是闭引号-转义引号-开引号 ('\'' )。密钥来自配置文件,
// 可能含任意字符(含 $(cmd) / 反引号), 不包裹会在目标机器上被当命令执行。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// renderAgentInstallPage 把地址/密钥/平台按钮注入模板。
//
// 用简单字符串替换而不是 html/template: 模板里含 CSS/JS 的大量 `{{ }}` 类写法与
// 花括号, 交给 html/template 解析会被当成动作(项目里 Vue 模板踩过同类坑),
// 这里只有 4 个明确占位符, 手工替换更可控且零依赖。
func renderAgentInstallPage(tpl, hostOS, hostArch string) string {
	addr := agentAdvertiseAddr()
	if addr == "" {
		addr = "<中心端IP>:8600"
	}
	// ADDRHOST: 去掉端口后的纯主机地址, 供下载命令里的 https://<主机>:<Web端口> 拼装
	// (下载走中心端 Web 端口 HTTPS, 与探针 TCP 协议端口 8600 不是一回事)。
	// 脚本内 curl 已带 -k: 中心端使用自签证书, 不 -k 会被 curl 以证书不受信任拒绝。
	addrHost := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addrHost = addr[:i]
	}
	token := probeCfg.Center.Token
	if token == "" {
		token = "<节点密钥, 见 probe.json 的 center.token>"
	}
	out := tpl
	out = strings.ReplaceAll(out, "{{ADDR}}", htmlEscape(addr))
	out = strings.ReplaceAll(out, "{{ADDRHOST}}", htmlEscape(addrHost))
	out = strings.ReplaceAll(out, "{{TOKEN}}", htmlEscape(token))
	out = strings.ReplaceAll(out, "{{PROTO}}", fmt.Sprint(agentProtocolVersion()))
	out = strings.ReplaceAll(out, "{{VER}}", appVersion)
	out = strings.ReplaceAll(out, "{{UIPORT}}", fmt.Sprint(uiPort))
	out = strings.ReplaceAll(out, "{{SIZE}}", agentPackageSizeHint())
	out = strings.ReplaceAll(out, "{{PLATFORMS}}", agentPlatformButtons(hostOS, hostArch))
	return out
}

// agentPlatformButtons 生成各平台下载按钮的 HTML。
//
// 未分发的平台按钮置灰并给出原因(而不是隐藏): 用户看到"这台机器对应的包还没产出"
// 比"按钮凭空消失"更容易理解, 也才知道该去找谁补包。
func agentPlatformButtons(hostOS, hostArch string) string {
	var b strings.Builder
	for _, p := range agentPlatforms {
		_, name, ok := findAgentBinary(p.OS, p.Arch)
		size := ""
		if ok {
			if path, _, fok := findAgentBinary(p.OS, p.Arch); fok {
				if fi, err := os.Stat(path); err == nil {
					size = fmt.Sprintf("%.1f MB", float64(fi.Size())/(1024*1024))
				}
			}
			_ = name
		}
		cls := "dl"
		if !ok {
			cls += " off"
		}
		href := "javascript:void(0)"
		title := ""
		if ok {
			href = fmt.Sprintf("/api/v2/probe/agent/download?os=%s&arch=%s", p.OS, p.Arch)
		} else {
			title = ` title="该平台安装包尚未产出, 请在中心端补包(探针管理页有按钮/命令)"`
		}
		sub := p.OS + "/" + p.Arch
		if size != "" {
			sub = size + " · " + sub
		}
		fmt.Fprintf(&b, `<a class="%s" data-os="%s" data-arch="%s" href="%s"%s><b>%s</b><em>%s</em></a>`,
			cls, p.OS, p.Arch, href, title, p.Label, sub)
	}
	return b.String()
}

// agentPackageSizeHint 落地页顶部展示的包体大小(取已分发包的典型值)。
func agentPackageSizeHint() string {
	for _, p := range agentPlatforms {
		if path, _, ok := findAgentBinary(p.OS, p.Arch); ok {
			if fi, err := os.Stat(path); err == nil {
				return fmt.Sprintf("%.1f", float64(fi.Size())/(1024*1024))
			}
		}
	}
	return "7"
}

// agentpkgHostPlatform 本机平台(经 agentpkg 统一口径, 避免多处各自实现)
func agentpkgHostPlatform() (string, string) { return agentpkg.HostPlatform() }

// htmlEscape 转义注入到 HTML 文本/属性里的值(& < > " ')。
//
// 地址与密钥来自配置文件, 理论上可能包含引号等字符; 未转义会让页面结构被破坏
// (甚至形成注入面), 所以四个占位符一律转义后再注入。
func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}

// hostPlatform 本机平台(供落地页高亮"本机"按钮)
func hostPlatform() (string, string) {
	return agentpkgHostPlatform()
}

var _ = server.OK
