// probe_agent_install.go 探针"安装落地页"——面向被扫描机器上的人的可视化页面。
//
// ===== 与既有接口的分工 =====
//
//	/api/v2/probe/agent/list     给中心端使用者看的数据(JSON)
//	/api/v2/probe/agent/download 给浏览器下载用(附件流)
//	/api/v2/probe/agent/guide    纯文本指引(贴工单/邮件)
//	/api/v2/probe/agent/install  本文件: 一个能直接在目标机器上打开的 HTML 页面
//
// 为什么还需要一个 HTML 页: 目标机器上的操作者通常不是安全运维, 让他"看 JSON 里的
// addr/token 再手拼命令行"是部署失败的主要来源(密钥抄错、地址抄漏)。落地页把
// 平台选择、下载按钮、可复制的启动命令放在一屏里, 照做即可。
//
// 安全边界(三条, 都很实际):
//  1. 走 requireAuth: 页面内含节点密钥, 未登录者拿不到;
//  2. 不把 token 放进 URL: 密钥进浏览器历史/代理日志/Referer 是实打实的泄漏面,
//     所以由服务端在渲染时注入, 而不是让页面自己再请求一次;
//  3. Referrer-Policy: no-referrer + 页面内禁止外链(见模板注释)。
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"yugsight/agentpkg"
	"yugsight/server"
)

// agentInstallTemplatePath 落地页模板路径(exe 同目录 web/agent_install.html)。
//
// 优先读磁盘、回落到内嵌版本的理由: 运维想改文案/加公司内网说明时, 直接改文件
// 重开页面即可, 不必重新编译中心端(与 report_template.html 同一约定)。
var agentInstallTemplatePath = func() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "web", "agent_install.html")
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
//   - 目标机器浏览器打开同一个 URL(需先用 http://<中心端IP>:端口/app/ 登录过,
//     会话 cookie 在同一浏览器才有效; 未登录会得到 401, 这正是期望行为)。
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
	token := probeCfg.Center.Token
	if token == "" {
		token = "<节点密钥, 见 probe.json 的 center.token>"
	}
	out := tpl
	out = strings.ReplaceAll(out, "{{ADDR}}", htmlEscape(addr))
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
