// probe_agent_install_script_test.go Linux 一键安装脚本(/api/v2/probe/agent/install.sh)测试。
//
// 覆盖重点:
//  1. 脚本能渲染: 探针通信地址/密钥被注入, 下载源用请求实际 origin, 关键步骤在位;
//  2. 密钥必须 shell 单引号包裹 —— 密钥来自配置文件, 含 $(...) / 单引号时不得
//     破坏脚本结构(这是 curl | bash 场景最容易被忽视的注入面);
//  3. Host 头是请求方可控字符串, 不满足安全字符集必须回落到广播地址;
//  4. 磁盘模板不存在时回落到内嵌模板(与 HTML 落地页同一约定);
//  5. 安装落地页的"Linux 一键安装"命令指向 install.sh 接口。
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doAgentScriptReq 带 Host 头的 GET(install.sh 的渲染依赖 r.Host)。
func doAgentScriptReq(t *testing.T, srv interface {
	Handler() http.Handler
}, path, host string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if host != "" {
		req.Host = host
	}
	srv.Handler().ServeHTTP(w, req)
	return w
}

// TestAgentInstallScriptRenders 地址/密钥/下载源注入 + 关键步骤 + 响应头。
func TestAgentInstallScriptRenders(t *testing.T) {
	withAgentDir(t)
	prevListen, prevToken := probeCfg.Center.Listen, probeCfg.Center.Token
	probeCfg.Center.Listen = "192.168.5.20:8600"
	probeCfg.Center.Token = "TESTTOKEN123"
	t.Cleanup(func() {
		probeCfg.Center.Listen = prevListen
		probeCfg.Center.Token = prevToken
	})

	srv := agentTestServer(t)
	w := doAgentScriptReq(t, srv, "/api/v2/probe/agent/install.sh", "10.9.8.7:8420")
	if w.Code != http.StatusOK {
		t.Fatalf("install.sh HTTP %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/x-shellscript") {
		t.Fatalf("Content-Type 应为 shell 脚本: %s", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("脚本含密钥, 必须 no-store, 实际 %q", cc)
	}
	body := w.Body.String()
	for _, want := range []string{
		"#!/bin/bash",
		"192.168.5.20", // 探针通信主机(中心端广播地址)
		"8600",         // 探针通信端口
		"TESTTOKEN123", // 节点密钥已注入
		"10.9.8.7",     // 下载源用请求实际 origin
		"/api/v2/probe/agent/download?os=linux",
		"systemctl daemon-reload",
		"systemctl enable --now yugsight-agent",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("install.sh 缺少关键内容 %q", want)
		}
	}
}

// shellQuotedLiteral 校验 line 是 "PROBE_TOKEN='<单引号字面量>'" 形式且字面量
// 只含 bash 单引号规则允许的转义('\'' )。bash 单引号内没有任何转义, 唯一特殊
// 字符是单引号本身 —— 因此"合法字面量"的结构检查就等价于注入安全检查:
// 若密钥被裸注入(未包裹), 扫描必然失败。
func shellQuotedLiteral(line string) bool {
	const prefix = "PROBE_TOKEN='"
	if !strings.HasPrefix(line, prefix) {
		return false
	}
	s := line[len(prefix):]
	if len(s) == 0 || s[len(s)-1] != '\'' { // 结尾的闭合引号
		return false
	}
	s = s[:len(s)-1]
	for i := 0; i < len(s); {
		if s[i] != '\'' {
			i++
			continue
		}
		// 字面量内的单引号必须是 '\'' 转义序列(4 字符: ' \ ' ')
		if i+3 < len(s) && s[i+1] == '\\' && s[i+2] == '\'' && s[i+3] == '\'' {
			i += 4
			continue
		}
		return false
	}
	return true
}

// TestAgentInstallScriptShellQuotesToken 密钥含单引号/命令字符时必须被安全包裹:
// 否则 $(cmd)/裸命令会在目标机器上被执行(curl | bash 场景最易被忽视的注入面)。
func TestAgentInstallScriptShellQuotesToken(t *testing.T) {
	withAgentDir(t)
	prevToken := probeCfg.Center.Token
	probeCfg.Center.Token = "evil'; touch /tmp/ys-pwned; echo '"
	t.Cleanup(func() { probeCfg.Center.Token = prevToken })

	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/install.sh")
	body := w.Body.String()

	// 定位的是服务端注入的那一行(单引号字面量赋值), 而非 ":-" 默认值那行
	idx := strings.Index(body, "PROBE_TOKEN='")
	if idx < 0 {
		t.Fatalf("脚本缺少注入的 PROBE_TOKEN 字面量赋值: %s", snippetAround(body, "PROBE_TOKEN"))
	}
	eol := strings.IndexAny(body[idx:], "\n")
	line := body[idx : idx+eol]

	if !shellQuotedLiteral(line) {
		t.Fatalf("密钥未被安全地单引号包裹: line=%q", line)
	}
	if !strings.Contains(line, "touch /tmp/ys-pwned") {
		t.Errorf("密钥内容应原样保留在字面量内: %s", line)
	}
	// 反例自检: 裸注入(未包裹)必须被判定为不安全
	if shellQuotedLiteral("PROBE_TOKEN=" + "evil'; touch /tmp/ys-pwned; echo '") {
		t.Fatal("裸注入的密钥未被识别为不安全, 校验函数失效")
	}
}

// TestAgentInstallScriptMaliciousHost 请求 Host 头不可信: 含空格/$() 等字符时
// 不得原样注入, 必须回落到中心端广播地址。
func TestAgentInstallScriptMaliciousHost(t *testing.T) {
	withAgentDir(t)
	prevListen := probeCfg.Center.Listen
	probeCfg.Center.Listen = "192.168.5.20:8600"
	t.Cleanup(func() { probeCfg.Center.Listen = prevListen })

	srv := agentTestServer(t)
	w := doAgentScriptReq(t, srv, "/api/v2/probe/agent/install.sh", "evil host $(reboot):9999")
	body := w.Body.String()
	if strings.Contains(body, "reboot") || strings.Contains(body, "evil host") {
		t.Fatalf("Host 头被原样注入脚本: %s", snippetAround(body, "reboot"))
	}
	if !strings.Contains(body, "192.168.5.20") {
		t.Error("Host 非法时应回落到广播地址")
	}
}

// TestAgentInstallScriptFallsBackToEmbedded 磁盘模板不存在时回落内嵌模板。
func TestAgentInstallScriptFallsBackToEmbedded(t *testing.T) {
	withAgentDir(t)
	prev := agentInstallScriptTemplatePath
	agentInstallScriptTemplatePath = func() string { return "/nonexistent/does-not-exist.sh" }
	t.Cleanup(func() { agentInstallScriptTemplatePath = prev })

	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/install.sh")
	if w.Code != http.StatusOK {
		t.Fatalf("回落内嵌模板应 200, 实际 %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/x-shellscript") {
		t.Fatalf("应仍返回脚本: %s", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "yugsight-agent") {
		t.Fatalf("内嵌模板内容异常: %s", snippetAround(w.Body.String(), "yugsight"))
	}
}

// TestInstallPageOneLinerPointsToInstallSh 落地页"Linux 一键安装"命令必须指向
// install.sh 接口(一行命令, 密钥不再出现在页面里)。
func TestInstallPageOneLinerPointsToInstallSh(t *testing.T) {
	withAgentDir(t)
	srv := agentTestServer(t)
	w := doAgentReq(t, srv, "/api/v2/probe/agent/install")
	page := w.Body.String()
	if !strings.Contains(page, "/api/v2/probe/agent/install.sh | bash") {
		t.Errorf("落地页一键安装命令应指向 install.sh: %s", snippetAround(page, "一键安装"))
	}
}
