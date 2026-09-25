// probe_agent_update_test.go 探针自动更新的中心端逻辑测试。
//
// 只覆盖两类"被别人改坏就会静默失效"的契约(见项目规则 9):
//  1. 下载签名: 若签名校验被改松, 任何人都能下载更新包 —— 这是安全边界, 必须守住;
//  2. 版本比对: 若口径改错, 要么所有探针反复重下(判据过宽), 要么永远不更新(过严)。
//
// 不测 HTTP 细节(那些由 server 包与端到端冒烟覆盖), 不测文件下载本身。
package main

import (
	"testing"
	"time"
)

// TestAgentUpdateSign 覆盖下载签名的合法/非法判定。
func TestAgentUpdateSign(t *testing.T) {
	token := "s3cr3t-node-token"
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()

	sig := agentUpdateSign(token, "windows", "amd64", future)

	cases := []struct {
		name       string
		token      string
		osName     string
		arch       string
		exp        int64
		sig        string
		wantAccept bool
	}{
		{"合法签名", token, "windows", "amd64", future, sig, true},
		{"大小写与空白容忍(URL 传输后再解析)", token, "windows", "amd64", future, "  " + sig + " ", true},

		// 以下每一条都对应一种攻击或误用, 必须拒绝
		{"密钥错误", "wrong-token", "windows", "amd64", future, sig, false},
		{"过期签名", token, "windows", "amd64", past, agentUpdateSign(token, "windows", "amd64", past), false},
		{"跨平台复用签名(签的是 windows 却拿去下 linux)", token, "linux", "amd64", future, sig, false},
		{"跨架构复用签名", token, "windows", "arm64", future, sig, false},
		{"伪造签名", token, "windows", "amd64", future, "deadbeef", false},
		{"空签名", token, "windows", "amd64", future, "", false},
		{"未设密钥时不接受签名通道", "", "windows", "amd64", future, sig, false},
	}
	for _, c := range cases {
		got := agentUpdateSignOK(c.token, c.osName, c.arch, c.exp, c.sig)
		if got != c.wantAccept {
			t.Errorf("%s: 期望 %v, 实际 %v", c.name, c.wantAccept, got)
		}
	}
}

// TestCenterUpdateDirective 覆盖版本比对口径与前置条件。
func TestCenterUpdateDirective(t *testing.T) {
	// 准备 agents/ 目录: 放一个 windows/amd64 的包, 用来验证"有包才下发"
	dir := t.TempDir()
	oldDir := agentDownloadDir
	agentDownloadDir = func() string { return dir }
	t.Cleanup(func() { agentDownloadDir = oldDir })

	// 未放包时: 版本不同也不下发(下了也 404, 白跑一趟)
	if d := centerUpdateDirective("0.9.0", "windows", "amd64"); d != nil {
		t.Errorf("无包时不该下发更新, 实际: %+v", d)
	}

	writeAgentPkg(t, dir, "yugsight-agent_windows_amd64.exe", "fake-agent-binary")

	// 恢复中心端密钥, 否则 updateDownloadURL 因无密钥返回空串 → 不下发
	oldToken := probeCfg.Center.Token
	probeCfg.Center.Token = "test-token"
	t.Cleanup(func() { probeCfg.Center.Token = oldToken })

	// 版本相同: 不下发(核心口径, 改错会导致反复重下或永不更新)
	if d := centerUpdateDirective(agentUpdateVersion(), "windows", "amd64"); d != nil {
		t.Errorf("版本一致时不该下发更新, 实际: %+v", d)
	}

	// 版本不同 + 平台有包: 下发, 且 URL 必须带签名与有效期
	d := centerUpdateDirective("0.9.0", "windows", "amd64")
	if d == nil {
		t.Fatal("版本不一致且平台有包时应下发更新, 实际未下发")
	}
	if d.Version != agentUpdateVersion() {
		t.Errorf("更新目标版本应为中心端版本 %s, 实际 %s", agentUpdateVersion(), d.Version)
	}
	if d.URL == "" {
		t.Fatal("更新 URL 为空, 探针无法下载")
	}
	if !hasAll(d.URL, "os=windows", "arch=amd64", "sig=", "exp=") {
		t.Errorf("更新 URL 缺少必要参数(平台/签名/有效期): %s", d.URL)
	}

	// 平台越界: 不下发
	if d := centerUpdateDirective("0.9.0", "freebsd", "amd64"); d != nil {
		t.Errorf("平台越界时不该下发更新, 实际: %+v", d)
	}
	// 平台在矩阵内但没放包: 不下发
	if d := centerUpdateDirective("0.9.0", "linux", "arm64"); d != nil {
		t.Errorf("该平台无包时不该下发更新, 实际: %+v", d)
	}
	// 探针未上报版本(极旧包): 应下发 —— 空版本不等于"已是最新"
	if d := centerUpdateDirective("", "windows", "amd64"); d == nil {
		t.Error("探针未上报版本时应下发更新(属于最该更新的情况)")
	}
}

// hasAll 判断 s 是否同时包含所有子串。
func hasAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
