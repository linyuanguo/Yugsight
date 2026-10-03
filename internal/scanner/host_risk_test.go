package scanner

// 守"端口开放不报高危"的口径(2026-09-25 用户反馈: "MySQL 数据库端口开放"
// 标成高危不对 —— 不开放就没法连接, 端口开放是正常业务状态)。
//
// 契约: 纯"端口/服务开放"类静态规则(没有验证认证配置/已知漏洞)不得用 high;
// 高危必须留给真实验证过的发现(弱口令命中、CVE 版本匹配、POC 成功)。

import "testing"

func TestServiceRiskNoHighForOpenPorts(t *testing.T) {
	for _, sr := range serviceRisks {
		if sr.severity == "high" {
			t.Errorf("端口 %d(%s) 被标为 high —— '端口开放'是正常业务状态, 静态规则不许报高危", sr.port, sr.title)
		}
	}
}
