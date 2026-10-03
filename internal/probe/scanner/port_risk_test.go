package scanner

// 守"端口开放不报高危"的口径(与中心端 scanner 同一契约, 2026-09-25):
// 探针回传的风险级别会进中心端漏洞库与报告, 两端口径必须一致。

import "testing"

func TestPortRiskNoHighForOpenPorts(t *testing.T) {
	ports := []int{21, 23, 135, 139, 445, 3306, 3389, 5432, 5900, 6379, 7001, 9200, 11211, 1433, 2375, 27017}
	for _, p := range ports {
		sev, title, _ := portRisk(p)
		if sev == "high" {
			t.Errorf("端口 %d(%s) 被标为 high —— '端口开放'是正常业务状态, 静态规则不许报高危", p, title)
		}
	}
}
