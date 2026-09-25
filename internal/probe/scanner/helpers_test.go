package scanner

import (
	"yugsight/internal/normalizer"
	"yugsight/internal/scanner"
)

// helpers_test.go 测试构造辅助(仅测试文件使用, 不进生产二进制)。

// probeVulnForTest 构造一条探针漏洞(CVE / 协议 / 端口 / 标题可指定)。
func probeVulnForTest(ip, cve, proto string, port int, title string) normalizer.ProbeVuln {
	return normalizer.ProbeVuln{
		IP: ip, CVE: cve, Protocol: proto, Port: port, Title: title,
		Severity: "medium", Confidence: 60,
	}
}

// withSeverity 覆盖严重级别(测试排序用)。
func withSeverity(v normalizer.ProbeVuln, sev string) normalizer.ProbeVuln {
	v.Severity = sev
	return v
}

// probeAssetForTest 构造一条探针资产。
func probeAssetForTest(ip string, ports []int, banner string) normalizer.ProbeAsset {
	return normalizer.ProbeAsset{IP: ip, Ports: ports, Banner: banner}
}

// portResultsForTest 构造开放端口结果集(系统推断测试用)。
func portResultsForTest(ports ...int) []scanner.PortResult {
	out := make([]scanner.PortResult, 0, len(ports))
	for _, p := range ports {
		out = append(out, scanner.PortResult{Port: p, State: "open"})
	}
	return out
}
