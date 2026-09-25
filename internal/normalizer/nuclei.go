package normalizer

import (
	"strings"
	"time"
)

// 内置 Nuclei（Yugsight 内置模板引擎）结果适配器。
//
// 本包不依赖 scanner 包：调用方把引擎命中结果按 NucleiResult 的
// 字段口径（与 scanner.NucleiFinding 对齐）传入即可。

// NucleiResult 内置 Nuclei 模板单条命中。
type NucleiResult struct {
	Host        string    // 目标主机（IP / 域名）
	Port        int
	Scheme      string    // http / https
	TemplateID  string
	CVE         string
	Title       string
	Severity    string
	Detail      string
	Fix         string
	RawRequest  string
	RawResponse string
	Evidence    string
	FoundAt     time.Time
}

// FromNuclei 内置 Nuclei 命中批量转归一化输入批次。
func FromNuclei(host string, results []NucleiResult) *RawBatch {
	b := &RawBatch{Source: SourceNuclei}
	for _, r := range results {
		h := strings.TrimSpace(r.Host)
		if h == "" {
			h = host
		}
		protocol := strings.ToLower(strings.TrimSpace(r.Scheme))
		if protocol == "" {
			protocol = "tcp"
		}
		desc := strings.TrimSpace(r.Detail)
		if r.Fix != "" {
			fix := "修复建议: " + strings.TrimSpace(r.Fix)
			if desc == "" {
				desc = fix
			} else {
				desc += "\n" + fix
			}
		}
		b.Vulns = append(b.Vulns, RawVuln{
			AssetIP:     h,
			Port:        r.Port,
			Protocol:    protocol,
			CVE:         r.CVE,
			Title:       r.Title,
			Severity:    r.Severity,
			Description: desc,
			Evidence:    r.Evidence,
			Request:     r.RawRequest,
			Response:    r.RawResponse,
			FoundAt:     r.FoundAt,
		})
	}
	return b
}
