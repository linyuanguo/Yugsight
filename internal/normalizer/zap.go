package normalizer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"yugsight/internal/models"
)

// ZAP 结果适配器：解析 OWASP ZAP JSON 报告（site / alerts 结构）。

type zapDoc struct {
	Site []zapSite `json:"site"`
}

type zapSite struct {
	Name   string     `json:"name"`
	Alerts []zapAlert `json:"alerts"`
}

type zapAlert struct {
	Name           string `json:"name"`
	RiskCode       int    `json:"riskcode"`
	ConfidenceCode int    `json:"confidencecode"`
	RiskDesc       string `json:"riskdesc"`
	Desc           string `json:"desc"`
	Detail         string `json:"detail"`
	Evidence       string `json:"evidence"`
	URI            string `json:"uri"`
	Method         string `json:"method"`
	Parameter      string `json:"parameter"`
	Attack         string `json:"attack"`
	Solution       string `json:"solution"`
}

// FromZAPJSON 解析 ZAP JSON 报告为归一化输入批次（资产 + 漏洞）。
func FromZAPJSON(data []byte) (*RawBatch, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("zap: 输出为空")
	}
	var doc zapDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("zap: JSON 解析失败: %w", err)
	}
	b := &RawBatch{Source: SourceZAP}
	for _, site := range doc.Site {
		host, port, scheme := parseSiteName(site.Name)
		if host == "" {
			continue
		}
		b.Assets = append(b.Assets, RawAsset{
			IP:      host,
			Ports:   []int{port},
			Service: scheme,
		})
		for _, al := range site.Alerts {
			sev := ""
			switch al.RiskCode {
			case 3:
				sev = models.SeverityHigh
			case 2:
				sev = models.SeverityMedium
			case 1:
				sev = models.SeverityLow
			case 0:
				sev = models.SeverityInfo
			default:
				sev = models.NormalizeSeverity(al.RiskDesc)
			}
			request := ""
			if al.Method != "" {
				request = strings.Join([]string{al.Method, al.URI}, " ")
			}
			desc := strings.TrimSpace(al.Desc)
			if al.Solution != "" {
				fix := "修复建议: " + al.Solution
				if desc == "" {
					desc = fix
				} else {
					desc += "\n" + fix
				}
			}
			b.Vulns = append(b.Vulns, RawVuln{
				AssetIP:     host,
				Port:        port,
				Protocol:    scheme,
				Title:       strings.TrimSpace(al.Name),
				Severity:    sev,
				Description: desc,
				Evidence:    strings.TrimSpace(al.Evidence),
				Request:     request,
				Confidence:  al.ConfidenceCode * 20, // ZAP 置信度 0-5 → 0-100
			})
		}
	}
	return b, nil
}

// parseSiteName 解析 ZAP 站点名（URL 或裸主机）为 主机 / 端口 / 协议。
func parseSiteName(name string) (host string, port int, scheme string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", 0, ""
	}
	if u, err := url.Parse(name); err == nil && u.Host != "" {
		host = u.Hostname()
		scheme = strings.ToLower(u.Scheme)
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		if scheme == "" {
			if port == 443 {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}
		if port == 0 {
			if scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
		return host, port, scheme
	}
	if h, p, err := net.SplitHostPort(name); err == nil {
		port, _ = strconv.Atoi(p)
		return h, port, "http"
	}
	return name, 80, "http"
}
