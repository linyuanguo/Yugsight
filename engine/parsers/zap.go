package parsers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"yugsight/models"
	"yugsight/normalizer"
)

// ZAP 输出解析(任务 6.2):
//
//   - 主口径为 ZAP JSON 报告(-J <file>), 结构 site[].alerts[];
//   - 在 normalizer.FromZAPJSON 基础上补齐:
//     URL / 参数(parameter) / 攻击载荷(attack) / 证据(evidence) /
//     CWE 编号 / 可信度 / 修复建议(含 References), 并输出更细的资产(含路径);
//   - 兼容 ZAP 2.x 的 report 包裹结构({"site": [...]} 与 {"Report":{"site":[...]}}),
//     以及 alerts 的 0-3 风险码 / riskdesc 文本两种等级表达。
//
// 注意: ZAP JSON 不支持输出到 stdout(必须落文件), 调用方读文件后传入。

// ===== JSON 结构 =====

type zapReport struct {
	Site   []zapSiteEx `json:"site"`
	Report *struct {
		Site []zapSiteEx `json:"site"`
	} `json:"Report"`
}

type zapSiteEx struct {
	Name      string        `json:"name"`
	Host      string        `json:"host"`
	Port      string        `json:"port"`
	SSL       bool          `json:"ssl"`
	Alerts    []zapAlertEx  `json:"alerts"`
}

type zapAlertEx struct {
	PluginID       string      `json:"pluginid"`
	AlertRef       string      `json:"alertRef"`
	Name           string      `json:"name"`
	RiskCode       json.Number `json:"riskcode"`
	Confidence     string      `json:"confidence"`
	ConfidenceCode json.Number `json:"confidencecode"`
	RiskDesc       string      `json:"riskdesc"`
	Desc           string      `json:"desc"`
	Instances      []zapInstance `json:"instances"`
	// 老版本 / -J 输出为单实例平铺字段
	URI       string `json:"uri"`
	Method    string `json:"method"`
	Param     string `json:"param"`
	Parameter string `json:"parameter"`
	Attack    string `json:"attack"`
	Evidence  string `json:"evidence"`
	OtherInfo string `json:"otherinfo"`
	Solution  string `json:"solution"`
	Reference string `json:"reference"`
	CWEID     json.Number `json:"cweid"`
	WASCID    json.Number `json:"wascid"`
	Tags      []string    `json:"tags"`
}

type zapInstance struct {
	URI       string      `json:"uri"`
	Method    string      `json:"method"`
	Param     string      `json:"param"`
	Attack    string      `json:"attack"`
	Evidence  string      `json:"evidence"`
	OtherInfo string      `json:"otherinfo"`
	RID       json.Number `json:"id"`
}

// ===== 入口 =====

// ParseZap 解析 ZAP JSON 报告为归一化批次(资产 + Web 漏洞)。
func ParseZap(data []byte) (*Batch, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errEmpty("zap")
	}
	var rep zapReport
	if err := json.Unmarshal(data, &rep); err != nil {
		raw, ferr := normalizer.FromZAPJSON(data)
		if ferr != nil {
			return nil, fmt.Errorf("zap: JSON 解析失败: %w", err)
		}
		return &Batch{Source: normalizer.SourceZAP, Assets: raw.Assets, Vulns: raw.Vulns,
			Warnings: []string{"zap: 主解析器失败, 已降级为宽松适配器解析"}}, nil
	}
	sites := rep.Site
	if len(sites) == 0 && rep.Report != nil {
		sites = rep.Report.Site
	}
	if len(sites) == 0 {
		// 结构可解析但无站点: 再退一次宽松适配器(可能为其它 ZAP 变体)
		if raw, ferr := normalizer.FromZAPJSON(data); ferr == nil && len(raw.Vulns) > 0 {
			return &Batch{Source: normalizer.SourceZAP, Assets: raw.Assets, Vulns: raw.Vulns,
				Warnings: []string{"zap: 站点结构与预期不符, 已降级为宽松适配器解析"}}, nil
		}
		return nil, fmt.Errorf("zap: 报告中未找到站点(site)数据")
	}

	b := &Batch{Source: normalizer.SourceZAP}
	now := time.Now()
	for _, site := range sites {
		host, port, scheme := zapSiteTarget(site)
		if host == "" {
			b.Warnings = append(b.Warnings, "zap: 跳过无法解析主机名的站点: "+strings.TrimSpace(site.Name))
			continue
		}
		b.Assets = append(b.Assets, normalizer.RawAsset{
			IP:      host,
			Ports:   []int{port},
			Service: scheme,
			Tags:    []string{"web"},
			FoundAt: now,
		})
		for _, al := range site.Alerts {
			insts := al.Instances
			if len(insts) == 0 {
				// 平铺结构: 单实例
				insts = []zapInstance{{
					URI: al.URI, Method: al.Method, Param: firstNonEmpty(al.Parameter, al.Param),
					Attack: al.Attack, Evidence: al.Evidence, OtherInfo: al.OtherInfo,
				}}
			}
			sev := zapSeverity(al)
			conf := zapConfidence(al)
			// 归一化合并键口径为「资产 + CVE」/「资产 + 协议:端口 + 标题」,
			// 不含 URL 路径 —— 同一告警的多条实例(同一资产同一标题)会被归一化层
			// 合并成一条漏洞(全部证据保留在 EvidenceRecords)。
			// 这里保持"每实例一条"的原始粒度, 让归一化层统一去重合并。
			for _, inst := range insts {
				if v, ok := zapAlertToVuln(al, inst, host, port, scheme, sev, conf); ok {
					v.FoundAt = now
					b.Vulns = append(b.Vulns, v)
				}
			}
		}
	}
	return b, nil
}

// zapSiteTarget 解析站点为 主机 / 端口 / 协议:
// 优先 site.host + site.port + site.ssl, 回退站点名(URL 或裸主机)。
func zapSiteTarget(s zapSiteEx) (host string, port int, scheme string) {
	host = strings.TrimSpace(s.Host)
	if host == "" {
		host, port, scheme = parseZapSiteName(s.Name)
	}
	if host == "" {
		return "", 0, ""
	}
	if p, err := strconv.Atoi(strings.TrimSpace(s.Port)); err == nil && p > 0 {
		port = p
	}
	if s.SSL {
		scheme = "https"
	}
	switch {
	case scheme == "" && port == 443:
		scheme = "https"
	case scheme == "":
		scheme = "http"
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

// parseZapSiteName 解析 ZAP 站点名(URL 或裸主机)为 主机 / 端口 / 协议。
func parseZapSiteName(name string) (host string, port int, scheme string) {
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
	return name, 0, ""
}

// zapSeverity 风险等级: riskcode(0-3) 优先, 回退 riskdesc 文本。
func zapSeverity(al zapAlertEx) string {
	if code, err := al.RiskCode.Int64(); err == nil {
		switch code {
		case 3:
			return models.SeverityHigh
		case 2:
			return models.SeverityMedium
		case 1:
			return models.SeverityLow
		case 0:
			return models.SeverityInfo
		}
	}
	// riskdesc 形如 "High (Medium)" / "Informational"
	desc := strings.TrimSpace(al.RiskDesc)
	if i := strings.IndexAny(desc, " ("); i > 0 {
		desc = desc[:i]
	}
	return models.NormalizeSeverity(desc)
}

// zapConfidence 可信度: confidencecode(0-5) * 20, 无码时按文本给经验值。
func zapConfidence(al zapAlertEx) int {
	if code, err := al.ConfidenceCode.Int64(); err == nil && code >= 0 {
		if c := int(code) * 20; c > 0 && c <= 100 {
			return c
		}
	}
	switch strings.ToLower(strings.TrimSpace(al.Confidence)) {
	case "confirmed", "high":
		return 90
	case "medium":
		return 60
	case "low":
		return 30
	default:
		return 0
	}
}

// zapAlertToVuln 单条告警 + 单实例 → 原始漏洞。
// 提取 URL / 方法 / 参数 / 攻击载荷 / 证据, 并在描述中附修复建议与参考。
func zapAlertToVuln(al zapAlertEx, inst zapInstance, host string, port int, scheme string, sev string, conf int) (normalizer.RawVuln, bool) {
	title := strings.TrimSpace(al.Name)
	if title == "" {
		return normalizer.RawVuln{}, false
	}

	// 实例 URI 可能带路径, 但漏洞资产的归属仍按站点主机(归一化按 IP/主机聚合),
	// 完整 URL 保留在证据与请求里, 不丢失定位信息
	uri := strings.TrimSpace(inst.URI)
	method := strings.TrimSpace(inst.Method)
	param := firstNonEmpty(inst.Param, al.Parameter, al.Param)
	attack := strings.TrimSpace(inst.Attack)

	desc := strings.TrimSpace(al.Desc)
	if p := strings.TrimSpace(param); p != "" {
		desc = appendLine(desc, "参数: "+p)
	}
	if a := attack; a != "" {
		desc = appendLine(desc, "攻击载荷: "+a)
	}
	if oi := strings.TrimSpace(inst.OtherInfo); oi != "" {
		desc = appendLine(desc, "补充: "+oi)
	}
	if cwe, err := al.CWEID.Int64(); err == nil && cwe > 0 {
		desc = appendLine(desc, fmt.Sprintf("CWE-%d", cwe))
	}
	if sol := strings.TrimSpace(al.Solution); sol != "" {
		desc = appendLine(desc, "修复建议: "+sol)
	}
	if ref := strings.TrimSpace(al.Reference); ref != "" {
		desc = appendLine(desc, "参考: "+ref)
	}

	evidence := strings.TrimSpace(inst.Evidence)
	if evidence == "" {
		evidence = strings.TrimSpace(inst.OtherInfo)
	}
	if evidence == "" {
		evidence = uri
	}
	request := ""
	if method != "" && uri != "" {
		request = method + " " + uri
	} else if uri != "" {
		request = uri
	}
	if param != "" {
		request = appendLine(request, "参数: "+param)
	}
	if attack != "" {
		request = appendLine(request, "载荷: "+attack)
	}

	protocol := scheme
	if protocol == "" {
		protocol = "http"
	}
	return normalizer.RawVuln{
		AssetIP:     host,
		Port:        port,
		Protocol:    protocol,
		Title:       title,
		Severity:    sev,
		Description: desc,
		Evidence:    evidence,
		Request:     request,
		Confidence:  conf,
	}, true
}
