//go:build !windows || windows

// model.go 全局统一资产 / 漏洞标准模型(供后续归一化模块复用)。
//
// 设计:
//   - Asset 统一资产模型: IP + 端口 + 协议 + 服务指纹(产品/版本) + 操作系统,
//     ID 为 Key() 的稳定哈希(同一资产跨扫描稳定, 可作数据库主键/归一化键);
//     与既有 ServiceAsset(执行器输入) 双向兼容(AssetFromServiceAsset)
//   - Vulnerability 统一漏洞模型: 资产 + 漏洞标识(CVE/规则 ID/来源) +
//     严重度(CVSS) + 置信度(0-100, 见 confidence.go) + 匹配类型
//     (version 版本匹配型 / verified 实际验证型, 见 cpe_engine.go) +
//     KEV 标记与 EPSS 分值(自动从情报集 intel.go 填充) + 证据/修复建议
//     + 白名单标记(自动判定, 见 whitelist.go)
//   - 转换函数: 各扫描引擎的原始结果(Finding / NucleiFinding /
//     CPEEngineMatch) 统一转为 Vulnerability, 后续归一化模块只面对
//     本模型, 不再关心各引擎的私有结构
//   - 去重: DedupVulns 按稳定键 (资产 ID | CVE | 规则 ID | 标题) 去重
//
// 依赖: 仅 Go 标准库(复用同包 sha256Hex / intel / confidence / whitelist)。
package scanner

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ===== 统一资产模型 =====

// Asset 统一资产模型(归一化输出单元: 一台主机的一个服务端口)。
// ID 为 Key() 的 SHA1 前 16 位, 跨扫描稳定(不随时间变化)。
type Asset struct {
	ID      string    `json:"id"`
	IP      string    `json:"ip"`
	Port    int       `json:"port"`
	Scheme  string    `json:"scheme"` // http / https / ""(非 Web 服务)
	Product string    `json:"product"` // 服务指纹产品键(nginx/apache/redis...)
	Version string    `json:"version"` // 版本号(可能为空)
	OS      string    `json:"os,omitempty"`
	Banner  string    `json:"banner,omitempty"`
	Alive   bool      `json:"alive"`
	Ports   []int     `json:"ports,omitempty"` // 主机级开放端口(主机维度填充, 端口维度可空)
	FoundAt time.Time `json:"foundAt"`
}

// Key 资产归一化键: 默认端口省略(与 ServiceAsset.HostPort 口径一致)
func (a Asset) Key() string {
	if a.Scheme == "http" && a.Port == 80 || a.Scheme == "https" && a.Port == 443 {
		return a.IP + "/" + a.Scheme
	}
	return a.IP + ":" + itoa(a.Port) + "/" + a.Scheme
}

// NewAsset 构造统一资产并计算稳定 ID
func NewAsset(ip string, port int, scheme, product, version string) Asset {
	a := Asset{
		IP:      strings.TrimSpace(ip),
		Port:    port,
		Scheme:  strings.ToLower(strings.TrimSpace(scheme)),
		Product: productKey(strings.TrimSpace(product)),
		Version: strings.TrimSpace(version),
		Alive:   true,
		FoundAt: time.Now(),
	}
	a.ID = assetID(a)
	return a
}

// AssetFromServiceAsset 从执行器输入单元 ServiceAsset 转为统一资产模型
func AssetFromServiceAsset(a ServiceAsset) Asset {
	return NewAsset(a.IP, a.Port, a.Scheme, a.Product, a.Version)
}

func assetID(a Asset) string {
	sum := sha1.Sum([]byte(a.Key()))
	return hex.EncodeToString(sum[:])[:16]
}

// ===== 统一漏洞模型 =====

// 漏洞来源标记(与 NucleiFinding.Source / Finding 体系对齐并扩展)
const (
	VulnSourceBuiltin   = "builtin"        // 内置正则规则(vuln_builtin.json / vuln/)
	VulnSourceNuclei    = "nuclei"         // 外部 Nuclei 模板
	VulnSourceNucleiBS  = "nuclei-builtin" // 内置 Nuclei 模板(exe 打包)
	VulnSourceCPE       = "cpe"            // CPE 版本匹配引擎
	VulnSourceHost      = "host"           // 主机扫描主动探测(如 Redis 未授权)
)

// Vulnerability 统一漏洞模型(标准化输出, 供归一化模块复用)
type Vulnerability struct {
	ID              string    `json:"id"` // 稳定唯一 ID(SHA1 前 16 位, 见 Key)
	AssetID         string    `json:"assetId"`
	Asset           Asset     `json:"asset"` // 内嵌全量资产(报告免二次查询)
	CVE             string    `json:"cve,omitempty"`
	RuleID          string    `json:"ruleId,omitempty"` // 模板 ID / YUGSIGHT-000X
	Source          string    `json:"source"`           // 见 VulnSource* 常量
	Title           string    `json:"title"`
	Severity        string    `json:"severity"` // critical/high/medium/low/info
	CVSS            float64   `json:"cvss,omitempty"`
	Confidence      int       `json:"confidence"`      // 0-100(confidence.go 基础计算)
	ConfidenceLevel string    `json:"confidenceLevel"` // high/medium/low
	MatchType       string    `json:"matchType"`       // version / verified
	KeV             bool      `json:"kev,omitempty"`   // CISA KEV(已知被利用)
	Epss            float64   `json:"epss,omitempty"`  // EPSS 分值(0-1)
	Detail          string    `json:"detail,omitempty"`
	Fix             string    `json:"fix,omitempty"`
	Evidence        string    `json:"evidence,omitempty"` // 证据(限量, 防报告膨胀)
	Whitelisted     bool      `json:"whitelisted"`        // 白名单命中(whitelist.go)
	FoundAt         time.Time `json:"foundAt"`
}

// Key 去重键: 资产 ID | CVE | 规则 ID | 标题(无 CVE 时以规则 ID/标题兜底)
func (v Vulnerability) Key() string {
	return v.AssetID + "|" + normCVE(v.CVE) + "|" + v.RuleID + "|" + strings.TrimSpace(v.Title)
}

func vulnID(v Vulnerability) string {
	sum := sha1.Sum([]byte(v.Key()))
	return hex.EncodeToString(sum[:])[:16]
}

// knownCVEHit CVE 号是否在已知漏洞情报中(KEV / EPSS 任一命中)
func knownCVEHit(cve string) bool {
	if cve == "" {
		return false
	}
	if _, ok := IsKEV(cve); ok {
		return true
	}
	_, ok := EPSSScore(cve)
	return ok
}

// NewVulnerability 构造统一漏洞模型: 自动计算 ID / 置信度 / KEV / EPSS / 白名单标记。
// evidenceType 为证据类型(status/header/word/regex/dsl/body/banner/cert/""),
// evidenceText 为证据原文(自动限量 20KB)。
func NewVulnerability(a Asset, source, ruleID, cve, title, severity, matchType, evidenceType string, cvss float64, detail, fix, evidenceText string) *Vulnerability {
	v := Vulnerability{
		Asset:         a,
		AssetID:       a.ID,
		CVE:           normCVE(cve),
		RuleID:        strings.TrimSpace(ruleID),
		Source:        source,
		Title:         strings.TrimSpace(title),
		Severity:      severity,
		CVSS:          cvss,
		MatchType:     matchType,
		Detail:        detail,
		Fix:           fix,
		Evidence:      truncateEvidence(evidenceText),
		FoundAt:       time.Now(),
	}
	v.Confidence, v.ConfidenceLevel = CalculateConfidence(ConfidenceInput{
		MatchType:  v.MatchType,
		Evidence:   evidenceType,
		HasVersion: a.Version != "",
		KnownCVE:   knownCVEHit(v.CVE),
		Severity:   v.Severity,
	})
	if e, ok := IsKEV(v.CVE); ok {
		v.KeV = true
		_ = e
	}
	if s, ok := EPSSScore(v.CVE); ok {
		v.Epss = s
	}
	v.Whitelisted, _ = IsWhitelisted(&v)
	v.ID = vulnID(v)
	return &v
}

// FromFinding 从内置正则规则命中(Finding) 转统一漏洞模型。
// 正则规则命中 = 请求实际发出且响应匹配, 属主动验证型, 证据按 regex 计。
func FromFinding(a Asset, f Finding, source, ruleID, cve string) *Vulnerability {
	return NewVulnerability(a, source, ruleID, cve, f.Title, f.Severity,
		MatchTypeVerified, "regex", 0, f.Detail, f.Fix, "")
}

// FromNucleiFinding 从 Nuclei 模板命中转统一漏洞模型。
// source 取 NucleiFinding.Source("nuclei" / "nuclei-builtin");
// 证据取原始响应(限量 20KB)。
func FromNucleiFinding(a ServiceAsset, f NucleiFinding) *Vulnerability {
	src := f.Source
	if src == "" {
		src = VulnSourceNuclei
	}
	asset := AssetFromServiceAsset(a)
	title := f.Title
	if f.CVE != "" && !strings.Contains(title, f.CVE) {
		title = title + " (" + f.CVE + ")"
	}
	return NewVulnerability(asset, src, f.TemplateID, f.CVE, title, f.Severity,
		MatchTypeVerified, "word", 0, f.Detail, f.Fix, f.RawResponse)
}

// FromCPEMatches 从 CPE 引擎匹配结果转统一漏洞模型列表(版本匹配型)。
// 每条 CVE 一个 Vulnerability, 置信度按 version 类型基础计算;
// severity 由 CVSS 分值换算(CVSSSeverity)。
func FromCPEMatches(a Asset, ms []CPEEngineMatch) []*Vulnerability {
	var out []*Vulnerability
	for _, m := range ms {
		for _, cv := range m.CVEs {
			out = append(out, NewVulnerability(
				a, VulnSourceCPE, "", cv.ID,
				fmt.Sprintf("[%s %s] 已知漏洞 %s (版本匹配型, 未实际验证)", m.Product, m.Version, cv.ID),
				CVSSSeverity(cv.CVSS), MatchTypeVersion, "", cv.CVSS,
				cv.Description, cv.Fix, "",
			))
		}
	}
	return out
}

// DedupVulns 按稳定键去重(同资产同漏洞只保留第一条), 输入顺序决定保留次序
func DedupVulns(vs []*Vulnerability) []*Vulnerability {
	seen := map[string]bool{}
	var out []*Vulnerability
	for _, v := range vs {
		if v == nil || seen[v.Key()] {
			continue
		}
		seen[v.Key()] = true
		out = append(out, v)
	}
	return out
}

// SortByPriority 按优先级排序漏洞列表(返回新切片):
// KEV 优先 -> EPSS 降序 -> CVSS 降序 -> 标题升序(同分稳定)。
// 与 PrioritizeRules 的排序口径一致, 供报告/前端"高危在前"展示。
func SortByPriority(vs []*Vulnerability) []*Vulnerability {
	out := make([]*Vulnerability, len(vs))
	copy(out, vs)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.KeV != b.KeV {
			return a.KeV
		}
		if a.Epss != b.Epss {
			return a.Epss > b.Epss
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return a.Title < b.Title
	})
	return out
}

// truncateEvidence 证据限量(前 20KB, 与 nuclei_runner.go evidenceLimit 同口径)
func truncateEvidence(s string) string {
	if len(s) <= evidenceLimit {
		return s
	}
	return s[:evidenceLimit]
}
