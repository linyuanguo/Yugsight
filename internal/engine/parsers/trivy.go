package parsers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"yugsight/internal/models"
	"yugsight/internal/normalizer"
)

// Trivy 输出解析(任务 6.2):
//
//   - 主口径为 trivy -f json 输出(资产 = 镜像名 / 目标路径, 漏洞 = CVE);
//   - 在此基础上补齐 normalizer.FromTrivyJSON 未覆盖的部分:
//     Misconfigurations(配置缺陷) / Secrets(硬编码凭据) / 修复建议字段,
//     以及 Trivy 多目标(一个镜像多个 Target)的资产聚合;
//   - 输出统一转为 normalizer.RawBatch, 资产 IP 字段用工件标识
//     (镜像名 / 路径), 与归一化模块既有口径一致(Trivy 扫描对象非 IP)。
//
// 兼容 trivy 0.4x ~ 0.5x 的字段命名差异(首字母大小写两种风格)。

// ===== JSON 结构 =====

type trivyReport struct {
	SchemaVersion int             `json:"SchemaVersion"`
	ArtifactName  string          `json:"ArtifactName"`
	ArtifactType  string          `json:"ArtifactType"`
	Metadata      trivyMetadata   `json:"Metadata"`
	Results       []trivyResultEx `json:"Results"`
}

type trivyMetadata struct {
	OS           trivyOSInfo `json:"OS"`
	ImageID      string      `json:"ImageID"`
	RepoTags     []string    `json:"RepoTags"`
	ImageConfig  struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"ImageConfig"`
}

type trivyOSInfo struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type trivyResultEx struct {
	Target           string            `json:"Target"`
	Class            string            `json:"Class"` // os-pkgs | lang-pkgs | config
	Type             string            `json:"Type"`  // debian | npm | ...
	Vulnerabilities  []trivyVulnEx     `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconf   `json:"Misconfigurations"`
	Secrets          []trivySecret     `json:"Secrets"`
}

type trivyVulnEx struct {
	VulnerabilityID  string     `json:"VulnerabilityID"`
	PkgID            string     `json:"PkgID"`
	PkgName          string     `json:"PkgName"`
	PkgPath          string     `json:"PkgPath"`
	InstalledVersion string     `json:"InstalledVersion"`
	FixedVersion     string     `json:"FixedVersion"`
	Status           string     `json:"Status"`
	Severity         string     `json:"Severity"`
	Title            string     `json:"Title"`
	Description      string     `json:"Description"`
	PrimaryURL       string     `json:"PrimaryURL"`
	References       []string   `json:"References"`
	CweIDs           []string   `json:"CweIDs"`
	Cvss             trivyCvssEx `json:"Cvss"`
	VendorSeverity   map[string]int `json:"VendorSeverity"`
}

type trivyCvssEx struct {
	NVD      trivyScoreEx `json:"NVD"`
	RedHat   trivyScoreEx `json:"RedHat"`
	GitHub   trivyScoreEx `json:"GitHub"`
	Bitnami  trivyScoreEx `json:"Bitnami"`
}

type trivyScoreEx struct {
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
	Score    float64 `json:"Score"`
}

type trivyMisconf struct {
	ID          string            `json:"ID"`
	AVDID       string            `json:"AVDID"`
	Title       string            `json:"Title"`
	Description string            `json:"Description"`
	Message     string            `json:"Message"`
	Resolution  string            `json:"Resolution"`
	Severity    string            `json:"Severity"`
	PrimaryURL  string            `json:"PrimaryURL"`
	Status      string            `json:"Status"`
	CauseMetadata trivyCause      `json:"CauseMetadata"`
}

type trivyCause struct {
	Resource  string `json:"Resource"`
	Provider  string `json:"Provider"`
	Service   string `json:"Service"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

type trivySecret struct {
	RuleID    string            `json:"RuleID"`
	Category  string            `json:"Category"`
	Severity  string            `json:"Severity"`
	Title     string            `json:"Title"`
	StartLine int               `json:"StartLine"`
	EndLine   int               `json:"EndLine"`
	Match     string            `json:"Match"`
	Code      trivyCause        `json:"Code"`
}

// ===== 入口 =====

// ParseTrivy 解析 Trivy JSON 输出(漏洞 + 配置缺陷 + 泄露凭据)为归一化批次。
// 解析失败时降级调用 normalizer.FromTrivyJSON(口径更窄但容错), 保证有数据可用。
func ParseTrivy(data []byte) (*Batch, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errEmpty("trivy")
	}
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		// 结构不符(旧版本 / 非预期输入): 尝试归一化模块的宽松适配器
		raw, ferr := normalizer.FromTrivyJSON(data)
		if ferr != nil {
			return nil, fmt.Errorf("trivy: JSON 解析失败: %w", err)
		}
		return &Batch{Source: normalizer.SourceTrivy, Assets: raw.Assets, Vulns: raw.Vulns,
			Warnings: []string{"trivy: 主解析器失败, 已降级为宽松适配器解析"}}, nil
	}

	b := &Batch{Source: normalizer.SourceTrivy}
	now := time.Now()
	artifact := strings.TrimSpace(rep.ArtifactName)
	if artifact == "" {
		artifact = firstTag(rep.Metadata.RepoTags)
	}
	if artifact == "" {
		artifact = strings.TrimSpace(rep.Metadata.ImageID)
	}

	// 资产: 工件标识(镜像名 / 路径) 作为资产键; 一个工件一条记录
	asset := normalizer.RawAsset{IP: artifact, FoundAt: now}
	if os := strings.TrimSpace(rep.Metadata.OS.Family); os != "" {
		if n := strings.TrimSpace(rep.Metadata.OS.Name); n != "" {
			asset.OS = os + " " + n
		} else {
			asset.OS = os
		}
	}
	if arch := strings.TrimSpace(rep.Metadata.ImageConfig.Architecture); arch != "" {
		asset.Tags = append(asset.Tags, "arch:"+arch)
	}
	if typ := strings.TrimSpace(rep.ArtifactType); typ != "" {
		asset.Tags = append(asset.Tags, "type:"+typ)
	}

	seenTarget := make(map[string]bool)
	for _, r := range rep.Results {
		target := strings.TrimSpace(r.Target)
		if target == "" {
			target = artifact
		}
		if target == "" {
			b.Warnings = append(b.Warnings, "trivy: 跳过无 Target 与 ArtifactName 的结果块")
			continue
		}
		if !seenTarget[target] {
			seenTarget[target] = true
			// 多目标时按目标补资产(包管理器维度也作为独立资产记录)
			t := normalizer.RawAsset{IP: target, FoundAt: now}
			if cls := strings.TrimSpace(r.Class); cls != "" {
				t.Tags = append(t.Tags, "class:"+cls)
			}
			if typ := strings.TrimSpace(r.Type); typ != "" {
				t.Tags = append(t.Tags, "type:"+typ)
			}
			b.Assets = append(b.Assets, t)
		}

		// 1) 依赖 / OS 包漏洞
		for _, v := range r.Vulnerabilities {
			if strings.EqualFold(strings.TrimSpace(v.Status), "fixed") {
				continue
			}
			b.Vulns = append(b.Vulns, trivyVulnToRaw(v, target))
		}
		// 2) 配置缺陷(Misconfiguration)
		for _, m := range r.Misconfigurations {
			b.Vulns = append(b.Vulns, trivyMisconfToRaw(m, target))
		}
		// 3) 泄露凭据(Secret)
		for _, s := range r.Secrets {
			b.Vulns = append(b.Vulns, trivySecretToRaw(s, target))
		}
	}

	if asset.IP == "" && len(b.Assets) == 0 {
		b.Warnings = append(b.Warnings, "trivy: 未解析到工件标识(ArtifactName / Target 均为空)")
	} else if asset.IP != "" {
		b.Assets = append([]normalizer.RawAsset{asset}, b.Assets...)
	}
	return b, nil
}

func firstTag(tags []string) string {
	for _, t := range tags {
		if s := strings.TrimSpace(t); s != "" {
			return s
		}
	}
	return ""
}

// trivyVulnToRaw 依赖 / OS 包漏洞 → 原始漏洞。
func trivyVulnToRaw(v trivyVulnEx, target string) normalizer.RawVuln {
	cvss := trivyMaxCVSS(v.Cvss)
	title := strings.TrimSpace(v.Title)
	if title == "" {
		title = strings.TrimSpace(v.VulnerabilityID)
	}
	if title == "" {
		title = fmt.Sprintf("%s@%s 已知漏洞", v.PkgName, v.InstalledVersion)
	}
	desc := strings.TrimSpace(v.Description)
	if v.FixedVersion != "" {
		desc = appendLine(desc, fmt.Sprintf("修复: 升级 %s 到 %s", v.PkgName, v.FixedVersion))
	}
	if v.PrimaryURL != "" {
		desc = appendLine(desc, "参考: "+v.PrimaryURL)
	}
	ev := strings.TrimSpace(v.PkgID)
	if ev == "" {
		ev = fmt.Sprintf("%s@%s", v.PkgName, v.InstalledVersion)
	}
	if p := strings.TrimSpace(v.PkgPath); p != "" {
		ev += " (" + p + ")"
	}
	cve := ""
	if models.IsCVE(v.VulnerabilityID) {
		cve = models.NormalizeCVE(v.VulnerabilityID)
	}
	return normalizer.RawVuln{
		AssetIP:     target,
		CVE:         cve,
		Title:       title,
		Severity:    v.Severity,
		Description: desc,
		Evidence:    ev,
		CVSS:        cvss,
	}
}

// trivyMisconfToRaw 配置缺陷 → 原始漏洞(无 CVE, 用规则 ID 作标题)。
func trivyMisconfToRaw(m trivyMisconf, target string) normalizer.RawVuln {
	id := firstNonEmpty(m.AVDID, m.ID)
	title := strings.TrimSpace(m.Title)
	if title == "" {
		title = id
	}
	if id != "" && title != id {
		title = title + " (" + id + ")"
	}
	desc := firstNonEmpty(m.Description, m.Message)
	if r := strings.TrimSpace(m.Resolution); r != "" {
		desc = appendLine(desc, "修复建议: "+r)
	}
	ev := strings.TrimSpace(m.CauseMetadata.Resource)
	if ev == "" {
		ev = target
	}
	if l := m.CauseMetadata.StartLine; l > 0 {
		ev += fmt.Sprintf(":%d", l)
	}
	if p := strings.TrimSpace(m.PrimaryURL); p != "" {
		desc = appendLine(desc, "参考: "+p)
	}
	if title == "" {
		title = "配置缺陷"
	}
	return normalizer.RawVuln{
		AssetIP:     target,
		Title:       title,
		Severity:    m.Severity,
		Description: desc,
		Evidence:    ev,
	}
}

// trivySecretToRaw 泄露凭据 → 原始漏洞(不落原始密文, 只留位置与规则)。
func trivySecretToRaw(s trivySecret, target string) normalizer.RawVuln {
	title := firstNonEmpty(s.Title, s.RuleID)
	if s.Category != "" {
		title = strings.TrimSpace(title + " [" + s.Category + "]")
	}
	if title == "" {
		title = "疑似硬编码凭据"
	}
	desc := "检测到疑似硬编码凭据(已脱敏, 不记录原始内容)"
	if s.RuleID != "" {
		desc = appendLine(desc, "规则: "+s.RuleID)
	}
	ev := strings.TrimSpace(s.Code.Resource)
	if ev == "" {
		ev = target
	}
	if l := firstNonZero(s.StartLine, s.Code.StartLine); l > 0 {
		ev += fmt.Sprintf(":%d", l)
	}
	return normalizer.RawVuln{
		AssetIP:     target,
		Title:       title,
		Severity:    s.Severity,
		Description: desc,
		Evidence:    ev,
	}
}

// trivyMaxCVSS 取各来源 CVSS 最高分(V3 优先, 回退 Score/V2)。
func trivyMaxCVSS(c trivyCvssEx) float64 {
	scores := []trivyScoreEx{c.NVD, c.RedHat, c.GitHub, c.Bitnami}
	best := 0.0
	for _, s := range scores {
		for _, v := range []float64{s.V3Score, s.Score, s.V2Score} {
			if v > best && v <= 10 {
				best = v
			}
		}
	}
	if math.IsNaN(best) || math.IsInf(best, 0) {
		return 0
	}
	return best
}

func appendLine(base, line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return base
	}
	if base == "" {
		return line
	}
	return base + "\n" + line
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
