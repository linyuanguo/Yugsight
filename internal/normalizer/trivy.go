package normalizer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

// Trivy 结果适配器：解析 trivy -f json 输出（镜像 / 依赖漏洞扫描）。
// Trivy 的扫描对象是容器镜像或文件（非 IP），以工件标识（镜像名 / 目标路径）
// 作为「资产 IP」字段参与归一化合并。

type trivyDoc struct {
	ArtifactName string        `json:"ArtifactName"`
	Results      []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string        `json:"Target"`
	Class           string        `json:"Class"`
	Type            string        `json:"Type"`
	Vulnerabilities []trivyVuln   `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string      `json:"VulnerabilityID"`
	PkgName          string      `json:"PkgName"`
	InstalledVersion string      `json:"InstalledVersion"`
	FixedVersion     string      `json:"FixedVersion"`
	Status           string      `json:"Status"`
	Severity         string      `json:"Severity"`
	Title            string      `json:"Title"`
	Description      string      `json:"Description"`
	Cvss             trivyCvss   `json:"Cvss"`
}

type trivyCvss struct {
	NVD    trivyScore `json:"NVD"`
	GitHub trivyScore `json:"GitHub"`
}

type trivyScore struct {
	Score float64 `json:"Score"`
}

// FromTrivyJSON 解析 trivy -f json 输出为归一化输入批次（仅漏洞）。
// Status=FIXED 的漏洞跳过（已修复，不计入当前漏洞）。
func FromTrivyJSON(data []byte) (*RawBatch, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("trivy: 输出为空")
	}
	var doc trivyDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("trivy: JSON 解析失败: %w", err)
	}
	b := &RawBatch{Source: SourceTrivy}
	artifact := strings.TrimSpace(doc.ArtifactName)
	for _, r := range doc.Results {
		target := strings.TrimSpace(r.Target)
		if target == "" {
			target = artifact
		}
		for _, v := range r.Vulnerabilities {
			if strings.EqualFold(strings.TrimSpace(v.Status), "fixed") {
				continue
			}
			cvss := math.Max(v.Cvss.NVD.Score, v.Cvss.GitHub.Score)
			title := strings.TrimSpace(v.Title)
			if title == "" {
				title = fmt.Sprintf("%s@%s 已知漏洞", v.PkgName, v.InstalledVersion)
			}
			desc := strings.TrimSpace(v.Description)
			if v.FixedVersion != "" {
				fix := fmt.Sprintf("修复: 升级 %s 到 %s", v.PkgName, v.FixedVersion)
				if desc == "" {
					desc = fix
				} else {
					desc += "\n" + fix
				}
			}
			b.Vulns = append(b.Vulns, RawVuln{
				AssetIP:     target,
				CVE:         v.VulnerabilityID,
				Title:       title,
				Severity:    v.Severity,
				Description: desc,
				CVSS:        cvss,
			})
		}
	}
	return b, nil
}
