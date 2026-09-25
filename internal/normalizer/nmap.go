package normalizer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"yugsight/internal/models"
)

// Nmap 结果适配器：解析 nmap -oJ（JSON）输出。
// 仅解析外部 Nmap 引擎的标准输出格式（资产 + NSE 漏洞插件），不依赖 nmap 进程。

type nmapDoc struct {
	Hosts []nmapHost `json:"hosts"`
}

type nmapHost struct {
	Address    string      `json:"address"`
	Hostnames  []nmapName  `json:"hostnames"`
	MACAddress string      `json:"mac-address"`
	OS         []nmapName  `json:"os"`
	State      nmapState   `json:"state"`
	Ports      []nmapPort  `json:"ports"`
	Vulns      []nmapVuln  `json:"vulns"`
}

type nmapName struct {
	Name string `json:"name"`
}

type nmapState struct {
	State string `json:"state"`
}

type nmapPort struct {
	PortID   int         `json:"portid"`
	Protocol string      `json:"protocol"`
	State    nmapState   `json:"state"`
	Service  nmapService `json:"service"`
	Vulns    []nmapVuln  `json:"vulns"`
}

type nmapService struct {
	Name      string `json:"name"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	ExtraInfo string `json:"extrainfo"`
}

type nmapVuln struct {
	ID          string      `json:"id"`
	ScriptID    string      `json:"script-id"`
	State       string      `json:"state"`
	Severity    interface{} `json:"severity"`
	Description string      `json:"description"`
}

// FromNmapJSON 解析 nmap -oJ 输出为归一化输入批次（资产 + 漏洞）。
func FromNmapJSON(data []byte) (*RawBatch, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("nmap: 输出为空")
	}
	var doc nmapDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("nmap: JSON 解析失败: %w", err)
	}
	b := &RawBatch{Source: SourceNmap}
	for _, h := range doc.Hosts {
		if models.NormIP(h.Address) == "" {
			continue
		}
		asset := RawAsset{
			IP:       h.Address,
			MAC:      h.MACAddress,
			Hostname: firstNmapName(h.Hostnames),
			OS:       firstNmapName(h.OS),
		}
		for _, p := range h.Ports {
			if !p.open() {
				continue
			}
			asset.Ports = append(asset.Ports, p.PortID)
			if asset.Service == "" && strings.TrimSpace(p.Service.Name) != "" {
				asset.Service = p.Service.Name
				asset.Version = p.Service.Version
				asset.Banner = p.Service.ExtraInfo
			}
		}
		b.Assets = append(b.Assets, asset)
		for _, v := range h.Vulns {
			if v.active() {
				b.Vulns = append(b.Vulns, nmapVulnToRaw(v, h.Address, 0, ""))
			}
		}
		for _, p := range h.Ports {
			if !p.open() {
				continue
			}
			for _, v := range p.Vulns {
				if v.active() {
					b.Vulns = append(b.Vulns, nmapVulnToRaw(v, h.Address, p.PortID, p.Protocol))
				}
			}
		}
	}
	return b, nil
}

func (p nmapPort) open() bool { return p.State.State == "open" }

// active 漏洞插件状态是否表示命中（vulnerable / exploitable / detected）。
func (v nmapVuln) active() bool {
	return v.State == "vulnerable" || v.State == "exploitable" || v.State == "detected"
}

func firstNmapName(ns []nmapName) string {
	for _, n := range ns {
		if s := strings.TrimSpace(n.Name); s != "" {
			return s
		}
	}
	return ""
}

// nmapVulnToRaw NSE 漏洞插件结果转原始漏洞。
// 非 CVE 插件 ID（如 default-credentials）不进 CVE 字段，仅进标题。
func nmapVulnToRaw(v nmapVuln, ip string, port int, protocol string) RawVuln {
	cve := ""
	if models.IsCVE(v.ID) {
		cve = models.NormalizeCVE(v.ID)
	}
	title := strings.TrimSpace(v.ScriptID)
	if title == "" {
		title = v.ID
	}
	if cve != "" && !strings.Contains(title, cve) {
		title = cve + " (" + title + ")"
	}
	desc := strings.TrimSpace(v.Description)
	if v.State != "" {
		if desc == "" {
			desc = "状态: " + v.State
		} else {
			desc += "\n状态: " + v.State
		}
	}
	cvss := parseNmapSeverity(v.Severity)
	return RawVuln{
		AssetIP:     ip,
		Port:        port,
		Protocol:    protocol,
		CVE:         cve,
		Title:       title,
		Description: desc,
		CVSS:        cvss,
	}
}

// parseNmapSeverity 解析 Nmap 灵活的 severity 格式：
// 字符串 "9.8" 或对象 {"type":"CVSSv3","value":"9.8"}，返回 CVSS 分值（0 = 未知）。
func parseNmapSeverity(s interface{}) float64 {
	switch v := s.(type) {
	case float64:
		return v
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return 0
		}
		return f
	case map[string]interface{}:
		val, ok := v["value"]
		if !ok {
			return 0
		}
		if s2, ok := val.(string); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(s2), 64)
			if err != nil {
				return 0
			}
			return f
		}
		if f, ok := val.(float64); ok {
			return f
		}
	}
	return 0
}
