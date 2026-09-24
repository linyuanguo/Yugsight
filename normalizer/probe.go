package normalizer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"yugsight/models"
)

// 远端探针上报适配器：解析探针节点上报的标准 JSON 报告。
//
// 报告格式（探针 → 控制端）：
//
//	{
//	  "nodeId": "probe-01",
//	  "scanId": "scan-xxx",
//	  "time": "2026-09-16T10:00:00Z",
//	  "assets": [{"ip":"...","mac":"...","hostname":"...","os":"...","ports":[22,80],
//	              "service":"ssh","version":"","banner":"...","tags":["..."]}],
//	  "vulns":  [{"ip":"...","port":80,"protocol":"http","cve":"CVE-...","title":"...",
//	              "severity":"high","description":"...","evidence":"...",
//	              "request":"...","response":"...","cvss":9.8,"confidence":90,
//	              "pcapFile":"...","foundAt":"..."}]
//	}

// ProbeAsset 探针节点上报的资产。
type ProbeAsset struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac"`
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Ports    []int    `json:"ports"`
	Service  string   `json:"service"`
	Version  string   `json:"version"`
	Banner   string   `json:"banner"`
	Tags     []string `json:"tags"`
}

// ProbeVuln 探针节点上报的漏洞。
type ProbeVuln struct {
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	CVE         string    `json:"cve"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	Request     string    `json:"request"`
	Response    string    `json:"response"`
	CVSS        float64   `json:"cvss"`
	Confidence  int       `json:"confidence"`
	PcapFile    string    `json:"pcapFile"`
	FoundAt     time.Time `json:"foundAt"`
}

// ProbeReport 探针节点完整报告。
type ProbeReport struct {
	NodeID string       `json:"nodeId"`
	ScanID string       `json:"scanId"`
	Time   time.Time    `json:"time"`
	Assets []ProbeAsset `json:"assets"`
	Vulns  []ProbeVuln  `json:"vulns"`
}

// FromProbeReport 结构化探针报告转归一化输入批次。
func FromProbeReport(r ProbeReport) *RawBatch {
	b := &RawBatch{Source: SourceProbe, ScanID: r.ScanID}
	for _, a := range r.Assets {
		if models.NormIP(a.IP) == "" {
			continue
		}
		b.Assets = append(b.Assets, RawAsset{
			IP:        a.IP,
			MAC:       a.MAC,
			Hostname:  a.Hostname,
			OS:        a.OS,
			Ports:     a.Ports,
			Service:   a.Service,
			Version:   a.Version,
			Banner:    a.Banner,
			ProbeNode: r.NodeID,
			Tags:      a.Tags,
			FoundAt:   r.Time,
		})
	}
	for _, v := range r.Vulns {
		if models.NormIP(v.IP) == "" {
			continue
		}
		b.Vulns = append(b.Vulns, RawVuln{
			AssetIP:     v.IP,
			Port:        v.Port,
			Protocol:    v.Protocol,
			CVE:         v.CVE,
			Title:       v.Title,
			Severity:    v.Severity,
			Description: v.Description,
			Evidence:    v.Evidence,
			Request:     v.Request,
			Response:    v.Response,
			CVSS:        v.CVSS,
			Confidence:  v.Confidence,
			PcapFile:    v.PcapFile,
			FoundAt:     v.FoundAt,
		})
	}
	return b
}

// FromProbeJSON 探针上报 JSON 字节转归一化输入批次。
func FromProbeJSON(data []byte) (*RawBatch, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("probe: 上报为空")
	}
	var r ProbeReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("probe: JSON 解析失败: %w", err)
	}
	return FromProbeReport(r), nil
}
