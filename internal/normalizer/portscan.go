package normalizer

import (
	"strings"
	"time"
)

// Go 原生端口扫描结果适配器（资产维度）。

// OpenPort 单个开放端口。
type OpenPort struct {
	Port     int
	Protocol string // tcp / udp
	Service  string
	Version  string
	Banner   string
}

// PortScanHost 端口扫描单主机结果。
type PortScanHost struct {
	IP        string
	MAC       string
	Hostname  string
	OS        string
	Ports     []OpenPort
	Tags      []string
	ProbeNode string
	FoundAt   time.Time
}

// FromPortScan 端口扫描结果转归一化输入批次（资产维度）。
// 端口扫描以资产发现为主：主服务取首个有服务名的开放端口，
// 完整端口列表入 Ports；如扫描附带漏洞结论，由调用方追加到批次 Vulns。
func FromPortScan(hosts []PortScanHost) *RawBatch {
	b := &RawBatch{Source: SourcePortScan}
	for _, h := range hosts {
		var ports []int
		var service, version, banner string
		for _, p := range h.Ports {
			if p.Port <= 0 {
				continue
			}
			ports = append(ports, p.Port)
			if service == "" && strings.TrimSpace(p.Service) != "" {
				service = strings.TrimSpace(p.Service)
				version = strings.TrimSpace(p.Version)
				banner = strings.TrimSpace(p.Banner)
			}
		}
		b.Assets = append(b.Assets, RawAsset{
			IP:        h.IP,
			MAC:       h.MAC,
			Hostname:  h.Hostname,
			OS:        h.OS,
			Ports:     ports,
			Service:   service,
			Version:   version,
			Banner:    banner,
			ProbeNode: h.ProbeNode,
			Tags:      h.Tags,
			FoundAt:   h.FoundAt,
		})
	}
	return b
}
