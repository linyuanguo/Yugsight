// Package normalizer 多源扫描结果归一化模块（第一阶段：核心数据模型与归一化层）。
//
// 统一接收 6 类来源的原始扫描结果，产出标准化资产 / 漏洞
// (models.Asset / models.Vuln)，供 Web API、报告模块、大屏查询调用：
//
//  1. nuclei     内置 Nuclei（Yugsight 内置模板引擎）
//  2. portscan   Go 原生端口扫描
//  3. nmap       Nmap（解析 -oJ JSON 输出）
//  4. trivy      Trivy（解析 -f json 输出）
//  5. zap        OWASP ZAP（解析 JSON 报告）
//  6. probe      远端探针上报（本项目协议 JSON）
//
// 核心能力：
//   - 资产合并：同 IP 合并为一个资产，端口 / 标签取并集
//   - 漏洞去重合并：同资产 + 同 CVE 合并多条证据，保留全部原始请求 / 响应
//   - 漏洞状态标记：new 新发现 / duplicate 重复 / fixed 历史已修复（对比上一轮基线）
//
// 本包仅依赖 Go 标准库 + models 包，可独立工作，
// 不依赖外部引擎进程(bin)与探针节点；外部引擎以标准 JSON 输出接入。
package normalizer

import "time"

// 来源类型常量（6 类 + 未知兜底）。
const (
	SourceNuclei   = "nuclei"   // 内置 Nuclei（Yugsight 内置模板引擎）
	SourcePortScan = "portscan" // Go 原生端口扫描
	SourceNmap     = "nmap"     // Nmap
	SourceTrivy    = "trivy"    // Trivy
	SourceZAP      = "zap"      // OWASP ZAP
	SourceProbe    = "probe"    // 远端探针上报
	SourceUnknown  = "unknown"  // 未知来源
)

// RawAsset 原始资产（各来源适配器转换成的统一中间表示）。
type RawAsset struct {
	IP        string
	MAC       string
	Hostname  string
	OS        string
	Ports     []int
	Service   string
	Version   string
	Banner    string
	ProbeNode string
	Tags      []string
	FoundAt   time.Time
}

// RawVuln 原始漏洞（各来源适配器转换成的统一中间表示）。
type RawVuln struct {
	AssetIP     string
	Port        int
	Protocol    string
	CVE         string
	Title       string
	Severity    string
	Description string
	Evidence    string
	Request     string
	Response    string
	CVSS        float64
	Confidence  int
	PcapFile    string
	FoundAt     time.Time
}

// RawBatch 单来源的一批原始结果（归一化的统一输入单元）。
type RawBatch struct {
	Source string
	ScanID string
	Assets []RawAsset
	Vulns  []RawVuln
}
