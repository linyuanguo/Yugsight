package models

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// 漏洞状态常量。
//
// 内部状态机保留 new/duplicate 细粒度(normalizer 依据上一轮基线标记, 报告引擎
// 与大屏统计依赖), 但**用户可见口径只有两态**: open(未修复, 含 new/duplicate/open)
// 与 fixed。"重复发现"不再作为状态展示 —— 它由 LastSeenAt(最后命中时间)表达。
const (
	// VulnStatusNew 新发现漏洞：本轮扫描首次出现（上一轮基线中不存在）。
	VulnStatusNew = "new"
	// VulnStatusDuplicate 重复漏洞：上一轮基线中存在且本轮再次命中（重复出现）。
	VulnStatusDuplicate = "duplicate"
	// VulnStatusOpen 开放(用户态)：已修复的漏洞被后续扫描再次命中时回退到此状态
	// (说明修复未生效)。前端 new/duplicate/open 统一显示为"开放"。
	VulnStatusOpen = "open"
	// VulnStatusFixed 历史已修复漏洞：上一轮基线中存在但本轮未再命中。
	VulnStatusFixed = "fixed"
)

// IsFixedStatus 是否已修复(用户两态口径的唯一分界)。
func IsFixedStatus(status string) bool {
	return status == VulnStatusFixed
}

// EvidenceRecord 单条原始证据（多来源合并时全部保留，不截断不丢弃）。
type EvidenceRecord struct {
	Source   string    `json:"source"`
	Evidence string    `json:"evidence,omitempty"`
	Request  string    `json:"request,omitempty"`
	Response string    `json:"response,omitempty"`
	FoundAt  time.Time `json:"foundAt"`
}

// Vuln 统一漏洞模型（多源归一化输出单元）。
//
// 字段与规范对齐：漏洞唯一 ID / CVE 编号 / 资产 IP / 端口 /
// 协议 / 风险等级 / 标题 / 描述 / 验证证据 / 原始请求 / 原始响应 /
// 置信度 / 来源引擎 / 发现时间 / PCAP 证据附件路径。
// 归一化扩展字段（Status / Sources / EvidenceRecords / LastSeenAt / FixedAt）
// 支撑同资产+同 CVE 合并去重与新发现 / 重复 / 已修复状态标记。
type Vuln struct {
	ID              string           `json:"id"`
	CVE             string           `json:"cve,omitempty"`
	AssetIP         string           `json:"assetIp"`
	Port            int              `json:"port"`
	Protocol        string           `json:"protocol,omitempty"`
	Severity        string           `json:"severity"`
	Title           string           `json:"title"`
	Description     string           `json:"description,omitempty"`
	Evidence        string           `json:"evidence,omitempty"`
	Request         string           `json:"request,omitempty"`
	Response        string           `json:"response,omitempty"`
	Confidence      int              `json:"confidence"`
	Source          string           `json:"source"`
	FoundAt         time.Time        `json:"foundAt"`
	PcapFile        string           `json:"pcapFile,omitempty"`
	CVSS            float64          `json:"cvss,omitempty"`
	Status          string           `json:"status"`
	Sources         []string         `json:"sources"`
	EvidenceRecords []EvidenceRecord `json:"evidenceRecords,omitempty"`
	LastSeenAt      time.Time        `json:"lastSeenAt"`
	FixedAt         *time.Time       `json:"fixedAt,omitempty"`
	// FalsePositive 人工误报标记（scanctl 误报管理模块填充）:
	// 后续扫描命中相同资产+CVE 时自动标记; 报告导出时误报项被排除。
	FalsePositive bool   `json:"falsePositive,omitempty"`
	FPNote        string `json:"fpNote,omitempty"` // 误报备注

	// 渗透验证（阶段 5 渗透工作台"一键回传"填充）:
	// 扫描只发现、渗透才验证 —— 验证结论单独存字段而不是改 Status,
	// 因为"可利用/不可利用"与"开放/已修复"是两个正交维度。
	PentaTaskID     string     `json:"pentaTaskId,omitempty"`      // 产出验证的渗透任务 ID
	PentaResult     string     `json:"pentaResult,omitempty"`      // exploitable / partial / not_exploitable
	PentaRiskLevel  string     `json:"pentaRiskLevel,omitempty"`   // 验证后修正的风险等级（空 = 未修正）
	PentaVerifiedAt *time.Time `json:"pentaVerifiedAt,omitempty"`  // 回传时间
}

// NormalizeCVE 归一化 CVE 编号：去首尾空白 + 转大写，CVE_ 前缀转 CVE-。
// 非 CVE 值（规则 ID 等）原样返回，是否入 CVE 字段由调用方判定。
func NormalizeCVE(cve string) string {
	s := strings.ToUpper(strings.TrimSpace(cve))
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "CVE_") {
		s = "CVE-" + strings.ReplaceAll(s[4:], "_", "-")
	}
	return s
}

// IsCVE 判断 s 是否为 CVE 编号（归一化后以 CVE- 开头）。
func IsCVE(s string) bool {
	return strings.HasPrefix(NormalizeCVE(s), "CVE-")
}

// MergeKey 去重合并键：同资产 + 同 CVE（CVE 归一化后比较）；
// 无 CVE 时退化为「资产 + 协议:端口 + 标题」（规则 ID / 标题维度）。
func (v *Vuln) MergeKey() string {
	ip := NormIP(v.AssetIP)
	if cve := NormalizeCVE(v.CVE); cve != "" {
		return ip + "|" + cve
	}
	return ip + "|" + strings.ToLower(strings.TrimSpace(v.Protocol)) + ":" + strconv.Itoa(v.Port) + "|" + strings.TrimSpace(v.Title)
}

// StableID 稳定漏洞唯一 ID：合并键的 SHA1 前 16 位，
// 同资产 + 同漏洞跨扫描不变，可作数据库主键。
func (v *Vuln) StableID() string {
	sum := sha1.Sum([]byte(v.MergeKey()))
	return hex.EncodeToString(sum[:])[:16]
}
