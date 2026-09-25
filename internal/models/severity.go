package models

import "strings"

// 风险等级常量（与 Nuclei / 报告口径一致）。
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// NormalizeSeverity 将各来源的等级表述归一化为标准等级。
// 未知 / 空 / 无法识别返回 low（不高估风险）。
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "information", "informational", "notice":
		return SeverityInfo
	default:
		return SeverityLow
	}
}

// SeverityRank 风险等级序（数值越大越严重），供排序与合并取最高。
func SeverityRank(s string) int {
	switch NormalizeSeverity(s) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// CVSSSeverity CVSS 分值换算风险等级。
func CVSSSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}
