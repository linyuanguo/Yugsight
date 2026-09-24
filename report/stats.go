package report

import (
	"fmt"
	"strings"

	"yugsight/models"
)

// ComputeStats 汇总快照统计(风险总览图表数据源)。
//
// 口径说明:
//   - 误报(FalsePositive)默认不计入漏洞统计 —— 报告是给客户/领导看的结论材料,
//     把人工已确认的误报算进风险数字会让报告失去可信度。调用方若要统计误报
//     数量, 请用 Filter.Apply 返回的 SnapshotStats.FalsePos(它记录被排除的条数)。
//   - 资产在线状态: 有 FoundAt 则视为在线(models 无独立"在线"字段, 存活探测
//     命中的资产才会入库, 因此"在库即在线"是与既有链路一致的近似口径)。
func ComputeStats(s *Snapshot) SnapshotStats {
	st := SnapshotStats{
		BySource:   map[string]int{},
		ByProbe:    map[string]int{},
		BySeverity: map[string]int{},
	}
	if s == nil {
		return st
	}

	st.AssetTotal = len(s.Assets)
	st.AssetAlive = len(s.Assets)
	for _, a := range s.Assets {
		if a == nil {
			continue
		}
		st.PortTotal += len(a.Ports)
	}

	for _, v := range s.Vulns {
		if v == nil {
			continue
		}
		st.VulnTotal++
		switch models.NormalizeSeverity(v.Severity) {
		case models.SeverityCritical:
			st.Critical++
		case models.SeverityHigh:
			st.High++
		case models.SeverityMedium:
			st.Medium++
		case models.SeverityLow:
			st.Low++
		default:
			st.Info++
		}
		st.BySeverity[models.NormalizeSeverity(v.Severity)]++

		if models.IsCVE(v.CVE) {
			st.WithCVE++
		}
		if strings.TrimSpace(v.Evidence) != "" || len(v.EvidenceRecords) > 0 {
			st.WithEvidence++
		}
		if strings.TrimSpace(FixOf(v)) != "" {
			st.WithFix++
		}
		if strings.TrimSpace(v.PcapFile) != "" {
			st.WithPcap++
		}
		src := strings.TrimSpace(v.Source)
		if src == "" {
			src = "unknown"
		}
		st.BySource[src]++
		// 节点分布: 有明确节点信息才计入(否则会造出一个无意义的空键)
		if node := nodeLabel(v); node != "" {
			st.ByProbe[node]++
		}
	}

	st.RiskScore, st.RiskLevel = riskScore(st)
	return st
}

// nodeLabel 漏洞的来源节点标签(空 = 无信息)。
//
// 依据: 探针上报的漏洞 Source 为 "probe", 装配层在构建快照时会把它改写为
// "probe:<节点ID>"(见 report_api.go), 这里按前缀拆出节点 ID。
func nodeLabel(v *models.Vuln) string {
	if v == nil {
		return ""
	}
	src := strings.TrimSpace(v.Source)
	if src == "" || src == LocalNode {
		return ""
	}
	if strings.HasPrefix(src, "probe:") {
		return strings.TrimPrefix(src, "probe:")
	}
	return ""
}

// riskScore 计算 0-100 风险评分与等级文案。
//
// 算法(刻意简单可解释): 按等级加权求和后饱和映射。
//
//	critical 40 / high 15 / medium 5 / low 1 / info 0.2 (info 按 5 条记 1 分)
//
// 上限 100。之所以用"饱和"而不是归一化到条目数: 归一化会让"扫了 10 条低危"
// 和"扫到 1 条严重"拿到同样的满分, 那与安全直觉完全相反。
func riskScore(st SnapshotStats) (int, string) {
	score := float64(st.Critical)*40 + float64(st.High)*15 + float64(st.Medium)*5 + float64(st.Low)*1 + float64(st.Info)*0.2
	if score > 100 {
		score = 100
	}
	n := int(score + 0.5)
	level := "无风险"
	switch {
	case st.Critical > 0:
		level = "严重"
	case n >= 60:
		level = "高危"
	case n >= 30:
		level = "中危"
	case n > 0:
		level = "低危"
	}
	return n, level
}

// SummaryText 生成总体结论文字(模板中的"总体建议"章节)。
func SummaryText(st SnapshotStats, tool, timeStr string) string {
	var b strings.Builder
	switch {
	case st.Critical > 0:
		fmt.Fprintf(&b, "<b>检测到 %d 项严重风险。</b>建议立即停止相关业务对外暴露，组织应急响应并在修复后复测。<br>", st.Critical)
	case st.High > 0:
		fmt.Fprintf(&b, "<b>检测到 %d 项高危风险。</b>建议在 24 小时内核实并修复高危项（如敏感文件暴露、注入漏洞、未授权访问等），修复后复测。<br>", st.High)
	}
	if st.Medium > 0 {
		fmt.Fprintf(&b, "<b>检测到 %d 项中危风险。</b>建议在一周内完成加固：收敛管理界面暴露面、更新过期证书、隐藏服务版本信息。<br>", st.Medium)
	}
	if st.Low > 0 {
		fmt.Fprintf(&b, "存在 %d 项低危与配置类问题，建议结合安全基线逐步优化（补充安全响应头、Cookie 安全标志、关闭非必要端口等）。<br>", st.Low)
	}
	if st.VulnTotal == 0 {
		b.WriteString("本次扫描未发现明显风险。建议保持定期扫描，并关注系统更新与新发布漏洞。<br>")
	}
	if st.WithFix < st.VulnTotal {
		fmt.Fprintf(&b, "其中 %d/%d 项已给出修复建议，其余项请结合业务上下文人工确认。<br>", st.WithFix, st.VulnTotal)
	}
	fmt.Fprintf(&b, "本报告由 %s 于 %s 基于黑盒探测自动生成，结果可能存在误报或漏报，请人工核实后使用。", tool, timeStr)
	return b.String()
}
