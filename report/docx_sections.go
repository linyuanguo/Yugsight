// docx_sections.go 报告章节生成: 把 Snapshot + 统计转成 Word 块序列。
//
// 章节结构与既有 HTML 报告(report/render.go)对齐 —— 用户在 Word 与 HTML 两种
// 格式里看到同样的章节, 只是排版载体不同:
//
//	一、总体概况  二、风险等级分布  三、资产清单  四、漏洞明细
//	五、渗透验证结果(阶段 5, 无渗透数据时整节不出现, 编号不跳号)
//	…扫描范围  …修复建议  (末段免责声明)
//
// 编号为什么改成动态: 扫描范围/渗透验证都是"有数据才渲染"的可选章节, 硬编码
// 数字会在省略某一节时出现"四、漏洞明细"之后直接跳到"六"的空洞 —— 报告的
// 章节号是读者核对完整性的唯一线索, 跳号会被读成"缺了一章"。
//
// 篇幅控制: 漏洞明细/资产清单各截断 200 行, 扫描范围截断 50 行 —— 与 HTML
// 报告的截断口径一致(报告里列 200 条已足够, 防篇幅失控)。
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"yugsight/models"
)

// SectionBlocks 生成报告内容章节(不含封面 —— 封面在模板里)。
//
// disclaimer 为免责声明文案(空 = 不输出末段)。
func SectionBlocks(s *Snapshot, st SnapshotStats, disclaimer string) []Block {
	var out []Block

	// 章节序号从 4 起(前四章在下方硬编码), 后续章节按需递增 —— 必须是局部
	// 变量: 用包级变量会让第二份报告的编号从上一份的尾巴继续(报告之间串号)。
	sec := 4
	cnNums := []string{"", "一", "二", "三", "四", "五", "六", "七", "八", "九", "十"}
	nextSec := func() string {
		sec++
		if sec < len(cnNums) {
			return cnNums[sec]
		}
		return fmt.Sprintf("%d", sec)
	}

	// ---- 一、总体概况 ----
	out = append(out, heading(1, "一、总体概况"))
	out = append(out, pRun(fmt.Sprintf(
		"本次扫描共覆盖 %d 台资产(在线 %d), 开放端口 %d 个, 发现漏洞 %d 项: 严重 %d / 高危 %d / 中危 %d / 低危 %d / 信息 %d。",
		st.AssetTotal, st.AssetAlive, st.PortTotal, st.VulnTotal,
		st.Critical, st.High, st.Medium, st.Low, st.Info)))
	out = append(out, pRun(fmt.Sprintf("整体风险评分 %d 分(百分制), 风险等级: %s。", st.RiskScore, st.RiskLevel)))
	if s != nil && strings.TrimSpace(s.Summary) != "" {
		out = append(out, pRun(s.Summary))
	}

	// ---- 二、风险等级分布 ----
	out = append(out, heading(1, "二、风险等级分布"))
	sevs := []struct{ name string; n int }{
		{"严重", st.Critical}, {"高危", st.High}, {"中危", st.Medium}, {"低危", st.Low}, {"信息", st.Info},
	}
	rows := make([][]string, 0, len(sevs))
	for _, sv := range sevs {
		pct := "0%"
		if st.VulnTotal > 0 {
			pct = fmt.Sprintf("%.1f%%", float64(sv.n)*100/float64(st.VulnTotal))
		}
		rows = append(rows, []string{sv.name, fmt.Sprintf("%d", sv.n), pct})
	}
	out = append(out, tableBlock([]string{"等级", "数量", "占比"}, rows))

	// ---- 三、资产清单 ----
	out = append(out, heading(1, "三、资产清单"))
	if len(s.Assets) == 0 {
		out = append(out, pRun("无资产数据。"))
	} else {
		vulnByIP := map[string][]*models.Vuln{}
		for _, v := range s.Vulns {
			if v != nil {
				vulnByIP[models.NormIP(v.AssetIP)] = append(vulnByIP[models.NormIP(v.AssetIP)], v)
			}
		}
		assets := make([]*models.Asset, len(s.Assets))
		copy(assets, s.Assets)
		sort.SliceStable(assets, func(i, j int) bool { return assets[i].IP < assets[j].IP })
		rows := make([][]string, 0, len(assets))
		for _, a := range assets {
			if a == nil {
				continue
			}
			if len(rows) >= 200 {
				break
			}
			risk := "无"
			if vs := vulnByIP[models.NormIP(a.IP)]; len(vs) > 0 {
				risk = sevName(maxSeverity(vs))
			}
			rows = append(rows, []string{
				a.IP,
				orDash(a.Hostname),
				orDash(a.OS),
				fmt.Sprintf("%d", len(a.Ports)),
				orDash(a.Service),
				aliveLabel(a.Alive),
				risk,
				fmt.Sprintf("%d", len(vulnByIP[models.NormIP(a.IP)])),
			})
		}
		out = append(out, tableBlock(
			[]string{"IP", "主机名", "系统", "端口数", "服务", "在线", "风险", "漏洞数"}, rows))
	}

	// ---- 四、漏洞明细 ----
	out = append(out, heading(1, "四、漏洞明细"))
	if len(s.Vulns) == 0 {
		out = append(out, pRun("未发现漏洞。"))
	} else {
		vs := make([]*models.Vuln, len(s.Vulns))
		copy(vs, s.Vulns)
		sort.SliceStable(vs, func(i, j int) bool {
			ri, rj := sevRankOf(vs[i].Severity), sevRankOf(vs[j].Severity)
			if ri != rj {
				return ri < rj
			}
			if vs[i].AssetIP != vs[j].AssetIP {
				return vs[i].AssetIP < vs[j].AssetIP
			}
			return vs[i].Port < vs[j].Port
		})
		rows := make([][]string, 0, len(vs))
		for _, v := range vs {
			if v == nil {
				continue
			}
			if len(rows) >= 200 {
				break
			}
			port := "-"
			if v.Port > 0 {
				port = fmt.Sprintf("%d", v.Port)
			}
			// 渗透验证列追加在末尾: 既有测试按列下标断言状态列(Cells[7]),
			// 插在中间会把所有下游断言错位。
			verdict := "-"
			if v.PentaResult != "" {
				verdict = pentaExploitName(v.PentaResult)
			}
			rows = append(rows, []string{
				sevName(v.Severity),
				v.Title,
				orDash(v.CVE),
				models.NormIP(v.AssetIP),
				port,
				orDash(v.Protocol),
				fmt.Sprintf("%d", v.Confidence),
				statusLabel(v.Status),
				timeLabel(v.FoundAt),
				verdict,
			})
		}
		out = append(out, tableBlock(
			[]string{"级别", "标题", "CVE", "资产", "端口", "协议", "置信度", "状态", "发现时间", "渗透验证"}, rows))
	}

	// ---- 五、渗透验证结果(阶段 5: 扫描+渗透验证整合报告; 无数据不渲染) ----
	if s != nil && len(s.Penta) > 0 {
		out = append(out, heading(1, nextSec()+"、渗透验证结果"))
		rows := make([][]string, 0, len(s.Penta))
		for _, p := range s.Penta {
			if len(rows) >= 200 {
				break
			}
			// 未做定级修正时显示 "-", 不能直接走 sevName: 它对空串返回"低危",
			// 会把"未修正"读成"修正成了低危"
			level := "-"
			if strings.TrimSpace(p.RiskLevel) != "" {
				level = sevName(p.RiskLevel)
			}
			rows = append(rows, []string{
				orDash(p.Target),
				orDash(p.Title),
				orDash(p.CVE),
				pentaExploitName(p.Exploitability),
				level,
				orDash(p.Summary),
				timeLabel(p.VerifiedAt),
				orDash(p.Operator),
			})
		}
		out = append(out, tableBlock(
			[]string{"目标", "验证对象", "CVE", "验证结论", "定级", "摘要", "验证时间", "操作者"}, rows))
		out = append(out, pSmallGray("验证结论来自渗透工作台(仅对已授权目标实施, 操作全程审计留痕)。「可利用」= 验证过程中实际观测到漏洞行为; 完整命令日志与响应证据留存于平台渗透工作台。"))
	}

	// ---- 扫描范围 ----
	if len(s.Scans) > 0 {
		out = append(out, heading(1, nextSec()+"、扫描范围"))
		rows := make([][]string, 0, len(s.Scans))
		for _, sc := range s.Scans {
			if len(rows) >= 50 {
				break
			}
			rows = append(rows, []string{
				timeLabel(sc.CreatedAt),
				orDash(sc.Target),
				orDash(sc.Type),
				orDash(sc.Status),
				orDash(sc.ProbeNode),
			})
		}
		out = append(out, tableBlock([]string{"时间", "目标", "类型", "状态", "节点"}, rows))
	}

	// ---- 六、修复建议(只列需要立即处置的: 严重/高危, 最多 10 条) ----
	var top []*models.Vuln
	for _, v := range s.Vulns {
		if v == nil {
			continue
		}
		sv := models.NormalizeSeverity(v.Severity)
		if sv == models.SeverityCritical || sv == models.SeverityHigh {
			top = append(top, v)
		}
	}
	if len(top) > 0 {
		sort.SliceStable(top, func(i, j int) bool {
			ri, rj := sevRankOf(top[i].Severity), sevRankOf(top[j].Severity)
			if ri != rj {
				return ri < rj
			}
			return top[i].AssetIP < top[j].AssetIP
		})
		out = append(out, heading(1, nextSec()+"、重点修复建议"))
		for i, v := range top {
			if i >= 10 {
				break
			}
			out = append(out, pRun(fmt.Sprintf("%d. [%s] %s (资产 %s) —— %s",
				i+1, sevName(v.Severity), v.Title, models.NormIP(v.AssetIP), FixOf(v))))
		}
	}

	if strings.TrimSpace(disclaimer) != "" {
		out = append(out, pSmallGray(disclaimer))
	}
	return out
}

// ===== 小工具 =====

var sevRankMap = map[string]int{
	models.SeverityCritical: 0,
	models.SeverityHigh:     1,
	models.SeverityMedium:   2,
	models.SeverityLow:      3,
	models.SeverityInfo:     4,
}

func sevRankOf(sev string) int {
	if r, ok := sevRankMap[models.NormalizeSeverity(sev)]; ok {
		return r
	}
	return 5
}

// maxSeverity 取一组漏洞中的最高等级(修复建议/资产风险标注用)。
func maxSeverity(vs []*models.Vuln) string {
	best := ""
	bestRank := 99
	for _, v := range vs {
		r := sevRankOf(v.Severity)
		if r < bestRank {
			bestRank, best = r, v.Severity
		}
	}
	return best
}

func orDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return s
}

func aliveLabel(alive bool) string {
	if alive {
		return "在线"
	}
	return "离线"
}

func statusLabel(status string) string {
	switch status {
	case "fixed":
		return "已修复"
	case "duplicate":
		return "重复"
	default:
		return "未修复"
	}
}

func timeLabel(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04")
}
