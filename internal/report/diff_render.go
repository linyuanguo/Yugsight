package report

import (
	"bytes"
	"html/template"
)

// diffTemplate 历史扫描对比报告模板。
//
// 与主报告同样自包含(内联 CSS, 无外部资源); 结构上刻意做成"三栏差异"的
// 视觉习惯: 新增=红(要立刻处置)、已修复=绿(成效证明)、仍然存在=橙(存量风险)。
var diffTemplate = template.Must(template.New("diff").Parse(diffHTML))

// diffView 对比报告模板数据。
type diffView struct {
	Title      string
	Tool       string
	Time       string
	BaseName   string
	TargetName string
	Stats      DiffStats
	Header     Header
	New        []*DiffItem
	Fixed      []*DiffItem
	Persisted  []*DiffItem
	NewAssets  []string
	FixedAssets []string
	// Verdict 一句话结论(给管理层看的那句)
	Verdict string
}

// RenderDiff 渲染历史扫描对比报告。
func RenderDiff(d *Diff, title, tool string, h Header) (string, error) {
	if d == nil {
		return "", errNilDiff
	}
	v := &diffView{
		Title:      title,
		Tool:       tool,
		Time:       d.ComparedAt.Format("2006-01-02 15:04:05"),
		BaseName:   d.BaseName,
		TargetName: d.TargetName,
		Stats:      d.Stats,
		Header:     EffectiveHeader(h),
		New:        d.New,
		Fixed:      d.Fixed,
		Persisted:  d.Persisted,
		NewAssets:  d.NewAssets,
		FixedAssets: d.FixedAssets,
	}
	v.Verdict = diffVerdict(d)
	var buf bytes.Buffer
	if err := diffTemplate.Execute(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// diffVerdict 生成对比结论(安全成效/恶化的定性判断)。
func diffVerdict(d *Diff) string {
	if d == nil {
		return ""
	}
	switch {
	case d.Stats.NewCount == 0 && d.Stats.FixedCount > 0:
		return "风险面收窄：本轮无新增漏洞，且修复了 " + itoa(d.Stats.FixedCount) + " 项历史问题，安全加固有效。"
	case d.Stats.NewCount == 0 && d.Stats.FixedCount == 0:
		return "风险面持平：本轮与基线相比无新增、无修复，建议复核扫描配置与覆盖范围是否发生变化。"
	case d.Stats.NewCritical > 0:
		return "风险显著恶化：本轮新增 " + itoa(d.Stats.NewCritical) + " 项严重漏洞，建议立即启动应急处置并核实暴露面变化。"
	case d.Stats.NewCount > d.Stats.FixedCount:
		return "风险扩大：新增 " + itoa(d.Stats.NewCount) + " 项、修复 " + itoa(d.Stats.FixedCount) + " 项，新增多于修复，建议优先处置新增项。"
	default:
		return "风险基本可控：新增 " + itoa(d.Stats.NewCount) + " 项、修复 " + itoa(d.Stats.FixedCount) + " 项，修复力度不低于新增。"
	}
}

// diffHTML 对比报告模板正文。
const diffHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>{{.Title}}</title>
<style>
  @page { size: A4; margin: 18mm 14mm 16mm 14mm; }
  * { box-sizing: border-box; }
  body { font-family: "Microsoft YaHei", "Segoe UI", "PingFang SC", sans-serif;
    color: #1f2937; background: #fff; margin: 0; font-size: 13px; }
  .page { max-width: 980px; margin: 0 auto; padding: 28px 32px 60px; }
  .print-header, .print-footer { display: none; }
  @media print {
    .print-header, .print-footer { display: block; position: fixed; left: 0; right: 0;
      font-size: 10.5px; color: #6b7280; }
    .print-header { top: -10mm; border-bottom: 1px solid #e5e7eb; padding-bottom: 3mm; }
    .print-footer { bottom: -10mm; border-top: 1px solid #e5e7eb; padding-top: 3mm; }
    .pfh-l { float: left; } .pfh-r { float: right; } .pfh-c { text-align: center; }
    table, .verdict { break-inside: avoid; }
  }
  .pfh-l { display: inline-block; width: 32%; }
  .pfh-r { display: inline-block; width: 32%; text-align: right; }
  .pfh-c { display: inline-block; width: 34%; text-align: center; }
  h1 { font-size: 24px; margin: 0 0 6px; }
  h2 { font-size: 16px; border-left: 4px solid #4f46e5; padding-left: 10px; margin: 24px 0 12px; }
  .sub { color: #6b7280; font-size: 13px; margin-bottom: 18px; }
  .cards { display: flex; gap: 10px; margin: 14px 0; flex-wrap: wrap; }
  .card { flex: 1; min-width: 150px; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px; text-align: center; }
  .card b { font-size: 26px; display: block; }
  .card span { font-size: 12px; color: #6b7280; }
  .c-new b { color: #b91c1c; } .c-fixed b { color: #15803d; } .c-keep b { color: #c2410c; } .c-delta b { color: #374151; }
  .verdict { background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 8px; padding: 13px 16px;
    font-size: 13px; line-height: 1.85; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th { background: #f3f4f6; text-align: left; padding: 8px 10px; border: 1px solid #e5e7eb; }
  td { padding: 7px 10px; border: 1px solid #e5e7eb; word-break: break-all; vertical-align: top; }
  .sev { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11.5px; font-weight: 600; white-space: nowrap; }
  .sev-critical { background: #fee2e2; color: #7f1d1d; }
  .sev-high { background: #fee2e2; color: #b91c1c; }
  .sev-medium { background: #ffedd5; color: #c2410c; }
  .sev-low { background: #fef9c3; color: #a16207; }
  .sev-info { background: #e0f2fe; color: #0369a1; }
  .tag { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .tag-new { background: #fee2e2; color: #b91c1c; }
  .tag-fixed { background: #dcfce7; color: #15803d; }
  .tag-keep { background: #ffedd5; color: #c2410c; }
  .empty { color: #9ca3af; font-size: 12.5px; padding: 10px 0; }
  .footer { margin-top: 28px; padding-top: 12px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 11.5px; line-height: 1.8; }
</style>
</head>
<body>

<div class="print-header">
  <span class="pfh-l">{{.Header.HeaderLeft}}</span><span class="pfh-c">{{.Header.HeaderCenter}}</span><span class="pfh-r">{{.Header.HeaderRight}}</span>
</div>
<div class="print-footer">
  <span class="pfh-l">{{.Header.FooterLeft}}</span><span class="pfh-c">{{.Header.FooterCenter}}</span><span class="pfh-r">{{.Header.FooterRight}}</span>
</div>

<div class="page">
  <h1>{{.Title}}</h1>
  <div class="sub">
    对比对象：<b>{{.BaseName}}</b> → <b>{{.TargetName}}</b>　|　生成时间：{{.Time}}　|　工具：{{.Tool}}
  </div>

  <h2>一、差异总览</h2>
  <div class="cards">
    <div class="card c-new"><b>{{.Stats.NewCount}}</b><span>新增漏洞</span></div>
    <div class="card c-fixed"><b>{{.Stats.FixedCount}}</b><span>已修复漏洞</span></div>
    <div class="card c-keep"><b>{{.Stats.PersistedCount}}</b><span>仍然存在</span></div>
    <div class="card c-delta"><b>{{.Stats.Delta}}</b><span>总数变化</span></div>
  </div>
  <table>
    <tr><th style="width:200px">指标</th><th>基线段</th><th>目标段</th><th>变化</th></tr>
    <tr><td>漏洞总数</td><td>{{.Stats.BaseTotal}}</td><td>{{.Stats.TargetTotal}}</td><td>{{.Stats.Delta}}</td></tr>
    <tr><td>涉及资产数</td><td>{{.Stats.BaseAssetTotal}}</td><td>{{.Stats.TargetAssetTotal}}</td><td>{{.Stats.NewAssetCount}} 新增 / {{.Stats.FixedAssetCount}} 消失</td></tr>
    <tr><td>新增中的高危项</td><td colspan="3">严重 {{.Stats.NewCritical}} 项 / 高危 {{.Stats.NewHigh}} 项</td></tr>
  </table>

  <h2>二、对比结论</h2>
  <div class="verdict">{{.Verdict}}</div>

  <h2>三、新增漏洞（{{.Stats.NewCount}}）</h2>
  {{if .New}}
  <table>
    <tr><th style="width:66px">级别</th><th>漏洞标题</th><th style="width:120px">CVE</th><th style="width:118px">资产</th><th style="width:56px">端口</th><th style="width:70px">标记</th></tr>
    {{range .New}}
    <tr>
      <td><span class="sev sev-{{.TargetSeverity}}">{{.TargetSeverity}}</span></td>
      <td>{{.Title}}</td>
      <td style="font-family:Consolas,monospace">{{if .CVE}}{{.CVE}}{{else}}-{{end}}</td>
      <td style="font-family:Consolas,monospace">{{.AssetIP}}</td>
      <td style="font-family:Consolas,monospace">{{if .Port}}{{.Port}}{{else}}-{{end}}</td>
      <td><span class="tag tag-new">新增</span></td>
    </tr>
    {{end}}
  </table>
  {{else}}<div class="empty">本段对比未发现新增漏洞。</div>{{end}}

  <h2>四、已修复漏洞（{{.Stats.FixedCount}}）</h2>
  {{if .Fixed}}
  <table>
    <tr><th style="width:66px">原级别</th><th>漏洞标题</th><th style="width:120px">CVE</th><th style="width:118px">资产</th><th style="width:56px">端口</th><th style="width:70px">标记</th></tr>
    {{range .Fixed}}
    <tr>
      <td><span class="sev sev-{{.BaseSeverity}}">{{.BaseSeverity}}</span></td>
      <td>{{.Title}}</td>
      <td style="font-family:Consolas,monospace">{{if .CVE}}{{.CVE}}{{else}}-{{end}}</td>
      <td style="font-family:Consolas,monospace">{{.AssetIP}}</td>
      <td style="font-family:Consolas,monospace">{{if .Port}}{{.Port}}{{else}}-{{end}}</td>
      <td><span class="tag tag-fixed">已修复</span></td>
    </tr>
    {{end}}
  </table>
  <div class="empty">说明：已修复 = 基线存在但目标段未再命中。建议结合变更记录复核，确认并非因目标下线或扫描范围缩小而"消失"。</div>
  {{else}}<div class="empty">本段对比未发现已修复漏洞。</div>{{end}}

  <h2>五、仍然存在的漏洞（{{.Stats.PersistedCount}}）</h2>
  {{if .Persisted}}
  <table>
    <tr><th style="width:66px">级别</th><th>漏洞标题</th><th style="width:120px">CVE</th><th style="width:118px">资产</th><th style="width:56px">端口</th><th style="width:130px">等级变化</th></tr>
    {{range .Persisted}}
    <tr>
      <td><span class="sev sev-{{.TargetSeverity}}">{{.TargetSeverity}}</span></td>
      <td>{{.Title}}</td>
      <td style="font-family:Consolas,monospace">{{if .CVE}}{{.CVE}}{{else}}-{{end}}</td>
      <td style="font-family:Consolas,monospace">{{.AssetIP}}</td>
      <td style="font-family:Consolas,monospace">{{if .Port}}{{.Port}}{{else}}-{{end}}</td>
      <td>{{if .SeverityChange}}{{.SeverityChange}}{{else}}未变化{{end}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}<div class="empty">本段对比没有重复出现的漏洞。</div>{{end}}

  {{if .NewAssets}}
  <h2>六、新增资产（{{len .NewAssets}}）</h2>
  <table>
    <tr><th>资产 IP / 标识</th></tr>
    {{range .NewAssets}}<tr><td style="font-family:Consolas,monospace">{{.}}</td></tr>{{end}}
  </table>
  {{end}}

  {{if .FixedAssets}}
  <h2>七、不再出现漏洞的资产（{{len .FixedAssets}}）</h2>
  <table>
    <tr><th>资产 IP / 标识</th></tr>
    {{range .FixedAssets}}<tr><td style="font-family:Consolas,monospace">{{.}}</td></tr>{{end}}
  </table>
  {{end}}

  <div class="footer">
    {{.Title}} · 由 {{.Tool}} 于 {{.Time}} 自动生成<br>
    对比口径：按「资产 + CVE」（无 CVE 时按「资产 + 协议:端口 + 标题」）匹配，人工标记的误报不参与对比。<br>
    {{.Header.Disclaimer}}
  </div>
</div>
</body>
</html>
`
