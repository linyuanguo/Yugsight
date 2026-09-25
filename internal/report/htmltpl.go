// htmltpl.go 模板包 HTML 出口(html/template 渲染 + 内置 default 模板)。
//
// 为什么用 html/template 而不是继续拼字符串:
//
//	模板由用户自己写(build/report_templates/<名>/report.html.tpl), 数据里含
//	漏洞标题/证据这类完全不受控的文本。字符串拼接会把它们原样写进 HTML ——
//	一条精心构造的标题就能注入脚本, 报告是要发给客户的文件, 这是真实风险面。
//	html/template 自动按上下文转义, 模板作者无需记得写 esc。
//
// 模板语法错误时的降级(重要): 用户模板写错 -> 记日志 + 回落内置模板, 而不是
// 让"生成报告"整体失败。报告生成失败会让整轮扫描的成果无法交付, 而换内置模板
// 只是样式不同 —— 可用永远优先于精确。
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

// RenderPackHTML 用模板渲染 ReportData; tplText 为空用内置 default 模板。
func RenderPackHTML(data *ReportData, tplText string) (string, error) {
	if data == nil {
		return "", fmt.Errorf("报告数据为空")
	}
	text := strings.TrimSpace(tplText)
	if text == "" {
		text = BuiltinHTMLTemplate
	}
	tpl, err := template.New("report").Funcs(packFuncs()).Parse(text)
	if err != nil {
		return "", fmt.Errorf("模板解析失败: %w", err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("模板渲染失败: %w", err)
	}
	return buf.String(), nil
}

// packFuncs 模板函数(只放"不写就得在模板里做数据转换"的少数几个)。
func packFuncs() template.FuncMap {
	return template.FuncMap{
		// join 把 []int(端口) / []string(标签) 拼成展示串, 空集给占位符
		"join": func(v any, sep string) string {
			out := joinAny(v, sep)
			if strings.TrimSpace(out) == "" {
				return "-"
			}
			return out
		},
		"sevLabel": sevLabel,
		"default":  func(def, val string) string { if strings.TrimSpace(val) == "" { return def }; return val },
	}
}

// joinAny 拼接任意切片为字符串。
func joinAny(v any, sep string) string {
	var parts []string
	switch t := v.(type) {
	case nil:
		return ""
	case []int:
		for _, n := range t {
			parts = append(parts, fmt.Sprint(n))
		}
	case []string:
		parts = append(parts, t...)
	case []any:
		for _, x := range t {
			parts = append(parts, fmt.Sprint(x))
		}
	default:
		return fmt.Sprint(v)
	}
	return strings.Join(parts, sep)
}

// sevLabel 等级 key -> 中文名(模板里显示"严重/高危"而不是英文 key)。
func sevLabel(key string) string {
	for _, l := range sevLabels {
		if l.Key == strings.ToLower(strings.TrimSpace(key)) {
			return l.Label
		}
	}
	return key
}

// BuiltinHTMLTemplate 内置 default 模板(html/template 语法)。
//
// 自包含: 不引任何外部 CSS/字体/图片, 报告拷到任何机器打开都一样。
// 打印: @page 与 @media print 让浏览器"另存为 PDF"即得正式报告。
const BuiltinHTMLTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
  :root { --accent: {{default "#4f46e5" .Accent}}; }
  * { box-sizing: border-box; }
  body { margin:0; background:#f1f5f9; color:#0f172a;
         font-family:"Microsoft YaHei","PingFang SC",system-ui,sans-serif; font-size:14px; }
  .page { max-width:960px; margin:0 auto; background:#fff; padding:32px 40px; }
  h1 { font-size:24px; margin:0 0 6px; }
  h2 { font-size:17px; margin:28px 0 12px; padding-left:10px; border-left:4px solid var(--accent); }
  .muted { color:#64748b; }
  table { width:100%; border-collapse:collapse; margin-top:8px; }
  th, td { border:1px solid #e2e8f0; padding:6px 8px; text-align:left; vertical-align:top; font-size:13px; }
  th { background:#f8fafc; font-weight:600; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-top:10px; }
  .card { flex:1 1 140px; border:1px solid #e2e8f0; border-radius:8px; padding:12px; }
  .card b { display:block; font-size:22px; color:var(--accent); }
  .badge { display:inline-block; padding:1px 8px; border-radius:10px; color:#fff; font-size:12px; }
  .s-critical { background:#b91c1c; } .s-high { background:#ea580c; }
  .s-medium { background:#ca8a04; } .s-low { background:#2563eb; } .s-info { background:#64748b; }
  .cover { text-align:center; padding:60px 0 40px; border-bottom:2px solid var(--accent); }
  .cover img { max-height:64px; margin-bottom:18px; }
  .foot { margin-top:32px; padding-top:12px; border-top:1px solid #e2e8f0; color:#64748b; font-size:12px; }
  @media print {
    body { background:#fff; }
    .page { max-width:none; padding:0; }
    h2 { page-break-after:avoid; }
    table { page-break-inside:auto; }
    tr { page-break-inside:avoid; }
  }
</style>
</head>
<body>
<div class="page">
{{if .Cover}}
  <div class="cover">
    {{if .Logo}}<img src="{{.Logo}}" alt="logo">{{end}}
    <h1>{{.Title}}</h1>
    <div class="muted">{{default "网络安全扫描与漏洞评估报告" .Subtitle}}</div>
    <div class="muted" style="margin-top:18px">
      {{if .Client}}客户: {{.Client}} &nbsp;|&nbsp; {{end}}
      报告人: {{default "-" .Operator}} &nbsp;|&nbsp; {{.GeneratedAtText}}
    </div>
    <div class="muted">工具: {{default "Yugsight" .Tool}}</div>
  </div>
{{else}}
  <h1>{{.Title}}</h1>
  <div class="muted">{{.GeneratedAtText}} · {{default "Yugsight" .Tool}}</div>
{{end}}

{{define "sec-summary"}}
  <h2>一、总体结论</h2>
  <div class="cards">
    <div class="card"><span class="muted">资产总数</span><b>{{.Stats.AssetTotal}}</b></div>
    <div class="card"><span class="muted">在线资产</span><b>{{.Stats.AssetAlive}}</b></div>
    <div class="card"><span class="muted">开放端口</span><b>{{.Stats.PortTotal}}</b></div>
    <div class="card"><span class="muted">漏洞总数</span><b>{{.Stats.VulnTotal}}</b></div>
    <div class="card"><span class="muted">风险评分</span><b>{{.Stats.RiskScore}}</b><span class="muted">{{.Stats.RiskLevel}}</span></div>
  </div>
  <table>
    <tr><th>风险等级</th>{{range .SevRows}}<th>{{.Label}}</th>{{end}}</tr>
    <tr><td>数量</td>{{range .SevRows}}<td>{{.Count}}</td>{{end}}</tr>
  </table>
  {{if .Summary}}<p>{{.Summary}}</p>{{end}}
  {{if .Targets}}<p class="muted">扫描目标: {{join .Targets "、 "}}</p>{{end}}
{{end}}

{{define "sec-assets"}}
  <h2>二、资产清单</h2>
  <table>
    <tr><th>IP</th><th>主机名</th><th>操作系统</th><th>开放端口</th><th>标签</th><th>存活</th></tr>
    {{range .Assets}}
    <tr><td>{{.IP}}</td><td>{{default "-" .Hostname}}</td><td>{{default "-" .OS}}</td>
        <td>{{join .Ports ", "}}</td><td>{{join .Tags ", "}}</td>
        <td>{{if .Alive}}是{{else}}否{{end}}</td></tr>
    {{else}}
    <tr><td colspan="6" class="muted">本次无资产数据</td></tr>
    {{end}}
  </table>
{{end}}

{{define "sec-vulns"}}
  <h2>三、漏洞明细</h2>
  <table>
    <tr><th>等级</th><th>标题</th><th>资产</th><th>端口</th><th>CVE</th><th>置信度</th><th>说明</th></tr>
    {{range .Vulns}}
    <tr>
      <td><span class="badge s-{{.Severity}}">{{sevLabel .Severity}}</span></td>
      <td>{{.Title}}</td>
      <td>{{.AssetIP}}</td>
      <td>{{if .Port}}{{.Port}}{{else}}-{{end}}</td>
      <td>{{default "-" .CVE}}</td>
      <td>{{.Confidence}}</td>
      <td>{{default "-" .Description}}</td>
    </tr>
    {{else}}
    <tr><td colspan="7" class="muted">本次未发现漏洞</td></tr>
    {{end}}
  </table>
{{end}}

{{define "sec-scans"}}
  <h2>四、扫描范围</h2>
  <table>
    <tr><th>任务</th><th>类型</th><th>目标</th><th>状态</th><th>节点</th><th>时间</th></tr>
    {{range .ScansView}}
    <tr><td>{{.ID}}</td><td>{{.Type}}</td><td>{{.Target}}</td><td>{{.Status}}</td>
        <td>{{default "本地" .ProbeNode}}</td><td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td></tr>
    {{else}}
    <tr><td colspan="6" class="muted">无扫描任务记录</td></tr>
    {{end}}
  </table>
{{end}}

{{define "sec-topology"}}
  <h2>五、资产拓扑</h2>
  {{if .TopoRows}}
  <table>
    <tr><th>节点</th><th>类型</th><th>地址</th><th>服务</th><th>风险</th><th>关联漏洞</th></tr>
    {{range .TopoRows}}
    <tr><td>{{.Label}}</td><td>{{.KindName}}</td><td>{{default "-" .Addr}}</td>
        <td>{{default "-" .Service}}</td>
        <td><span class="badge s-{{.Risk}}">{{sevLabel .Risk}}</span></td><td>{{.VulnCount}}</td></tr>
    {{end}}
  </table>
  {{else}}
  <p class="muted">本次无拓扑数据</p>
  {{end}}
{{end}}

{{range .Sections}}
  {{if eq . "summary"}}{{template "sec-summary" $}}{{end}}
  {{if eq . "assets"}}{{template "sec-assets" $}}{{end}}
  {{if eq . "vulns"}}{{template "sec-vulns" $}}{{end}}
  {{if eq . "scans"}}{{template "sec-scans" $}}{{end}}
  {{if eq . "topology"}}{{template "sec-topology" $}}{{end}}
{{end}}

  <div class="foot">{{default "本报告由 Yugsight 自动生成" .Footer}} · {{.GeneratedAtText}}</div>
</div>
</body>
</html>`
