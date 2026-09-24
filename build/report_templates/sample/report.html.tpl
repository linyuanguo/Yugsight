<!DOCTYPE html>
<!--
  示例模板: 演示"改 logo / 配色 / 客户名 / 章节顺序"四种定制。

  可用变量(完整清单见 README 与 /api/v2/report/packs 的 variables 字段):
    .Title .Subtitle .Client .Operator .Tool .GeneratedAtText
    .Targets .Stats .SevRows .Assets .Vulns .ScansView .TopoRows
    .Logo .Accent .Footer .Cover .Sections
  函数: join(端口/标签列表)  sevLabel(等级转中文)  default(空值兜底)

  渲染走 html/template: 漏洞标题这类不受控文本会自动转义, 不需要手工处理。
-->
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
  :root { --accent: {{default "#0f766e" .Accent}}; }
  body { margin:0; background:#eef2f5; color:#111827;
         font-family:"Microsoft YaHei","PingFang SC",system-ui,sans-serif; font-size:14px; }
  .wrap { max-width:900px; margin:0 auto; background:#fff; padding:0 0 24px; }
  .cover { background:var(--accent); color:#fff; padding:48px 40px 40px; }
  .cover img { max-height:56px; display:block; margin-bottom:16px; }
  .cover h1 { margin:0 0 8px; font-size:26px; font-weight:600; }
  .cover .sub { opacity:.85; }
  .cover .client { margin-top:18px; font-size:15px; }
  .cover .meta { margin-top:6px; font-size:12px; opacity:.8; }
  .body { padding:0 40px; }
  h2 { font-size:16px; margin:26px 0 10px; color:var(--accent);
       border-bottom:1px solid #e5e7eb; padding-bottom:6px; }
  .cards { display:flex; gap:10px; flex-wrap:wrap; }
  .card { flex:1 1 130px; background:#f8fafc; border-radius:6px; padding:10px 12px; }
  .card span { display:block; color:#64748b; font-size:12px; }
  .card b { font-size:20px; color:var(--accent); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { border-bottom:1px solid #e5e7eb; padding:6px 8px; text-align:left; }
  th { color:#475569; font-weight:600; }
  tbody tr:nth-child(even) { background:#f9fafb; }
  .badge { padding:1px 7px; border-radius:9px; color:#fff; font-size:12px; }
  .s-critical{background:#b91c1c}.s-high{background:#ea580c}.s-medium{background:#ca8a04}
  .s-low{background:#2563eb}.s-info{background:#64748b}
  .empty { color:#94a3b8; padding:8px 0; }
  footer { margin:28px 40px 0; padding-top:10px; border-top:1px solid #e5e7eb;
           color:#94a3b8; font-size:12px; }
  @media print { body{background:#fff} .wrap{max-width:none} tr{page-break-inside:avoid} }
</style>
</head>
<body>
<div class="wrap">
{{if .Cover}}
  <div class="cover">
    {{if .Logo}}<img src="{{.Logo}}" alt="logo">{{end}}
    <h1>{{.Title}}</h1>
    <div class="sub">{{default "网络安全扫描与漏洞评估报告" .Subtitle}}</div>
    {{if .Client}}<div class="client">客户: {{.Client}}</div>{{end}}
    <div class="meta">{{default "Yugsight" .Tool}} · 报告人 {{default "-" .Operator}} · {{.GeneratedAtText}}</div>
  </div>
{{end}}

<div class="body">
{{define "s-summary"}}
  <h2>总体结论</h2>
  <div class="cards">
    <div class="card"><span>资产</span><b>{{.Stats.AssetTotal}}</b></div>
    <div class="card"><span>漏洞</span><b>{{.Stats.VulnTotal}}</b></div>
    <div class="card"><span>开放端口</span><b>{{.Stats.PortTotal}}</b></div>
    <div class="card"><span>风险评分</span><b>{{.Stats.RiskScore}}</b></div>
  </div>
  <table>
    <tr>{{range .SevRows}}<th>{{.Label}}</th>{{end}}</tr>
    <tr>{{range .SevRows}}<td>{{.Count}}</td>{{end}}</tr>
  </table>
  {{if .Targets}}<p>扫描目标: {{join .Targets "、 "}}</p>{{end}}
{{end}}

{{define "s-vulns"}}
  <h2>漏洞明细</h2>
  <table>
    <tr><th>等级</th><th>标题</th><th>资产</th><th>端口</th><th>CVE</th><th>说明</th></tr>
    {{range .Vulns}}
    <tr>
      <td><span class="badge s-{{.Severity}}">{{sevLabel .Severity}}</span></td>
      <td>{{.Title}}</td><td>{{.AssetIP}}</td>
      <td>{{if .Port}}{{.Port}}{{else}}-{{end}}</td>
      <td>{{default "-" .CVE}}</td><td>{{default "-" .Description}}</td>
    </tr>
    {{end}}
  </table>
  {{if not .Vulns}}<div class="empty">本次未发现漏洞</div>{{end}}
{{end}}

{{define "s-assets"}}
  <h2>资产清单</h2>
  <table>
    <tr><th>IP</th><th>主机名</th><th>操作系统</th><th>端口</th><th>存活</th></tr>
    {{range .Assets}}
    <tr><td>{{.IP}}</td><td>{{default "-" .Hostname}}</td><td>{{default "-" .OS}}</td>
        <td>{{join .Ports ", "}}</td><td>{{if .Alive}}是{{else}}否{{end}}</td></tr>
    {{end}}
  </table>
  {{if not .Assets}}<div class="empty">无资产数据</div>{{end}}
{{end}}

{{define "s-scans"}}
  <h2>扫描范围</h2>
  <table>
    <tr><th>任务</th><th>类型</th><th>目标</th><th>状态</th><th>时间</th></tr>
    {{range .ScansView}}
    <tr><td>{{.ID}}</td><td>{{.Type}}</td><td>{{.Target}}</td><td>{{.Status}}</td>
        <td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td></tr>
    {{end}}
  </table>
  {{if not .ScansView}}<div class="empty">无扫描任务记录</div>{{end}}
{{end}}

{{range .Sections}}
  {{if eq . "summary"}}{{template "s-summary" $}}{{end}}
  {{if eq . "vulns"}}{{template "s-vulns" $}}{{end}}
  {{if eq . "assets"}}{{template "s-assets" $}}{{end}}
  {{if eq . "scans"}}{{template "s-scans" $}}{{end}}
{{end}}
</div>

<footer>{{default "本报告由 Yugsight 自动生成" .Footer}} · {{.GeneratedAtText}}</footer>
</div>
</body>
</html>
