package report

import "html/template"

// reportTemplate 内置报告模板(解析失败会在 init 阶段 panic —— 模板是编译期
// 常量, 语法错误属于开发期缺陷, 必须在构建/自测时立刻暴露, 而不是等到用户
// 点"生成报告"时才报错)。
var reportTemplate = template.Must(template.New("report").Parse(reportHTML))

// reportHTML 报告模板正文。
//
// 设计约束(与项目硬约束一致):
//
//  1. 自包含: 内联 CSS + CSS 条形图 + 环形评分, 无外部 JS/CSS/图片引用 ——
//     报告要能在离线的内网/邮件附件场景正常渲染;
//  2. 可打印: @page 分页 + @media print 规则, 浏览器"另存为 PDF"即得正式报告;
//  3. 页眉页脚: 打印时用 position:fixed 在每页重复显示(fixed 元素在打印
//     上下文中按页重复是浏览器标准行为), 内容来自 Header 模板(支持自定义);
//  4. 不用任何自定义模板函数: 用户拿到的自定义模板若引用了未定义函数会直接
//     渲染失败, 只使用内置 action(if/else/range/eq/ge/index)最稳妥。
//
// 数据安全: 全部动态内容经 html/template 自动转义, 证据里的 <script> 不会被执行。
const reportHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>{{.Title}}</title>
<style>
  /* ===== 打印分页与页眉页脚 ===== */
  @page { size: A4; margin: 18mm 14mm 16mm 14mm; }
  * { box-sizing: border-box; }
  body {
    font-family: "Microsoft YaHei", "Segoe UI", "PingFang SC", sans-serif;
    color: #1f2937; background: #fff; margin: 0; font-size: 13px;
  }
  .page { max-width: 980px; margin: 0 auto; padding: 28px 32px 60px; }

  /* 打印时每页重复的页眉页脚(fixed 在打印上下文按页重复) */
  .print-header, .print-footer { display: none; }
  @media print {
    .print-header, .print-footer { display: block; position: fixed; left: 0; right: 0;
      font-size: 10.5px; color: #6b7280; }
    .print-header { top: -10mm; border-bottom: 1px solid #e5e7eb; padding-bottom: 3mm; }
    .print-footer { bottom: -10mm; border-top: 1px solid #e5e7eb; padding-top: 3mm; }
    .print-header .l, .print-footer .l { float: left; }
    .print-header .r, .print-footer .r { float: right; }
    .print-header .c, .print-footer .c { text-align: center; }
    .no-print { display: none !important; }
    .vuln-card, table, .cover, .topo-asset { break-inside: avoid; }
    h2 { break-after: avoid; }
  }
  .pfh-l { display: inline-block; width: 32%; }
  .pfh-r { display: inline-block; width: 32%; text-align: right; }
  .pfh-c { display: inline-block; width: 34%; text-align: center; }

  /* ===== 封面 ===== */
  .cover {
    border: 1px solid #e5e7eb; border-radius: 12px; padding: 40px 44px; margin-bottom: 26px;
    background: linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%);
  }
  .cover .brand { font-size: 12.5px; font-weight: 700; color: {{.Accent}}; letter-spacing: 2px; }
  .cover h1 { font-size: 27px; margin: 10px 0 6px; color: #111827; }
  .cover .sub { color: #6b7280; font-size: 13.5px; }
  .cover .meta { margin-top: 24px; border-top: 1px solid #e5e7eb; padding-top: 14px;
    font-size: 13px; color: #374151; line-height: 2.05; }
  .risk { display: inline-block; padding: 3px 14px; border-radius: 999px; font-weight: 700; font-size: 13px; }
  .risk-critical { background: #fee2e2; color: #7f1d1d; }
  .risk-high { background: #fee2e2; color: #b91c1c; }
  .risk-medium { background: #ffedd5; color: #c2410c; }
  .risk-low { background: #fef9c3; color: #a16207; }
  .risk-none { background: #dcfce7; color: #15803d; }

  /* ===== 章节标题 ===== */
  h2 { font-size: 16.5px; border-left: 4px solid {{.Accent}}; padding-left: 10px;
    margin: 26px 0 12px; color: #111827; }
  h3 { font-size: 14px; margin: 16px 0 8px; color: #374151; }
  .meta-line { font-size: 12.5px; color: #6b7280; margin-bottom: 10px; }

  /* ===== 统计卡片 ===== */
  .stat-cards { display: flex; gap: 10px; margin: 12px 0 6px; flex-wrap: wrap; }
  .stat { flex: 1; min-width: 106px; border: 1px solid #e5e7eb; border-radius: 10px;
    padding: 13px 10px; text-align: center; background: #fafafa; }
  .stat b { font-size: 23px; display: block; margin-bottom: 2px; }
  .stat span { font-size: 11.5px; color: #6b7280; }
  .stat.s-critical b { color: #7f1d1d; }
  .stat.s-high b { color: #b91c1c; }
  .stat.s-medium b { color: #c2410c; }
  .stat.s-low b { color: #a16207; }
  .stat.s-info b { color: #0369a1; }

  /* ===== 图表(纯 CSS, 无外部依赖) ===== */
  .chart-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: 12.5px; }
  .chart-row .c-label { width: 96px; flex-shrink: 0; color: #4b5563; }
  .chart-row .c-track { flex: 1; height: 15px; background: #f3f4f6; border-radius: 8px;
    overflow: hidden; border: 1px solid #e5e7eb; }
  .chart-row .c-fill { display: block; height: 100%; border-radius: 8px; min-width: 2px; }
  .chart-row .c-val { width: 52px; flex-shrink: 0; font-family: Consolas, monospace; color: #374151; }
  .fill-critical { background: #991b1b; }
  .fill-high { background: #dc2626; }
  .fill-medium { background: #ea580c; }
  .fill-low { background: #ca8a04; }
  .fill-info { background: #0284c7; }
  .fill-blue { background: #2563eb; }
  .fill-purple { background: #7c3aed; }

  /* 风险评分环形(conic-gradient 绘制, 无需图片) */
  .gauge { position: relative; display: inline-block; width: 92px; height: 92px; border-radius: 50%;
    background: conic-gradient({{.Accent}} {{.RiskScore}}%, #e5e7eb 0); vertical-align: middle; }
  .gauge::after { content: ""; position: absolute; inset: 11px; background: #fff; border-radius: 50%; }
  .gauge-val { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
    font-size: 20px; font-weight: 800; color: #111827; }
  .gauge-note { display: inline-block; vertical-align: middle; margin-left: 16px; font-size: 12.5px; color: #6b7280; }

  /* ===== 表格 ===== */
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-bottom: 14px; }
  th { background: #f3f4f6; text-align: left; padding: 8px 10px; border: 1px solid #e5e7eb; }
  td { padding: 7px 10px; border: 1px solid #e5e7eb; word-break: break-all; vertical-align: top; }
  .sev { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 11.5px; font-weight: 600; white-space: nowrap; }
  .sev-critical { background: #fee2e2; color: #7f1d1d; }
  .sev-high { background: #fee2e2; color: #b91c1c; }
  .sev-medium { background: #ffedd5; color: #c2410c; }
  .sev-low { background: #fef9c3; color: #a16207; }
  .sev-info { background: #e0f2fe; color: #0369a1; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
    background: #ede9fe; color: #6d28d9; white-space: nowrap; }
  .badge-ok { background: #dcfce7; color: #15803d; }

  /* ===== 漏洞详情卡 ===== */
  .vuln-card { border: 1px solid #e5e7eb; border-radius: 10px; margin-bottom: 14px; overflow: hidden; }
  .vuln-head { padding: 9px 13px; background: #f9fafb; border-bottom: 1px solid #e5e7eb;
    display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
  .vuln-head .idx { font-family: Consolas, monospace; color: #6b7280; font-size: 12px; }
  .vuln-head .t { font-weight: 700; font-size: 13.5px; flex: 1; min-width: 200px; }
  .vuln-body { padding: 11px 13px; }
  .kv { display: grid; grid-template-columns: 92px 1fr; gap: 4px 12px; font-size: 12.5px; margin-bottom: 8px; }
  .kv .k { color: #6b7280; }
  .kv .v { word-break: break-all; }
  .block-label { font-size: 12px; color: #6b7280; margin: 10px 0 4px; font-weight: 600; }
  .code-block { font-family: Consolas, monospace; font-size: 11.5px; line-height: 1.55;
    background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 7px; padding: 8px 10px;
    white-space: pre-wrap; word-break: break-all; color: #374151; }
  .fix-box { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 7px; padding: 9px 11px;
    font-size: 12.5px; line-height: 1.75; color: #14532d; }
  .pcap { font-family: Consolas, monospace; font-size: 11.5px; color: #0369a1;
    background: #f0f9ff; border: 1px solid #bae6fd; border-radius: 6px; padding: 5px 9px;
    display: inline-block; margin-top: 4px; }
  .sec-note { font-size: 11.5px; color: #9ca3af; margin-top: 5px; }

  /* ===== 资产拓扑 ===== */
  .topo-wrap { border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px; background: #fcfdff; }
  .topo-legend { font-size: 11.5px; color: #6b7280; margin-bottom: 10px; line-height: 1.9; }
  .topo-legend i { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin: 0 4px 0 12px; vertical-align: -1px; }
  .topo-asset { border: 1px solid #e5e7eb; border-radius: 9px; margin-bottom: 9px; overflow: hidden; background: #fff; }
  .topo-asset-head { padding: 7px 11px; background: #f9fafb; border-bottom: 1px solid #e5e7eb;
    display: flex; align-items: center; gap: 9px; font-size: 12.5px; flex-wrap: wrap; }
  .topo-asset-head .ip { font-family: Consolas, monospace; font-weight: 700; }
  .topo-asset-head .sep { color: #d1d5db; }
  .topo-ports { padding: 8px 11px; display: flex; flex-wrap: wrap; gap: 6px; }
  .topo-port { font-family: Consolas, monospace; font-size: 11.5px; border-radius: 6px;
    padding: 3px 9px; border: 1px solid #d1d5db; color: #6b7280; background: #fff; }
  .topo-port .svc { color: #9ca3af; }
  .r-critical { border-color: #991b1b; color: #7f1d1d; background: #fee2e2; }
  .r-high { border-color: #dc2626; color: #b91c1c; background: #fee2e2; }
  .r-medium { border-color: #ea580c; color: #c2410c; background: #ffedd5; }
  .r-low { border-color: #ca8a04; color: #a16207; background: #fef9c3; }
  .r-info { border-color: #0284c7; color: #0369a1; background: #e0f2fe; }
  .r-none { border-color: #d1d5db; color: #6b7280; background: #fff; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }
  .dot-on { background: #22c55e; }
  .dot-off { background: #d1d5db; }
  .dot-unknown { background: #facc15; }

  /* ===== 结论 / 页脚 ===== */
  .rec { background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px 16px;
    font-size: 13px; line-height: 1.9; }
  .footer { margin-top: 30px; padding-top: 13px; border-top: 1px solid #e5e7eb; color: #9ca3af;
    font-size: 11.5px; line-height: 1.85; }
</style>
</head>
<body>

<!-- 打印页眉页脚(屏幕不显示, 打印时每页重复) -->
<div class="print-header">
  <span class="pfh-l">{{.Header.HeaderLeft}}</span><span class="pfh-c">{{.Header.HeaderCenter}}</span><span class="pfh-r">{{.Header.HeaderRight}}</span>
</div>
<div class="print-footer">
  <span class="pfh-l">{{.Header.FooterLeft}}</span><span class="pfh-c">{{.Header.FooterCenter}}</span><span class="pfh-r">{{.Header.FooterRight}}</span>
</div>

<div class="page">

  <!-- ===== 封面 ===== -->
  <div class="cover">
    <div class="brand">{{.LogoText}}</div>
    <h1>{{.Title}}</h1>
    <div class="sub">{{.Subtitle}}</div>
    <div class="meta">
      <div>整体风险等级:
        {{if eq .RiskLevel "严重"}}<span class="risk risk-critical">严重</span>
        {{else if eq .RiskLevel "高危"}}<span class="risk risk-high">高危</span>
        {{else if eq .RiskLevel "中危"}}<span class="risk risk-medium">中危</span>
        {{else if eq .RiskLevel "低危"}}<span class="risk risk-low">低危</span>
        {{else}}<span class="risk risk-none">未发现风险</span>{{end}}
        <span style="margin-left:10px;color:#6b7280">风险评分 {{.RiskScore}} / 100</span>
      </div>
      <div>资产范围: 共 {{.Stats.AssetTotal}} 个资产, {{.Stats.PortTotal}} 个开放端口{{if .Scans}}；扫描任务 {{len .Scans}} 个{{end}}</div>
      <div>漏洞统计: 共 {{.Stats.VulnTotal}} 项（严重 {{.Stats.Critical}} / 高危 {{.Stats.High}} / 中危 {{.Stats.Medium}} / 低危 {{.Stats.Low}} / 信息 {{.Stats.Info}}）</div>
      <div>操作者 / 单位: {{if .Operator}}{{.Operator}}{{else}}-{{end}}</div>
      <div>扫描工具: {{.Tool}}</div>
      <div>报告生成时间: {{.Time}}</div>
      {{if .Stats.FalsePos}}<div>已排除人工确认误报: {{.Stats.FalsePos}} 项</div>{{end}}
    </div>
  </div>

  <!-- ===== 一、风险总览 ===== -->
  <h2>一、风险总览</h2>
  <div class="stat-cards">
    <div class="stat"><b>{{.Stats.VulnTotal}}</b><span>发现总数</span></div>
    <div class="stat s-critical"><b>{{.Stats.Critical}}</b><span>严重</span></div>
    <div class="stat s-high"><b>{{.Stats.High}}</b><span>高危</span></div>
    <div class="stat s-medium"><b>{{.Stats.Medium}}</b><span>中危</span></div>
    <div class="stat s-low"><b>{{.Stats.Low}}</b><span>低危</span></div>
    <div class="stat s-info"><b>{{.Stats.Info}}</b><span>信息</span></div>
  </div>

  <h3>风险评分与等级分布</h3>
  <div class="gauge"><span class="gauge-val">{{.RiskScore}}</span></div>
  <span class="gauge-note">综合风险评分 {{.RiskScore}} / 100 —— 当前等级 <b>{{.RiskLevel}}</b><br>评分按等级加权（严重 40 / 高危 15 / 中危 5 / 低危 1）饱和计算，上限 100。</span>
  <div style="height:12px"></div>
  {{if .Stats.VulnTotal}}
  {{range .SevBars}}
  <div class="chart-row">
    <span class="c-label">{{.Name}}</span>
    <span class="c-track"><span class="c-fill {{.Class}}" style="width:{{.Pct}}%"></span></span>
    <span class="c-val">{{.Count}}</span>
  </div>
  {{end}}
  {{else}}<div class="rec">本次扫描未发现风险项。</div>{{end}}

  <h3>风险构成</h3>
  <table>
    <tr><th style="width:150px">指标</th><th>数值</th><th style="width:150px">指标</th><th>数值</th></tr>
    <tr><td>资产总数</td><td>{{.Stats.AssetTotal}}</td><td>开放端口总数</td><td>{{.Stats.PortTotal}}</td></tr>
    <tr><td>带 CVE 编号</td><td>{{.Stats.WithCVE}}</td><td>含验证证据</td><td>{{.Stats.WithEvidence}}</td></tr>
    <tr><td>含修复建议</td><td>{{.Stats.WithFix}}</td><td>含 PCAP 附件</td><td>{{.Stats.WithPcap}}</td></tr>
  </table>

  {{if .SourceBars}}
  <h3>发现来源分布</h3>
  {{range .SourceBars}}
  <div class="chart-row">
    <span class="c-label">{{.Name}}</span>
    <span class="c-track"><span class="c-fill fill-blue" style="width:{{.Pct}}%"></span></span>
    <span class="c-val">{{.Count}}</span>
  </div>
  {{end}}
  {{end}}

  {{if .ProbeBars}}
  <h3>探针节点分布</h3>
  {{range .ProbeBars}}
  <div class="chart-row">
    <span class="c-label">{{.Name}}</span>
    <span class="c-track"><span class="c-fill fill-purple" style="width:{{.Pct}}%"></span></span>
    <span class="c-val">{{.Count}}</span>
  </div>
  {{end}}
  {{end}}

  {{if .Scans}}
  <h3>扫描范围</h3>
  <table>
    <tr><th style="width:110px">类型</th><th>目标</th><th style="width:110px">执行节点</th><th style="width:88px">状态</th><th style="width:150px">完成时间</th></tr>
    {{range .Scans}}
    <tr><td>{{.Type}}</td><td>{{.Target}}</td>
      <td>{{if .ProbeNode}}{{.ProbeNode}}{{else}}中心本地{{end}}</td>
      <td>{{.Status}}</td>
      <td>{{if .FinishedAt}}{{.FinishedAt.Format "2006-01-02 15:04:05"}}{{else}}-{{end}}</td></tr>
    {{end}}
  </table>
  {{end}}

  {{if .ShowTopology}}
  <!-- ===== 资产拓扑 ===== -->
  <h2>{{.SecTopology}}、资产拓扑</h2>
  {{if .TopoAssets}}
  <div class="topo-wrap">
    <div class="topo-legend">
      资产 {{.Topology.Stats.Assets}} 个（在线 {{.Topology.Stats.Online}} / 状态未知 {{.Topology.Stats.Offline}}）·
      端口 {{.Topology.Stats.Ports}} 个 · 服务 {{.Topology.Stats.Services}} 类 ·
      高危及以上资产 {{.Topology.Stats.AtRisk}} 个
      <br>颜色标记:
      <i style="background:#991b1b"></i>严重<i style="background:#dc2626"></i>高危<i style="background:#ea580c"></i>中危<i style="background:#ca8a04"></i>低危<i style="background:#d1d5db"></i>无风险
    </div>
    {{range .TopoAssets}}
    <div class="topo-asset">
      <div class="topo-asset-head">
        <span class="dot {{if .Unknown}}dot-unknown{{else if .Online}}dot-on{{else}}dot-off{{end}}"></span>
        <span class="ip">{{.IP}}</span>
        {{if .Hostname}}<span>{{.Hostname}}</span>{{end}}
        {{if .OS}}<span class="sep">|</span><span>{{.OS}}</span>{{end}}
        <span class="sep">|</span>
        <span class="badge {{if eq .Risk "none"}}badge-ok{{end}}">{{.RiskName}}</span>
        <span>漏洞 {{.VulnCount}}</span>
        {{if .ProbeNode}}<span class="sep">|</span><span>节点 {{.ProbeNode}}</span>{{end}}
      </div>
      <div class="topo-ports">
        {{if .Ports}}{{range .Ports}}<span class="topo-port r-{{.Risk}}">{{.Port}}{{if .Service}}<span class="svc">/{{.Service}}</span>{{end}}{{if .VulnCount}} · {{.VulnCount}} 风险{{end}}</span>{{end}}
        {{else}}<span class="sec-note">未发现开放端口</span>{{end}}
      </div>
    </div>
    {{end}}
  </div>
  {{else}}<div class="rec">本次报告范围内未发现资产。</div>{{end}}
  {{end}}

  <!-- ===== 资产清单 ===== -->
  <h2>{{.SecAssets}}、资产清单</h2>
  {{if .Assets}}
  <table>
    <tr>
      <th style="width:118px">IP</th><th style="width:118px">主机名</th><th style="width:106px">操作系统</th>
      <th style="width:126px">开放端口</th><th>服务 / 版本</th><th style="width:96px">执行节点</th>
    </tr>
    {{range .Assets}}
    <tr>
      <td style="font-family:Consolas,monospace">{{.IP}}</td>
      <td>{{if .Hostname}}{{.Hostname}}{{else}}-{{end}}</td>
      <td>{{if .OS}}{{.OS}}{{else}}-{{end}}</td>
      <td style="font-family:Consolas,monospace">{{if .Ports}}{{range $i, $p := .Ports}}{{if $i}}, {{end}}{{$p}}{{end}}{{else}}-{{end}}</td>
      <td>{{if .Service}}{{.Service}}{{if .Version}} <span class="badge">{{.Version}}</span>{{end}}{{else}}-{{end}}{{if .Banner}}<div class="sec-note">{{.Banner}}</div>{{end}}</td>
      <td>{{if .ProbeNode}}{{.ProbeNode}}{{else}}本地{{end}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}<div class="rec">本次报告范围内无资产记录。</div>{{end}}

  <!-- ===== 漏洞汇总与详情 ===== -->
  <h2>{{.SecVulns}}、漏洞分级汇总与详情</h2>
  {{if .Vulns}}
  <table>
    <tr>
      <th style="width:34px">#</th><th style="width:66px">级别</th><th>漏洞标题</th>
      <th style="width:140px">CVE</th><th style="width:116px">资产</th><th style="width:56px">端口</th>
      <th style="width:58px">置信度</th><th style="width:78px">状态</th><th style="width:76px">渗透验证</th>
    </tr>
    {{range .Vulns}}
    <tr>
      <td>{{.Index}}</td>
      <td><span class="sev sev-{{.Severity}}">{{.SevName}}</span></td>
      <td>{{.Title}}{{if .FP}} <span class="badge">误报</span>{{end}}</td>
      <td style="font-family:Consolas,monospace">{{if .CVE}}{{.CVE}}{{else}}-{{end}}</td>
      <td style="font-family:Consolas,monospace">{{.AssetIP}}</td>
      <td style="font-family:Consolas,monospace">{{if .Port}}{{.Port}}{{else}}-{{end}}</td>
      <td>{{.Confidence}}</td>
      <td>{{.StatusName}}</td>
      <td>{{if .PentaExploit}}<span class="badge">{{.PentaExploit}}</span>{{else}}-{{end}}</td>
    </tr>
    {{end}}
  </table>

  <h3>漏洞详情</h3>
  {{range .Vulns}}
  <div class="vuln-card">
    <div class="vuln-head">
      <span class="idx">#{{.Index}}</span>
      <span class="sev sev-{{.Severity}}">{{.SevName}}</span>
      <span class="t">{{.Title}}</span>
      {{if .CVE}}<span class="badge">{{.CVE}}</span>{{end}}
      <span class="badge {{if eq .Status "fixed"}}badge-ok{{end}}">{{.StatusName}}</span>
    </div>
    <div class="vuln-body">
      <div class="kv">
        <span class="k">资产</span><span class="v" style="font-family:Consolas,monospace">{{.AssetIP}}{{if .Port}}:{{.Port}}{{end}}{{if .Protocol}} ({{.Protocol}}){{end}}</span>
        <span class="k">置信度</span><span class="v">{{.Confidence}} —— {{.ConfidenceNote}}</span>
        <span class="k">来源</span><span class="v">{{if .Source}}{{.Source}}{{else}}内置引擎{{end}}</span>
        <span class="k">发现时间</span><span class="v">{{if .FoundAt}}{{.FoundAt}}{{else}}-{{end}}</span>
        {{if .CVELink}}<span class="k">CVE 详情</span><span class="v">{{.CVELink}}</span>{{end}}
        {{if .FP}}<span class="k">误报说明</span><span class="v">{{if .FPNote}}{{.FPNote}}{{else}}人工标记为误报{{end}}</span>{{end}}
      </div>

      {{if .Description}}
      <div class="block-label">漏洞描述</div>
      <div class="code-block">{{.Description}}</div>
      {{end}}

      {{if .Evidence}}
      <div class="block-label">验证证据</div>
      <div class="code-block">{{.Evidence}}</div>
      {{end}}

      {{if .Requests}}
      <div class="block-label">原始请求 / 响应</div>
      {{range .Requests}}
      {{if .Request}}<div class="code-block">{{.Request}}</div>{{end}}
      {{if .Response}}<div class="code-block" style="margin-top:6px">{{.Response}}</div>{{end}}
      {{end}}
      {{end}}

      {{if .PcapFile}}
      <div class="block-label">PCAP 抓包附件</div>
      <div class="pcap">附件路径: {{.PcapFile}}</div>
      <div class="sec-note">抓包文件由扫描节点本地保存，可使用 Wireshark 打开查看完整报文交互；如需随报告归档，请从上述路径拷贝。</div>
      {{end}}

      <div class="block-label">修复建议</div>
      <div class="fix-box">{{.Fix}}</div>
    </div>
  </div>
  {{end}}
  {{else}}<div class="rec">本次报告范围内无漏洞记录。</div>{{end}}

  <!-- ===== 渗透验证结果(阶段 5: 扫描+渗透验证整合报告; 无数据不渲染) ===== -->
  {{if .Penta}}
  <h2>{{.SecPenta}}、渗透验证结果</h2>
  <div class="sec-note">验证结论来自渗透工作台(仅对授权目标实施, 操作全程审计留痕)。「可利用」= 验证中实际观测到漏洞行为, 完整命令日志与响应证据留存于平台渗透工作台。</div>
  <table>
    <tr>
      <th>目标</th><th>验证对象</th><th style="width:140px">CVE</th>
      <th style="width:90px">验证结论</th><th style="width:70px">定级</th>
      <th>摘要</th><th style="width:150px">验证时间</th><th style="width:80px">操作者</th>
    </tr>
    {{range .Penta}}
    <tr>
      <td style="font-family:Consolas,monospace">{{.Target}}</td>
      <td>{{.Title}}</td>
      <td style="font-family:Consolas,monospace">{{if .CVE}}{{.CVE}}{{else}}-{{end}}</td>
      <td><span class="sev sev-{{if eq .Exploitability "可利用"}}critical{{else if eq .Exploitability "部分利用"}}high{{else}}low{{end}}">{{.Exploitability}}</span></td>
      <td>{{if .RiskLevel}}{{.RiskLevel}}{{else}}-{{end}}</td>
      <td>{{if .Summary}}{{.Summary}}{{else}}-{{end}}</td>
      <td style="font-family:Consolas,monospace">{{.VerifiedAt}}</td>
      <td>{{.Operator}}</td>
    </tr>
    {{end}}
  </table>
  {{end}}

  <!-- ===== 总体建议 ===== -->
  <h2>{{.SecAdvice}}、总体结论与建议</h2>
  <div class="rec">{{.Summary}}</div>

  <div class="footer">
    {{.Title}} · 由 {{.Tool}} 于 {{.Time}} 自动生成<br>
    {{.Header.Disclaimer}}
  </div>

</div>
</body>
</html>
`
