package report

import (
	"strings"
	"testing"
	"time"

	"yugsight/models"
)

// ===== 测试数据构造 =====

func mkVuln(ip, title, sev string, port int) *models.Vuln {
	return &models.Vuln{
		ID:         "v-" + ip + "-" + title,
		AssetIP:    ip,
		Title:      title,
		Severity:   sev,
		Port:       port,
		Protocol:   "tcp",
		Confidence: 80,
		Source:     "builtin",
		FoundAt:    time.Now(),
		LastSeenAt: time.Now(),
		Status:     models.VulnStatusNew,
	}
}

func mkAsset(ip string, ports []int, svc string) *models.Asset {
	a := models.NewAsset(ip)
	a.Ports = ports
	a.Service = svc
	a.FoundAt = time.Now()
	return a
}

// ===== 筛选 =====

func TestFilterSeverity(t *testing.T) {
	snap := &Snapshot{
		Assets: []*models.Asset{mkAsset("10.0.0.1", []int{80}, "80/http")},
		Vulns: []*models.Vuln{
			mkVuln("10.0.0.1", "严重漏洞", models.SeverityCritical, 80),
			mkVuln("10.0.0.1", "高危漏洞", models.SeverityHigh, 80),
			mkVuln("10.0.0.1", "低危漏洞", models.SeverityLow, 80),
		},
	}
	out, st := Filter{Severity: []string{"critical", "high"}}.Apply(snap)
	if st.VulnTotal != 2 {
		t.Fatalf("等级筛选应保留 2 条, 实际 %d", st.VulnTotal)
	}
	if len(snap.Vulns) != 3 {
		t.Fatal("筛选不得污染原快照(必须返回副本)")
	}
	// 资产不按风险维度过滤(否则用户会看到"没有资产"的错误结论)
	if len(out.Assets) != 1 {
		t.Fatalf("资产应保留 1 条, 实际 %d", len(out.Assets))
	}
}

func TestFilterCIDRAndIP(t *testing.T) {
	snap := &Snapshot{Vulns: []*models.Vuln{
		mkVuln("192.168.1.5", "A", models.SeverityHigh, 80),
		mkVuln("192.168.2.5", "B", models.SeverityHigh, 80),
		mkVuln("10.0.0.5", "C", models.SeverityHigh, 80),
	}}
	_, st := Filter{CIDR: "192.168.1.0/24"}.Apply(snap)
	if st.VulnTotal != 1 {
		t.Fatalf("CIDR 筛选应保留 1 条, 实际 %d", st.VulnTotal)
	}
	_, st2 := Filter{IP: "10.0.0.5"}.Apply(snap)
	if st2.VulnTotal != 1 {
		t.Fatalf("IP 筛选应保留 1 条, 实际 %d", st2.VulnTotal)
	}
	// 非法 CIDR 被忽略(不能反过来把全部数据滤掉)
	_, st3 := Filter{CIDR: "not-a-cidr"}.Apply(snap)
	if st3.VulnTotal != 3 {
		t.Fatalf("非法 CIDR 应被忽略, 实际 %d", st3.VulnTotal)
	}
}

func TestFilterCVE(t *testing.T) {
	v1 := mkVuln("10.0.0.1", "Log4j", models.SeverityCritical, 8080)
	v1.CVE = "cve-2021-44228"
	v2 := mkVuln("10.0.0.1", "Spring", models.SeverityHigh, 8080)
	v2.CVE = "CVE-2022-22965"
	v3 := mkVuln("10.0.0.1", "无 CVE 项", models.SeverityLow, 80)

	snap := &Snapshot{Vulns: []*models.Vuln{v1, v2, v3}}
	_, st := Filter{CVE: "cve-2021-44228"}.Apply(snap)
	if st.VulnTotal != 1 {
		t.Fatalf("CVE 精确筛选应保留 1 条, 实际 %d", st.VulnTotal)
	}
	// 前缀匹配
	_, st2 := Filter{CVE: "CVE-2021"}.Apply(snap)
	if st2.VulnTotal != 1 {
		t.Fatalf("CVE 前缀筛选应保留 1 条, 实际 %d", st2.VulnTotal)
	}
}

func TestFilterTimeWindow(t *testing.T) {
	now := time.Now()
	old := mkVuln("10.0.0.1", "旧", models.SeverityHigh, 80)
	old.FoundAt = now.Add(-48 * time.Hour)
	fresh := mkVuln("10.0.0.1", "新", models.SeverityHigh, 80)
	fresh.FoundAt = now.Add(-1 * time.Hour)

	snap := &Snapshot{Vulns: []*models.Vuln{old, fresh}}
	_, st := Filter{TimeFrom: now.Add(-24 * time.Hour)}.Apply(snap)
	if st.VulnTotal != 1 {
		t.Fatalf("时间窗筛选应保留 1 条, 实际 %d", st.VulnTotal)
	}
}

func TestFilterExcludeFalsePositive(t *testing.T) {
	fp := mkVuln("10.0.0.1", "误报项", models.SeverityHigh, 80)
	fp.FalsePositive = true
	real := mkVuln("10.0.0.1", "真实项", models.SeverityHigh, 80)

	snap := &Snapshot{Vulns: []*models.Vuln{fp, real}}
	// 默认排除误报(报告不能统计误报)
	_, st := Filter{}.Apply(snap)
	if st.VulnTotal != 1 {
		t.Fatalf("默认应排除误报, 实际 %d", st.VulnTotal)
	}
	if st.FalsePos != 1 {
		t.Fatalf("应记录被排除的误报数, 实际 %d", st.FalsePos)
	}
	// 显式包含
	no := false
	_, st2 := Filter{ExcludeFalsePositive: &no}.Apply(snap)
	if st2.VulnTotal != 2 {
		t.Fatalf("显式包含误报时应为 2, 实际 %d", st2.VulnTotal)
	}
}

func TestParseSeverityList(t *testing.T) {
	if got := ParseSeverityList(""); got != nil {
		t.Fatalf("空串应返回 nil, 实际 %v", got)
	}
	got := ParseSeverityList("high,critical")
	if len(got) != 2 || got[0] != models.SeverityHigh {
		t.Fatalf("解析结果错误: %v", got)
	}
	// 未知值归一化为 low(models 既有口径)
	got2 := ParseSeverityList("unknown")
	if len(got2) != 1 || got2[0] != models.SeverityLow {
		t.Fatalf("未知等级应归一化为 low, 实际 %v", got2)
	}
}

// ===== 统计与风险评分 =====

func TestComputeStatsAndRiskScore(t *testing.T) {
	snap := &Snapshot{
		Assets: []*models.Asset{
			mkAsset("10.0.0.1", []int{80, 443}, "80/http"),
			mkAsset("10.0.0.2", []int{22}, "22/ssh"),
		},
		Vulns: []*models.Vuln{
			mkVuln("10.0.0.1", "Critical", models.SeverityCritical, 80),
			mkVuln("10.0.0.1", "High", models.SeverityHigh, 80),
			mkVuln("10.0.0.2", "Info", models.SeverityInfo, 22),
		},
	}
	st := ComputeStats(snap)
	if st.AssetTotal != 2 || st.PortTotal != 3 {
		t.Fatalf("资产/端口统计错误: %+v", st)
	}
	if st.Critical != 1 || st.High != 1 || st.Info != 1 || st.VulnTotal != 3 {
		t.Fatalf("等级统计错误: %+v", st)
	}
	if st.RiskLevel != "严重" {
		t.Fatalf("存在严重漏洞时应为严重等级, 实际 %s", st.RiskLevel)
	}
	if st.WithFix != 3 {
		t.Fatalf("所有漏洞都应有修复建议(兜底), 实际 %d", st.WithFix)
	}
}

func TestRiskScoreSaturates(t *testing.T) {
	// 饱和而非归一化: 10 条低危不应等于 1 条严重
	low := SnapshotStats{Low: 10}
	lowScore, _ := riskScore(low)
	crit := SnapshotStats{Critical: 1}
	critScore, _ := riskScore(crit)
	if lowScore >= critScore {
		t.Fatalf("低危 10 条(%d) 不应 >= 严重 1 条(%d)", lowScore, critScore)
	}
	// 上限 100
	lots := SnapshotStats{Critical: 10}
	if score, _ := riskScore(lots); score != 100 {
		t.Fatalf("评分应饱和到 100, 实际 %d", score)
	}
	if score, level := riskScore(SnapshotStats{}); score != 0 || level != "无风险" {
		t.Fatalf("空统计应为 0/无风险, 实际 %d/%s", score, level)
	}
}

// ===== 修复建议 / CVE 提取 =====

func TestFixOfBuiltinAndGeneric(t *testing.T) {
	// 关键字规则优先于端口规则: "未授权访问" 比 "Redis 通用加固" 更精确,
	// 报告应给出针对未授权的处置步骤
	v := mkVuln("10.0.0.1", "Redis 未授权访问", models.SeverityHigh, 6379)
	fix := FixOf(v)
	if !strings.Contains(fix, "未授权") && !strings.Contains(fix, "认证") {
		t.Fatalf("未授权关键字规则未命中: %s", fix)
	}

	// 关键字未命中时按端口退化(Redis 端口规则)
	vPort := mkVuln("10.0.0.1", "服务版本过期", models.SeverityMedium, 6379)
	if pfix := FixOf(vPort); !strings.Contains(pfix, "requirepass") {
		t.Fatalf("Redis 端口规则未命中: %s", pfix)
	}

	// 端口与关键字都未命中, 且无 CVE -> 按等级兜底
	v2 := mkVuln("10.0.0.1", "某个未知问题 xyz123", models.SeverityHigh, 12345)
	if fix := FixOf(v2); !strings.Contains(fix, "24 小时") {
		t.Fatalf("高危兜底建议未命中: %s", fix)
	}
	v3 := mkVuln("10.0.0.1", "未知信息项", models.SeverityInfo, 12345)
	if fix := FixOf(v3); !strings.Contains(fix, "信息类") {
		t.Fatalf("信息级兜底建议未命中: %s", fix)
	}

	// 带 CVE 但无端口/关键字命中 -> CVE 兜底规则
	v4 := mkVuln("10.0.0.1", "某组件缺陷", models.SeverityHigh, 12345)
	v4.CVE = "CVE-2023-999999"
	if fix := FixOf(v4); !strings.Contains(fix, "厂商已修复版本") {
		t.Fatalf("CVE 兜底规则未命中: %s", fix)
	}
}

func TestCVEOfExtractsFromTitle(t *testing.T) {
	v := mkVuln("10.0.0.1", "Apache Log4j2 RCE (CVE-2021-44228)", models.SeverityCritical, 8080)
	if got := CVEOf(v); got != "CVE-2021-44228" {
		t.Fatalf("应从标题提取 CVE, 实际 %q", got)
	}
	v2 := mkVuln("10.0.0.1", "无编号项", models.SeverityLow, 80)
	if got := CVEOf(v2); got != "" {
		t.Fatalf("无 CVE 应返回空, 实际 %q", got)
	}
}

// ===== 拓扑 =====

func TestBuildTopology(t *testing.T) {
	assets := []*models.Asset{
		mkAsset("10.0.0.1", []int{80, 22}, "80/http,22/ssh"),
		mkAsset("10.0.0.2", []int{3306}, "3306/mysql"),
	}
	vulns := []*models.Vuln{
		mkVuln("10.0.0.1", "Web 漏洞", models.SeverityHigh, 80),
		mkVuln("10.0.0.2", "数据库弱口令", models.SeverityCritical, 3306),
	}
	topo := BuildTopology(assets, vulns)
	if topo.Stats.Assets != 2 {
		t.Fatalf("资产节点数错误: %d", topo.Stats.Assets)
	}
	if topo.Stats.Ports != 3 {
		t.Fatalf("端口节点数错误: %d", topo.Stats.Ports)
	}
	if topo.Stats.Services != 3 {
		t.Fatalf("服务节点数错误: %d", topo.Stats.Services)
	}
	if topo.Stats.AtRisk != 2 {
		t.Fatalf("高危及以上资产应为 2, 实际 %d", topo.Stats.AtRisk)
	}

	// 资产节点的风险 = 其下最高风险
	var a1 *TopoNode
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "10.0.0.1" {
			a1 = &topo.Nodes[i]
		}
	}
	if a1 == nil {
		t.Fatal("未找到资产节点 10.0.0.1")
	}
	if a1.Risk != models.SeverityHigh {
		t.Fatalf("资产风险应为 high, 实际 %s", a1.Risk)
	}
	if a1.VulnCount != 1 {
		t.Fatalf("资产漏洞数应为 1, 实际 %d", a1.VulnCount)
	}

	// 端口节点: 80 端口应带 http 服务且风险为 high
	var p80 *TopoNode
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "10.0.0.1:80" {
			p80 = &topo.Nodes[i]
		}
	}
	if p80 == nil || p80.Service != "http" || p80.Risk != models.SeverityHigh {
		t.Fatalf("端口节点错误: %+v", p80)
	}

	// 边数 = 每个端口一条 host-port + 每个有服务的端口一条 port-service
	if len(topo.Edges) != 3+3 {
		t.Fatalf("边数应为 6, 实际 %d", len(topo.Edges))
	}
}

func TestBuildTopologyOrphanVuln(t *testing.T) {
	// 漏洞涉及但资产表未入库: 应补一个"状态未知"的资产节点, 而不是丢失
	vulns := []*models.Vuln{mkVuln("10.9.9.9", "孤儿漏洞", models.SeverityHigh, 8080)}
	topo := BuildTopology(nil, vulns)
	if topo.Stats.Assets != 1 {
		t.Fatalf("应补 1 个资产节点, 实际 %d", topo.Stats.Assets)
	}
	for _, n := range topo.Nodes {
		if n.Kind == KindAsset && !n.Unknown {
			t.Fatal("孤儿资产节点应标记 Unknown(在线状态未知), 否则前端会误显示为离线")
		}
	}
}

func TestBuildTopologyEmpty(t *testing.T) {
	topo := BuildTopology(nil, nil)
	if topo == nil {
		t.Fatal("空输入也应返回非 nil 拓扑")
	}
	if len(topo.Nodes) != 0 || len(topo.Edges) != 0 {
		t.Fatalf("空输入应产出空拓扑: %+v", topo)
	}
}

func TestParseServices(t *testing.T) {
	m := parseServices("80/http, 443/https ,bad,22/ssh")
	if m[80] != "http" || m[443] != "https" || m[22] != "ssh" {
		t.Fatalf("服务解析错误: %v", m)
	}
	if _, ok := m[0]; ok {
		t.Fatal("非法 token 不应进入结果")
	}
}

// ===== 历史对比 =====

func TestCompareNewFixedPersisted(t *testing.T) {
	base := &Snapshot{Vulns: []*models.Vuln{
		mkVuln("10.0.0.1", "一直存在", models.SeverityHigh, 80),
		mkVuln("10.0.0.1", "已修复项", models.SeverityMedium, 80),
	}}
	target := &Snapshot{Vulns: []*models.Vuln{
		mkVuln("10.0.0.1", "一直存在", models.SeverityHigh, 80),
		mkVuln("10.0.0.2", "新增项", models.SeverityCritical, 443),
	}}
	diff := Compare(base, target, "b1", "t1")

	if diff.Stats.NewCount != 1 || len(diff.New) != 1 || diff.New[0].Title != "新增项" {
		t.Fatalf("新增识别错误: %+v", diff.New)
	}
	if diff.Stats.FixedCount != 1 || diff.Fixed[0].Title != "已修复项" {
		t.Fatalf("已修复识别错误: %+v", diff.Fixed)
	}
	if diff.Stats.PersistedCount != 1 || diff.Persisted[0].Title != "一直存在" {
		t.Fatalf("仍然存在识别错误: %+v", diff.Persisted)
	}
	if diff.Stats.NewCritical != 1 {
		t.Fatalf("新增严重数应为 1, 实际 %d", diff.Stats.NewCritical)
	}
	if diff.Stats.Delta != 0 {
		t.Fatalf("总数 2->2 变化应为 0, 实际 %d", diff.Stats.Delta)
	}
	// 已修复条目取基线侧详情
	if diff.Fixed[0].BaseSeverity != models.SeverityMedium {
		t.Fatalf("已修复条目应带基线等级, 实际 %s", diff.Fixed[0].BaseSeverity)
	}
	// 资产维度: 10.0.0.2 为新增资产
	if len(diff.NewAssets) != 1 || diff.NewAssets[0] != "10.0.0.2" {
		t.Fatalf("新增资产识别错误: %v", diff.NewAssets)
	}
}

func TestCompareExcludesFalsePositive(t *testing.T) {
	fp := mkVuln("10.0.0.1", "误报项", models.SeverityHigh, 80)
	fp.FalsePositive = true
	base := &Snapshot{Vulns: []*models.Vuln{fp}}
	target := &Snapshot{Vulns: []*models.Vuln{}}

	diff := Compare(base, target, "b", "t")
	// 误报"消失"不能被当作"已修复"(这会向客户虚报修复成果)
	if diff.Stats.FixedCount != 0 {
		t.Fatalf("误报不应参与对比, 实际已修复 %d", diff.Stats.FixedCount)
	}
	if diff.Stats.BaseTotal != 0 {
		t.Fatalf("基线总量应排除误报, 实际 %d", diff.Stats.BaseTotal)
	}
}

func TestCompareSeverityChange(t *testing.T) {
	b := mkVuln("10.0.0.1", "等级变化项", models.SeverityMedium, 80)
	tg := mkVuln("10.0.0.1", "等级变化项", models.SeverityHigh, 80)
	diff := Compare(&Snapshot{Vulns: []*models.Vuln{b}}, &Snapshot{Vulns: []*models.Vuln{tg}}, "b", "t")
	if len(diff.Persisted) != 1 {
		t.Fatalf("应为 1 条仍然存在, 实际 %d", len(diff.Persisted))
	}
	if diff.Persisted[0].SeverityChange != "medium -> high" {
		t.Fatalf("等级变化标注错误: %q", diff.Persisted[0].SeverityChange)
	}
}

func TestCompareSortsHighRiskFirst(t *testing.T) {
	base := &Snapshot{}
	target := &Snapshot{Vulns: []*models.Vuln{
		mkVuln("10.0.0.1", "低", models.SeverityLow, 80),
		mkVuln("10.0.0.1", "严", models.SeverityCritical, 80),
		mkVuln("10.0.0.1", "中", models.SeverityMedium, 80),
	}}
	diff := Compare(base, target, "b", "t")
	if diff.New[0].TargetSeverity != models.SeverityCritical {
		t.Fatalf("新增列表应按风险降序, 首条应为 critical, 实际 %s", diff.New[0].TargetSeverity)
	}
}

// ===== 渲染 =====

func TestRenderHTMLContainsAllSections(t *testing.T) {
	v := mkVuln("10.0.0.1", "注入漏洞 (CVE-2024-1234)", models.SeverityHigh, 80)
	v.Evidence = "HTTP/1.1 200 OK, payload reflected"
	v.Request = "GET /x?id=1' HTTP/1.1"
	v.Response = "HTTP/1.1 500 Internal Server Error"
	v.PcapFile = "capture/pcap_10.0.0.1_80.pcap"
	snap := &Snapshot{
		Title:    "测试报告",
		Operator: "安全部",
		Tool:     "Yugsight v1.0.0",
		Assets:   []*models.Asset{mkAsset("10.0.0.1", []int{80}, "80/http")},
		Vulns:    []*models.Vuln{v},
		Scans:    []ScanInfo{{ID: "st1", Type: "port", Target: "10.0.0.1", Status: "success", CreatedAt: time.Now()}},
	}
	st := ComputeStats(snap)
	html, err := Render(snap, st, DefaultHeader(), nil)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	// 任务书要求的全部章节都必须存在
	for _, want := range []string{
		"测试报告", "风险总览", "资产拓扑", "资产清单", "漏洞分级汇总与详情",
		"验证证据", "修复建议", "总体结论与建议", "CVE-2024-1234",
		"扫描范围", "风险评分", "PCAP 抓包附件", "原始请求 / 响应",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("报告缺少内容: %s", want)
		}
	}
	// 页眉页脚(打印样式)
	if !strings.Contains(html, "print-footer") {
		t.Error("报告缺少打印页眉页脚")
	}
	// 自包含: 不得出现外部资源引用
	for _, bad := range []string{"<script src=", "cdn.", "http://", "https://cdn"} {
		if strings.Contains(html, bad) {
			t.Errorf("报告不应引用外部资源: %s", bad)
		}
	}
}

func TestRenderEscapesEvidence(t *testing.T) {
	v := mkVuln("10.0.0.1", "XSS 探测", models.SeverityHigh, 80)
	v.Evidence = `<script>alert('xss')</script>`
	v.Description = `"><img src=x onerror=alert(1)>`

	snap := &Snapshot{Title: "转义测试", Vulns: []*models.Vuln{v}}
	html, err := Render(snap, ComputeStats(snap), DefaultHeader(), nil)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if strings.Contains(html, "<script>alert('xss')</script>") {
		t.Fatal("证据中的脚本未被转义 —— 报告存在 XSS 风险")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("证据应被 HTML 转义后输出")
	}
}

func TestRenderCustomHeader(t *testing.T) {
	snap := &Snapshot{Title: "页眉测试", Operator: "运维组", Vulns: []*models.Vuln{}}
	h := Header{
		HeaderLeft:   "{{title}}",
		FooterCenter: "操作人 {{operator}} 于 {{time}}",
		Disclaimer:   "自定义免责声明",
	}
	html, err := Render(snap, ComputeStats(snap), h, nil)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if !strings.Contains(html, "页眉测试") {
		t.Error("{{title}} 占位符未展开")
	}
	if !strings.Contains(html, "操作人 运维组") {
		t.Error("{{operator}} 占位符未展开")
	}
	if !strings.Contains(html, "自定义免责声明") {
		t.Error("自定义免责声明未生效")
	}
}

func TestRenderTemplateSwitches(t *testing.T) {
	snap := &Snapshot{
		Title: "开关测试",
		Assets: []*models.Asset{mkAsset("10.0.0.1", []int{80}, "80/http")},
		Vulns:  []*models.Vuln{mkVuln("10.0.0.1", "漏洞", models.SeverityHigh, 80)},
	}
	no := false
	tpl := &Template{Accent: "#ff0000", ShowTopology: &no, Subtitle: "自定义副标题"}
	html, err := Render(snap, ComputeStats(snap), Header{}, tpl)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if strings.Contains(html, "资产拓扑") {
		t.Error("关闭拓扑后不应出现该章节")
	}
	if !strings.Contains(html, "#ff0000") {
		t.Error("自定义主题色未生效")
	}
	if !strings.Contains(html, "自定义副标题") {
		t.Error("自定义副标题未生效")
	}
}

func TestPrintHTMLWrapsReport(t *testing.T) {
	report := `<!DOCTYPE html><html><head><style>body{color:red}</style></head><body><h1>报告正文</h1></body></html>`
	out := PrintHTML(report, "我的报告")
	if !strings.Contains(out, "window.print()") {
		t.Fatal("打印页应包含自动唤起打印的脚本")
	}
	if !strings.Contains(out, "报告正文") {
		t.Fatal("打印页应包含报告正文")
	}
	if !strings.Contains(out, "body{color:red}") {
		t.Fatal("打印页应保留报告样式")
	}
	// 不应出现嵌套 html/body(会破坏样式)
	if strings.Count(out, "<body") != 1 {
		t.Fatalf("打印页 body 标签数应为 1, 实际 %d", strings.Count(out, "<body"))
	}
}

func TestRenderDiffHTML(t *testing.T) {
	base := &Snapshot{Vulns: []*models.Vuln{mkVuln("10.0.0.1", "旧问题", models.SeverityMedium, 80)}}
	target := &Snapshot{Vulns: []*models.Vuln{mkVuln("10.0.0.2", "新问题", models.SeverityCritical, 443)}}
	diff := Compare(base, target, "b", "t")
	diff.BaseName, diff.TargetName = "基线轮次", "目标轮次"

	html, err := RenderDiff(diff, "对比报告", "Yugsight v1.0.0", DefaultHeader())
	if err != nil {
		t.Fatalf("对比报告渲染失败: %v", err)
	}
	for _, want := range []string{"对比报告", "差异总览", "新增漏洞", "已修复漏洞", "仍然存在的漏洞", "新问题", "旧问题", "基线轮次"} {
		if !strings.Contains(html, want) {
			t.Errorf("对比报告缺少内容: %s", want)
		}
	}
}

func TestRenderDiffNil(t *testing.T) {
	if _, err := RenderDiff(nil, "x", "y", Header{}); err == nil {
		t.Fatal("空对比数据应返回错误而非崩溃")
	}
}

// ===== 存档契约 =====

func TestArchiveEntityContract(t *testing.T) {
	a := &Archive{}
	id := a.EntityID()
	if id == "" {
		t.Fatal("存档 ID 不应为空")
	}
	if a.EntityID() != id {
		t.Fatal("存档 ID 必须稳定不变(重复调用返回同一值)")
	}
	// 默认值补全
	a2 := &Archive{}
	if err := a2.Validate(); err != nil {
		t.Fatalf("Validate 不应报错: %v", err)
	}
	if a2.Title == "" || a2.Format == "" || a2.CreatedAt.IsZero() {
		t.Fatalf("Validate 应补全缺省字段: %+v", a2)
	}
	if a2.Size != len(a2.Content) {
		t.Fatalf("Size 应等于正文长度, 实际 %d/%d", a2.Size, len(a2.Content))
	}
}

func TestTemplateEntityContract(t *testing.T) {
	tp := &Template{}
	if tp.EntityID() == "" {
		t.Fatal("模板 ID 不应为空")
	}
	if err := tp.Validate(); err != nil {
		t.Fatalf("Validate 不应报错: %v", err)
	}
	if tp.Name == "" {
		t.Fatal("模板名应有默认值")
	}
}

func TestEffectiveHeaderDefaults(t *testing.T) {
	h := EffectiveHeader(Header{})
	if h.HeaderLeft == "" || h.FooterLeft == "" || h.Disclaimer == "" {
		t.Fatalf("零值 Header 应回落到内置默认: %+v", h)
	}
	if h.ShowPageNumber == nil || !*h.ShowPageNumber {
		t.Fatal("页码开关默认应为开启")
	}
	// 自定义字段优先
	h2 := EffectiveHeader(Header{HeaderLeft: "自定义", Disclaimer: "D"})
	if h2.HeaderLeft != "自定义" || h2.Disclaimer != "D" {
		t.Fatalf("自定义值被覆盖: %+v", h2)
	}
}

func TestSummaryTextBySeverity(t *testing.T) {
	if got := SummaryText(SnapshotStats{Critical: 1}, "T", "now"); !strings.Contains(got, "严重风险") {
		t.Fatalf("有严重漏洞时结论应警示: %s", got)
	}
	if got := SummaryText(SnapshotStats{}, "T", "now"); !strings.Contains(got, "未发现明显风险") {
		t.Fatalf("无漏洞时结论应中性: %s", got)
	}
}
