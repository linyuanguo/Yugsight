package bigscreen

import (
	"testing"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/models"
)

// newTestDB 独立临时库(不触碰真实 ./data 目录)。
func newTestDB(t *testing.T) *db.Database {
	t.Helper()
	d, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// addVuln 写一条漏洞(时间字段显式给出, 便于构造趋势用例)。
func addVuln(t *testing.T, d *db.Database, ip, title, sev, status string, foundAt time.Time, fixedAt *time.Time) *db.Vuln {
	t.Helper()
	v := db.NewVuln(ip, title, sev)
	v.FoundAt = foundAt
	v.LastSeenAt = foundAt
	v.Status = status
	v.Severity = models.NormalizeSeverity(sev)
	v.FixedAt = fixedAt
	if status == models.VulnStatusFixed && v.FixedAt == nil {
		now := foundAt
		v.FixedAt = &now
	}
	if _, err := d.Vulns().Upsert(v); err != nil {
		t.Fatalf("upsert vuln: %v", err)
	}
	return v
}

// TestOverviewCounts 数字卡片: 资产总量/存活资产/漏洞分级/任务/探针。
func TestOverviewCounts(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()

	// 资产: 3 台, 其中 2 台存活
	for _, it := range []struct {
		ip    string
		alive bool
	}{{"10.0.0.1", true}, {"10.0.0.2", true}, {"10.0.0.3", false}} {
		a := db.NewAsset(it.ip)
		a.Alive = it.alive
		a.Ports = []int{80, 443}
		if _, err := d.Assets().Upsert(a); err != nil {
			t.Fatalf("upsert asset: %v", err)
		}
	}

	addVuln(t, d, "10.0.0.1", "严重-1", "critical", models.VulnStatusNew, now.Add(-time.Hour), nil)
	addVuln(t, d, "10.0.0.1", "高危-1", "high", models.VulnStatusNew, now.Add(-2*time.Hour), nil)
	addVuln(t, d, "10.0.0.2", "中危-1", "medium", models.VulnStatusDuplicate, now.Add(-3*time.Hour), nil)
	addVuln(t, d, "10.0.0.2", "低危-1", "low", models.VulnStatusNew, now.Add(-4*time.Hour), nil)
	addVuln(t, d, "10.0.0.3", "信息-1", "info", models.VulnStatusNew, now.Add(-5*time.Hour), nil)
	addVuln(t, d, "10.0.0.3", "已修复-1", "high", models.VulnStatusFixed, now.Add(-30*time.Hour), nil)

	// 任务: 1 运行中 1 待执行 1 成功 1 失败
	for _, st := range []string{db.TaskRunning, db.TaskPending, db.TaskSuccess, db.TaskFailed} {
		task := &db.ScanTask{Type: "port", Target: "10.0.0.0/24", Status: st}
		if err := d.ScanTasks().Create(task); err != nil {
			t.Fatalf("create task: %v", err)
		}
	}

	// 探针: 1 在线 1 离线
	on := &db.Probe{ID: "pb-online", Name: "edge-1", Status: db.ProbeOnline,
		Load: map[string]any{"cpuPercent": 12.5, "memPercent": 40.0, "tasksRunning": 1},
		NodeInfo: map[string]any{"hostname": "edge-1", "os": "linux", "cpuCores": 4,
			"memTotal": uint64(1000), "memUsed": uint64(400)}}
	off := &db.Probe{ID: "pb-offline", Name: "edge-2", Status: db.ProbeOffline}
	for _, p := range []*db.Probe{on, off} {
		if _, err := d.Probes().Upsert(p); err != nil {
			t.Fatalf("upsert probe: %v", err)
		}
	}

	s := Build(d, now, Options{})
	ov := s.Overview

	if ov.Assets != 3 || ov.AssetsAlive != 2 || ov.AssetsDown != 1 {
		t.Fatalf("资产指标错误: %+v", ov)
	}
	// 未修复: 4 条风险(1 严重 1 高 1 中 1 低) + 1 条 info; 已修复单独计数
	if ov.Vulns.Critical != 1 || ov.Vulns.High != 1 || ov.Vulns.Medium != 1 || ov.Vulns.Low != 1 {
		t.Fatalf("分级统计错误: %+v", ov.Vulns)
	}
	if ov.Vulns.Info != 1 {
		t.Fatalf("info 应为 1: %+v", ov.Vulns)
	}
	if ov.Vulns.Risk != 4 {
		t.Fatalf("风险类合计应为 4(不含 info): %d", ov.Vulns.Risk)
	}
	if ov.Vulns.Total != 5 {
		t.Fatalf("未修复合计应为 5: %d", ov.Vulns.Total)
	}
	if ov.VulnTotal != 6 || ov.VulnFixed != 1 {
		t.Fatalf("漏洞总量/已修复错误: total=%d fixed=%d", ov.VulnTotal, ov.VulnFixed)
	}
	if ov.TasksRunning != 2 {
		t.Fatalf("运行中任务应为 2(pending+running): %d", ov.TasksRunning)
	}
	if ov.TasksSuccess != 1 || ov.TasksFailed != 1 {
		t.Fatalf("任务成功/失败统计错误: %+v", ov)
	}
	if ov.Probes != 2 || ov.ProbesOnline != 1 || ov.ProbesOffline != 1 {
		t.Fatalf("探针统计错误: %+v", ov)
	}
	if len(s.Probes) != 2 || !s.Probes[0].Online {
		t.Fatalf("探针列表应在线优先: %+v", s.Probes)
	}
	if s.Probes[0].CPUPercent == nil || *s.Probes[0].CPUPercent != 12.5 {
		t.Fatalf("在线探针 CPU 负载未解析: %+v", s.Probes[0])
	}
	if s.Probes[1].CPUPercent != nil {
		t.Fatalf("离线探针负载应为 nil(区别于 0): %+v", s.Probes[1])
	}
}

// TestAssetAliveDefault 老数据(无 alive 字段)按未存活处理, 不因缺字段而虚增存活数。
func TestAssetAliveDefault(t *testing.T) {
	d := newTestDB(t)
	a := db.NewAsset("10.1.1.1") // Alive 零值
	if _, err := d.Assets().Upsert(a); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	n, err := d.Assets().CountAlive()
	if err != nil {
		t.Fatalf("CountAlive: %v", err)
	}
	if n != 0 {
		t.Fatalf("未标记存活应为 0, got %d", n)
	}
	s := Build(d, time.Now(), Options{})
	if s.Overview.Assets != 1 || s.Overview.AssetsAlive != 0 || s.Overview.AssetsDown != 1 {
		t.Fatalf("总览错误: %+v", s.Overview)
	}
}

// TestTrendBuckets 趋势分桶: 按自然日、新增看 FoundAt、修复看 FixedAt。
func TestTrendBuckets(t *testing.T) {
	d := newTestDB(t)
	now := time.Date(2026, 9, 17, 15, 30, 0, 0, time.Local)
	day := func(offset int, hour int) time.Time {
		base := time.Date(2026, 9, 17, 0, 0, 0, 0, time.Local).AddDate(0, 0, offset)
		return base.Add(time.Duration(hour) * time.Hour)
	}

	// 今天新增 2 条(其中 1 条同日修复)
	addVuln(t, d, "10.0.0.1", "今日新增-1", "high", models.VulnStatusNew, day(0, 9), nil)
	addVuln(t, d, "10.0.0.2", "今日新增-2", "medium", models.VulnStatusNew, day(0, 23), nil)
	// 3 天前新增, 今天修复 -> 新增记在 -3 天, 修复记在今天
	fixed := day(0, 10)
	addVuln(t, d, "10.0.0.3", "老漏洞今日修复", "critical", models.VulnStatusFixed, day(-3, 8), &fixed)
	// 6 天前新增(窗口内边界)
	addVuln(t, d, "10.0.0.4", "6天前新增", "low", models.VulnStatusNew, day(-6, 1), nil)
	// 8 天前新增(窗口外, 不计入)
	addVuln(t, d, "10.0.0.5", "8天前新增", "low", models.VulnStatusNew, day(-8, 1), nil)

	s := Build(d, now, Options{Days: 7})
	if s.Trend.Days != 7 || len(s.Trend.Points) != 7 {
		t.Fatalf("趋势点数错误: days=%d len=%d", s.Trend.Days, len(s.Trend.Points))
	}
	// 窗口应为 9-11 ~ 9-17
	if got := s.Trend.Points[0].Date; got != "2026-09-11" {
		t.Fatalf("窗口起始日错误: %s", got)
	}
	if got := s.Trend.Points[6].Date; got != "2026-09-17" {
		t.Fatalf("窗口结束日错误: %s", got)
	}
	// 今日新增 2(不含 8 天前那条)
	if n := s.Trend.Points[6].New; n != 2 {
		t.Fatalf("今日新增应为 2: %d", n)
	}
	// 今日修复 1
	if n := s.Trend.Points[6].Fixed; n != 1 {
		t.Fatalf("今日修复应为 1: %d", n)
	}
	// 净增 = 2 - 1 = 1
	if n := s.Trend.Points[6].Opened; n != 1 {
		t.Fatalf("当日净增应为 1: %d", n)
	}
	// 3 天前那条的"新增"计入 -3 天, 且不出现在今日
	if n := s.Trend.Points[3].New; n != 1 {
		t.Fatalf("3 天前新增应为 1: %d", n)
	}
	// 合计: 窗口内新增 4 条(今日 2 + 3 天前 1 + 6 天前 1)
	if s.Trend.NewTotal != 4 {
		t.Fatalf("窗口新增合计应为 4: %d", s.Trend.NewTotal)
	}
	if s.Trend.FixedTotal != 1 {
		t.Fatalf("窗口修复合计应为 1: %d", s.Trend.FixedTotal)
	}
	// 概要里的近 7 天字段与趋势一致
	if s.Overview.FindingsWeek != 4 || s.Overview.FixedWeek != 1 {
		t.Fatalf("概要趋势字段错误: %+v", s.Overview)
	}
	if s.Overview.FindingsToday != 2 {
		t.Fatalf("今日新增应为 2: %d", s.Overview.FindingsToday)
	}
}

// TestTrendWindowBoundary 窗口边界: 恰好在窗口首日 00:00 的记录应计入。
func TestTrendWindowBoundary(t *testing.T) {
	d := newTestDB(t)
	now := time.Date(2026, 9, 17, 10, 0, 0, 0, time.Local)
	start := time.Date(2026, 9, 11, 0, 0, 0, 0, time.Local) // 7 天窗口首日
	addVuln(t, d, "10.0.0.1", "边界-首日0点", "high", models.VulnStatusNew, start, nil)
	addVuln(t, d, "10.0.0.2", "边界-首日前1秒", "high", models.VulnStatusNew, start.Add(-time.Second), nil)

	s := Build(d, now, Options{Days: 7})
	// 首日 00:00 计入(dayKey 与分桶键一致)
	if s.Trend.Points[0].New != 1 {
		t.Fatalf("首日 00:00 记录应计入: %+v", s.Trend.Points[0])
	}
	if s.Trend.NewTotal != 1 {
		t.Fatalf("前 1 秒的记录应被排除: %d", s.Trend.NewTotal)
	}
}

// TestSeverityBars 占比基数不含 info, 且 info 仍单独返回数量。
func TestSeverityBars(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	addVuln(t, d, "10.0.0.1", "c", "critical", models.VulnStatusNew, now, nil)
	addVuln(t, d, "10.0.0.2", "h1", "high", models.VulnStatusNew, now, nil)
	addVuln(t, d, "10.0.0.3", "h2", "high", models.VulnStatusNew, now, nil)
	addVuln(t, d, "10.0.0.4", "l", "low", models.VulnStatusNew, now, nil)
	// 20 条 info: 不能把上面的占比稀释到 4%
	for i := 0; i < 20; i++ {
		addVuln(t, d, "10.9.0."+itoa(i), "info-"+itoa(i), "info", models.VulnStatusNew, now, nil)
	}

	s := Build(d, now, Options{})
	byKey := map[string]SevBar{}
	for _, b := range s.Severity {
		byKey[b.Key] = b
	}
	if byKey[SevCritical].Pct != 25 {
		t.Fatalf("严重占比应为 25%%(基数 4): %+v", byKey[SevCritical])
	}
	if byKey[SevHigh].Pct != 50 {
		t.Fatalf("高危占比应为 50%%: %+v", byKey[SevHigh])
	}
	if byKey[SevInfo].Count != 20 || byKey[SevInfo].Pct != 0 {
		t.Fatalf("info 数量应为 20 且不参与占比: %+v", byKey[SevInfo])
	}
	// 顺序固定: critical -> info
	if len(s.Severity) != 5 || s.Severity[0].Key != SevCritical || s.Severity[4].Key != SevInfo {
		t.Fatalf("占比顺序错误: %+v", s.Severity)
	}
}

// TestSeverityBarsEmpty 零数据时不应出现 NaN(0/0)。
func TestSeverityBarsEmpty(t *testing.T) {
	d := newTestDB(t)
	s := Build(d, time.Now(), Options{})
	for _, b := range s.Severity {
		if b.Pct != 0 {
			t.Fatalf("空数据占比应为 0: %+v", b)
		}
	}
	if s.Overview.Vulns.Total != 0 {
		t.Fatalf("空库漏洞数应为 0: %+v", s.Overview.Vulns)
	}
}

// TestTopVulnsOrdering 高危 TOP: 等级 -> CVSS -> 置信度 -> 更早发现优先。
func TestTopVulnsOrdering(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	mk := func(ip, title, sev string, cvss float64, conf int, ago time.Duration) {
		v := addVuln(t, d, ip, title, sev, models.VulnStatusNew, now.Add(-ago), nil)
		v.CVSS = cvss
		v.Confidence = conf
		if err := d.Vulns().Update(v); err != nil {
			t.Fatalf("update: %v", err)
		}
	}
	mk("10.0.0.1", "高CVSS严重", "critical", 9.8, 90, time.Hour)
	mk("10.0.0.2", "低CVSS严重", "critical", 9.0, 90, time.Hour)
	mk("10.0.0.3", "高危-1", "high", 8.0, 90, time.Hour)
	mk("10.0.0.4", "中危-1", "medium", 5.0, 90, time.Hour)
	mk("10.0.0.5", "信息-1", "info", 1.0, 90, time.Hour)

	s := Build(d, now, Options{TopN: 3})
	if len(s.TopVulns) != 3 {
		t.Fatalf("TOP 应截断为 3: %d", len(s.TopVulns))
	}
	want := []string{"高CVSS严重", "低CVSS严重", "高危-1"}
	for i, w := range want {
		if s.TopVulns[i].Title != w {
			t.Fatalf("TOP[%d] 应为 %s, got %s", i, w, s.TopVulns[i].Title)
		}
	}
}

// TestTopAssetsAndOrphan 风险资产排行 + 漏洞 IP 不在资产表时仍上榜。
func TestTopAssetsAndOrphan(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	// 资产表只有 10.0.0.1
	a := db.NewAsset("10.0.0.1")
	a.Hostname = "web01"
	a.OS = "linux"
	a.Ports = []int{80, 443}
	if _, err := d.Assets().Upsert(a); err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	// 10.0.0.1: 1 严重 + 1 高危 = 风险 2
	addVuln(t, d, "10.0.0.1", "c1", "critical", models.VulnStatusNew, now, nil)
	addVuln(t, d, "10.0.0.1", "h1", "high", models.VulnStatusNew, now, nil)
	// 10.0.0.9 不在资产表(资产已清理 / 漏洞直接回传): 3 高危 + 1 info,
	// 风险计数必须只算 3 条高危(info 是加固建议, 不计风险)
	addVuln(t, d, "10.0.0.9", "h2", "high", models.VulnStatusNew, now, nil)
	addVuln(t, d, "10.0.0.9", "h3", "high", models.VulnStatusNew, now, nil)
	addVuln(t, d, "10.0.0.9", "h4", "high", models.VulnStatusNew, now, nil)
	addVuln(t, d, "10.0.0.9", "i1", "info", models.VulnStatusNew, now, nil)

	s := Build(d, now, Options{})
	if len(s.TopAssets) != 2 {
		t.Fatalf("风险资产应为 2: %+v", s.TopAssets)
	}
	if s.TopAssets[0].IP != "10.0.0.9" || s.TopAssets[0].Risk != 3 || s.TopAssets[0].High != 3 {
		t.Fatalf("风险数最多的应为 10.0.0.9(3 条高危, info 不计): %+v", s.TopAssets[0])
	}
	if s.TopAssets[1].IP != "10.0.0.1" || s.TopAssets[1].Hostname != "web01" || s.TopAssets[1].OpenPorts != 2 {
		t.Fatalf("资产详情未补齐: %+v", s.TopAssets[1])
	}
	if s.TopAssets[0].Hostname != "" {
		t.Fatalf("孤儿资产不应有主机名: %+v", s.TopAssets[0])
	}
}

// TestFalsePositiveExcluded 误报默认排除出风险指标, 但仍在漏洞总量中。
func TestFalsePositiveExcluded(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	v := addVuln(t, d, "10.0.0.1", "误报-严重", "critical", models.VulnStatusNew, now, nil)
	addVuln(t, d, "10.0.0.2", "真-高危", "high", models.VulnStatusNew, now, nil)

	s := Build(d, now, Options{})
	if s.Overview.Vulns.Critical != 1 || s.Overview.Vulns.Risk != 2 {
		t.Fatalf("默认应计入误报前的计数: %+v", s.Overview.Vulns)
	}

	v.FalsePositive = true
	if err := d.Vulns().Update(v); err != nil {
		t.Fatalf("update: %v", err)
	}
	s = Build(d, now, Options{})
	if s.Overview.Vulns.Critical != 0 || s.Overview.Vulns.Risk != 1 {
		t.Fatalf("误报应被排除出风险指标: %+v", s.Overview.Vulns)
	}
	if s.Overview.FalsePosCount != 1 {
		t.Fatalf("误报计数应为 1: %d", s.Overview.FalsePosCount)
	}
	if s.Overview.VulnTotal != 2 {
		t.Fatalf("漏洞总量应仍含误报: %d", s.Overview.VulnTotal)
	}

	// 显式要求计入时恢复原值
	s = Build(d, now, Options{IncludeFP: true})
	if s.Overview.Vulns.Critical != 1 {
		t.Fatalf("IncludeFP=true 时应计入: %+v", s.Overview.Vulns)
	}
}

// TestRecentTasks 最近任务倒序 + 截断。
func TestRecentTasks(t *testing.T) {
	d := newTestDB(t)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 12; i++ {
		task := &db.ScanTask{Type: "port", Target: "10.0.0." + itoa(i), Status: db.TaskPending,
			CreatedAt: base.Add(time.Duration(i) * time.Minute)}
		if err := d.ScanTasks().Create(task); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	s := Build(d, time.Now(), Options{MaxRecent: 5})
	if len(s.RecentTasks) != 5 {
		t.Fatalf("最近任务应截断为 5: %d", len(s.RecentTasks))
	}
	if s.RecentTasks[0].Target != "10.0.0.11" {
		t.Fatalf("应倒序(最新在前): %+v", s.RecentTasks[0])
	}
}

// TestPendingCountsAsToday 今日任务按 CreatedAt 统计(排队的任务无 StartedAt)。
func TestPendingCountsAsToday(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	task := &db.ScanTask{Type: "port", Target: "10.0.0.1", Status: db.TaskPending, CreatedAt: now}
	if err := d.ScanTasks().Create(task); err != nil {
		t.Fatalf("create: %v", err)
	}
	// 昨天建的任务不计入今日
	old := &db.ScanTask{Type: "port", Target: "10.0.0.2", Status: db.TaskSuccess,
		CreatedAt: now.AddDate(0, 0, -1)}
	if err := d.ScanTasks().Create(old); err != nil {
		t.Fatalf("create: %v", err)
	}
	s := Build(d, now, Options{})
	if s.Overview.TasksToday != 1 {
		t.Fatalf("今日任务应为 1: %d", s.Overview.TasksToday)
	}
}

// TestOptionsClamp 参数钳制(防前端传参把响应体积放大)。
func TestOptionsClamp(t *testing.T) {
	if o := (Options{}).withDefaults(); o.Days != TrendDays || o.TopN != MaxTopList {
		t.Fatalf("默认值错误: %+v", o)
	}
	if o := (Options{Days: 9999, TopN: 9999, MaxRecent: 9999}).withDefaults(); o.Days != 90 || o.TopN != 50 || o.MaxRecent != 50 {
		t.Fatalf("上限钳制错误: %+v", o)
	}
	if o := (Options{Days: -1, TopN: -1, MaxRecent: -1}).withDefaults(); o.Days != TrendDays || o.TopN != MaxTopList {
		t.Fatalf("下限钳制错误: %+v", o)
	}
}

// TestNilDatabase 库不可用时不 panic, 返回告警。
func TestNilDatabase(t *testing.T) {
	s := Build(nil, time.Now(), Options{})
	if s == nil {
		t.Fatal("不应返回 nil")
	}
	if len(s.Warnings) == 0 {
		t.Fatal("应带数据缺失告警")
	}
	if s.Overview.Assets != 0 || len(s.Trend.Points) != TrendDays {
		t.Fatalf("空库结构应完整: %+v", s)
	}
}

// TestClosedDatabase Stats 关闭后调用不应 panic(DAO 被置 nil)。
func TestClosedDatabase(t *testing.T) {
	d, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if d.Assets() != nil {
		t.Fatal("Close 后 Assets() 应为 nil")
	}
	// 关闭后各 DAO 为 nil: Build 必须走告警分支而不是 nil 解引用
	s := Build(d, time.Now(), Options{})
	if s == nil {
		t.Fatal("不应返回 nil")
	}
	// Stats 对 nil DAO 的兜底(诊断接口会调它)
	_ = d.Stats()
}

// TestProbeLoadFallback 心跳无负载时用节点信息里的内存占用兜底。
func TestProbeLoadFallback(t *testing.T) {
	d := newTestDB(t)
	p := &db.Probe{
		ID: "pb-1", Name: "edge", Status: db.ProbeOnline,
		NodeInfo: map[string]any{"hostname": "e1", "os": "linux", "cpuCores": 8,
			"memTotal": uint64(16 * 1024 * 1024 * 1024), "memUsed": uint64(4 * 1024 * 1024 * 1024),
			"diskTotal": uint64(1000), "diskUsed": uint64(250)},
	}
	if _, err := d.Probes().Upsert(p); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	s := Build(d, time.Now(), Options{})
	if len(s.Probes) != 1 {
		t.Fatalf("探针数错误: %d", len(s.Probes))
	}
	pn := s.Probes[0]
	if pn.CPUPercent != nil {
		t.Fatalf("无负载上报时 CPU 应为 nil: %+v", pn)
	}
	if pn.MemPercent == nil || *pn.MemPercent != 25 {
		t.Fatalf("内存占用兜底应为 25%%: %+v", pn.MemPercent)
	}
	if pn.DiskPercent == nil || *pn.DiskPercent != 25 {
		t.Fatalf("磁盘占用应为 25%%: %+v", pn.DiskPercent)
	}
	if pn.CPUCores != 8 || pn.Hostname != "e1" {
		t.Fatalf("节点信息未解析: %+v", pn)
	}
}

// TestProbeStatusCounts 探针状态计数覆盖三种键。
func TestProbeStatusCounts(t *testing.T) {
	d := newTestDB(t)
	for _, st := range []string{db.ProbeOnline, db.ProbeOnline, db.ProbeOffline, db.ProbeDisabled} {
		p := &db.Probe{ID: "pb-" + itoa(statusSeq()), Status: st}
		if _, err := d.Probes().Upsert(p); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	cnt, err := d.Probes().CountByStatus()
	if err != nil {
		t.Fatalf("CountByStatus: %v", err)
	}
	if cnt[db.ProbeOnline] != 2 || cnt[db.ProbeOffline] != 1 || cnt[db.ProbeDisabled] != 1 {
		t.Fatalf("状态计数错误: %+v", cnt)
	}
}

// TestTaskCountByStatus 任务状态计数覆盖五个键。
func TestTaskCountByStatus(t *testing.T) {
	d := newTestDB(t)
	for _, st := range []string{db.TaskPending, db.TaskRunning, db.TaskFailed} {
		task := &db.ScanTask{Type: "port", Target: "10.0.0.1", Status: st}
		if err := d.ScanTasks().Create(task); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	cnt, err := d.ScanTasks().CountByStatus()
	if err != nil {
		t.Fatalf("CountByStatus: %v", err)
	}
	if cnt[db.TaskPending] != 1 || cnt[db.TaskRunning] != 1 || cnt[db.TaskFailed] != 1 {
		t.Fatalf("任务状态计数错误: %+v", cnt)
	}
	if cnt[db.TaskSuccess] != 0 || cnt[db.TaskCancelled] != 0 {
		t.Fatalf("缺失状态应补 0: %+v", cnt)
	}
	active, err := d.ScanTasks().Active()
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("运行中(pending+running)应为 2: %d", len(active))
	}
}

// TestVulnOpenAndFixedSince DAO 查询口径。
func TestVulnOpenAndFixedSince(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	addVuln(t, d, "10.0.0.1", "a", "high", models.VulnStatusNew, now.Add(-time.Hour), nil)
	fixedAt := now.Add(-time.Minute)
	addVuln(t, d, "10.0.0.2", "b", "high", models.VulnStatusFixed, now.Add(-2*time.Hour), &fixedAt)

	open, err := d.Vulns().Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(open) != 1 {
		t.Fatalf("未修复应为 1: %d", len(open))
	}
	fs, err := d.Vulns().FixedSince(now.Add(-10 * time.Minute))
	if err != nil {
		t.Fatalf("FixedSince: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("近 10 分钟修复应为 1: %d", len(fs))
	}
	if none, _ := d.Vulns().FixedSince(now.Add(time.Minute)); len(none) != 0 {
		t.Fatalf("未来时间点不应有修复记录: %d", len(none))
	}
}
