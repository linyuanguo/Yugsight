package db

import (
	"testing"
	"time"

	"yugsight/internal/models"
)

// 屏幕聚合测试的固定基准时刻: 全部数据围绕它构造, 避免"用例写的时间恰好
// 落在窗口边界外"导致断言整段错位(任务 7.2 时间窗测试踩过的坑)。
// 口径与 bigscreen 真实调用一致: start = dayStart(now) - (days-1) 天(日首 00:00),
// 而不是 now 直接减天数 —— 差一个 12 小时就会让"今日"判定整体错位。
// now = 2026-09-20 12:00 本地; days=7 窗口 = 09-14 00:00 ~ 09-21 00:00。
var (
	screenNow    = time.Date(2026, 9, 20, 12, 0, 0, 0, time.Local)
	screenStart  = time.Date(2026, 9, 14, 0, 0, 0, 0, time.Local) // dayStart(now).AddDate(0,0,-6)
	screenDays   = 7
	screenToday  = time.Date(2026, 9, 20, 0, 0, 0, 0, time.Local)
	screenFixDay = time.Date(2026, 9, 15, 8, 0, 0, 0, time.Local) // 窗口内
	screenOutDay = time.Date(2026, 9, 1, 8, 0, 0, 0, time.Local)  // 窗口外
)

// seedScreenVulns 灌入覆盖全部聚合维度的漏洞数据集。
// 返回口径(手工推算, 与 ScreenAgg 断言对照):
//
//	total=6  fixed=1  fp=2
//	风险类(includeFP=false): critical 1 + high 1 + medium 1 + info 0 = 3 条
//	  (v1 critical 新 / v2 high 新 / v3 medium 新; v5 是 info 但被 fixed 排除)
//	  误报 v4(high,FP) 与 v6(low,FP) 被排除
//	TrendNew: 09-15 有 v1(窗口第 2 天, idx=1) + v3(idx=1) = 2; 09-20 有 v2(idx=6) = 1;
//	          v4/v5/v6 的 FoundAt 在窗口外不计
//	TrendFixed: v5 FixedAt=09-15 => idx=1 = 1
//	FindingsToday: FoundAt 严格晚于 09-20 00:00 => 只有 v2(09-20 10:00) = 1
//	AssetRisk: 10.0.0.1 => critical 1 risk 1; 10.0.0.2 => high 1 risk 1; 10.0.0.3 => risk 1(medium)
func seedScreenVulns(t *testing.T, d *Database) {
	t.Helper()
	mk := func(ip, title, sev, status string, found time.Time, fp bool, fixedAt *time.Time) *Vuln {
		v := NewVuln(ip, title, sev)
		v.Status = status
		v.FoundAt = found
		v.LastSeenAt = found
		v.FalsePositive = fp
		v.FixedAt = fixedAt
		return v
	}
	v1 := mk("10.0.0.1", "严重漏洞", "critical", models.VulnStatusNew,
		screenFixDay, false, nil) // 09-15 发现(窗口内)
	v2 := mk("10.0.0.2", "高危漏洞", "high", models.VulnStatusNew,
		time.Date(2026, 9, 20, 10, 0, 0, 0, time.Local), false, nil) // 今日 10:00 发现
	v3 := mk("10.0.0.3", "中危漏洞", "medium", models.VulnStatusNew,
		screenFixDay, false, nil)
	v4 := mk("10.0.0.1", "误报高危", "high", models.VulnStatusNew,
		screenOutDay, true, nil) // 窗口外 + FP
	v5 := mk("10.0.0.2", "已修复", "info", models.VulnStatusFixed,
		screenOutDay, false, &screenFixDay) // 窗口外发现, 窗口内修复
	v6 := mk("10.0.0.3", "误报低危", "low", models.VulnStatusNew,
		screenOutDay, true, nil)
	for _, v := range []*Vuln{v1, v2, v3, v4, v5, v6} {
		if _, err := d.Vulns().Upsert(v); err != nil {
			t.Fatalf("Upsert %s: %v", v.Title, err)
		}
	}
}

// TestScreenAggMetrics 单遍聚合的每个口径必须与逐条人工推算一致。
// 这是"字段口径决定统计正确性"的守卫: 新增/修复/今日/误报任何一个口径被改坏,
// 大屏数字就会与漏洞列表对不上。
func TestScreenAggMetrics(t *testing.T) {
	d := openTestDB(t)
	seedScreenVulns(t, d)

	agg, err := d.Vulns().ScreenAgg(screenStart, screenDays, false)
	if err != nil {
		t.Fatalf("ScreenAgg: %v", err)
	}
	if agg.Total != 6 || agg.Fixed != 1 || agg.FalsePos != 2 {
		t.Fatalf("Total/Fixed/FalsePos = %d/%d/%d, 期望 6/1/2", agg.Total, agg.Fixed, agg.FalsePos)
	}
	if got := agg.Sev["critical"]; got != 1 {
		t.Fatalf("critical=%d, 期望 1", got)
	}
	if got := agg.Sev["high"]; got != 1 {
		t.Fatalf("high=%d, 期望 1(误报的 high 应被排除)", got)
	}
	if got := agg.Sev["medium"]; got != 1 {
		t.Fatalf("medium=%d, 期望 1", got)
	}
	if _, ok := agg.Sev["info"]; ok {
		t.Fatal("info 不应进入风险分布(已修复的 info 被排除)")
	}
	if len(agg.Risky) != 3 {
		t.Fatalf("Risky=%d, 期望 3 条", len(agg.Risky))
	}
	// 趋势: idx=1 是 09-15(2 条新增 + 1 条修复), idx=6 是 09-20(1 条新增)
	if agg.TrendNew[1] != 2 || agg.TrendNew[6] != 1 {
		t.Fatalf("TrendNew[%d]=%d TrendNew[%d]=%d, 期望 2/1", 1, agg.TrendNew[1], 6, agg.TrendNew[6])
	}
	if agg.TrendFixed[1] != 1 {
		t.Fatalf("TrendFixed[1]=%d, 期望 1", agg.TrendFixed[1])
	}
	if agg.FindingsToday != 1 {
		t.Fatalf("FindingsToday=%d, 期望 1(只有 09-20 10:00 那条)", agg.FindingsToday)
	}
	// 资产聚合
	a1 := agg.AssetRisk["10.0.0.1"]
	if a1 == nil || a1.Critical != 1 || a1.Risk != 1 {
		t.Fatalf("AssetRisk[10.0.0.1]=%+v, 期望 critical=1 risk=1", a1)
	}
	a3 := agg.AssetRisk["10.0.0.3"]
	if a3 == nil || a3.Risk != 1 || a3.Critical != 0 {
		t.Fatalf("AssetRisk[10.0.0.3]=%+v, 期望 risk=1(medium)", a3)
	}
}

// TestScreenAggIncludeFP 误报计入口径: includeFP=true 时误报进入风险分布。
func TestScreenAggIncludeFP(t *testing.T) {
	d := openTestDB(t)
	seedScreenVulns(t, d)

	agg, err := d.Vulns().ScreenAgg(screenStart, screenDays, true)
	if err != nil {
		t.Fatalf("ScreenAgg: %v", err)
	}
	// high 变成 2(v2 + 误报 v4), Risky 变 5 条
	if got := agg.Sev["high"]; got != 2 {
		t.Fatalf("includeFP high=%d, 期望 2", got)
	}
	if len(agg.Risky) != 5 {
		t.Fatalf("includeFP Risky=%d, 期望 5", len(agg.Risky))
	}
	// Total/Fixed/FalsePos 与口径无关
	if agg.Total != 6 || agg.Fixed != 1 || agg.FalsePos != 2 {
		t.Fatalf("Total/Fixed/FalsePos=%d/%d/%d 不应随 includeFP 变化", agg.Total, agg.Fixed, agg.FalsePos)
	}
}

// TestScreenAggCacheInvalidate 缓存契约: 参数相同且数据未变 => 复用;
// 数据一变(写入代数 +1) => 立即拿到新结果, 不返回陈旧统计。
func TestScreenAggCacheInvalidate(t *testing.T) {
	d := openTestDB(t)
	seedScreenVulns(t, d)

	first, err := d.Vulns().ScreenAgg(screenStart, screenDays, false)
	if err != nil {
		t.Fatalf("ScreenAgg: %v", err)
	}
	// 命中缓存的第二次调用: 结果一致, 且返回的是拷贝(改它不能污染缓存)
	second, err := d.Vulns().ScreenAgg(screenStart, screenDays, false)
	if err != nil {
		t.Fatalf("ScreenAgg(2nd): %v", err)
	}
	if second.Total != first.Total {
		t.Fatalf("缓存命中结果不一致: %d vs %d", second.Total, first.Total)
	}
	second.Sev["critical"] = 999
	third, _ := d.Vulns().ScreenAgg(screenStart, screenDays, false)
	if third.Sev["critical"] != 1 {
		t.Fatalf("修改返回的副本污染了缓存: critical=%d", third.Sev["critical"])
	}

	// 新增一条漏洞 => 代数变化, 缓存必须作废
	v := NewVuln("10.0.0.9", "新增严重", "critical")
	v.FoundAt = time.Date(2026, 9, 20, 11, 0, 0, 0, time.Local)
	if _, err := d.Vulns().Upsert(v); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	fourth, err := d.Vulns().ScreenAgg(screenStart, screenDays, false)
	if err != nil {
		t.Fatalf("ScreenAgg(4th): %v", err)
	}
	if fourth.Total != 7 {
		t.Fatalf("数据变化后 Total=%d, 期望 7(缓存未作废会返回 6)", fourth.Total)
	}
	if fourth.FindingsToday != 2 {
		t.Fatalf("数据变化后 FindingsToday=%d, 期望 2", fourth.FindingsToday)
	}
}

// TestScreenAggTTLDisabled TTL 置 0 时缓存关闭, 每次都是现算(结果当然仍正确)。
func TestScreenAggTTLDisabled(t *testing.T) {
	d := openTestDB(t)
	seedScreenVulns(t, d)
	old := vulnScreenCacheTTL
	vulnScreenCacheTTL = 0
	t.Cleanup(func() { vulnScreenCacheTTL = old })

	agg, err := d.Vulns().ScreenAgg(screenStart, screenDays, false)
	if err != nil {
		t.Fatalf("ScreenAgg: %v", err)
	}
	if agg.Total != 6 {
		t.Fatalf("缓存关闭时 Total=%d, 期望 6", agg.Total)
	}
}

// TestCountWhereAndCountBy Table 单遍统计: 结果与 List+遍历一致且无拷贝。
func TestCountWhereAndCountBy(t *testing.T) {
	d := openTestDB(t)
	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		a := NewAsset(ip)
		if i == 0 {
			a.Alive = true
		}
		if _, err := d.Assets().Upsert(a); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	n, err := d.Assets().CountAlive()
	if err != nil || n != 1 {
		t.Fatalf("CountAlive=%d err=%v, 期望 1", n, err)
	}
	// 按"是否存活"分类: 单遍统计的计数必须与逐条遍历一致。
	counts, err := d.Assets().CountBy(func(a *Asset) string {
		if a.Alive {
			return "alive"
		}
		return "down"
	})
	if err != nil {
		t.Fatalf("CountBy: %v", err)
	}
	if counts["alive"] != 1 || counts["down"] != 2 {
		t.Fatalf("CountBy alive/down=%d/%d, 期望 1/2", counts["alive"], counts["down"])
	}
}

// TestGetMany 只返回请求中存在的 IP, 请求的 IP 缺失时不报错。
func TestGetMany(t *testing.T) {
	d := openTestDB(t)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		if _, err := d.Assets().Upsert(NewAsset(ip)); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	got, err := d.Assets().GetMany([]string{"10.0.0.1", "10.0.0.9", "10.0.0.2", "10.0.0.1"})
	if err != nil {
		t.Fatalf("GetMany: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("GetMany 返回 %d 条, 期望 2(去重且只含存在的 IP)", len(got))
	}
	if got["10.0.0.1"] == nil || got["10.0.0.2"] == nil {
		t.Fatal("存在的 IP 必须返回")
	}
	// 副本语义: 改返回值不能污染表内数据
	got["10.0.0.1"].Hostname = "hacked"
	again, _ := d.Assets().GetMany([]string{"10.0.0.1"})
	if again["10.0.0.1"].Hostname == "hacked" {
		t.Fatal("GetMany 返回副本, 修改不应影响表内数据")
	}
}

// TestVersionBumpsOnWrite 写入代数: 每次写成功 +1, 读操作不变。
func TestVersionBumpsOnWrite(t *testing.T) {
	d := openTestDB(t)
	dao := d.Assets()
	v0 := dao.Version()
	if _, err := dao.Upsert(NewAsset("10.0.0.1")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	v1 := dao.Version()
	if v1 != v0+1 {
		t.Fatalf("Upsert 后 Version=%d, 期望 %d", v1, v0+1)
	}
	if _, err := dao.Upsert(NewAsset("10.0.0.2")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := dao.Update(NewAsset("10.0.0.2")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := dao.Delete("10.0.0.1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	v2 := dao.Version()
	if v2 != v1+2 {
		t.Fatalf("Update+Delete 后 Version=%d, 期望 %d", v2, v1+2)
	}
	// 读操作不改变代数
	_, _ = dao.List()
	_, _ = dao.Count()
	_, _ = dao.Query(func(a *Asset) bool { return true })
	if dao.Version() != v2 {
		t.Fatal("读操作不应改变 Version")
	}
}
