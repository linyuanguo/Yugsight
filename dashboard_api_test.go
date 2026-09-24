// dashboard_api_test.go 任务 10d 离线单测: IP 解析 + 流向聚合 + 静态资源防穿越。
//
// 守的契约(改坏会静默失效, 非复述实现):
//  1. firstIP 从各种目标写法里取到正确 IP —— 解析错了所有流向都丢, 地球空白
//     而日志无任何报错, 用户以为"地图没数据"其实是解析全错;
//  2. buildFlows 按城市聚合 + 中心质心兜底 + 私有/未收录排除 —— 大屏常驻,
//     聚合口径错了弧线数量/热点计数会悄悄错, 运维误读流量分布;
//  3. geoip 空表(未开启)时返回结构完整但空 arcs/points, 而非 nil/panic ——
//     "默认关闭降级为空"是明确口径, 不能整屏 500;
//  4. /vendor/globe 路径穿越被拒 —— 该端点直读 exe 同目录文件, 穿越=任意文件外发。
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"yugsight/db"
	"yugsight/geoip"
)

// ===== 测试夹具 =====

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

// 测试地理段: 3 个公共城市 + 坐标(经 city_geo.tsv 显式给定, 不依赖内置国家重心,
// 保证断言坐标确定)。
//   8.8.8.0/24   → 美国 旧金山 (37.77, -122.42)
//   1.1.1.0/24   → 澳洲 布里斯班 (25.27, 133.78)
//   203.0.113.0/24 → 中国 杭州 (30.27, 120.16)
const testGeoIP4 = "134744064\t134744319\tUnited States\tCalifornia\tSan Francisco\n" +
	"16843008\t16843263\tAustralia\tQueensland\tBrisbane\n" +
	"3405803776\t3405804031\tChina\tZhejiang\tHangzhou\n"

const testCityGeo = "San Francisco\t37.77\t-122.42\n" +
	"Brisbane\t25.27\t133.78\n" +
	"Hangzhou\t30.27\t120.16\n"

// newTestGeoIP 从测试 TSV 加载地理库。
func newTestGeoIP(t *testing.T) *geoip.DB {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geoip4.tsv"), []byte(testGeoIP4), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "city_geo.tsv"), []byte(testCityGeo), 0o644); err != nil {
		t.Fatal(err)
	}
	g, _ := geoip.Load(dir)
	return g
}

// addTask 写一条扫描任务。
func addTask(t *testing.T, d *db.Database, target, probeNode string) {
	t.Helper()
	st := &db.ScanTask{Type: "ip", Target: target, Status: db.TaskSuccess, ProbeNode: probeNode, CreatedAt: time.Now()}
	if _, err := d.ScanTasks().Upsert(st); err != nil {
		t.Fatalf("upsert task: %v", err)
	}
}

// addProbe 写一个探针(Addr 给源 IP)。
func addProbe(t *testing.T, d *db.Database, id, addr string) {
	t.Helper()
	p := &db.Probe{ID: id, Addr: addr, Status: db.ProbeOnline, CreatedAt: time.Now()}
	if _, err := d.Probes().Upsert(p); err != nil {
		t.Fatalf("upsert probe: %v", err)
	}
}

// ===== 用例 =====

// TestFirstIP 目标解析: 各种真实写法都要取到正确 IP(解析错=流向全丢)。
func TestFirstIP(t *testing.T) {
	cases := map[string]string{
		"8.8.8.8":              "8.8.8.8",
		"8.8.8.8:8080":         "8.8.8.8",
		"10.0.0.0/24":          "10.0.0.0",
		"1.1.1.1,2.2.2.2":      "1.1.1.1",
		"http://8.8.8.8/x":     "8.8.8.8",
		"8.8.8.8 1.1.1.1":      "8.8.8.8",
		"2001:db8::1":          "2001:db8::1",
		"not-an-ip":            "",
		"":                     "",
		"192.168.1.1;10.0.0.1": "192.168.1.1",
	}
	for in, want := range cases {
		if got := firstIP(in); got != want {
			t.Fatalf("firstIP(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// TestBuildFlowsAggregation 聚合契约: 同城合并、中心质心兜底、私有/未收录排除。
func TestBuildFlowsAggregation(t *testing.T) {
	d := newTestDB(t)
	g := newTestGeoIP(t)
	// 4 条可定位任务(旧金山 x2 / 布里斯班 / 杭州) + 2 条私有段(应排除)
	addTask(t, d, "8.8.8.1", "")
	addTask(t, d, "8.8.8.2", "")
	addTask(t, d, "1.1.1.1", "")
	addTask(t, d, "203.0.113.5", "")
	addTask(t, d, "10.0.0.1", "")    // 私有
	addTask(t, d, "192.168.1.1", "") // 私有

	cfg := dashboardConfig{Enabled: true, Days: 7, TopCities: 50, Center: centerPoint{}}
	resp := buildFlows(d, g, cfg)
	if resp == nil {
		t.Fatal("buildFlows 不应返回 nil")
	}
	// 私有/未收录排除
	if resp.Stats["private"] != 2 {
		t.Fatalf("private 应为 2, got %d (stats=%v)", resp.Stats["private"], resp.Stats)
	}
	if resp.Stats["known"] != 4 {
		t.Fatalf("known 应为 4, got %d (stats=%v)", resp.Stats["known"], resp.Stats)
	}
	// 中心未配置 → 质心兜底(有坐标)
	if resp.Center.Lat == 0 && resp.Center.Lon == 0 {
		t.Fatal("中心未配置应用目标城市质心兜底, 不应是 (0,0)")
	}
	// 本地任务全部从中心出发 → 3 条弧线(旧金山 x2 合并, 布里斯班, 杭州)
	if len(resp.Arcs) != 3 {
		t.Fatalf("应有 3 条弧线, got %d: %+v", len(resp.Arcs), resp.Arcs)
	}
	// 旧金山弧线 count=2(同城合并)
	var sfCount int
	for _, a := range resp.Arcs {
		if a.To.Name == "San Francisco" {
			sfCount = a.Count
		}
	}
	if sfCount != 2 {
		t.Fatalf("旧金山弧线 count 应为 2(同城合并), got %d", sfCount)
	}
	// 热点: 旧金山 2 / 布里斯班 1 / 杭州 1
	if len(resp.Points) != 3 {
		t.Fatalf("应有 3 个热点城市, got %d: %+v", len(resp.Points), resp.Points)
	}
}

// TestBuildFlowsProbeSource 远程任务源=探针城市(非中心)。
func TestBuildFlowsProbeSource(t *testing.T) {
	d := newTestDB(t)
	g := newTestGeoIP(t)
	// 探针在杭州(203.0.113.50), 任务从该探针扫旧金山(8.8.8.1)
	addProbe(t, d, "pb1", "203.0.113.50")
	addTask(t, d, "8.8.8.1", "pb1")

	cfg := dashboardConfig{Enabled: true, Days: 7, TopCities: 50}
	resp := buildFlows(d, g, cfg)
	if len(resp.Arcs) != 1 {
		t.Fatalf("应有 1 条弧线, got %d: %+v", len(resp.Arcs), resp.Arcs)
	}
	a := resp.Arcs[0]
	if a.From.Name != "Hangzhou" {
		t.Fatalf("远程任务源应为探针城市 Hangzhou, got %q (from=%+v)", a.From.Name, a.From)
	}
	if a.To.Name != "San Francisco" {
		t.Fatalf("目标应为 San Francisco, got %q", a.To.Name)
	}
}

// TestBuildFlowsEmptyGeoIP geoip 未开启(空表) → 结构完整但空 arcs/points, 不 nil/panic。
// 这是"默认关闭降级为空地图"口径的回归防线。
func TestBuildFlowsEmptyGeoIP(t *testing.T) {
	d := newTestDB(t)
	g := geoip.New() // 空表
	addTask(t, d, "8.8.8.1", "")
	addTask(t, d, "1.1.1.1", "")

	cfg := dashboardConfig{Enabled: true, Days: 7, TopCities: 50}
	resp := buildFlows(d, g, cfg)
	if resp == nil {
		t.Fatal("空 geoip 时 buildFlows 仍应返回完整结构, 不能 nil")
	}
	if len(resp.Arcs) != 0 || len(resp.Points) != 0 {
		t.Fatalf("空 geoip 时弧线/热点应为空, got arcs=%d points=%d", len(resp.Arcs), len(resp.Points))
	}
	// 全部落到 unknown(查不到)
	if resp.Stats["unknown"] != 2 {
		t.Fatalf("空 geoip 时 2 条任务应计入 unknown, got %d (stats=%v)", resp.Stats["unknown"], resp.Stats)
	}
	// 契约: resp.GeoIP["enabled"] 必须如实回显 geoip 开关, 供前端判断"是数据缺失
	// 还是功能关闭"。默认值随口径改为**开启**(开关在页面上, 配置文件只存参数),
	// 故这里断言 true —— 若哪天默认值被改回去, 这条会立刻失败提醒同步。
	if resp.GeoIP["enabled"] != true {
		t.Fatalf("resp.GeoIP.enabled 应反映配置(默认开启), got %v", resp.GeoIP["enabled"])
	}
}

// TestHandleGlobeFileTraversal 路径穿越与非法扩展名被拒(该端点直读 exe 同目录文件)。
func TestHandleGlobeFileTraversal(t *testing.T) {
	cases := map[string]int{
		"../../etc/passwd": http.StatusBadRequest, // 穿越
		"..\\..\\win.ini":  http.StatusBadRequest, // Windows 穿越
		".":                http.StatusBadRequest,
		"..":               http.StatusBadRequest,
		"secret.exe":       http.StatusNotFound, // 合法单段但非白名单扩展名
	}
	for name, wantCode := range cases {
		r := httptest.NewRequest(http.MethodGet, "/vendor/globe/"+name, nil)
		r.SetPathValue("file", name)
		w := httptest.NewRecorder()
		handleGlobeFile(w, r)
		if w.Code != wantCode {
			t.Fatalf("handleGlobeFile(%q) = %d, 期望 %d", name, w.Code, wantCode)
		}
	}
}
