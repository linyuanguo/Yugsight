// dashboard_api.go 任务 10d: 3D 地球 IP 流向图的数据源与前端资源。
//
// 本文件是 main 包与 geoip 包、db 包、globe 前端资源之间的唯一连接点, 与
// monitor_api / bigscreen_api 同一装配模式: settings.json 的 dashboard/geoip
// 两节开关 + geoip 单例 + /api/dashboard/flows 路由 + /vendor/globe/* 静态资源。
//
// ===== 数据口径 =====
//
//   - flows(弧线) = 时间窗内的扫描任务: 每条任务是一次"从源到目标"的流量,
//     源 = 执行节点(本地中心 或 远端探针), 目标 = 任务目标 IP;
//   - 两端 IP 经 geoip 查城市级坐标, 按"城市"聚合(弧线聚合到城市层级, 见任务
//     精度声明); 私有/内网段与查不到的 IP 无法定位, 计入 stats.unknown 不画弧;
//   - 热点(points) = 所有可定位的目标城市聚合(任务目标 + 已发现资产), 带计数。
//
// ===== 默认关闭(项目规则 5) =====
//
//   - geoip.enabled=false: 不加载段表, 一切查询返回 unknown, 地图为空;
//   - dashboard.enabled=false: 不注册 /api/dashboard/flows, 前端地球无数据。
//     两者都显式开启后才出图 —— 与"新增功能默认关闭, 配置开关启用"一致。
//
// ===== 资源不打包 =====
//
//   前端 three.js / globe.gl 与贴图放 build/globe/(由 scripts/build.ps1 镜像到
//   exe 同目录 res/globe/), 运行时经 /vendor/globe/{file} 直读, 不 go:embed 进二进制
//   (three.js 数百 KB, 嵌入会让单文件 exe 无谓膨胀, 且升级贴图需重编)。
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/geoip"
	"yugsight/internal/server"
)

// ===== 配置 =====

// dashboardConfig 大屏 3D 地球配置(settings.json 的 dashboard 节, 可选)。
type dashboardConfig struct {
	// Enabled 是否注册 /api/dashboard/flows。默认 false(功能默认关闭)。
	Enabled bool `json:"enabled"`
	// Days 流向聚合时间窗(天)。默认 7, 钳制到 [1,90]。
	Days int `json:"days"`
	// TopCities 返回的城市/弧线数量上限。默认 50, 钳制到 [1,200]。
	TopCities int `json:"topCities"`
	// Center 中心节点(本部署的监控中心)展示坐标。留空(lat/lon 均 0)时
	// 回退为"所有可定位目标城市的质心", 保证弧线始终有起点。
	Center centerPoint `json:"center"`
}

type centerPoint struct {
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
	Name string  `json:"name"`
}

// geoipConfig IP 地理映射开关(settings.json 的 geoip 节)。
type geoipConfig struct {
	// Enabled 是否加载 build/geoip 段表。默认 false → 查询全 unknown, 地图空。
	Enabled bool `json:"enabled"`
}

var (
	dashCfgMu   sync.RWMutex
	dashCfgVal  dashboardConfig
	dashCfgDone bool
	geoCfgMu    sync.RWMutex
	geoCfgVal   geoipConfig
	geoCfgDone  bool
)

// clampInt 把 v 钳制到 [lo,hi], v 非法(<=0)时取 def。
func clampInt(v, lo, hi, def int) int {
	if v <= 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// loadDashboardConfig 读 settings.json 的 dashboard 节。
//
// 默认开启(用户口径: 开关在页面上, settings.json 只是保存参数的地方):
// 该接口是只读聚合, 开启后唯一的行为变化是注册一条路由, 不改任何执行链路;
// 用户在页面上关掉时才写 enabled=false。
//
// 与 report 模块同一手法: 必须区分"配置没写 enabled"与"显式写了 false",
// 否则只改 days 就会把功能关掉(用户现象: 我改了参数, 地球没了)。
func loadDashboardConfig() dashboardConfig {
	dashCfgMu.RLock()
	if dashCfgDone {
		cfg := dashCfgVal
		dashCfgMu.RUnlock()
		return cfg
	}
	dashCfgMu.RUnlock()

	cfg := dashboardConfig{Enabled: true}
	if data, ok := section(secDashboard, ""); ok {
		if uerr := jsonUnmarshalSafe(data, &cfg); uerr != nil {
			logLine("settings.json 的 dashboard 节解析失败, 使用默认配置(开启): " + uerr.Error())
			cfg = dashboardConfig{Enabled: true}
		} else if !hasExplicitEnabled(data) {
			cfg.Enabled = true // 节里没写 enabled = 保持默认开
		}
	}
	cfg.Days = clampInt(cfg.Days, 1, 90, 7)
	cfg.TopCities = clampInt(cfg.TopCities, 1, 200, 50)

	dashCfgMu.Lock()
	dashCfgVal, dashCfgDone = cfg, true
	dashCfgMu.Unlock()
	return cfg
}

// loadGeoIPConfig 读 settings.json 的 geoip 节; 缺失 = 开启(默认开箱即用)。
//
// 开启后的实际加载发生在首次请求 flows 时(懒加载): 段表缺失/损坏只是"地图空白
// + 一条告警", 不阻塞任何功能 —— 因此默认开没有代价, 而默认关会让用户以为
// 功能不存在。
func loadGeoIPConfig() geoipConfig {
	geoCfgMu.RLock()
	if geoCfgDone {
		cfg := geoCfgVal
		geoCfgMu.RUnlock()
		return cfg
	}
	geoCfgMu.RUnlock()

	cfg := geoipConfig{Enabled: true}
	if data, ok := section(secGeoIP, ""); ok {
		if uerr := jsonUnmarshalSafe(data, &cfg); uerr != nil {
			logLine("settings.json 的 geoip 节解析失败, 使用默认配置(开启): " + uerr.Error())
			cfg = geoipConfig{Enabled: true}
		} else if !hasExplicitEnabled(data) {
			cfg.Enabled = true
		}
	}
	geoCfgMu.Lock()
	geoCfgVal, geoCfgDone = cfg, true
	geoCfgMu.Unlock()
	return cfg
}

// ===== geoip 单例 =====

var (
	// geoipMu 保护 geoipInst:
	//
	// 刻意不用 sync.Once —— Once 执行过就无法重置, 而配置热重载(二期 15)要求
	// "改 geoip.enabled 并保存后立即生效", 段表必须能重建。Once 不可重入、
	// 不可重置, 用 mutex + nil 判断是这里唯一既能懒加载又能重建的形状。
	geoipMu   sync.Mutex
	geoipInst *geoip.DB
)

// instanceGeoIP 懒加载地理映射单例。
//
// 关闭 / 数据缺失都返回非 nil 的空 DB(Lookup 返回 unknown, 不 panic) ——
// 与 monitor 的"兜底非 nil"同一手法, 保证 handler 解引用安全。
func instanceGeoIP() *geoip.DB {
	geoipMu.Lock()
	defer geoipMu.Unlock()
	build := func() {
		if !loadGeoIPConfig().Enabled {
			geoipInst = geoip.New()
			logLine("IP 地理映射已关闭(页面开关), 地图显示为空 —— 需要时在页面重新开启即可, 无需重启")
			return
		}
		// 2026-09-24 dist 目录整理: 内置数据资源收进 res/(旧 "exe 同目录 geoip/" 由
		// main.go 的 migrateLegacyDirs 启动时一次性迁移; build.ps1 也改从 build/geoip 镜像到 res/geoip)
		dir := filepath.Join(exeDir(), "res", "geoip")
		db, warnings := geoip.Load(dir)
		for _, w := range warnings {
			logLine("[geoip] " + w)
		}
		v4, v6, c4, c6 := db.Loaded()
		if v4 || v6 {
			logLine(fmt.Sprintf("IP 地理映射已加载: IPv4 段 %d, IPv6 段 %d (v4=%v v6=%v)", c4, c6, v4, v6))
		}
		geoipInst = db
	}
	if geoipInst == nil {
		build()
	}
	if geoipInst == nil {
		geoipInst = geoip.New()
	}
	return geoipInst
}

// exeDir 可执行文件所在目录(配置/数据资源运行时根)。
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// jsonUnmarshalSafe 解析配置节; settings.json 已由 loadSettings 剥 BOM。
func jsonUnmarshalSafe(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// ===== 流向数据模型 =====

type flowPoint struct {
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
	Name  string  `json:"name"`
	Count int     `json:"count"`
}

type flowArc struct {
	From  flowPoint `json:"from"`
	To    flowPoint `json:"to"`
	Count int       `json:"count"`
}

type flowsResponse struct {
	Center flowPoint      `json:"center"`
	Arcs   []flowArc      `json:"arcs"`
	Points []flowPoint    `json:"points"`
	Stats  map[string]int `json:"stats"`
	GeoIP  map[string]any `json:"geoip"`
}

// cityKey 城市聚合键(经度+纬度, 展示近似点, 浮点直接做键足够稳定)。
type cityKey struct {
	Lat, Lon float64
	Name     string
}

// geoOf 查 IP 城市坐标; 私有/内网段与查不到的返回 (nil, true=known 否)。
// 返回 *geoip.Location 便于调用方区分"私有"与"查不到"。
func geoOf(g *geoip.DB, ip string) *geoip.Location {
	if strings.TrimSpace(ip) == "" {
		return nil
	}
	loc := g.Lookup(ip)
	if loc == nil {
		return nil
	}
	if !loc.Known {
		return loc // Private=true 或 Reason=查不到, 调用方按 Known 判断
	}
	return loc
}

// firstIP 从扫描目标里取第一个可解析的 IP。目标可能是 "1.2.3.4"、
// "1.2.3.4:8080"、"10.0.0.0/24"、"1.1.1.1,2.2.2.2"、"http://1.2.3.4/x"。
// 解析不出返回 ""(调用方按 unknown 处理)。
func firstIP(target string) string {
	s := strings.TrimSpace(target)
	if s == "" {
		return ""
	}
	// 去 scheme 前缀(http:// https://)
	for _, pre := range []string{"http://", "https://", "//"} {
		if strings.HasPrefix(s, pre) {
			s = s[len(pre):]
			break
		}
	}
	// 按逗号/分号/空格/斜杠(路径)拆成候选
	cands := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '/'
	})
	for _, c := range cands {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// 带端口: host:port
		if h, _, err := net.SplitHostPort(c); err == nil {
			c = h
		}
		// 带网段: a.b.c.d/N
		if i := strings.IndexByte(c, '/'); i > 0 {
			c = c[:i]
		}
		if ip := net.ParseIP(c); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// centroid 一组 (lat,lon) 的质心。空集返回 (0,0,false)。
func centroid(pts []flowPoint) (lat, lon float64, ok bool) {
	if len(pts) == 0 {
		return 0, 0, false
	}
	var sLat, sLon float64
	for _, p := range pts {
		sLat += p.Lat
		sLon += p.Lon
	}
	return sLat / float64(len(pts)), sLon / float64(len(pts)), true
}

// taskFlow 一条任务的流向(两遍扫描的中间结果): 目标城市 + 源探针 ID(空=本地)。
type taskFlow struct {
	dst     cityKey
	probeID string
}

// buildFlows 从 db 任务/资产/探针 + geoip 构建流向。
//
// 两遍扫描: 第一遍收集全部可定位的目标城市与任务(源=探针/本地); 据此定中心
// 坐标(配置优先, 否则目标城市质心兜底 —— 保证弧线始终有起点); 第二遍才把
// 每条任务归到"源城市 → 目标城市"弧线上。单遍做不到, 因为"本地任务"的源
// 正是最后才算出的中心, 先算中心再画弧才不会漏弧。
//
// 降级口径: db 不可用返回 nil(调用方 503); geoip 空表返回结构完整但空
// arcs/points(地图空白而非报错) —— 大屏常驻, 数据缺失不该整屏 500。
func buildFlows(d *db.Database, g *geoip.DB, cfg dashboardConfig) *flowsResponse {
	resp := &flowsResponse{
		Arcs:   []flowArc{},
		Points: []flowPoint{},
		Stats:  map[string]int{"known": 0, "unknown": 0, "private": 0},
	}
	v4, v6, c4, c6 := g.Loaded()
	resp.GeoIP = map[string]any{"v4": v4, "v6": v6, "v4Count": c4, "v6Count": c6, "enabled": loadGeoIPConfig().Enabled}

	cutoff := time.Now().AddDate(0, 0, -cfg.Days)

	// Location → 城市聚合键(名字取 城市>区域>国家>IP 的可用项)。
	addCity := func(loc *geoip.Location) (cityKey, bool) {
		if loc == nil || !loc.Known {
			return cityKey{}, false
		}
		name := loc.City
		if name == "" {
			name = loc.Region
		}
		if name == "" {
			name = loc.Country
		}
		if name == "" {
			name = loc.IP
		}
		return cityKey{Lat: loc.Lat, Lon: loc.Lon, Name: name}, true
	}

	// 探针 ID → 源坐标(远程任务从探针发起)。探针 Addr 是回调/注册 IP。
	probeCity := map[string]cityKey{}
	if dao := d.Probes(); dao != nil {
		if list, err := dao.List(); err == nil {
			for _, p := range list {
				if p == nil || p.ID == "" {
					continue
				}
				if ip := firstIP(p.Addr); ip != "" {
					if k, ok := addCity(geoOf(g, ip)); ok {
						probeCity[p.ID] = k
					}
				}
			}
		}
	}

	centerName := cfg.Center.Name
	if centerName == "" {
		centerName = "监控中心"
	}
	centerSet := cfg.Center.Lat != 0 || cfg.Center.Lon != 0

	cityCount := map[cityKey]int{} // 目标城市热点计数
	var tasks []taskFlow
	var destCities []flowPoint

	// 1) 扫描任务: 收集目标城市 + 记录源(探针/本地)
	if dao := d.ScanTasks(); dao != nil {
		if list, err := dao.List(); err == nil {
			for _, t := range list {
				if t == nil || t.CreatedAt.Before(cutoff) {
					continue
				}
				dstIP := firstIP(t.Target)
				if dstIP == "" {
					resp.Stats["unknown"]++
					continue
				}
				dstLoc := geoOf(g, dstIP)
				if dstLoc == nil || !dstLoc.Known {
					if dstLoc != nil && dstLoc.Private {
						resp.Stats["private"]++
					} else {
						resp.Stats["unknown"]++
					}
					continue
				}
				dstKey, _ := addCity(dstLoc)
				resp.Stats["known"]++
				cityCount[dstKey]++
				destCities = append(destCities, flowPoint{Lat: dstKey.Lat, Lon: dstKey.Lon, Name: dstKey.Name})
				tasks = append(tasks, taskFlow{dst: dstKey, probeID: t.ProbeNode})
			}
		}
	}

	// 2) 资产 → 热点(补充任务之外的可定位资产, 不产生弧线)
	if dao := d.Assets(); dao != nil {
		if list, err := dao.List(); err == nil {
			for _, a := range list {
				if a == nil {
					continue
				}
				if ip := firstIP(a.IP); ip != "" {
					if k, ok := addCity(geoOf(g, ip)); ok {
						cityCount[k]++
					}
				}
			}
		}
	}

	// 3) 定中心坐标: 配置优先, 否则目标城市质心兜底。
	var center cityKey
	if centerSet {
		center = cityKey{Lat: cfg.Center.Lat, Lon: cfg.Center.Lon, Name: centerName}
	} else if lat, lon, ok := centroid(destCities); ok {
		center = cityKey{Lat: lat, Lon: lon, Name: centerName}
	}

	resp.Center = flowPoint{Lat: center.Lat, Lon: center.Lon, Name: center.Name, Count: len(tasks)}

	// 4) 画弧: 源 = 探针城市(远程) 或 中心(本地/探针坐标缺失)。
	arcs := aggArcs(tasks, probeCity, center)
	if len(arcs) > cfg.TopCities {
		arcs = arcs[:cfg.TopCities]
	}
	resp.Arcs = arcs

	// 6) 热点列表(按计数降序, 截断 TopCities)
	points := make([]flowPoint, 0, len(cityCount))
	for k, c := range cityCount {
		points = append(points, flowPoint{Lat: k.Lat, Lon: k.Lon, Name: k.Name, Count: c})
	}
	sortPointsDesc(points)
	if len(points) > cfg.TopCities {
		points = points[:cfg.TopCities]
	}
	resp.Points = points

	return resp
}

// aggArcs 把一批任务流聚合成弧线列表(按 源→目标 计数, 降序)。
//
// 抽成函数是因为"总览"与"时序回放(按天分帧)"都要用同一套聚合口径 —— 两处
// 各写一份必然漂移, 表现为"回放时看到的弧和总览对不上"。
func aggArcs(tasks []taskFlow, probeCity map[string]cityKey, center cityKey) []flowArc {
	type arcKey struct{ from, to cityKey }
	arcAgg := map[arcKey]int{}
	if len(center.Name) == 0 {
		return []flowArc{} // 无中心(既没配置也没有可定位目标)则画不出弧
	}
	for _, tf := range tasks {
		from, ok := probeCity[tf.probeID]
		if !ok {
			from = center // 本地任务, 或探针坐标查不到 → 归到中心
		}
		if from == tf.dst {
			continue // 源=目标(同城), 弧线零长, 不画
		}
		arcAgg[arcKey{from: from, to: tf.dst}]++
	}
	arcs := make([]flowArc, 0, len(arcAgg))
	for k, c := range arcAgg {
		arcs = append(arcs, flowArc{
			From:  flowPoint{Lat: k.from.Lat, Lon: k.from.Lon, Name: k.from.Name, Count: c},
			To:    flowPoint{Lat: k.to.Lat, Lon: k.to.Lon, Name: k.to.Name, Count: c},
			Count: c,
		})
	}
	sortFlowsDesc(arcs)
	return arcs
}

// ===== 时序回放(二期 14) =====

// flowFrame 时间轴上的一帧(一天)。
type flowFrame struct {
	Day    string      `json:"day"`
	Arcs   []flowArc   `json:"arcs"`
	Points []flowPoint `json:"points"`
	Tasks  int         `json:"tasks"`
}

// buildFlowTimeline 按天分帧, 供大屏"时序回放"逐帧播放。
//
// 为什么按天而不是按小时: 扫描任务的自然节奏是"一天扫一轮", 按小时分帧会
// 得到大量空帧(播放时地球长时间不动), 按天既有变化又能看完整个窗口。
func buildFlowTimeline(d *db.Database, g *geoip.DB, cfg dashboardConfig) ([]flowFrame, cityKey) {
	cutoff := time.Now().AddDate(0, 0, -cfg.Days)
	type bucket struct {
		tasks  []taskFlow
		cities map[cityKey]int
		order  int // 天序号(决定帧顺序)
	}
	buckets := map[string]*bucket{}
	var destCities []flowPoint
	probeCity := map[string]cityKey{}
	if dao := d.Probes(); dao != nil {
		if list, err := dao.List(); err == nil {
			for _, p := range list {
				if p == nil || p.ID == "" {
					continue
				}
				if ip := firstIP(p.Addr); ip != "" {
					if loc := geoOf(g, ip); loc != nil && loc.Known {
						name := loc.City
						if name == "" {
							name = loc.Region
						}
						if name == "" {
							name = loc.Country
						}
						probeCity[p.ID] = cityKey{Lat: loc.Lat, Lon: loc.Lon, Name: name}
					}
				}
			}
		}
	}
	if dao := d.ScanTasks(); dao != nil {
		if list, err := dao.List(); err == nil {
			for _, t := range list {
				if t == nil || t.CreatedAt.Before(cutoff) {
					continue
				}
				ip := firstIP(t.Target)
				if ip == "" {
					continue
				}
				loc := geoOf(g, ip)
				if loc == nil || !loc.Known {
					continue
				}
				name := loc.City
				if name == "" {
					name = loc.Region
				}
				key := cityKey{Lat: loc.Lat, Lon: loc.Lon, Name: name}
				day := t.CreatedAt.Format("2006-01-02")
				b := buckets[day]
				if b == nil {
					b = &bucket{cities: map[cityKey]int{}, order: int(time.Since(t.CreatedAt).Hours() / 24)}
					buckets[day] = b
				}
				b.tasks = append(b.tasks, taskFlow{dst: key, probeID: t.ProbeNode})
				b.cities[key]++
				destCities = append(destCities, flowPoint{Lat: key.Lat, Lon: key.Lon, Name: key.Name})
			}
		}
	}
	var center cityKey
	if cfg.Center.Lat != 0 || cfg.Center.Lon != 0 {
		center = cityKey{Lat: cfg.Center.Lat, Lon: cfg.Center.Lon, Name: firstNonEmptyStr(cfg.Center.Name, "监控中心")}
	} else if lat, lon, ok := centroid(destCities); ok {
		center = cityKey{Lat: lat, Lon: lon, Name: "监控中心"}
	}
	days := make([]string, 0, len(buckets))
	for day := range buckets {
		days = append(days, day)
	}
	sort.Strings(days) // 时间升序: 回放从最早的一天开始
	frames := make([]flowFrame, 0, len(days))
	for _, day := range days {
		b := buckets[day]
		pts := make([]flowPoint, 0, len(b.cities))
		for k, c := range b.cities {
			pts = append(pts, flowPoint{Lat: k.Lat, Lon: k.Lon, Name: k.Name, Count: c})
		}
		sortPointsDesc(pts)
		if len(pts) > cfg.TopCities {
			pts = pts[:cfg.TopCities]
		}
		arcs := aggArcs(b.tasks, probeCity, center)
		if len(arcs) > cfg.TopCities {
			arcs = arcs[:cfg.TopCities]
		}
		frames = append(frames, flowFrame{Day: day, Arcs: arcs, Points: pts, Tasks: len(b.tasks)})
	}
	return frames, center
}

// sortFlowsDesc 弧线按 Count 降序(稳定: 计数相同保持原序)。
func sortFlowsDesc(a []flowArc) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].Count > a[j-1].Count; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func sortPointsDesc(a []flowPoint) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].Count > a[j-1].Count; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// ===== 路由 =====

// registerDashboardRoutes 注册大屏 3D 地球数据与 globe 静态资源。
//
// 【必须挂根 mux, 不能挂 v2 server】v2 服务在 main.go 经 mux.Handle("/api/v2/", ...)
// 挂在 /api/v2/ 子树上, 而 /api/dashboard/flows 与 /vendor/globe/* 都不在该前缀下,
// 挂 v2 会永远 404 —— 故这两条走根 ServeMux, 与 /api/env、/app/ 同层级。
//
// flows 受 dashboard.enabled 控制(默认关闭); globe 静态资源始终注册
// (资源文件缺失时前端自行降级为占位, 不影响其它功能, 且避免"开了 dashboard
// 却因漏注册静态路由导致地球白屏"的排查盲区)。
func registerDashboardRoutes(mux *http.ServeMux) {
	// 路由恒注册, 启用与否由 handler 内判断:
	//
	// 开关现在在页面上(默认开), 启动时刻的开关值不能决定"这条路由是否存在" ——
	// 否则用户页面关掉后再打开, 接口仍是 404(必须重启才恢复), 那就不叫开关。
	// 未启用时 handler 返回带原因的 503, 前端同样按空态处理。
	mux.HandleFunc("GET /api/dashboard/flows", requireAuth(hDashboardFlows))
	mux.HandleFunc("GET /vendor/globe/{file}", handleGlobeFile)
}

// hDashboardFlows GET /api/dashboard/flows
// 返回 3D 地球渲染所需的中心/弧线/热点/统计。
func hDashboardFlows(w http.ResponseWriter, r *http.Request) {
	cfg := loadDashboardConfig()
	if !cfg.Enabled {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable,
			"3D 地球流向已关闭: 在页面的功能开关里重新开启即可(无需重启)")
		return
	}
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	g := instanceGeoIP()
	// timeline=1: 返回按天分帧的数据(大屏时序回放); 缺省为总量聚合
	if r.URL.Query().Get("timeline") == "1" {
		frames, center := buildFlowTimeline(d, g, cfg)
		server.OK(w, map[string]any{
			"frames": frames,
			"center": flowPoint{Lat: center.Lat, Lon: center.Lon, Name: center.Name},
			"geoip":  map[string]any{"enabled": loadGeoIPConfig().Enabled},
		})
		return
	}
	resp := buildFlows(d, g, cfg)
	server.OK(w, resp)
}

// ===== globe 前端静态资源 =====

// globeDir 运行时 globe 资源目录(exe 同目录 res/globe/, 由 build.ps1 从 build/globe 镜像。
// 2026-09-24 dist 目录整理: 内置数据资源收进 res/)。
func globeDir() string {
	return filepath.Join(exeDir(), "res", "globe")
}

// handleGlobeFile GET /vendor/globe/{file} 直读 exe 同目录 res/globe/ 下文件。
//
// 安全: {file} 是 Go 1.22 单段路径(不含 /), 天然挡掉 ../ 目录穿越;
// 这里再校验一次"最终路径必须落在 globe 目录内", 双保险。
// 缺失返回 404(前端据此降级为纯色地球占位, 不报错)。
func handleGlobeFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		server.Fail(w, http.StatusBadRequest, server.CodeBadRequest, "非法文件名")
		return
	}
	dir := globeDir()
	full := filepath.Join(dir, name)
	// 防穿越: 清洗后必须仍在 dir 内
	cleanDir, _ := filepath.Abs(dir)
	cleanFull, _ := filepath.Abs(full)
	if cleanDir == "" || !strings.HasPrefix(cleanFull, cleanDir+string(os.PathSeparator)) {
		server.Fail(w, http.StatusBadRequest, server.CodeBadRequest, "非法文件名")
		return
	}
	// 白名单扩展名(防把任意文件当静态资源外发)
	switch path.Ext(name) {
	case ".js", ".mjs", ".json", ".jpg", ".jpeg", ".png", ".webp", ".gif", ".css":
	default:
		server.Fail(w, http.StatusNotFound, server.CodeNotFound, "不支持的资源类型")
		return
	}
	http.ServeFile(w, r, full)
}
