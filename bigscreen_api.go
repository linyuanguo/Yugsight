// bigscreen_api.go 安全运维大屏接口装配层(任务 7.3)。
//
// 本文件是 main 包与 bigscreen 包的唯一连接点, 职责:
//   - 注册 /api/v2/screen/* 路由(走 v2 统一响应与鉴权)
//   - 把装配层运行时状态(探针实时负载快照)并入聚合结果
//
// 为什么探针负载在装配层补: bigscreen 包只依赖 db 与 models(纯函数、可离线
// 单测), 而"探针实时负载"躺在 probe 包的内存结构里。若让 bigscreen 直接
// import probe, 就把统计逻辑与实时通信层焊死了, 单测必须连真实 TCP ——
// 这正是项目其它模块(parsers 不 import engine、scheduler 不 import probe)
// 刻意避开的坑, 这里沿用同一约定。
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"yugsight/bigscreen"
	"yugsight/server"
)

// ===== 配置 =====

// bigScreenConfig 大屏配置(exe 同目录 screen.json, 可选, 缺失=全默认)。
//
// 单独一个文件而不复用其它配置: 大屏目前只有一个开关, 语义独立;
// 挂在别人的配置上会让将来"大屏加个刷新间隔"这种需求波及报告/调度模块。
type bigScreenConfig struct {
	// Metrics 是否挂载 Prometheus 兼容的文本指标端点(/api/v2/screen/metrics)。
	//
	// 默认 false: 该端点不含 v2 统一信封, 且可能被外部系统(Grafana/Prometheus)
	// 抓取, 属于任务书明确的"二期扩展预留"能力。默认关闭符合项目约定
	// "新增功能默认关闭, 配置开关启用"。
	Metrics bool `json:"metrics"`
}

var (
	bigScreenCfgMu   sync.RWMutex
	bigScreenCfgVal  bigScreenConfig
	bigScreenCfgDone bool
)

// bigScreenConfigPath 配置文件路径(exe 同目录 screen.json)。
func bigScreenConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "screen.json"
	}
	return filepath.Join(filepath.Dir(exe), "screen.json")
}

// loadBigScreenConfig 读 screen.json(可选: 缺失/损坏一律用默认, 不报错退出)。
func loadBigScreenConfig() bigScreenConfig {
	bigScreenCfgMu.RLock()
	if bigScreenCfgDone {
		cfg := bigScreenCfgVal
		bigScreenCfgMu.RUnlock()
		return cfg
	}
	bigScreenCfgMu.RUnlock()

	var cfg bigScreenConfig
	// settings.json 的 screen 节优先, 回退旧 screen.json。
	data, ok := section(secScreen, "")
	if ok {
		// settings.json 走 loadSettings 已剥 BOM, 这里无需再处理
		if uerr := json.Unmarshal(data, &cfg); uerr != nil {
			logLine("settings.json 的 screen 节解析失败, 使用默认配置(metrics 关闭): " + uerr.Error())
			cfg = bigScreenConfig{}
		}
		bigScreenCfgMu.Lock()
		bigScreenCfgVal, bigScreenCfgDone = cfg, true
		bigScreenCfgMu.Unlock()
		return cfg
	}
	// 红线「配置唯一」: 不再回退 screen.json —— 旧文件由 settings.go 的
	// migrateLegacyConfigs 在启动时并入 settings.json 的 screen 节。
	bigScreenCfgMu.Lock()
	bigScreenCfgVal, bigScreenCfgDone = cfg, true
	bigScreenCfgMu.Unlock()
	return cfg
}

// ===== 路由 =====

// registerBigScreenRoutes 注册大屏 API。
//
// 无"启用大屏"开关: 大屏是只读聚合视图, 不改变任何既有行为(不接管扫描、
// 不下发任务、不写库), 因此不必像 scheduler/report 那样默认关闭 —— 那些模块
// 默认关闭是因为会改变执行链路。这里若也加开关, 只会多一个"大屏为什么没数据"
// 的排查点。
func registerBigScreenRoutes(srv *server.Server) {
	srv.Get("/api/v2/screen/overview", requireAuth(hScreenOverview))
	// 二期预留: Prometheus 抓取端点(文本格式), 默认不注册。
	if loadBigScreenConfig().Metrics {
		srv.Get("/api/v2/screen/metrics", hScreenMetrics)
		logLine("大屏 Prometheus 指标端点已启用: /api/v2/screen/metrics")
	}
}

// hScreenOverview GET /api/v2/screen/overview?days=&top=&recent=
// 一次返回大屏全部指标(卡片 + 趋势 + 探针 + 榜单 + 最近任务)。
func hScreenOverview(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	q := r.URL.Query()
	days, _ := strconv.Atoi(q.Get("days"))
	topN, _ := strconv.Atoi(q.Get("top"))
	recent, _ := strconv.Atoi(q.Get("recent"))

	snap := bigscreen.Build(d, time.Now(), bigscreen.Options{
		Days: days, TopN: topN, MaxRecent: recent,
	})
	enrichProbeLoad(snap)
	server.OK(w, snap)
}

// hScreenMetrics GET /api/v2/screen/metrics Prometheus 文本导出(二期扩展预留)。
//
// 刻意不走 requireAuth: 抓取端(Prometheus)不便携带会话 cookie, 若强加鉴权
// 只会让人去抓 cookie 而不是真正收紧安全边界。该端点默认不注册(见
// bigScreenConfig.Metrics), 需要时由部署方在可信网络内开启。
func hScreenMetrics(w http.ResponseWriter, r *http.Request) {
	d := v2GetDB()
	snap := bigscreen.Build(d, time.Now(), bigscreen.Options{})
	if d != nil {
		enrichProbeLoad(snap)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(bigscreen.Metrics(snap)))
}

// ===== 装配层补数据 =====

// enrichProbeLoad 用探针中心端的实时快照覆盖库中负载。
//
// 为什么必须覆盖: 探针表里的 Load 是**心跳落库那一刻**的快照, 心跳间隔通常
// 3~10 秒, 而中心端内存中的快照是最新的。大屏展示 CPU/内存负载, 差一个心跳
// 周期就可能在"探针已经跑满"时仍显示 20%, 告警意义尽失。
func enrichProbeLoad(snap *bigscreen.Snapshot) {
	if snap == nil || probeCenter == nil {
		return
	}
	live := probeCenter.Snapshots()
	if len(live) == 0 {
		return
	}
	type loadView struct {
		cpu, mem *float64
		tasks    int
		task     string
	}
	byID := make(map[string]loadView, len(live))
	for _, s := range live {
		var e loadView
		if s.Load != nil {
			cpu, mem := s.Load.CPUPercent, s.Load.MemPercent
			e.cpu, e.mem = &cpu, &mem
			e.tasks, e.task = s.Load.TasksRunning, s.Load.CurrentTask
		}
		byID[s.ProbeID] = e
	}
	online := 0
	for i := range snap.Probes {
		// 中心端有实时连接 = 在线(库中状态可能滞后于进程实时态)
		if probeCenter.Online(snap.Probes[i].ID) {
			snap.Probes[i].Online = true
			online++
		}
		e, ok := byID[snap.Probes[i].ID]
		if !ok {
			continue
		}
		if e.cpu != nil {
			snap.Probes[i].CPUPercent = e.cpu
		}
		if e.mem != nil {
			snap.Probes[i].MemPercent = e.mem
		}
		snap.Probes[i].TasksRunning = e.tasks
		snap.Probes[i].CurrentTask = e.task
	}
	// 在线的探针若不在库中(注册未落库/落库失败), 也应出现在大屏上 ——
	// 大屏显示"0 个在线探针"而实际有节点在跑任务, 是最容易误导运维的情形。
	known := make(map[string]bool, len(snap.Probes))
	for i := range snap.Probes {
		known[snap.Probes[i].ID] = true
	}
	for _, s := range live {
		if known[s.ProbeID] {
			continue
		}
		pn := bigscreen.ProbeNode{
			ID: s.ProbeID, Name: s.Name, Addr: s.Remote,
			Status: "online", Online: true,
		}
		if s.Load != nil {
			cpu, mem := s.Load.CPUPercent, s.Load.MemPercent
			pn.CPUPercent, pn.MemPercent = &cpu, &mem
			pn.TasksRunning, pn.CurrentTask = s.Load.TasksRunning, s.Load.CurrentTask
		}
		if s.Info != nil {
			pn.Hostname, pn.OS = s.Info.Hostname, s.Info.OS
			pn.CPUCores = s.Info.CPUCores
			pn.MemTotal, pn.MemUsed = s.Info.MemTotal, s.Info.MemUsed
		}
		if ts, err := time.Parse(time.RFC3339, s.LastSeen); err == nil {
			pn.LastSeenAt = ts
		}
		snap.Probes = append(snap.Probes, pn)
		snap.Overview.ProbesOnline++
		snap.Overview.Probes++
	}
	if online > snap.Overview.ProbesOnline {
		snap.Overview.ProbesOnline = online
	}
	if snap.Overview.ProbesOnline > snap.Overview.Probes {
		snap.Overview.Probes = snap.Overview.ProbesOnline
	}
	snap.Overview.ProbesOffline = snap.Overview.Probes - snap.Overview.ProbesOnline
}
