// monitor_api.go SNMP 网络监控装配层(任务 10a)。
//
// main 包与 monitor/snmp/db 包之间的唯一连接点, 与 bigscreen_api / scheduler_api
// 同一装配模式: 配置(settings.json 的 monitor 节) + 单例 + 采集循环启停 + 路由。
//
// 架构边界:
//   - monitor 包是纯逻辑(不 import db), 落库经注入的 WriteHistory、配置经
//     每轮重读的 ReadConfig —— UI 上改目标/间隔, 一轮之内生效, 无需重启;
//   - 周期采集不进 scheduler: scheduler 是一次性队列调度(终态不重排、槽位与
//     限速为扫描设计), SNMP 轮询语义完全不同, 独立循环不占扫描并发槽位;
//   - 只读 GET/GETBULK, 对目标设备零影响。
//
// 配置语义(2026-09-21, 对齐"开箱即用"口径): enabled 默认 true,
// 空 targets = 零网络活动、零行为变化 —— 用户从监控页加目标后才开始发 UDP 包。
// 这与 scheduler 2026-09-20 默认启用是同一判断: 不改变既有默认行为的能力默认开。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/monitor"
	"yugsight/internal/probe"
	"yugsight/internal/scanner"
	"yugsight/internal/server"
	"yugsight/internal/sse"
)

// centerTargetID 内置"中心端(本机)"条目的固定 ID(不进配置, 不可编辑/删除)。
const centerTargetID = "center-self"

var (
	monOnce = &sync.Once{}
	monInst *monitor.Monitor
)

// instanceMonitor 懒加载监控单例。
//
// 与 instanceScheduler 同一手法: 指针型 Once + Do 内非 nil 守卫 + Do 外兜底。
// 守卫保证测试预注入的实例不被覆盖; 兜底保证"Once 被外部消费"的异常态下
// 调用方拿到的永远是非 nil(否则 handler 解引用 panic → 前端只见 500)。
func instanceMonitor() *monitor.Monitor {
	monOnce.Do(func() {
		if monInst != nil {
			return
		}
		cfg := loadMonitorConfig()
		m := monitor.New(cfg, loadMonitorConfig, monitorWriteHistory)
		m.SetLogger(monitorLogLine)
		m.SetHook(monitorOnRound)
		monInst = m
		if cfg.Enabled {
			m.Start()
			monitorLogLine(fmt.Sprintf("SNMP 监控已启用(默认): 间隔 %ds, 当前 %d 个目标(无目标时不发起任何采集)",
				cfg.IntervalSec, len(cfg.Targets)))
		} else {
			monitorLogLine("SNMP 监控已被显式关闭(settings.json monitor.enabled=false), 在监控页可重新开启")
		}
	})
	if monInst == nil {
		cfg := loadMonitorConfig()
		m := monitor.New(cfg, loadMonitorConfig, monitorWriteHistory)
		m.SetLogger(monitorLogLine)
		m.SetHook(monitorOnRound)
		if cfg.Enabled {
			m.Start()
		}
		monInst = m
	}
	return monInst
}

// stopMonitor 退出路径调用(未启用时为空操作)。
func stopMonitor() {
	if monInst != nil {
		monInst.Stop()
	}
}

// resetMonitorForTest 测试复位(与 resetSchedulerForTest 同模式)。
func resetMonitorForTest() {
	monInst = nil
	monOnce = &sync.Once{}
}

// monitorLogLine 监控日志并入 yugsight.log。
func monitorLogLine(msg string) { logLine("[监控] " + msg) }

// loadMonitorConfig 读 settings.json 的 monitor 节。
// 缺失 = 默认值(启用 / 60s / 空目标) —— 空目标零网络活动, 见文件头说明。
func loadMonitorConfig() monitor.Config {
	def := monitor.Config{Enabled: true, IntervalSec: 60}
	b, ok := section(secMonitor, "")
	if !ok {
		return def
	}
	var cfg monitor.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		logLine("settings.json monitor 节解析失败, 使用默认配置: " + err.Error())
		return def
	}
	if cfg.IntervalSec <= 0 {
		cfg.IntervalSec = def.IntervalSec
	}
	return cfg
}

// saveMonitorConfig 写回 settings.json 的 monitor 节。
//
// 配置口径(2026-09-23 用户要求): 中心端所有配置一律 settings.json, 不再写
// 独立 monitor.json —— 避免"配置散落在多份文件"导致用户改 A 文件、服务读
// B 文件的错位。读取仍保留 monitor.json 回退(兼容旧部署), 但写入只进 settings。
func saveMonitorConfig(c monitor.Config) error {
	if err := writeSection(secMonitor, c); err != nil {
		return err
	}
	// 2026-09-29 修: writeSection 之后必须 resetSettingsCache(与 node_push/collect 同口径) ——
	// loadSettings 是一次性缓存, 不清缓存则 monitor 引擎每轮 currentCfg→loadMonitorConfig
	// 拿到的永远是启动时的旧快照, SetConfig 更新的目标"下一轮被冲回", 表现为
	// "页面上加了监控目标, 但一直不采集 / status 里看不到"(2026-09-29 实机复现)。
	resetSettingsCache()
	return nil
}

// monitorWriteHistory 一轮样本落库(装配层注入 monitor 包)。
//
// 双 nil 守卫: v2DB() 可能 nil(库未就绪), Close() 还会把 DAO 置 nil ——
// 把 *MonitorDAO(nil) 装箱进接口后 == nil 判不出来(同 db.isNilAny 的坑),
// 这里直接拿类型化指针判。
//
// 历史裁剪: 每目标保留最近 keepSamples 条(60s 间隔 ≈ 24h),
// 防 JSONL 无限增长。
const keepSamples = 1440

func monitorWriteHistory(samples []*monitor.Sample) {
	d := v2DB()
	if d == nil {
		return
	}
	dao := d.MonitorSamples()
	if dao == nil {
		return
	}
	for _, s := range samples {
		if _, err := dao.Upsert(&db.MonitorSample{Sample: *s}); err != nil {
			monitorLogLine("采样落库失败 " + s.ID + ": " + err.Error())
		}
	}
	// 逐目标裁剪(轮次刚写完, 此时每个目标恰多一条)
	retention := loadMonitorConfig().RetentionHours
	for _, s := range samples {
		pruneMonitorSamples(dao, s.TargetID, retention)
	}
}

// 注: 样本裁剪(pruneMonitorSamples)在 monitor_timeseries.go —— 二期加了
// "保留时长"维度后不再是纯条数裁剪, 与时序查询放在同一文件便于一起维护。

// monitorOnRound 轮次结束 → SSE 广播(前端监控页可实时感知, 不必等 10s 轮询)。
func monitorOnRound(r *monitor.RoundResult) {
	_ = sse.Default().PublishJSON("monitor", map[string]any{
		"at":         r.At.Format(time.RFC3339),
		"ok":         r.OKCount,
		"total":      r.Total,
		"durationMs": r.DurationMs,
		"errors":     r.Errors,
	})
	// 拓扑链路流量/状态随 SNMP 轮次刷新(2026-09-29 阶段 B; 5s 节流)
	publishTopoLinks()
}

// ===== 路由(在 api_v2.go 的 registerV2Routes 内挂载) =====

func registerMonitorRoutes(srv *server.Server) {
	srv.Get("/api/v2/monitor/status", requireAuth(hMonitorStatus))
	srv.Get("/api/v2/monitor/targets", requireAuth(hMonitorTargets))
	srv.Post("/api/v2/monitor/targets", requireAuth(adminOrOperator(hMonitorUpsertTarget)))
	srv.Delete("/api/v2/monitor/targets/{id}", requireAuth(adminOrOperator(hMonitorDeleteTarget)))
	srv.Get("/api/v2/monitor/samples", requireAuth(hMonitorSamples))
	// 时序曲线(二期 13): 单目标单指标的时间序列, 供监控页/大屏画历史曲线
	srv.Get("/api/v2/monitor/timeseries", requireAuth(hMonitorTimeseries))
	srv.Post("/api/v2/monitor/collect", requireAuth(adminOrOperator(hMonitorCollectNow)))
	srv.Post("/api/v2/monitor/config", requireAuth(adminOrOperator(hMonitorSaveConfig)))
}

// monitorTargetView 一个目标的状态视图(配置 + 最新样本 + 速率)。
type monitorTargetView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Addr       string   `json:"addr"`
	Community  string   `json:"community"`
	TimeoutMs  int      `json:"timeoutMs"`
	Collected  bool     `json:"collected"`  // 是否采到过数据
	Online     bool     `json:"online"`     // 最近一轮成功(且未超过 2 个间隔)
	LastAt     string   `json:"lastAt,omitempty"`
	LastErr    string   `json:"lastErr,omitempty"`
	UptimeSec  int64    `json:"uptimeSec"`
	SysName    string   `json:"sysName,omitempty"`
	SysDescr   string   `json:"sysDescr,omitempty"`
	// MAC 设备首个 up 接口的物理地址(2026-09-27 监控页"MAC 地址"列; 空 = 设备未上报)
	MAC string `json:"mac,omitempty"`
	CpuLoad    int64    `json:"cpuLoad"`   // 0 = 设备不支持
	MemTotal   int64    `json:"memTotal"`  // 0 = 设备不支持
	MemUsed    int64    `json:"memUsed"`
	IfaceCount int      `json:"ifaceCount"`
	IfUp       int      `json:"ifUp"`
	// v3 元信息: 只回协议名与"是否已配置口令", 口令本身一律不回传
	// (监控目标列表是常见截屏对象, 口令不该出现在浏览器里)
	Version     string `json:"version"`
	V3User      string `json:"v3User,omitempty"`
	AuthProto   string `json:"authProto,omitempty"`
	PrivProto   string `json:"privProto,omitempty"`
	HasAuthPass bool   `json:"hasAuthPass"`
	HasPrivPass bool   `json:"hasPrivPass"`
	InRateBps  int64    `json:"inRateBps"`  // 两帧差分÷帧间隔(字节/秒), 首轮为 0
	OutRateBps int64    `json:"outRateBps"`
	Ifaces     []monIfaceView `json:"ifaces,omitempty"` // TOP5 按流量
	// Source 区分条目来源: 空=用户配置的 SNMP 目标; "center"=内置"中心端(本机)"
	// (2026-10-01 用户要求: 探针页能看到中心端, 监控目标里也该有它)。
	// 内置条目不在 cfg.Targets 里, 不落配置、不可编辑/删除(前端据此禁用操作按钮)。
	Source string `json:"source,omitempty"`
}

// centerMonitorView 内置"中心端(本机)"监控目标(2026-10-01 用户要求: 探针页能看到
// 中心端, 监控目标里也该有它 —— 本机同样是被监控对象)。
//
// 为什么做成"状态视图里的虚拟条目"而不是写进 cfg.Targets: 中心端不是 SNMP 设备,
// 存进配置会污染用户配置(导出/迁移带着一条改不动又删不掉的目标), 且每轮重建会被
// 覆盖。指标全是本进程真实采集: CPU 两采样差分、内存、网卡上下行(Windows 走 PDH
// 速率计数器, 非阻塞; 其它平台走 /proc); 任一采集失败对应字段归 0 —— UI 按"无数据
// 不显示"处理, 不编造。
func centerMonitorView() monitorTargetView {
	host, _ := os.Hostname()
	v := monitorTargetView{
		ID: centerTargetID, Name: "中心端(本机)", Addr: strings.TrimSpace(scanner.LocalIP()),
		Version: "center", Source: "center",
		Collected: true, Online: true,
		LastAt:  time.Now().Format(time.RFC3339),
		SysName: host,
		SysDescr: "Yugsight 中心端 v" + appVersion + " (" + runtime.GOOS + "/" + runtime.GOARCH + ")",
	}
	if p := centerCPUPercent(); p != nil {
		v.CpuLoad = int64(*p)
	}
	if total, used, ok := probe.MemStats(); ok {
		v.MemTotal = int64(total)
		v.MemUsed = int64(used)
	}
	// 网卡速率: 中心端进程与探针共用同一采集实现(probe.SampleMetrics)。
	// 入方向=接收(NetDown), 出方向=发送(NetUp), 与 SNMP ifIn/ifOut 口径对齐。
	if s := probe.SampleMetrics(30 * time.Second); s != nil {
		v.InRateBps = int64(s.NetDownBps)
		v.OutRateBps = int64(s.NetUpBps)
	}
	// 网卡端口明细(2026-10-02 用户要求: 中心端也要能看网口/绑端口): 与探针同一采样
	// 实现(probe.SampleIfaces, 逐口累计字节窗口差分)。主机网卡数量少, 全量回带不做
	// TOP5 截断(截断口径只用于交换机 100+ 口的聚合展示)。平台给不了的状态/带宽字段
	// 留空, 前端显示 '-' —— 不猜不编造。
	if faces := probe.SampleIfaces(30 * time.Second); len(faces) > 0 {
		ivs := make([]monIfaceView, 0, len(faces))
		for _, f := range faces {
			ivs = append(ivs, monIfaceView{
				Name: f.Name, Speed: f.Speed, Up: f.State == "up",
				InRate: int64(f.InBps), OutRate: int64(f.OutBps),
			})
			if f.State == "up" {
				v.IfUp++
			}
		}
		v.Ifaces = ivs
		v.IfaceCount = len(ivs)
	}
	return v
}

// monIfaceView 接口视图(聚合展示用)。
type monIfaceView struct {
	Name    string `json:"name"`
	Speed   int64  `json:"speed"`
	Up      bool   `json:"up"`
	InRate  int64  `json:"inRate"`
	OutRate int64  `json:"outRate"`
}

// hMonitorStatus GET /api/v2/monitor/status
// 配置 + 轮次 + 每目标最新视图(监控页与大屏共用数据源)。
func hMonitorStatus(w http.ResponseWriter, r *http.Request) {
	m := instanceMonitor()
	cfg := m.Config()
	latest := m.Latest()
	prev := m.Prev()
	interval := monitor.EffectiveInterval(cfg.IntervalSec)

	type targetView = monitorTargetView
	// 内置"中心端(本机)"排在最前: 它是本进程自己, 永远在线且指标实时可取
	// (2026-10-01 用户要求: 中心端也要进监控目标)。只出现在状态视图, 不入配置。
	views := make([]targetView, 0, len(cfg.Targets)+1)
	views = append(views, centerMonitorView())
	for _, t := range cfg.Targets {
		v := targetView{ID: t.ID, Name: t.Name, Addr: t.Addr, TimeoutMs: t.TimeoutMs,
			Version: t.Version(), V3User: t.User, AuthProto: t.AuthProto, PrivProto: t.PrivProto,
			HasAuthPass: t.AuthPass != "", HasPrivPass: t.PrivPass != ""}
		if s, ok := latest[t.ID]; ok {
			v.Collected = true
			v.LastAt = s.At.Format(time.RFC3339)
			v.Online = s.OK && time.Since(s.At) < interval*2
			if !s.OK {
				v.LastErr = s.Err
			}
			v.UptimeSec = s.UptimeSec
			v.SysName = s.SysName
			v.SysDescr = s.SysDescr
			v.MAC = s.MAC
			v.CpuLoad = s.CpuLoad
			v.MemTotal = s.MemTotal
			v.MemUsed = s.MemUsed
			v.IfaceCount = len(s.Ifaces)
			// 速率: latest 与 prev 两帧差分 ÷ 两帧实际间隔(字节/秒); 接口按名字对齐(设备重启后 ifIndex 可能变)
			pi := map[string]*monitor.IfaceSample{}
			var dt time.Duration // 两帧间隔; 无 prev(首轮) = 0 → 速率归 0
			if p, ok := prev[t.ID]; ok {
				for i := range p.Ifaces {
					pi[p.Ifaces[i].Name] = &p.Ifaces[i]
				}
				dt = s.At.Sub(p.At)
			}
			top := make([]monIfaceView, 0, 5)
			for i := range s.Ifaces {
				cur := &s.Ifaces[i]
				inBps, outBps := monitor.IfaceRate(cur, pi[cur.Name], dt)
				v.InRateBps += inBps
				v.OutRateBps += outBps
				if cur.Oper == 1 {
					v.IfUp++
				}
				top = append(top, monIfaceView{
					Name: cur.Name, Speed: cur.Speed, Up: cur.Oper == 1,
					InRate: inBps, OutRate: outBps,
				})
			}
			// TOP5 按入+出速率降序(流量最大的接口最有运维价值)
			sortIfaceByRate(top)
			if len(top) > 5 {
				top = top[:5]
			}
			v.Ifaces = top
		}
		views = append(views, v)
	}

	out := map[string]any{
		"enabled":     cfg.Enabled,
		"intervalSec": cfg.IntervalSec,
		"running":     m.Running(),
		"targets":     views,
		// 密钥是否就绪: 未设置时口令以明文存, 前端据此给出提示
		"secretKeySet": len(monitor.SecretKey()) > 0,
	}
	if lr := m.LastRound(); lr != nil {
		out["lastRound"] = map[string]any{
			"at":         lr.At.Format(time.RFC3339),
			"ok":         lr.OKCount,
			"total":      lr.Total,
			"durationMs": lr.DurationMs,
			"errors":     lr.Errors,
		}
	}
	server.OK(w, out)
}

func sortIfaceByRate(v []monIfaceView) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0; j-- {
			if v[j].InRate+v[j].OutRate > v[j-1].InRate+v[j-1].OutRate {
				v[j], v[j-1] = v[j-1], v[j]
			} else {
				break
			}
		}
	}
}

// hMonitorTargets GET /api/v2/monitor/targets
//
// 口令一律不回传(见 sanitizeTargets): 该接口服务于"编辑目标"表单, 而浏览器里
// 的口令既没必要也容易随截图外流; 前端留空表示"不修改"。
func hMonitorTargets(w http.ResponseWriter, r *http.Request) {
	server.OK(w, map[string]any{"targets": sanitizeTargets(instanceMonitor().Config().Targets)})
}

// sanitizeTargets 脱敏: 清掉社区串与 v3 口令, 只留协议名与"是否已配置"标记。
func sanitizeTargets(in []monitor.Target) []monitor.Target {
	out := make([]monitor.Target, 0, len(in))
	for _, t := range in {
		t.Community = ""
		t.AuthPass = ""
		t.PrivPass = ""
		out = append(out, t)
	}
	return out
}

// hMonitorUpsertTarget POST /api/v2/monitor/targets
// body: {id?, name, addr, community, timeoutMs} —— id 缺省自动生成。
// 按 id upsert(同 id 覆盖, 不同 id 追加), 保存后 SetConfig 让下一轮立即生效。
func hMonitorUpsertTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Addr      string `json:"addr"`
		Community string `json:"community"`
		TimeoutMs int    `json:"timeoutMs"`
		// v3(USM): User 非空即 v3 模式
		User      string `json:"user"`
		AuthProto string `json:"authProto"`
		AuthPass  string `json:"authPass"`
		PrivProto string `json:"privProto"`
		PrivPass  string `json:"privPass"`
		Context   string `json:"context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		server.Fail(w, http.StatusBadRequest, server.CodeBadRequest, "请求格式错误: "+err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Addr = strings.TrimSpace(in.Addr)
	in.Community = strings.TrimSpace(in.Community)
	in.User = strings.TrimSpace(in.User)
	in.AuthProto = strings.TrimSpace(in.AuthProto)
	in.PrivProto = strings.TrimSpace(in.PrivProto)
	in.Context = strings.TrimSpace(in.Context)
	if in.Name == "" || in.Addr == "" {
		server.Fail(w, http.StatusBadRequest, server.CodeBadRequest, "name / addr 必填")
		return
	}
	v3 := in.User != ""
	// 凭据校验: v2c 要 community, v3 要用户名 + 鉴权口令(私有/加密口令可选)
	if !v3 && in.Community == "" {
		server.Fail(w, http.StatusBadRequest, server.CodeBadRequest, "v2c 目标必须填 community")
		return
	}
	if v3 && in.AuthProto != "" && in.AuthPass == "" {
		server.Fail(w, http.StatusBadRequest, server.CodeBadRequest, "v3 指定了鉴权协议时必须填鉴权口令")
		return
	}
	if in.TimeoutMs < 0 || in.TimeoutMs > 60000 {
		in.TimeoutMs = 3000
	}
	if in.ID == "" {
		in.ID = "m" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	}
	in.ID = strings.TrimSpace(in.ID)

	m := instanceMonitor()
	cfg := m.Config()
	// 口令落盘前加密(secrets.go); 前端编辑时留空 = "不修改", 故空值保留原密文。
	// 密钥缺失时 EncryptSecret 原样返回明文并在此告警 —— 明文是可运行状态,
	// 但必须让用户知道(否则"以为加密了"比"知道是明文"危险得多)。
	key := monitor.SecretKey()
	if key == nil && (in.Community != "" || in.AuthPass != "" || in.PrivPass != "") {
		monitorLogLine("环境变量 " + monitor.SecretKeyEnv + " 未设置: SNMP 口令将以明文写入配置文件(设置后重新保存即自动转为密文)")
	}
	enc := func(plain, old string) string {
		if strings.TrimSpace(plain) == "" {
			return old
		}
		return monitor.EncryptSecret(key, plain)
	}
	found := false
	for i := range cfg.Targets {
		if cfg.Targets[i].ID == in.ID {
			old := cfg.Targets[i]
			cfg.Targets[i] = monitor.Target{
				ID: in.ID, Name: in.Name, Addr: in.Addr, TimeoutMs: in.TimeoutMs,
				Community: enc(in.Community, old.Community),
				User:      in.User, AuthProto: in.AuthProto, PrivProto: in.PrivProto, Context: in.Context,
				AuthPass: enc(in.AuthPass, old.AuthPass),
				PrivPass: enc(in.PrivPass, old.PrivPass),
			}
			found = true
			break
		}
	}
	if !found {
		cfg.Targets = append(cfg.Targets, monitor.Target{
			ID: in.ID, Name: in.Name, Addr: in.Addr, TimeoutMs: in.TimeoutMs,
			Community: enc(in.Community, ""),
			User:      in.User, AuthProto: in.AuthProto, PrivProto: in.PrivProto, Context: in.Context,
			AuthPass: enc(in.AuthPass, ""),
			PrivPass: enc(in.PrivPass, ""),
		})
	}
	if err := saveMonitorConfig(cfg); err != nil {
		server.Fail(w, http.StatusInternalServerError, server.CodeInternal, "配置保存失败: "+err.Error())
		return
	}
	m.SetConfig(cfg)
	logAudit(v2DB(), r, "monitor.target.upsert", in.ID, "addr="+in.Addr)
	server.OK(w, map[string]any{"id": in.ID, "updated": found, "targets": cfg.Targets})
}

// hMonitorDeleteTarget DELETE /api/v2/monitor/targets/{id}
func hMonitorDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		server.Fail(w, http.StatusBadRequest, server.CodeBadRequest, "缺少目标 ID")
		return
	}
	m := instanceMonitor()
	cfg := m.Config()
	out := cfg.Targets[:0]
	found := false
	for _, t := range cfg.Targets {
		if t.ID == id {
			found = true
			continue
		}
		out = append(out, t)
	}
	if !found {
		server.Fail(w, http.StatusNotFound, server.CodeNotFound, "目标不存在: "+id)
		return
	}
	cfg.Targets = out
	if err := saveMonitorConfig(cfg); err != nil {
		server.Fail(w, http.StatusInternalServerError, server.CodeInternal, "配置保存失败: "+err.Error())
		return
	}
	m.SetConfig(cfg)
	logAudit(v2DB(), r, "monitor.target.delete", id, "")
	server.OK(w, map[string]any{"deleted": id, "targets": cfg.Targets})
}

// hMonitorSamples GET /api/v2/monitor/samples?target=&limit=
// 采样历史(时间升序): target 缺省 = 全部; limit 默认 200, 上限 2000。
func hMonitorSamples(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	dao := d.MonitorSamples()
	if dao == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "监控采样表不可用")
		return
	}
	target := r.URL.Query().Get("target")
	limit := 200
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 2000 {
		limit = 2000
	}

	var rows []any
	if target != "" {
		list, err := dao.ByTargetTail(target, limit)
		if err != nil {
			server.Fail(w, http.StatusInternalServerError, server.CodeInternal, "查询失败: "+err.Error())
			return
		}
		for _, s := range list {
			rows = append(rows, &s.Sample)
		}
	} else {
		all, err := dao.List()
		if err != nil {
			server.Fail(w, http.StatusInternalServerError, server.CodeInternal, "查询失败: "+err.Error())
			return
		}
		if len(all) > limit {
			all = all[len(all)-limit:]
		}
		for _, s := range all {
			rows = append(rows, &s.Sample)
		}
	}
	if rows == nil {
		rows = []any{}
	}
	server.OK(w, map[string]any{"samples": rows, "limit": limit})
}

// hMonitorCollectNow POST /api/v2/monitor/collect
// 手动触发一轮(不等周期), 120s 时限(大表 walk 可能 10s 级)。
func hMonitorCollectNow(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	res := instanceMonitor().CollectNow(ctx)
	if res == nil {
		server.Fail(w, http.StatusInternalServerError, server.CodeInternal, "触发失败")
		return
	}
	if len(res.Errors) > 0 && res.OKCount == 0 && res.Total > 0 {
		server.Fail(w, http.StatusBadGateway, server.CodeInternal, "采集失败: "+fmt.Sprint(res.Errors))
		return
	}
	// 2026-10-02 用户口径: 节点监控是连续采样, 不生成原始报告(报告中心被节点监控
	// 报告刷屏, 用户: "这些不需要生成原始报告, 最多是信息做为日志记录一下") →
	// 只记一条摘要日志; 周期轮询原本也不存档, 口径统一为"节点监控永不进报告中心"。
	logLine(fmt.Sprintf("节点监控采集一轮完成: %d/%d 在线(不存报告中心, 仅日志记录)", res.OKCount, res.Total))
	server.OK(w, res)
}

// hMonitorSaveConfig POST /api/v2/monitor/config
// body: {enabled, intervalSec} —— 只改这两项, targets 不动。
func hMonitorSaveConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled     *bool `json:"enabled"`
		IntervalSec *int  `json:"intervalSec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		server.Fail(w, http.StatusBadRequest, server.CodeBadRequest, "请求格式错误: "+err.Error())
		return
	}
	m := instanceMonitor()
	cfg := m.Config()
	if in.Enabled != nil {
		cfg.Enabled = *in.Enabled
	}
	if in.IntervalSec != nil {
		if *in.IntervalSec < 5 {
			server.Fail(w, http.StatusBadRequest, server.CodeBadRequest, "轮询间隔最小 5 秒")
			return
		}
		cfg.IntervalSec = *in.IntervalSec
	}
	if err := saveMonitorConfig(cfg); err != nil {
		server.Fail(w, http.StatusInternalServerError, server.CodeInternal, "配置保存失败: "+err.Error())
		return
	}
	m.SetConfig(cfg)
	if cfg.Enabled {
		m.Start() // 幂等: 已运行则空操作; 从关闭切到开启时这里拉起循环
	} else {
		m.Stop()
	}
	logAudit(v2DB(), r, "monitor.config", "", fmt.Sprintf("enabled=%v intervalSec=%d", cfg.Enabled, cfg.IntervalSec))
	server.OK(w, map[string]any{"enabled": cfg.Enabled, "intervalSec": cfg.IntervalSec})
}


