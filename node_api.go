// node_api.go 节点监控装配层(阶段 1: 采集底座)。
//
// main 包与 collect 包之间的唯一连接点, 与 monitor_api / scheduler_api /
// bigscreen_api 同一装配模式: 配置(settings.json 的 collect 节) + 单例 +
// 引擎启停 + 路由 + 落库/广播注入。
//
// 架构边界:
//   - collect 包是纯逻辑(不 import db/http), 落库经注入的 WriteHistory、
//     事件经 SetEventHook、配置经每 tick 重读的 readCfg —— UI 上改任务/
//     间隔, 一个 tick(1s)内生效, 无需重启;
//   - 周期采集不进 scheduler: scheduler 是一次性队列调度(终态不重排、槽位
//     与限速为扫描设计), 采集轮询语义完全不同, 独立循环不占扫描并发槽位;
//   - SNMP 网络设备监控继续走既有 monitor 包(独立表), 本模块的 snmp 协议
//     是"主机 SNMP"(HR-MIB), 两者页面同屏展示但数据源独立;
//   - 标准化输出: 全部产出统一为 collect.Metric, ReportSink 预留报告中心
//     入口(阶段 1 保持 NopSink 空转, 不实现 AI)。
//
// 默认关闭(项目规则 5): settings.json 无 collect 节 = enabled=false,
// 引擎不跑循环、不监听端口、不发起任何外连 —— 用户在节点监控页显式开启。
//
// 配置口径(2026-09-23, 用户要求): 中心端所有配置一律在 settings.json,
// 不再写独立 collect.json(新模块直接按新口径, 不做旧文件回退)。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/collect"
	"yugsight/db"
	"yugsight/monitor"
	"yugsight/server"
	"yugsight/sse"
)

var (
	nodeOnce = &sync.Once{}
	nodeInst *collect.Engine
)

// instanceCollect 懒加载采集引擎单例。
//
// 与 instanceScheduler/instanceMonitor 同一手法: 指针型 Once + Do 内非 nil
// 守卫 + Do 外兜底。守卫保证测试预注入的实例不被覆盖; 兜底保证"Once 被外部
// 消费"的异常态下调用方拿到的永远是非 nil(否则 handler 解引用 panic →
// 前端只见 500 无从排查)。
func instanceCollect() *collect.Engine {
	nodeOnce.Do(func() {
		if nodeInst != nil {
			return
		}
		cfg := loadCollectConfig()
		e := collect.New(cfg, loadCollectConfig, collectWriteHistory)
		e.SetLogger(nodeLogLine)
		e.SetEventHook(collectOnEvent)
		nodeInst = e
		if cfg.Enabled {
			e.Start()
			nodeLogLine(fmt.Sprintf("节点采集引擎已启用: 默认间隔 %ds, 并发 %d, 全局限速 %d/s, 当前 %d 个任务",
				cfg.IntervalSec, cfg.Concurrent, cfg.GlobalRate, len(cfg.Tasks)))
		} else {
			nodeLogLine("节点采集默认关闭(规则 5): 在节点监控页开启后开始采集")
		}
	})
	if nodeInst == nil {
		cfg := loadCollectConfig()
		e := collect.New(cfg, loadCollectConfig, collectWriteHistory)
		e.SetLogger(nodeLogLine)
		e.SetEventHook(collectOnEvent)
		if cfg.Enabled {
			e.Start()
		}
		nodeInst = e
	}
	return nodeInst
}

// stopCollect 退出路径调用(未启用时为空操作)。
func stopCollect() {
	if nodeInst != nil {
		nodeInst.Stop()
	}
}

// resetCollectForTest 测试复位(与 resetMonitorForTest 同模式)。
func resetCollectForTest() {
	nodeInst = nil
	nodeOnce = &sync.Once{}
}

// nodeLogLine 节点采集日志并入 yugsight.log。
func nodeLogLine(msg string) { logLine("[节点采集] " + msg) }

// loadCollectConfig 读 settings.json 的 collect 节。
// 缺失 = 默认全关(规则 5)。新模块不读旧独立文件(配置口径统一在 settings.json)。
func loadCollectConfig() collect.Config {
	var cfg collect.Config
	b, ok := section(secCollect, "")
	if !ok {
		return cfg
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		logLine("settings.json collect 节解析失败, 使用默认(全关)配置: " + err.Error())
		return collect.Config{}
	}
	return cfg
}

// saveCollectConfig 写回 settings.json 的 collect 节(合并写, 保留其它节)。
// 用户要求: 中心端配置一律 settings.json, 不写独立文件。
func saveCollectConfig(c collect.Config) error {
	return writeSection(secCollect, c)
}

// collectWriteHistory 一轮样本落库(装配层注入 collect 包)。
//
// 双 nil 守卫: v2DB() 可能 nil(库未就绪), Close() 还会把 DAO 置 nil ——
// 把 (*CollectSampleDAO)(nil) 装箱进接口后 == nil 判不出来(同 db.isNilAny
// 的坑), 这里直接拿类型化指针判。
//
// 历史裁剪: 保留时长 + 每任务条数双限(与 monitor 同口径), 防 JSONL 无限增长。
func collectWriteHistory(rounds []*collect.Round) {
	d := v2DB()
	if d == nil {
		return
	}
	dao := d.CollectSamples()
	if dao == nil {
		return
	}
	for _, r := range rounds {
		if _, err := dao.Upsert(&db.CollectSample{Round: *r}); err != nil {
			nodeLogLine("轮次落库失败 " + r.ID + ": " + err.Error())
		}
	}
	// 裁剪: 时长(保留窗口) + 每任务条数
	cfg := loadCollectConfig().WithDefaults()
	cut := time.Now().Add(-time.Duration(cfg.RetentionHours) * time.Hour)
	_, _ = dao.PruneByTime(cut)
	_, _ = dao.PrunePerTask(keepCollectRounds)
}

// keepCollectRounds 每任务内存/磁盘保留的轮次数(60s 间隔 ≈ 24h)。
const keepCollectRounds = 1440

// collectOnEvent 异常事件 → 落库 + SSE 广播(装配层注入 collect 包)。
func collectOnEvent(ev *collect.Event) {
	d := v2DB()
	if d != nil {
		if dao := d.CollectEvents(); dao != nil {
			if _, err := dao.Upsert(&db.CollectEvent{Event: *ev}); err != nil {
				nodeLogLine("事件落库失败 " + ev.ID + ": " + err.Error())
			}
			// 事件保留 30 天(比轮次长: 事件是排障线索, 值得留更久)
			_, _ = dao.PruneByTime(time.Now().Add(-30 * 24 * time.Hour))
		}
	}
	_ = sse.Default().PublishJSON("nodecollect", map[string]any{
		"type": ev.Type, "level": ev.Level, "task": ev.TaskID,
		"target": ev.Target, "msg": ev.Msg,
		"at":     ev.At.Format(time.RFC3339),
	})
}

// ===== 路由(在 api_v2.go 的 registerV2Routes 内挂载) =====

func registerNodeRoutes(srv *server.Server) {
	srv.Get("/api/v2/node/status", requireAuth(hNodeStatus))
	srv.Get("/api/v2/node/protocols", requireAuth(hNodeProtocols))
	srv.Get("/api/v2/node/tasks", requireAuth(hNodeTasks))
	srv.Post("/api/v2/node/tasks", requireAuth(adminOrOperator(hNodeUpsertTask)))
	srv.Delete("/api/v2/node/tasks/{id}", requireAuth(adminOrOperator(hNodeDeleteTask)))
	srv.Post("/api/v2/node/collect", requireAuth(adminOrOperator(hNodeCollectNow)))
	srv.Get("/api/v2/node/metrics", requireAuth(hNodeMetrics))
	srv.Get("/api/v2/node/events", requireAuth(hNodeEvents))
	srv.Post("/api/v2/node/config", requireAuth(adminOrOperator(hNodeSaveConfig)))
}

// nodeTaskView 任务的脱敏视图(口令只回"是否已配置", 不回明文 —— 与
// monitor 目标视图同一口径: 监控配置是常见截屏对象, 口令不该出现在浏览器里)。
type nodeTaskView struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Side        string            `json:"side"`
	Protocol    string            `json:"protocol"`
	Target      string            `json:"target"`
	Enabled     bool              `json:"enabled"`
	IntervalSec int               `json:"intervalSec,omitempty"`
	TimeoutMs   int               `json:"timeoutMs,omitempty"`
	Community   string            `json:"community,omitempty"`
	User        string            `json:"user,omitempty"`
	AuthProto   string            `json:"authProto,omitempty"`
	PrivProto   string            `json:"privProto,omitempty"`
	HasAuthPass bool              `json:"hasAuthPass"`
	HasPrivPass bool              `json:"hasPrivPass"`
	Params      map[string]string `json:"params,omitempty"`
	// 运行时状态(来自引擎内存时序)
	Collected bool   `json:"collected"`
	Online    bool   `json:"online"`
	LastAt    string `json:"lastAt,omitempty"`
	LastErr   string `json:"lastErr,omitempty"`
	ElapsedMs int64  `json:"elapsedMs"`
	Metrics   []collect.Metric `json:"metrics,omitempty"` // 最新一轮指标(展示)
}

func toTaskView(t collect.Task, latest map[string]*collect.Round) nodeTaskView {
	v := nodeTaskView{
		ID: t.ID, Name: t.Name, Side: t.Side, Protocol: t.Protocol, Target: t.Target,
		Enabled: t.Enabled, IntervalSec: t.IntervalSec, TimeoutMs: t.TimeoutMs,
		Community: t.Community, User: t.User, AuthProto: t.AuthProto, PrivProto: t.PrivProto,
		Params: t.Params,
	}
	key := monitor.SecretKey()
	v.HasAuthPass = t.AuthPass != ""
	v.HasPrivPass = t.PrivPass != ""
	_ = key
	if r := latest[t.ID]; r != nil {
		v.Collected = true
		v.Online = r.OK && time.Since(r.At) < 2*collectDefaultInterval()
		v.LastAt = r.At.Format(time.RFC3339)
		v.LastErr = r.Err
		v.ElapsedMs = r.ElapsedMs
		v.Metrics = r.Metrics
	}
	return v
}

// collectDefaultInterval 状态视图"在线"判定的默认间隔兜底(60s)。
func collectDefaultInterval() time.Duration { return 60 * time.Second }

// hNodeStatus GET /api/v2/node/status
// 引擎状态 + 配置 + 协议清单 + 每任务最新视图(节点监控页两个 Tab 共用数据源)。
func hNodeStatus(w http.ResponseWriter, r *http.Request) {
	e := instanceCollect()
	cfg := e.Config().WithDefaults()
	latest := e.Store().Latest()

	views := make([]nodeTaskView, 0, len(cfg.Tasks))
	for _, t := range cfg.Tasks {
		views = append(views, toTaskView(t, latest))
	}
	server.OK(w, map[string]any{
		"enabled":         e.Running() && cfg.Enabled,
		"running":         e.Running(),
		"intervalSec":     cfg.IntervalSec,
		"concurrent":      cfg.Concurrent,
		"globalRate":      cfg.GlobalRate,
		"retentionHours":  cfg.RetentionHours,
		"whitelist":       cfg.Whitelist,
		"alerts":          cfg.Alerts,
		"netflowEnabled":  cfg.NetFlow.Enabled,
		"netflowListen":   cfg.NetFlow.Listen,
		"netflowActive":   e.FlowsListening(),
		"secretKeySet":    monitor.SecretKey() != nil,
		"protocols":       collect.Protocols(),
		"tasks":           views,
		"taskCount":       len(views),
		"sampleCount":     nodeSampleCount(),
		"eventCount":      nodeEventCount(),
	})
}

func nodeSampleCount() int {
	d := v2DB()
	if d == nil {
		return 0
	}
	if dao := d.CollectSamples(); dao != nil {
		n, _ := dao.Count()
		return n
	}
	return 0
}

func nodeEventCount() int {
	d := v2DB()
	if d == nil {
		return 0
	}
	if dao := d.CollectEvents(); dao != nil {
		n, _ := dao.Count()
		return n
	}
	return 0
}

// hNodeProtocols GET /api/v2/node/protocols —— 协议能力矩阵(建任务表单用)。
func hNodeProtocols(w http.ResponseWriter, r *http.Request) {
	server.OK(w, map[string]any{"protocols": collect.Protocols()})
}

// hNodeTasks GET /api/v2/node/tasks?side=
func hNodeTasks(w http.ResponseWriter, r *http.Request) {
	e := instanceCollect()
	cfg := e.Config()
	latest := e.Store().Latest()
	side := strings.TrimSpace(r.URL.Query().Get("side"))
	out := make([]nodeTaskView, 0, len(cfg.Tasks))
	for _, t := range cfg.Tasks {
		if side != "" && t.Side != side {
			continue
		}
		out = append(out, toTaskView(t, latest))
	}
	server.OK(w, map[string]any{"tasks": out})
}

// hNodeUpsertTask POST /api/v2/node/tasks —— 新增/更新(按 ID)。
func hNodeUpsertTask(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID          string            `json:"id"`
		Name        string            `json:"name"`
		Side        string            `json:"side"`
		Protocol    string            `json:"protocol"`
		Target      string            `json:"target"`
		Enabled     *bool             `json:"enabled"`
		IntervalSec *int              `json:"intervalSec"`
		TimeoutMs   *int              `json:"timeoutMs"`
		Community   string            `json:"community"`
		User        string            `json:"user"`
		AuthProto   string            `json:"authProto"`
		PrivProto   string            `json:"privProto"`
		AuthPass    string            `json:"authPass"`
		PrivPass    string            `json:"privPass"`
		Params      map[string]string `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		server.FailBadRequest(w, "请求格式错误: "+err.Error())
		return
	}
	// ID: 不传则按协议+目标生成稳定 ID(同一目标重复提交幂等)
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = in.Protocol + "-" + strings.ReplaceAll(strings.TrimSpace(in.Target), ":", "_")
	}
	if id == "" {
		server.FailBadRequest(w, "target 必填(或由 id 指定)")
		return
	}
	if in.Side != collect.SideHost && in.Side != collect.SideNet {
		server.FailBadRequest(w, "side 必须是 host 或 net")
		return
	}
	if !collect.ProtocolKnown(in.Protocol) {
		server.FailBadRequest(w, "未知协议: "+in.Protocol)
		return
	}
	if !collect.InScheduler(in.Protocol) {
		server.Fail(w, http.StatusBadRequest, server.CodeBadRequest,
			"agent 协议由探针中心管理(见探针节点管理区), 不在此处建采集任务")
		return
	}
	if strings.TrimSpace(in.Target) == "" {
		server.FailBadRequest(w, "target 不能为空")
		return
	}

	e := instanceCollect()
	cfg := e.Config()
	key := monitor.SecretKey()

	// 按 ID 找现有任务(合并: 留空的口令字段保持原值 —— 与 monitor 目标编辑同口径)
	idx := -1
	for i, t := range cfg.Tasks {
		if t.ID == id {
			idx = i
			break
		}
	}
	t := collect.Task{
		ID: id, Name: in.Name, Side: in.Side, Protocol: in.Protocol,
		Target: strings.TrimSpace(in.Target),
	}
	if idx >= 0 {
		t = cfg.Tasks[idx] // 以现有为基础合并
	}
	if in.Name != "" {
		t.Name = in.Name
	}
	t.Protocol = in.Protocol
	t.Side = in.Side
	t.Target = strings.TrimSpace(in.Target)
	if in.Enabled != nil {
		t.Enabled = *in.Enabled
	}
	if in.IntervalSec != nil {
		t.IntervalSec = *in.IntervalSec
	}
	if in.TimeoutMs != nil {
		t.TimeoutMs = *in.TimeoutMs
	}
	if in.Community != "" {
		t.Community = in.Community
	}
	if in.User != "" {
		t.User = in.User
	}
	if in.AuthProto != "" {
		t.AuthProto = in.AuthProto
	}
	if in.PrivProto != "" {
		t.PrivProto = in.PrivProto
	}
	if in.AuthPass != "" {
		t.AuthPass = monitor.EncryptSecret(key, in.AuthPass)
	}
	if in.PrivPass != "" {
		t.PrivPass = monitor.EncryptSecret(key, in.PrivPass)
	}
	if in.Params != nil {
		if t.Params == nil {
			t.Params = map[string]string{}
		}
		for k, v := range in.Params {
			t.Params[k] = v
		}
	}

	if idx >= 0 {
		cfg.Tasks[idx] = t
	} else {
		cfg.Tasks = append(cfg.Tasks, t)
	}
	if err := saveCollectConfig(cfg); err != nil {
		server.FailInternal(w, "配置保存失败: "+err.Error())
		return
	}
	e.SetConfig(cfg)
	logAudit(v2DB(), r, "node.task.upsert", t.ID, "protocol="+t.Protocol+" target="+t.Target)
	server.OK(w, map[string]any{"id": t.ID, "saved": true})
}

// hNodeDeleteTask DELETE /api/v2/node/tasks/{id}
func hNodeDeleteTask(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	e := instanceCollect()
	cfg := e.Config()
	found := false
	out := make([]collect.Task, 0, len(cfg.Tasks))
	for _, t := range cfg.Tasks {
		if t.ID == id {
			found = true
			continue
		}
		out = append(out, t)
	}
	if !found {
		server.Fail(w, http.StatusNotFound, server.CodeNotFound, "任务不存在: "+id)
		return
	}
	cfg.Tasks = out
	if err := saveCollectConfig(cfg); err != nil {
		server.FailInternal(w, "配置保存失败: "+err.Error())
		return
	}
	e.SetConfig(cfg)
	logAudit(v2DB(), r, "node.task.delete", id, "")
	server.OK(w, map[string]any{"id": id, "deleted": true})
}

// hNodeCollectNow POST /api/v2/node/collect {taskID?} —— 手动触发一轮。
func hNodeCollectNow(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TaskID string `json:"taskID"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	e := instanceCollect()
	cfg := e.Config()
	if !cfg.Enabled {
		server.Fail(w, http.StatusConflict, server.CodeConflict,
			"节点采集未启用(在节点监控页开启后手动采集)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 130*time.Second)
	defer cancel()

	var resp map[string]any
	if in.TaskID != "" {
		var t *collect.Task
		for i := range cfg.Tasks {
			if cfg.Tasks[i].ID == in.TaskID {
				t = &cfg.Tasks[i]
				break
			}
		}
		if t == nil {
			server.Fail(w, http.StatusNotFound, server.CodeNotFound, "任务不存在: "+in.TaskID)
			return
		}
		round := e.CollectNow(ctx, *t)
		resp = map[string]any{"task": in.TaskID, "round": round}
	} else {
		// 全部启用任务各跑一轮
		rounds := make([]any, 0)
		for _, t := range cfg.Tasks {
			if !t.Enabled {
				continue
			}
			rounds = append(rounds, e.CollectNow(ctx, t))
		}
		resp = map[string]any{"total": len(rounds), "rounds": rounds}
	}
	logAudit(v2DB(), r, "node.collect.now", in.TaskID, "")
	// 报告中心二期: "立即采集"完成 → 原始报告自动存档(与 SNMP 监控同口径:
	// 周期轮询不自动存档, 手动触发的采集轮才留档)
	if rr := buildRawCollectReport(currentUser()); rr != nil {
		autoSaveRawReport(v2DB(), rr)
	}
	server.OK(w, resp)
}

// hNodeMetrics GET /api/v2/node/metrics?task=&limit= —— 某任务历史时序。
func hNodeMetrics(w http.ResponseWriter, r *http.Request) {
	taskID := strings.TrimSpace(r.URL.Query().Get("task"))
	if taskID == "" {
		server.FailBadRequest(w, "task 必填")
		return
	}
	limit := 300
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	if limit > 5000 {
		limit = 5000
	}
	d := v2DB()
	if d == nil {
		server.OK(w, map[string]any{"task": taskID, "points": []any{}})
		return
	}
	dao := d.CollectSamples()
	if dao == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "采集时序表不可用")
		return
	}
	rows, err := dao.ByTaskTail(taskID, limit)
	if err != nil {
		server.FailInternal(w, "查询失败: "+err.Error())
		return
	}
	points := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		pts := make([]map[string]any, 0, len(row.Metrics))
		for _, m := range row.Metrics {
			p := map[string]any{"name": m.Name, "value": m.Value}
			if m.Unit != "" {
				p["unit"] = m.Unit
			}
			if m.Labels != nil {
				p["labels"] = m.Labels
			}
			pts = append(pts, p)
		}
		points = append(points, map[string]any{
			"at":  row.At.Format(time.RFC3339),
			"ok":  row.OK,
			"err": row.Err,
			"metrics": pts,
		})
	}
	server.OK(w, map[string]any{"task": taskID, "points": points, "count": len(points)})
}

// hNodeEvents GET /api/v2/node/events?limit= —— 异常事件列表。
func hNodeEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	if limit > 2000 {
		limit = 2000
	}
	d := v2DB()
	if d == nil {
		server.OK(w, map[string]any{"events": []any{}})
		return
	}
	dao := d.CollectEvents()
	if dao == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "事件表不可用")
		return
	}
	rows, err := dao.Tail(limit)
	if err != nil {
		server.FailInternal(w, "查询失败: "+err.Error())
		return
	}
	out := make([]any, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- { // 倒序(新事件在前)
		out = append(out, rows[i])
	}
	server.OK(w, map[string]any{"events": out, "count": len(out)})
}

// hNodeSaveConfig POST /api/v2/node/config —— 全局配置(开关/间隔/并发/限速/白名单/保留)。
func hNodeSaveConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled        *bool     `json:"enabled"`
		IntervalSec    *int      `json:"intervalSec"`
		Concurrent     *int      `json:"concurrent"`
		GlobalRate     *int      `json:"globalRate"`
		RetentionHours *int      `json:"retentionHours"`
		Whitelist      []string  `json:"whitelist"`
		NetFlow        *struct {
			Enabled bool   `json:"enabled"`
			Listen  string `json:"listen"`
		} `json:"netflow"`
		Alerts *struct {
			CPUPct     int `json:"cpuPct"`
			MemPct     int `json:"memPct"`
			RTTMs      int `json:"rttMs"`
			LossPct    int `json:"lossPct"`
			FailStreak int `json:"failStreak"`
		} `json:"alerts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		server.FailBadRequest(w, "请求格式错误: "+err.Error())
		return
	}
	e := instanceCollect()
	cfg := e.Config()
	if in.Enabled != nil {
		cfg.Enabled = *in.Enabled
	}
	if in.IntervalSec != nil && *in.IntervalSec >= 5 {
		cfg.IntervalSec = *in.IntervalSec
	}
	if in.Concurrent != nil && *in.Concurrent >= 1 {
		cfg.Concurrent = *in.Concurrent
	}
	if in.GlobalRate != nil && *in.GlobalRate >= 1 {
		cfg.GlobalRate = *in.GlobalRate
	}
	if in.RetentionHours != nil && *in.RetentionHours >= 1 {
		cfg.RetentionHours = *in.RetentionHours
	}
	if in.Whitelist != nil {
		cfg.Whitelist = in.Whitelist
	}
	if in.NetFlow != nil {
		cfg.NetFlow.Enabled = in.NetFlow.Enabled
		if in.NetFlow.Listen != "" {
			cfg.NetFlow.Listen = in.NetFlow.Listen
		}
	}
	if in.Alerts != nil {
		cfg.Alerts = collect.Alerts{
			CPUPct: in.Alerts.CPUPct, MemPct: in.Alerts.MemPct,
			RTTMs: in.Alerts.RTTMs, LossPct: in.Alerts.LossPct, FailStreak: in.Alerts.FailStreak,
		}
	}
	if err := saveCollectConfig(cfg); err != nil {
		server.FailInternal(w, "配置保存失败: "+err.Error())
		return
	}
	e.SetConfig(cfg)
	if cfg.Enabled {
		e.Start() // 幂等
	} else {
		e.Stop()
	}
	logAudit(v2DB(), r, "node.config", "", fmt.Sprintf("enabled=%v interval=%ds rate=%d/s", cfg.Enabled, cfg.IntervalSec, cfg.GlobalRate))
	server.OK(w, map[string]any{"saved": true, "enabled": cfg.Enabled})
}
