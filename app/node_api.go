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

	"yugsight/internal/collect"
	"yugsight/internal/db"
	"yugsight/internal/monitor"
	"yugsight/internal/server"
	"yugsight/internal/sse"
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
//
// 写盘后必须刷 settings 缓存(2026-09-28 E2E 实测): 采集引擎调度循环每 tick
// 经 readCfg() 重读 collect 节, 若不刷缓存, 循环会拿启动时的旧快照把
// SetConfig 刚更新的任务"冲回"原值 —— 表现是页面上改任务目标/启停,
// 约 1 秒后又变回改之前的值。与 saveNodePushCfg / persistAICfg 同一口径。
func saveCollectConfig(c collect.Config) error {
	if err := writeSection(secCollect, c); err != nil {
		return err
	}
	resetSettingsCache()
	return nil
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
	// 告警推送闭环(2026-09-28): 事件 → 告警落表 + 规则匹配 + Webhook 推送,
	// 详见 node_push.go 的 onNodeAlert(内部有 recover, 不会反噬采集循环)。
	onNodeAlert(ev)
	// 拓扑链路状态随之刷新(2026-09-29 阶段 B; 5s 节流, 见 topology_links_api.go)
	publishTopoLinks()
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
	// 每节点告警阈值覆盖(借鉴 Zabbix 全局宏/主机宏: 节点级优先, 0 值回落全局)
	srv.Get("/api/v2/node/alert/thresholds", requireAuth(hNodeThresholdsGet))
	srv.Put("/api/v2/node/alert/thresholds", requireAuth(adminOrOperator(hNodeThresholdsPut)))
	// 采集模板(2026-09-29 阶段 C, 借鉴 Zabbix 监控模板: 命名预设=协议+参数+默认阈值)
	srv.Get("/api/v2/node/templates", requireAuth(hNodeTemplatesGet))
	srv.Put("/api/v2/node/templates", requireAuth(adminOrOperator(hNodeTemplatesPut)))
	// 连通性测试(2026-09-30: 节点配置页从"前端纯模拟"改为真实探测, 见 connectivity_api.go)
	srv.Post("/api/v2/node/connectivity", requireAuth(adminOrOperator(hNodeConnectivity)))
	// 路由跟踪(2026-09-30: ping(ICMP)/端口(TCP) 两种, 见 connectivity_api.go hNodeTrace)
	srv.Post("/api/v2/node/trace", requireAuth(adminOrOperator(hNodeTrace)))
}

// ===== 采集模板(阶段 C, 借鉴 Zabbix 监控模板) =====
//
// 口径: 模板 = 命名预设(协议 + 参数 + 默认阈值 + 说明)。建任务时选模板,
// 任务一次性继承模板参数与阈值(阈值写入 PerNode, 之后仍可单独覆盖)。
// 整体替换语义(同 perNode/authcheck): PUT 请求体 = 完整模板列表。
// 上限 50(与白名单同口径, 防 settings.json 膨胀)。

const maxNodeTemplates = 50

// validateNodeTemplates 逐条硬校验(坏条目整体 400 不跳过: 静默丢模板会让
// "建任务选了模板却没继承"最难排查)。
func validateNodeTemplates(list []collect.Template) error {
	if len(list) > maxNodeTemplates {
		return fmt.Errorf("模板数量超限(最多 %d)", maxNodeTemplates)
	}
	seen := map[string]bool{}
	for _, t := range list {
		if err := t.Validate(); err != nil {
			return err
		}
		if seen[t.ID] {
			return fmt.Errorf("模板 ID 重复: %s", t.ID)
		}
		seen[t.ID] = true
		// 阈值字段复用每节点阈值的范围校验口径
		if t.Alerts.CPUPct < 0 || t.Alerts.CPUPct > 100 ||
			t.Alerts.MemPct < 0 || t.Alerts.MemPct > 100 ||
			t.Alerts.RTTMs < 0 || t.Alerts.RTTMs > 60000 ||
			t.Alerts.LossPct < 0 || t.Alerts.LossPct > 100 ||
			t.Alerts.FailStreak < 0 || t.Alerts.FailStreak > 100 {
			return fmt.Errorf("%s: 阈值字段超出范围", t.ID)
		}
	}
	return nil
}

// hNodeTemplatesGet GET /api/v2/node/templates
func hNodeTemplatesGet(w http.ResponseWriter, r *http.Request) {
	list := instanceCollect().Config().Templates
	if list == nil {
		list = []collect.Template{}
	}
	server.OK(w, map[string]any{"templates": list, "count": len(list)})
}

// hNodeTemplatesPut PUT /api/v2/node/templates body {templates:[...]}
// 整体替换; 删任务时不联动清模板(模板是预设, 与具体任务解耦)。
func hNodeTemplatesPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Templates []collect.Template `json:"templates"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Templates == nil {
		in.Templates = []collect.Template{}
	}
	if err := validateNodeTemplates(in.Templates); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	e := instanceCollect()
	cfg := e.Config()
	cfg.Templates = in.Templates
	if err := saveCollectConfig(cfg); err != nil {
		server.FailInternal(w, "配置保存失败: "+err.Error())
		return
	}
	e.SetConfig(cfg)
	logAudit(v2DB(), r, "node.templates.save", "", fmt.Sprintf("templates=%d 项", len(in.Templates)))
	server.OK(w, map[string]any{"saved": true, "count": len(in.Templates)})
}

// ===== 每节点告警阈值覆盖 =====
//
// 口径(2026-09-29, 借 Zabbix Trigger"每主机独立阈值"语义):
// 全局 alerts 是默认值, PerNode[taskID] 只存"与全局不同的字段",
// 0 值=未覆盖(回落全局)。整体替换语义(同 authcheck.config 先例):
// 请求体就是完整的 perNode 映射, 不传某任务 = 该任务回到全局阈值。

// validatePerNodeThresholds 逐字段硬校验(坏条目整体 400, 不跳过 ——
// 阈值是告警触发条件, 静默丢弃坏值会让"以为配了其实没配"最难排查)。
func validatePerNodeThresholds(m map[string]collect.Alerts) error {
	for id, a := range m {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("任务 ID 不能为空")
		}
		if a.CPUPct < 0 || a.CPUPct > 100 {
			return fmt.Errorf("%s: cpuPct 需在 0-100", id)
		}
		if a.MemPct < 0 || a.MemPct > 100 {
			return fmt.Errorf("%s: memPct 需在 0-100", id)
		}
		if a.RTTMs < 0 || a.RTTMs > 60000 {
			return fmt.Errorf("%s: rttMs 需在 0-60000", id)
		}
		if a.LossPct < 0 || a.LossPct > 100 {
			return fmt.Errorf("%s: lossPct 需在 0-100", id)
		}
		if a.FailStreak < 0 || a.FailStreak > 100 {
			return fmt.Errorf("%s: failStreak 需在 0-100", id)
		}
	}
	return nil
}

// hNodeThresholdsGet GET /api/v2/node/alert/thresholds
// {global: 全局阈值(含默认回填), perNode: 节点覆盖映射}
func hNodeThresholdsGet(w http.ResponseWriter, r *http.Request) {
	cfg := instanceCollect().Config()
	g := cfg.WithDefaults().Alerts
	per := cfg.PerNode
	if per == nil {
		per = map[string]collect.Alerts{}
	}
	server.OK(w, map[string]any{"global": g, "perNode": per})
}

// hNodeThresholdsPut PUT /api/v2/node/alert/thresholds body {perNode: {...}}
// 整体替换 perNode 映射; 空对象 = 全部回落全局阈值。
func hNodeThresholdsPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PerNode map[string]collect.Alerts `json:"perNode"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.PerNode == nil {
		in.PerNode = map[string]collect.Alerts{}
	}
	// 只保留任务实际存在的 key(删任务后前端残留 key 由此兜底清除, 与推送规则同口径)
	e := instanceCollect()
	exist := map[string]bool{}
	for _, t := range e.Config().Tasks {
		exist[t.ID] = true
	}
	out := make(map[string]collect.Alerts, len(in.PerNode))
	for id, a := range in.PerNode {
		if exist[id] {
			out[id] = a
		}
	}
	if err := validatePerNodeThresholds(out); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	cfg := e.Config()
	if len(out) == 0 {
		cfg.PerNode = nil // 空映射不落盘(避免 settings.json 里留 perNode:{} 噪音)
	} else {
		cfg.PerNode = out
	}
	if err := saveCollectConfig(cfg); err != nil {
		server.FailInternal(w, "配置保存失败: "+err.Error())
		return
	}
	e.SetConfig(cfg) // 下一轮采集即生效, 无需重启
	logAudit(v2DB(), r, "node.thresholds.save", "", fmt.Sprintf("perNode=%d 项", len(out)))
	server.OK(w, map[string]any{"saved": true, "perNode": out})
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
		"perNode":         cfg.PerNode,
		"templates":       cfg.Templates,
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
		// TemplateID 采集模板(2026-09-29 阶段 C): 新建任务时指定 → 继承模板
		// 参数预设与默认阈值(写入 PerNode, 之后仍可在"每节点阈值"覆盖)。
		TemplateID string `json:"templateId"`
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

	// 模板继承(2026-09-29 阶段 C): 仅新建任务生效(编辑时模板无意义 ——
	// 任务已有自己的参数/阈值)。继承 = 模板参数补空 + 阈值写入 PerNode。
	// 阈值是一次性继承起点: 之后改模板不影响已建任务(行为可追溯, 见 Template 注释)。
	templID := strings.TrimSpace(in.TemplateID)
	if idx < 0 && templID != "" {
		if tpl := findTemplate(cfg, templID); tpl != nil {
			if t.Params == nil {
				t.Params = map[string]string{}
			}
			for k, v := range tpl.Params {
				if t.Params[k] == "" {
					t.Params[k] = v
				}
			}
			if cfg.PerNode == nil {
				cfg.PerNode = map[string]collect.Alerts{}
			}
			if _, ok := cfg.PerNode[t.ID]; !ok {
				cfg.PerNode[t.ID] = tpl.Alerts
			}
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
	server.OK(w, map[string]any{"id": t.ID, "saved": true, "fromTemplate": idx < 0 && templID != ""})
}

// findTemplate 按 ID 找采集模板(nil = 未找到; 调用方静默忽略, 模板可能已被删)。
func findTemplate(cfg collect.Config, id string) *collect.Template {
	for i := range cfg.Templates {
		if cfg.Templates[i].ID == id {
			return &cfg.Templates[i]
		}
	}
	return nil
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
	// 任务删除 → 清掉它的每节点阈值残留(否则 settings.json 里留孤儿 key,
	// 前端"每节点阈值"表又看不到对应任务行)
	if cfg.PerNode != nil {
		if _, ok := cfg.PerNode[id]; ok {
			delete(cfg.PerNode, id)
			if len(cfg.PerNode) == 0 {
				cfg.PerNode = nil
			}
		}
	}
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
	// 2026-10-02 用户口径: 节点采集同属节点监控, 不生成原始报告(报告中心被刷屏;
	// 用户: "这些不需要生成原始报告, 最多是信息做为日志记录一下") → 只记摘要日志,
	// node.collect.now 审计记录照旧。
	collectDesc := "全部启用任务"
	if in.TaskID != "" {
		collectDesc = "任务 " + in.TaskID
	}
	logLine(fmt.Sprintf("节点采集完成: %s(不存报告中心, 仅日志记录)", collectDesc))
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
