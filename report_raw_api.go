package main

// report_raw_api.go 报告中心二期: 原始结构化报告的存储与合并底座(装配层)。
//
// 与 report_api.go(渲染报告引擎)的分工:
//
//	report_api.go    = 从数据库聚合渲染 HTML/Word/PDF 的"报告引擎"(任务 7.2);
//	report_raw_api.go = 四大业务模块执行完成后自动落库的"原始报告"(本阶段):
//	                   实时抓包 / 扫描作业 / 弱口令检测 / 节点监控。
//
// 数据流(底座定位, 本阶段不开发 AI 模块):
//
//	业务模块执行完成 → RawReport(原始结构化数据, 自包含)
//	                  → 报告中心: 查看 / 多选合并 / 标签 / 来源 / 时间 / 资产筛选
//	                  → [三期 AI 模块读取原始报告分析, 结果写回 AIData 预留字段]
//
// 落库时机(每个模块的"执行完成"定义):
//   - 抓包   = 用户点"停止抓包"(或抓包进程异常退出, 会话同样结束);
//   - 扫描   = 本地扫描管线收尾(runScanPipeline, 含引擎编排路径)
//              + 探针回传落库完成(onProbeResultIngest);
//   - 弱口令 = 批量探测批次结束(run.finish);
//   - 节点监控 = 连续采样过程, 周期性轮询不做自动存档(60s 一轮会刷屏),
//              只在"立即采集一轮"完成时自动存档 + 提供"存快照到报告中心"按钮。
//
// 所有自动存档都是 best-effort: 构建快照在内存里同步完成(数据是易失的),
// 写库异步 + recover, 失败只记日志 —— 报告中心故障绝不影响业务主流程(规则 4)。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"yugsight/collect"
	"yugsight/db"
	"yugsight/normalizer"
	"yugsight/probe"
	"yugsight/report"
	"yugsight/server"
)

// ===== 自动存档总控 =====

// rawAutoSaveEnabled 业务模块执行完成后是否自动存入报告中心。
//
// 默认开启: 二期核心需求就是"执行完成后自动保存", 且原始报告是只读聚合
// (不改变任何执行链路), 与报告引擎"用户明确要求默认开"同口径;
// settings.json 的 report.autoSave=false 可显式关闭。
func rawAutoSaveEnabled() bool {
	cfg := loadReportConfig()
	if !cfg.Enabled {
		return false
	}
	return cfg.AutoSave == nil || *cfg.AutoSave
}

// saveRawReportDAO 原始报告的落库核心(校验 + upsert + 超限按时间淘汰最旧)。
//
// 超限淘汰与报告存档同口径(FIFO by CreatedAt): JSONL 引擎整文件重写,
// 不设上限的话每次写入的 IO 都会随存量线性增长。
// 只依赖 DAO(内部自持锁), 不依赖 Database 门面 —— 异步 goroutine 持有它
// 就安全(见 autoSaveRawReport 的竞态说明)。
// 只依赖 DAO(内部自持锁), 不依赖 Database 门面 —— 异步 goroutine 持有它
// 就安全(见 autoSaveRawReport 的竞态说明)。
func saveRawReportDAO(dao *db.RawReportDAO, rr *report.RawReport) error {
	if dao == nil {
		return fmt.Errorf("原始报告存储不可用")
	}
	if rr == nil {
		return fmt.Errorf("原始报告为空")
	}
	if err := rr.Validate(); err != nil {
		return err
	}
	if len(rr.Payload) == 0 {
		return fmt.Errorf("原始报告正文为空")
	}
	if _, err := dao.Upsert(rr); err != nil {
		return err
	}
	cfg := loadReportConfig()
	if cfg.MaxRaw <= 0 {
		return nil
	}
	list, err := dao.List()
	if err != nil || len(list) <= cfg.MaxRaw {
		return nil
	}
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})
	for i := 0; i < len(list)-cfg.MaxRaw; i++ {
		if list[i] == nil {
			continue
		}
		_, _ = dao.Delete(list[i].ID)
	}
	return nil
}

// saveRawReport 同步存一份原始报告(API 接口用: 合并/快照, 需把结果同步回给用户)。
func saveRawReport(d *db.Database, rr *report.RawReport) error {
	if d == nil || d.RawReports() == nil {
		return fmt.Errorf("原始报告存储不可用")
	}
	return saveRawReportDAO(d.RawReports(), rr)
}

// rawSaveWG 待完成的自动存档 goroutine 计数。
// 用途: 测试收尾前排空 —— 异步写入若拖到测试 TempDir 清理之后才落盘,
// Windows 下 RemoveAll 会因"目录非空"失败(文件正被写入/创建)。
var rawSaveWG sync.WaitGroup

// autoSaveRawReport 业务模块收尾时的自动存档入口(异步写 + recover 兜底)。
//
// rr 必须已由调用方在内存里构建完(易失数据同步抓取), 这里只负责落库。
// 开关关闭 / 正文为空 / 存储不可用时直接跳过(返回前同步判断, 不启 goroutine)。
//
// 【竞态防护】goroutine 只持有同步快照的 DAO 指针, 不持有 Database 门面:
// db.Close() 会把 Database 的 DAO 字段无锁置 nil, 若迟到的异步写入再经
// d.RawReports() 读这些字段, 与 Close 构成数据竞争(测试 -race 实测命中)。
// DAO(*Table) 自身方法带内部锁, 且 Close 不触碰其内部状态, 持有它就安全。
func autoSaveRawReport(d *db.Database, rr *report.RawReport) {
	if rr == nil || len(rr.Payload) == 0 {
		return
	}
	if !rawAutoSaveEnabled() {
		return
	}
	if d == nil || d.RawReports() == nil {
		return // 存储不可用(未注入/已关闭): 静默跳过, 与"best-effort"口径一致
	}
	dao := d.RawReports() // 同步快照, goroutine 不再读 Database 字段
	rawSaveWG.Add(1)
	go func() {
		defer rawSaveWG.Done()
		defer func() {
			if p := recover(); p != nil {
				reportLogLine(fmt.Sprintf("原始报告自动存档异常(已恢复): %v", p))
			}
		}()
		if err := saveRawReportDAO(dao, rr); err != nil {
			reportLogLine("原始报告自动存档失败: " + err.Error())
		}
	}()
}

// waitRawSaves 排空所有待完成的自动存档(测试收尾用; 生产路径不调用)。
func waitRawSaves() { rawSaveWG.Wait() }

// ===== 各模块的原始报告构建(快照在内存同步完成) =====

// buildRawCaptureReport 实时抓包 → 原始报告。
//
// 数据源: 会话参数 + 统计 + 环形缓冲内全部报文(上限 2000 条, 缓冲即上限,
// 超出的早已被挤出 —— 报告存的是"缓冲里还活着的", 与页面看到的口径一致)。
func buildRawCaptureReport() *report.RawReport {
	meta := capSessMetaSnapshot()
	pkts := capSess.Packets()
	if pkts == nil || pkts.Len() == 0 {
		return nil // 零报文会话不值得留档(避免一堆空报告刷屏)
	}
	records := pkts.Since(0, 0)
	if len(records) == 0 {
		return nil
	}
	var durMs int64
	if !meta.StartedAt.IsZero() {
		durMs = time.Since(meta.StartedAt).Milliseconds()
	}
	payload := map[string]any{
		"device":        meta.Device,
		"filter":        meta.Filter,
		"displayFilter": meta.DisplayFilter,
		"captureAll":    meta.CaptureAll,
		"startedAt":     meta.StartedAt,
		"stoppedAt":     time.Now(),
		"stats":         capSess.Stats(),
		"events":        capSess.EventsSince(0),
		"packets":       records,
	}
	return &report.RawReport{
		Module:     report.RawModCapture,
		Title:      fmt.Sprintf("抓包报告 %s (%s)", meta.Device, time.Now().Format("2006-01-02 15:04")),
		Source:     "local",
		CreatedAt:  time.Now(),
		Tags:       []string{"抓包"},
		DurationMs: durMs,
		Summary:    fmt.Sprintf("%d 个报文, 网卡 %s", len(records), meta.Device),
		Stats:      report.RawStats{Items: len(records)},
		Payload:    rawJSON(payload),
	}
}

// buildRawScanReport 本地扫描作业 → 原始报告(运行在 runScanPipeline 收尾)。
//
// 口径: 与落库完全一致 —— findings 已过白名单/误报过滤, 是"这次扫描真实产出"。
func buildRawScanReport(req scanReq, sink *scanSink, startedAt time.Time) *report.RawReport {
	if sink == nil {
		return nil
	}
	pl := sink.rawPayload()
	findings, _ := pl["findings"].([]scanFindingJSON)
	assets, _ := pl["assets"].([]normalizer.RawAsset)
	alive, _ := pl["alive"].(map[string]aliveRecord)

	// 资产 IP 汇总(finding 的 host + 资产表 + 存活判定)
	ipSet := map[string]bool{}
	var ips []string
	addIP := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" || ipSet[ip] {
			return
		}
		ipSet[ip] = true
		ips = append(ips, ip)
	}
	for _, f := range findings {
		addIP(f.Host)
	}
	for _, a := range assets {
		addIP(a.IP)
	}
	for ip := range alive {
		addIP(ip)
	}

	target := scanTargetOf(req)
	var engine string
	if req.UseEngine {
		engine = "engine"
	}
	payload := map[string]any{
		"scan": map[string]any{
			"type":      req.Type,
			"target":    target,
			"ports":     req.Ports,
			"url":       req.URL,
			"aliveMode": req.AliveMode,
			"engine":    engine,
			"webDeep":   req.WebDeep,
		},
		"elapsedMs": time.Since(startedAt).Milliseconds(),
		"findings":  findings,
		"assets":    assets,
		"alive":     alive,
		"ports":     pl["ports"],
	}
	nVuln, nAsset := len(findings), len(assets)
	return &report.RawReport{
		Module:     report.RawModScan,
		Title:      fmt.Sprintf("%s扫描报告 %s", scanTypeLabel(req.Type), target),
		Source:     engineOrLocal(engine),
		Operator:   currentUser(),
		CreatedAt:  time.Now(),
		Tags:       []string{"扫描", scanTypeLabel(req.Type)},
		Target:     target,
		Assets:     ips,
		DurationMs: time.Since(startedAt).Milliseconds(),
		Summary:    fmt.Sprintf("%d 个漏洞 / %d 个资产 / %d 台存活", nVuln, nAsset, len(alive)),
		Stats: report.RawStats{
			Items: nVuln,
			Extra: map[string]int{"assets": nAsset, "alive": len(alive)},
		},
		Payload: rawJSON(payload),
	}
}

// scanTargetOf 扫描目标的标准展示形态(与 SSE 首帧/任务表同口径)。
func scanTargetOf(req scanReq) string {
	switch req.Type {
	case "web":
		if req.URL != "" {
			return req.URL
		}
		return req.IP
	case "port", "host", "unified":
		if req.CIDR != "" {
			return req.CIDR
		}
		return req.IP
	default:
		if req.CIDR != "" {
			return req.CIDR
		}
		return req.IP
	}
}

func scanTypeLabel(t string) string {
	switch t {
	case "ip", "alive":
		return "存活"
	case "port":
		return "端口"
	case "web":
		return "Web"
	case "host":
		return "主机"
	case "unified":
		return "综合"
	}
	return t
}

func engineOrLocal(engine string) string {
	if engine == "" {
		return "local"
	}
	return engine
}

// buildRawWeakpassReport 弱口令批量探测 → 原始报告(运行在批次 finish 后)。
//
// 结果里含命中的弱口令明文: 与弱口令页结果表同口径(该页本来就展示命中口令),
// 接口整体在 requireAuth 之后, 报告中心内网部署场景可接受。
func buildRawWeakpassReport(run *authCheckRun) *report.RawReport {
	if run == nil {
		return nil
	}
	snap := run.snapshot()
	if len(snap.Results) == 0 {
		return nil // 零结果批次不留档
	}
	// 资产 IP: 结果目标 host 部分
	ipSet := map[string]bool{}
	var ips []string
	for _, r := range snap.Results {
		ip := hostPartOf(r.Host)
		if ip != "" && !ipSet[ip] {
			ipSet[ip] = true
			ips = append(ips, ip)
		}
	}
	found := 0
	for _, r := range snap.Results {
		if r.OK {
			found++
		}
	}
	payload := map[string]any{
		"batch":   map[string]any{"id": snap.ID, "startedAt": snap.StartedAt, "finished": snap.Finished, "stopped": snap.Stopped},
		"summary": snap.Summary,
		"results": snap.Results,
		"audit":   snap.Audit,
	}
	return &report.RawReport{
		Module:    report.RawModWeakPass,
		Title:     fmt.Sprintf("弱口令报告 %s", time.Now().Format("2006-01-02 15:04")),
		Source:    "local",
		Operator:  currentUser(),
		CreatedAt: time.Now(),
		Tags:      []string{"弱口令"},
		Assets:    ips,
		Summary:   fmt.Sprintf("%d 个目标, %d 个命中", len(snap.Results), found),
		Stats: report.RawStats{
			Items: len(snap.Results),
			Extra: map[string]int{"found": found},
		},
		Payload: rawJSON(payload),
	}
}

// buildRawMonitorReport 节点监控(SNMP) → 原始报告。
//
// 存的是"当前最新一轮的完整快照": 目标配置(口令字段剥离, 与 API 回显同口径)
// + 每目标最新样本(含 ifTable 接口明细) + 上一轮汇总。
func buildRawMonitorReport(operator string) *report.RawReport {
	m := instanceMonitor()
	if m == nil {
		return nil
	}
	cfg := m.Config()
	latest := m.Latest()
	if len(cfg.Targets) == 0 && len(latest) == 0 {
		return nil // 无目标且无样本, 无内容可存
	}
	targets := make([]map[string]any, 0, len(cfg.Targets))
	assets := map[string]bool{}
	var ips []string
	okCount := 0
	for _, t := range cfg.Targets {
		ip := hostPartOf(t.Addr)
		if ip != "" && !assets[ip] {
			assets[ip] = true
			ips = append(ips, ip)
		}
		v := map[string]any{
			"id": t.ID, "name": t.Name, "addr": t.Addr, "version": t.Version(),
		}
		if s := latest[t.ID]; s != nil {
			v["sample"] = s
			if s.OK {
				okCount++
			}
		}
		targets = append(targets, v)
	}
	last := m.LastRound()
	payload := map[string]any{
		"intervalSec": cfg.IntervalSec,
		"running":     m.Running(),
		"lastRound":   last,
		"targets":     targets,
	}
	n := len(cfg.Targets)
	return &report.RawReport{
		Module:    report.RawModMonitor,
		Title:     fmt.Sprintf("节点监控快照 %s", time.Now().Format("2006-01-02 15:04")),
		Source:    "monitor",
		Operator:  operator,
		CreatedAt: time.Now(),
		Tags:      []string{"节点监控"},
		Assets:    ips,
		Summary:   fmt.Sprintf("%d 个监控目标, %d 个在线", n, okCount),
		Stats: report.RawStats{
			Items: n,
			Extra: map[string]int{"online": okCount},
		},
		Payload: rawJSON(payload),
	}
}

// buildRawCollectReport 节点采集(主机/网络设备信息采集) → 原始报告。
//
// 存的是"当前最新一轮的完整快照": 任务配置(口令剥离) + 每任务最新轮次
// (指标/服务/中间件/数据库明细) + 最近异常事件(从 db 读, 上限 200 条)。
func buildRawCollectReport(operator string) *report.RawReport {
	e := instanceCollect()
	if e == nil {
		return nil
	}
	cfg := e.Config()
	latest := e.Store().Latest()
	if len(cfg.Tasks) == 0 && len(latest) == 0 {
		return nil
	}
	tasks := make([]map[string]any, 0, len(cfg.Tasks))
	rounds := make([]any, 0, len(latest))
	assets := map[string]bool{}
	var ips []string
	okCount := 0
	for _, t := range cfg.Tasks {
		ip := hostPartOf(t.Target)
		if ip != "" && !assets[ip] {
			assets[ip] = true
			ips = append(ips, ip)
		}
		v := map[string]any{
			"id": t.ID, "name": t.Name, "side": t.Side,
			"protocol": t.Protocol, "target": t.Target, "enabled": t.Enabled,
		}
		if r := latest[t.ID]; r != nil {
			v["lastRound"] = r
			if r.OK {
				okCount++
			}
		}
		tasks = append(tasks, v)
	}
	for _, r := range latest {
		rounds = append(rounds, r)
	}
	sort.SliceStable(rounds, func(i, j int) bool {
		ri, _ := rounds[i].(*collect.Round)
		rj, _ := rounds[j].(*collect.Round)
		return ri != nil && rj != nil && ri.At.Before(rj.At)
	})
	// 最近异常事件(db; 全任务聚合取最近 200 条, 时间升序)
	var events []any
	if d := v2DB(); d != nil && d.CollectEvents() != nil {
		if evs, err := d.CollectEvents().Tail(200); err == nil {
			for _, ev := range evs {
				events = append(events, ev)
			}
		}
	}
	payload := map[string]any{
		"intervalSec": cfg.IntervalSec,
		"running":     e.Running(),
		"tasks":       tasks,
		"rounds":      rounds,
		"events":      events,
	}
	n := len(cfg.Tasks)
	return &report.RawReport{
		Module:    report.RawModMonitor,
		Title:     fmt.Sprintf("节点采集快照 %s", time.Now().Format("2006-01-02 15:04")),
		Source:    "collect",
		Operator:  operator,
		CreatedAt: time.Now(),
		Tags:      []string{"节点监控", "节点采集"},
		Assets:    ips,
		Summary:   fmt.Sprintf("%d 个采集任务, %d 个本轮成功", n, okCount),
		Stats: report.RawStats{
			Items: n,
			Extra: map[string]int{"ok": okCount},
		},
		Payload: rawJSON(payload),
	}
}

// buildRawProbeScanReport 探针回传扫描结果 → 原始报告(运行在 onProbeResultIngest 收尾)。
//
// 存的是探针回传的原始 Report 结构(中心端落库用的同一份数据), 来源标记
// probe:<nodeId> 区分于本地扫描。
func buildRawProbeScanReport(probeID string, res *probe.TaskResult, stat *probeIngestStat) *report.RawReport {
	if res == nil || stat == nil {
		return nil
	}
	rep, ok := extractProbeReport(res)
	if !ok {
		return nil // 该任务无结构化报告(非扫描类任务), 不落原始报告
	}
	pl, err := json.Marshal(rep)
	if err != nil {
		return nil
	}
	if len(pl) > report.RawPayloadMaxSize {
		return nil // 超限不存(防单行膨胀)
	}
	// 资产 IP 从回传 Report 里抽
	var ips []string
	seen := map[string]bool{}
	for _, a := range rep.Assets {
		ip := hostPartOf(a.IP)
		if ip != "" && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return &report.RawReport{
		Module:    report.RawModScan,
		Title:     fmt.Sprintf("探针扫描报告(%s) %s", probeID, time.Now().Format("2006-01-02 15:04")),
		Source:    "probe:" + probeID,
		Operator:  currentUser(),
		CreatedAt: time.Now(),
		Tags:      []string{"扫描", "探针"},
		Assets:    ips,
		Summary:   fmt.Sprintf("%d 条漏洞 / %d 个资产(探针 %s)", stat.Vulns, stat.Assets, probeID),
		Stats: report.RawStats{
			Items: stat.Vulns,
			Extra: map[string]int{"assets": stat.Assets, "newVulns": stat.NewVulns},
		},
		Payload: json.RawMessage(pl),
	}
}

// ===== 工具 =====

// rawJSON 序列化(构建器输入都是可序列化结构, 失败返回空对象不阻断)。
// 命名避开 probe_api.go 已有的 mustJSON(签名不同: 那边返回 []byte)。
func rawJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

// hostPartOf 取 host:port 形态字符串的 host 部分(纯 IP 原样返回)。
func hostPartOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i+1:], ":") {
		return s[:i]
	}
	return s
}

// ===== 报告中心 API(原始报告) =====
//
// 路由挂在 /api/v2/raw/ 下(前缀原因见 registerRawReportRoutes 注释):
//
//	GET    /list      列表(轻量: 无 payload), 支持 module/tag/asset/from/to/keyword 筛选
//	GET    /{id}      详情(含完整 payload)
//	DELETE /{id}      删除(adminOrOperator)
//	POST   /merge     多选合并 → 新的合并报告
//	POST   /snapshot  手动存快照(monitor/collect 两类连续模块)
//	GET    /options   筛选选项(模块计数/标签/资产/时间范围)

// hRawList GET /api/v2/raw/list
func hRawList(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil || d.RawReports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告中心未启用")
		return
	}
	q := r.URL.Query()
	page, size := parsePage(q)
	module := strings.TrimSpace(q.Get("module"))
	tag := strings.TrimSpace(q.Get("tag"))
	asset := strings.ToLower(strings.TrimSpace(q.Get("asset")))
	keyword := strings.ToLower(strings.TrimSpace(q.Get("keyword")))
	var from, to time.Time
	if s := q.Get("from"); s != "" {
		from, _ = time.ParseInLocation("2006-01-02", s, time.Local)
	}
	if s := q.Get("to"); s != "" {
		t, err := time.ParseInLocation("2006-01-02", s, time.Local)
		if err == nil {
			to = t.Add(24*time.Hour - time.Nanosecond) // 含当天
		}
	}

	list, err := d.RawReports().List()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	var out []any
	for _, rr := range list {
		if rr == nil {
			continue
		}
		if module != "" && rr.Module != module {
			continue
		}
		if tag != "" && !containsStr(rr.Tags, tag) {
			continue
		}
		if asset != "" && !containsStrFold(rr.Assets, asset) {
			continue
		}
		if keyword != "" {
			hay := strings.ToLower(rr.Title + " " + rr.Summary + " " + rr.Source)
			if !strings.Contains(hay, keyword) {
				continue
			}
		}
		if !from.IsZero() && rr.CreatedAt.Before(from) {
			continue
		}
		if !to.IsZero() && rr.CreatedAt.After(to) {
			continue
		}
		out = append(out, d.RawReports().ReleasePayload(rr))
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := out[i].(*report.RawReport)
		b, _ := out[j].(*report.RawReport)
		return a != nil && b != nil && a.CreatedAt.After(b.CreatedAt) // 时间倒序
	})
	server.OK(w, map[string]any{
		"list":  paginate(out, page, size),
		"total": len(out), "page": page, "size": size,
	})
}

// hRawGet GET /api/v2/raw/{id} —— 详情(含完整 payload)。
func hRawGet(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil || d.RawReports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告中心未启用")
		return
	}
	rr, err := d.RawReports().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "原始报告不存在")
		return
	}
	server.OK(w, rr)
}

// hRawDelete DELETE /api/v2/raw/{id}
func hRawDelete(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil || d.RawReports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告中心未启用")
		return
	}
	id := r.PathValue("id")
	if ok, err := d.RawReports().Delete(id); err != nil || !ok {
		server.FailInternal(w, "删除失败")
		return
	}
	logAudit(d, r, "rawreport.delete", id, "")
	server.OK(w, map[string]any{"deleted": id})
}

// hRawMerge POST /api/v2/raw/merge —— 多选合并为一份汇总报告。
//
// 合并口径见 report.MergeRawReports: 按模块分组 + 原文照搬 + 资产/标签并集 +
// SourceIDs 可下钻。合并本身不删源报告(源报告独立保留, 可单独查看/删除)。
func hRawMerge(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil || d.RawReports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告中心未启用")
		return
	}
	var in struct {
		IDs   []string `json:"ids"`
		Title string   `json:"title"`
		Tags  []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.IDs) < 2 {
		server.FailBadRequest(w, "至少选择 2 份原始报告进行合并")
		return
	}
	reports := make([]*report.RawReport, 0, len(in.IDs))
	for _, id := range in.IDs {
		rr, err := d.RawReports().Get(id)
		if err != nil {
			server.FailNotFound(w, "原始报告不存在: "+id)
			return
		}
		reports = append(reports, rr)
	}
	merged, err := report.MergeRawReports(reports, in.Title, in.Tags, currentUser())
	if err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	if err := saveRawReport(d, merged); err != nil {
		server.FailInternal(w, "合并报告保存失败: "+err.Error())
		return
	}
	logAudit(d, r, "rawreport.merge", merged.ID, fmt.Sprintf("sources=%d", len(reports)))
	server.OK(w, map[string]any{"id": merged.ID, "report": d.RawReports().ReleasePayload(merged)})
}

// hRawSnapshot POST /api/v2/raw/snapshot —— 手动存快照。
//
// 服务连续采样类模块: 周期性轮询不自动存档(60s 一轮会刷屏), 用户按需
// 在节点监控页点"存快照到报告中心"。module 只接受 monitor(SNMP 监控) /
// collect(节点采集) 两类 —— 其余模块的原始报告由各自的执行完成钩子产出,
// 不开放客户端直接投递(防伪造"扫描报告"进入报告中心)。
func hRawSnapshot(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil || d.RawReports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告中心未启用")
		return
	}
	var in struct {
		Module string `json:"module"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	in.Module = strings.TrimSpace(in.Module)
	var rr *report.RawReport
	switch in.Module {
	case report.RawModMonitor:
		rr = buildRawMonitorReport(currentUser())
	case "collect":
		rr = buildRawCollectReport(currentUser())
	default:
		server.FailBadRequest(w, "快照仅支持 monitor / collect 两类连续采样模块")
		return
	}
	if rr == nil {
		server.Fail(w, http.StatusConflict, server.CodeConflict, "当前无可保存的快照(未配置目标或尚无采集数据)")
		return
	}
	if err := saveRawReport(d, rr); err != nil {
		server.FailInternal(w, "快照保存失败: "+err.Error())
		return
	}
	logAudit(d, r, "rawreport.snapshot", rr.ID, in.Module)
	server.OK(w, map[string]any{"id": rr.ID, "report": d.RawReports().ReleasePayload(rr)})
}

// hRawOptions GET /api/v2/raw/options —— 筛选选项与模块计数。
func hRawOptions(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil || d.RawReports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告中心未启用")
		return
	}
	list, err := d.RawReports().List()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	modCount := map[string]int{}
	tagSet := map[string]bool{}
	assetSet := map[string]bool{}
	var oldest, newest time.Time
	for _, rr := range list {
		if rr == nil {
			continue
		}
		modCount[rr.Module]++
		for _, t := range rr.Tags {
			tagSet[t] = true
		}
		for _, a := range rr.Assets {
			assetSet[a] = true
		}
		if oldest.IsZero() || rr.CreatedAt.Before(oldest) {
			oldest = rr.CreatedAt
		}
		if rr.CreatedAt.After(newest) {
			newest = rr.CreatedAt
		}
	}
	modules := make([]map[string]any, 0, len(report.RawModules))
	for _, m := range report.RawModules {
		modules = append(modules, map[string]any{"id": m, "label": report.RawModuleLabel(m), "count": modCount[m]})
	}
	server.OK(w, map[string]any{
		"modules": modules,
		"tags":    setToSorted(tagSet),
		"assets":  setToSorted(assetSet),
		"dateRange": map[string]any{
			"from": fmtT(oldest),
			"to":   fmtT(newest),
		},
		"total": len(list),
	})
}

// ===== 工具函数(报告中心原始报告专用) =====

// containsStr 大小写敏感包含(标签/资产本身是精确值)。
func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// containsStrFold 大小写不敏感的子串匹配(资产 IP 输入容错: 允许输段前缀)。
func containsStrFold(list []string, sub string) bool {
	if sub == "" {
		return true
	}
	for _, x := range list {
		if strings.Contains(strings.ToLower(x), sub) {
			return true
		}
	}
	return false
}

func setToSorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fmtT(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

// registerRawReportRoutes 注册原始报告 API(报告中心二期)。
// 调用点在 registerReportRoutes 内 —— 与渲染报告同族, 统一在报告中心入口挂载。
//
// 前缀用 /api/v2/raw/ 而不是 /api/v2/report/raw/: Go 1.22 ServeMux 下
// "report/raw/{id}" 与既有的 "report/{id}/download" 无法区分(路径
// /api/v2/report/raw/download 两条都能匹配, 互不更具体 → 注册即 panic),
// 而 report/{id} 族是 7.2 的既有对外契约, 不能动 —— 只能换前缀。
func registerRawReportRoutes(srv *server.Server) {
	raw := func(h http.HandlerFunc) http.HandlerFunc {
		return requireAuth(adminOrOperator(h))
	}
	srv.Get("/api/v2/raw/list", raw(hRawList))
	srv.Get("/api/v2/raw/options", raw(hRawOptions))
	srv.Get("/api/v2/raw/{id}", raw(hRawGet))
	srv.Delete("/api/v2/raw/{id}", raw(hRawDelete))
	srv.Post("/api/v2/raw/merge", raw(hRawMerge))
	srv.Post("/api/v2/raw/snapshot", raw(hRawSnapshot))
}
