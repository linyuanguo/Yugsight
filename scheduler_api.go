package main

// ===== 任务 7.1 装配层: 把 scheduler 包接到真实执行能力上 =====
//
// 位置: 本文件是 main 包与 scheduler 包的唯一连接点(与 probe_api.go /
// engine_api.go 同一角色)。scheduler 包自身只依赖标准库, 因此:
//   - 调度逻辑(排队/并发/限速/状态机)可脱离网络与数据库单测;
//   - 真实执行通过 ExecFunc 在此注入(本地扫描 / 探针下发)。
//
// 默认启用(2026-09-20 起, 用户要求开箱即用): 排队提交(queue=true)直接可用,
// 普通 /api/scan 的即时执行 + SSE 流语义不变。显式 enabled=false 时全部 API
// 仍可访问(便于前端展示"未启用"), 且 /api/scan 不会被接管 —— 走原有即时
// 执行路径, 零行为变化。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/db"
	"yugsight/probe"
	"yugsight/scheduler"
	"yugsight/server"
	"yugsight/sse"
)

// schedOnce 用指针而非值: 测试需要重置单例(sync.Once 含 noCopy, 值类型
// 赋值会被 go vet 判为复制锁)。指针让测试可以整体替换而不触碰原对象。
var (
	schedOnce   = &sync.Once{}
	schedInst   *scheduler.Scheduler
	schedCfgVal scheduler.Config
)

// schedConfigPath scheduler.json 路径(exe 同目录, 与其它配置同惯例)。
//
// 声明为变量而非函数: 测试需要把它改指临时目录, 否则用例一跑就会覆盖开发机上
// 真实的调度配置(这是"测试污染现场"类问题的典型来源)。
//
// 【统一配置后仍有存在意义】settings.json 里的 scheduler 节优先; 该节缺失时
// 回退读这个路径指向的旧 scheduler.json。保存配置(saveSchedulerConfig)也仍写
// 这里 —— 程序自动保存用户在前端改的配置时不该去重写用户手写的 settings.json
// (会连带覆盖用户写在里面的注释与其它节)。
var schedConfigPath = func() string {
	exe, err := os.Executable()
	if err != nil {
		return "scheduler.json"
	}
	return filepath.Join(filepath.Dir(exe), "scheduler.json")
}

// loadSchedulerConfig 读取调度配置(settings.json 的 scheduler 节优先, 回退 scheduler.json)。
//
// 复用 scheduler 包既有的 SetConfigPath/SetConfigReader 注入点, 因此 **scheduler
// 包一行都不用改** —— 配置来源的变化被完全挡在装配层。这正是当初把路径做成
// 可注入函数的收益。
func loadSchedulerConfig() scheduler.Config {
	scheduler.SetLogger(schedLogLine)
	// 配置读取: 先看 settings.json 的 scheduler 节, 没有再回退旧文件。
	// 用 SetConfigReader 而非直接把 settings 内容塞进临时文件: 后者会引入
	// 文件 IO 竞态与清理负担, 且用户改 settings.json 后无需重启即可生效。
	scheduler.SetConfigReader(func() ([]byte, bool) {
		return section(secScheduler, "")
	})
	scheduler.SetConfigPath(schedConfigPath)
	cfg := scheduler.LoadConfig()
	return cfg
}

// schedLogLine 调度器日志并入 yugsight.log(与 probeLogLine / engineLogLine 同格式)。
func schedLogLine(msg string) {
	logLine("[调度] " + msg)
}

// instanceScheduler 懒加载调度器单例。
//
// 与 db / probe / engine 的懒加载同一手法: 首次调用时才读配置、启动调度循环。
// 配置 enabled=false 时**仍创建调度器**但不 Start() —— 这样前端能查到完整的
// 策略模板/节点/限速视图(只读), 用户改配置后无需重启即可 enabled=true 生效。
func instanceScheduler() *scheduler.Scheduler {
	schedOnce.Do(func() {
		// 已存在实例则不重建: 测试会预先注入实例并把 Once 标记为"已执行",
		// 此守卫保证注入的实例不被覆盖(否则测试断言全错位)。
		if schedInst != nil {
			return
		}
		cfg := loadSchedulerConfig()
		schedCfgVal = cfg
		schedInst = scheduler.New(cfg, schedExec)
		// 事件钩子: 落库 + SSE 广播
		schedInst.OnEvent(schedOnEvent)
		if cfg.Enabled {
			schedInst.Start()
			// 同步一次探针节点视图(此后由心跳事件增量更新)
			syncSchedulerNodes()
			schedLogLine(fmt.Sprintf("任务调度已启用(默认): 排队提交可用, 全局并发 %d / 限速 %d pps / 队列上限 %d",
				cfg.MaxConcurrency, cfg.DefaultRate, cfg.MaxQueue))
		} else {
			schedLogLine("任务调度已被显式关闭(settings.json scheduler.enabled=false), 排队提交退回即时执行")
		}
	})
	// 兜底返回非 nil 实例: 调用方(HTTP handler)一律直接解引用返回值,
	// 返回 nil 会变成 nil 解引用 panic -> 前端只看到 500, 无从排查。
	// 正常路径下 Once 内部已完成赋值; 这里只防御"Once 被外部消费"的异常态。
	if schedInst == nil {
		cfg := loadSchedulerConfig()
		schedCfgVal = cfg
		schedInst = scheduler.New(cfg, schedExec)
		schedInst.OnEvent(schedOnEvent)
		if cfg.Enabled {
			schedInst.Start()
			syncSchedulerNodes()
		}
	}
	return schedInst
}

// schedulerEnabled 调度器是否已启用并接管任务提交。
func schedulerEnabled() bool {
	if schedInst == nil {
		// 未初始化时不要触发启动: 判定只读配置(避免"查一下状态"就把调度器跑起来)
		return loadSchedulerConfig().Enabled
	}
	return schedInst.Config().Enabled
}

// stopScheduler 进程退出时停止调度循环。
//
// 未初始化时为空操作(不能在此处 instanceScheduler() —— 那会在退出路径上
// 反过来把调度器创建/启动起来)。运行中任务会被置为暂停(而非失败), 使下次
// 启动仍可从任务表恢复(任务书的"任务中断支持续扫")。
func stopScheduler() {
	if schedInst == nil {
		return
	}
	schedInst.Stop()
	schedLogLine("调度器已停止")
}

// ===== 执行能力注入 =====

// schedExec 调度器的执行回调: 按任务节点路由到"探针下发"或"中心本地执行"。
//
// 这是整个装配层最关键的一段: 调度器只给出"该在哪个节点跑", 具体怎么跑由这里
// 决定。两条路径共用 Params, 因此参数映射只需写一次(见 paramsToScanReq)。
func schedExec(ctx context.Context, t *scheduler.Task, progress func(string)) (string, error) {
	if t.Node != "" {
		return execOnProbe(ctx, t, progress)
	}
	return execOnLocal(ctx, t, progress)
}

// paramsToScanReq 把调度参数映射为本地扫描请求(与 /api/scan 的 scanReq 同结构)。
//
// 为什么要映射而不是让调度器直接持 scanReq: scanReq 是 HTTP 层结构(带 json tag
// 与前端字段), 让 scheduler 包依赖它会破坏"调度器只依赖标准库"的边界。
func paramsToScanReq(t *scheduler.Task) scanReq {
	p := t.Params
	req := scanReq{
		Type:              t.Kind,
		IP:                p.IP,
		CIDR:              p.CIDR,
		URL:               p.URL,
		Ports:             p.Ports,
		TimeoutMs:         p.Timeout,
		Concurrency:       p.Concurrency,
		EnableNuclei:      p.EnableNuclei,
		NucleiTags:        p.NucleiTags,
		NucleiTagsExclude: p.NucleiTagsExclude,
		EnableArp:         p.EnableArp,
		EnableExternal:    p.EnableExternal,
		EnableSynScan:     p.EnableSynScan,
		Capture:           p.Capture,
		CaptureDevice:     p.CaptureDevice,
		CaptureFilter:     p.CaptureFilter,
		AliveMode:         p.AliveMode,
		WebDeep:           p.WebDeep,
	}
	// 目标兜底: 按类型回填(调度层已归一, 这里再兜一层防止手工构造的任务缺字段)
	switch t.Kind {
	case "ip", "alive", "unified":
		if req.CIDR == "" {
			req.CIDR = firstNonEmptyStr(p.CIDR, p.Target)
		}
	case "web":
		if req.URL == "" {
			req.URL = firstNonEmptyStr(p.URL, p.Target)
		}
	default:
		if req.IP == "" {
			req.IP = firstNonEmptyStr(p.IP, p.Target)
		}
	}
	return req
}

// execOnLocal 在中心本地执行任务(复用既有 handleScan 的扫描能力)。
//
// 进度上报: 扫描过程中的关键节点通过 progress 回传, 由调度器转成 SSE 事件,
// 前端任务列表就能看到"正在扫描 10.0.0.5"这类实时进度, 而不是只有一个转圈。
func execOnLocal(ctx context.Context, t *scheduler.Task, progress func(string)) (string, error) {
	req := paramsToScanReq(t)
	target := firstNonEmptyStr(req.IP, req.CIDR, req.URL)
	if target == "" {
		return "", fmt.Errorf("任务目标为空")
	}
	progress("开始本地扫描: " + target)

	// 限速器接入: 按目标网段申请发包令牌(超速阻塞等待, 不丢包 ——
	// 丢包会让端口被误判为关闭, 产生静默的错误结论)。
	if err := waitRateToken(ctx, t); err != nil {
		return "", err
	}
	progress("限速放行, 执行中: " + target)

	d := currentDB()
	var buf strings.Builder
	var emitMu sync.Mutex
	emit := func(event string, data any) {
		emitMu.Lock()
		defer emitMu.Unlock()
		if event == "done" {
			if b, err := json.Marshal(data); err == nil {
				buf.Write(b)
			}
		}
		broadcastScanEvent(event, data)
	}
	_ = d // 扫描器自身不写库(落库由既有 onProbeResultIngest / scanctl 链路负责)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	runScanPipeline(ctx, req, emit)

	summary := strings.TrimSpace(buf.String())
	if len(summary) > 4096 {
		summary = summary[:4096] + "...(已截断)"
	}
	// done 事件里 msg 为"扫描终止"代表中途失败(如目标 IP 非法), 需如实上报,
	// 否则失败任务会被记成成功 —— 用户再也看不到问题。
	if strings.Contains(summary, "扫描终止") && !strings.Contains(summary, "全部完成") {
		return "", fmt.Errorf("扫描未完成: %s", summary)
	}
	return summary, nil
}

// waitRateToken 按任务目标网段等待发包许可。
//
// n 取"本次将要发多少包"的粗估: 端口扫描按 端口数 x 目标数, 其它类型按 1。
// 目的是让限速对"一次性发几百个包的大任务"也能起到抑制突发的作用, 而不是
// 每个任务只扣 1 个令牌(那样限速完全失真)。
func waitRateToken(ctx context.Context, t *scheduler.Task) error {
	if schedInst == nil {
		return nil
	}
	target := firstNonEmptyStr(t.Params.CIDR, t.Params.IP, t.Params.URL, t.Target)
	if target == "" {
		return nil
	}
	n := estimatePackets(t)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
	}()
	defer close(done)
	if err := schedInst.RateLimiter().Wait(ctx.Done(), target, n); err != nil {
		return err
	}
	return nil
}

// estimatePackets 粗估任务发包量(限速配额用)。
//
// 刻意保守取小值: 高估会让小任务被大额预扣卡死(明明只发 10 个包却等 1 秒),
// 低估只是让限速略宽松 —— 后者是更可接受的偏差方向。
func estimatePackets(t *scheduler.Task) int {
	ports := countPorts(t.Params.Ports)
	if ports <= 0 {
		ports = 8
	}
	targets := countTargets(t.Params.CIDR, t.Params.IP)
	n := ports * targets
	if n < 1 {
		n = 1
	}
	if n > 2000 { // 单次最多预扣 2000, 避免大网段任务一次性把桶扣穿
		n = 2000
	}
	return n
}

// countPorts 统计端口串里的端口数量(支持 "80,443" 与 "1-1024" 混排)。
//
// 非法项(空串/反向区间/非数字)一律按 1 个端口计: 既不丢弃(否则限速配额偏小),
// 也不放大(否则会误把用户的错别字当成上万端口, 直接卡死任务)。
func countPorts(spec string) int {
	if strings.TrimSpace(spec) == "" {
		return 0
	}
	n := 0
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "-"); i > 0 {
			a, errA := strconv.Atoi(strings.TrimSpace(part[:i]))
			b, errB := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if errA == nil && errB == nil && b >= a {
				n += b - a + 1
				continue
			}
		}
		n++
	}
	return n
}

// countTargets 统计目标数量。
//
// 口径: 网段按 2^(32-前缀) 估算(含网络号与广播地址, 是**上界**)。
// 取上界的理由: 限速配额宁可略大 —— 少算会让限速对"实际发包量更大的任务"
// 形同虚设(超额发出去才被拦住), 多算只是让任务起步稍慢, 后者安全得多。
// 大网段(前缀 <= 16)统一按 256 估, 不做指数放大(否则 /8 会算出上千万)。
func countTargets(cidr, ip string) int {
	cidr = strings.TrimSpace(cidr)
	if cidr != "" && strings.Contains(cidr, "/") {
		_, bits, err := parseCIDRBits(cidr)
		if err == nil {
			if bits <= 16 {
				return 256 // 大网段按 256 估, 不做指数放大
			}
			if bits >= 32 {
				return 1
			}
			return 1 << (32 - bits)
		}
	}
	return 1
}

// parseCIDRBits 取 CIDR 的前缀长度(不引入 net 依赖的轻量实现)。
func parseCIDRBits(cidr string) (string, int, error) {
	i := strings.LastIndex(cidr, "/")
	if i <= 0 {
		return cidr, 0, fmt.Errorf("非 CIDR")
	}
	bits, err := strconv.Atoi(strings.TrimSpace(cidr[i+1:]))
	if err != nil || bits < 0 || bits > 128 {
		return cidr, 0, fmt.Errorf("前缀长度非法: %s", cidr[i+1:])
	}
	return cidr[:i], bits, nil
}

// execOnProbe 把任务下发给指定探针执行。
//
// 与既有 dispatchToProbe 的区别: 这里不直接产出 SSE 事件流(调度器统一广播),
// 且失败时返回 error 让调度器的"自动重分配"机制接手换节点重试。
func execOnProbe(ctx context.Context, t *scheduler.Task, progress func(string)) (string, error) {
	if probeCenter == nil {
		return "", fmt.Errorf("探针中心端未启用, 无法下发到节点 %s", t.Node)
	}
	if !probeCenter.Online(t.Node) {
		return "", fmt.Errorf("%w: %s", probe.ErrProbeOffline, t.Node)
	}
	req := paramsToScanReq(t)
	target := firstNonEmptyStr(req.IP, req.CIDR, req.URL)
	if target == "" {
		return "", fmt.Errorf("任务目标为空")
	}
	if err := waitRateToken(ctx, t); err != nil {
		return "", err
	}
	progress("下发到探针 " + t.Node + ": " + target)

	args := probeTaskArgs(req, req.Ports)
	d := currentDB()
	if err := assignToProbeWithArgs(d, t.ID, t.Node, t.Kind, target, args, t.CreatedBy); err != nil {
		return "", err
	}
	// 探针任务是异步执行的(下发即返回)。这里等待结果或 ctx 取消:
	// 探针回传结果后会由既有 onProbeResultIngest 落库, 调度器据此感知完成。
	return waitProbeCompletion(ctx, d, t.ID, progress)
}

// waitProbeCompletion 轮询探针任务状态直到终态。
//
// 为什么用轮询而不是回调: 探针结果回传链路(onProbeResultIngest)属于既有代码,
// 改成回调会侵入那条稳定链路; 而探针任务表本身已持久化了状态, 轮询它是零侵入
// 且天然支持"进程重启后仍在等待"的语义。间隔 2s 对扫描任务(分钟级)足够细。
func waitProbeCompletion(ctx context.Context, d *db.Database, taskID string, progress func(string)) (string, error) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	lastStatus := ""
	for {
		select {
		case <-ctx.Done():
			// 取消时通知探针停止(尽力而为, 失败不影响调度层状态)
			if probeCenter != nil {
				_ = probeCenter.CancelTask("", taskID)
			}
			return "", ctx.Err()
		case <-tick.C:
		}
		if d == nil {
			return "", fmt.Errorf("数据库不可用, 无法跟踪探针任务")
		}
		pt, err := d.ProbeTasks().Get(taskID)
		if err != nil || pt == nil {
			continue
		}
		if pt.Status != lastStatus {
			lastStatus = pt.Status
			progress("探针任务状态: " + pt.Status)
		}
		switch pt.Status {
		case db.ProbeTaskSuccess:
			return firstNonEmptyStr(pt.Result, "探针执行完成"), nil
		case db.ProbeTaskFailed:
			// 中心端与探针都对取消置 failed(探针任务表无 cancelled 常量),
			// 故按 ctx 是否已取消区分"用户取消"与"真实失败", 让前端提示更准确。
			if ctx.Err() != nil {
				return "", fmt.Errorf("探针任务已中断")
			}
			return "", fmt.Errorf("探针执行失败: %s", firstNonEmptyStr(pt.Error, "未提供原因"))
		}
	}
}

// ===== 事件观测(落库 + SSE 广播) =====

// schedOnEvent 调度事件统一处理: 落库状态 + 广播到前端。
//
// 落库口径: 任务表(db.ScanTask)是"用户看到的任务", 必须与调度器状态同步;
// 探针任务表(db.ProbeTask)由既有 onProbeResultIngest 维护, 此处不重复写。
func schedOnEvent(e scheduler.Event) {
	// SSE 广播: 事件名统一用 "sched", 与扫描事件(status/ip/port/finding)并存,
	// 前端按需订阅 —— 让调度事件混进扫描事件流会让既有解析逻辑需要改动。
	if b, err := json.Marshal(e); err == nil {
		sse.Default().Publish("sched", b)
	}
	if e.TaskID == "" {
		return
	}
	d := currentDB()
	if d == nil {
		return
	}
	status := dbStatusOf(e)
	if status == "" {
		return
	}
	// DAO 可能为 nil(db.Close() 会把所有 DAO 置 nil), 必须先守卫 ——
	// 对 nil DAO 调方法会直接 panic(既有代码踩过的坑)。
	if d.ScanTasks() == nil {
		return
	}
	_, _ = d.ScanTasks().UpdateStatus(e.TaskID, status, e.Msg)
}

// dbStatusOf 调度事件 -> DB 任务状态。
//
// 映射口径(与 scheduler 包 types.go 的说明对应):
//
//	queued/resumed -> pending   DB 无 queued 常量, 用既有 pending 兼容 v2 与前端
//	paused         -> pending   同上; "是否暂停"由调度器内存态决定(前端从本 API 读)
//	started        -> running
//	done           -> success/failed  由事件消息前缀判定(调度器把终态写进 Msg)
//	cancelled      -> cancelled
func dbStatusOf(e scheduler.Event) string {
	switch e.Type {
	case scheduler.EventQueued, scheduler.EventResumed, scheduler.EventPaused:
		return db.TaskPending
	case scheduler.EventStarted:
		return db.TaskRunning
	case scheduler.EventCancelled:
		return db.TaskCancelled
	case scheduler.EventDone:
		// 调度器的 done 事件 Msg 形如 "success: ..." / "failed: ..."
		if strings.HasPrefix(e.Msg, scheduler.StatusFailed) {
			return db.TaskFailed
		}
		return db.TaskSuccess
	}
	return ""
}

// ===== /api/scan 的队列接管 =====

// enqueueScanRequest 把 /api/scan 的请求转入调度队列。
//
// 触发条件: 请求带 queue=true 且调度器已启用(见 handleScan 的调用点)。
// 入队后立即通过同一个 emit 通道告知前端"已入队 + 队列位置", 然后结束 HTTP
// 流 —— 任务的实际进度由 /api/v2/scheduler/tasks 或 SSE 的 sched 事件追踪。
//
// 为什么不用"保持 SSE 连接等任务跑完": 排队时间不可预期(可能几分钟到几小时),
// 让 HTTP 连接一直挂着会耗尽浏览器连接数, 且用户刷新页面就丢失了关联。
// 入队即返回 + 事件推进是队列系统的标准做法。
func enqueueScanRequest(req scanReq, emit func(string, any)) {
	s := instanceScheduler()
	params := scheduler.Params{
		Ports:             req.Ports,
		Timeout:           req.TimeoutMs,
		Concurrency:       req.Concurrency,
		EnableNuclei:      req.EnableNuclei,
		NucleiTags:        req.NucleiTags,
		NucleiTagsExclude: req.NucleiTagsExclude,
		EnableArp:         req.EnableArp,
		EnableExternal:    req.EnableExternal,
		Capture:           req.Capture,
		CaptureDevice:     req.CaptureDevice,
		CaptureFilter:     req.CaptureFilter,
		CaptureMaxBytes:   req.CaptureMaxBytes,
		WebDeep:           req.WebDeep,
	}
	target := firstNonEmptyStr(req.IP, req.CIDR, req.URL)
	// 执行节点: queueNode="auto" 时由调度器挑最空闲探针; 未指定则本地执行。
	// 注意与既有 execAt/probeNode 语义对齐: 若用户传了 execAt=probe, 沿用其节点。
	node := strings.TrimSpace(req.QueueNode)
	if node == "" && req.ExecAt == "probe" {
		node = req.ProbeNode
	}
	task, err := s.Submit(scheduler.SubmitRequest{
		Kind:      req.Type,
		Target:    target,
		Strategy:  req.Strategy,
		Params:    params,
		Node:      node,
		Priority:  req.Priority,
		AutoRetry: req.AutoRetry,
	})
	if err != nil {
		emit("status", map[string]any{"msg": "入队失败: " + err.Error()})
		emit("done", map[string]any{"ok": false, "msg": "入队失败: " + err.Error()})
		return
	}
	emit("status", map[string]any{
		"msg":      fmt.Sprintf("任务已入队(队列位置 %d), 由调度器按并发与限速派发", len(s.Queued())),
		"taskId":   task.ID,
		"strategy": task.Strategy,
		"node":     firstNonEmptyStr(task.Node, "中心本地"),
	})
	emit("done", map[string]any{"ok": true, "queued": true, "taskId": task.ID})
}

// ===== 节点同步 =====

// syncSchedulerNodes 从探针中心端同步在线节点到调度器。
//
// 负载信息的来源: 探针心跳上报的 NodeInfo(CPU/内存)。中心端 Snapshots() 是
// 既有只读接口, 这里只做读取映射, 不改动探针链路。
func syncSchedulerNodes() {
	if schedInst == nil || probeCenter == nil {
		return
	}
	nodes := make([]scheduler.Node, 0, 8)
	for _, snap := range probeCenter.Snapshots() {
		n := scheduler.Node{
			ID:     snap.ProbeID,
			Name:   snap.Name,
			Kind:   scheduler.NodeProbe,
			Online: true, // Snapshots 只包含在线探针
		}
		if snap.Info != nil {
			n.Name = firstNonEmptyStr(n.Name, snap.Info.Name, snap.Info.Hostname)
			// 能力集从节点信息推导: Npcap 决定抓包能力; 引擎决定 SYN 与外部扫描能力。
			// 不直接读 db.Probe.Capabilities 是因为那是"注册时快照", 心跳里
			// Npcap 的安装状态更实时(用户可能刚装完 Npcap 无需重新注册)。
			n.Capabilities = capabilitiesOf(snap.Info)
		}
		if snap.Load != nil {
			n.CPUPercent = snap.Load.CPUPercent
			n.MemPercent = snap.Load.MemPercent
			n.TasksRunning = snap.Load.TasksRunning
		}
		nodes = append(nodes, n)
	}
	schedInst.SyncNodes(nodes)
}

// capabilitiesOf 从探针节点信息推导能力集(逗号分隔, 与 probe_api 上报口径一致)。
//
// 依据: 端口/Web/主机扫描是探针内置引擎实现(始终具备); 抓包需要 Npcap;
// SYN 扫描需要 Npcap + nmapcore; 外部引擎能力由其 bin 目录探测结果决定。
// 这个推导必须与探针端上报的 capabilities 口径一致, 否则调度器会因为
// "能力不匹配"错误拒绝本可执行的任务(用户看到的是"探针不支持抓包"却抓得到包)。
func capabilitiesOf(info *probe.NodeInfo) string {
	caps := []string{"portscan", "web", "host", "nuclei"}
	if info.NpcapInstalled {
		caps = append(caps, "capture", "synscan")
	}
	for _, e := range info.Engines {
		if e.Found {
			caps = append(caps, e.Name)
		}
	}
	return strings.Join(caps, ",")
}

// ===== 与既有扫描管线的桥接 =====

// broadcastScanEvent 把扫描过程中的事件广播到全局 SSE 流。
func broadcastScanEvent(event string, data any) {
	if b, err := json.Marshal(data); err == nil {
		_ = sse.Default().Publish(event, b)
	}
}

// currentDB 取当前数据库(v2 单例)。不可用时返回 nil, 由调用方降级。
func currentDB() *db.Database {
	defer func() { _ = recover() }()
	return v2DB()
}

// firstNonEmptyStr 返回首个非空字符串。
func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ===== HTTP API =====

// schedOK / schedFail v2 统一响应封装。
//
// 包一层的原因: 调度接口的错误映射是集中规则(队列满 -> 503, 任务不存在 -> 404),
// 逐个 handler 手写 server.Fail(w, httpStatus, code, msg) 三参数极易出现
// "业务码与 HTTP 状态码错配"(如 503 业务码配 400 状态), 前端按 HTTP 状态
// 分流的逻辑就会失效。
func schedOK(w http.ResponseWriter, data any) {
	server.OK(w, data)
}

func schedFail(w http.ResponseWriter, code int, msg string) {
	server.Fail(w, httpStatusOf(code), code, msg)
}

// httpStatusOf 业务错误码 -> HTTP 状态码(与 server 包既有映射保持一致)。
func httpStatusOf(code int) int {
	switch code {
	case server.CodeBadRequest:
		return http.StatusBadRequest
	case server.CodeUnauthorized:
		return http.StatusUnauthorized
	case server.CodeForbidden:
		return http.StatusForbidden
	case server.CodeNotFound:
		return http.StatusNotFound
	case server.CodeConflict:
		return http.StatusConflict
	case server.CodeDBUnavailable:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

// registerSchedulerRoutes 注册调度 API(走 v2 统一响应与鉴权, 与探针 API 同风格)。
func registerSchedulerRoutes(srv *server.Server) {
	srv.Get("/api/v2/scheduler/status", requireAuth(hSchedStatus))
	srv.Get("/api/v2/scheduler/strategies", requireAuth(hSchedStrategies))
	srv.Get("/api/v2/scheduler/tasks", requireAuth(hSchedTaskList))
	// 写操作(触发扫描/变更任务状态/改配置)挂 adminOnly: auditor 只读,
	// 免登录模式直通(规则 6)。读接口(状态/队列/节点/限速统计)保持 requireAuth。
	srv.Post("/api/v2/scheduler/submit", requireAuth(adminOrOperator(hSchedSubmit)))
	srv.Post("/api/v2/scheduler/pause", requireAuth(adminOrOperator(hSchedPause)))
	srv.Post("/api/v2/scheduler/resume", requireAuth(adminOrOperator(hSchedResume)))
	srv.Post("/api/v2/scheduler/cancel", requireAuth(adminOrOperator(hSchedCancel)))
	srv.Post("/api/v2/scheduler/retry", requireAuth(adminOrOperator(hSchedRetry)))
	srv.Delete("/api/v2/scheduler/tasks/{id}", requireAuth(adminOrOperator(hSchedDelete)))
	srv.Get("/api/v2/scheduler/nodes", requireAuth(hSchedNodes))
	srv.Get("/api/v2/scheduler/config", requireAuth(hSchedGetConfig))
	srv.Post("/api/v2/scheduler/config", requireAuth(hSchedSetConfig))
	srv.Get("/api/v2/scheduler/rate", requireAuth(hSchedRate))
}

// hSchedStatus GET 调度器总览(前端仪表盘: 并发/队列/统计/限速)。
func hSchedStatus(w http.ResponseWriter, r *http.Request) {
	s := instanceScheduler()
	cfg := s.Config()
	out := map[string]any{
		"stats":         s.Stats(),
		"config":        cfg,
		"configPath":    schedConfigPath(),
		"enabled":       cfg.Enabled,
		"strategies":    s.Strategies(),
		"nodes":         s.Nodes(),
		"rate":          s.RateStats(),
		"queueLen":      len(s.Queued()),
		"probeAvailable": probeCenter != nil,
	}
	// 提示只在"被显式关闭"时给出(默认就是启用的, 正常情况前端看不到这条)
	if !cfg.Enabled {
		out["hint"] = "调度已被关闭: 在 settings.json 的 scheduler 节设置 enabled=true 后重启(默认启用, 一般无需改)"
	}
	schedOK(w, out)
}

// hSchedStrategies GET 内置策略模板列表。
func hSchedStrategies(w http.ResponseWriter, r *http.Request) {
	s := instanceScheduler()
	schedOK(w, map[string]any{
		"strategies": s.Strategies(),
		"ports": map[string]string{
			"alive":  scheduler.PortsAlive,
			"common": scheduler.PortsCommon,
			"web":    scheduler.PortsWeb,
		},
	})
}

// hSchedTaskList GET 任务列表(?status=&page=&size=), 同时返回队列顺序。
func hSchedTaskList(w http.ResponseWriter, r *http.Request) {
	s := instanceScheduler()
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("size"))
	items, total := s.List(q.Get("status"), page, size)
	schedOK(w, map[string]any{
		"items": items,
		"total": total,
		"queue": s.Queued(),
		"stats": s.Stats(),
		"page":  page,
		"size":  size,
	})
}

// schedSubmitReq 提交任务的请求体(前端表单直接映射)。
type schedSubmitReq struct {
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	Strategy string `json:"strategy"`
	// 以下为用户自定义参数(留空/0 表示"用策略模板默认值")
	Ports             string `json:"ports"`
	TimeoutMs         int    `json:"timeoutMs"`
	Concurrency       int    `json:"concurrency"`
	EnableSynScan     bool   `json:"enableSynScan"`
	EnableNuclei      bool   `json:"enableNuclei"`
	NucleiTags        string `json:"nucleiTags"`
	NucleiTagsExclude string `json:"nucleiTagsExclude"`
	Capture           bool   `json:"capture"`
	CaptureDevice     string `json:"captureDevice"`
	CaptureFilter     string `json:"captureFilter"`
	EnableArp         *bool  `json:"enableArp"`
	EnableExternal    *bool  `json:"enableExternal"`
	// WebDeep Web 深度扫描(仅 kind=web 有效): 追加同源爬虫 + POST + 多类型注入探测。
	// 默认 false; 选 webdeep 策略时由模板默认打开。
	WebDeep bool `json:"webdeep"`
	// Node 执行节点: 空 = 中心本地, "auto" = 自动挑最空闲探针, 其它 = 探针 ID
	Node      string `json:"node"`
	Priority  int    `json:"priority"`
	AutoRetry *bool  `json:"autoRetry"`
}

// toSchedulerParams 映射为调度参数。
func (r schedSubmitReq) toSchedulerParams() scheduler.Params {
	return scheduler.Params{
		Ports:             r.Ports,
		Timeout:           r.TimeoutMs,
		Concurrency:       r.Concurrency,
		EnableNuclei:      r.EnableNuclei,
		NucleiTags:        r.NucleiTags,
		NucleiTagsExclude: r.NucleiTagsExclude,
		EnableArp:         r.EnableArp,
		EnableExternal:    r.EnableExternal,
		EnableSynScan:     r.EnableSynScan,
		Capture:           r.Capture,
		CaptureDevice:     r.CaptureDevice,
		CaptureFilter:     r.CaptureFilter,
		WebDeep:           r.WebDeep,
	}
}

// hSchedSubmit POST 提交扫描任务入队。
//
// 与 /api/scan 的关系: /api/scan 是"立即执行", 本接口是"排队执行"。
// 两者并存 —— 用户想立刻看结果用 /api/scan, 想被调度管控(并发/限速/暂停)
// 用本接口。这样既满足任务书的排队要求, 又不动既有稳定路径。
func hSchedSubmit(w http.ResponseWriter, r *http.Request) {
	var req schedSubmitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		schedFail(w, server.CodeBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	s := instanceScheduler()
	// 节点预检(任务书: 探针负载过高时中心拒绝新任务下发)
	if req.Node != "" && !strings.EqualFold(req.Node, "auto") {
		if rej := s.CheckNode(req.Node, req.Kind, req.Capture); rej != nil {
			if b, err := json.Marshal(scheduler.Event{
				Type: scheduler.EventRejected, Kind: req.Kind, Target: req.Target,
				Node: req.Node, Msg: rej.Msg, Time: time.Now(),
			}); err == nil {
				_ = sse.Default().Publish("sched", b)
			}
			schedFail(w, server.CodeBadRequest, "任务被拒绝: "+rej.Msg)
			return
		}
	}
	task, err := s.Submit(scheduler.SubmitRequest{
		Kind:      req.Kind,
		Target:    req.Target,
		Strategy:  req.Strategy,
		Params:    req.toSchedulerParams(),
		Node:      req.Node,
		Priority:  req.Priority,
		AutoRetry: req.AutoRetry,
	})
	if err != nil {
		code := server.CodeBadRequest
		if errors.Is(err, scheduler.ErrQueueFull) {
			code = server.CodeDBUnavailable // 503: 服务暂时无法处理, 提示稍后重试
		}
		schedFail(w, code, err.Error())
		return
	}
	// 同步落一条任务记录到 v2 任务表(调度器的状态变更由 schedOnEvent 续写)
	persistSchedTask(task, r)
	schedOK(w, map[string]any{
		"task":     task,
		"queuePos": len(s.Queued()),
		"stats":    s.Stats(),
	})
}

// persistSchedTask 把调度任务登记进 v2 任务表(供既有任务列表/看板共用)。
func persistSchedTask(t *scheduler.Task, r *http.Request) {
	d := currentDB()
	if d == nil {
		return
	}
	// Params 以 json.RawMessage 保存(与既有 v2 任务口径一致), 便于任务列表
	// 回显参数而不需要为调度器单独加列。
	raw, _ := json.Marshal(t.Params)
	rec := &db.ScanTask{
		Type:      t.Kind,
		Target:    t.Target,
		Params:    raw,
		Status:    db.TaskPending,
		ProbeNode: t.Node,
		CreatedBy: currentUser(),
		CreatedAt: t.CreatedAt,
	}
	// 复用调度器生成的任务 ID: 两处 ID 一致才能让 schedOnEvent 的 UpdateStatus
	// 命中同一条记录(否则调度状态永远同步不到任务列表里, 前端只看到"待执行")。
	rec.ID = t.ID
	if err := d.ScanTasks().Create(rec); err != nil {
		// 已存在(重试场景)时 Update 一次, 不视为失败
		if uerr := d.ScanTasks().Update(rec); uerr != nil {
			schedLogLine("任务落库失败(不影响执行): " + err.Error())
		}
	}
}

// hSchedPause POST 暂停任务(?id= 或 body {id})。
func hSchedPause(w http.ResponseWriter, r *http.Request) {
	schedSimpleAction(w, r, "暂停", func(s *scheduler.Scheduler, id string) error { return s.Pause(id) })
}

// hSchedResume POST 恢复任务。
func hSchedResume(w http.ResponseWriter, r *http.Request) {
	schedSimpleAction(w, r, "恢复", func(s *scheduler.Scheduler, id string) error { return s.Resume(id) })
}

// hSchedCancel POST 取消任务。
func hSchedCancel(w http.ResponseWriter, r *http.Request) {
	schedSimpleAction(w, r, "取消", func(s *scheduler.Scheduler, id string) error { return s.Cancel(id) })
}

// hSchedRetry POST 重试任务(失败/已取消 -> 重新入队)。
func hSchedRetry(w http.ResponseWriter, r *http.Request) {
	schedSimpleAction(w, r, "重试", func(s *scheduler.Scheduler, id string) error { return s.Retry(id) })
}

// schedSimpleAction 任务控制类接口的统一实现(id 取值 + 错误映射)。
//
// 抽出来的原因: 暂停/恢复/取消/重试四个接口除了动作不同完全一致, 逐个复制会
// 让"id 解析口径"(query 与 body 都支持)和错误码映射出现四份实现, 极易漂移。
func schedSimpleAction(w http.ResponseWriter, r *http.Request, name string, fn func(*scheduler.Scheduler, string) error) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			id = strings.TrimSpace(body.ID)
		}
	}
	if id == "" {
		schedFail(w, server.CodeBadRequest, "缺少任务 ID")
		return
	}
	s := instanceScheduler()
	if err := fn(s, id); err != nil {
		code := server.CodeBadRequest
		if errors.Is(err, scheduler.ErrNotFound) {
			code = server.CodeNotFound
		}
		schedFail(w, code, name+"失败: "+err.Error())
		return
	}
	task, _ := s.Get(id)
	schedOK(w, map[string]any{"task": task, "stats": s.Stats()})
}

// hSchedDelete DELETE 删除任务记录。
func hSchedDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		schedFail(w, server.CodeBadRequest, "缺少任务 ID")
		return
	}
	s := instanceScheduler()
	if err := s.Delete(id); err != nil {
		code := server.CodeBadRequest
		if errors.Is(err, scheduler.ErrNotFound) {
			code = server.CodeNotFound
		}
		schedFail(w, code, "删除失败: "+err.Error())
		return
	}
	// 同步删除 v2 任务表记录(保持两处口径一致, 否则前端任务列表会残留幽灵条目)
	if d := currentDB(); d != nil && d.ScanTasks() != nil {
		_, _ = d.ScanTasks().Delete(id)
	}
	schedOK(w, map[string]any{"deleted": id})
}

// hSchedNodes GET 执行节点视图(负载/槽位/接纳判定)。
//
// 每次调用顺带同步一次探针节点: 前端刷新节点列表的意图就是"我要看最新负载",
// 若只读缓存会看到过期数据(用户会以为负载阈值没生效)。
func hSchedNodes(w http.ResponseWriter, r *http.Request) {
	s := instanceScheduler()
	syncSchedulerNodes()
	nodes := s.Nodes()
	// 附上"为何不可用"的原因, 前端可直接提示用户(而不是只显示"满载")
	type nodeWithReason struct {
		scheduler.NodeView
		Reject *scheduler.RejectReason `json:"reject,omitempty"`
	}
	out := make([]nodeWithReason, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, nodeWithReason{NodeView: n, Reject: s.CheckNode(n.ID, "port", false)})
	}
	schedOK(w, map[string]any{
		"nodes":    out,
		"rate":     s.RateStats(),
		"capacity": s.Stats().MaxSlots,
	})
}

// hSchedGetConfig GET 调度配置回显。
func hSchedGetConfig(w http.ResponseWriter, r *http.Request) {
	schedOK(w, map[string]any{
		"config":     instanceScheduler().Config(),
		"configPath": schedConfigPath(),
	})
}

// hSchedSetConfig POST 保存调度配置(热更新 + 落盘, 无需重启)。
//
// 落盘是必需的: 热更新只影响当前进程, 重启后会回到旧配置 —— 用户会认为
// "保存失败"。同时写文件与内存, 两者口径始终一致。
func hSchedSetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg scheduler.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		schedFail(w, server.CodeBadRequest, "配置解析失败: "+err.Error())
		return
	}
	s := instanceScheduler()
	wasEnabled := s.Config().Enabled
	s.UpdateConfig(cfg)
	if err := saveSchedulerConfig(cfg); err != nil {
		schedLogLine("调度配置落盘失败(内存已生效, 重启后会回到旧配置): " + err.Error())
		schedFail(w, server.CodeInternal, "配置已热更新但落盘失败: "+err.Error())
		return
	}
	// 从未启用 -> 启用: 需要把调度循环真正跑起来(UpdateConfig 不会 Start)
	if !wasEnabled && cfg.Enabled {
		s.Start()
		syncSchedulerNodes()
	}
	schedOK(w, map[string]any{
		"config":  s.Config(),
		"saved":   true,
		"started": !wasEnabled && cfg.Enabled,
	})
}

// saveSchedulerConfig 保存调度配置。
//
// 【写到哪里: 必须与"读哪里"一致】
// 读配置时 settings.json 的 scheduler 节优先、旧 scheduler.json 回退。因此保存
// 也必须遵循同一优先级, 否则会出现"读一套、写另一套"的严重错乱: 用户在页面上
// 改完保存(写入旧文件), 下次启动时被 settings.json 里的旧值覆盖, 表现为
// "我保存了但重启后配置又变回去了" —— 用户会认为保存功能坏了。
//
// 因此:
//   - settings.json 里有 scheduler 节 → 合并写回该节(保留其它节与用户注释);
//   - 没有该节 → 写独立的 scheduler.json(与旧版本行为一致, 不强行给用户
//     新建一个 settings 节, 那会让"我只想改个并发数"变成"多出一个配置文件")。
//
// 落盘失败不 panic 也不中断服务: 按项目规则 3"外部资源可选, 失败降级运行"。
// saveSchedulerConfig 写回 settings.json 的 scheduler 节。
//
// 配置口径(2026-09-23 用户要求): 中心端所有配置一律 settings.json, 不再写
// 独立 scheduler.json。读取仍保留 scheduler.json 回退(兼容旧部署)。
func saveSchedulerConfig(cfg scheduler.Config) error {
	return writeSection(secScheduler, cfg)
}

// hSchedRate GET 网段限速视图。
func hSchedRate(w http.ResponseWriter, r *http.Request) {
	s := instanceScheduler()
	cfg := s.Config()
	// 附上"这个网段限速值从哪来"的解释, 避免用户改错地方找不到生效项
	type ruleView struct {
		scheduler.RateStat
		Source string `json:"source"` // rule = 网段规则; default = 全局默认
	}
	rows := make([]ruleView, 0, len(cfg.RateRules)+1)
	for _, st := range s.RateStats() {
		src := "default"
		for _, rr := range cfg.RateRules {
			if rr.CIDR == st.Net {
				src = "rule"
				break
			}
		}
		rows = append(rows, ruleView{RateStat: st, Source: src})
	}
	schedOK(w, map[string]any{
		"default": cfg.DefaultRate,
		"rules":   cfg.RateRules,
		"rows":    rows,
	})
}


