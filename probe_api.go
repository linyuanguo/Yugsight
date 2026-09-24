// probe_api.go 任务 6.3: 分布式扫描探针框架 —— 装配与 API 层(最小侵入接线点)。
//
// 本文件是 main 包与 probe 包的唯一连接点, 不修改任何既有扫描流程:
//
//   - 中心端: 主程序承担(probe.json 的 center 段 / -probe=center)。
//   - 探针端: 独立程序 yugsight-agent(见 cmd/agent), 不随主程序构建 ——
//     探针要装到多台机器上, 携带完整 Web UI/规则库毫无意义且会暴露额外攻击面。
//     -probe=both 仅用于同机联调(中心端 + 本地探针端一个进程跑通全链路)。
//
// 其余约定:
//   - probe.json(exe 同目录, 可选): { "center": {...}, "client": {...} }
//   - 默认全关(enabled=false): 不监听端口、不发起外连, 行为与单机版完全一致。
//   - 中心端: 探针上线/心跳/离线/任务结果全部落 db(probes / probe_tasks 表),
//     状态与统计经 /api/v2/probe/* 暴露给 Vue 与经典页。
//   - 探针端任务执行逻辑在 probe/agentexec 包(与 agent 共用一份实现, 避免漂移)。
//
// 降级: 端口占用/配置损坏/中心端不可达 一律记日志继续运行(不 panic 不中断)。

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"yugsight/db"
	"yugsight/probe"
	"yugsight/probe/agentexec"
	pscan "yugsight/probe/scanner"
	"yugsight/server"
	"yugsight/sse"
)

// ProbeConfig 探针框架总配置(exe 同目录 probe.json)。
type ProbeConfig struct {
	Center probe.ServerConfig `json:"center"`
	Client probe.ProbeConfig  `json:"client"`
}

var (
	// 指针而非值: sync.Once 含 noCopy, 值拷贝会被 go vet 拦截, 且测试需要
	// 整体替换来重置单例(与 schedOnce 同一手法, 见 schedAPITestMode)。
	probeOnce     *sync.Once
	probeCfg      ProbeConfig
	probeCenter   *probe.Center
	probeClient   *probe.Probe
	probeLog      []string
	probeMu       sync.Mutex
	probeRecorder *taskRecorder
)

func init() { probeOnce = &sync.Once{} }

const probeLogMax = 120

// probeOverrideRole -probe 命令行覆盖: "", center, agent, both。
//
// 用途: 免手改 probe.json 快速起角色(尤其在容器/无人值守环境)。
// 只覆盖 enabled 开关, 监听地址与中心端地址仍从 probe.json 读取。
var probeOverrideRole string

// instanceProbe 懒加载探针框架(中心端 + 探针端), 配置缺失时静默降级为全关。
func instanceProbe() {
	probeOnce.Do(func() {
		probeCfg = loadProbeConfig()
		applyProbeRole()
		probe.SetGlobalLogger(probeLogLine)
		probe.SetProbeVersion(appVersion)
		probeRecorder = newTaskRecorder()
		probeRecorder.Start()
		if !probeCfg.Center.Enabled && !probeCfg.Client.Enabled {
			probeLogLine("分布式探针: 未启用(probe 配置缺失或 enabled=false), 保持单机模式")
			return
		}
		if probeCfg.Center.Enabled {
			startCenter(probeCfg.Center)
		}
		if probeCfg.Client.Enabled {
			startClient(probeCfg.Client)
		}
	})
}

// applyProbeRole 应用 -probe 命令行角色覆盖(空值时保持 probe.json 原配置)。
//
// 行为: center -> 只开中心端; both -> 同时开中心端与探针端(同机联调用)。
// 探针端角色已独立为 yugsight-agent 二进制(见 cmd/agent), 故 -probe=agent 会被
// 明确拒绝并提示正确做法 —— 静默忽略会让用户以为 agent 已随主程序启动。
// 无效值只记日志忽略(不 panic, 不改变配置文件原语义)。
func applyProbeRole() {
	switch strings.ToLower(strings.TrimSpace(probeOverrideRole)) {
	case "":
		return
	case "center", "server":
		probeCfg.Center.Enabled = true
		probeCfg.Client.Enabled = false
	case "agent", "probe", "client":
		probeLogLine("探针端已拆分为独立程序, 请使用 yugsight-agent.exe 部署到探针机器; " +
			"主程序的 -probe=agent 不再生效(如需同机联调请用 -probe=both)")
		probeCfg.Center.Enabled = false
		probeCfg.Client.Enabled = false
	case "both", "all":
		probeCfg.Center.Enabled = true
		probeCfg.Client.Enabled = true
	default:
		probeLogLine("-probe 参数无效(可用 center/both): " + probeOverrideRole + ", 已忽略")
		return
	}
	probeLogLine("探针角色由命令行覆盖: -probe=" + probeOverrideRole)
}

// startCenter 启动中心端服务并接通落库回调。
func startCenter(cfg probe.ServerConfig) {
	c := probe.NewCenter(cfg)
	// 中心端日志分流: probe 包只管"发生了什么", 由这里决定"要不要给用户看"。
	// 分流放在接线层而不是 probe 包内, 是为了让 probe 保持与 UI 策略无关 ——
	// 它是可独立复用的通信层, 不该知道什么叫"静音"。
	c.SetLogger(probeConnLogLine)
	c.OnOnline(func(info *probe.NodeInfo) { probeRecorder.Online(info) })
	c.OnOffline(func(id, reason string) { probeRecorder.Offline(id, reason) })
	c.OnHeartbeat(func(id string, ld *probe.Load) { probeRecorder.Heartbeat(id, ld) })
	c.OnProgress(func(id, taskID, msg string) { probeRecorder.Progress(id, taskID, msg) })
	c.OnResult(func(id string, r *probe.TaskResult) { probeRecorder.Result(id, r) })
	if err := c.Start(); err != nil {
		probeLogLine("中心端启动失败(降级为未启用): " + err.Error())
		return
	}
	probeCenter = c
	// 注入版本比对: 探针注册时中心端会按它上报的 OS/Arch 精确分发对应平台的更新
	// 指令(见 probe_agent_update.go)。必须在 Start 之后 —— 注入要用到 probeCenter。
	setupAgentAutoUpdate()
}

// startClient 启动探针端(用本地扫描能力执行中心端下发的任务)。
func startClient(cfg probe.ProbeConfig) {
	p := probe.NewProbe(cfg, runProbeTask)
	p.SetLogger(probeLogLine)
	p.Start()
	probeClient = p
}

// runProbeTask 探针任务执行入口。
//
// 实现已抽出到 probe/agentexec 包(2026-09-16 拆分): 该包不依赖 db/engine/sse/http,
// 因而可被独立的 yugsight-agent 入口安全引用 —— 主程序与 agent 共用同一份执行逻辑,
// 避免双份实现漂移。此处仅做一层转发, 保持既有调用点不变。
func runProbeTask(t *probe.TaskAssign, progress func(string)) (*probe.TaskResult, error) {
	return agentexec.Run(t, progress)
}

// ===== 落库(中心端侧) =====

// taskRecorder 中心端持久化与统计: 探针表 + 探针任务表。
//
// 单独成类型的原因: 所有回调都发生在 probe 包的连接 goroutine 上,
// 统一在此做 recover + 错误降级, 保证 db 异常不会反噬通信链路。
type taskRecorder struct {
	mu       sync.Mutex
	lastSeen map[string]time.Time
}

func newTaskRecorder() *taskRecorder {
	return &taskRecorder{lastSeen: make(map[string]time.Time)}
}

// Start 占位: 预留周期性离线扫描(离线判定由 probe 包 sweep 负责)。
func (r *taskRecorder) Start() {}

// Online 探针上线: 落库(存在则刷新信息与状态)。
//
// 用 Upsert 而非 Create: 探针重启/重连会重复上线, 需覆盖旧记录并保留任务统计,
// 因此这里先读出旧记录再合并, 避免 Upsert 整体覆盖把累计统计清零。
func (r *taskRecorder) Online(info *probe.NodeInfo) {
	defer r.guard("上线处理")
	d := v2DB()
	if d == nil || info == nil {
		return
	}
	p := &db.Probe{}
	if old, err := d.Probes().Get(info.ProbeID); err == nil && old != nil {
		*p = *old // 保留任务统计与创建时间
	}
	p.ID = info.ProbeID
	p.Name = info.Name
	p.Addr = strings.Join(info.LocalIPs, ",")
	p.Status = db.ProbeOnline
	p.Capabilities = probeCapabilities(info)
	p.LastSeenAt = time.Now()
	p.NodeInfo = info
	if _, err := d.Probes().Upsert(p); err != nil {
		probeLogLine("探针落库失败: " + err.Error())
		return
	}
	r.mu.Lock()
	r.lastSeen[info.ProbeID] = time.Now()
	r.mu.Unlock()
	sse.Default().PublishJSON("probe", map[string]any{
		"event": "online", "probeId": info.ProbeID, "name": info.Name,
		"os": info.OS, "arch": info.Arch, "ip": info.LocalIPs,
	})
}

// Offline 探针离线: 置离线状态 + 未完成任务标记失败(可选重派)。
func (r *taskRecorder) Offline(id, reason string) {
	defer r.guard("离线处理")
	d := v2DB()
	if d == nil {
		return
	}
	if _, err := d.Probes().SetStatus(id, db.ProbeOffline); err != nil {
		probeLogLine("探针离线状态落库失败: " + err.Error())
	}
	// 该节点未完成任务统一置失败(避免任务永远挂在运行中), 由上层决定是否重派
	if tasks, err := d.ProbeTasks().ByProbe(id); err == nil {
		for _, t := range tasks {
			switch t.Status {
			case db.ProbeTaskPending, db.ProbeTaskSent, db.ProbeTaskRunning:
				_, _ = d.ProbeTasks().Finish(t.ID, db.ProbeTaskFailed, "", "",
					"探针离线("+reason+"), 任务未完成", t.FindingNum, 0)
			}
		}
	}
	sse.Default().PublishJSON("probe", map[string]any{"event": "offline", "probeId": id, "reason": reason})
}

// Heartbeat 心跳: 刷新在线与最后活跃时间。
func (r *taskRecorder) Heartbeat(id string, ld *probe.Load) {
	defer r.guard("心跳处理")
	d := v2DB()
	if d == nil {
		return
	}
	r.mu.Lock()
	last := r.lastSeen[id]
	r.lastSeen[id] = time.Now()
	r.mu.Unlock()
	// 30s 内已刷过则跳过, 避免高频心跳放大磁盘写(负载一并丢弃: 前端展示无需秒级精度)
	if time.Since(last) < 30*time.Second {
		return
	}
	// 负载随心跳落库, 供探针面板展示(CPU/内存/当前任务)
	if p, err := d.Probes().Get(id); err == nil && p != nil {
		p.Load = ld
		p.Status = db.ProbeOnline
		p.LastSeenAt = time.Now()
		_, _ = d.Probes().Upsert(p)
	} else if _, err := d.Probes().MarkSeen(id); err != nil {
		return
	}
	sse.Default().PublishJSON("probe", map[string]any{"event": "heartbeat", "probeId": id, "load": ld})
}

// Progress 任务进度: 更新探针任务进度 + 首次进度视为开始执行。
func (r *taskRecorder) Progress(id, taskID, msg string) {
	defer r.guard("进度处理")
	d := v2DB()
	if d == nil || taskID == "" {
		return
	}
	if _, err := d.ProbeTasks().MarkRunning(taskID, msg); err != nil {
		return
	}
	if d.ScanTasks() != nil {
		if _, err := d.ScanTasks().UpdateStatus(taskID, db.TaskRunning, ""); err != nil {
			// 任务不存在于统一任务表时忽略(探针任务可独立下发)
		}
	}
	if _, err := d.ProbeTasks().SetProgress(taskID, msg); err != nil {
		probeLogLine("任务进度落库失败: " + err.Error())
	}
	sse.Default().PublishJSON("probe", map[string]any{
		"event": "progress", "probeId": id, "taskId": taskID, "message": msg,
	})
}

// Result 任务结果: 落库明细 + 同步统一任务表状态 + 广播 SSE。
func (r *taskRecorder) Result(id string, res *probe.TaskResult) {
	defer r.guard("结果处理")
	d := v2DB()
	if d == nil || res == nil {
		return
	}
	status := db.ProbeTaskSuccess
	if res.Status != probe.TaskDone {
		status = db.ProbeTaskFailed
	}
	resultText := res.Raw
	if resultText == "" {
		resultText = summarizeFindings(res.Findings)
	}
	if _, err := d.ProbeTasks().Finish(res.TaskID, status, res.Summary, truncateText(resultText, 8000),
		res.Error, len(res.Findings), res.DurationMs); err != nil {
		// 落库失败是真问题(直接影响能否看到结果), 走面板日志
		probeLogLine("任务结果落库失败: " + err.Error())
	}

	// 任务 6.4: 探针上报的结构化结果送归一化模块统一处理(资产/漏洞落库 + 白名单/误报过滤)。
	// 独立于上面的任务明细落库: 归一化失败不影响任务状态流转(内部已 recover 兜底)。
	// 仅成功任务才归一化: 失败任务的部分结果可能不完整, 直接入库会污染资产/漏洞基线。
	if status == db.ProbeTaskSuccess {
		onProbeResultIngest(id, res)
	}
	// 统一任务表状态流转(存在则更新, 不存在忽略)
	taskStatus := db.TaskSuccess
	if status != db.ProbeTaskSuccess {
		taskStatus = db.TaskFailed
	}
	summary := res.Summary
	if summary == "" {
		summary = res.Error
	}
	if _, err := d.ScanTasks().UpdateStatus(res.TaskID, taskStatus, summary); err != nil {
		// 忽略: 探针任务可能未经 v2 任务表创建
	}
	// 累计探针任务统计(面板展示成功率)
	if p, err := d.Probes().Get(id); err == nil && p != nil {
		p.BumpTaskStat(status == db.ProbeTaskSuccess)
		_, _ = d.Probes().Upsert(p)
	}
	sse.Default().PublishJSON("probe", map[string]any{
		"event": "result", "probeId": id, "taskId": res.TaskID, "status": status,
		"summary": res.Summary, "findings": len(res.Findings), "error": res.Error,
	})
	// 任务结果条数属数据流过程, 只落盘不进面板(见 probeFlowLine)。
	// 结果的最终状态在"探针任务"列表里可见, 不需要日志再报一遍。
	probeFlowLine(fmt.Sprintf("探针 %s 任务 %s 结果: %s (%d 条发现)", id, res.TaskID, status, len(res.Findings)))
}

func (r *taskRecorder) guard(what string) {
	if p := recover(); p != nil {
		probeLogLine(fmt.Sprintf("探针%s异常(已恢复): %v", what, p))
	}
}

// probeCapabilities 汇总探针能力(供中心端选择下发节点):
//
//	portscan / web / host / alive  内置引擎能力(全平台, 任务 6.4 起含 ARP/Nuclei POC)
//	capture                        依赖 Npcap(仅 Windows), 且采集器已注册
//	synscan                        依赖 Npcap + nmapcore
//	<引擎名>                        ./bin/ 下探测到的外部引擎(nmapcore/trivycore/zapcore)
//
// 注意 info 可为 nil(上游节点信息缺失时的兜底路径), 故整段判空后再取字段。
func probeCapabilities(info *probe.NodeInfo) string {
	// 任务 6.4: 探针本地扫描能力集(存活探测/端口/Web/主机/Nuclei POC 均已内置)
	caps := []string{"alive", "portscan", "web", "host"}
	if pscan.CaptureSupported() {
		caps = append(caps, "capture")
	}
	if info == nil {
		return strings.Join(caps, ",")
	}
	if info.NpcapInstalled {
		caps = append(caps, "capture", "synscan")
	}
	for _, e := range info.Engines {
		if e.Found {
			caps = append(caps, e.Name)
		}
	}
	// 去重: capture 可能被平台采集器与 Npcap 检测两条路径各加一次
	return strings.Join(dedupStrings(caps), ",")
}

// dedupStrings 保序去重(能力串冗余会让中心端调度逻辑出现重复匹配)。
func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ===== 统一任务下发入口(供 v2 API 调用) =====

// assignToProbe 把扫描任务下发给指定探针(中心端本地登记 + 探针任务明细)。
// 探针离线时返回错误, 由调用方决定降级为本地执行或提示用户。
func assignToProbe(d *db.Database, taskID, probeID, kind, target, ports string, createdBy string) error {
	if probeCenter == nil {
		return fmt.Errorf("中心端未启用(probe.json center.enabled=false)")
	}
	if !probeCenter.Online(probeID) {
		return fmt.Errorf("%w: %s", probe.ErrProbeOffline, probeID)
	}
	pt := &db.ProbeTask{
		ID: taskID, ProbeNode: probeID, Kind: kind, Target: target, CreatedBy: createdBy,
	}
	if ports != "" {
		pt.Summary = "端口: " + ports
	}
	if _, err := d.ProbeTasks().Upsert(pt); err != nil {
		return fmt.Errorf("探针任务登记失败: %w", err)
	}
	task := &probe.TaskAssign{
		TaskID: taskID, Kind: kind, Target: target, Ports: ports, CreatedAt: time.Now().Unix(),
	}
	if err := probeCenter.AssignTask(probeID, task); err != nil {
		_, _ = d.ProbeTasks().Finish(taskID, db.ProbeTaskFailed, "", "", err.Error(), 0, 0)
		return err
	}
	_, _ = d.ProbeTasks().MarkSent(taskID)
	return nil
}

// dispatchToProbe 把扫描控制台的任务下发给指定探针(任务 6.3 执行位置路由)。
//
// 与 hProbeAssign 的区别: 这里从 /api/scan 的 SSE 通道回事件, 用户在控制台能
// 直接看到"已下发到探针 X"以及探针的进度/结果(经中心端 SSE 事件流进来是另一路,
// 此处同步返回下发结论即可, 不做阻塞等待)。
//
// 失败语义: 一律通过 emit 输出 status 事件说明原因(不返回 HTTP 错误码 —— 此时
// SSE 响应头已发出, 无法再改状态码), 并按本地降级还是直接失败交给用户决定。
func dispatchToProbe(req scanReq, emit func(string, any)) {
	d := v2DB()
	if d == nil {
		emit("status", map[string]any{"msg": "数据库不可用, 无法下发探针任务"})
		emit("done", map[string]any{"ok": false, "msg": "数据库不可用"})
		return
	}
	if probeCenter == nil {
		emit("status", map[string]any{"msg": "中心端未启用(probe.json center.enabled=false), 无法下发到探针"})
		emit("done", map[string]any{"ok": false, "msg": "中心端未启用"})
		return
	}
	if !probeCenter.Online(req.ProbeNode) {
		emit("status", map[string]any{"msg": "探针 " + req.ProbeNode + " 不在线, 任务未下发"})
		emit("done", map[string]any{"ok": false, "msg": "探针不在线"})
		return
	}
	target, ports := probeTarget(req)
	if target == "" {
		emit("status", map[string]any{"msg": "目标为空, 无法下发"})
		emit("done", map[string]any{"ok": false, "msg": "目标为空"})
		return
	}
	// 统一任务表登记(便于任务列表统一查看; 探针链路明细另落 probe_tasks)
	st := &db.ScanTask{
		Type: req.Type, Target: target, ProbeNode: req.ProbeNode, CreatedBy: currentUser(),
	}
	if raw, err := json.Marshal(map[string]string{"ports": ports}); err == nil {
		st.Params = raw
	}
	if err := d.ScanTasks().Create(st); err != nil {
		emit("status", map[string]any{"msg": "任务登记失败: " + err.Error()})
		emit("done", map[string]any{"ok": false, "msg": "任务登记失败"})
		return
	}
	emit("status", map[string]any{"msg": fmt.Sprintf("下发任务 %s 到探针 %s (%s %s)", st.ID, req.ProbeNode, req.Type, target)})
	// 任务参数(端口/并发/超时/Nuclei tag/抓包)一并下发, 探针端按 probe/scanner.OptionsFromArgs 解析
	args := probeTaskArgs(req, ports)
	if err := assignToProbeWithArgs(d, st.ID, req.ProbeNode, req.Type, target, args, currentUser()); err != nil {
		emit("status", map[string]any{"msg": "下发失败: " + err.Error()})
		emit("done", map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	emit("info", map[string]any{
		"probeTask": map[string]any{"taskId": st.ID, "probeId": req.ProbeNode},
		"msg":       "任务已下发, 执行进度与结果见探针管理页 / 实时事件流",
	})
	emit("done", map[string]any{"ok": true, "remote": true, "taskId": st.ID, "probeId": req.ProbeNode})
}

// probeTaskArgs 组装下发给探针的任务参数(JSON 串)。
//
// 只放"探针端真正会用到的"参数, 空值一律不填 —— 探针端对缺失字段使用内置默认,
// 下发侧无脑透传空值会让探针拿到 "concurrency": 0 之类的无效值。
// 返回空串表示无参数(探针端 OptionsFromArgs 走默认分支, 能力全开)。
func probeTaskArgs(req scanReq, ports string) string {
	args := map[string]any{}
	// collect 任务透传超时/并发即可: 它枚举的是探针本机, 端口集、抓包、Nuclei
	// 这些参数对它没有意义, 下发过去只会让探针端做无谓解析(项目规则: 只传用得到的)。
	if req.Type == "collect" {
		if req.TimeoutMs > 0 {
			args["timeoutMs"] = req.TimeoutMs
		}
		if req.Concurrency > 0 {
			args["concurrency"] = req.Concurrency
		}
		return marshalProbeTaskArgs(args)
	}
	if strings.TrimSpace(ports) != "" {
		args["ports"] = ports
	}
	if req.TimeoutMs > 0 {
		args["timeoutMs"] = req.TimeoutMs
	}
	if req.Concurrency > 0 {
		args["concurrency"] = req.Concurrency
	}
	if req.EnableNuclei {
		args["enableNuclei"] = true
	}
	if s := strings.TrimSpace(req.NucleiTags); s != "" {
		args["nucleiTags"] = s
	}
	if s := strings.TrimSpace(req.NucleiTagsExclude); s != "" {
		args["nucleiExclude"] = s
	}
	if req.EnableArp != nil {
		args["enableArp"] = *req.EnableArp
	}
	if req.EnableExternal != nil {
		args["enableExternal"] = *req.EnableExternal
	}
	// SYN 半开扫描: 默认关, 显式开启才下发(项目规则 5)。探针端 OptionsFromArgs
	// 解析 synscan; 无特权环境自动降级全连接, 不会让任务失败。
	if req.EnableSynScan {
		args["synscan"] = true
	}
	// 抓包骨架: 默认关, 显式开启才下发(项目规则 5)
	if req.Capture {
		args["capture"] = true
		if s := strings.TrimSpace(req.CaptureDevice); s != "" {
			args["captureDevice"] = s
		}
		if s := strings.TrimSpace(req.CaptureFilter); s != "" {
			args["captureFilter"] = s
		}
		if req.CaptureMaxBytes > 0 {
			args["captureMaxBytes"] = req.CaptureMaxBytes
		}
	}
	return marshalProbeTaskArgs(args)
}

// marshalProbeTaskArgs 序列化任务参数(空集返回空串 = 探针端走默认)。
func marshalProbeTaskArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	b, err := json.Marshal(args)
	if err != nil {
		// 语法上不可能失败(map[string]any 且值均为基础类型), 兜底记日志不阻断下发
		probeLogLine("探针任务参数序列化失败(按无参数执行): " + err.Error())
		return ""
	}
	return string(b)
}

// probeTarget 从扫描请求里取探针任务的目标与端口:
// 与本地执行口径一致 —— ip/alive 用 CIDR、port/host 用 IP、web 用 URL。
func probeTarget(req scanReq) (target, ports string) {
	switch req.Type {
	case "ip", "alive":
		target = strings.TrimSpace(req.CIDR)
		if target == "" {
			target = strings.TrimSpace(req.IP)
		}
	case "web":
		target = strings.TrimSpace(req.URL)
	case "collect":
		// 本机枚举: 采集探针所在机器自身, 目标就是本机。中心端一般不知道探针的
		// 出口 IP, 未填时用 127.0.0.1 作为"本机"占位(探针端 collectLocalIP 会
		// 再取真实出口 IP); 这里必须给非空值, 否则会被"目标为空"拦下。
		target = strings.TrimSpace(req.IP)
		if target == "" {
			target = "127.0.0.1"
		}
	default: // port / host
		target = strings.TrimSpace(req.IP)
	}
	if target == "" {
		target = strings.TrimSpace(req.CIDR)
	}
	if target == "" {
		target = strings.TrimSpace(req.URL)
	}
	if req.Type == "port" || req.Type == "host" {
		ports = strings.TrimSpace(req.Ports)
	}
	return target, ports
}

// assignToProbeWithArgs 下发任务并携带额外参数(任务 6.4: 抓包、端口、能力开关等)。
//
// Args 会被探针端 agentexec 解析(见 probe/scanner.OptionsFromArgs), 用于:
//   - 覆盖端口集/并发/超时
//   - 开关 Nuclei POC / ARP 探测 / 外部引擎
//   - capture=true 开启抓包骨架
//
// 与 assignToProbe 的差别: 参数直传给探针, 不落 ScanTask.Params(那份是给
// v2 任务列表展示的, 抓包开关等内部参数不值得暴露在任务列表里)。
func assignToProbeWithArgs(d *db.Database, taskID, probeID, kind, target, args string, createdBy string) error {
	if probeCenter == nil {
		return fmt.Errorf("中心端未启用(probe.json center.enabled=false)")
	}
	if !probeCenter.Online(probeID) {
		return fmt.Errorf("%w: %s", probe.ErrProbeOffline, probeID)
	}
	var extra map[string]any
	if strings.TrimSpace(args) != "" {
		if err := json.Unmarshal([]byte(args), &extra); err != nil {
			probeLogLine("探针任务参数解析失败(按无参数执行): " + err.Error())
		}
	}
	pt := &db.ProbeTask{
		ID: taskID, ProbeNode: probeID, Kind: kind, Target: target, CreatedBy: createdBy,
	}
	if _, err := d.ProbeTasks().Upsert(pt); err != nil {
		return fmt.Errorf("探针任务登记失败: %w", err)
	}
	task := &probe.TaskAssign{
		TaskID: taskID, Kind: kind, Target: target, Args: extra, CreatedAt: time.Now().Unix(),
	}
	if err := probeCenter.AssignTask(probeID, task); err != nil {
		_, _ = d.ProbeTasks().Finish(taskID, db.ProbeTaskFailed, "", "", err.Error(), 0, 0)
		return err
	}
	_, _ = d.ProbeTasks().MarkSent(taskID)
	return nil
}

// ===== HTTP API =====

// registerProbeRoutes 注册探针管理 API(挂在 /api/v2/probe/, 走 v2 统一响应与鉴权)。
func registerProbeRoutes(srv *server.Server) {
	srv.Get("/api/v2/probe/status", requireAuth(hProbeStatus))
	srv.Post("/api/v2/probe/enable", requireAuth(adminOrOperator(hProbeEnable)))
	srv.Get("/api/v2/probe/list", requireAuth(hProbeList))
	// 任务下发/取消/删除探针是写操作, 只读角色禁止(adminOnly; 免登录直通)
	srv.Post("/api/v2/probe/assign", requireAuth(adminOrOperator(hProbeAssign)))
	srv.Post("/api/v2/probe/cancel", requireAuth(adminOrOperator(hProbeCancel)))
	srv.Delete("/api/v2/probe/{id}", requireAuth(adminOrOperator(hProbeDelete)))
	srv.Get("/api/v2/probe/tasks", requireAuth(hProbeTaskList))
	// 探针 agent 分发(见 probe_agent_download.go): 从 exe 同目录 agents/ 读取
	// 各平台安装包供用户下载。必须注册在 /{id} 之一致的位置之前 —— 这里全是
	// 静态段, Go 1.22 ServeMux 按"最具体优先"匹配, 不会与 /{id} 冲突;
	// 但为可读性仍集中在此处, 与探针管理同一装配点。
	srv.Get("/api/v2/probe/agent/list", requireAuth(hAgentList))
	srv.Get("/api/v2/probe/agent/download", requireAuth(hAgentDownload))
	srv.Get("/api/v2/probe/agent/guide", requireAuth(hAgentGuide))
	// 探针自动更新下载(见 probe_agent_update.go): 给探针用的通道, **刻意不走
	// requireAuth** —— 探针只有一条 TCP 长连接, 没有浏览器会话 cookie。鉴权改为
	// URL 签名(HMAC(节点密钥, 平台+有效期)), 密钥本身不出现在 URL 里。
	srv.Get("/api/v2/probe/agent/update", hAgentUpdate)
	// 就地补包: 中心端自己编译本平台探针(服务器上没有构建脚本时的自救路径),
	// 详见 probe_agent_download.go 的"就地补包"小节。编译=在服务器落盘+起编译
	// 进程, 写操作, 只读角色禁止(adminOnly; 免登录直通)。
	srv.Post("/api/v2/probe/agent/build", requireAuth(adminOrOperator(hAgentBuild)))
	// 安装落地页(见 probe_agent_install.go): 面向被扫描机器上的操作者,
	// 一个能直接打开、按提示下载+复制启动命令的 HTML 页面。
	srv.Get("/api/v2/probe/agent/install", requireAuth(hAgentInstall))
}

// hProbeStatus GET /api/v2/probe/status 中心端/探针端运行状态(前端状态卡片)。
func hProbeStatus(w http.ResponseWriter, r *http.Request) {
	registerProbeOnce()
	out := map[string]any{
		"centerEnabled": probeCfg.Center.Enabled,
		"clientEnabled": probeCfg.Client.Enabled,
		"center":        probeCenter != nil,
		"client":        probeClient != nil,
		"configPath":    probeCfgPath(),
		"protocol":      probe.ProtocolVersion,
		// agentVersion 中心端当前提供的探针版本: 前端据此把探针列表里版本不一致的
		// 节点标出来(那些节点会在下次注册时自动更新)。始终回带, 与是否启用中心端
		// 无关 —— 前端需要在未启用时也能展示"探针应为哪个版本"。
		"agentVersion": agentUpdateVersion(),
	}
	if probeCfg.Center.Enabled {
		// 中心端配置回给前端: 监听地址用于展示, token 用于"下载探针"弹窗生成
		// 可直接复制的部署命令(用户不必再去翻 probe.json 手抄密钥 —— 抄错是
		// 探针部署最常见的失败原因)。接口本身走 requireAuth, 与其它配置
		// 展示口径一致(如 db/status 也回显配置字段)。
		out["centerCfg"] = probeCfg.Center
	}
	if probeCenter != nil {
		out["centerStat"] = probeCenter.Stats()
		out["online"] = probeCenter.Snapshots()
	}
	if probeClient != nil {
		out["clientOnline"] = probeClient.Online()
		out["clientId"] = probeClient.ID()
		out["centerAddr"] = probeCfg.Client.CenterAddr
		// 本机节点信息(与上报中心端同一份数据, 供面板展示, 避免前端重复采集)
		out["clientInfo"] = probe.CollectNodeInfo(probeCfg.Client.Name, appVersion)
	}
	out["log"] = probeLogSnapshot()
	server.OK(w, out)
}

// hProbeEnable POST /api/v2/probe/enable 一键开启探针中心端。
//
// 背景(功能审计 P0-5): 此前开启探针的唯一路径是"手工编辑 settings.json 后重启",
// 页面上只给一段 JSON 示例, 运维直接懵。现在页面点一下就把配置写好, 用户只剩
// "重启服务 + 部署探针"两步。
//
// 语义与边界:
//   - 写入 settings.json 的 probe 节(settings.json 优先于旧 probe.json, 统一写
//     新文件; 旧 probe.json 里已有的 listen/token 会先读进来保留, 不覆盖用户值);
//   - 只开 center 段, 不动 client 段(探针端已独立为 yugsight-agent 程序);
//   - 重启才生效: 探针中心端在 main 启动阶段初始化, 接口里热启动会触发
//     probeOnce 的 Once 语义与 agent 自更新链路的守卫(见 probe_agent_update.go
//     的注释), 不值得为"少等一次重启"引入时序风险 —— 明确提示重启即可;
//   - token 为空时自动生成(部署探针必须带密钥, 留空=不校验, 内网场景也可接受,
//     但生成一个可免去"要不要自己造密钥"的决策)。
func hProbeEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	registerProbeOnce()
	if probeCenter != nil {
		server.OK(w, map[string]any{
			"enabled": true, "restartRequired": false,
			"msg": "探针中心端已在运行, 无需重复开启",
		})
		return
	}
	tokenGenerated := false
	cfg := loadProbeConfig()
	cfg.Center.Enabled = true
	if strings.TrimSpace(cfg.Center.Listen) == "" {
		cfg.Center.Listen = ":8600"
	}
	if strings.TrimSpace(cfg.Center.Token) == "" {
		cfg.Center.Token = randHex(16)
		tokenGenerated = true
	}
	if err := writeSection(secProbe, cfg); err != nil {
		server.FailInternal(w, "写入 settings.json 失败: "+err.Error())
		return
	}
	logAudit(v2DB(), r, "probe.enable", "",
		fmt.Sprintf("listen=%s tokenGenerated=%v (重启后生效)", cfg.Center.Listen, tokenGenerated))
	server.OK(w, map[string]any{
		"enabled":         true,
		"restartRequired": true,
		"listen":          cfg.Center.Listen,
		"token":           cfg.Center.Token,
		"tokenGenerated":  tokenGenerated,
		"msg":             "探针配置已写入 settings.json, 重启服务后生效",
	})
}

// hProbeList GET /api/v2/probe/list 已登记探针列表(落库数据 + 在线态合并)。
func hProbeList(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	list, err := d.Probes().List()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	// 以真实连接状态覆盖库中状态(库可能滞后于进程实时态)
	type item struct {
		*db.Probe
		Online bool `json:"online"`
	}
	out := make([]item, 0, len(list))
	for _, p := range list {
		on := false
		if probeCenter != nil {
			on = probeCenter.Online(p.ID)
		}
		out = append(out, item{Probe: p, Online: on})
	}
	server.OK(w, map[string]any{"list": out, "total": len(out)})
}

// hProbeAssign POST /api/v2/probe/assign 下发扫描任务到指定探针。
//
// 入参: {probeId, type, target, ports?, scanTaskId?}
// scanTaskId 提供时复用既有任务 ID(便于任务列表关联), 否则自动创建统一任务记录。
func hProbeAssign(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var in struct {
		ProbeID    string `json:"probeId"`
		Type       string `json:"type"`
		Target     string `json:"target"`
		Ports      string `json:"ports"`
		ScanTaskID string `json:"scanTaskId"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.ProbeID) == "" || strings.TrimSpace(in.Target) == "" {
		server.FailBadRequest(w, "probeId 与 target 不能为空")
		return
	}
	if in.Type == "" {
		in.Type = "port"
	}
	taskID := in.ScanTaskID
	if taskID == "" {
		st := &db.ScanTask{
			Type: in.Type, Target: in.Target, ProbeNode: in.ProbeID, CreatedBy: currentUser(),
		}
		if raw, err := json.Marshal(map[string]string{"ports": in.Ports}); err == nil {
			st.Params = raw
		}
		if err := d.ScanTasks().Create(st); err != nil {
			server.FailBadRequest(w, "任务创建失败: "+err.Error())
			return
		}
		taskID = st.ID
	}
	if err := assignToProbe(d, taskID, in.ProbeID, in.Type, in.Target, in.Ports, currentUser()); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	logAudit(d, r, "probe.assign", in.ProbeID, in.Type+" "+in.Target)
	server.OK(w, map[string]any{"taskId": taskID, "probeId": in.ProbeID, "status": db.ProbeTaskSent})
}

// hProbeCancel POST /api/v2/probe/cancel 通知探针取消任务。
func hProbeCancel(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var in struct {
		ProbeID string `json:"probeId"`
		TaskID  string `json:"taskId"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if probeCenter == nil {
		server.FailBadRequest(w, "中心端未启用")
		return
	}
	if err := probeCenter.CancelTask(in.ProbeID, in.TaskID); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	_, _ = d.ProbeTasks().Finish(in.TaskID, db.ProbeTaskFailed, "", "", "中心端取消", 0, 0)
	logAudit(d, r, "probe.cancel", in.ProbeID, in.TaskID)
	server.OK(w, map[string]any{"cancelled": true})
}

// hProbeDelete DELETE /api/v2/probe/{id} 移除探针登记(在线探针拒删, 避免误操作)。
func hProbeDelete(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	id := r.PathValue("id")
	if probeCenter != nil && probeCenter.Online(id) {
		server.FailBadRequest(w, "探针在线, 请先停止探针进程再移除")
		return
	}
	ok, err := d.Probes().Delete(id)
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	if !ok {
		server.FailNotFound(w, "探针不存在")
		return
	}
	logAudit(d, r, "probe.delete", id, "")
	server.OK(w, map[string]any{"deleted": true})
}

// hProbeTaskList GET /api/v2/probe/tasks 探针任务明细 ?probeId=&status=&page=&size=
func hProbeTaskList(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	q := r.URL.Query()
	page, size := parsePage(q)
	list, err := d.ProbeTasks().List()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	if pid := q.Get("probeId"); pid != "" {
		list, _ = d.ProbeTasks().ByProbe(pid)
	}
	if s := q.Get("status"); s != "" {
		filtered := list[:0]
		for _, t := range list {
			if t.Status == s {
				filtered = append(filtered, t)
			}
		}
		list = filtered
	}
	// 倒序(最新在前)
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	server.OK(w, map[string]any{
		"list": paginate(list, page, size), "total": len(list), "page": page, "size": size,
	})
}

// registerProbeOnce 确保探针框架已初始化(API 首次访问时兜底触发)。
func registerProbeOnce() { instanceProbe() }

// stopProbe 关闭探针框架(中心端监听 + 探针端连接)。
//
// 未启用时 probeCenter/probeClient 均为 nil, 此处自然退化为空操作;
// 关闭失败只记日志, 不阻塞退出流程(退出路径不允许 panic)。
func stopProbe() {
	defer func() {
		if p := recover(); p != nil {
			logLine("probe: 关闭异常(已忽略): " + fmt.Sprint(p))
		}
	}()
	if probeClient != nil {
		probeClient.Stop()
	}
	if probeCenter != nil {
		probeCenter.Stop()
	}
}

// ===== 状态查询(供 /api/info 与状态卡片使用) =====

// probeEnabled 探针框架是否启用(中心端或探针端任一开启)。
func probeEnabled() bool {
	registerProbeOnce()
	return probeCfg.Center.Enabled || probeCfg.Client.Enabled
}

// probeRole 本机在探针框架中的角色, 用于前端展示:
// "center" / "probe" / "center+probe"; 未启用返回空串。
func probeRole() string {
	registerProbeOnce()
	switch {
	case probeCfg.Center.Enabled && probeCfg.Client.Enabled:
		return "center+probe"
	case probeCfg.Center.Enabled:
		return "center"
	case probeCfg.Client.Enabled:
		return "probe"
	}
	return ""
}

// probeOnlineCount 中心端当前在线探针数(未启用中心端时为 0)。
func probeOnlineCount() int {
	registerProbeOnce()
	if probeCenter == nil {
		return 0
	}
	return len(probeCenter.OnlineIDs())
}

// ===== 配置与日志 =====

// probeCfgPath probe.json 路径(exe 同目录)。
// probeCfgPath 探针模块的配置来源路径(展示给运维看"配置在哪改")。
//
// 红线「配置唯一」(2026-09-23 整改): 中心端不再有 probe.json —— 探针中心的
// enabled/listen/token 全部落在 settings.json 的 probe 节, 旧 probe.json 由
// migrateLegacyConfigs 在启动时并入并改名 .migrated。
// 仅分布式 agent 端保留本地 probe.json(红线明确允许)。
func probeCfgPath() string {
	return settingsFilePath()
}

// loadProbeConfig 读探针配置(可选, 缺失/损坏一律默认全关, 不报错)。
//
// 优先取 settings.json 的 probe 节, 回退旧的 probe.json(两者结构完全相同:
// 都是 {center:{...}, client:{...}}) —— 因此解析代码只有一份。
func loadProbeConfig() ProbeConfig {
	data, ok := section(secProbe, "")
	if !ok {
		return ProbeConfig{}
	}
	var cfg ProbeConfig
	if json.Unmarshal(data, &cfg) != nil {
		probeLogLine("probe 配置解析失败, 探针功能保持关闭")
		return ProbeConfig{}
	}
	return cfg
}

// probeLogLine 记录探针日志(并入 yugsight.log, 保留最近 120 条供面板展示)。
//
// 【用途边界 —— 只记"连接与配置类事件"】探针上线/离线、连接失败、配置解析结果这些
// 是用户需要主动感知的状态变化。**数据流量的过程日志一律走 probeFlowLine**,
// 不要用这个函数(理由见 probeFlowLine 的注释)。
func probeLogLine(s string) {
	logLine("分布式探针: " + s)
	probeMu.Lock()
	probeLog = append(probeLog, time.Now().Format("15:04:05")+"  "+s)
	if len(probeLog) > probeLogMax {
		probeLog = probeLog[len(probeLog)-probeLogMax:]
	}
	probeMu.Unlock()
}

// probeFlowLine 记录探针"数据流"日志 —— 只落文件, 不进面板日志。
//
// 【为什么不进面板/主日志】用户提的诉求: "探针传数据之类日志就不要在这显示"。
// 一次探针扫描会回传进度、结果、归一化统计, 每条任务至少产生 3-4 行:
//
//	探针 xxx 任务 xxxx 结果: success (12 条发现)
//	探针 xxx 结果归一化: 资产 5, 漏洞 12(新增 3/重复 9), 过滤 白名单0/误报0
//	探针 xxx 归一化完成, 耗时 42ms
//
// 这些是**过程细节**, 面板上已有任务列表与漏洞页可查; 打在日志里只会把
// "探针上线/离线"这类真正需要立刻看到的事件冲走(和 HTTP 轮询刷屏是同一类问题)。
//
// 【为什么仍要写文件】完全丢弃会让排障时失去线索 —— 真出现"任务成功但漏洞没入库"
// 时, 归一化统计行是唯一能判断"到底入了几条"的依据。所以保留落盘能力, 只是不往
// 用户盯着看的那两个地方推。
func probeFlowLine(s string) {
	logLine("分布式探针: " + s)
}

// probeConnLogLine 中心端日志的分流器: 按内容判定"连接事件"还是"数据流"。
//
// 【为什么需要按内容分流】probe 包通过 SetLogger 注入的是**一个**日志函数, 但它的
// 输出混着两类性质完全不同的信息, 而用户只想要其中一类:
//
//	连接类(要显示): 探针上线 / 探针离线 / 注册被拒 / 心跳超时 / 中心端启动停止
//	数据类(不显示): 探针 x 任务 y 已下发 / 探针 x 任务 y 执行成功
//
// 后两条是任务下发的流水账, 与 probe_api.go 里"任务结果"那条重复, 且面板上
// "探针任务"列表已把每个任务的状态与时间线列得清清楚楚, 日志再报一遍只是噪音。
//
// 【为什么按前缀匹配而不是给 probe 加分类参数】probe 是可独立复用的通信层,
// 不该为了 UI 展示策略去改它的接口(会污染协议层语义, 也让将来单独用 probe 包的
// 场景被迫接受一套"哪些该显示"的业务判断)。日志文案本就是给人看的稳定契约,
// 用前缀匹配来分流成本最低、且改动集中在这一个函数里。
func probeConnLogLine(s string) {
	if probeIsFlowLine(s) {
		probeFlowLine(s)
		return
	}
	probeLogLine(s)
}

// probeIsFlowLine 判定一条中心端日志是否属于"数据流"(只落盘、不进面板)。
//
// 判据: "探针 <标识> 任务 <id> ..." 形态的流水账, 即任务下发与执行结果。
// 抽成独立函数是为了让测试与实现共用同一份判据 —— 否则测试复制一遍字符串匹配规则,
// 两边迟早不一致, 测试就变成了"自我验证"而不是守住实现。
func probeIsFlowLine(s string) bool {
	return strings.HasPrefix(s, "探针 ") && strings.Contains(s, " 任务 ")
}

func probeLogSnapshot() []string {
	probeMu.Lock()
	defer probeMu.Unlock()
	out := make([]string, len(probeLog))
	copy(out, probeLog)
	return out
}

// ===== 小工具 =====

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func truncateText(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "\n...[已截断]"
}

func summarizeFindings(fs []probe.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	var b strings.Builder
	for i, f := range fs {
		if i >= 50 {
			b.WriteString(fmt.Sprintf("...[共 %d 条, 已省略]\n", len(fs)))
			break
		}
		b.WriteString(fmt.Sprintf("[%s] %s %s\n", f.Severity, f.Title, f.Detail))
	}
	return b.String()
}
