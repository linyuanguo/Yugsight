// Package scheduler 扫描任务队列调度模块(任务 7.1)。
//
// 定位: 在既有扫描能力(handleScan 本地执行 / probe 中心端下发)之上加一层
// **队列编排层** —— 解决"多用户并发提交任务"时无人管控的问题。
//
// 依赖边界(关键): 只依赖 Go 标准库 + models。
//
//	不 import db / probe / scanner / normalizer —— 调度器只做"排队 + 限流 +
//	路由决策 + 状态机", 真正执行由装配层(scheduler_api.go)经 ExecFunc 回调注入。
//	这样调度器可以完全脱离真实网络与数据库单元测试(与 engine/parsers 的
//	ExecFunc 注入同一设计思路, 避免包循环依赖)。
//
// 能力:
//
//	1. 多任务排队: 无界 FIFO 队列 + 优先级(数字越小越先), 同优先级按提交时间
//	2. 双层并发限制: 全局最大并发 + 单节点(探针)最大并发
//	3. 内置扫描策略模板: 快速存活探测 / 完整资产审计 / 深度 Web 漏洞扫描
//	4. 网段发包限速: 源网段维度令牌桶, 支持不同网段不同速率, 超速阻塞等待
//	5. 完整状态流转: queued -> running -> paused -> cancelled / success / failed
//	6. 分布式探针适配: 节点负载过高拒绝新任务 + 失败/离线任务自动重分配
//
// 默认启用(2026-09-20 起): 开箱即用, 带 queue=true 的提交直接入队; 普通
// /api/scan 仍走即时执行路径(语义不变)。需关闭时在 settings.json 的 scheduler
// 节显式写 enabled=false。
package scheduler

import (
	"errors"
	"time"
)

// ===== 任务状态机 =====
//
// 与 db.ScanTask 的既有常量(pending/running/success/failed/cancelled)保持兼容,
// 另外新增 paused(暂停) —— 任务书要求的六态完整流转:
//
//	queued(等待) → running(运行) → success(完成) / failed(失败)
//	                  ↓    ↑
//	               paused(暂停)
//	                  ↓
//	              cancelled(取消)
//
// 命名用 queued 而非 pending 的原因: pending 在既有 db 层表示"已创建待执行",
// 而队列里的"等待"是"已确认执行、正在排队等资源", 两者语义不同 —— 混用会让
// 前端把"排队中"误显示为"待执行"。装配层落库时做 queued<->pending 的双向映射
// (见 scheduler_api.go 的 dbStatusOf / queueStatusOf)。
const (
	StatusQueued    = "queued"    // 等待(排队中, 尚未拿到执行资源)
	StatusRunning   = "running"   // 运行中
	StatusPaused    = "paused"    // 已暂停(释放执行槽位, 保留进度, 支持续扫)
	StatusCancelled = "cancelled" // 已取消(用户主动)
	StatusSuccess   = "success"   // 已完成
	StatusFailed    = "failed"    // 已失败(执行报错/节点离线/超时)
)

// ErrUnknownStatus 状态流转非法(如已完成的任务再置运行)。
var ErrUnknownStatus = errors.New("scheduler: 非法状态")

// ErrQueueFull 队列已满(配置了 MaxQueue > 0 时可能发生)。
var ErrQueueFull = errors.New("scheduler: 任务队列已满")

// ErrNotFound 任务不存在。
var ErrNotFound = errors.New("scheduler: 任务不存在")

// Scheduler 调度器未启用(配置 enabled=false)。
var ErrDisabled = errors.New("scheduler: 任务调度未启用")

// ErrNoNode 无可接纳任务的执行节点(探针负载过高或全部离线)。
var ErrNoNode = errors.New("scheduler: 无可用执行节点")

// Terminal 是否为终态(终态任务不再被调度, 也不允许再流转)。
func Terminal(status string) bool {
	switch status {
	case StatusSuccess, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// Active 是否为"占用执行资源"的状态(用于并发统计与暂停释放)。
func Active(status string) bool {
	return status == StatusRunning
}

// ===== 任务实体 =====

// Task 一个被调度的扫描任务。
//
// 字段分三组: 调度控制(策略/节点/优先级/限速) + 执行参数(Params) + 运行时状态。
type Task struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // ip | alive | port | web | host
	// Target 展示用目标(网段/IP/URL), 与 Params 里的具体字段保持一致口径。
	Target   string `json:"target"`
	Strategy string `json:"strategy"`           // 策略模板 ID(quick/alive/audit/webdeep/custom)
	Params   Params `json:"params"`             // 扫描参数(策略模板展开后的最终值)
	Node     string `json:"node"`               // 执行节点: "" = 中心本地, 其它 = 探针 ID
	Priority int    `json:"priority"`           // 优先级(数字越小越先; 0 为默认档)
	Status   string `json:"status"`             // 见上方状态常量
	Progress string `json:"progress,omitempty"` // 最近一条进度(一句话)
	Result   string `json:"result,omitempty"`   // 结果摘要 / 失败原因
	Err      string `json:"err,omitempty"`      // 失败原因(原始, 供排障)

	CreatedBy string    `json:"createdBy,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	QueueAt   time.Time `json:"queueAt,omitempty"` // 入队时间(算排队耗时)
	StartAt   time.Time `json:"startAt,omitempty"`
	EndAt     time.Time `json:"endAt,omitempty"`

	// Attempts 已尝试次数(含重分配); MaxAttempts 上限, 0 取配置默认。
	Attempts    int `json:"attempts,omitempty"`
	MaxAttempts int `json:"maxAttempts,omitempty"`

	// AutoRetry 节点离线/执行失败时是否允许换节点重试(任务书: 支持任务重分配)。
	AutoRetry bool `json:"autoRetry,omitempty"`
	// ResumeOnPause 续扫语义: 暂停后恢复时是否从头开始(默认 false = 续扫)。
	//
	// 内置扫描器(端口/存活)是无状态多目标遍历, 真正的"断点续扫"需要引擎侧
	// 记录已完成目标集。本调度层提供 ResumeDone 字段承载这个进度, 并在恢复时
	// 通过 Params.Skip 传给执行器 —— 执行器支持则续扫, 不支持则等价于重跑。
	ResumeDone []string `json:"resumeDone,omitempty"`

	// QueuedMs/RunMs 耗时统计(前端展示排队与执行各自耗时)。
	QueuedMs int64 `json:"queuedMs,omitempty"`
	RunMs    int64 `json:"runMs,omitempty"`
}

// Params 扫描参数(用户自定义参数 + 策略模板展开)。
//
// 字段刻意与 probe/scanner.OptionsFromArgs 及 /api/scan 的 scanReq 对齐,
// 这样本地执行与探针下发可以共用同一份参数体, 不需要两套映射。
type Params struct {
	Target  string `json:"target,omitempty"`  // CIDR / IP / URL(策略展开后的真实目标)
	IP      string `json:"ip,omitempty"`      // port/host 类型的单 IP
	CIDR    string `json:"cidr,omitempty"`    // ip/alive 类型的网段
	URL     string `json:"url,omitempty"`     // web 类型的目标 URL
	Ports   string `json:"ports,omitempty"`   // 端口范围 "22,80,443" / "1-1024"
	Timeout int    `json:"timeoutMs,omitempty"`
	// Concurrency 单任务并发度(连接数)。注意与"发包速率"是两个维度:
	// 并发高但速率低时, 表现为"很快发起但被限速拖住"。
	Concurrency int `json:"concurrency,omitempty"`
	// Rate 本任务所在网段的发包速率上限(包/秒), 0 = 不限速。实际限速值
	// 由 RateLimiter 按"源网段"取配置, 此处仅保留任务自身意愿值(便于展示)。
	Rate int `json:"rate,omitempty"`

	EnableNuclei      bool   `json:"enableNuclei,omitempty"`
	NucleiTags        string `json:"nucleiTags,omitempty"`
	NucleiTagsExclude string `json:"nucleiTagsExclude,omitempty"`
	EnableArp         *bool  `json:"enableArp,omitempty"`
	EnableExternal    *bool  `json:"enableExternal,omitempty"`
	EnableSynScan     bool   `json:"enableSynScan,omitempty"` // SYN 扫描(需探针端 Npcap + nmapcore)
	Capture           bool   `json:"capture,omitempty"`        // 抓包采集
	CaptureDevice     string `json:"captureDevice,omitempty"`
	CaptureFilter     string `json:"captureFilter,omitempty"`
	CaptureMaxBytes   int64  `json:"captureMaxBytes,omitempty"`

	// Skip 续扫时跳过的目标(已完成集合), 由调度层在恢复时填充。
	Skip []string `json:"skip,omitempty"`

	// AliveMode 存活判定模式(仅 ip/unified 类型有效): strict/loose/none, 空值=loose。
	AliveMode string `json:"aliveMode,omitempty"`

	// WebDeep Web 深度扫描(仅 web 类型有效): 开启后追加同源爬虫 + POST +
	// 多类型注入探测。默认 false —— 请求量远大于单 URL 扫描, 需显式开启。
	WebDeep bool `json:"webdeep,omitempty"`
}

// ===== 事件 =====

// EventType 调度事件类型(SSE 广播 + 前端实时面板)。
const (
	EventQueued    = "queued"
	EventStarted   = "started"
	EventProgress  = "progress"
	EventPaused    = "paused"
	EventResumed   = "resumed"
	EventCancelled = "cancelled"
	EventDone      = "done"
	EventReassign  = "reassign"
	EventRejected  = "rejected" // 探针负载过高拒绝新任务
)

// Event 一次调度事件。
type Event struct {
	Type   string    `json:"type"`
	TaskID string    `json:"taskId,omitempty"`
	Kind   string    `json:"kind,omitempty"`
	Target string    `json:"target,omitempty"`
	Node   string    `json:"node,omitempty"`
	Msg    string    `json:"msg,omitempty"`
	Time   time.Time `json:"time"`
}
