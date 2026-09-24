package scheduler

import (
	"strings"
	"sync"
	"time"
)

// ===== 执行节点(中心本地 + 远端探针) =====
//
// 任务书要求: "任务路由到中心本地或远端探针节点; 探针负载过高时, 中心拒绝新任务
// 下发到该节点, 支持任务重分配"。
//
// 本包只维护"调度视角的节点视图"(在线/负载/槽位), 不感知 TCP 连接细节 ——
// 真实在线状态由装配层从 probe 中心端同步进来(见 scheduler_api.go 的 syncNodes)。
// 这样调度器可脱离探针框架单测, 也避免 probe -> scheduler 的反向依赖。

// NodeKind 节点类型。
const (
	NodeLocal = "local" // 中心本地执行
	NodeProbe = "probe" // 远端探针
)

// Node 调度视角的一个执行节点。
type Node struct {
	ID   string `json:"id"`   // ""(或 local) = 中心本地; 其它 = 探针 ID
	Name string `json:"name"` // 展示名
	Kind string `json:"kind"` // local / probe

	Online bool `json:"online"`

	// MaxConcurrency 该节点允许的并发任务数上限(0 = 用全局默认)。
	MaxConcurrency int `json:"maxConcurrency"`

	// 负载指标(探针心跳上报; 中心本地恒为 0)。
	CPUPercent   float64 `json:"cpuPercent"`
	MemPercent   float64 `json:"memPercent"`
	TasksRunning int     `json:"tasksRunning"` // 探针自报的运行中任务数(交叉校验)

	// MaxCPUPercent/MaxMemPercent 负载阈值: 超过即拒绝新任务(0 = 用全局默认)。
	MaxCPUPercent float64 `json:"maxCpuPercent"`
	MaxMemPercent float64 `json:"maxMemPercent"`

	// Capabilities 能力集("portscan,web,host,capture" 等)。
	Capabilities string `json:"capabilities,omitempty"`

	// LastSeen 最近心跳(装配层同步)。
	LastSeen time.Time `json:"lastSeen,omitempty"`

	// running 本调度器分配出去、尚在执行的任务数(与 TasksRunning 是不同口径:
	// 前者是"我们派了多少", 后者是"探针自报在执行多少", 可能有偏差 ——
	// 限流用前者更可控, 后者用于展示与异常检测)。
	running int
}

// RejectReason 拒绝原因(空 = 可接纳)。
type RejectReason struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

// 拒绝码。
const (
	RejectOffline  = "offline"   // 节点离线
	RejectSlots    = "slots"     // 槽位已满
	RejectCPU      = "cpu"       // CPU 负载过高
	RejectMem      = "mem"       // 内存负载过高
	RejectCapacity = "capacity"  // 探针自报任务数达上限
	RejectAbility  = "ability"   // 能力不匹配(如要求抓包但探针无 Npcap)
	RejectUnknown  = "unknown"   // 节点未注册
)

// AcceptConfig 节点接纳判定参数(来自调度配置)。
type AcceptConfig struct {
	DefaultMaxConcurrency int     // 节点未单独配置时的并发上限
	MaxCPUPercent         float64 // CPU 负载阈值(0 = 不判)
	MaxMemPercent         float64 // 内存负载阈值(0 = 不判)
	MaxTasksRunning       int     // 探针自报任务数上限(0 = 不判)
}

// nodeRegistry 节点注册表。
type nodeRegistry struct {
	mu    sync.RWMutex
	nodes map[string]*Node
}

func newNodeRegistry() *nodeRegistry {
	return &nodeRegistry{nodes: make(map[string]*Node)}
}

// Upsert 写入/更新节点信息(装配层同步探针状态时调用)。
//
// 只覆盖"来自外部的事实"字段(在线/负载/能力), **不动 running** ——
// running 是调度器自己派出去的计数, 外部同步不该清零, 否则并发限制失效。
func (r *nodeRegistry) Upsert(n Node) {
	if n.ID == "" {
		n.ID = NodeLocal
	}
	if n.Kind == "" {
		n.Kind = NodeProbe
		if n.ID == NodeLocal {
			n.Kind = NodeLocal
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.nodes[n.ID]
	if !ok {
		cp := n
		r.nodes[n.ID] = &cp
		return
	}
	old.Name = n.Name
	old.Kind = n.Kind
	old.Online = n.Online
	old.CPUPercent = n.CPUPercent
	old.MemPercent = n.MemPercent
	old.TasksRunning = n.TasksRunning
	old.Capabilities = n.Capabilities
	old.LastSeen = n.LastSeen
	if n.MaxConcurrency > 0 {
		old.MaxConcurrency = n.MaxConcurrency
	}
	if n.MaxCPUPercent > 0 {
		old.MaxCPUPercent = n.MaxCPUPercent
	}
	if n.MaxMemPercent > 0 {
		old.MaxMemPercent = n.MaxMemPercent
	}
}

// Remove 摘除节点(探针被删除时调用); 该节点运行中的任务计数一并丢弃。
func (r *nodeRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.nodes, id)
}

// Reset 用给定集合整体替换节点视图(装配层同步探针列表时调用)。
//
// 保留仍存在的节点的 running 计数: 用整体替换而非增删同步, 是因为"探针被删掉
// 又立刻重注册"这种抖动会导致计数错乱; 以 running 为锚点最稳。
func (r *nodeRegistry) Reset(list []Node) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]*Node, len(list)+1)
	for i := range list {
		n := list[i]
		if n.ID == "" {
			n.ID = NodeLocal
		}
		if n.Kind == "" {
			n.Kind = NodeProbe
		}
		if old, ok := r.nodes[n.ID]; ok {
			n.running = old.running
		}
		cp := n
		next[n.ID] = &cp
	}
	if _, ok := next[NodeLocal]; !ok {
		// 未显式给出本地节点: 保留其既有运行计数与并发上限(LocalConcurrency
		// 由 UpdateConfig 写入, 不能被一次探针同步冲掉)
		old, existed := r.nodes[NodeLocal]
		n := &Node{ID: NodeLocal, Name: "中心本地", Kind: NodeLocal, Online: true}
		if existed {
			n.running = old.running
			n.MaxConcurrency = old.MaxConcurrency
		}
		next[NodeLocal] = n
	}
	r.nodes = next
}

// Get 取节点(不存在返回 nil, ok=false)。
func (r *nodeRegistry) Get(id string) (*Node, bool) {
	if id == "" {
		id = NodeLocal
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.nodes[id]
	return n, ok
}

// Snapshot 节点列表快照(含运行中任务数, 已排序: 本地在前, 其它按 ID)。
func (r *nodeRegistry) Snapshot() []NodeView {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]NodeView, 0, len(r.nodes))
	for _, n := range r.nodes {
		out = append(out, NodeView{
			Node:    *n,
			Running: n.running,
			Max:     n.effectiveMax(0),
		})
	}
	sortNodes(out)
	return out
}

// NodeView 节点快照(供前端展示: 含调度器视角的运行数与上限)。
type NodeView struct {
	Node
	Running int `json:"running"` // 调度器已分配但未结束的任务数
	Max     int `json:"max"`     // 生效的并发上限
}

// effectiveMax 节点生效并发上限(0 = 未配置)。
func (n *Node) effectiveMax(def int) int {
	if n.MaxConcurrency > 0 {
		return n.MaxConcurrency
	}
	return def
}

// Accept 判定节点能否再接纳一个任务(返回 nil 表示可以)。
//
// 判定顺序刻意"从硬到软": 离线/不存在 -> 槽位 -> 能力 -> 负载。
// 这样前端能拿到最有信息量的拒绝原因(比如"节点离线"比"CPU 高"更值得优先告知)。
//
// 注意中心本地节点**不套用单节点并发上限**: cfg.DefaultMaxConcurrency
// (= NodeConcurrency) 的存在意义是保护资源受限的探针(边缘网点低配机),
// 中心本地的并发规模由全局 MaxConcurrency 表达。若本地也套 NodeConcurrency,
// 默认配置(NodeConcurrency=1)下全局并发永远只能到 1, "支持全局最大并发数
// 限制"这条需求就形同虚设 —— 且用户会以为是自己配置写错了。
func (r *nodeRegistry) Accept(id, kind string, needCapture bool, cfg AcceptConfig) *RejectReason {
	if id == "" {
		id = NodeLocal
	}
	r.mu.RLock()
	n, ok := r.nodes[id]
	r.mu.RUnlock()
	if !ok {
		return &RejectReason{Code: RejectUnknown, Msg: "执行节点未注册: " + id}
	}
	if !n.Online {
		return &RejectReason{Code: RejectOffline, Msg: "执行节点离线: " + id}
	}
	max := n.effectiveMax(cfg.DefaultMaxConcurrency)
	if n.Kind == NodeLocal && n.MaxConcurrency <= 0 {
		max = 0 // 本地节点未显式配置 -> 只受全局并发约束
	}
	if max > 0 && n.running >= max {
		return &RejectReason{Code: RejectSlots,
			Msg: nodeLabel(n) + " 并发槽位已满(" + itoa(n.running) + "/" + itoa(max) + "), 任务保持排队"}
	}
	// 能力校验: 要求抓包但节点没有 capture 能力 -> 提前拒绝, 下发过去也只会失败
	if needCapture && n.Kind == NodeProbe && n.Capabilities != "" &&
		!hasCapability(n.Capabilities, "capture") {
		return &RejectReason{Code: RejectAbility,
			Msg: nodeLabel(n) + " 不支持抓包(未安装 Npcap), 无法执行该任务"}
	}
	cpuMax := n.MaxCPUPercent
	if cpuMax <= 0 {
		cpuMax = cfg.MaxCPUPercent
	}
	if cpuMax > 0 && n.CPUPercent >= cpuMax {
		return &RejectReason{Code: RejectCPU,
			Msg: nodeLabel(n) + " CPU 负载过高(" + ftoa(n.CPUPercent) + "% ≥ " + ftoa(cpuMax) + "%), 中心端暂不下发"}
	}
	memMax := n.MaxMemPercent
	if memMax <= 0 {
		memMax = cfg.MaxMemPercent
	}
	if memMax > 0 && n.MemPercent >= memMax {
		return &RejectReason{Code: RejectMem,
			Msg: nodeLabel(n) + " 内存负载过高(" + ftoa(n.MemPercent) + "% ≥ " + ftoa(memMax) + "%), 中心端暂不下发"}
	}
	if cfg.MaxTasksRunning > 0 && n.TasksRunning >= cfg.MaxTasksRunning {
		return &RejectReason{Code: RejectCapacity,
			Msg: nodeLabel(n) + " 自报运行任务数已达上限(" + itoa(n.TasksRunning) + "), 暂不下发"}
	}
	return nil
}

// canAccept 是 Accept 的布尔封装(调度循环用, 不关心原因)。
func (r *nodeRegistry) canAccept(id, kind string, needCapture bool, cfg AcceptConfig) bool {
	return r.Accept(id, kind, needCapture, cfg) == nil
}

// incRunning / decRunning 维护节点运行计数(调度器派发/回收时调用)。
func (r *nodeRegistry) incRunning(id string) {
	if id == "" {
		id = NodeLocal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.nodes[id]; ok {
		n.running++
	}
}

func (r *nodeRegistry) decRunning(id string) {
	if id == "" {
		id = NodeLocal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.nodes[id]; ok && n.running > 0 {
		n.running--
	}
}

// RecommendNode 在候选节点里挑一个"最空闲"的探针(负载均衡 + 重分配用)。
//
// 打分: 运行中任务数占比最低者优先; 占比相同取 CPU 低者; 仍相同取 ID 字典序
// (保证结果稳定可测)。
func (r *nodeRegistry) RecommendNode(cfg AcceptConfig, needCapture bool, exclude map[string]bool) (string, *RejectReason) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var best *Node
	bestScore := 0.0
	for _, n := range r.nodes {
		if n.Kind == NodeLocal || exclude[n.ID] {
			continue
		}
		if !n.Online {
			continue
		}
		max := n.effectiveMax(cfg.DefaultMaxConcurrency)
		score := 0.0
		if max > 0 {
			score = float64(n.running) / float64(max)
		}
		if best == nil || score < bestScore || (score == bestScore && n.CPUPercent < best.CPUPercent) ||
			(score == bestScore && n.CPUPercent == best.CPUPercent && n.ID < best.ID) {
			best = n
			bestScore = score
		}
	}
	if best == nil {
		return "", &RejectReason{Code: RejectUnknown, Msg: "无在线探针节点可用"}
	}
	if rej := r.acceptLocked(best, needCapture, cfg); rej != nil {
		return "", rej
	}
	return best.ID, nil
}

// acceptLocked 与 Accept 同逻辑, 但假定调用方已持读锁。
func (r *nodeRegistry) acceptLocked(n *Node, needCapture bool, cfg AcceptConfig) *RejectReason {
	if !n.Online {
		return &RejectReason{Code: RejectOffline, Msg: "执行节点离线: " + n.ID}
	}
	max := n.effectiveMax(cfg.DefaultMaxConcurrency)
	if n.Kind == NodeLocal && n.MaxConcurrency <= 0 {
		max = 0 // 本地节点只受全局并发约束(理由见 Accept)
	}
	if max > 0 && n.running >= max {
		return &RejectReason{Code: RejectSlots,
			Msg: nodeLabel(n) + " 并发槽位已满(" + itoa(n.running) + "/" + itoa(max) + ")"}
	}
	if needCapture && n.Capabilities != "" && !hasCapability(n.Capabilities, "capture") {
		return &RejectReason{Code: RejectAbility, Msg: nodeLabel(n) + " 不支持抓包"}
	}
	cpuMax := n.MaxCPUPercent
	if cpuMax <= 0 {
		cpuMax = cfg.MaxCPUPercent
	}
	if cpuMax > 0 && n.CPUPercent >= cpuMax {
		return &RejectReason{Code: RejectCPU, Msg: nodeLabel(n) + " CPU 负载过高"}
	}
	memMax := n.MaxMemPercent
	if memMax <= 0 {
		memMax = cfg.MaxMemPercent
	}
	if memMax > 0 && n.MemPercent >= memMax {
		return &RejectReason{Code: RejectMem, Msg: nodeLabel(n) + " 内存负载过高"}
	}
	if cfg.MaxTasksRunning > 0 && n.TasksRunning >= cfg.MaxTasksRunning {
		return &RejectReason{Code: RejectCapacity, Msg: nodeLabel(n) + " 自报任务数达上限"}
	}
	return nil
}

// hasCapability 能力串包含判断(逗号分隔, 大小写不敏感)。
func hasCapability(caps, want string) bool {
	for _, c := range strings.Split(caps, ",") {
		if strings.EqualFold(strings.TrimSpace(c), want) {
			return true
		}
	}
	return false
}

func nodeLabel(n *Node) string {
	if n.Name != "" {
		return n.Name + "(" + n.ID + ")"
	}
	return n.ID
}

// sortNodes 本地节点排最前, 其余按 ID。
func sortNodes(list []NodeView) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0; j-- {
			a, b := list[j-1], list[j]
			if lessNode(a, b) {
				break
			}
			list[j-1], list[j] = list[j], list[j-1]
		}
	}
}

func lessNode(a, b NodeView) bool {
	if a.Kind != b.Kind {
		return a.Kind == NodeLocal
	}
	return a.ID < b.ID
}
