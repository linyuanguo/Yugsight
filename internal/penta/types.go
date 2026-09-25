// Package penta 渗透工作台(阶段 5): 针对已知漏洞的轻量验证引擎。
//
// 职责隔离(改动前必读, 与项目"扫描不利用、利用只验证"的分界对齐):
//
//   - 扫描模块(scanner/engine/weakpass)只做广谱探测发现漏洞, 不做漏洞利用;
//   - 本包只对漏洞管理里**已登记的已知漏洞**做可利用性验证, 不做广谱扫描;
//   - 模板是数据不是代码: 内置/导入的"EXP"全部是验证探针
//     (HTTP 请求 / TCP 协议交互 / 弱口令登录试探 / 可选外部引擎),
//     不含破坏性载荷与 shellcode。"可利用"的结论仅表示
//     "漏洞行为被实际观测到"(如未授权访问成立), 不代表做了进一步渗透。
//
// 权限与审计(装配层 penta_api.go 强制, 本包不重复):
//
//   - 全部接口仅 admin 角色可访问(operator/auditor 无入口无权限);
//   - 每次执行与每一步探测写审计日志(action 前缀 penta.*), 审计 DAO 层面对
//     penta.* 记录不可删除(合规要求: 全程留痕、不可删除);
//   - 每次执行前用户必须在界面上勾选授权确认(仅可对授权目标使用)。
package penta

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// ===== 任务状态 =====

const (
	TaskPending = "pending" // 待执行
	TaskRunning = "running" // 执行中
	TaskDone    = "done"    // 完成(有验证结论)
	TaskFailed  = "failed"  // 失败(无法得出验证结论, 如目标不可达)
)

// TaskStatusName 状态中文名。
func TaskStatusName(s string) string {
	switch s {
	case TaskPending:
		return "待执行"
	case TaskRunning:
		return "执行中"
	case TaskDone:
		return "完成"
	case TaskFailed:
		return "失败"
	}
	if s == "" {
		return "待执行"
	}
	return s
}

// ===== 可利用性结论(三态口径) =====

const (
	Exploitable      = "exploitable"       // 可利用: 全部验证步骤命中
	Partial          = "partial"           // 部分利用: 部分步骤命中
	NotExploitable   = "not_exploitable"   // 不可利用: 步骤均执行但无命中
)

// ExploitabilityName 结论中文名。
func ExploitabilityName(s string) string {
	switch s {
	case Exploitable:
		return "可利用"
	case Partial:
		return "部分利用"
	case NotExploitable:
		return "不可利用"
	}
	if s == "" {
		return "未验证"
	}
	return s
}

// ===== 步骤类型 =====

const (
	StepHTTP     = "http"     // HTTP 请求探针(状态码/响应体/响应头断言)
	StepTCP      = "tcp"      // TCP 协议交互探针(发送字节 + 响应正则断言)
	StepWeakPass = "weakpass" // 弱口令登录试探(复用 weakpass 包, 只试登录不注入)
	StepExternal = "external" // 外部渗透引擎(可选, 调用 bin/ 下的用户自备引擎)
)

// 单步超时与输出上限(防止单个探针拖垮整次执行 / 把证据撑爆存储)。
const (
	defaultStepTimeout = 10 * time.Second
	maxStepTimeout     = 120 * time.Second
	maxStepOutput      = 2048  // 每步输出片段上限(字节)
	maxStepEvidence    = 4096  // 每步请求/响应证据上限(字节)
	maxRunLog          = 100000 // 整次执行日志上限(字节, 超限截断)
	maxPasswords       = 10 // 弱口令试探单步口令数上限(验证场景非爆破)
)

// StepSpec 模板中的单个验证步骤。
//
// 全部字段都是"观测型"参数: 发什么、期待什么响应。没有"执行命令"这类
// 破坏性字段 —— 命令执行回显需求由 weakpass(登录态验证)与 external
// (用户自备引擎, 风险自担)两条受控通道覆盖。
type StepSpec struct {
	Name string `json:"name" yaml:"name"`
	Type string `json:"type" yaml:"type"`

	// Host 目标主机; 支持占位符 {target}/{port}/{cve}(空 = 用任务目标)
	Host string `json:"host,omitempty" yaml:"host"`
	// Port 端口(空 = 用任务端口)
	Port int `json:"port,omitempty" yaml:"port"`
	// TimeoutMs 单步超时(0 = 10s, 上限 120s)
	TimeoutMs int `json:"timeoutMs,omitempty" yaml:"timeoutMs"`

	// ---- http ----
	Method       string            `json:"method,omitempty" yaml:"method"` // GET/POST/... 默认 GET
	Path         string            `json:"path,omitempty" yaml:"path"`     // 默认 /
	Headers      map[string]string `json:"headers,omitempty" yaml:"headers"`
	ExpectStatus int               `json:"expectStatus,omitempty" yaml:"expectStatus"` // 0 = 不校验状态码
	ExpectBody   string            `json:"expectBody,omitempty" yaml:"expectBody"`     // 响应体正则, 空 = 不校验
	ExpectHeader map[string]string `json:"expectHeader,omitempty" yaml:"expectHeader"` // 头名 -> 正则

	// ---- tcp ----
	Send   string `json:"send,omitempty" yaml:"send"`   // 发送的原始字节
	Expect string `json:"expect,omitempty" yaml:"expect"` // 响应正则, 空 = 连接成功即命中

	// ---- weakpass ----
	Service   string   `json:"service,omitempty" yaml:"service"` // redis/ftp/ssh/...
	User      string   `json:"user,omitempty" yaml:"user"`
	Passwords []string `json:"passwords,omitempty" yaml:"passwords"` // 显式给定口令(≤10), 空 = 空口令/免认证试探

	// ---- external ----
	Bin  string   `json:"bin,omitempty" yaml:"bin"`  // bin/ 目录下的引擎名前缀
	Args []string `json:"args,omitempty" yaml:"args"` // 参数, 支持占位符
}

// Template EXP 模板(数据驱动)。
type Template struct {
	ID          string     `json:"id" yaml:"id"`
	Name        string     `json:"name" yaml:"name"`
	CVE         string     `json:"cve,omitempty" yaml:"cve"`
	Tags        []string   `json:"tags,omitempty" yaml:"tags"`
	Description string     `json:"description,omitempty" yaml:"description"`
	// BuiltIn 内置模板(不可覆盖; 自定义导入的同 ID 会被拒绝)
	BuiltIn bool `json:"builtin,omitempty" yaml:"builtin"`
	Steps   []StepSpec `json:"steps" yaml:"steps"`
}

// StepResult 单步执行结果(留存为任务证据)。
type StepResult struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Hit        bool   `json:"hit"`
	Output     string `json:"output,omitempty"`     // 输出片段(截断)
	Evidence   string `json:"evidence,omitempty"`   // 请求/响应证据(截断)
	Err        string `json:"err,omitempty"`        // 执行错误(区别于"未命中")
	DurationMs int64  `json:"durationMs"`
}

// RunOutcome 一次执行的完整结果。
type RunOutcome struct {
	OK             bool         `json:"ok"` // 是否完成到可下结论(目标不可达 = false)
	Steps          []StepResult `json:"steps"`
	Exploitability string       `json:"exploitability"` // 三态结论(不可达时为空)
	Summary        string       `json:"summary"`
	Log            string       `json:"log,omitempty"` // 全程日志(截断)
}

// Task 渗透任务(与 db.PentaTask 实体对应, 内嵌保数据契约一致)。
type Task struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	// Target 目标主机(IP); 域名由调用方自行解析, 与 weakpass 同口径
	Target   string `json:"target"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // tcp/http/https/...
	// VulnID 关联的漏洞管理条目 ID(从漏扫管控导入时回填; 手动建任务可空)
	VulnID   string `json:"vulnId,omitempty"`
	CVE      string `json:"cve,omitempty"`
	Title    string `json:"title,omitempty"` // 漏洞名称(展示与报告用)
	Source   string `json:"source,omitempty"` // manual | vuln
	Status   string `json:"status"`
	TemplateID string `json:"templateId,omitempty"`

	// Exploitability 可利用性结论(执行完成后回填; 空 = 未验证)
	Exploitability string `json:"exploitability,omitempty"`
	// RiskLevel 风险等级: 初始 = 来源漏洞等级, 验证后可人工修正(空 = 未修正)
	RiskLevel  string `json:"riskLevel,omitempty"`
	Summary    string `json:"summary,omitempty"`
	Note       string `json:"note,omitempty"`
	Evidence   []StepResult `json:"evidence,omitempty"`
	RunLog     string `json:"runLog,omitempty"`

	// FeedbackAt 结果回传漏洞管理的时间(空 = 未回传)
	FeedbackAt time.Time `json:"feedbackAt,omitempty"`

	Operator   string    `json:"operator,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	StartedAt  time.Time `json:"startedAt,omitempty"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
}

// NewTaskID 任务 ID: 时间戳 + 随机后缀(同秒并发不碰撞)。
func NewTaskID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return "pt_" + time.Now().Format("20060102150405") + "_" + hex.EncodeToString(b)
}

// Validate 自检: 目标必填, 缺省字段补全。
func (t *Task) Validate() error {
	if strings.TrimSpace(t.Target) == "" {
		return errors.New("渗透任务目标不能为空")
	}
	if t.Port < 0 || t.Port > 65535 {
		return errors.New("端口超出范围(0-65535)")
	}
	if t.ID == "" {
		t.ID = NewTaskID()
	}
	if t.Status == "" {
		t.Status = TaskPending
	}
	if t.Source == "" {
		t.Source = "manual"
	}
	if t.Name == "" {
		t.Name = "渗透任务 " + t.Target
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	return nil
}
