package db

import (
	"errors"
	"strings"
	"time"
)

// 探针任务状态常量: 与中心端 probe.TaskXxx 状态机同口径。
const (
	ProbeTaskPending = "pending" // 已创建待下发
	ProbeTaskSent    = "sent"    // 已下发待确认
	ProbeTaskRunning = "running" // 探针执行中
	ProbeTaskSuccess = "success" // 执行成功
	ProbeTaskFailed  = "failed"  // 执行失败
)

// ProbeTask 探针任务表实体(任务 6.3 分布式扫描)。
//
// 与 ScanTask 的分工:
//   - ScanTask  = 中心端统一任务视图(本地执行 / 远端执行都在此登记, ProbeNode 标记归属);
//   - ProbeTask = 下发链路明细(下发时间/确认/进度/结果原始输出), 一个 ScanTask 对应 0..1 条。
//
// 记录探针执行全生命周期, 用于"任务下发 -> 探针执行 -> 结果回传"的链路追踪与重派判断。
type ProbeTask struct {
	ID         string     `json:"id"`        // 任务 ID(与 ScanTask.ID 一致, 便于关联跳转)
	ProbeNode  string     `json:"probeNode"` // 目标探针 ID
	Kind       string     `json:"kind"`      // ip|port|web|host
	Target     string     `json:"target"`
	Status     string     `json:"status"`
	Progress   string     `json:"progress,omitempty"` // 最近进度(一句话)
	Summary    string     `json:"summary,omitempty"`  // 结果摘要
	Result     string     `json:"result,omitempty"`   // 结果详情(截断后原文, 便于排查)
	Error      string     `json:"error,omitempty"`
	FindingNum int        `json:"findingNum,omitempty"` // 发现条目数
	SentAt     *time.Time `json:"sentAt,omitempty"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	DurationMs int64      `json:"durationMs,omitempty"`
	CreatedBy  string     `json:"createdBy,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// EntityID 任务 ID。
func (t *ProbeTask) EntityID() string {
	if t.ID == "" {
		t.ID = newID("pt")
	}
	return t.ID
}

// Validate 自检: 探针/类型/目标必填, 状态默认 pending。
func (t *ProbeTask) Validate() error {
	if strings.TrimSpace(t.ProbeNode) == "" {
		return errors.New("探针节点不能为空")
	}
	if strings.TrimSpace(t.Kind) == "" {
		return errors.New("扫描类型不能为空")
	}
	if strings.TrimSpace(t.Target) == "" {
		return errors.New("扫描目标不能为空")
	}
	t.ProbeNode = strings.TrimSpace(t.ProbeNode)
	t.Target = strings.TrimSpace(t.Target)
	if t.Status == "" {
		t.Status = ProbeTaskPending
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	return nil
}

// ProbeTaskDAO 探针任务 DAO。
type ProbeTaskDAO struct {
	*Table[*ProbeTask]
}

// newProbeTaskTable 打开探针任务表。
func newProbeTaskTable(path string) (*ProbeTaskDAO, error) {
	t, err := NewTable[*ProbeTask]("probe_tasks", path, func() *ProbeTask { return &ProbeTask{} })
	if err != nil {
		return nil, err
	}
	return &ProbeTaskDAO{Table: t}, nil
}

// MarkSent 标记已下发(置 sent + 下发时间)。
func (d *ProbeTaskDAO) MarkSent(id string) (*ProbeTask, error) {
	t, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	t.Status = ProbeTaskSent
	t.SentAt = &now
	if err := d.Update(t); err != nil {
		return t, err
	}
	return t, nil
}

// MarkRunning 标记执行中(探针首次回进度/确认执行时调用)。
func (d *ProbeTaskDAO) MarkRunning(id, progress string) (*ProbeTask, error) {
	t, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if t.Status != ProbeTaskRunning {
		t.Status = ProbeTaskRunning
		t.StartedAt = &now
	}
	if progress != "" {
		t.Progress = progress
	}
	if err := d.Update(t); err != nil {
		return t, err
	}
	return t, nil
}

// SetProgress 更新进度(不改变状态)。
func (d *ProbeTaskDAO) SetProgress(id, progress string) (*ProbeTask, error) {
	t, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	t.Progress = progress
	if err := d.Update(t); err != nil {
		return t, err
	}
	return t, nil
}

// Finish 结束任务(成功/失败), 记录摘要与耗时。
func (d *ProbeTaskDAO) Finish(id, status, summary, result, errMsg string, findings int, durationMs int64) (*ProbeTask, error) {
	t, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	if status == "" {
		status = ProbeTaskSuccess
	}
	now := time.Now()
	t.Status = status
	t.Summary = summary
	t.Result = result
	t.Error = errMsg
	t.FindingNum = findings
	t.DurationMs = durationMs
	t.FinishedAt = &now
	if t.StartedAt == nil {
		t.StartedAt = &now
	}
	if err := d.Update(t); err != nil {
		return t, err
	}
	return t, nil
}

// ByProbe 查某探针的任务。
func (d *ProbeTaskDAO) ByProbe(probeID string) ([]*ProbeTask, error) {
	return d.Query(func(t *ProbeTask) bool { return t.ProbeNode == probeID })
}

// ByStatus 按状态查任务。
func (d *ProbeTaskDAO) ByStatus(status string) ([]*ProbeTask, error) {
	return d.Query(func(t *ProbeTask) bool { return t.Status == status })
}

// Unfinished 未完成任务(pending/sent/running), 用于探针离线后重派判断。
func (d *ProbeTaskDAO) Unfinished() ([]*ProbeTask, error) {
	return d.Query(func(t *ProbeTask) bool {
		switch t.Status {
		case ProbeTaskPending, ProbeTaskSent, ProbeTaskRunning:
			return true
		}
		return false
	})
}
