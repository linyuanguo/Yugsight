package db

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// 扫描任务状态常量。
const (
	TaskPending   = "pending"   // 已创建待执行
	TaskRunning   = "running"   // 执行中
	TaskSuccess   = "success"   // 执行成功
	TaskFailed    = "failed"    // 执行失败
	TaskCancelled = "cancelled" // 已取消
)

// ScanTask 扫描任务表实体。
// 中心管理端任务模型: Linux 环境下不建议本地执行抓包 / SYN 扫描,
// 这类任务经 ProbeNode 字段下发远端探针执行(探针管理表联动)。
type ScanTask struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"` // ip|port|web|host
	Target     string          `json:"target"`
	Params     json.RawMessage `json:"params,omitempty"` // 扫描参数(原样保存)
	Status     string          `json:"status"`
	Result     string          `json:"result,omitempty"` // 结果摘要
	CreatedBy  string          `json:"createdBy,omitempty"`
	ProbeNode  string          `json:"probeNode,omitempty"` // 远端探针 ID(空 = 本地执行)
	CreatedAt  time.Time       `json:"createdAt"`
	StartedAt  *time.Time      `json:"startedAt,omitempty"`
	FinishedAt *time.Time      `json:"finishedAt,omitempty"`
}

// EntityID 任务 ID。
func (t *ScanTask) EntityID() string {
	if t.ID == "" {
		t.ID = newID("st")
	}
	return t.ID
}

// Validate 自检: 类型/目标必填, 状态默认 pending。
func (t *ScanTask) Validate() error {
	if t.Type == "" {
		return errors.New("扫描类型不能为空")
	}
	if strings.TrimSpace(t.Target) == "" {
		return errors.New("扫描目标不能为空")
	}
	t.Target = strings.TrimSpace(t.Target)
	if t.Status == "" {
		t.Status = TaskPending
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	return nil
}

// ScanTaskDAO 扫描任务 DAO: 基础 CRUD + 状态流转 + 按状态查询。
type ScanTaskDAO struct {
	*Table[*ScanTask]
}

// newScanTaskTable 打开扫描任务表。
func newScanTaskTable(path string) (*ScanTaskDAO, error) {
	t, err := NewTable[*ScanTask]("scan_tasks", path, func() *ScanTask { return &ScanTask{} })
	if err != nil {
		return nil, err
	}
	return &ScanTaskDAO{Table: t}, nil
}

// UpdateStatus 状态流转(自动补 startedAt/finishedAt)。
func (d *ScanTaskDAO) UpdateStatus(id, status, result string) (*ScanTask, error) {
	t, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	t.Status = status
	if result != "" {
		t.Result = result
	}
	now := time.Now()
	switch status {
	case TaskRunning:
		if t.StartedAt == nil {
			t.StartedAt = &now
		}
	case TaskSuccess, TaskFailed, TaskCancelled:
		t.FinishedAt = &now
	}
	if err := d.Update(t); err != nil {
		return t, err
	}
	return t, nil
}

// ByStatus 按状态查任务。
func (d *ScanTaskDAO) ByStatus(status string) ([]*ScanTask, error) {
	return d.Query(func(t *ScanTask) bool { return t.Status == status })
}

// Active 运行中的任务(pending + running)。
// 大屏"当前运行任务数"用这个口径: 只算 running 会让"已排队还没起跑"的任务从
// 大屏上消失, 运维看到的现象是"提交了任务大屏却没反应"。
func (d *ScanTaskDAO) Active() ([]*ScanTask, error) {
	return d.Query(func(t *ScanTask) bool {
		return t.Status == TaskRunning || t.Status == TaskPending
	})
}

// CountByStatus 按状态统计任务数量, 返回值一定覆盖五个状态键(缺失补 0)。
// CountBy 单遍统计不拷贝实体(大屏轮询只需要计数)。
func (d *ScanTaskDAO) CountByStatus() (map[string]int, error) {
	out := map[string]int{
		TaskPending: 0, TaskRunning: 0, TaskSuccess: 0, TaskFailed: 0, TaskCancelled: 0,
	}
	counts, err := d.CountBy(func(t *ScanTask) string { return t.Status })
	if err != nil {
		return out, err
	}
	for k, v := range counts {
		out[k] = v
	}
	return out, nil
}

// DeleteAll 清空全部扫描任务记录(集合级清理, 返回删除条数)。
//
// 与 VulnDAO.DeleteAll 同口径: 走 Table.Clear 一次落盘, 不用循环 Delete
// (那是 O(N^2) 写盘)。只清任务表, 不动资产/漏洞/探针任务明细 —— 用户清的是
// "历史任务列表", 顺手删掉别的表会让排障数据一起消失。
//
// DAO 为 nil(库已关闭)时返回 0 而不是 panic: 这是页面上的清理动作,
// 不该因为库状态把整个接口拖成 500。
func (d *ScanTaskDAO) DeleteAll() (int, error) {
	if d == nil || d.Table == nil {
		return 0, nil
	}
	return d.Table.Clear()
}

// CreatedSince 指定时间之后创建的任务(按 CreatedAt, 含当日 0 点口径由调用方定)。
// 大屏"今日任务数"用 CreatedAt 而非 StartedAt: 排队中的任务没有 StartedAt,
// 用它会让"今天提交的还没跑"的任务从今日统计消失。
func (d *ScanTaskDAO) CreatedSince(t time.Time) (int, error) {
	return d.CountWhere(func(x *ScanTask) bool { return x.CreatedAt.After(t) || x.CreatedAt.Equal(t) })
}
