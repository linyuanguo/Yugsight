package db

// 扫描任务名登记簿(2026-09-25 四轮换口径, 用户要求去掉"扫描作业"页面):
// 扫描任务不再是自动编排作业, 而是**扫描控制台立即扫描 + 任务名**驱动的人工
// 分步流程: 任务名 + IP/子网(可多个) 快速发现 → 勾选扫出的主机 → 主机漏扫 /
// web漏扫 / 弱口令 / 渗透(各步带同一任务名)。
// scan_jobs 表在此口径下是**任务名登记簿**(ID = 任务名, 全局唯一):
// 带任务名的扫描在 runScanPipeline 入口自动登记(幂等 upsert), 报告中心据此
// 按任务名生成报告(漏洞 ScanTaskID="job-<任务名>"、资产 Jobs 含 <任务名>、
// 渗透任务 Job=<任务名>) / 按任务名分类原始报告(原始报告 Job=<任务名>)。
// 结构里的 Status/Stages/Log/PentaTaskID 等编排字段保留(数据兼容),
// 四轮换口径后不再使用 —— 分步由用户在控制台手动发起。

import (
	"errors"
	"strings"
	"time"
)

// ScanJob 状态/阶段常量(状态与 ScanTask 同口径; 作业是长流程, 多 stage 维度)。
const (
	JobStatusPending   = "pending"
	JobStatusRunning   = "running"
	JobStatusSuccess   = "success"
	JobStatusFailed    = "failed"
	JobStatusCancelled = "cancelled"

	// 阶段(按流程顺序): 深度扫描 → 弱口令 → 渗透 → 完成
	JobStageDeep     = "deep"
	JobStageWeakpass = "weakpass"
	JobStagePenta    = "penta"
	JobStageDone     = "done"
)

// JobStage 单个阶段的执行记录(报告"扫描范围"章节按作业展示时用)。
type JobStage struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"` // host/web/weakpass/penta
	Status     string    `json:"status"`
	Summary    string    `json:"summary,omitempty"`
	StartedAt  time.Time `json:"startedAt,omitempty"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
}

// ScanJob 扫描作业实体。
type ScanJob struct {
	ID        string `json:"id"`
	Name      string `json:"name"` // 任务名(用户填, 报告/原始报告按它分类)
	Target    string `json:"target"`
	Status    string `json:"status"`
	Stage     string `json:"stage,omitempty"` // 当前阶段(进行中)
	Stages    []JobStage `json:"stages,omitempty"`
	// PentaTaskID 渗透阶段创建的渗透任务 ID(报告按作业过滤渗透结论时关联)
	PentaTaskID string `json:"pentaTaskId,omitempty"`
	// Log 日志尾部(上限 300 行, 运行中实时可见; 进程重启后保留终值)
	Log         []string   `json:"log,omitempty"`
	Result      string     `json:"result,omitempty"` // 终态摘要(成功=统计, 失败=原因)
	CreatedBy   string     `json:"createdBy,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty"`
}

// EntityID 作业 ID。
func (j *ScanJob) EntityID() string {
	if j.ID == "" {
		j.ID = newID("job")
	}
	return j.ID
}

// Validate 自检: 任务名/目标必填, 状态默认 pending。
func (j *ScanJob) Validate() error {
	if strings.TrimSpace(j.Name) == "" {
		return errors.New("任务名不能为空")
	}
	if strings.TrimSpace(j.Target) == "" {
		return errors.New("目标不能为空")
	}
	j.Name = strings.TrimSpace(j.Name)
	j.Target = strings.TrimSpace(j.Target)
	if j.Status == "" {
		j.Status = JobStatusPending
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now()
	}
	return nil
}

// JobDAO 扫描作业 DAO: 基础 CRUD + 倒序列表 + 状态流转。
type JobDAO struct {
	*Table[*ScanJob]
}

// newScanJobTable 打开扫描作业表。
func newScanJobTable(path string) (*JobDAO, error) {
	t, err := NewTable[*ScanJob]("scan_jobs", path, func() *ScanJob { return &ScanJob{} })
	if err != nil {
		return nil, err
	}
	return &JobDAO{Table: t}, nil
}

// List 倒序(新作业在前)。
func (d *JobDAO) List() ([]*ScanJob, error) {
	all, err := d.Table.List()
	if err != nil {
		return nil, err
	}
	for i := range all {
		all[i] = all[i].clone()
	}
	for i, k := 0, len(all)-1; i < k; i, k = i+1, k-1 {
		all[i], all[k] = all[k], all[i]
	}
	return all, nil
}

// UpdateStatus 状态流转(自动补 startedAt/finishedAt)。
func (d *JobDAO) UpdateStatus(id, status, result string) (*ScanJob, error) {
	j, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	j.Status = status
	if result != "" {
		j.Result = result
	}
	now := time.Now()
	switch status {
	case JobStatusRunning:
		if j.StartedAt == nil {
			j.StartedAt = &now
		}
	case JobStatusSuccess, JobStatusFailed, JobStatusCancelled:
		j.FinishedAt = &now
	}
	if err := d.Update(j); err != nil {
		return j, err
	}
	return j, nil
}

// clone 深拷贝(切片/指针字段副本, 防外部改动污染内存缓存)。
func (j *ScanJob) clone() *ScanJob {
	c := *j
	if j.Stages != nil {
		c.Stages = make([]JobStage, len(j.Stages))
		copy(c.Stages, j.Stages)
	}
	if j.Log != nil {
		c.Log = make([]string, len(j.Log))
		copy(c.Log, j.Log)
	}
	if j.StartedAt != nil {
		t := *j.StartedAt
		c.StartedAt = &t
	}
	if j.FinishedAt != nil {
		t := *j.FinishedAt
		c.FinishedAt = &t
	}
	return &c
}
