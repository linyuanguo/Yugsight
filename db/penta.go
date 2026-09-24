package db

import (
	"strings"

	"yugsight/penta"
)

// PentaTask 渗透任务表实体(阶段 5 渗透工作台)。
//
// 内嵌 penta.Task 与任务/引擎层数据契约完全一致(同 db.Vuln 内嵌 models.Vuln 的
// 手法): 工作台业务逻辑在 penta 包, 本实体只是存储外壳。
type PentaTask struct {
	penta.Task
}

// EntityID 任务 ID。
func (t *PentaTask) EntityID() string {
	if t.ID == "" {
		t.ID = penta.NewTaskID()
	}
	return t.ID
}

// Validate 委托给领域模型自检。
func (t *PentaTask) Validate() error {
	return t.Task.Validate()
}

// PentaTaskQuery 任务多维筛选(空字段 = 不过滤)。
type PentaTaskQuery struct {
	Status string // pending/running/done/failed
	Risk   string // 风险等级(初始=来源漏洞等级, 验证后可修正)
	Target string // 目标主机(前缀匹配, 与资产 IP 筛同口径)
}

// Match 判断任务是否满足全部筛选条件。
func (q PentaTaskQuery) Match(t *PentaTask) bool {
	if q.Status != "" && t.Status != q.Status {
		return false
	}
	if q.Risk != "" && t.RiskLevel != q.Risk {
		return false
	}
	if q.Target != "" && !strings.Contains(t.Target, q.Target) {
		return false
	}
	return true
}

// PentaTaskDAO 渗透任务 DAO: 基础 CRUD + 多维筛选。
type PentaTaskDAO struct {
	*Table[*PentaTask]
}

// newPentaTable 打开渗透任务表(第 20 表, data/penta_tasks.jsonl)。
func newPentaTable(path string) (*PentaTaskDAO, error) {
	t, err := NewTable[*PentaTask]("penta_tasks", path, func() *PentaTask {
		return &PentaTask{}
	})
	if err != nil {
		return nil, err
	}
	return &PentaTaskDAO{Table: t}, nil
}

// Search 多维筛选(不分页)。
func (d *PentaTaskDAO) Search(q PentaTaskQuery) ([]*PentaTask, error) {
	return d.Query(func(t *PentaTask) bool { return q.Match(t) })
}

// SearchPage 多维筛选 + 分页(page 从 1 起, size<=0 默认 20, 上限 200)。
func (d *PentaTaskDAO) SearchPage(q PentaTaskQuery, page, size int) ([]*PentaTask, int, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}
	all, err := d.Search(q)
	if err != nil {
		return nil, 0, err
	}
	total := len(all)
	offset := (page - 1) * size
	if offset >= total {
		return []*PentaTask{}, total, nil
	}
	end := offset + size
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}
