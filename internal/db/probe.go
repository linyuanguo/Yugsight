package db

import (
	"errors"
	"strings"
	"time"
)

// 探针状态常量。
const (
	ProbeOnline   = "online"   // 在线
	ProbeOffline  = "offline"  // 离线(心跳超时)
	ProbeDisabled = "disabled" // 停用
)

// Probe 探针管理表实体(远端探针节点)。
// 中心管理端通过探针下发扫描任务: Linux 中心节点不本地执行抓包 /
// SYN 扫描, 这类任务经 ScanTask.ProbeNode 下发到远端探针执行。
type Probe struct {
	ID           string    `json:"id"` // 探针节点 ID
	Name         string    `json:"name,omitempty"`
	Addr         string    `json:"addr,omitempty"` // 回调/注册地址
	Status       string    `json:"status"`
	Capabilities string    `json:"capabilities,omitempty"` // 能力(逗号分隔: portscan,web,nuclei,capture...)
	LastSeenAt   time.Time `json:"lastSeenAt,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`

	// 节点信息与负载: 存结构化子对象而非把字段铺平, 因为它是"探针上报的原始快照",
	// 字段集合会随探针版本演进(db 层不做字段裁剪, 保持弱耦合)。
	// 声明为 any 而非 map[string]any 以保持 db 包对 probe 包零依赖。
	NodeInfo any `json:"nodeInfo,omitempty"` // 主机信息(OS/CPU/内存/网卡/Npcap/引擎)
	Load     any `json:"load,omitempty"`     // 最近一次心跳负载(CPU/内存/当前任务)

	// 任务统计(中心端按任务结果累计, 供面板展示)
	TaskTotal   int `json:"taskTotal,omitempty"`
	TaskSuccess int `json:"taskSuccess,omitempty"`
	TaskFailed  int `json:"taskFailed,omitempty"`
}

// BumpTaskStat 累计任务统计(成功/失败数)。
func (p *Probe) BumpTaskStat(ok bool) {
	p.TaskTotal++
	if ok {
		p.TaskSuccess++
	} else {
		p.TaskFailed++
	}
}

// EntityID 探针 ID。
func (p *Probe) EntityID() string {
	if p.ID == "" {
		p.ID = newID("pb")
	}
	return p.ID
}

// Validate 自检: ID 必填, 状态默认 offline。
func (p *Probe) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return errors.New("探针 ID 不能为空")
	}
	p.ID = strings.TrimSpace(p.ID)
	if p.Status == "" {
		p.Status = ProbeOffline
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	return nil
}

// ProbeDAO 探针管理 DAO: 基础 CRUD + 心跳 + 在线查询。
type ProbeDAO struct {
	*Table[*Probe]
}

// newProbeTable 打开探针管理表。
func newProbeTable(path string) (*ProbeDAO, error) {
	t, err := NewTable[*Probe]("probes", path, func() *Probe { return &Probe{} })
	if err != nil {
		return nil, err
	}
	return &ProbeDAO{Table: t}, nil
}

// MarkSeen 更新心跳(置在线 + 最后心跳时间)。
func (d *ProbeDAO) MarkSeen(id string) (*Probe, error) {
	p, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	p.Status = ProbeOnline
	p.LastSeenAt = time.Now()
	if err := d.Update(p); err != nil {
		return p, err
	}
	return p, nil
}

// SetStatus 设置探针状态。
func (d *ProbeDAO) SetStatus(id, status string) (*Probe, error) {
	p, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	p.Status = status
	if err := d.Update(p); err != nil {
		return p, err
	}
	return p, nil
}

// Online 在线探针。
func (d *ProbeDAO) Online() ([]*Probe, error) {
	return d.Query(func(p *Probe) bool { return p.Status == ProbeOnline })
}

// Offline 离线 / 停用探针(在线之外的都算, 供大屏区分"在线/异常"两态)。
func (d *ProbeDAO) Offline() ([]*Probe, error) {
	return d.Query(func(p *Probe) bool { return p.Status != ProbeOnline })
}

// CountByStatus 按状态统计探针数量(在线/离线/停用)。
// 返回的 map 一定包含三个状态键(缺失补 0), 前端无需做 undefined 判定。
// CountBy 单遍统计不拷贝实体(大屏轮询只需要计数)。
func (d *ProbeDAO) CountByStatus() (map[string]int, error) {
	out := map[string]int{ProbeOnline: 0, ProbeOffline: 0, ProbeDisabled: 0}
	counts, err := d.CountBy(func(p *Probe) string { return p.Status })
	if err != nil {
		return out, err
	}
	for k, v := range counts {
		out[k] = v
	}
	return out, nil
}
