// nodepush.go 节点告警推送的持久化层(2026-09-28, 告警→规则匹配→推送→日志闭环)。
//
// 两张表(与 collect 表同一"单一事实来源"口径, 实体自带 json tag, 不套 wrapper):
//   - node_alerts  告警记录: 采集引擎异常事件(离线/恢复/阈值越限)经装配层落表,
//     携带推送状态(pushStatus)与处理标记(handled), 是告警列表页的唯一事实来源;
//   - push_logs    推送日志: 每次"告警 × 推送目标"的发送结果一条, 经 alertId
//     关联告警记录(推送日志页"关联告警ID"跳转定位的数据基础)。
//
// 存储形态: 一表一 JSONL(原子写, 崩溃安全), 容量由装配层按"时长+条数"双限裁剪
// (PruneByTime/PruneKeep), 防文件无限增长 —— 与 collect_events 同口径。
package db

import (
	"errors"
	"time"
)

// NodeAlert 节点告警记录实体。
//
// Level 口径是前端三级(与漏洞五级 critical..info 区分):
//   critical=紧急 / warning=重要 / info=提示。
// 采集引擎事件级别是 info/warn/critical, warn→warning 的映射在装配层完成,
// 表里只存前端口径。
type NodeAlert struct {
	ID     string `json:"id"`
	TaskID string `json:"taskId,omitempty"`
	// Source 告警来源: device(设备) / link(链路) / probe(探针)
	Source  string `json:"source,omitempty"`
	Device  string `json:"device,omitempty"` // 设备名称(采集任务名)
	IP      string `json:"ip,omitempty"`
	Level   string `json:"level"`
	Type    string `json:"type,omitempty"` // offline/recover/high_cpu/...
	Content string `json:"content"`
	At      time.Time `json:"at"`
	// PushStatus 推送状态: unpushed(未推送) / pushed(推送成功) / failed(推送失败)
	PushStatus string     `json:"pushStatus"`
	PushedAt   *time.Time `json:"pushedAt,omitempty"`
	// Handled 人工处理标记: confirmed(已确认) / ignored(已忽略) / 空=未处理
	Handled string `json:"handled,omitempty"`
}

// EntityID 实体 ID(装配层生成, 含任务+毫秒时间戳+随机后缀, 同任务同毫秒不撞)。
func (a *NodeAlert) EntityID() string { return a.ID }

// Validate 自检。
func (a *NodeAlert) Validate() error {
	if a.ID == "" {
		return errors.New("告警 ID 不能为空")
	}
	if a.Level == "" {
		return errors.New("告警级别不能为空")
	}
	if a.Content == "" {
		return errors.New("告警内容不能为空")
	}
	return nil
}

// PushLog 推送日志实体(一次发送 = 一条; 多目标告警每目标各一条)。
type PushLog struct {
	ID      string `json:"id"`
	AlertID string `json:"alertId,omitempty"` // 关联告警记录(空=测试推送等无主记录)
	At      time.Time `json:"at"`
	Level   string `json:"level,omitempty"`
	Content string `json:"content,omitempty"`
	// Target 推送目标名称(企业微信群/钉钉群/飞书群); 跳过类日志(未匹配规则等)为空。
	Target string `json:"target,omitempty"`
	// Status: success(成功) / failed(失败) / skipped(已跳过)
	Status string `json:"status"`
	// Reason 失败原因(仅 failed 有意义; 展示为悬浮提示)
	Reason string `json:"reason,omitempty"`
}

// EntityID 实体 ID(装配层生成: alertId + 目标 + 毫秒时间戳)。
func (l *PushLog) EntityID() string { return l.ID }

// Validate 自检。
func (l *PushLog) Validate() error {
	if l.ID == "" {
		return errors.New("推送日志 ID 不能为空")
	}
	if l.Status == "" {
		return errors.New("推送状态不能为空")
	}
	return nil
}

// ---- 建表 ----

func newNodeAlertTable(path string) (*NodeAlertDAO, error) {
	t, err := NewTable[*NodeAlert]("node_alerts", path, func() *NodeAlert { return &NodeAlert{} })
	if err != nil {
		return nil, err
	}
	return &NodeAlertDAO{t: t}, nil
}

func newPushLogTable(path string) (*PushLogDAO, error) {
	t, err := NewTable[*PushLog]("push_logs", path, func() *PushLog { return &PushLog{} })
	if err != nil {
		return nil, err
	}
	return &PushLogDAO{t: t}, nil
}

// ---- DAO ----

// NodeAlertDAO 告警记录表访问。
type NodeAlertDAO struct{ t *Table[*NodeAlert] }

// Upsert 写入一条告警(幂等)。
func (d *NodeAlertDAO) Upsert(a *NodeAlert) (bool, error) {
	return d.t.Upsert(a)
}

// Get 按 ID 取; 不存在返回 ErrNotFound。
// 返回**副本**(Table 内部存指针, 直出会让推送 goroutine 的回写与 API 的
// JSON 序列化/测试轮询竞争同一结构体 —— 2026-09-28 -race 实测命中)。
func (d *NodeAlertDAO) Get(id string) (*NodeAlert, error) {
	a, err := d.t.Get(id)
	if err != nil {
		return nil, err
	}
	c := *a
	return &c, nil
}

// Update 更新(推送状态回写/人工处理标记)。
func (d *NodeAlertDAO) Update(a *NodeAlert) error {
	return d.t.Update(a)
}

// TailNewest 最近 n 条, 新在前(存储序是入库序=时间升序, 这里倒序返回)。
// n<=0 返回全部。逐条返回副本(同 Get 的拷贝口径)。
func (d *NodeAlertDAO) TailNewest(n int) ([]*NodeAlert, error) {
	items, err := d.t.List()
	if err != nil {
		return nil, err
	}
	if n > 0 && len(items) > n {
		items = items[len(items)-n:]
	}
	out := make([]*NodeAlert, 0, len(items))
	for i := len(items) - 1; i >= 0; i-- {
		c := *items[i]
		out = append(out, &c)
	}
	return out, nil
}

// PruneByTime 清理早于 before 的告警(一次落盘)。
func (d *NodeAlertDAO) PruneByTime(before time.Time) (int, error) {
	if before.IsZero() {
		return 0, nil
	}
	return d.t.Purge(func(a *NodeAlert) bool { return !a.At.After(before) })
}

// PruneKeep 只保留最近 keep 条(按入库序, 一次落盘)。
func (d *NodeAlertDAO) PruneKeep(keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	items, err := d.t.List()
	if err != nil {
		return 0, err
	}
	if len(items) <= keep {
		return 0, nil
	}
	del := make(map[string]bool, len(items)-keep)
	for _, a := range items[:len(items)-keep] {
		del[a.ID] = true
	}
	return d.t.Purge(func(a *NodeAlert) bool { return del[a.ID] })
}

// Count 总条数。
func (d *NodeAlertDAO) Count() (int, error) { return d.t.Count() }

// Clear 清空全表(恢复出厂用)。
func (d *NodeAlertDAO) Clear() (int, error) { return d.t.Clear() }

// PushLogDAO 推送日志表访问。
type PushLogDAO struct{ t *Table[*PushLog] }

// Upsert 写入一条日志。
func (d *PushLogDAO) Upsert(l *PushLog) (bool, error) {
	return d.t.Upsert(l)
}

// ListNewest 新在前, n<=0 全部。筛选(状态/级别/目标/时间窗)在装配层做:
// JSONL 引擎无 SQL, 表已被双限裁剪, 全表遍历成本可控。逐条返回副本。
func (d *PushLogDAO) ListNewest(n int) ([]*PushLog, error) {
	items, err := d.t.List()
	if err != nil {
		return nil, err
	}
	if n > 0 && len(items) > n {
		items = items[len(items)-n:]
	}
	out := make([]*PushLog, 0, len(items))
	for i := len(items) - 1; i >= 0; i-- {
		c := *items[i]
		out = append(out, &c)
	}
	return out, nil
}

// List 全部(入库序, 副本)。供装配层筛选。
func (d *PushLogDAO) List() ([]*PushLog, error) {
	items, err := d.t.List()
	if err != nil {
		return nil, err
	}
	out := make([]*PushLog, 0, len(items))
	for i := range items {
		c := *items[i]
		out = append(out, &c)
	}
	return out, nil
}

// PruneByTime 清理早于 before 的日志(一次落盘)。
func (d *PushLogDAO) PruneByTime(before time.Time) (int, error) {
	if before.IsZero() {
		return 0, nil
	}
	return d.t.Purge(func(l *PushLog) bool { return !l.At.After(before) })
}

// PruneKeep 只保留最近 keep 条(一次落盘)。
func (d *PushLogDAO) PruneKeep(keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	items, err := d.t.List()
	if err != nil {
		return 0, err
	}
	if len(items) <= keep {
		return 0, nil
	}
	del := make(map[string]bool, len(items)-keep)
	for _, l := range items[:len(items)-keep] {
		del[l.ID] = true
	}
	return d.t.Purge(func(l *PushLog) bool { return del[l.ID] })
}

// Count 总条数。
func (d *PushLogDAO) Count() (int, error) { return d.t.Count() }

// Clear 清空全表(恢复出厂用)。
func (d *PushLogDAO) Clear() (int, error) { return d.t.Clear() }
