// collect.go 节点监控采集的时序与事件表(采集底座产出物落库)。
//
// 两张表直接嵌入 collect 包的实体(与 monitor 表同一"单一事实来源"口径,
// 不套 wrapper; 指针实体同 monitor.Sample):
//   - collect_samples  每任务每轮一条 Round(标准化指标数组);
//   - collect_events   异常事件(离线/恢复/阈值越限)。
//
// 与 monitor 表的边界: monitor 是"网络设备 SNMP 轮询"(既有功能, 节点监控
// Tab 2 的 SNMP 部分继续用它); collect 是"节点监控采集底座"(WinRM/SSH/
// 主机SNMP/ICMP/NetFlow/NETCONF/RESTCONF + 统一调度/限速/白名单/事件),
// 两者产出各自的表, 报告中心二期从两张表聚合。
package db

import (
	"errors"
	"time"

	"yugsight/internal/collect"
)

// CollectSample 节点采集轮次实体(直接嵌入, EntityID 来自 Round.ID)。
type CollectSample struct {
	collect.Round
}

// EntityID 实体 ID(每轮唯一: taskID@unixmilli)。
func (s *CollectSample) EntityID() string { return s.Round.ID }

// Validate 自检。
func (s *CollectSample) Validate() error {
	if s.Round.ID == "" {
		return errors.New("采集轮次 ID 不能为空")
	}
	if s.Round.TaskID == "" {
		return errors.New("采集轮次任务 ID 不能为空")
	}
	return nil
}

// CollectEvent 节点采集异常事件实体。
type CollectEvent struct {
	collect.Event
}

// EntityID 实体 ID(事件 ID 已含任务+时间戳+类型)。
func (e *CollectEvent) EntityID() string { return e.Event.ID }

// Validate 自检。
func (e *CollectEvent) Validate() error {
	if e.Event.ID == "" {
		return errors.New("采集事件 ID 不能为空")
	}
	if e.Event.TaskID == "" {
		return errors.New("采集事件任务 ID 不能为空")
	}
	return nil
}

// ---- 建表 ----

// newCollectSampleTable 打开采集轮次表。
func newCollectSampleTable(path string) (*CollectSampleDAO, error) {
	t, err := NewTable[*CollectSample]("collect_samples", path, func() *CollectSample { return &CollectSample{} })
	if err != nil {
		return nil, err
	}
	return &CollectSampleDAO{t: t}, nil
}

// newCollectEventTable 打开异常事件表。
func newCollectEventTable(path string) (*CollectEventDAO, error) {
	t, err := NewTable[*CollectEvent]("collect_events", path, func() *CollectEvent { return &CollectEvent{} })
	if err != nil {
		return nil, err
	}
	return &CollectEventDAO{t: t}, nil
}

// ---- DAO ----

// CollectSampleDAO 采集轮次表访问。
type CollectSampleDAO struct{ t *Table[*CollectSample] }

// CollectEventDAO 异常事件表访问。
type CollectEventDAO struct{ t *Table[*CollectEvent] }

// Upsert 写入一轮(幂等)。
func (d *CollectSampleDAO) Upsert(s *CollectSample) (bool, error) {
	return d.t.Upsert(s)
}

// ByTaskTail 某任务最近 n 轮(时间升序; n<=0 全部)。
//
// 为什么单独提供: 页面"历史曲线"按任务取, 直接 List() 全表遍历在
// JSONL 引擎下是 O(总行数); 这里先按任务过滤再裁剪, 装配层会配合
// 保留时长裁剪控制总量。
func (d *CollectSampleDAO) ByTaskTail(taskID string, n int) ([]*CollectSample, error) {
	items, err := d.t.List()
	if err != nil {
		return nil, err
	}
	out := make([]*CollectSample, 0)
	for _, s := range items {
		if s.TaskID == taskID {
			out = append(out, s)
		}
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

// PruneByTime 清理早于 before 的轮次(一次落盘)。
func (d *CollectSampleDAO) PruneByTime(before time.Time) (int, error) {
	if before.IsZero() {
		return 0, nil
	}
	return d.t.Purge(func(s *CollectSample) bool { return !s.At.After(before) })
}

// List 全部轮次(时间升序)。供 AI 结构化记忆库按时间窗检索 —— 表本身
// 已被"时长+条数"双裁剪(PruneByTime/PrunePerTask), 全表量可控。
func (d *CollectSampleDAO) List() ([]*CollectSample, error) {
	return d.t.List()
}

// PrunePerTask 每任务只保留最近 keep 轮(一次落盘)。
// 只按条数裁剪会在低频任务上留下陈数据, 只按时长裁剪又可能在高频任务上
// 撑爆 JSONL —— 时长(PruneByTime)与条数(本方法)双限都要, 与 monitor 同口径。
func (d *CollectSampleDAO) PrunePerTask(keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	items, err := d.t.List()
	if err != nil {
		return 0, err
	}
	byTask := map[string][]string{} // 任务 → 按入库(时间)序的 ID
	for _, s := range items {
		byTask[s.TaskID] = append(byTask[s.TaskID], s.EntityID())
	}
	del := map[string]bool{}
	for _, ids := range byTask {
		if len(ids) > keep {
			for _, id := range ids[:len(ids)-keep] {
				del[id] = true
			}
		}
	}
	if len(del) == 0 {
		return 0, nil
	}
	return d.t.Purge(func(s *CollectSample) bool { return del[s.EntityID()] })
}

// Count 总行数。
func (d *CollectSampleDAO) Count() (int, error) { return d.t.Count() }

// Upsert 写入一条事件(幂等)。
func (d *CollectEventDAO) Upsert(e *CollectEvent) (bool, error) {
	return d.t.Upsert(e)
}

// Tail 最近 n 条事件(时间升序; n<=0 全部)。
func (d *CollectEventDAO) Tail(n int) ([]*CollectEvent, error) {
	items, err := d.t.List()
	if err != nil {
		return nil, err
	}
	if n > 0 && len(items) > n {
		items = items[len(items)-n:]
	}
	out := make([]*CollectEvent, len(items))
	copy(out, items)
	return out, nil
}

// List 全部事件(时间升序)。供 AI 结构化记忆库按时间窗检索。
func (d *CollectEventDAO) List() ([]*CollectEvent, error) {
	return d.t.List()
}

// PruneByTime 清理早于 before 的事件(一次落盘)。
func (d *CollectEventDAO) PruneByTime(before time.Time) (int, error) {
	if before.IsZero() {
		return 0, nil
	}
	return d.t.Purge(func(e *CollectEvent) bool { return !e.At.After(before) })
}

// Count 总条数。
func (d *CollectEventDAO) Count() (int, error) { return d.t.Count() }
