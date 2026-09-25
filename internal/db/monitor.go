package db

import (
	"errors"

	"yugsight/internal/monitor"
)

// MonitorSample 监控采样历史表实体(monitor_samples 表)。
//
// 直接嵌入 monitor.Sample 而非重新定义字段: 单一事实来源,
// 采集端与存储端不会出现两份结构漂移。
type MonitorSample struct {
	monitor.Sample
}

// EntityID 采样 ID(targetID@unixmilli, 每轮唯一)。
func (e *MonitorSample) EntityID() string { return e.Sample.ID }

// Validate 自检。
func (e *MonitorSample) Validate() error {
	if e.Sample.ID == "" {
		return errors.New("监控采样 ID 不能为空")
	}
	if e.Sample.TargetID == "" {
		return errors.New("监控目标 ID 不能为空")
	}
	return nil
}

// MonitorDAO 监控采样 DAO: 基础 CRUD + 按目标查询。
type MonitorDAO struct {
	*Table[*MonitorSample]
}

// newMonitorTable 打开监控采样表。
func newMonitorTable(path string) (*MonitorDAO, error) {
	t, err := NewTable[*MonitorSample]("monitor_samples", path, func() *MonitorSample { return &MonitorSample{} })
	if err != nil {
		return nil, err
	}
	return &MonitorDAO{Table: t}, nil
}

// ByTarget 某目标的全部采样(按写入序, 即时间升序)。
func (d *MonitorDAO) ByTarget(targetID string) ([]*MonitorSample, error) {
	return d.Query(func(s *MonitorSample) bool { return s.TargetID == targetID })
}

// ByTargetTail 某目标最近 n 条(尾部切片, 大屏/页面趋势用)。
func (d *MonitorDAO) ByTargetTail(targetID string, n int) ([]*MonitorSample, error) {
	if n <= 0 {
		return nil, nil
	}
	all, err := d.ByTarget(targetID)
	if err != nil || len(all) <= n {
		return all, err
	}
	return all[len(all)-n:], nil
}
