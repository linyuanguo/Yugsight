// periodic.go 调度器周期任务(任务 10a: SNMP 监控周期采集的调度底座)。
//
// 为什么放在 scheduler 而不是各模块自建 ticker:
//
//	1. 调度器主循环已有 500ms 定时兜底(节点负载轮询), 周期任务挂在同一循环
//	   上, 不新增 goroutine 调度点, Stop() 一处即停全部;
//	2. 各模块(监控/将来的 SNMP 周期采集/日志清理)只需 AddPeriodic 一行接入,
//	   统一受"调度器是否启用"管控 —— 调度器关了, 周期采集随之停, 语义清晰;
//	3. 周期任务与扫描任务队列完全隔离: 不占执行槽位、不限速、不参与优先级,
//	   它只是"到点回调", 执行时长与失败不影响队列(回调自带超时/降级)。
//
// 契约:
//   - fn 在独立 goroutine 里调用, 绝不允许阻塞(阻塞会拖慢后续周期,
//     但不会卡调度循环);
//   - 同一任务上一轮未结束时下一轮跳过(不重叠执行, 防采集堆积);
//   - 首轮在注册后一个间隔触发(装配层需要立即执行时自行先跑一轮);
//   - 任务异常(recover)只记日志, 不终止后续周期。
package scheduler

import (
	"context"
	"errors"
	"time"
)

// PeriodicFunc 周期回调。ctx 无超时(与扫描任务的 ctx 语义不同),
// 调用方应自带超时控制(如 SNMP 采集的 3s 超时)。
type PeriodicFunc func(ctx context.Context)

// PeriodicJobInfo 周期任务快照(状态接口展示用)。
type PeriodicJobInfo struct {
	Name     string        `json:"name"`
	Interval time.Duration `json:"interval"`
	NextAt   time.Time     `json:"nextAt"`
	Running  bool          `json:"running"`
}

type periodicJob struct {
	name     string
	interval time.Duration
	fn       PeriodicFunc
	next     time.Time
	running  bool
}

// AddPeriodic 注册周期任务(幂等: 同名覆盖)。interval 必须 > 0。
//
// 调度器未 Start 时注册也有效 —— 任务先记账, 主循环起来后自然被调度
// (装配层常在 Start 前后交错初始化, 两种顺序都要支持)。
func (s *Scheduler) AddPeriodic(name string, interval time.Duration, fn PeriodicFunc) error {
	if name == "" {
		return errors.New("scheduler: 周期任务名不能为空")
	}
	if interval <= 0 {
		return errors.New("scheduler: 周期任务间隔必须 > 0")
	}
	if fn == nil {
		return errors.New("scheduler: 周期任务回调不能为 nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("scheduler: 调度器已停止")
	}
	job := &periodicJob{
		name:     name,
		interval: interval,
		fn:       fn,
		next:     s.nowFn().Add(interval),
	}
	if s.periodics == nil {
		s.periodics = make(map[string]*periodicJob)
	}
	s.periodics[name] = job
	logf("周期任务已注册: %s (间隔 %s)", name, interval)
	return nil
}

// RemovePeriodic 移除周期任务(运行中的那一轮允许跑完, 之后不再触发)。
func (s *Scheduler) RemovePeriodic(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.periodics[name]; ok {
		delete(s.periodics, name)
		logf("周期任务已移除: %s", name)
	}
}

// PeriodicJobs 周期任务快照(状态接口展示)。
func (s *Scheduler) PeriodicJobs() []PeriodicJobInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PeriodicJobInfo, 0, len(s.periodics))
	for _, j := range s.periodics {
		out = append(out, PeriodicJobInfo{
			Name:     j.name,
			Interval: j.interval,
			NextAt:   j.next,
			Running:  j.running,
		})
	}
	return out
}

// runPeriodics 扫描到期周期任务并触发(由调度主循环的 tick 分支调用)。
func (s *Scheduler) runPeriodics() {
	s.mu.Lock()
	now := s.nowFn()
	var due []*periodicJob
	for _, j := range s.periodics {
		// running 的跳过(不重叠执行); 到期的标记 running 防止并发重复触发
		if !j.running && !now.Before(j.next) {
			j.running = true
			due = append(due, j)
		}
	}
	s.mu.Unlock()
	for _, j := range due {
		go s.runPeriodicOnce(j)
	}
}

// runPeriodicOnce 执行一轮周期任务(独立 goroutine)。
func (s *Scheduler) runPeriodicOnce(j *periodicJob) {
	defer func() {
		if p := recover(); p != nil {
			logf("周期任务 %s 执行异常(已恢复, 不影响后续周期): %v", j.name, p)
		}
		s.finishPeriodic(j)
	}()
	j.fn(context.Background())
}

// finishPeriodic 一轮结束: 复位 running 并预约下一轮(幂等)。
func (s *Scheduler) finishPeriodic(j *periodicJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 调度器已关闭或任务被移除时不再预约下一轮
	if s.closed {
		return
	}
	if _, ok := s.periodics[j.name]; !ok {
		return
	}
	j.running = false
	j.next = s.nowFn().Add(j.interval)
}
