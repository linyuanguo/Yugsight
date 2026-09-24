// 周期任务契约测试: 触发节奏 / 不重叠 / 移除即停 / 异常不终止。
// 离线: 不依赖网络与磁盘, 只验证调度语义。
package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// newBareScheduler 最小可用调度器(零任务、无执行器)。
func newBareScheduler(t *testing.T) *Scheduler {
	t.Helper()
	s := New(DefaultConfig(), nil)
	t.Cleanup(s.Stop)
	return s
}

func TestPeriodicFiresAndStops(t *testing.T) {
	s := newBareScheduler(t)
	s.Start()
	var n atomic.Int32
	if err := s.AddPeriodic("tick", 120*time.Millisecond, func(ctx context.Context) {
		n.Add(1)
	}); err != nil {
		t.Fatal(err)
	}

	// 主循环 tick 500ms: 1.4s 内应至少触发 2 轮(首轮 120ms, 次轮 240ms)
	deadline := time.Now().Add(2 * time.Second)
	for n.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n.Load() < 2 {
		t.Fatalf("2s 内应至少触发 2 轮, 实际 %d", n.Load())
	}

	// 移除后不再触发
	s.RemovePeriodic("tick")
	after := n.Load()
	time.Sleep(400 * time.Millisecond)
	if n.Load() != after {
		t.Fatalf("移除后仍触发: %d -> %d", after, n.Load())
	}
}

func TestPeriodicNoOverlap(t *testing.T) {
	s := newBareScheduler(t)
	s.Start()
	var running, peak, rounds atomic.Int32
	_ = s.AddPeriodic("slow", 60*time.Millisecond, func(ctx context.Context) {
		cur := running.Add(1)
		if cur > peak.Load() {
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		}
		time.Sleep(150 * time.Millisecond) // 比间隔长 → 上一轮未结束
		rounds.Add(1)
		running.Add(-1)
	})
	time.Sleep(1300 * time.Millisecond)
	s.Stop()
	// 不重叠: 峰值并发必须 = 1
	if peak.Load() != 1 {
		t.Fatalf("周期任务重叠执行: 峰值并发 %d", peak.Load())
	}
	// 跳轮是预期行为(不堆积), 轮数应明显小于"无跳过"的 ~1300/60
	if rounds.Load() == 0 {
		t.Fatal("一轮都没执行")
	}
}

func TestPeriodicPanicDoesNotKillSubsequent(t *testing.T) {
	s := newBareScheduler(t)
	s.Start()
	var n atomic.Int32
	_ = s.AddPeriodic("boom", 80*time.Millisecond, func(ctx context.Context) {
		if n.Add(1) == 1 {
			panic("测试异常")
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for n.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n.Load() < 2 {
		t.Fatalf("异常后应继续触发后续周期, 实际 %d 轮", n.Load())
	}
}

func TestPeriodicAddValidation(t *testing.T) {
	s := newBareScheduler(t)
	if err := s.AddPeriodic("", time.Second, func(context.Context) {}); err == nil {
		t.Fatal("空名应报错")
	}
	if err := s.AddPeriodic("x", 0, func(context.Context) {}); err == nil {
		t.Fatal("零间隔应报错")
	}
	if err := s.AddPeriodic("x", time.Second, nil); err == nil {
		t.Fatal("nil 回调应报错")
	}
	// 未启动也可注册(先记账, 循环起来后调度)
	if err := s.AddPeriodic("lazy", time.Second, func(context.Context) {}); err != nil {
		t.Fatalf("未启动时注册应允许: %v", err)
	}
	jobs := s.PeriodicJobs()
	if len(jobs) != 1 || jobs[0].Name != "lazy" {
		t.Fatalf("PeriodicJobs: %+v", jobs)
	}
}
