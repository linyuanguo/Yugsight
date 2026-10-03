package collect

// threshold_test.go 每节点阈值覆盖(PerNode)的契约测试。
//
// 守的契约(改坏会静默失效):
//  1. 节点级覆盖优先: 同一轮指标, 全局阈值不告警而节点阈值告警;
//  2. 0 值回落全局: 覆盖项里只填一个字段, 其它字段仍按全局判定;
//  3. 未配置 PerNode 的任务行为与旧版完全一致(零行为变化, 规则 5 口径)。

import (
	"context"
	"testing"
)

func TestAlertsForPerNodeOverride(t *testing.T) {
	cfg := Config{
		Alerts: Alerts{CPUPct: 90, MemPct: 90, LossPct: 30, FailStreak: 3},
		PerNode: map[string]Alerts{
			"low-spec": {CPUPct: 60}, // 只覆盖 CPU, 其余应回落全局
		},
	}

	a := cfg.AlertsFor("low-spec")
	if a.CPUPct != 60 {
		t.Fatalf("节点覆盖应生效: cpuPct got %d, want 60", a.CPUPct)
	}
	if a.MemPct != 90 || a.LossPct != 30 || a.FailStreak != 3 {
		t.Fatalf("0 值字段应回落全局: mem=%d loss=%d failStreak=%d", a.MemPct, a.LossPct, a.FailStreak)
	}
	// 未配置的任务 = 纯全局
	b := cfg.AlertsFor("other")
	if b != cfg.WithDefaults().Alerts {
		t.Fatalf("未配置 PerNode 的任务应与全局默认一致: got %+v want %+v", b, cfg.WithDefaults().Alerts)
	}
}

// TestPerNodeThresholdEdgeTrigger 同一轮 CPU=75%: 全局阈值 90 不告警,
// 节点覆盖 70 告警(边缘触发: 上一轮 60 → 本轮 75 跨越 70)。
func TestPerNodeThresholdEdgeTrigger(t *testing.T) {
	cfg := Config{Enabled: true, IntervalSec: 60}
	cfg.Alerts.CPUPct = 90
	cfg.Alerts.FailStreak = 100 // 避免离线事件干扰
	cfg.PerNode = map[string]Alerts{"t2": {CPUPct: 70}}
	var events []Event
	e := New(cfg, func() Config { return cfg }, nil)
	e.SetEventHook(func(ev *Event) { events = append(events, *ev) })

	t1 := Task{ID: "t1", Side: SideHost, Protocol: "testok2", Target: "10.0.0.1", Enabled: true}
	t2 := Task{ID: "t2", Side: SideHost, Protocol: "testok2", Target: "10.0.0.2", Enabled: true}

	// 两任务同经历: 60% → 75%(对全局 90 都未越限, 对节点 70 越限)
	Register("testok2", fakeOK(60))
	e.CollectNow(context.Background(), t1)
	e.CollectNow(context.Background(), t2)
	Register("testok2", fakeOK(75))
	e.CollectNow(context.Background(), t1)
	e.CollectNow(context.Background(), t2)

	var t1High, t2High int
	for _, ev := range events {
		if ev.Type != EvtHighCPU {
			continue
		}
		if ev.TaskID == "t1" {
			t1High++
		}
		if ev.TaskID == "t2" {
			t2High++
		}
	}
	if t1High != 0 {
		t.Fatalf("全局阈值 90 下 75%% 不应告警, t1 报了 %d 次: %+v", t1High, events)
	}
	if t2High != 1 {
		t.Fatalf("节点阈值 70 下 75%% 应告警一次(边缘触发), t2 报了 %d 次: %+v", t2High, events)
	}
}
