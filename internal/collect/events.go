// events.go 异常事件判定(边缘触发)。
//
// 所有事件都是"状态跨变"才报一次, 不每轮重复 —— 否则 60s 间隔下持续超阈值
// 会每轮刷一条, 事件流被淹没(与"异常事件输出"的本意相反)。
//
// 两类:
//  1. 在线状态: 连续失败达 failStreak → offline(critical, 且此前在线过);
//     失败中恢复成功 → recover(info)。触发后置"已报离线"标记, 恢复前不重复。
//  2. 阈值越限: 上一轮低于阈值、本轮达到/超过 → high_cpu / high_mem /
//     high_rtt / high_loss(warn)。"上一轮"取本轮之前的状态机记录;
//     首轮没有上一轮, 不判(避免"从空到超"被误报)。
//
// 离线事件的边界: 只对"掉线"报 —— 从未连通过的目标不报(刚配置的目标首轮
// 超时是常态, 报 critical 会让用户误以为系统坏了)。
package collect

import (
	"fmt"
	"time"
)

// eventState 单任务的在线/告警状态机(引擎按任务维护)。
type eventState struct {
	failStreak int
	everOnline bool // 曾经成功过(决定 offline 是否可报)
	offline    bool // 已报离线(恢复前不重复)
	// 上一轮各指标值(阈值边缘判定用; 无值记 -1, 与合法的 0 区分)
	prevCPU, prevMem, prevRTT, prevLoss float64
	hadPrev                              bool
}

// DetectRound 一轮采集完成后判定事件, 返回要输出的事件(可能为空)。
// st 是调用方(引擎)持有的该任务状态机。
func DetectRound(st *eventState, cfg Config, r *Round) []Event {
	cfg = cfg.WithDefaults()
	out := make([]Event, 0, 2)
	emit := func(level, typ, msg string) {
		out = append(out, Event{
			ID:     fmt.Sprintf("e%s-%d-%s", r.TaskID, time.Now().UnixMilli(), typ),
			TaskID: r.TaskID, Side: r.Side, Target: r.Target,
			At: r.At, Level: level, Type: typ, Msg: msg,
		})
	}

	// ---- 在线状态 ----
	if !r.OK {
		st.failStreak++
		if !st.offline && st.everOnline && st.failStreak >= cfg.Alerts.FailStreak {
			st.offline = true
			emit(EvtCritical, EvtOffline, r.Err)
		}
	} else {
		if st.offline {
			st.offline = false
			emit(EvtInfo, EvtRecover, "采集恢复")
		}
		st.failStreak = 0
		st.everOnline = true
	}

	// ---- 阈值(仅成功轮判定; 失败轮的指标不可信) ----
	if r.OK {
		if m := metricValue(r, "cpu"); m >= 0 && st.hadPrev &&
			st.prevCPU < float64(cfg.Alerts.CPUPct) && m >= float64(cfg.Alerts.CPUPct) {
			emit(EvtWarn, EvtHighCPU, fmt.Sprintf("CPU %.1f%% 超过阈值 %d%%", m, cfg.Alerts.CPUPct))
		}
		if m := metricValue(r, "mem_used_pct"); m >= 0 && st.hadPrev &&
			st.prevMem < float64(cfg.Alerts.MemPct) && m >= float64(cfg.Alerts.MemPct) {
			emit(EvtWarn, EvtHighMem, fmt.Sprintf("内存 %.1f%% 超过阈值 %d%%", m, cfg.Alerts.MemPct))
		}
		if m := metricValue(r, "rtt_avg_ms"); m >= 0 && st.hadPrev && cfg.Alerts.RTTMs > 0 &&
			st.prevRTT < float64(cfg.Alerts.RTTMs) && m >= float64(cfg.Alerts.RTTMs) {
			emit(EvtWarn, EvtHighRTT, fmt.Sprintf("平均时延 %.0fms 超过阈值 %dms", m, cfg.Alerts.RTTMs))
		}
		if m := metricValue(r, "loss_pct"); m >= 0 && st.hadPrev && cfg.Alerts.LossPct > 0 &&
			st.prevLoss < float64(cfg.Alerts.LossPct) && m >= float64(cfg.Alerts.LossPct) {
			emit(EvtWarn, EvtHighLoss, fmt.Sprintf("丢包率 %.1f%% 超过阈值 %d%%", m, cfg.Alerts.LossPct))
		}
	}

	// ---- 更新上一轮状态 ----
	st.prevCPU, st.prevMem = metricValue(r, "cpu"), metricValue(r, "mem_used_pct")
	st.prevRTT, st.prevLoss = metricValue(r, "rtt_avg_ms"), metricValue(r, "loss_pct")
	st.hadPrev = true
	return out
}

// metricValue 取指标值; 不存在返回 -1(与 0 区分: 0 是合法测量值)。
func metricValue(r *Round, name string) float64 {
	for _, m := range r.Metrics {
		if m.Name == name {
			return m.Value
		}
	}
	return -1
}
