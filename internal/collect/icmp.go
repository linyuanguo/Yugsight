// icmp.go ICMP 链路探测: 周期 ping, 输出时延/抖动/丢包。
//
// 复用 scanner 包既有 ICMP 实现(与存活探测同一套原始套接字口径, 需要管理员
// 权限 —— 中心端默认 UAC 提权运行, 权限不足时 PingICMP 直接返回错误, 本
// 采集器如实记失败, 不假装在线)。
//
// 指标口径:
//   - rtt_avg_ms / rtt_min_ms / rtt_max_ms  成功探测的时延统计
//   - rtt_jitter_ms  相邻时延绝对差的均值(抖动, 链路质量的核心指标)
//   - loss_pct       丢包率(0-100)
// 探测次数由 params.count 控制(默认 4), 逐个发送(不并发 —— 并发的 ping 会
// 互相抢 ICMP 回复归属, 单目标探测串行才干净)。
package collect

import (
	"context"
	"time"

	"yugsight/internal/scanner"
)

func init() {
	Register(ProtoICMP, collectICMP)
}

func collectICMP(ctx context.Context, e *Engine, t Task) *Round {
	r := newRound(t, time.Now())
	count := t.IntParam("count", 4)
	if count < 1 {
		count = 1
	}
	if count > 20 {
		count = 20
	}

	var hit, lost int
	var min, max, sum, lastRTT, jitterSum float64
	var jitterN int

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			r.OK = false
			r.Err = "探测被取消/超时"
			return r
		default:
		}
		reach, rtt, err := scanner.PingICMP(t.Target, uint16(i+1), 2*time.Second)
		if !reach {
			lost++
			if r.Err == "" {
				if err != nil {
					r.Err = err.Error()
				} else {
					r.Err = "ping 超时(设备不可达或禁 ping)"
				}
			}
			continue
		}
		hit++
		v := float64(rtt)
		if hit == 1 {
			min, max = v, v
		}
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
		sum += v
		if hit > 1 {
			j := v - lastRTT
			if j < 0 {
				j = -j
			}
			jitterSum += j
			jitterN++
		}
		lastRTT = v
	}

	if hit > 0 {
		r.OK = true
		r.Metrics = append(r.Metrics,
			Metric{Name: "rtt_avg_ms", Value: sum / float64(hit), Unit: "ms"},
			Metric{Name: "rtt_min_ms", Value: min, Unit: "ms"},
			Metric{Name: "rtt_max_ms", Value: max, Unit: "ms"},
			Metric{Name: "loss_pct", Value: float64(lost) / float64(count) * 100, Unit: "%"},
		)
		if jitterN > 0 {
			r.Metrics = append(r.Metrics, Metric{Name: "rtt_jitter_ms", Value: jitterSum / float64(jitterN), Unit: "ms"})
		}
	} else if r.Err == "" {
		r.Err = "全部探测超时"
	}
	return r
}
