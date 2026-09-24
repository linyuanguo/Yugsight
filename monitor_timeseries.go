// monitor_timeseries.go 监控时序数据(二期 13): 历史可查 + 曲线接口。
//
// 存储: 复用 db 的 monitor_samples 表(每轮一条 Sample, 见 monitorWriteHistory),
// 每目标按"保留时长 + 条数上限"双限裁剪 —— 只按条数裁剪会在低频目标上留下
// 几个月前的陈数据, 只按时长裁剪又可能在高频目标上撑爆 JSONL, 两个都要。
//
// 指标口径(决定曲线画出来是什么):
//
//	cpu / mem   直接取样本里的瞬时值(设备上报, 无需推算)
//	in / out    速率必须由相邻两帧的累计字节差分得到 —— 设备只报累计 ifInOctets,
//	            直接画累计值会得到一条永远上升的、毫无运维价值的直线
//	iface       指定接口的速率(同名接口对齐: 设备重启后 ifIndex 可能变,
//	            按名字对齐比按索引稳)
//	uptime      设备运行时长(秒)
//
// 降级: 库不可用 / 目标无样本一律返回空 points(不报错) —— 曲线空白是可接受的
// 展示态,"500"会把整个监控页打断。
package main

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"yugsight/db"
	"yugsight/monitor"
	"yugsight/server"
)

// timeseriesPoint 一个数据点。
type timeseriesPoint struct {
	T string  `json:"t"` // RFC3339
	V float64 `json:"v"`
}

// metricSpec 指标定义(取值函数 + 单位)。
type metricSpec struct {
	unit string
	// rate 为真表示该指标需要两帧差分(速率型)
	rate bool
}

var metricSpecs = map[string]metricSpec{
	"cpu":    {unit: "%"},
	"mem":    {unit: "%"},
	"uptime": {unit: "s"},
	"in":     {unit: "bps", rate: true},
	"out":    {unit: "bps", rate: true},
	"iface":  {unit: "bps", rate: true},
}

// hMonitorTimeseries GET /api/v2/monitor/timeseries?target=&metric=&from=&to=&limit=
//
// 参数:
//
//	target  目标 ID(必填)
//	metric  cpu / mem / uptime / in / out / iface(默认 cpu)
//	iface   metric=iface 时的接口名(必填)
//	from/to RFC3339 或 2006-01-02(可选, 缺省=全部保留窗口)
//	limit   最多返回多少点(默认 300, 上限 5000)
func hMonitorTimeseries(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	dao := d.MonitorSamples()
	if dao == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "监控采样表不可用")
		return
	}
	q := r.URL.Query()
	target := strings.TrimSpace(q.Get("target"))
	if target == "" {
		server.FailBadRequest(w, "target 必填")
		return
	}
	metric := strings.ToLower(strings.TrimSpace(q.Get("metric")))
	if metric == "" {
		metric = "cpu"
	}
	spec, ok := metricSpecs[metric]
	if !ok {
		server.FailBadRequest(w, "metric 仅支持 cpu / mem / uptime / in / out / iface")
		return
	}
	iface := strings.TrimSpace(q.Get("iface"))
	if metric == "iface" && iface == "" {
		server.FailBadRequest(w, "metric=iface 时必须指定 iface 接口名")
		return
	}
	limit := 300
	if n, err := strconv.Atoi(strings.TrimSpace(q.Get("limit"))); err == nil && n > 0 {
		limit = n
	}
	if limit > 5000 {
		limit = 5000
	}

	rows, err := dao.ByTargetTail(target, limit+1) // 多取一条: 速率需要前一帧
	if err != nil {
		server.FailInternal(w, "查询失败: "+err.Error())
		return
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].At.Before(rows[j].At) })

	from := parseReportTime(q.Get("from"))
	to := parseReportTimeEnd(q.Get("to"))

	pts := make([]timeseriesPoint, 0, len(rows))
	for i, row := range rows {
		s := row.Sample
		if !from.IsZero() && s.At.Before(from) {
			continue
		}
		if !to.IsZero() && s.At.After(to) {
			continue
		}
		var v float64
		switch metric {
		case "cpu":
			v = float64(s.CpuLoad)
		case "mem":
			if s.MemTotal > 0 {
				v = float64(s.MemUsed) / float64(s.MemTotal) * 100
			}
		case "uptime":
			v = float64(s.UptimeSec)
		default:
			// 速率型: 需要前一帧(已按时间升序, i>0 才有)
			if i == 0 {
				continue
			}
			prev := rows[i-1].Sample
			dt := s.At.Sub(prev.At).Seconds()
			if dt <= 0 {
				continue // 同一毫秒的两帧算不出速率, 跳过而不是除零
			}
			var cur, old int64
			if metric == "iface" {
				cur = ifaceOctets(s.Ifaces, iface, metric == "out")
				old = ifaceOctets(prev.Ifaces, iface, metric == "out")
			} else {
				cur = sumOctets(s.Ifaces, metric == "out")
				old = sumOctets(prev.Ifaces, metric == "out")
			}
			if cur < old || old == 0 {
				// 计数器回绕(32 位溢出)或设备重启: 该点不可信, 宁缺勿画出负速率
				continue
			}
			v = float64(cur-old) * 8 / dt // 字节 -> bps
		}
		pts = append(pts, timeseriesPoint{T: s.At.Format(time.RFC3339), V: v})
	}
	if len(pts) > limit {
		pts = pts[len(pts)-limit:]
	}
	server.OK(w, map[string]any{
		"target": target, "metric": metric, "iface": iface, "unit": spec.unit,
		"points": pts, "count": len(pts),
	})
}

// sumOctets 累加全部接口的入/出字节。
func sumOctets(list []monitor.IfaceSample, out bool) int64 {
	var n int64
	for _, f := range list {
		if out {
			n += f.Out
		} else {
			n += f.In
		}
	}
	return n
}

// ifaceOctets 取指定接口的入/出字节(按名字匹配, 找不到返回 0)。
func ifaceOctets(list []monitor.IfaceSample, name string, out bool) int64 {
	for _, f := range list {
		if f.Name != name {
			continue
		}
		if out {
			return f.Out
		}
		return f.In
	}
	return 0
}

// pruneMonitorSamples 保留窗口内的样本: 时长 + 条数双限。
//
// 为什么时长也要: 只按条数(1440)裁剪时, 一个 5 分钟才采一次的冷目标会留着
// 5 天前的点, 曲线横坐标被拉长到看不清今天发生了什么。
func pruneMonitorSamples(dao *db.MonitorDAO, targetID string, keepHours int) {
	if keepHours <= 0 {
		keepHours = defaultRetentionHours
	}
	all, err := dao.ByTarget(targetID)
	if err != nil {
		return
	}
	cut := time.Now().Add(-time.Duration(keepHours) * time.Hour)
	for _, old := range all {
		if old != nil && old.At.Before(cut) {
			_, _ = dao.Delete(old.EntityID())
		}
	}
	all, err = dao.ByTarget(targetID)
	if err != nil || len(all) <= keepSamples {
		return
	}
	for _, old := range all[:len(all)-keepSamples] {
		_, _ = dao.Delete(old.EntityID())
	}
}

// defaultRetentionHours 默认保留时长(24h; 60s 间隔 ≈ 1440 点, 与条数上限一致)。
const defaultRetentionHours = 24
