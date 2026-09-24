// center_status_api.go 阶段 4: 中心端运行状态聚合接口。
//
// 首页仪表盘(Tab1 概览)的"中心端运行状态"面板数据源: 中心主机负载
// (CPU/内存/磁盘)、服务运行时长、任务队列(扫描任务 + 节点采集任务)、
// 数据链路(探针连接 / 数据库 / SSE 消息总线)。
//
// ===== 口径与大屏总览一致: 只读聚合, 不加开关 =====
//
// 不接管扫描、不下发任务、不写库 —— scheduler/report 默认关闭是因为它们
// 改变执行链路, 本接口不属于这一类。若加"启用"开关, 只会多一个"面板为什么
// 没数据"的排查点(见 bigscreen_api.go 的同一决策)。
//
// ===== 逐项降级, 永不整体 500 =====
//
// 面板是常驻展示, 任一子项采集失败只回该子项的降级标记(ok=false / null),
// 不让整个请求失败 —— 数据库读不到不该让 CPU 负载一起消失。
//
// ===== CPU 是两次采样差分 =====
//
// 单次读取算不出占用率(没有基线), 首次调用只记基线并回 null, 前端显示 "-",
// 而不是误导性地显示 0%("看起来很健康")。采样平台实现见
// hoststat_windows.go / hoststat_other.go。
package main

import (
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"yugsight/probe"
	"yugsight/scheduler"
	"yugsight/server"
	"yugsight/sse"
)

// svcStartAt 服务启动时刻(进程初始化时间), 用于计算"服务运行时长"。
//
// 放在包级 var 而不是 main() 里赋值: 包变量初始化先于 main 执行, 任何时刻
// 读到的都是"进程活着多久", 无需关心初始化顺序。
var svcStartAt = time.Now()

var (
	// cpuSampleMu 保护 cpuPrev: 轮询由 HTTP 请求驱动, 可能并发到达,
	// 必须串行"采样 -> 算差 -> 更新基线", 否则差值会拿错基线算出漂移值。
	cpuSampleMu sync.Mutex
	cpuPrev     *cpuTicks
)

// centerCPUPercent 中心主机 CPU 使用率(0-100); 首次调用(无基线)返回 null。
func centerCPUPercent() *float64 {
	cpuSampleMu.Lock()
	defer cpuSampleMu.Unlock()
	cur := sampleCenterCPU()
	if cur == nil {
		return nil
	}
	if cpuPrev == nil {
		cpuPrev = cur
		return nil
	}
	p := cpuTicksPercent(cpuPrev, cur)
	cpuPrev = cur
	return &p
}

// registerCenterStatusRoutes 注册中心端运行状态接口(只读, 无开关)。
func registerCenterStatusRoutes(srv *server.Server) {
	srv.Get("/api/v2/center/status", requireAuth(hCenterStatus))
}

// hCenterStatus GET /api/v2/center/status
//
// 响应结构(全部子项独立降级):
//
//	{
//	  "hostname","os","arch","version",
//	  "startedAt": RFC3339, "uptimeSec": int,
//	  "cpu":   {"percent": 12.5|null, "cores": 8},
//	  "mem":   {"ok":true,"total":…,"used":…,"percent":45.2} | {"ok":false},
//	  "disk":  {"ok":true,"path":…,"total":…,"free":…,"percentUsed":42.1} | {"ok":false},
//	  "tasks": {"enabled","queued","running","paused","slots","maxSlots",
//	             "items":[{id,kind,target,node,progress,startAt}],
//	             "collect":{"running","taskCount"}},
//	  "links": {"probeCenterEnabled","probesOnline","probesTotal",
//	             "db":{"ok","type","dir","stats"},
//	             "sse":{"subscribers","ringUsed","ringCap","lastSeq"}}
//	}
func hCenterStatus(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	out := map[string]any{
		"hostname":  host,
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"version":   appVersion,
		"startedAt": svcStartAt.UTC().Format(time.RFC3339),
		"uptimeSec": int64(time.Since(svcStartAt) / time.Second),
	}

	// ===== 中心主机负载 =====
	out["cpu"] = map[string]any{
		"percent": centerCPUPercent(),
		"cores":   runtime.NumCPU(),
	}
	if total, used, ok := probe.MemStats(); ok {
		out["mem"] = map[string]any{
			"ok":      true,
			"total":   total,
			"used":    used,
			"percent": probe.MemPercent(total, used),
		}
	} else {
		out["mem"] = map[string]any{"ok": false}
	}
	// 磁盘看 exe 所在盘(数据/日志/引擎都落在这): 比固定 C 盘更贴近"还能存多久"
	if total, free, ok := probe.DiskStats(exeDir()); ok {
		pct := float64(0)
		if total > 0 {
			pct = float64(total-free) * 100 / float64(total)
		}
		out["disk"] = map[string]any{
			"ok":          true,
			"path":        exeDir(),
			"total":       total,
			"free":        free,
			"percentUsed": pct,
		}
	} else {
		out["disk"] = map[string]any{"ok": false}
	}

	// ===== 任务队列(扫描任务) =====
	s := instanceScheduler()
	st := s.Stats()
	items := make([]map[string]any, 0, 8)
	if running, _ := s.List(scheduler.StatusRunning, 1, 20); running != nil {
		for _, t := range running {
			items = append(items, map[string]any{
				"id":       t.ID,
				"kind":     t.Kind,
				"target":   t.Target,
				"node":     t.Node, // "" = 中心本地
				"progress": t.Progress,
				"startAt":  t.StartAt,
			})
		}
	}
	out["tasks"] = map[string]any{
		"enabled":    st.Enabled,
		"queued":     st.Queued,   // 等待中
		"running":    st.Running,  // 执行中
		"paused":     st.Paused,
		"slots":      st.Slots,    // 已占用并发槽位
		"maxSlots":   st.MaxSlots, // 全局并发上限
		"items":      items,
		"collect": map[string]any{
			// 节点采集(周期轮询, 独立于扫描队列): 只回"在跑/任务数",
			// 明细仍走 /api/v2/node/status, 这里不重复拉全量
			"running":   instanceCollect().Running(),
			"taskCount": len(instanceCollect().Config().WithDefaults().Tasks),
		},
	}

	// ===== 数据链路 =====
	links := map[string]any{}
	if probeCenter != nil {
		online := len(probeCenter.OnlineIDs())
		total := online
		if d := v2GetDB(); d != nil {
			if dao := d.Probes(); dao != nil {
				if n, err := dao.Count(); err == nil {
					total = n
				}
			}
		}
		if total < online { // 库里的记录可能滞后于实时连接(注册未落库)
			total = online
		}
		links["probeCenterEnabled"] = true
		links["probesOnline"] = online
		links["probesTotal"] = total
	} else {
		links["probeCenterEnabled"] = false
		links["probesOnline"] = 0
		links["probesTotal"] = 0
	}
	if d := v2GetDB(); d != nil {
		links["db"] = map[string]any{
			"ok":    true,
			"type":  d.Type(),
			"dir":   d.Dir(),
			"stats": d.Stats(),
		}
	} else {
		links["db"] = map[string]any{"ok": false}
	}
	// SSE 消息总线: 订阅者数 + 重连补发窗口占用 + 最新事件序号
	hub := sse.Default()
	ringUsed, ringCap, lastSeq := hub.RingStats()
	links["sse"] = map[string]any{
		"subscribers": hub.Clients(),
		"ringUsed":    ringUsed,
		"ringCap":     ringCap,
		"lastSeq":     lastSeq,
	}
	out["links"] = links

	server.OK(w, out)
}
