package bigscreen

import (
	"fmt"
	"strings"
	"time"

	"yugsight/db"
)

// ===== 二期扩展预留: Prometheus /metrics 文本导出 =====
//
// 现状: 本函数是**纯导出层**, 只把已有的 Snapshot 翻译成 Prometheus 文本格式,
// 不引入任何第三方客户端库(项目硬约束: 纯标准库、零第三方依赖), 也不改变
// MVP 的任何行为 —— 未挂载路由时这段代码不会被调用。
//
// 对外暴露的指标(前缀 yugsight_):
//   yugsight_assets_total{alive}                 资产总量(按存活态分组)
//   yugsight_vulns_total{severity}               未修复漏洞数(按等级)
//   yugsight_vulns_total{severity="fixed"}       已修复漏洞数
//   yugsight_vulns_false_positive_total          误报标记数
//   yugsight_vulns_found_total                   窗口内新增漏洞
//   yugsight_vulns_fixed_total                   窗口内修复漏洞
//   yugsight_probes_total{status}                探针数(online/offline/disabled)
//   yugsight_probe_cpu_percent{probe}            探针 CPU 占用
//   yugsight_probe_mem_percent{probe}            探针内存占用
//   yugsight_probe_tasks_running{probe}          探针当前任务数
//   yugsight_tasks_running                       运行中任务(pending+running)
//   yugsight_tasks_total{status}                 任务数(按状态)
//   yugsight_whitelist_entries                   生效白名单条数
//   yugsight_snapshot_timestamp_seconds          快照生成时间(Unix 秒)
//
// 接入方式(二期): 在 main.go 增加一条路由即可, 例如
//   mux.HandleFunc("/metrics", handleMetrics)
// 是否鉴权由部署方决定 —— 抓取端(Grafana/Prometheus)通常不便带会话 cookie,
// 因此建议独立端口或 IP 白名单, 而不是直接复用 requireAuth。
//
// Metrics 渲染 Prometheus 文本格式(见上表)。
func Metrics(s *Snapshot) string {
	if s == nil {
		return "# 无数据\n"
	}
	var b strings.Builder
	line := func(format string, args ...any) {
		b.WriteString(fmt.Sprintf(format, args...))
		b.WriteByte('\n')
	}

	line("# HELP yugsight_snapshot_timestamp_seconds 大屏快照生成时间(Unix 秒)")
	line("# TYPE yugsight_snapshot_timestamp_seconds gauge")
	line("yugsight_snapshot_timestamp_seconds %d", s.GeneratedAt.Unix())

	line("# HELP yugsight_assets_total 资产总量(alive=\"true\" 为存活资产)")
	line("# TYPE yugsight_assets_total gauge")
	line("yugsight_assets_total{alive=\"true\"} %d", s.Overview.AssetsAlive)
	line("yugsight_assets_total{alive=\"false\"} %d", s.Overview.AssetsDown)

	line("# HELP yugsight_vulns_total 漏洞数量(按风险等级; severity=\"fixed\" 为已修复)")
	line("# TYPE yugsight_vulns_total gauge")
	for _, k := range SevOrder {
		line("yugsight_vulns_total{severity=%q} %d", k, sevCountOf(s.Overview.Vulns, k))
	}
	line("yugsight_vulns_total{severity=\"fixed\"} %d", s.Overview.VulnFixed)
	line("yugsight_vulns_false_positive_total %d", s.Overview.FalsePosCount)

	line("# HELP yugsight_vulns_found_total 趋势窗口内新增(首次发现)漏洞数")
	line("# TYPE yugsight_vulns_found_total gauge")
	line("yugsight_vulns_found_total %d", s.Trend.NewTotal)

	line("# HELP yugsight_vulns_fixed_total 趋势窗口内修复漏洞数")
	line("# TYPE yugsight_vulns_fixed_total gauge")
	line("yugsight_vulns_fixed_total %d", s.Trend.FixedTotal)

	line("# HELP yugsight_probes_total 探针数量(按状态)")
	line("# TYPE yugsight_probes_total gauge")
	line("yugsight_probes_total{status=\"online\"} %d", s.Overview.ProbesOnline)
	line("yugsight_probes_total{status=\"offline\"} %d", s.Overview.ProbesOffline)

	line("# HELP yugsight_probe_cpu_percent 探针 CPU 占用百分比")
	line("# TYPE yugsight_probe_cpu_percent gauge")
	for _, p := range s.Probes {
		if !p.Online || p.CPUPercent == nil {
			continue
		}
		line("yugsight_probe_cpu_percent{probe=%s} %s", label(p.ID), ftoa(*p.CPUPercent))
	}
	line("# HELP yugsight_probe_mem_percent 探针内存占用百分比")
	line("# TYPE yugsight_probe_mem_percent gauge")
	for _, p := range s.Probes {
		if !p.Online || p.MemPercent == nil {
			continue
		}
		line("yugsight_probe_mem_percent{probe=%s} %s", label(p.ID), ftoa(*p.MemPercent))
	}
	line("# HELP yugsight_probe_tasks_running 探针当前执行中的任务数")
	line("# TYPE yugsight_probe_tasks_running gauge")
	for _, p := range s.Probes {
		if !p.Online {
			continue
		}
		line("yugsight_probe_tasks_running{probe=%s} %d", label(p.ID), p.TasksRunning)
	}

	line("# HELP yugsight_tasks_running 当前运行中(含排队)扫描任务数")
	line("# TYPE yugsight_tasks_running gauge")
	line("yugsight_tasks_running %d", s.Overview.TasksRunning)

	line("# HELP yugsight_tasks_total 扫描任务数(按状态)")
	line("# TYPE yugsight_tasks_total gauge")
	line("yugsight_tasks_total{status=\"success\"} %d", s.Overview.TasksSuccess)
	line("yugsight_tasks_total{status=\"failed\"} %d", s.Overview.TasksFailed)

	line("# HELP yugsight_whitelist_entries 生效中的白名单条目数")
	line("# TYPE yugsight_whitelist_entries gauge")
	line("yugsight_whitelist_entries %d", s.Overview.WhitelistCount)

	return b.String()
}

// label 渲染一个 Prometheus 标签: label="已转义的值"。
//
// 【踩过的坑】这里必须手工拼引号, 不能写 %q —— fmt 的 %q 会再做一次 Go 风格
// 转义, 与 esc 叠加后引号变成三个反斜杠, 输出的文本格式非法(Prometheus 侧
// 表现为整个 target up=0, 现象与原因相隔极远, 极难排查)。
func label(v string) string {
	return `"` + esc(v) + `"`
}

// esc 转义 Prometheus 标签值中的反斜杠/引号/换行。
//
// 不转义会让"探针 ID / 漏洞标题里带引号"这类数据直接把整个抓取响应弄成
// 非法格式。替换顺序必须是反斜杠在前: 若先转引号, 后加的 \ 会被再次转义。
func esc(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	return r.Replace(s)
}

// ftoa 浮点格式化(保留 1 位小数, 避免科学计数法)。
func ftoa(f float64) string { return fmt.Sprintf("%.1f", f) }

// MetricsTime 便捷函数: 生成当前时刻的快照并渲染为 Prometheus 文本。
func MetricsTime(d *db.Database, opt Options) string {
	return Metrics(Build(d, time.Now(), opt))
}
