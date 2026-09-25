package bigscreen

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/models"
)

// TestMetricsFormat 二期预留的 Prometheus 文本导出格式。
func TestMetricsFormat(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	addVuln(t, d, "10.0.0.1", "严重", "critical", models.VulnStatusNew, now, nil)
	addVuln(t, d, "10.0.0.2", "高危", "high", models.VulnStatusNew, now, nil)
	p := &db.Probe{
		ID: "pb-1", Name: "edge", Status: db.ProbeOnline,
		Load: map[string]any{"cpuPercent": 33.3, "memPercent": 50.0, "tasksRunning": 2},
	}
	if _, err := d.Probes().Upsert(p); err != nil {
		t.Fatalf("upsert probe: %v", err)
	}
	a := db.NewAsset("10.0.0.1")
	a.Alive = true
	if _, err := d.Assets().Upsert(a); err != nil {
		t.Fatalf("upsert asset: %v", err)
	}

	s := Build(d, now, Options{})
	text := Metrics(s)

	for _, want := range []string{
		"yugsight_assets_total{alive=\"true\"} 1",
		"yugsight_assets_total{alive=\"false\"} 0",
		"yugsight_vulns_total{severity=\"critical\"} 1",
		"yugsight_vulns_total{severity=\"high\"} 1",
		"yugsight_vulns_total{severity=\"fixed\"} 0",
		"yugsight_probes_total{status=\"online\"} 1",
		"yugsight_tasks_running 0",
		"yugsight_probe_cpu_percent{probe=\"pb-1\"} 33.3",
		"yugsight_probe_mem_percent{probe=\"pb-1\"} 50.0",
		"yugsight_probe_tasks_running{probe=\"pb-1\"} 2",
		"yugsight_snapshot_timestamp_seconds ",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("指标文本缺少 %q:\n%s", want, text)
		}
	}
	// 每个指标都应带 HELP/TYPE(否则 Grafana 无描述, 且部分采集器会告警)
	for _, name := range []string{"yugsight_assets_total", "yugsight_vulns_total", "yugsight_probes_total"} {
		if !strings.Contains(text, "# HELP "+name+" ") || !strings.Contains(text, "# TYPE "+name+" ") {
			t.Fatalf("%s 缺少 HELP/TYPE:\n%s", name, text)
		}
	}
}

// TestMetricsLabelEscaping 标签值必须转义引号/反斜杠/换行。
//
// 不转义会让整个抓取响应变成非法格式, Prometheus 侧的表现是整个 target
// up=0(而不是某条指标错), 现象与原因相隔极远, 所以这里单独守一条用例。
func TestMetricsLabelEscaping(t *testing.T) {
	s := &Snapshot{GeneratedAt: time.Now()}
	raw := "pb\"weird\\id\nnl" // 含 引号 / 反斜杠 / 换行
	s.Probes = []ProbeNode{{ID: raw, Online: true, CPUPercent: floatPtr(10)}}
	text := Metrics(s)

	// 逐字节断言期望输出: 引号 -> \"  反斜杠 -> \\  换行 -> \n
	//
	// 期望行的字面量含义(两层转义容易看错, 逐段拆开):
	//   probe="        开头的引号 + ID 起始
	//   pb\"           原始 ID 里的引号 -> \"
	//   weird\\id      原始 ID 里的反斜杠 -> \\
	//   \nnl           原始 ID 里的换行 -> \n
	//   "} 10.0        闭合引号
	want := "yugsight_probe_cpu_percent{probe=\"" + "pb" + `\"` + "weird" + `\\` + "id" + `\n` + "nl\"} 10.0"
	if !strings.Contains(text, want) {
		t.Fatalf("标签转义结果不符合预期\n期望行: %s\n实际文本:\n%q", want, text)
	}
	// 换行被转义后, 该指标必须仍是独立一行(未被截断)
	count := 0
	for _, ln := range strings.Split(text, "\n") {
		if strings.HasPrefix(ln, "yugsight_probe_cpu_percent{") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("CPU 指标应恰好一行, got %d:\n%s", count, text)
	}
	_ = fmt.Sprint // 保持 fmt 引用(排查时常用)
}

// TestMetricsNilSnapshot nil 快照不 panic。
func TestMetricsNilSnapshot(t *testing.T) {
	if out := Metrics(nil); !strings.Contains(out, "无数据") {
		t.Fatalf("nil 快照应返回占位文本: %q", out)
	}
}

// TestMetricsTimeWithNilDB 库不可用时仍能生成合法文本(抓取端不应 500)。
func TestMetricsTimeWithNilDB(t *testing.T) {
	out := MetricsTime(nil, Options{})
	if !strings.Contains(out, "yugsight_assets_total{alive=\"false\"} 0") {
		t.Fatalf("空库文本错误:\n%s", out)
	}
}
