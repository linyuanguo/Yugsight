package ai

import (
	"strings"
	"testing"
)

// TestRenderVars 六个内置变量全部替换。
func TestRenderVars(t *testing.T) {
	tpl := "{{time}} | {{asset_info}} | {{raw_data}} | {{scan_result}} | {{metric_data}} | {{structured_memory}}"
	got := Render(tpl, map[string]string{
		"time":              "T",
		"asset_info":        "10.0.0.1",
		"raw_data":          "RAW",
		"scan_result":       "VULNS",
		"metric_data":       "METRICS",
		"structured_memory": "MEM",
	})
	want := "T | 10.0.0.1 | RAW | VULNS | METRICS | MEM"
	if got != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

// TestRenderMissingVar 缺变量 = 替换为"无"(LLM 能区分"空数据"与"被截断")。
func TestRenderMissingVar(t *testing.T) {
	got := Render("资产: {{asset_info}} 结束", map[string]string{})
	if got != "资产: 无 结束" {
		t.Fatalf("got=%q", got)
	}
}

// TestRenderUnknownVarPreserved 用户自创变量原样保留 —— 静默抹掉会让
// 用户误以为变量生效了(实际是空的)。
func TestRenderUnknownVarPreserved(t *testing.T) {
	got := Render("自定义 {{my_var}} 保留", map[string]string{})
	if got != "自定义 {{my_var}} 保留" {
		t.Fatalf("got=%q", got)
	}
}

// TestRenderNoPlaceholder 无变量内容原样通过(含花括号字面量)。
func TestRenderNoPlaceholder(t *testing.T) {
	in := "JSON 示例 {\"a\": 1} 与单花括号 {x}"
	if got := Render(in, map[string]string{"time": "T"}); got != in {
		t.Fatalf("got=%q want=%q", got, in)
	}
	// 不完整占位 {{abc (无 }}) 原样通过
	in2 := "残缺 {{abc 保留"
	if got := Render(in2, nil); got != in2 {
		t.Fatalf("got=%q", got)
	}
}

// TestDefaultPromptContainsCoreVars 三套预设模板都含时间与原始数据变量
// (渲染契约: 业务页面把数据填进模板, 核心变量缺失 = 模板没用)。
func TestDefaultPromptContainsCoreVars(t *testing.T) {
	for _, k := range []string{TplCapture, TplScan, TplMonitor} {
		p := DefaultPrompt(k)
		if !strings.Contains(p, "{{time}}") || !strings.Contains(p, "{{raw_data}}") {
			t.Fatalf("模板 %s 缺少核心变量: %s", k, p)
		}
	}
	// 模块专属变量归属: 扫描模板用 scan_result, 监控模板用 metric_data
	if !strings.Contains(DefaultPrompt(TplScan), "{{scan_result}}") {
		t.Fatal("扫描模板应含 scan_result")
	}
	if !strings.Contains(DefaultPrompt(TplMonitor), "{{metric_data}}") {
		t.Fatal("监控模板应含 metric_data")
	}
}

// TestSortVars 变量列表排序稳定(UI 展示口径)。
func TestSortVars(t *testing.T) {
	got := SortVars([]string{"time", "raw_data", "asset_info"})
	if got[0] != "asset_info" || got[2] != "time" {
		t.Fatalf("got=%v", got)
	}
}
