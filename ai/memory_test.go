package ai

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeStore 四个范围各给固定数据(时间相对 now 排布, 验证保留时长过滤)。
type fakeStore struct {
	now   time.Time
	assets []MemoryEntry
	alerts []MemoryEntry
	captures []MemoryEntry
	metrics []MemoryEntry
}

func (f fakeStore) entry(scope string, ago time.Duration) MemoryEntry {
	return MemoryEntry{At: f.now.Add(-ago), Label: scope + "-entry"}
}

func (f fakeStore) AssetHistory(since time.Time, limit int) ([]MemoryEntry, error) {
	out := f.filter(f.assets, since, limit)
	return out, nil
}
func (f fakeStore) AlertHistory(since time.Time, limit int) ([]MemoryEntry, error) {
	return f.filter(f.alerts, since, limit), nil
}
func (f fakeStore) CaptureHistory(since time.Time, limit int) ([]MemoryEntry, error) {
	return f.filter(f.captures, since, limit), nil
}
func (f fakeStore) MetricHistory(since time.Time, limit int) ([]MemoryEntry, error) {
	return f.filter(f.metrics, since, limit), nil
}

func (f fakeStore) filter(items []MemoryEntry, since time.Time, limit int) []MemoryEntry {
	var out []MemoryEntry
	for _, it := range items {
		if it.At.Before(since) {
			continue
		}
		out = append(out, it)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func newFakeStore(t *testing.T, retainDays int) (MemoryConfig, fakeStore) {
	t.Helper()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.Local)
	st := fakeStore{now: now}
	st.assets = []MemoryEntry{st.entry("asset", time.Hour), st.entry("asset-old", 40 * 24 * time.Hour)}
	st.alerts = []MemoryEntry{st.entry("alert", 2 * time.Hour)}
	st.captures = []MemoryEntry{st.entry("cap", 3 * time.Hour)}
	st.metrics = []MemoryEntry{st.entry("metric", 4 * time.Hour)}
	cfg := DefaultConfig().Memory
	cfg.RetainDays = retainDays
	return cfg, st
}

// TestGatherAllScopes 四范围全开: 各自段落 + 保留时长过滤(40 天前的
// 资产记录被 30 天窗排除) + 条数统计。
func TestGatherAllScopes(t *testing.T) {
	cfg, st := newFakeStore(t, 30)
	text, n := Gather(cfg, st.now, st)
	if n != 4 {
		t.Fatalf("条数=%d 期望 4(1 条被保留时长过滤)", n)
	}
	for _, label := range []string{"【资产扫描记录】", "【历史告警事件】", "【抓包分析记录】", "【节点历史指标】"} {
		if !strings.Contains(text, label) {
			t.Fatalf("缺少段落 %s: %s", label, text)
		}
	}
	if strings.Contains(text, "asset-old") {
		t.Fatal("超出保留时长的记录不应出现")
	}
}

// TestGatherScopeOff 关闭某范围 = 该段落缺席, 其余照常。
func TestGatherScopeOff(t *testing.T) {
	cfg, st := newFakeStore(t, 30)
	cfg.Scopes.Metrics = false
	text, n := Gather(cfg, st.now, st)
	if n != 3 {
		t.Fatalf("条数=%d 期望 3", n)
	}
	if strings.Contains(text, "【节点历史指标】") {
		t.Fatal("关闭的范围不应出现")
	}
}

// TestGatherCompress vs 非压缩: 压缩模式只有单行摘要; 非压缩附 detail。
func TestGatherCompress(t *testing.T) {
	cfg, st := newFakeStore(t, 30)
	cfg.Scopes = MemoryScopes{Alerts: true}
	cfg.Scopes.Assets = false
	st.alerts[0].Detail = "完整JSON明细"

	comp, _ := Gather(cfg, st.now, st)
	if strings.Contains(comp, "完整JSON明细") {
		t.Fatal("压缩模式不应带 detail")
	}

	cfg.Compress = false
	raw, _ := Gather(cfg, st.now, st)
	if !strings.Contains(raw, "完整JSON明细") {
		t.Fatal("非压缩模式应带 detail")
	}
}

// TestGatherEmpty 全空/关闭 = 明确文案(不是空串 —— LLM 要能区分
// "没有历史"与"数据被截断")。
func TestGatherEmpty(t *testing.T) {
	cfg, st := newFakeStore(t, 30)
	if text, n := Gather(cfg, st.now, fakeStore{now: st.now}); n != 0 || text == "" {
		t.Fatalf("全空: text=%q n=%d", text, n)
	}
	cfg.Enabled = false
	if text, n := Gather(cfg, st.now, st); n != 0 || !strings.Contains(text, "未启用") {
		t.Fatalf("关闭: text=%q n=%d", text, n)
	}
}

// TestGatherTruncate 记忆总量超预算截断(参考资料不能挤占原始数据)。
func TestGatherTruncate(t *testing.T) {
	cfg, st := newFakeStore(t, 365)
	cfg.MaxItems = 50
	cfg.Scopes = MemoryScopes{Assets: true}
	for i := 0; i < 500; i++ {
		st.assets = append(st.assets, MemoryEntry{
			At:    st.now.Add(-time.Duration(i) * time.Minute),
			Label: fmt.Sprintf("条目-%03d %s", i, strings.Repeat("漏洞详情描述", 20)),
		})
	}
	text, n := Gather(cfg, st.now, st)
	if n != 50 {
		t.Fatalf("条数上限未生效: %d", n)
	}
	if !strings.Contains(text, "已截断") {
		t.Fatal("超预算应截断并留标记")
	}
}

// TestScopesLabel 已勾选范围标签(配置页/审计展示)。
func TestScopesLabel(t *testing.T) {
	cfg := DefaultConfig().Memory
	if got := cfg.ScopesLabel(); got != "资产扫描记录,历史告警事件,抓包分析记录,节点历史指标" {
		t.Fatalf("got=%s", got)
	}
	cfg.Scopes = MemoryScopes{Captures: true}
	if got := cfg.ScopesLabel(); got != "抓包分析记录" {
		t.Fatalf("got=%s", got)
	}
}
