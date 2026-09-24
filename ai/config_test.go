package ai

import (
	"testing"
)

// TestLoadConfigDefaults ai 节缺失 = 全默认: 全局默认关(规则 5),
// 模块开关/模板/RAG/记忆库按"用户点按钮即可用"预设。
func TestLoadConfigDefaults(t *testing.T) {
	cfg := LoadConfig(nil)
	if cfg.Enabled {
		t.Fatal("全局 enabled 默认必须为 false(默认关)")
	}
	if cfg.MaxContext != defMaxContext || cfg.TimeoutSec != defTimeoutSec {
		t.Fatalf("基础参数默认值漂移: maxContext=%d timeout=%d", cfg.MaxContext, cfg.TimeoutSec)
	}
	if !cfg.Modules.Capture || !cfg.Modules.Scan || !cfg.Modules.Monitor {
		t.Fatal("模块开关默认应全开(受全局 enabled 约束, 默认关时零调用)")
	}
	for _, k := range []string{TplCapture, TplScan, TplMonitor} {
		p, err := cfg.Prompt(k)
		if err != nil || p.Content == "" {
			t.Fatalf("默认模板缺失: %s err=%v", k, err)
		}
	}
	if !cfg.RAG.Enabled || cfg.RAG.TopK != defTopK {
		t.Fatalf("RAG 默认: enabled=%v topK=%d", cfg.RAG.Enabled, cfg.RAG.TopK)
	}
	if !cfg.Memory.Enabled || cfg.Memory.RetainDays != defRetainDays {
		t.Fatalf("记忆库默认: enabled=%v retain=%d", cfg.Memory.Enabled, cfg.Memory.RetainDays)
	}
	if !cfg.Memory.Scopes.Assets || !cfg.Memory.Scopes.Alerts || !cfg.Memory.Scopes.Captures || !cfg.Memory.Scopes.Metrics {
		t.Fatal("记忆库范围默认应全选")
	}
}

// TestLoadConfigPartialOverride 只写部分字段: 缺的保持默认, 写了的被覆盖
// (含显式 false —— "用户显式关"与"没写"不能混淆)。
func TestLoadConfigPartialOverride(t *testing.T) {
	raw := []byte(`{
		"enabled": true,
		"apiBase": "http://10.0.0.5:8000/v1",
		"model": "qwen2.5:14b",
		"desensitize": false,
		"modules": {"capture": false},
		"memory": {"retainDays": 7, "scopes": {"alerts": false}}
	}`)
	cfg := LoadConfig(raw)
	if !cfg.Enabled || cfg.Model != "qwen2.5:14b" {
		t.Fatalf("显式字段未生效: %+v", cfg.BasicConfig)
	}
	if cfg.Desensitize {
		t.Fatal("显式 desensitize=false 被默认值覆盖")
	}
	// 未写的模块开关保持默认 true
	if !cfg.Modules.Scan || !cfg.Modules.Monitor {
		t.Fatalf("未写的模块开关应保持默认: %+v", cfg.Modules)
	}
	if cfg.Modules.Capture {
		t.Fatal("显式 capture=false 被覆盖")
	}
	// memory 合并语义: 写了的覆盖, 没写的保持默认
	if cfg.Memory.RetainDays != 7 || cfg.Memory.Scopes.Alerts {
		t.Fatalf("memory 合并错: %+v", cfg.Memory)
	}
	if cfg.Memory.MaxItems != defMaxItems || !cfg.Memory.Scopes.Assets {
		t.Fatalf("memory 未写字段应保持默认: %+v", cfg.Memory)
	}
}

// TestLoadConfigCorrupt 配置损坏 = 全默认(降级不崩, 规则 4)。
func TestLoadConfigCorrupt(t *testing.T) {
	cfg := LoadConfig([]byte(`{"enabled": tru`))
	if cfg.Enabled || cfg.MaxContext != defMaxContext {
		t.Fatal("损坏配置应回退全默认")
	}
	cfg = LoadConfig([]byte("null"))
	if cfg.Enabled {
		t.Fatal("null 段应回退默认(enabled=false)")
	}
}

// TestTplKeyForModule 模块→模板映射(弱口令/合并复用漏洞报告模板;
// 未知模块明确拒绝 —— 防"随便传个模块就发 LLM 请求")。
func TestTplKeyForModule(t *testing.T) {
	cases := map[string]struct {
		key string
		ok  bool
	}{
		"capture":  {TplCapture, true},
		"scan":     {TplScan, true},
		"weakpass": {TplScan, true},
		"merged":   {TplScan, true},
		"monitor":  {TplMonitor, true},
		"collect":  {TplMonitor, true},
		"bogus":    {"", false},
		"":         {"", false},
	}
	for mod, want := range cases {
		got, ok := TplKeyForModule(mod)
		if ok != want.ok || (ok && got != want.key) {
			t.Fatalf("module=%q: got(%q,%v) want(%q,%v)", mod, got, ok, want.key, want.ok)
		}
	}
	cfg := DefaultConfig()
	cfg.Modules.Scan = false
	if cfg.ModuleEnabled(TplScan) {
		t.Fatal("关闭 scan 后 TplScan 应不可用")
	}
	if !cfg.ModuleEnabled(TplCapture) || !cfg.ModuleEnabled(TplMonitor) {
		t.Fatal("未关闭的模块应保持可用")
	}
}

// TestCurrentConfigReader 装配层注入读取器后 CurrentConfig 实时读;
// 未注入 = 全默认。
func TestCurrentConfigReader(t *testing.T) {
	prev := func() ([]byte, bool) { return nil, false }
	SetConfigReader(prev)
	t.Cleanup(func() { SetConfigReader(prev) })

	if c := CurrentConfig(); c.Enabled {
		t.Fatal("读取器返回不存在时应为默认(enabled=false)")
	}
	SetConfigReader(func() ([]byte, bool) {
		return []byte(`{"enabled":true,"model":"m1"}`), true
	})
	c := CurrentConfig()
	if !c.Enabled || c.Model != "m1" {
		t.Fatalf("注入后未生效: %+v", c.BasicConfig)
	}
}
