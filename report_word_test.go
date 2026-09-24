package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReportConfigDefaultEnabled 报告默认开启契约(用户 2026-09-20 硬要求):
// 配置缺失 = 开; 显式 enabled=false = 关; 部分配置(只写 maxArchive 不写 enabled)
// 不能隐式关闭 —— 否则用户现象是"我只调了存档上限, 报告怎么没了"。
//
// 配置唯一整改(2026-09-23)后: 用例改为写 settings.json 的 report 节 ——
// 中心端不再有 report.json, 旧文件由 migrateLegacyConfigs 启动时并入。
func TestReportConfigDefaultEnabled(t *testing.T) {
	dir := t.TempDir()
	setSettingsTestPath(filepath.Join(dir, "settings.json"))
	t.Cleanup(func() {
		setSettingsTestPath("")
		resetSettingsCache()
		resetReportConfigForTest()
	})

	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		resetSettingsCache()
		resetReportConfigForTest()
	}

	// 1) 无任何配置文件 -> 默认开
	if cfg := loadReportConfig(); !cfg.Enabled {
		t.Fatal("无配置时应默认启用报告引擎")
	}

	// 2) 部分配置(不写 enabled) -> 仍开, 且字段生效
	write(`{"report":{"maxArchive":100}}`)
	if cfg := loadReportConfig(); !cfg.Enabled {
		t.Fatal("部分配置(未写 enabled)不应隐式关闭报告引擎")
	}
	if cfg := loadReportConfig(); cfg.MaxArchive != 100 {
		t.Fatalf("maxArchive 未生效: %d", cfg.MaxArchive)
	}

	// 3) 显式 enabled=false -> 关
	write(`{"report":{"enabled":false}}`)
	if cfg := loadReportConfig(); cfg.Enabled {
		t.Fatal("显式 enabled=false 应关闭报告引擎")
	}
}

// TestReportConfigMigratedSection 旧 report.json 迁到 settings.json 后仍生效。
//
// 守的是迁移链路: 老机器升级后配置不能"看着还在其实没被读到"。
func TestReportConfigMigratedSection(t *testing.T) {
	dir := t.TempDir()
	setSettingsTestPath(filepath.Join(dir, "settings.json"))
	t.Cleanup(func() {
		setSettingsTestPath("")
		resetSettingsCache()
		resetReportConfigForTest()
	})
	// 模拟迁移结果: settings.json 里已有 report 节(内容来自原 report.json)
	if err := os.WriteFile(filepath.Join(dir, "settings.json"),
		[]byte(`{"report":{"enabled":true,"maxArchive":42}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	resetSettingsCache()
	resetReportConfigForTest()
	cfg := loadReportConfig()
	if !cfg.Enabled || cfg.MaxArchive != 42 {
		t.Fatalf("迁移后的 report 节未生效: %+v", cfg)
	}
}
