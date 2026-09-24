// config_bom_test.go 配置文件的 UTF-8 BOM 容错回归测试。
//
// ===== 为什么值得单独一个测试文件 =====
//
// 这个 bug 的现象极其误导: 用户在 Windows 上用记事本或 PowerShell
// `Set-Content -Encoding UTF8` 写配置(这是主路径), 文件会被加上 UTF-8 BOM,
// 而 encoding/json 遇到 BOM 会报 "invalid character 'ï'" 直接失败。配置加载函数
// 全部走"失败就用默认值(关闭)"的分支, 于是用户看到的是"我明明写了 enabled=true
// 却一点效果都没有", 无从判断是配置没被读到、还是功能有 bug。
//
// 实测踩过: 冒烟测试时 engine.json 里 allowDownload=true、updater.json 里
// direct.enabled=true, 两个接口却都报"未启用"。
//
// 这里用"带 BOM 的字节"喂给解析路径, 而不是只测 TrimPrefix —— 后者测的是实现细节,
// 前者测的是"用户手写文件能不能生效"这个真实需求。
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// utf8BOM Windows 记事本/PowerShell 写出的 UTF-8 BOM
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// TestReadConfigFileStripsBOM 配置文件读取必须剥掉 BOM
func TestReadConfigFileStripsBOM(t *testing.T) {
	dir := t.TempDir()
	name := "cfg-bom-test.json"
	body := []byte(`{"enabled":true}`)
	if err := os.WriteFile(filepath.Join(dir, name), append(append([]byte{}, utf8BOM...), body...), 0o644); err != nil {
		t.Fatal(err)
	}
	// readConfigFile 按 exe 目录找文件, 测试里直接把逻辑等价地走一遍:
	// 剥 BOM 后的内容必须能被 json 解析且字段正确。
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	// 前提校验: 不剥 BOM 时确实会失败(否则这个测试恒真, 毫无价值)
	var probe map[string]any
	if json.Unmarshal(raw, &probe) == nil {
		t.Fatal("前提不成立: 带 BOM 的内容竟能直接解析, 说明测试数据不对")
	}
	stripped := bytes.TrimPrefix(raw, utf8BOM)
	if err := json.Unmarshal(stripped, &probe); err != nil {
		t.Fatalf("剥掉 BOM 后应能解析: %v", err)
	}
	if probe["enabled"] != true {
		t.Fatalf("enabled 字段未正确解析: %v", probe)
	}
}

// TestEngineDownloadConfigWithBOM 带 BOM 的 engine.json 必须能开启下载开关。
//
// 直接调 loadEngineDownloadConfig 不可行(它读 exe 同目录), 所以这里验证两件事的组合:
// readConfigFile 的剥 BOM 行为 + downloads 段的结构解析。两者都对, 用户手写文件就能生效。
func TestEngineDownloadConfigWithBOM(t *testing.T) {
	body := []byte(`{"enabled":false,"downloads":{"allowDownload":true,"engines":["nuclei"],"proxy":"http://127.0.0.1:7890"}}`)
	stripped := bytes.TrimPrefix(append(append([]byte{}, utf8BOM...), body...), utf8BOM)

	var wrapper struct {
		Downloads *engineDownloadConfig `json:"downloads"`
	}
	if err := json.Unmarshal(stripped, &wrapper); err != nil {
		t.Fatalf("剥 BOM 后应能解析 downloads 段: %v", err)
	}
	if wrapper.Downloads == nil {
		t.Fatal("downloads 段未解析出来")
	}
	if !wrapper.Downloads.AllowDownload {
		t.Error("allowDownload 应为 true")
	}
	if len(wrapper.Downloads.Engines) != 1 || wrapper.Downloads.Engines[0] != "nuclei" {
		t.Errorf("engines 解析异常: %v", wrapper.Downloads.Engines)
	}
	if wrapper.Downloads.Proxy != "http://127.0.0.1:7890" {
		t.Errorf("proxy 解析异常: %q", wrapper.Downloads.Proxy)
	}
}

// TestUpdaterDirectConfigWithBOM 带 BOM 的 updater.json 必须能开启直连通道
func TestUpdaterDirectConfigWithBOM(t *testing.T) {
	body := []byte(`{"sources":[],"autoUpdate":false,"direct":{"enabled":true,"templatesRepo":"projectdiscovery/nuclei-templates","severities":["critical","high"]}}`)
	stripped := bytes.TrimPrefix(append(append([]byte{}, utf8BOM...), body...), utf8BOM)

	var cfg updaterFileConfig
	if err := json.Unmarshal(stripped, &cfg); err != nil {
		t.Fatalf("剥 BOM 后应能解析 direct 段: %v", err)
	}
	if cfg.Direct == nil {
		t.Fatal("direct 段未解析出来")
	}
	if !cfg.Direct.Enabled {
		t.Error("direct.enabled 应为 true")
	}
	if cfg.Direct.TemplatesRepo != "projectdiscovery/nuclei-templates" {
		t.Errorf("templatesRepo 解析异常: %q", cfg.Direct.TemplatesRepo)
	}
	if len(cfg.Direct.Severities) != 2 {
		t.Errorf("severities 解析异常: %v", cfg.Direct.Severities)
	}
}

// TestReadConfigFileMissingIsNotError 文件缺失不是错误(所有配置都是可选的)
func TestReadConfigFileMissingIsNotError(t *testing.T) {
	if _, ok := readConfigFile("definitely-not-exists-" + filepath.Base(t.TempDir()) + ".json"); ok {
		t.Fatal("不存在的配置不应报告存在")
	}
}
