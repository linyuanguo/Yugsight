package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMigrateLegacyDirs 守 2026-09-24 dist 目录整理的一次性迁移契约:
//   - 旧布局的散落目录(cpe/ rules/ templates/ geoip/ globe/ report_templates/
//     web/ scanctl/ cache/)迁移进新布局(vuln/ res/ data/), 文件不丢;
//   - 迁移后旧目录不再存在;
//   - 新旧并存时跳过, 绝不自动删除任何用户数据。
func TestMigrateLegacyDirs(t *testing.T) {
	withTempExeDir(t)
	base := exeDir()

	oldDirs := []struct{ dir, file string }{
		{"cpe", "nvd-nginx.json"},
		{"rules", "ms-1.yaml"},
		{"templates", "tpl.yaml"},
		{"geoip", "geoip4.tsv"},
		{"globe", "globe.gl.min.js"},
		{"report_templates", "config.yaml"},
		{"web", "agent_install.html"},
		{"scanctl", "whitelist.jsonl"},
		{"cache", "templates-abc.zip.part"},
	}
	for _, d := range oldDirs {
		p := filepath.Join(base, d.dir)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, d.file), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 新旧并存用例: intel/ 与 vuln/intel/ 同时存在 → 应跳过, 两边都保留
	for _, p := range []string{"intel", filepath.Join("vuln", "intel")} {
		if err := os.MkdirAll(filepath.Join(base, p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, p, "intel.json"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 迁移产物必须清理: 测试 exe 目录是共享的(与 withTempExeDir 其它用例同目录),
	// 残留的 res/web/agent_install.html(内容 "x") 会让后续安装落地页测试渲染出
	// 异常页面 —— "单跑通过、全量失败"的典型污染源
	t.Cleanup(func() {
		for _, d := range []string{
			filepath.Join("vuln", "cpe"), filepath.Join("vuln", "rules"),
			filepath.Join("vuln", "templates"), filepath.Join("vuln", "intel"),
			filepath.Join("res", "geoip"), filepath.Join("res", "globe"),
			filepath.Join("res", "report_templates"), filepath.Join("res", "web"),
			filepath.Join("data", "scanctl"), filepath.Join("data", "cache"),
		} {
			_ = os.RemoveAll(filepath.Join(base, d))
		}
		// 新旧并存用例的旧目录也清掉
		_ = os.RemoveAll(filepath.Join(base, "intel"))
		// 空父目录顺手清掉(非空时 os.Remove 静默失败, 无副作用)
		for _, d := range []string{"vuln", "res", "data"} {
			_ = os.Remove(filepath.Join(base, d))
		}
	})

	migrateLegacyDirs()

	wantNew := []struct{ dir, file string }{
		{filepath.Join("vuln", "cpe"), "nvd-nginx.json"},
		{filepath.Join("vuln", "rules"), "ms-1.yaml"},
		{filepath.Join("vuln", "templates"), "tpl.yaml"},
		{filepath.Join("res", "geoip"), "geoip4.tsv"},
		{filepath.Join("res", "globe"), "globe.gl.min.js"},
		{filepath.Join("res", "report_templates"), "config.yaml"},
		{filepath.Join("res", "web"), "agent_install.html"},
		{filepath.Join("data", "scanctl"), "whitelist.jsonl"},
		{filepath.Join("data", "cache"), "templates-abc.zip.part"},
	}
	for _, w := range wantNew {
		if !dirIsDir(filepath.Join(base, w.dir)) {
			t.Errorf("迁移后应存在目录 %s/", w.dir)
		}
		if _, err := os.Stat(filepath.Join(base, w.dir, w.file)); err != nil {
			t.Errorf("迁移后文件 %s/%s 应在: %v", w.dir, w.file, err)
		}
	}
	for _, d := range oldDirs {
		if dirIsDir(filepath.Join(base, d.dir)) {
			t.Errorf("迁移后旧目录 %s/ 不应再存在", d.dir)
		}
	}
	for _, p := range []string{"intel", filepath.Join("vuln", "intel")} {
		if !dirIsDir(filepath.Join(base, p)) {
			t.Errorf("新旧并存时 %s/ 应原样保留", p)
		}
	}
}
