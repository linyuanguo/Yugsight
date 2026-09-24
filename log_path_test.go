package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yugsight/pathrel"
)

// 契约: 任何模块经 logLine 输出的日志, exe 目录树内的绝对路径必须被相对化,
// 目录外的内容(如 URL)不受影响。兜底钩子在日志入口, 若有人改 logLine 绕过它,
// 这里会红 —— 而不是等用户在控制台看到长路径才发现。
//
// 根包测试无 t.Parallel()(包内串行), logLine 经 os.Stdout 写控制台,
// 故可安全地替换 os.Stdout 短暂捕获。
func TestLogLineRelativizesExeDirPaths(t *testing.T) {
	base := t.TempDir()
	pathrel.SetExeDirForTest(func() string { return base })
	t.Cleanup(func() { pathrel.SetExeDirForTest(func() string { return "" }) })

	marker := "pathrel-logcheck-9x7q"
	abs := filepath.Join(base, "data", "assets.jsonl")

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	logLine(fmt.Sprintf("%s: 表 assets 已加载 1 条记录 (%s), 见 http://192.168.1.143:8420", marker, abs))
	w.Close()
	os.Stdout = oldStdout
	buf, _ := io.ReadAll(r)

	out := string(buf)
	if !strings.Contains(out, marker) {
		t.Fatalf("未捕获到本用例写入的日志行: %q", out)
	}
	rel := "." + string(filepath.Separator)
	if !strings.Contains(out, rel+"data"+string(filepath.Separator)+"assets.jsonl") {
		t.Fatalf("日志行未相对化: %s", out)
	}
	if strings.Contains(out, base) {
		t.Fatalf("日志行仍含 exe 目录绝对路径: %s", out)
	}
	if !strings.Contains(out, "http://192.168.1.143:8420") {
		t.Fatalf("URL 被误伤: %s", out)
	}
}
