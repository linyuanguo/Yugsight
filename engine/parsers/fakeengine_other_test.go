//go:build !windows

package parsers

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 非 Windows 测试替身: engine.Executor.findBin 在非 Windows 上跳过带扩展点的
// 文件, 因此编译成无扩展名的可执行文件即可被"前缀匹配"命中。
// 替身逻辑: 参数含 -J <file> 时把报告写入该文件, 否则 fixed 内容写 stdout。

const fakeEngineSrc = `package main

import "os"

const payload = ` + "`" + `%PAYLOAD%` + "`" + `

func main() {
	args := os.Args[1:]
	out := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "-J" && i+1 < len(args) {
			out = args[i+1]
		}
	}
	if out != "" {
		if err := os.WriteFile(out, []byte(payload), 0o644); err != nil {
			os.Exit(3)
		}
		return
	}
	os.Stdout.WriteString(payload)
}
`

func buildFakeEngine(t *testing.T, dir, name, payload string) string {
	t.Helper()
	srcDir := t.TempDir()
	src := strings.Replace(fakeEngineSrc, "%PAYLOAD%", payload, 1)
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o600); err != nil {
		t.Logf("写入替身源码失败: %v", err)
		return ""
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module fakeengine\n\ngo 1.25\n"), 0o600); err != nil {
		t.Logf("写入替身 go.mod 失败: %v", err)
		return ""
	}
	bin := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = srcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("编译替身引擎失败: %v (%s)", err, strings.TrimSpace(string(out)))
		return ""
	}
	return bin
}

func fakeEngineBinary(t *testing.T, dir string) string {
	return fakeEngineBinaryContent(t, dir, nmapXMLSample)
}

func fakeEngineBinaryContent(t *testing.T, dir, content string) string {
	return buildFakeEngine(t, dir, "nmap", content)
}

func fakeEngineBinaryFor(t *testing.T, dir, engineName, content string) string {
	return buildFakeEngine(t, dir, engineName, content)
}

func fakeZapBinary(t *testing.T, dir string) bool {
	return buildFakeEngine(t, dir, "zap", zapSample) != ""
}
