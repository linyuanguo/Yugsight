package parsers

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Windows 测试替身: engine.Executor.findBin 在 Windows 上只认 .exe
// (其它平台跳过带扩展点的文件), 因此不能用手写 .bat 脚本, 改为现场编译
// 一个最小 Go 程序作为"引擎替身":
//
//	替身逻辑: 从命令行参数里找 -J <file>, 找到则把报告写进该文件;
//	             否则把固定内容写到 stdout。
//
// 编译需要 go 工具链(测试环境本就在跑 go test, 必然可用);
// 编译失败时返回空串, 由调用方 t.Skip。

const fakeEngineSrc = `package main

import (
	"os"
	"strings"
)

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
	_ = strings.TrimSpace
}
`

// buildFakeEngine 编译替身到 dir/<name>.exe 并返回其路径。
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
	bin := filepath.Join(dir, name+".exe")
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

// fakeEngineBinaryContent 编译名为 nmap.exe 的替身(引擎名 nmap 前缀匹配)。
func fakeEngineBinaryContent(t *testing.T, dir, content string) string {
	return buildFakeEngine(t, dir, "nmap", content)
}

// fakeEngineBinaryFor 编译指定引擎名的替身(nmap / trivy / zap)。
func fakeEngineBinaryFor(t *testing.T, dir, engineName, content string) string {
	return buildFakeEngine(t, dir, engineName, content)
}

// fakeZapBinary 编译 zap.exe: 把 ZAP 样例报告写入 -J 指定的文件。
func fakeZapBinary(t *testing.T, dir string) bool {
	return buildFakeEngine(t, dir, "zap", zapSample) != ""
}
