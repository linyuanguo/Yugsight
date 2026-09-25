package probe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// binDirPath 返回 exe 同目录的 bin/(本地引擎约定放置处, 与 envdetect 包一致)。
func binDirPath() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(".", "bin")
	}
	return filepath.Join(filepath.Dir(exe), "bin")
}

// findInDir 在 dir 下按前缀匹配引擎二进制:
// 精确 <prefix>[.exe] 优先, 否则任意 <prefix>* 可执行文件(如 nmap-7.94.exe)。
// 可执行判定与 envdetect 一致: Windows 只认 .exe, 其它平台跳过带点的文件。
func findInDir(dir, prefix string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	isWin := runtime.GOOS == "windows"
	var loose string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.ToLower(e.Name())
		if isWin && !strings.HasSuffix(n, ".exe") {
			continue
		}
		if !isWin && strings.Contains(n, ".") {
			continue
		}
		if n == prefix || n == prefix+".exe" {
			return filepath.Join(dir, e.Name())
		}
		if strings.HasPrefix(n, prefix) && loose == "" {
			loose = filepath.Join(dir, e.Name())
		}
	}
	return loose
}

var verRe = regexp.MustCompile(`(\d+\.\d+(?:\.\d+){0,3})`)

// versionOf 运行引擎的版本参数并解析版本号(5s 超时, 失败返回空串)。
func versionOf(path string) string {
	for _, args := range [][]string{{"--version"}, {"version"}, {"-version"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		cancel()
		if err != nil {
			continue
		}
		if m := verRe.FindString(string(out)); m != "" {
			return m
		}
	}
	return ""
}

// engineVersions 探测 ./bin/ 下的 nmap/trivy/zap 版本(探针端上报用, 平台通用)。
func engineVersions() []EngineVer {
	dir := binDirPath()
	specs := []struct{ Name, Prefix string }{
		{"nmapcore", "nmap"},
		{"trivycore", "trivy"},
		{"zapcore", "zap"},
	}
	out := make([]EngineVer, 0, len(specs))
	for _, sp := range specs {
		ev := EngineVer{Name: sp.Name}
		if p := findInDir(dir, sp.Prefix); p != "" {
			ev.Found = true
			ev.Version = versionOf(p)
		}
		out = append(out, ev)
	}
	return out
}
