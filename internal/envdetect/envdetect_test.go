package envdetect

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// bin/ 目录二进制识别: 精确匹配 + 前缀松散匹配 + 排除目录/配置文件(按当前平台构造样本)
func TestFindBinary(t *testing.T) {
	isWin := runtime.GOOS == "windows"
	suffix := ""
	if isWin {
		suffix = ".exe"
	}
	dir := t.TempDir()
	must := func(name string) {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		f.Close()
	}
	must("nmapcore" + suffix)
	must("trivy" + suffix)
	zapLoose := "zapcore"
	if isWin {
		zapLoose = "zap-1.0.0.exe"
	}
	must(zapLoose)
	must("nmap.cfg")     // 配置/数据文件, 不应命中
	must("zap.conf")     // 配置/数据文件, 不应命中
	must("zap.baseline") // 数据文件, 不应命中
	os.Mkdir(filepath.Join(dir, "nmapdir"), 0o755) // 目录排除

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := findBinary(entries, engineSpecs[0]); got != "nmapcore"+suffix {
		t.Fatalf("nmap -> %q, want nmapcore%s", got, suffix)
	}
	if got := findBinary(entries, engineSpecs[1]); got != "trivy"+suffix {
		t.Fatalf("trivy -> %q, want trivy%s", got, suffix)
	}
	if got := findBinary(entries, engineSpecs[2]); got != zapLoose {
		t.Fatalf("zap -> %q, want %s (前缀松散匹配)", got, zapLoose)
	}
}

// 版本正则: 常见输出格式
func TestVersionRegex(t *testing.T) {
	cases := map[string]string{
		"Nmap version 7.94 ( https://nmap.org )": "7.94",
		"Version: 0.51.4":                        "0.51.4",
		"ZAP version 2.15.0":                     "2.15.0",
		"trivy 1.36.0, built at 2024":            "1.36.0",
	}
	for in, want := range cases {
		if got := verRe.FindString(in); got != want {
			t.Fatalf("version %q -> %q, want %q", in, got, want)
		}
	}
}

// 引擎不可运行: probeVersion 返回错误(用测试二进制自身当假引擎, 未知参数必失败)
func TestProbeVersionFail(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("无测试二进制")
	}
	_, _, err = probeVersion(exe, [][]string{{"--version"}}, defaultVerTimeout)
	if err == nil {
		t.Fatal("期望不可运行错误")
	}
	if !strings.Contains(err.Error(), "无法运行引擎") {
		t.Fatalf("错误信息: %v", err)
	}
}

// zapVersionFromJar 零启动提取版本: 从入口同目录 zap-<ver>.jar 文件名取版本号,
// 忽略非 zap- 前缀 / 非 .jar 干扰项; 无 jar 时返回空串(调用方回退命令探测)。
// 守住"ZAP 探测不走 16s JVM 冷启动、不再被 5s 超时杀掉误报 exit status 1"的契约。
func TestZapVersionFromJar(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "zap.bat"), []byte("@echo off"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "zap-2.17.0.jar"), []byte{}, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "zapplugin.jar"), []byte{}, 0o644) // 干扰: 非 zap- 前缀
	_ = os.WriteFile(filepath.Join(dir, "zap-doc.txt"), []byte{}, 0o644) // 干扰: 非 .jar
	if got := zapVersionFromJar(filepath.Join(dir, "zap.bat")); got != "2.17.0" {
		t.Fatalf("应从 jar 名提取 2.17.0, got %q", got)
	}

	// 无 jar: 返回空串(回退命令探测), 不 panic
	empty := t.TempDir()
	_ = os.WriteFile(filepath.Join(empty, "zap.bat"), []byte{}, 0o644)
	if got := zapVersionFromJar(filepath.Join(empty, "zap.bat")); got != "" {
		t.Fatalf("无 jar 应返回空串, got %q", got)
	}
}

// bin/ 目录缺失: 全部引擎降级, 不 panic
func TestDetectNoBinDir(t *testing.T) {
	st := detect()
	if st.BinDir == "" {
		t.Fatal("binDir 为空")
	}
	// 引擎数 = 外部引擎 + 内置引擎(2026-10-01: 内置引擎计入引擎总数, 用户要求可见)
	if len(st.Engines) != len(engineSpecs)+1 {
		t.Fatalf("引擎数 = %d, 期望 %d(外部 %d + 内置 1)", len(st.Engines), len(engineSpecs)+1, len(engineSpecs))
	}
	var builtinSeen bool
	for _, e := range st.Engines {
		if e.State != "missing" && e.State != "ok" && e.State != "error" {
			t.Fatalf("引擎 %s 状态异常: %s", e.Name, e.State)
		}
		if e.State != "ok" && !e.Fallback {
			t.Fatalf("引擎 %s 缺失但未标记降级", e.Name)
		}
		if e.Name == EngineBuiltin {
			builtinSeen = true
			// 契约: 内置引擎恒就绪且不参与降级 —— 缺失 bin/ 也不能把它算成 missing/fallback
			if !e.Builtin || e.State != "ok" || e.Fallback {
				t.Fatalf("内置引擎状态异常: %+v", e)
			}
		}
	}
	if !builtinSeen {
		t.Fatal("引擎列表中缺少内置引擎 " + EngineBuiltin)
	}
	for _, d := range st.Degraded {
		if d == EngineBuiltin {
			t.Fatalf("内置引擎不应出现在降级列表: %v", st.Degraded)
		}
	}
}

// Get 在检测完成前返回"检测中"占位
func TestGetPlaceholder(t *testing.T) {
	mu.Lock()
	old := cached
	cached = nil
	mu.Unlock()
	defer func() {
		mu.Lock()
		cached = old
		mu.Unlock()
	}()
	s := Get()
	if !s.Detecting {
		t.Fatal("期望 detecting=true")
	}
	if len(s.Engines) != len(engineSpecs)+1 {
		t.Fatalf("占位引擎数 = %d, 期望 %d(外部 %d + 内置 1)", len(s.Engines), len(engineSpecs)+1, len(engineSpecs))
	}
}

// Npcap 状态结构: 各平台均能检测且不 panic, Supported 与平台一致
func TestNpcapStatus(t *testing.T) {
	s := detectNpcap()
	wantSupported := runtime.GOOS == "windows"
	if s.Supported != wantSupported {
		t.Fatalf("Supported = %v, want %v (os=%s)", s.Supported, wantSupported, runtime.GOOS)
	}
	if s.Source == "" {
		t.Fatal("Source 为空")
	}
}
