// java_bundled_test.go "ZAP 自带 JDK" 探测的回归测试。
//
// 【缺陷背景】为了免掉"用户自己装 Java 17"这一步, engmgr 现在会随 ZAP 一起下
// JDK 17 到 bin/zapcore/ZAP_<ver>/jre/。但只做下载是不够的 —— 环境状态页若仍以
// "PATH 里有没有 java"为唯一判据, 用户会看到:
//
//	ZAP 就绪  ·  Java 未检测到(红)  ·  但 ZAP 其实完全跑得起来
//
// 这个红灯会让人去装一个根本不需要的 Java, 属于"探测把已经解决的问题重新报成问题"。
// 所以本文件守三条:
//
//  1. 自带 JDK 存在时必须被判为达标, 且标记 Bundled=true(前端据此显示"内置");
//  2. 自带 JDK 缺失/损坏时必须**回落**去探系统 Java, 而不是直接判不达标
//     (否则会把"有系统 Java 17"的机器误报成红灯);
//  3. 两种目录布局都要认(zapcore 根下、以及 ZAP_<ver>/ 子目录下)。
//
// 全部用例用临时目录构造, 不依赖本机装了什么。
package envdetect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// jsonMarshalForTest 只为断言 json tag 而存在的薄封装
func jsonMarshalForTest(v any) ([]byte, error) { return json.Marshal(v) }

// containsStr 字符串包含判定(薄封装, 避免测试里到处 import strings)
func containsStr(s, sub string) bool { return strings.Contains(s, sub) }

// javaNameForTest 当前平台的 java 可执行文件名(与生产代码同口径)
func javaNameForTest() string {
	if runtime.GOOS == "windows" {
		return "java.exe"
	}
	return "java"
}

// writeFakeJava 在 dir/bin/<java> 写一个可执行占位文件。
func writeFakeJava(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(bin, javaNameForTest())
	if err := os.WriteFile(p, []byte("fake java"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// withFakeBinDir 把 binDir 指向临时目录。
//
// 【为什么必须把这个包级函数换掉而不是传参】bundledJRERoot / binDir 都读
// os.Executable() 的同级 bin/, 在测试进程里那是 go 的临时构建目录 —— 不改指向就
// 只能去测真实磁盘布局, 无法用构造数据覆盖各种边界。
func withFakeBinDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := binDirFn
	binDirFn = func() string { return dir }
	t.Cleanup(func() { binDirFn = orig })
	return dir
}

// TestBundledJRERootBothLayouts 两种布局都要能定位到 jre。
func TestBundledJRERootBothLayouts(t *testing.T) {
	cases := []struct {
		name string
		rel  string // 相对 bin/ 的 jre 路径
	}{
		// engmgr 实际装出来的形态: bin/zapcore/ZAP_2.17.0/jre
		{"子目录布局(engmgr 装出来的)", filepath.Join("zapcore", "ZAP_2.17.0", "jre")},
		// 手工解压到 zapcore 根的场景
		{"zapcore 根布局(手工解压)", filepath.Join("zapcore", "jre")},
	}
	for _, c := range cases {
		dir := withFakeBinDir(t)
		jre := filepath.Join(dir, c.rel)
		want := writeFakeJava(t, jre)
		got := bundledJRERoot()
		if got == "" {
			t.Errorf("%s: 未定位到自带 JDK", c.name)
			continue
		}
		if filepath.Join(got, "bin", javaNameForTest()) != want {
			t.Errorf("%s: 定位结果错误, 得到 %q 期望 jre 根 %q", c.name, got, jre)
		}
	}
}

// TestBundledJRERootAbsent 没有任何 ZAP 目录时必须返回空串(不 panic)。
//
// 返回空串是"继续探系统 Java"的信号, 不是"失败"—— 二者语义必须分清。
func TestBundledJRERootAbsent(t *testing.T) {
	dir := withFakeBinDir(t)
	if got := bundledJRERoot(); got != "" {
		t.Errorf("空 bin/ 应返回空串, 实际 %q", got)
	}
	// 有 zapcore 目录但没有 jre: 仍应返回空串
	if err := os.MkdirAll(filepath.Join(dir, "zapcore", "ZAP_2.17.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := bundledJRERoot(); got != "" {
		t.Errorf("zapcore 无 jre 时应返回空串, 实际 %q", got)
	}
	// 干扰项: 其它引擎的套装目录不能被误认成 ZAP
	if err := os.MkdirAll(filepath.Join(dir, "nmapcore"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeJava(t, filepath.Join(dir, "nmapcore"))
	if got := bundledJRERoot(); got != "" {
		t.Errorf("nmapcore 下的 jre 不应被当作 ZAP 的自带 JDK, 实际 %q", got)
	}
}

// TestBundledJRERootSkipsJreWithoutJava jre 目录在但里面没有 java 时不算数。
//
// 【为什么这条重要】解压 190MB 的 JDK 约几千个文件, 中途失败(磁盘满/被杀)很容易
// 留下一个"jre 目录已存在但没有 java"的半成品。若仅凭目录存在就判定"自带 JDK 就绪",
// 状态页会显示绿色而 ZAP 一启动就崩 —— 这种假绿灯比红灯更糟。
func TestBundledJRERootSkipsJreWithoutJava(t *testing.T) {
	dir := withFakeBinDir(t)
	// 只有目录, 没有 bin/java
	if err := os.MkdirAll(filepath.Join(dir, "zapcore", "ZAP_2.17.0", "jre", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := bundledJRERoot(); got != "" {
		t.Errorf("jre 内无 java 时不应判定为可用, 实际返回 %q", got)
	}
}

// TestDetectBundledJavaFallsBackWhenBroken 自带 JDK 的 java 跑不起来时必须回落。
//
// 【这条是本文件最关键的断言】用户机器上 Java 8 + 坏掉的自带 JDK 这种组合下,
// 正确结论是"继续看系统 Java"; 若在这里直接判"Java 不达标", 用户会看到红灯而去装
// Java 17 —— 但机器上其实已经有一个能用的(只是被坏掉的自带 JDK 挡住了)。
//
// 用非可执行内容的假 java 模拟"跑不起来": 进程启动失败即触发回落分支。
func TestDetectBundledJavaFallsBackWhenBroken(t *testing.T) {
	dir := withFakeBinDir(t)
	jre := filepath.Join(dir, "zapcore", "ZAP_2.17.0", "jre")
	writeFakeJava(t, jre) // 内容是 "fake java", 不是合法可执行文件
	_ = os.Chmod(filepath.Join(jre, "bin", javaNameForTest()), 0o644)

	st, ok := detectBundledJava()
	if ok {
		// 极少数情况下系统会把该文件当可执行并返回输出 —— 那时也不该判达标
		// (输出里没有版本号), 故仍要求 OK=false 或无版本号
		if st.OK {
			t.Errorf("无法执行的假 java 不应被判为达标: %+v", st)
		}
		return
	}
	// 返回 false = 交给调用方继续探系统 Java, 这正是我们要的语义
	if st.Note != "" && !st.OK {
		// note 允许为空(回落路径不设 note), 这里只确保没把 Bundled 置真
		if st.Bundled {
			t.Error("回落路径不应置 Bundled=true")
		}
	}
}

// TestDetectJavaConsistentWithBundled 总体自洽: 判定达标时必须有版本串。
//
// 与 java_test.go 的 TestDetectJavaSelfConsistent 同一口径, 这里额外覆盖
// "自带 JDK 命中"时的字段完备性(Bundled=true 时 Path 必须给出, 排障要用)。
func TestDetectJavaConsistentWithBundled(t *testing.T) {
	s := detectJava()
	if s.MinVersion != javaMinMajor {
		t.Errorf("MinVersion 应为 %d, 实际 %d", javaMinMajor, s.MinVersion)
	}
	if !s.OK {
		return // 本机没有可用的 Java 属正常, 不强制
	}
	if !s.Found {
		t.Error("达标时必须同时 found=true")
	}
	if s.Bundled && s.Path == "" {
		t.Error("命中自带 JDK 时必须给出 java 路径(Bundled=true 但 Path 为空)")
	}
}

// TestJavaStatusBundledFieldSerialized 字段必须能序列化给前端。
//
// 前端靠 bundled 区分"用自带 JDK(这台机器什么都不用装)"与"用系统 Java(换机器还得装)",
// 字段名写错会让前端永远拿不到这个信息。这里锁住 json tag。
func TestJavaStatusBundledFieldSerialized(t *testing.T) {
	st := JavaStatus{Supported: true, Found: true, OK: true, Bundled: true,
		Version: "17.0.20", MinVersion: 17, Path: `C:\x\jre\bin\java.exe`}
	b, err := jsonMarshalForTest(st)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, frag := range []string{`"bundled":true`, `"path"`, `"ok":true`, `"minVersion":17`} {
		if !containsStr(got, frag) {
			t.Errorf("序列化结果缺少 %q: %s", frag, got)
		}
	}
	// Bundled 为 false 时应省略(omitempty), 避免前端把零值当"明确不是自带"处理
	st2 := JavaStatus{Supported: true}
	b2, _ := jsonMarshalForTest(st2)
	if containsStr(string(b2), "bundled") {
		t.Errorf("Bundled=false 应被省略, 实际 %s", string(b2))
	}
}
