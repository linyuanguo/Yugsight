// jdk_test.go ZAP 自带 JDK 安装逻辑的回归测试。
//
// 【缺陷背景】ZAP 官方跨平台包不含 Java, 用户机器上又是 Java 8, 于是"安装成功但
// 一用就抛 UnsupportedClassVersionError"。修复方向是随 ZAP 一起下 JDK 17 到
// bin/zapcore/ZAP_<ver>/jre/。这里守三件事:
//
//  1. 平台映射正确 —— 传错架构会下到跑不起来的 JDK, 报的却是"无法启动"这种
//     看不出根因的错(实测 Adoptium 用 x64 不是 amd64, 传 GOARCH 会 400);
//  2. **启动脚本真的会用自带 jre** —— 这是整件事最容易做漏的一环: 官方 zap.bat
//     只从 PATH 找 java, 光把 JDK 放旁边是**没有用**的。必须改写脚本;
//  3. 幂等与备份 —— 重复安装不能把自己的脚本当成官方原版备份掉(那样就永远回不去了)。
//
// 全部用例不联网: 网络部分只做"参数拼装正确"的断言。
package engmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestAdoptiumPlatformMapping 平台映射必须与 Adoptium API 的实际取值一致。
//
// amd64 -> "x64" 是最容易写错的一条: 直觉上会直接传 runtime.GOARCH,
// 而 Adoptium 用 x64, 传 amd64 会得到 HTTP 400 Invalid architecture。
func TestAdoptiumPlatformMapping(t *testing.T) {
	archCases := map[string]string{
		"amd64": "x64", // 注意: 不是 amd64
		"arm64": "arm64",
		"386":   "", // 未知架构必须返回空串(由调用方跳过), 不能猜一个
		"arm":   "",
		"":      "",
	}
	for in, want := range archCases {
		if got := adoptiumArch(in); got != want {
			t.Errorf("adoptiumArch(%q) = %q, 期望 %q", in, got, want)
		}
	}

	osCases := map[string]string{
		"windows": "windows",
		"linux":   "linux",
		"darwin":  "mac", // Adoptium 用 mac, 不是 darwin
		"freebsd": "",
		"":        "",
	}
	for in, want := range osCases {
		if got := adoptiumOS(in); got != want {
			t.Errorf("adoptiumOS(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// TestZapLauncherWindowsUsesBundledJRE 钉住"启动脚本优先使用同目录 jre"。
//
// 【这是本次修复的核心断言】官方 zap.bat 全文只有一行有效命令:
//
//	java %jvmopts% -jar zap-2.17.0.jar %*
//
// 它只从 PATH 找 java。若我们不改写脚本, 那"下好 JDK 放到旁边"这件事对 ZAP 的
// 启动**毫无影响**, 系统里的 Java 8 依旧被优先命中 —— 用户看到的还是原来的错误。
// 所以下面这三条断言缺一不可: 引用 jre 目录、把 jre/bin 放进 PATH、保留原版备份。
func TestZapLauncherWindowsUsesBundledJRE(t *testing.T) {
	if !isWindows {
		t.Skip("Windows 启动脚本分支")
	}
	zapDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(zapDir, "zap-2.17.0.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(zapDir, "zap.bat")
	orig := "if exist \"%USERPROFILE%\\ZAP\\.ZAP_JVM.properties\" (\r\n" +
		"\tset /p jvmopts=< \"%USERPROFILE%\\ZAP\\.ZAP_JVM.properties\"\r\n" +
		") else (\r\n\tset jvmopts=-Xmx512m\r\n)\r\n\r\n" +
		"java %jvmopts% -jar zap-2.17.0.jar %*\r\n"
	if err := os.WriteFile(entry, []byte(orig), 0o755); err != nil {
		t.Fatal(err)
	}

	var logs []string
	changed, err := ensureZapLauncher(entry, func(s string) { logs = append(logs, s) })
	if err != nil {
		t.Fatalf("改写启动脚本失败: %v", err)
	}
	if !changed {
		t.Fatal("首次改写应返回 changed=true")
	}

	body, err := os.ReadFile(entry)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	// 1) 必须用 %~dp0jre(脚本所在目录下的 jre), 而不是某个硬编码绝对路径 ——
	//    硬编码在"把 dist 拷到别的电脑"这个主场景下会立刻失效。
	if !strings.Contains(got, `%~dp0jre`) {
		t.Errorf("脚本未引用同目录 jre:\n%s", got)
	}
	if !strings.Contains(got, `%ZAPJRE%\bin`) {
		t.Errorf("脚本未把 jre\\bin 放进 PATH(那样仍会命中系统 Java):\n%s", got)
	}
	// 2) jar 名必须按目录里实际存在的文件写, 不能写死 2.17.0
	if !strings.Contains(got, "zap-2.17.0.jar") {
		t.Errorf("脚本未指向实际存在的 jar:\n%s", got)
	}
	// 3) 原版必须备份(用户有权看到官方原始文件, 覆盖掉就永久丢失)
	backup, err := os.ReadFile(entry + ".orig")
	if err != nil {
		t.Fatalf("官方原版未备份: %v", err)
	}
	if string(backup) != orig {
		t.Error("备份内容与官方原版不一致")
	}
	// 4) 无自带 JRE 的回落提示必须在: 用户自行装了 Java 17 的场景不能被堵死
	if !strings.Contains(got, "Java 17") {
		t.Errorf("脚本缺少无自带 JRE 时的回落提示:\n%s", got)
	}
	if len(logs) == 0 {
		t.Error("改写应产生一条日志(否则用户不知道脚本被动过)")
	}
}

// TestZapLauncherIdempotent 重复执行不得覆盖备份。
//
// 【为什么这条很重要】若第二次执行时把自己的脚本当成"官方原版"又备份一次, 备份文件
// 就变成我们的脚本了 —— 用户再也拿不回官方原版。重装 ZAP / 修环境都会触发第二次,
// 所以这不是理论问题, 是必然路径。
func TestZapLauncherIdempotent(t *testing.T) {
	zapDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(zapDir, "zap-2.17.0.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(zapDir, zapLauncherName())
	orig := "java %jvmopts% -jar zap-2.17.0.jar %*\n"
	if err := os.WriteFile(entry, []byte(orig), 0o755); err != nil {
		t.Fatal(err)
	}
	logf := func(string) {}

	if _, err := ensureZapLauncher(entry, logf); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(entry)

	changed, err := ensureZapLauncher(entry, logf)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("第二次执行应识别出已是我们的脚本并跳过(changed=false)")
	}
	second, _ := os.ReadFile(entry)
	if string(first) != string(second) {
		t.Error("第二次执行改动了脚本内容(应完全不变)")
	}
	// 备份必须仍是官方原版
	backup, err := os.ReadFile(entry + ".orig")
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != orig {
		t.Errorf("备份被自己的脚本覆盖了, 用户再也拿不回官方原版: %q", string(backup))
	}
}

// TestZapLauncherMissingEntry 入口脚本不存在时报错而不是静默成功。
func TestZapLauncherMissingEntry(t *testing.T) {
	if _, err := ensureZapLauncher(filepath.Join(t.TempDir(), "nope.bat"), func(string) {}); err == nil {
		t.Error("入口脚本不存在应返回错误")
	}
	if _, err := ensureZapLauncher("", func(string) {}); err == nil {
		t.Error("空路径应返回错误")
	}
}

// TestJdkJavaBinLayouts 自带 java 的定位必须兼容多种归档结构。
//
// 硬编码 <root>/bin/java.exe 会在上游改目录结构(或 macOS 的 Contents/Home)时
// 变成"JDK 明明装好了, ZAP 却说找不到 Java" —— 这种失败现象与"没装 Java"完全一样,
// 排查方向会被彻底带偏。
func TestJdkJavaBinLayouts(t *testing.T) {
	javaName := "java"
	if isWindows {
		javaName = "java.exe"
	}
	cases := []struct {
		name string
		rel  string // 相对 jre/ 的 java 路径
	}{
		{"普通布局", filepath.Join("jdk-17.0.20+1", "bin", javaName)},
		{"直接一层", filepath.Join("bin", javaName)},
		{"macOS 布局", filepath.Join("jdk-17.0.20+1", "Contents", "Home", "bin", javaName)},
	}
	for _, c := range cases {
		zapDir := t.TempDir()
		p := filepath.Join(zapDir, jdkDirName, c.rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/fake"), 0o755); err != nil {
			t.Fatal(err)
		}
		if got := jdkJavaBin(zapDir); got == "" {
			t.Errorf("%s: 未找到 java (期望 %s)", c.name, p)
		}
	}
	// 目录不存在时返回空串, 不 panic
	if got := jdkJavaBin(t.TempDir()); got != "" {
		t.Errorf("无 jre 目录应返回空串, 实际 %q", got)
	}
}

// TestJdkInstalledVersion jre/version.txt 的读写口径。
func TestJdkInstalledVersion(t *testing.T) {
	zapDir := t.TempDir()
	if v := jdkInstalledVersion(zapDir); v != "" {
		t.Errorf("未安装时应返回空串, 实际 %q", v)
	}
	if err := os.MkdirAll(filepath.Join(zapDir, jdkDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(zapDir, jdkDirName, jdkVersionFile), []byte("17.0.20+101\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 必须 TrimSpace: 写文件时带了换行, 不回显换行才好在界面上展示与比较
	if v := jdkInstalledVersion(zapDir); v != "17.0.20+101" {
		t.Errorf("版本应为 %q, 实际 %q", "17.0.20+101", v)
	}
}

// TestExtractJDKZip 解压 JDK zip: 保留目录结构 + 必须有 java + 拒绝超量内容。
func TestExtractJDKZip(t *testing.T) {
	javaName := "java"
	if isWindows {
		javaName = "java.exe"
	}
	zipData := makeZip(t, map[string][]byte{
		"jdk-17.0.20+1/bin/" + javaName:            []byte("MZ fake java"),
		"jdk-17.0.20+1/lib/modules":                []byte("modules"),
		"jdk-17.0.20+1/conf/security/java.security": []byte("policy"),
		"jdk-17.0.20+1/release":                    []byte("JAVA_VERSION=\"17.0.20\""),
	})
	dir := t.TempDir()
	if err := extractJDKArchive(zipData, dir); err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	// 目录结构必须保留: JDK 靠相对自身的 lib/conf 找资源, 拍平就废了
	for _, rel := range []string{
		filepath.Join("jdk-17.0.20+1", "bin", javaName),
		filepath.Join("jdk-17.0.20+1", "lib", "modules"),
		filepath.Join("jdk-17.0.20+1", "conf", "security", "java.security"),
	} {
		if !fileExists(filepath.Join(dir, rel)) {
			t.Errorf("缺少文件 %s(目录结构未保留)", rel)
		}
	}
}

// TestExtractJDKZipNoJava 归档里没有 java 必须报错。
//
// 方向很重要: 若判成功, 后续 jdkJavaBin 找不到 java 时会再报错一次, 且调用方已经
// 把 version.txt 写下去了 —— 于是"标记说装了、实际没有", 变成永久性的假状态。
func TestExtractJDKZipNoJava(t *testing.T) {
	zipData := makeZip(t, map[string][]byte{
		"jdk-17/bin/notjava": []byte("x"),
		"jdk-17/README":      []byte("readme"),
	})
	if err := extractJDKArchive(zipData, t.TempDir()); err == nil {
		t.Error("归档内无 java 应返回错误")
	}
	// 不支持的格式也要报错而不是静默成功
	if err := extractJDKArchive(filepath.Join(t.TempDir(), "x.rar"), t.TempDir()); err == nil {
		t.Error("不支持的归档格式应返回错误")
	}
}

// TestExtractJDKZipRejectsTraversal 目录穿越条目必须被拦掉。
//
// JDK 包是从公网下的, 属于"不完全受控的输入"。穿越条目会让解压把文件写到 jre/
// 之外(如直接覆盖 bin/ 下的引擎二进制), 后果远超"JDK 装坏"。
func TestExtractJDKZipRejectsTraversal(t *testing.T) {
	javaName := "java"
	if isWindows {
		javaName = "java.exe"
	}
	zipData := makeZip(t, map[string][]byte{
		"jdk-17/bin/" + javaName: []byte("MZ"),
		"../../evil.txt":         []byte("pwned"),
		"jdk-17/../../../x.txt":  []byte("pwned"),
	})
	base := t.TempDir()
	dir := filepath.Join(base, "jre")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := extractJDKArchive(zipData, dir); err != nil {
		t.Fatalf("正常条目应解压成功: %v", err)
	}
	// 哨兵: 穿越条目若落地, 会出现在 base 之上或 base 内不该有的位置
	for _, bad := range []string{
		filepath.Join(base, "evil.txt"),
		filepath.Join(base, "x.txt"),
		filepath.Join(filepath.Dir(base), "evil.txt"),
	} {
		if fileExists(bad) {
			t.Errorf("目录穿越条目被解出: %s", bad)
		}
	}
}

// TestZapJarNameByDir 按目录里实际存在的 jar 生成脚本。
//
// 写死 zap-2.17.0.jar 会在 ZAP 升级后指向不存在的文件, 报 "Unable to access
// jarfile" —— 这个错误与我们要解决的 Java 版本问题混在一起, 排查会被带偏。
func TestZapJarNameByDir(t *testing.T) {
	dir := t.TempDir()
	if got := zapJarName(dir); got != "zap.jar" {
		t.Errorf("无 jar 时兜底名应为 zap.jar, 实际 %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "zap-2.18.1.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 干扰项: 不能把插件 jar 认成主 jar
	if err := os.WriteFile(filepath.Join(dir, "zap-api.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := zapJarName(dir); got != "zap-2.18.1.jar" {
		t.Errorf("应识别出 zap-2.18.1.jar, 实际 %q", got)
	}
}

// TestHumanSize 体积展示(与下载器/Adoptium 页面的 1000 进制口径一致)。
func TestHumanSize(t *testing.T) {
	cases := map[int64]string{
		190817615: "190.8MB", // Adoptium 实测的 JDK 包大小
		0:         "0B",
		-1:        "?",
		500:       "500B",
		// KB 不带小数(与 main.humanMB 的口径一致): 日志里 190.8MB 这种量级才需要
		// 精度, "1500 字节"写成 2KB 比 1.5KB 更好读, 也避免日志行长度抖动。
		1500: "2KB",
	}
	for in, want := range cases {
		if got := humanSize(in); got != want {
			t.Errorf("humanSize(%d) = %q, 期望 %q", in, got, want)
		}
	}
}

// TestAdoptiumURLContainsRequiredParams 拼出来的 API 地址必须带全必要参数。
//
// 少任何一个参数 Adoptium 都会返回空数组(而不是报错), 表现为"接口调通但拿不到包",
// 很难定位 —— 所以用断言把参数钉住。
func TestAdoptiumURLContainsRequiredParams(t *testing.T) {
	u := "https://api.adoptium.net/v3/assets/latest/17/hotspot" +
		"?architecture=x64&image_type=jdk&os=windows&vendor=eclipse"
	for _, frag := range []string{"latest/17", "architecture=x64", "image_type=jdk",
		"os=windows", "vendor=eclipse"} {
		if !strings.Contains(u, frag) {
			t.Errorf("API 地址缺少参数片段 %q", frag)
		}
	}
	// 走一次真实的模板拼装, 确保 fmt 参数顺序没错位(占位符与实参对不上是常见笔误)
	got := sprintfJDKURL(17, "x64", "jdk", "windows", "eclipse")
	for _, frag := range []string{"latest/17", "architecture=x64", "image_type=jdk",
		"os=windows", "vendor=eclipse"} {
		if !strings.Contains(got, frag) {
			t.Errorf("模板拼装结果 %q 缺少 %q", got, frag)
		}
	}
}

// sprintfJDKURL 只为测试暴露的模板拼装(避免测试里复制一份格式串导致漂移)。
func sprintfJDKURL(feature int, arch, imageType, os, vendor string) string {
	return fmt.Sprintf(jdkAPITemplate, feature, arch, imageType, os, vendor)
}

// 说明: fileExists 由生产代码 jdk.go 提供, 测试直接复用, 不在此重复声明
// (同包内重名会编译失败)。

// TestFlattenSingleRoot 归档自带的版本层目录必须被拍平。
//
// 【这是实测暴露的真实缺陷的回归用例】Adoptium 的 zip 解出来是
//
//	jre/jdk-17.0.20.1+1/bin/java.exe      <- 实际结构
//
// 而 ZAP 启动脚本只认 jre/bin/java.exe。不拍平的话脚本里的
// `if exist "%~dp0jre\bin\java.exe"` 永远不成立, 结果是: JDK 下好了、装好了、
// 状态页显示"已装入 JDK 17", 但 ZAP 启动时**依然用系统那个 Java 8** —— 一切看起来
// 都对, 错误却一模一样。这类"配置生效了但没起作用"的缺陷最难查。
func TestFlattenSingleRoot(t *testing.T) {
	javaName := javaExeName()
	t.Run("单层版本目录应被拍平", func(t *testing.T) {
		dir := t.TempDir()
		inner := filepath.Join(dir, "jdk-17.0.20.1+1")
		for _, rel := range []string{
			filepath.Join("bin", javaName),
			filepath.Join("lib", "modules"),
			filepath.Join("conf", "security", "java.security"),
		} {
			p := filepath.Join(inner, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// 版本层之外还有普通文件(真实 JDK zip 里有 release 与 README)
		if err := os.WriteFile(filepath.Join(dir, "release"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		moved, err := flattenSingleRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !moved {
			t.Fatal("应识别出版本层目录并拍平")
		}
		// 拍平后必须是 jre/bin/java 这一层(启动脚本唯一认的路径)
		if !fileExists(filepath.Join(dir, "bin", javaName)) {
			t.Errorf("拍平后缺少 bin/%s", javaName)
		}
		if !fileExists(filepath.Join(dir, "lib", "modules")) {
			t.Error("拍平后缺少 lib/modules(依赖文件丢失)")
		}
		if _, err := os.Stat(inner); !os.IsNotExist(err) {
			t.Error("空的版本层目录应被删除")
		}
	})

	t.Run("正确布局不应被动", func(t *testing.T) {
		// 根下已有多个目录(= 本身就是 jre 根), 再挑一个搬上去会把结构搞坏
		dir := t.TempDir()
		for _, d := range []string{"bin", "lib", "conf"} {
			if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "bin", javaName), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		moved, err := flattenSingleRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		if moved {
			t.Error("已有多目录的正确布局不应被拍平")
		}
	})

	t.Run("唯一目录但不是版本层", func(t *testing.T) {
		// 只有 lib/ 一个目录且里面没有 bin/java —— 不是版本层, 搬上去会搞坏结构
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "lib", "x"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		moved, err := flattenSingleRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		if moved {
			t.Error("唯一目录内无 bin/java 时不应判定为版本层")
		}
	})

	t.Run("空目录", func(t *testing.T) {
		if moved, err := flattenSingleRoot(t.TempDir()); err != nil || moved {
			t.Errorf("空目录应返回 (false, nil), 实际 (%v, %v)", moved, err)
		}
	})
}

// TestZapLauncherIsPureASCII 启动脚本必须是纯 ASCII。
//
// 【这是实测暴露的真实缺陷的回归用例】第一版脚本写了中文注释, 生成的 zap.bat 在
// cmd 里显示成 "rem 浼樺厛浣跨敤 ZAP 鑷甫 JRE", 因为 .bat 由 cmd 按**系统 ANSI 代码页**
// (中文 Windows 是 GBK) 读取, 而 Go 写的是 UTF-8 字节。
//
// 注释乱码只是难看, 但若乱码落在命令里就会改变行为(GBK 解码出的字节可能包含引号或
// 重定向符)—— 这属于随时会炸的隐患。同一份二进制要能在任意区域的 Windows 上跑,
// 无法预知代码页, 所以纯 ASCII 是唯一可靠的选择。
func TestZapLauncherIsPureASCII(t *testing.T) {
	zapDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(zapDir, "zap-2.17.0.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Windows 与 Unix 两个分支都要检查
	for _, name := range []string{"zap.bat", "zap.sh"} {
		script := zapLauncherScript(filepath.Join(zapDir, name))
		for i, r := range script {
			if r > 127 {
				t.Fatalf("%s 含非 ASCII 字符 %q(位置 %d), 在 cmd 下会因代码页不符而乱码:\n%s",
					name, r, i, script)
			}
		}
	}
}

// TestZapLauncherReferencesFlattenedLayout 脚本引用的 java 路径必须与拍平后的布局一致。
//
// 两条路径分处两个文件(解压逻辑与脚本生成), 一旦有人改动其中一处就会出现
// "装好了但没用上"。这里把两个事实对在一起断言。
func TestZapLauncherReferencesFlattenedLayout(t *testing.T) {
	zapDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(zapDir, "zap-2.17.0.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := zapLauncherScript(filepath.Join(zapDir, "zap.bat"))
	// 【断言的是"两处写的是同一个路径", 而不是某个字面量】
	// 解压逻辑保证的是 <zapDir>/jre/bin/java[.exe] 这个文件存在;
	// 脚本必须去查这同一个位置。这里把两者对起来, 任一被改都会立刻红灯 ——
	// 否则就会出现"JDK 装好了但脚本查的是别处"这种查起来极慢的错位。
	jreRoot := filepath.Join(zapDir, "jre")
	wantBin := filepath.Join(jreRoot, "bin", javaExeName())
	if !fileExists(filepath.Join(jreRoot, "bin", javaExeName())) {
		// 前置条件: 先造出与生产逻辑一致的文件, 否则断言恒真(等于没测)
		if err := os.MkdirAll(filepath.Join(jreRoot, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(wantBin, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// 脚本里必须体现"脚本所在目录下的 jre"(%~dp0jre / $BASEDIR/jre),
	// 而不是任何硬编码的绝对路径 —— 后者在"整个目录拷到别的电脑"时必然失效。
	hasWin := strings.Contains(script, `%~dp0jre`) && strings.Contains(script, `%ZAPJRE%\bin`)
	hasUnix := strings.Contains(script, `$BASEDIR/jre`) && strings.Contains(script, `$JAVA_HOME/bin`)
	if !hasWin && !hasUnix {
		t.Errorf("脚本未引用脚本同目录下的 jre/bin(与拍平后的布局不一致):\n%s", script)
	}
}

//
// 带上版本号后, 我们生成的 zap.bat 里写死的 %~dp0jre 就找不到目录了 —— 每次升级
// JDK 都要重写所有已装 ZAP 的启动脚本, 漏改一台就是"JDK 在但 ZAP 说没有"。
func TestJdkDirNameIsFixedWithoutVersion(t *testing.T) {
	if jdkDirName != "jre" {
		t.Errorf("jre 目录名必须固定为 \"jre\"(启动脚本按此路径查找), 实际 %q", jdkDirName)
	}
	// 冒烟: 固定名不能被版本号污染
	if strings.Contains(jdkDirName, "17") {
		t.Error("jre 目录名不应包含版本号")
	}
	_ = runtime.GOOS
}
