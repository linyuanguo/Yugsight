// java.go Java 运行时探测(envdetect 侧)。
//
// 【为什么 envdetect 也要探一遍 —— 与 engmgr/java_runtime.go 的分工】
// 两处探测的目的不同, 不能互相替代:
//
//	engmgr/java_runtime.go : 下载页用。判断"这台机器**装完 ZAP 能不能跑**",
//	                         不满足就把安装按钮置灰, 避免白下 273MB。
//	envdetect(本文件)      : 环境状态页用。判断"**已经从别处拷过来的** ZAP 能不能跑"。
//
// 第二种场景正是用户问到的"把 dist 目录整个移到别的电脑": 引擎文件跟着目录过来了
// (engmgr 那边判为"已安装"), 但目标机器可能根本没装 Java —— 此时引擎状态若只报
// "zapcore 就绪", 就是明确的误导。所以这里独立探一次并在状态页单列一行。
//
// 纯标准库; java 缺失/超时/输出异常一律降级为"未找到", 绝不 panic(项目规则 4)。
package envdetect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// javaMinMajor ZAP 2.17 要求的最低 Java 主版本。
// 依据: 其 class file version 61.0 对应 Java 17(52=8, 55=11, 61=17)。
const javaMinMajor = 17

// javaVerRe 抓引号内的版本 token(含构建号, 由解析函数再归一化)。
//
// 覆盖实测见过的各种形态:
//
//	Java 8 及更早: "1.8.0_391"      -> 主版本是 **8**(在第 2 段, 不是 1)
//	Java 9 及以后: "17.0.9"         -> 主版本就是 17
//	Temurin 21:    "21.0.1+12-LTS"  -> 主版本 21(必须允许字母, 否则整条匹配失败)
//	Early Access:  "21-ea"          -> 主版本 21
//
// 关键点: 不能写成 `[0-9._+\-]*` —— 那样遇到 "21.0.1+12-LTS" 会因 LTS 字母而**整条
// 匹配不上**, 结果是"装了 Java 21 却报未检测到"(实测踩到)。这里放宽到字母, 并用
// {0,24} 限制长度, 避免把后续整行文本吞进来。
//
// 与 engmgr/java_runtime.go 保持完全相同的口径(那里是下载前预检, 这里是状态页)。
var javaVerRe = regexp.MustCompile(`"([0-9][0-9A-Za-z._+\-]{0,24})"`)

// detectJava 探测本机 Java 是否满足 ZAP 要求。
//
// 【两路探测的顺序很关键】先找"ZAP 自带 JDK"(bin/zapcore/ZAP_<ver>/jre),
// 它存在就**直接判达标并不再看系统 Java**。
//
// 为什么顺序不能反: 实测用户机器上是 Java 8, 而 ZAP 自带的 JDK 17 装在旁边。
// 如果先探 PATH 里的 java, 结论会是"Java 版本过低", 于是状态页亮红灯、前端拦住
// ZAP 的启动按钮 —— 但 ZAP 实际上完全跑得起来(我们改写的 zap.bat 优先用自带 jre)。
// 这个红灯会让人去装一个根本不需要的 Java, 属于"探测把已解决的问题重新报成问题"。
//
// 反过来, 自带 jre 里的 java 若是旧版(理论上不会, 但我们按内容判定而不靠假设),
// 则继续看系统 Java —— 两路取"能用的那个"。
func detectJava() JavaStatus {
	s := JavaStatus{Supported: true, MinVersion: javaMinMajor}
	if bs, ok := detectBundledJava(); ok {
		return bs
	}
	out, err := runJavaVersion()
	if err != nil {
		s.Note = "未检测到 Java。ZAP 是 Java 程序且官方免安装包不含 Java, " +
			"可在引擎下载页重装 ZAP 以自动装入自带 JDK, 或自行安装 JDK/JRE 17 或更高版本"
		return s
	}
	s.Found = true
	ver, major, ok := parseJavaVersionOut(out)
	s.Version = ver
	if !ok {
		s.Note = "检测到 Java 但无法解析版本号。ZAP 需要 Java 17+, 请自行确认"
		return s
	}
	if major < javaMinMajor {
		s.Note = "Java 版本过低(当前 " + ver + ", 需要 " + strconv.Itoa(javaMinMajor) + "+)。" +
			"用低版本 Java 启动 ZAP 会抛 UnsupportedClassVersionError(class file version 61.0); " +
			"可在引擎下载页重装 ZAP 以自动装入自带 JDK, 与系统 Java 隔离并存"
		return s
	}
	s.OK = true
	return s
}

// detectBundledJava 探测 ZAP 自带 JDK(bin/zapcore/ZAP_<ver>/jre/bin/java)。
//
// 返回 (状态, 是否发现自带 JDK)。第二个返回值为 false 表示"没有自带 JDK",
// 调用方应继续探系统 Java —— 这两种情况必须分开, 否则"没装自带 JDK"会被当成
// "Java 不达标"而误报红灯。
func detectBundledJava() (JavaStatus, bool) {
	s := JavaStatus{Supported: true, MinVersion: javaMinMajor}
	dir := bundledJRERoot()
	if dir == "" {
		return s, false
	}
	bin := filepath.Join(dir, "bin", javaExeName())
	out, err := runJavaVersionAt(bin)
	if err != nil {
		// 目录在但 java 跑不起来: 只能说明这份自带 JDK 坏了, 不代表本机没有 Java。
		// 返回 false 让调用方继续看系统 Java(它能用的话就没必要为坏掉的自带 JDK 亮红灯)。
		logf("环境检测: ZAP 自带 JDK 存在但无法执行(" + err.Error() + "), 继续检测系统 Java")
		return s, false
	}
	ver, major, ok := parseJavaVersionOut(out)
	s.Found = true
	s.Version = ver
	s.Bundled = true
	s.Path = shortPath(bin)
	if !ok {
		s.Note = "ZAP 自带 JDK 存在但无法解析版本号。ZAP 需要 Java 17+, 请自行确认"
		return s, true
	}
	if major < javaMinMajor {
		// 自带 JDK 版本偏低: 这不该发生(我们下的就是 17), 但按内容判定而非假设,
		// 且**不**直接返回不达标 —— 交给调用方回落到系统 Java, 两路取能用的那个。
		logf("环境检测: ZAP 自带 JDK 版本偏低(" + ver + "), 继续检测系统 Java")
		return s, false
	}
	s.OK = true
	s.Note = "使用 ZAP 自带 JDK(与系统 Java 隔离)"
	return s, true
}

// javaExeName 当前平台的 java 可执行文件名。
func javaExeName() string {
	if runtime.GOOS == "windows" {
		return "java.exe"
	}
	return "java"
}

// bundledJRERoot 定位 bin/zapcore/ZAP_<ver>/jre 目录, 找不到返回空串。
//
// 【为什么这里要自己 Walk 一遍而不复用 findBinaryPath 的结果】
// findBinaryPath 给的是 zap.bat 路径, 而 jre 与它同级 —— 理论上
// filepath.Dir(zapEntry)/jre 就够了。但那个结果依赖 findBinaryInSubdir 的查找顺序
// (同名引擎装了多份时会拿到任意一份), 用它推 jre 路径会把"Java 探测"绑死在
// "任务里恰好选中了哪个 ZAP"上。这里独立按固定约定定位, 语义更稳。
//
// 兼容两种布局:
//
//	bin/zapcore/ZAP_2.17.0/jre/bin/java.exe   (engmgr 装出来的形态)
//	bin/zapcore/jre/bin/java.exe              (手工解压到 zapcore 根的场景)
func bundledJRERoot() string {
	dir := binDir()
	subs, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	javaName := javaExeName()
	for _, e := range subs {
		if !e.IsDir() || !strings.HasPrefix(strings.ToLower(e.Name()), "zap") {
			continue
		}
		root := filepath.Join(dir, e.Name())
		// 先看 zapcore 根下, 再看任意一层子目录(如 ZAP_2.17.0/)
		if p := filepath.Join(root, "jre", "bin", javaName); fileExists(p) {
			return filepath.Join(root, "jre")
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, sub := range entries {
			if !sub.IsDir() {
				continue
			}
			jre := filepath.Join(root, sub.Name(), "jre")
			if fileExists(filepath.Join(jre, "bin", javaName)) {
				return jre
			}
		}
	}
	return ""
}

// fileExists 文件存在且不是目录。
func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// runJavaVersionAt 执行指定路径的 java -version(自带 JDK 用)。
//
// 与 runJavaVersion 的唯一差别是指定绝对路径: 不走 PATH —— 自带 JDK 的目的正是
// "不受系统 PATH 里的 Java 8 影响", 若这里还走 PATH 就完全失去意义了。
func runJavaVersionAt(javaPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, javaPath, "-version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", err
	}
	return string(out), nil
}

// parseJavaVersionOut 从 java -version 输出解析 (展示用版本串, 主版本号, 是否解析成功)。
//
// 纯函数便于单测: 版本号格式在 Java 8→9 时变过一次, 是最容易写错的地方
// (把 "1.8.0_391" 的主版本读成 1 还是 8 会直接改变判定结论)。
// 归一化规则与 engmgr/java_runtime.go 一致: 丢掉构建号, 让展示串便于肉眼对比。
func parseJavaVersionOut(out string) (string, int, bool) {
	m := javaVerRe.FindStringSubmatch(out)
	if len(m) < 2 {
		return "", 0, false
	}
	token := m[1]
	// 丢掉构建号: '+' 之后(如 17.0.9+9)与 '_' 之后(如 1.8.0_391)
	if i := strings.IndexAny(token, "+_"); i >= 0 {
		token = token[:i]
	}
	token = strings.Trim(token, ".-")
	if token == "" {
		return "", 0, false
	}
	segs := strings.Split(token, ".")
	major, err := strconv.Atoi(segs[0])
	if err != nil {
		return "", 0, false
	}
	// Java 8 及更早写 "1.8.0": 真正的主版本在第二段(是 8, 不是 1)
	if major == 1 && len(segs) >= 2 {
		if n, e := strconv.Atoi(segs[1]); e == nil {
			major = n
		}
	}
	return token, major, true
}

// runJavaVersion 执行 `java -version` 并合并 stdout/stderr。
//
// 注意: java -version 把版本写到 **stderr**(历史惯性), 只读 stdout 会拿到空串,
// 因此必须用 CombinedOutput。超时 5s: java 启动很快, 超时说明环境异常,
// 不应拖慢环境检测的整体刷新。
func runJavaVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "java", "-version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", err
	}
	return string(out), nil
}
