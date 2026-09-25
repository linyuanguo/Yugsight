// java_runtime.go Java 运行时探测(供 ZAP 这类 Java 引擎做"安装前预检")。
//
// 【为什么要做这个预检 —— 这是一次真实故障】
// ZAP 官方跨平台包(Crossplatform.zip, 273MB)**不含 Java**, 运行要求 Java 17+。
// 实测用户机器上是 Java 8, 于是: 下载 273MB 成功 → 解包成功 → 整包落位成功 →
// 但 `zap.bat -version` 抛:
//
//	java.lang.UnsupportedClassVersionError: org/zaproxy/zap/ZAP
//	has been compiled by a more recent version of the Java Runtime (class file version 61.0)
//
// 对用户而言这是最糟糕的失败形态: 界面上"安装成功", 真正使用时却起不来,
// 且错误信息是 JVM 的 class 版本号(61.0 = Java 17), 大多数人看不出该装什么。
// 所以在**安装前**就把结论明确到 UI: "未检测到 Java 17+ (当前: 1.8.0_391)"。
//
// 纯标准库实现: 直接执行 java -version 解析版本号; java 缺失/超时/输出异常
// 一律当作"不可用"并带上原因(项目规则 3: 降级不报错)。
package engmgr

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// javaMinMajor ZAP 2.17 要求的最低 Java 主版本。
// 依据: 其 class file version 61.0 对应 Java 17(52=8, 55=11, 61=17)。
const javaMinMajor = 17

// javaVerRe 从 `java -version` 的输出里抓版本号 token(构建号交给 parseJavaVersion 归一化)。
//
// 覆盖实测见过的各种形态:
//
//	Java 8  : "1.8.0_391"      -> 主版本 8,  展示串 "1.8.0"
//	Java 17+: "17.0.9"         -> 主版本 17, 展示串 "17.0.9"
//	Temurin : "21.0.1+12-LTS"  -> 主版本 21, 展示串 "21.0.1"
//
// 关键点: 字符类必须允许字母。若写成 `[0-9._+\-]*`, 遇到 "21.0.1+12-LTS" 会因 LTS
// 而**整条匹配失败** → "装了 Java 21 却报未检测到"(实测踩到)。用 {0,24} 限制长度,
// 避免吞掉后续整行文本。拆成"抓 token + 后处理"两步比一条精确正则更稳: 构建号形态
// 太多样(_391 / +9 / +12-LTS / -ea), 一次性切准反而脆。
var javaVerRe = regexp.MustCompile(`"([0-9][0-9A-Za-z._+\-]{0,24})"`)

// javaRuntimeOK 探测本机 Java 是否满足 ZAP 要求。
// 返回 (是否可用, 版本描述)。版本描述在失败时也尽量给出(便于 UI 展示"当前是几")。
func javaRuntimeOK() (bool, string) {
	out, err := runJavaVersion()
	if err != nil {
		return false, ""
	}
	ver, major, ok := parseJavaVersion(out)
	if !ok {
		// 能执行但解析不出版本(极少见): 无法确认满足要求, 判为不可用并给出可读说明
		// (方向很重要: 误判"可用"会让用户白下 273MB 才失败)
		return false, "版本未知"
	}
	return major >= javaMinMajor, ver
}

// parseJavaVersion 从 java -version 输出解析 (展示用版本串, 主版本号, 是否解析成功)。
//
// 纯函数便于单测: 版本号格式在 Java 8→9 时变过一次, 是最容易写错的地方 ——
// 把 "1.8.0_391" 的主版本读成 1 还是 8 会直接改变"能否运行 ZAP"的结论。
//
// 归一化规则(对用户展示友好, 且便于与 17 做肉眼对比):
//
//	"1.8.0_391" -> 主版本 8,  展示串 "1.8.0"   (丢掉 _391 构建号)
//	"17.0.9+9"  -> 主版本 17, 展示串 "17.0.9"
//	"17"        -> 主版本 17, 展示串 "17"
func parseJavaVersion(out string) (string, int, bool) {
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

// firstNonEmpty 返回第一个非空字符串(仅用于生成人类可读的提示文本)
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// runJavaVersion 执行 `java -version` 并合并 stdout/stderr。
//
// 注意 java -version 是把版本写到 **stderr** 的(历史惯性), 只读 stdout 会拿到空串,
// 因此这里用 CombinedOutput。超时 5s: java 启动很快, 超过说明环境异常(如 PATH 命中
// 了会挂住的包装脚本), 不宜拖慢界面刷新。
func runJavaVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "java", "-version")
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", err
	}
	return string(out), nil
}
