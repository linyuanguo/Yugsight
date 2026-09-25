// java_runtime_test.go Java 版本判定的回归测试。
//
// 【缺陷背景】ZAP 需要 Java 17+, 但官方跨平台包不含 Java。实测用户机器是 Java 8:
// 273MB 下载成功、解包成功、落位成功, 执行 zap.bat 却抛
//
//	UnsupportedClassVersionError: class file version 61.0
//
// 这类"装好了但跑不起来"的失败必须在安装前暴露, 所以引入了 javaRuntimeOK 预检。
//
// 【为什么必须测版本解析】java -version 的版本号格式在历史上换过一次:
//   - Java 8 及更早:  "1.8.0_391"   -> 主版本是 **8**, 不是 1
//   - Java 9 及以后:  "17.0.9"      -> 主版本就是 17
//
// 若把 "1.8.0_391" 的主版本误读成 1, 会得出"1 >= 17 不成立"→ 恰好判对(误打误撞);
// 但若把它读成 8 却写成 `major >= 17` 之外的条件, 或把 "1.9.0"(Java 9 的过渡写法)
// 读成 1, 就会出现"Java 9 被当成不满足"这类误判。这里用表驱动把两种格式都钉住。
package engmgr

import (
	"testing"
)

// TestJavaVersionMajorParsing 版本号 -> (是否满足 Java 17+, 展示用版本串)
func TestJavaVersionMajorParsing(t *testing.T) {
	cases := []struct {
		name    string
		out     string // java -version 的原始输出形态
		wantOK  bool
		wantVer string
	}{
		{
			name:    "Java 8 旧格式(实测用户环境)",
			out:     "java version \"1.8.0_391\"\nJava(TM) SE Runtime Environment (build 1.8.0_391-b13)",
			wantOK:  false,
			wantVer: "1.8.0",
		},
		{
			name:    "OpenJDK 17",
			out:     "openjdk version \"17.0.9\" 2023-10-17\nOpenJDK Runtime Environment (build 17.0.9+9)",
			wantOK:  true,
			wantVer: "17.0.9",
		},
		{
			name:    "OpenJDK 21",
			out:     "openjdk version \"21.0.1\" 2023-10-17",
			wantOK:  true,
			wantVer: "21.0.1",
		},
		{
			name:    "Java 11 不满足",
			out:     "openjdk version \"11.0.20\" 2023-08-17",
			wantOK:  false,
			wantVer: "11.0.20",
		},
		{
			// Temurin/Eclipse 的 21 版会带 "+12-LTS", 版本 token 里出现字母。
			// 若正则只允许数字与 . _ + -, 这条会整条匹配失败 → "装了 Java 21 却报未检测到"。
			name:    "Temurin 21 带 +12-LTS 构建号",
			out:     "openjdk version \"21.0.1+12-LTS\" 2023-10-17\nOpenJDK Runtime Environment Temurin-21.0.1+12 (build 21.0.1+12-LTS)",
			wantOK:  true,
			wantVer: "21.0.1",
		},
		{
			name:    "恰好 17 必须满足(边界)",
			out:     "java version \"17\"",
			wantOK:  true,
			wantVer: "17",
		},
		{
			name:    "16 不满足(边界下沿)",
			out:     "java version \"16.0.2\"",
			wantOK:  false,
			wantVer: "16.0.2",
		},
	}
	for _, c := range cases {
		ver, major, ok := parseJavaVersion(c.out)
		if !ok {
			t.Errorf("%s: 应能被解析出来, 实际失败 (ver=%q)", c.name, ver)
			continue
		}
		// 可用性 = 主版本是否达标, 与 javaRuntimeOK 的判定口径保持一致
		if got := major >= javaMinMajor; got != c.wantOK {
			t.Errorf("%s: 可用性判定错误, 主版本=%d 得到 %v 期望 %v", c.name, major, got, c.wantOK)
		}
		if ver != c.wantVer {
			t.Errorf("%s: 版本串应为 %q, 实际 %q", c.name, c.wantVer, ver)
		}
	}
}

// TestJavaVersionUnparsable 解析不出时必须判"不可用"而不是"可用"。
//
// 方向很重要: 误判为"可用"会让用户白下 273MB 才失败(正是本次故障的现象);
// 误判为"不可用"最多是提示用户手动确认一下, 代价小得多。
func TestJavaVersionUnparsable(t *testing.T) {
	for _, out := range []string{"", "not java at all", "Exception in thread main"} {
		if _, _, ok := parseJavaVersion(out); ok {
			t.Errorf("无法解析的输入 %q 不应判定为解析成功", out)
		}
	}
}

// TestJavaRuntimeOKMatchesEnv 真机探测与解析结果自洽(不依赖本机一定装了 Java)。
//
// 只断言"两件事不矛盾": 若探测到可用, 版本串必须非空; 若不可用, 版本串为空或"版本未知"。
// 这样在装了 Java 8 的机器(本次故障环境)与装了 Java 17 的机器上都能稳定通过。
func TestJavaRuntimeOKMatchesEnv(t *testing.T) {
	ok, ver := javaRuntimeOK()
	if ok && ver == "" {
		t.Error("判定可用时版本串不应为空(UI 要展示给用户核对)")
	}
	// 不可用但解析出了具体版本 -> 属于"版本偏低", 这是最有用的提示, 记一条日志便于排查
	if !ok && ver != "" && ver != "版本未知" {
		t.Logf("本机 Java 不满足 ZAP 要求, 预检提示为: %s", ver)
	}
}
