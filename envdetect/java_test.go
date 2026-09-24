// java_test.go Java 版本解析的回归测试(envdetect 侧)。
//
// 【缺陷背景】用户问"把 dist 目录移到别的电脑要装环境吗" —— 对 ZAP 答案是"要装 Java 17+"。
// 引擎文件会随目录一起过去(判为已安装), 但目标机器可能只有 Java 8 甚至没装 Java,
// 此时若状态页只报"zapcore 就绪"就是误导。故单列 Java 一项, 本文件守其判定逻辑。
//
// 【为什么必须测版本解析】java -version 的格式在 Java 8→9 时变过一次:
//
//	Java 8 及更早:  "1.8.0_391"  -> 主版本是 **8**(在第 2 段, 不是 1)
//	Java 9 及以后:  "17.0.9"     -> 主版本就是 17
//
// 读错会直接颠倒结论(要么让用户以为能跑, 要么反过来白装一遍 Java)。
package envdetect

import (
	"testing"
	"time"
)

func TestParseJavaVersionOut(t *testing.T) {
	cases := []struct {
		name      string
		out       string
		wantVer   string
		wantMajor int
		wantOK    bool
	}{
		{
			name:      "Java 8 旧格式(构建号要去掉)",
			out:       "java version \"1.8.0_391\"\nJava(TM) SE Runtime Environment (build 1.8.0_391-b13)",
			wantVer:   "1.8.0",
			wantMajor: 8,
			wantOK:    true,
		},
		{
			name:      "OpenJDK 17(恰好达标)",
			out:       "openjdk version \"17.0.9\" 2023-10-17\nOpenJDK Runtime Environment (build 17.0.9+9)",
			wantVer:   "17.0.9",
			wantMajor: 17,
			wantOK:    true,
		},
		{
			name:      "OpenJDK 21(+构建号要去掉)",
			out:       "openjdk version \"21.0.1+12-LTS\" 2023-10-17",
			wantVer:   "21.0.1",
			wantMajor: 21,
			wantOK:    true,
		},
		{
			name:      "Java 11(不达标)",
			out:       "openjdk version \"11.0.20\" 2023-08-17",
			wantVer:   "11.0.20",
			wantMajor: 11,
			wantOK:    true,
		},
		{
			name:      "纯主版本号",
			out:       "java version \"17\"",
			wantVer:   "17",
			wantMajor: 17,
			wantOK:    true,
		},
	}
	for _, c := range cases {
		ver, major, ok := parseJavaVersionOut(c.out)
		if ok != c.wantOK {
			t.Errorf("%s: 解析状态错误, 得到 %v 期望 %v", c.name, ok, c.wantOK)
			continue
		}
		if ver != c.wantVer {
			t.Errorf("%s: 版本串应为 %q, 实际 %q", c.name, c.wantVer, ver)
		}
		if major != c.wantMajor {
			t.Errorf("%s: 主版本应为 %d, 实际 %d", c.name, c.wantMajor, major)
		}
	}

	// 单独断言"是否达标"的边界: 16 不达标 / 17 达标 —— 这是与 ZAP 要求绑定的关键分界
	for _, c := range []struct {
		out  string
		want bool
	}{
		{"java version \"16.0.2\"", false},
		{"java version \"17\"", true},
	} {
		_, major, ok := parseJavaVersionOut(c.out)
		if !ok {
			t.Fatalf("%q 应能解析", c.out)
		}
		if got := major >= javaMinMajor; got != c.want {
			t.Errorf("%q: 达标判定应为 %v, 实际 %v (主版本 %d)", c.out, c.want, got, major)
		}
	}
}

// TestParseJavaVersionOutUnparsable 解析不出时必须判失败。
//
// 方向很重要: 误判"达标"会让用户以为 ZAP 能用, 实际一扫描就报 class 版本错;
// 误判"不达标"最多是让他确认一下, 代价小得多。
func TestParseJavaVersionOutUnparsable(t *testing.T) {
	for _, out := range []string{"", "command not found", "Exception in thread \"main\""} {
		if _, _, ok := parseJavaVersionOut(out); ok {
			t.Errorf("无法解析的输入 %q 不应判定为解析成功", out)
		}
	}
}

// TestDetectJavaSelfConsistent 真机探测自洽(不假设本机装了哪个版本的 Java)。
func TestDetectJavaSelfConsistent(t *testing.T) {
	s := detectJava()
	if s.MinVersion != javaMinMajor {
		t.Errorf("MinVersion 应为 %d, 实际 %d", javaMinMajor, s.MinVersion)
	}
	if s.OK {
		// 达标时必须能说出是哪个版本(状态页要展示给用户核对)
		if !s.Found || s.Version == "" {
			t.Errorf("判定达标时应同时有 found 与 version: %+v", s)
		}
	} else {
		// 不达标时必须有可读原因, 否则前端只能显示一个空洞的红点
		if s.Note == "" {
			t.Errorf("判定不达标时必须给出 note 说明原因: %+v", s)
		}
	}
}

// TestDetectJavaTimeBudget 保证探测不会拖慢环境检测刷新(内部 5s 超时必须生效)。
//
// 预留 8s(5s 超时 + 启动开销): 若超时控制失效, 探测会一直挂住, 本用例会及时红灯,
// 而不是等到用户发现"点重新检测后界面一直转圈"。
func TestDetectJavaTimeBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过耗时探测")
	}
	done := make(chan JavaStatus, 1)
	go func() { done <- detectJava() }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("Java 探测超过 8 秒未返回, 超时控制可能失效(会拖慢环境状态刷新)")
	}
}
