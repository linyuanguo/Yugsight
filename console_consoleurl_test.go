package main

import (
	"strings"
	"sync"
	"testing"
)

// 控制台地址常显(console_consoleurl.go)的用例。
//
// 【为什么这些是该测的】守的是两个"改坏了会静默失效"的契约:
//   1. console 节缺失时必须默认**开启** —— 有人把默认值改成 false, 功能会静默消失,
//      界面毫无变化, 只有用户下次关掉网页想重新打开时才发现;
//   2. {"hint":false} 必须真的关掉 —— 若把 *bool 优化成 bool, JSON 零值与"没写"
//      混为一谈, 用例 1 与用例 2 会有一边失败。
// setConsoleTitle 本身是 Win32 调用, 离线无法断言, 不在单测范围。
//
// 复用 settings_test.go 的 withTempExeDir/writeTestSettings: 配置路径基于
// os.Executable(), 不能换目录, 只能"独占 + 用完即清"(详见那边的注释)。

func TestConsoleHintDefaultEnabled(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"_comment": "不配置 console 节"}`)
	resetConsoleConfigCache()

	if !consoleHintEnabled() {
		t.Fatal("console 节缺失时必须默认启用地址常显(否则功能静默消失)")
	}
}

func TestConsoleHintExplicitlyDisabled(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"console": {"hint": false}}`)
	resetConsoleConfigCache()

	if consoleHintEnabled() {
		t.Fatal(`settings.json 写了 console.hint=false 时必须关闭`)
	}
}

func TestConsoleHintExplicitlyEnabled(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"console": {"hint": true}}`)
	resetConsoleConfigCache()

	if !consoleHintEnabled() {
		t.Fatal(`settings.json 写了 console.hint=true 时必须启用`)
	}
}

// TestUIURLConcurrentAccess 用 -race 跑: SetUIURL 在启动阶段写, GetUIURL 在标题刷新与
// 键盘监听两个 goroutine 里读。去掉 uiURLMu 这个用例就会报数据竞争。
func TestUIURLConcurrentAccess(t *testing.T) {
	SetUIURL("http://192.168.1.143:8420")
	t.Cleanup(func() { SetUIURL("") })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if u := GetUIURL(); u != "http://192.168.1.143:8420" {
					t.Errorf("读到的地址不符: %q", u)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestUIURLEmptyBeforeStart 未启动完成时地址必须是空串。
// 键盘监听里靠这个判空决定是否开浏览器 —— 返回假地址会打开一个不存在的页面。
func TestUIURLEmptyBeforeStart(t *testing.T) {
	SetUIURL("")
	t.Cleanup(func() { SetUIURL("") })
	if u := GetUIURL(); u != "" {
		t.Fatalf("未启动时应为空串, 实际 %q", u)
	}
}

// ===== 顶栏常显(consoleURLLineText/displayWidth/viewportAtBottom) =====

func TestDisplayWidth(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"http://192.168.1.143:8420", 25},
		{"中文", 4},
		{"UI 界面", 7}, // 2+1+4
		{"ａｂ", 4},   // 全角拉丁(FF01-FF60)按 2 列
		{"a①b", 3},  // 带圈数字不在宽字符表内, 按窄算(粗算的可接受误差)
	}
	for _, c := range cases {
		if got := displayWidth(c.in); got != c.want {
			t.Errorf("displayWidth(%q) = %d, 期望 %d", c.in, got, c.want)
		}
	}
}

func TestConsoleURLLineText(t *testing.T) {
	SetUIURL("http://192.168.1.143:8420")
	t.Cleanup(func() { SetUIURL("") })

	// 常规宽度: 整行显示宽必须恰好等于 width-1。
	// 【为什么钉死这个数】填到 width 会触发 conhost 自动折行(顶栏占两行), 填少了行尾
	// 残留旧内容 —— 两个方向都是回归, 这里一次性守住。
	const w = 120
	line := consoleURLLineText(w)
	if got := displayWidth(line); got != w-1 {
		t.Fatalf("顶栏整行显示宽 = %d, 期望 %d", got, w-1)
	}
	if !strings.Contains(line, "http://192.168.1.143:8420") {
		t.Fatal("顶栏必须包含 URL 本身(点击检测靠它)")
	}

	// 极窄窗口: 必须截断到不超宽, 绝不能折行
	narrow := consoleURLLineText(30)
	if nw := displayWidth(narrow); nw > 29 {
		t.Fatalf("窄窗口(30 列)下顶栏显示宽 = %d, 超过了 width-1=29(会折行)", nw)
	}
	if !strings.Contains(narrow, "http://192.168.1.143:8420") {
		t.Fatal("窄窗口下 URL 本身也应完整保留(提示语可丢)")
	}

	// 过窄到连 URL 都放不下: 空串(宁可不显示也不能把日志区顶乱)
	if got := consoleURLLineText(10); got != "" {
		t.Fatalf("10 列窗口应返回空串, 实际 %q", got)
	}

	// 无 URL(未启动完成): 空串, 不能输出"UI 界面: "这种残缺行
	SetUIURL("")
	if got := consoleURLLineText(w); got != "" {
		t.Fatalf("无 URL 时应返回空串, 实际 %q", got)
	}
}

func TestViewportAtBottom(t *testing.T) {
	// 贴底: 视口底 == 光标行或光标行+1(长行折行时视口可能滞后)
	if !viewportAtBottom(30, 30) {
		t.Fatal("视口底==光标行 应视为贴底")
	}
	if !viewportAtBottom(31, 30) {
		t.Fatal("视口底==光标行+1 应视为贴底")
	}
	// 回滚: 视口底明显在光标上方, 用户正在看历史
	if viewportAtBottom(20, 30) {
		t.Fatal("视口底比光标行高 10 行不应视为贴底(用户回滚中)")
	}
	// 容差边界: 只允许滞后 1 行, 滞后 2 行就算回滚
	if viewportAtBottom(28, 30) {
		t.Fatal("滞后 2 行应视为回滚")
	}
}
