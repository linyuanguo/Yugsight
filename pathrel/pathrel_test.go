package pathrel

import (
	"path/filepath"
	"strings"
	"testing"
)

// InMessage 守的契约: 日志消息里 exe 目录前缀必须被相对化, 目录外/边界不满足的内容
// 必须原样保留 —— 误伤 URL/系统路径比"长一点"严重得多。
func TestInMessage(t *testing.T) {
	sep := string(filepath.Separator)
	prefix := "." + sep

	restore := func(fn func() string) {
		SetExeDirForTest(fn)
		t.Cleanup(func() { SetExeDirForTest(func() string { return "" }) })
	}

	t.Run("树内路径相对化", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		msg := "表 assets 已加载 1 条记录 (" + filepath.Join(base, "data", "assets.jsonl") + ")"
		want := "表 assets 已加载 1 条记录 (" + prefix + "data" + sep + "assets.jsonl)"
		if got := InMessage(msg); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("多处出现全部替换", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		p1 := filepath.Join(base, "a.log")
		p2 := filepath.Join(base, "b", "c.txt")
		msg := p1 + " -> " + p2
		want := prefix + "a.log -> " + prefix + "b" + sep + "c.txt"
		if got := InMessage(msg); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("目录外路径原样保留", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base})
		outside := filepath.Join(t.TempDir(), "java.exe")
		msg := "java 路径 " + outside
		if got := InMessage(msg); got != msg {
			t.Fatalf("got %q, want 原样 %q", got, msg)
		}
	})

	t.Run("边界: 同前缀更长目录不误换", func(t *testing.T) {
		// base=...\dist 时, 消息里的 ...\dist2\xxx 不得被替换(否则变成 ".\2\xxx")
		parent := t.TempDir()
		base := filepath.Join(parent, "dist")
		restore(func() string { return base })
		msg := "目录 " + filepath.Join(parent, "dist2", "x.log")
		if got := InMessage(msg); got != msg {
			t.Fatalf("got %q, want 原样 %q", got, msg)
		}
	})

	t.Run("边界: 前缀前有字母数字不误换", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		msg := "XE" + base + sep + "x.log" // "XE<base>" 不是独立路径
		if got := InMessage(msg); got != msg {
			t.Fatalf("got %q, want 原样 %q", got, msg)
		}
	})

	t.Run("大小写不敏感", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		msg := "目录 " + upperFirst(base) + sep + "data"
		want := "目录 " + prefix + "data"
		if got := InMessage(msg); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("URL 与 CIDR 不受影响", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		msg := "UI 地址 http://192.168.1.143:8420 白名单 10.0.0.0/8"
		if got := InMessage(msg); got != msg {
			t.Fatalf("got %q, want 原样 %q", got, msg)
		}
	})

	t.Run("基准不可得原样保留", func(t *testing.T) {
		restore(func() string { return "" })
		msg := "任意消息 " + filepath.Join("C:", "x", "y.log")
		if got := InMessage(msg); got != msg {
			t.Fatalf("got %q, want 原样 %q", got, msg)
		}
	})

	t.Run("空消息", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		if got := InMessage(""); got != "" {
			t.Fatalf("got %q, want 空串", got)
		}
	})
}

func TestShort(t *testing.T) {
	sep := string(filepath.Separator)
	prefix := "." + sep

	t.Run("树内相对化", func(t *testing.T) {
		base := t.TempDir()
		SetExeDirForTest(func() string { return base })
		t.Cleanup(func() { SetExeDirForTest(func() string { return "" }) })
		want := prefix + "bin" + sep + "nucleicore.exe"
		if got := Short(filepath.Join(base, "bin", "nucleicore.exe")); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("树外原样保留", func(t *testing.T) {
		base := t.TempDir()
		SetExeDirForTest(func() string { return base })
		t.Cleanup(func() { SetExeDirForTest(func() string { return "" }) })
		outside := filepath.Join(t.TempDir(), "java.exe")
		if got := Short(outside); got != outside {
			t.Fatalf("got %q, want 原样 %q", got, outside)
		}
	})

	t.Run("空输入返回空", func(t *testing.T) {
		SetExeDirForTest(func() string { return t.TempDir() })
		t.Cleanup(func() { SetExeDirForTest(func() string { return "" }) })
		if got := Short(""); got != "" {
			t.Fatalf("got %q, want 空串", got)
		}
	})
}

// upperFirst 首字符转大写(构造与基准大小写不同的同一路径, 仅测试用)。
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
