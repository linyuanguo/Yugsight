package envdetect

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"yugsight/pathrel"
)

// shortPath(委托 pathrel.Short) 守着一个会被"别人改坏就静默失效"的契约:
// exe 目录树内的路径必须相对化, exe 目录外的路径必须原样保留。
// 若相对化误伤目录外路径(如系统 Java 的 PATH 路径), 前端/日志会显示不可定位的假路径。
func TestShortPath(t *testing.T) {
	restore := func(fn func() string) {
		pathrel.SetExeDirForTest(fn)
		t.Cleanup(func() { pathrel.SetExeDirForTest(func() string { return "" }) })
	}
	sep := string(os.PathSeparator)
	rel := filepath.Join("bin", "nucleicore.exe")
	want := "." + sep + rel

	t.Run("exe目录树内相对化", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		if got := shortPath(filepath.Join(base, rel)); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("exe目录外原样保留", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		outside := filepath.Join(t.TempDir(), "java.exe")
		if got := shortPath(outside); got != outside {
			t.Fatalf("got %q, want 原样 %q", got, outside)
		}
	})

	t.Run("基准目录不可得时原样保留", func(t *testing.T) {
		restore(func() string { return "" })
		p := filepath.Join("C:", "x", "y.exe")
		if runtime.GOOS != "windows" {
			p = "/usr/local/bin/java"
		}
		if got := shortPath(p); got != p {
			t.Fatalf("got %q, want 原样 %q", got, p)
		}
	})

	t.Run("空输入返回空", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		if got := shortPath(""); got != "" {
			t.Fatalf("got %q, want 空串", got)
		}
	})

	t.Run("等于基准目录本身时原样保留", func(t *testing.T) {
		base := t.TempDir()
		restore(func() string { return base })
		if got := shortPath(base); got != base {
			t.Fatalf("got %q, want 原样 %q", got, base)
		}
	})
}
