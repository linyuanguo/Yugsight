package weakpass

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ===== 内置字典规模契约 =====

// TestBuiltinDictExactCount 守"内置字典恰为 349 条且无重复"的硬契约。
//
// 任务要求"首次启动自动内置 349 条常用弱口令, 数据完整无重复" —— 这一数字是
// 用户可见承诺(前端徽标/重置恢复目标), 若 top100.txt 被误改增删, 前端"内置 349"
// 与"重置恢复 349"会静默对不上, 故用精确断言锁死。
func TestBuiltinDictExactCount(t *testing.T) {
	if err := BuiltinLoadErr(); err != nil {
		t.Fatalf("内置字典读取失败: %v", err)
	}
	d := BuiltinDict()
	if len(d) != 349 {
		t.Fatalf("内置字典应为 349 条, 实际 %d", len(d))
	}
	seen := map[string]bool{}
	for _, p := range d {
		if seen[p] {
			t.Fatalf("内置字典存在重复项: %q", p)
		}
		seen[p] = true
	}
}

// writeUserDict 造一个含标记口令的用户字典文件。
func writeUserDict(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dict.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func dictContains(d []string, p string) bool {
	for _, x := range d {
		if x == p {
			return true
		}
	}
	return false
}

// TestDictSourceOverride 注入的字典源返回非空列表时, loadDict 以它为准并去重保序。
//
// 这是"字典与任务自动联动"的引擎侧契约: 装配层把 db 全量字典喂进来, 引擎必须
// 真正用它(而不是仍读内置/文件)。若实现退回内置, 自定义口令将永远不参与爆破。
func TestDictSourceOverride(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.0.0/24"}, Rate: testRate}, nil)
	// 故意含重复(aaa)与内置已有(123456), 验证去重; 顺序 aaa,123456,bbb 应保留
	e.SetDictSource(func() []string { return []string{"aaa", "123456", "bbb", "aaa"} })
	d := e.loadDict()
	if !dictContains(d, "aaa") || !dictContains(d, "bbb") || !dictContains(d, "123456") {
		t.Fatalf("字典源条目未生效: %v", d)
	}
	// 保序: aaa 在 bbb 前, 且 123456 只出现一次
	idxA, idxB := -1, -1
	for i, x := range d {
		if x == "aaa" && idxA < 0 {
			idxA = i
		}
		if x == "bbb" {
			idxB = i
		}
	}
	if idxA < 0 || idxB < 0 || idxA > idxB {
		t.Fatalf("字典源顺序未保留: %v", d)
	}
	n := 0
	for _, x := range d {
		if x == "123456" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("123456 应去重只保留一条, 实际 %d", n)
	}
}

// TestDictSourceEmptyFallsBack 字典源返回空(读失败/表空)时, 降级为 内置+用户文件。
//
// 契约: 空字典源绝不能让任务拿空字典跑 —— 那是"扫了个寂寞"的假阴性。
func TestDictSourceEmptyFallsBack(t *testing.T) {
	path := writeUserDict(t, "# 注释", "fromfile", "123456")
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.0.0/24"}, Rate: testRate, DictFile: path}, nil)
	e.SetDictSource(func() []string { return []string{} }) // 空 = 不可用
	d := e.loadDict()
	if !dictContains(d, "fromfile") {
		t.Fatal("字典源为空时应降级合并用户文件, fromfile 丢失")
	}
	if !dictContains(d, "123456") {
		t.Fatal("降级后内置字典条目丢失")
	}
}

// TestDictSourceNilKeepsLegacy 未注入字典源(nil)时, 保持 内置+用户文件 的原始行为。
// 规则 1 最小侵入: 既有"文件字典"能力不被新特性破坏。
func TestDictSourceNilKeepsLegacy(t *testing.T) {
	path := writeUserDict(t, "fromfile", "123456")
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.0.0/24"}, Rate: testRate, DictFile: path}, nil)
	// 不 SetDictSource → nil
	d := e.loadDict()
	if !dictContains(d, "fromfile") || !dictContains(d, "123456") {
		t.Fatal("无字典源时应为 内置+用户文件")
	}
}

// TestBuiltinOnlyExcludesCustom 页面"仅使用内置字典"开关: BuiltinOnly=true 时
// 只取内置字典, 用户文件条目不生效(任务要求"自定义条目不生效")。
func TestBuiltinOnlyExcludesCustom(t *testing.T) {
	path := writeUserDict(t, "fromfile", "123456")
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.0.0/24"}, Rate: testRate, DictFile: path}, nil)

	// 默认(全量): 文件条目生效
	if !dictContains(e.resolveDict(Options{}), "fromfile") {
		t.Fatal("默认全量口径应包含用户文件条目")
	}
	// 仅内置: 文件条目不生效, 内置条目仍在
	builtin := e.resolveDict(Options{BuiltinOnly: true})
	if dictContains(builtin, "fromfile") {
		t.Fatal("BuiltinOnly 不应包含用户文件条目")
	}
	if !dictContains(builtin, "123456") {
		t.Fatal("BuiltinOnly 应包含内置字典条目")
	}

	// 显式 Dict 优先: 传了 Dict 时 BuiltinOnly 不生效(调用方精确意图)
	explicit := e.resolveDict(Options{Dict: []string{"only-this"}, BuiltinOnly: true})
	if len(explicit) != 1 || explicit[0] != "only-this" {
		t.Fatalf("显式 Dict 应优先于 BuiltinOnly, 实际 %v", explicit)
	}
}
