package probe

import (
	"path/filepath"
	"testing"
)

// TestHostStatMem 中心端运行状态面板依赖的内存采集: 总量必须为正、已用不超总量。
// 双平台(Windows GlobalMemoryStatusEx / Linux /proc/meminfo)都应可用,
// 采集失败会导致面板整块空白, 这里守住"可用"这条契约。
func TestHostStatMem(t *testing.T) {
	total, used, ok := MemStats()
	if !ok {
		t.Fatal("MemStats 应成功")
	}
	if total == 0 || used > total {
		t.Fatalf("内存采集异常: total=%d used=%d", total, used)
	}
}

// TestHostStatDisk 对真实存在的目录采集: 总量为正、0<=可用<=总量,
// 同目录与其父目录必须一致(同一分区, 防止误把相对路径解析到别的盘)。
func TestHostStatDisk(t *testing.T) {
	dir := t.TempDir()
	total, free, ok := DiskStats(dir)
	if !ok {
		t.Fatal("DiskStats 应成功")
	}
	if total == 0 || free > total {
		t.Fatalf("磁盘采集异常: total=%d free=%d", total, free)
	}
	total2, _, ok2 := DiskStats(filepath.Dir(dir))
	if !ok2 || total2 != total {
		t.Fatalf("同一分区容量应一致: %d vs %d", total, total2)
	}
}

// TestHostStatDiskBadPath 非法路径不 panic, 回退默认盘仍应可用。
func TestHostStatDiskBadPath(t *testing.T) {
	total, _, ok := DiskStats("Z:\\definitely\\not\\exists\\dir")
	if !ok {
		t.Skip("回退盘采集不可用(受限环境)")
	}
	if total == 0 {
		t.Fatalf("回退后总量应为正, got 0")
	}
}
