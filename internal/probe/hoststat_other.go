//go:build !windows

package probe

import "syscall"

// diskStatsFor 读 path 所在分区容量(Statfs), 失败回退 /。
func diskStatsFor(path string) (total, free uint64, ok bool) {
	target := path
	if target == "" {
		target = "/"
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(target, &st); err != nil {
		if err := syscall.Statfs("/", &st); err != nil {
			return 0, 0, false
		}
	}
	bs := uint64(st.Bsize)
	total = st.Blocks * bs
	free = st.Bavail * bs
	if free > total {
		free = total
	}
	return total, free, true
}
