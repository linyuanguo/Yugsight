//go:build windows

package probe

import (
	"unsafe"

	"syscall"
)

// kernel32Disk 本文件私有句柄(不依赖其它文件的共享句柄, 保持文件自洽)。
var kernel32Disk = syscall.NewLazyDLL("kernel32.dll")

// diskStatsFor 读 path 所在分区容量(GetDiskFreeSpaceExW)。
//
// free 返回 freeAvail(用户可用)而非 totalFree(含系统保留), 与"剩余空间"的
// 口径一致; 给非法路径时 API 失败, 回退 C 盘(与 diskStatsOS 同一兜底)。
func diskStatsFor(path string) (total, free uint64, ok bool) {
	target := path
	if target == "" {
		target = "C:\\"
	}
	root, _ := windowsUTF16PtrFromString(target)
	proc := kernel32Disk.NewProc("GetDiskFreeSpaceExW")
	var freeAvail, totalBytes, totalFree uint64
	if r, _, _ := proc.Call(
		uintptr(unsafe.Pointer(root)),
		uintptr(unsafe.Pointer(&freeAvail)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	); r == 0 {
		// 回退 C 盘: 目标盘符无效/路径异常时不至于整项空白
		root2, _ := windowsUTF16PtrFromString("C:\\")
		r2, _, _ := proc.Call(
			uintptr(unsafe.Pointer(root2)),
			uintptr(unsafe.Pointer(&freeAvail)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFree)),
		)
		if r2 == 0 {
			return 0, 0, false
		}
	}
	if totalBytes > totalFree {
		totalFree = totalBytes // 防御: 总空闲不可能超过总容量
	}
	return totalBytes, freeAvail, true
}
