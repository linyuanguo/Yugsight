//go:build windows

package main

import (
	"unsafe"
)

// 中心主机 CPU 采样(阶段 4 运行状态面板用)。
//
// 为什么不用 probe 包的 sampleCPU: 它用 GetTickCount64(开机毫秒数)近似,
// Idle 恒为 0, 差分口径下 CPU 占用会恒算成 100% —— 作为负载趋势近似勉强,
// 但展示成"中心主机 CPU 使用率"就误导了。这里走 GetSystemTimes(XP 起可用),
// 拿真实的 idle/kernel/user 累计节拍, 与探针端 /proc/stat 同一精度口径。

type cpuTicks struct {
	total uint64 // kernel + user(kernel 已含 idle)
	idle  uint64
}

// sampleCenterCPU 读一次系统累计节拍; 失败返回 nil(调用方降级为"无数据")。
func sampleCenterCPU() *cpuTicks {
	proc := kernel32.NewProc("GetSystemTimes")
	var idle, kernel, user uint64 // FILETIME 小端下低 32 位在前, 与 uint64 布局一致
	if r, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	); r == 0 {
		return nil
	}
	return &cpuTicks{total: kernel + user, idle: idle}
}

// cpuTicksPercent 两次采样的 CPU 占用百分比(0-100); 无效差值返回 0。
func cpuTicksPercent(prev, cur *cpuTicks) float64 {
	if prev == nil || cur == nil || cur.total <= prev.total {
		return 0
	}
	dt := cur.total - prev.total
	di := uint64(0)
	if cur.idle > prev.idle {
		di = cur.idle - prev.idle
	}
	if dt == 0 || di > dt {
		return 0
	}
	return float64(dt-di) * 100 / float64(dt)
}
