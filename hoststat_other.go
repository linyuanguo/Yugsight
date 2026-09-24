//go:build !windows

package main

// 中心主机 CPU 采样(阶段 4 运行状态面板用, 非 Windows)。
//
// 复用探针包 /proc/stat 的采样实现(累计节拍口径一致), 不重复解析:
// 两套实现各自维护必然漂移, 表现为同一台机器上"中心端面板"与"探针
// 节点"的 CPU 数字对不上。
import "yugsight/probe"

type cpuTicks struct {
	total uint64
	idle  uint64
}

// sampleCenterCPU 读一次系统累计节拍; 不可用(如非 Linux)返回 nil。
func sampleCenterCPU() *cpuTicks {
	s := probe.SampleCPU()
	if s.Total == 0 {
		return nil
	}
	return &cpuTicks{total: s.Total, idle: s.Idle}
}

// cpuTicksPercent 两次采样的 CPU 占用百分比(0-100); 口径与探针端一致。
func cpuTicksPercent(prev, cur *cpuTicks) float64 {
	return probe.CPUPercent(
		probe.CpuSample{Total: prev.total, Idle: prev.idle},
		probe.CpuSample{Total: cur.total, Idle: cur.idle},
	)
}
