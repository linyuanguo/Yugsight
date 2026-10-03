//go:build windows

package probe

import (
	"time"
)

// ===== Windows: PDH 每网卡实例速率 =====
//
// 数据来源是 PDH 的 "Network Interface(<实例>)\Bytes Sent/Received/sec" —— 组 7
// (2026-10-01)修好后本机已能展开真实网卡实例(本机没有 _Total 实例)。
//
// 口径边界(刻意不为好看而编造): PDH 只给"实例名 + 速率", 给不出 MAC / IP /
// 链路状态; Windows 上 PDH 实例名是适配器描述(如 "Realtek PCIe GbE Family
// Controller"), 与标准库 net.Interfaces() 的接口名("以太网"/GUID)不同源,
// 强行按序或按名匹配会错配(把 A 口的 MAC 安到 B 口比留空危害大得多)—— 因此
// 这些字段留空, UI 显示 '-'。要补全需走 GetAdaptersAddresses/GetIfTable2 FFI,
// 属后续增强。

func sampleIfaces(interval time.Duration) []IfaceSample {
	pdhMu.Lock()
	defer pdhMu.Unlock()
	if !pdhInit() {
		return nil
	}
	// 与 SampleMetrics 共用同一次 PDH 采集(同拍复用, 见 pdhCollectOnce 注释):
	// 此前本函数独立推一拍, 同拍内紧跟 SampleMetrics 之后被调时, 两拍间隔微秒级,
	// 网卡明细速率恒 0(2026-10-02 中心端首上线即踩中)。
	vals, ok := pdhCollectOnce()
	if !ok {
		return nil
	}
	upVals := vals[pdhIdxNetUp]     // Bytes Sent/sec     = 上行
	downVals := vals[pdhIdxNetDown] // Bytes Received/sec = 下行

	// 两组由同一次展开建立, 实例名与顺序一一对应
	names := pdhNames[pdhIdxNetUp]
	if len(names) == 0 {
		names = pdhNames[pdhIdxNetDown]
	}
	out := make([]IfaceSample, 0, len(names))
	for i, n := range names {
		it := IfaceSample{Name: n}
		if i < len(upVals) {
			it.OutBps = upVals[i]
		}
		if i < len(downVals) {
			it.InBps = downVals[i]
		}
		out = append(out, it)
	}
	return out
}
