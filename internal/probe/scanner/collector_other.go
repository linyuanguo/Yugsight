//go:build !windows && !linux

package scanner

// collector_other.go 非 Windows 且非 Linux 平台(macOS 等)的采集器空桩。
//
// 说明: 这里**刻意不注册任何 Collector**(SetCollector 不调用), 于是
// CaptureSupported() 返回 false, 探针在这些平台上:
//   - 编译通过(项目规则 2);
//   - 抓包能力上报为"不支持", 中心端不会给这类节点下发 capture/arp 任务;
//   - 若仍被下发, 走 pcap.go 的"摘要模式"降级: 只记录交互文字证据, 不 crash。
//
// 平台实现分布: Windows = collector_windows.go(Npcap),
// Linux = collector_linux.go(AF_PACKET 原始套接字, 2026-09-27 新增)。
