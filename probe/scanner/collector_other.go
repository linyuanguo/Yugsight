//go:build !windows

package scanner

// collector_other.go 非 Windows 平台的采集器空桩(与 collector_windows.go 对应)。
//
// 说明: 这里**刻意不注册任何 Collector**(SetCollector 不调用), 于是
// CaptureSupported() 返回 false, 探针在 Linux/macOS 上:
//   - 编译通过(项目规则 2);
//   - 抓包能力上报为"不支持", 中心端不会给这类节点下发 capture 任务;
//   - 若仍被下发, 走 pcap.go 的"摘要模式"降级: 只记录交互文字证据, 不 crash。
//
// 为什么不注册一个"总是失败"的采集器: 那会让 CaptureSupported()=true 而
// 实际上报"支持但永远失败", 中心端无法据能力做正确调度。
// 未来若要支持 Linux(AF_PACKET 原始套接字), 在此文件按 Collector 接口实现并注册即可。
