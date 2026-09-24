//go:build !windows

package main

import "fmt"

// pcap_other.go 非 Windows 平台抓包空桩(与 pcap_windows.go 一一对应)。
//
// 抓包依赖 Npcap(WinPcap API 的 Windows 实现), 其它平台没有等价的本地方案,
// 因此这里只提供"接口存在但明确不可用"的桩实现:
//   - 全平台编译通过(项目规则 2: Windows 专属功能必须配 *_other.go 空桩);
//   - 调用方(抓包 API / 探针抓包骨架)拿到错误后走降级路径, 不 panic 不崩溃(规则 3/4);
//   - 不引入 libpcap 的 cgo 依赖, 保持"纯标准库单二进制"约束。
//
// 若未来需要支持 Linux 抓包, 在 build 标签为 linux 的文件里改用 AF_PACKET 原始套接字
// 实现同名函数即可, 上层代码零改动(接口在此固定)。

const pcapUnsupported = "抓包功能仅支持 Windows(需安装 Npcap)"

// PcapDevice 捕获适配器(非 Windows 恒为空列表)。
type PcapDevice struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// PcapDevices 枚举捕获适配器: 非 Windows 返回空列表与说明性错误。
func PcapDevices() ([]PcapDevice, error) {
	return nil, fmt.Errorf("%s", pcapUnsupported)
}

// pcapHandle 抓包句柄空桩(仅占位, 不会被成功构造)。
type pcapHandle struct{}

// PcapOpenLive 打开实时抓包: 非 Windows 直接失败。
func PcapOpenLive(name string, snapLen uint32, filter string) (*pcapHandle, error) {
	return nil, fmt.Errorf("%s", pcapUnsupported)
}

// Next 读取一个报文: 非 Windows 恒返回 (nil, false)。
func (h *pcapHandle) Next() ([]byte, bool) { return nil, false }

// ErrCount 连续读取错误计数: 空桩恒为 0。
func (h *pcapHandle) ErrCount() int { return 0 }

// Close 释放句柄: 空桩无操作。
func (h *pcapHandle) Close() {}

// LastHdr 返回最近一个报文的长度信息: 空桩恒为无数据。
// 必须与 pcap_windows.go 的同名方法签名一致 —— capture_worker.go 无构建约束,
// 全平台都会编译到这些调用点(项目规则 2: Windows 专属功能必须配 *_other.go 空桩)。
func (h *pcapHandle) LastHdr() (capLen, length uint32, hasData bool) { return 0, 0, false }

// ReadStats 返回读取统计(收到/超时/错误): 空桩恒为 0。
func (h *pcapHandle) ReadStats() (got, zero, neg int) { return 0, 0, 0 }

// LinkType 返回链路层类型: 空桩恒为 0(非 Windows 无法抓到报文, 该值不会被使用)。
func (h *pcapHandle) LinkType() int { return 0 }

// PcapRelease 释放 wpcap.dll: 非 Windows 无操作(保留接口以统一调用方代码)。
func PcapRelease() {}
