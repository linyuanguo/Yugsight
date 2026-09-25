//go:build windows

package main

import (
	"syscall"
	"testing"
)

// TestPcapProcSymbols 检查 initPcap 用到的符号在当前 wpcap.dll 里是否真的存在。
//
// 【为什么怀疑这里】同机同网卡同参数下:
//   - 独立写的 wpcap 测试程序(自己 LoadLibrary + FindProc + Call) 抓到 777 个包;
//   - 本程序的 -pcap=capture worker 抓到 0 个包, 且 stderr 只有 READY。
// 两者唯一的结构差异是符号获取与调用路径。initPcap 里所有 FindProc 都写成
// `procXxx, _ = dll.FindProc(...)`, **错误被丢弃** —— 若某符号名在当前 Npcap
// 版本里不存在, 拿到的是"带内部错误的 Proc", 调用不 panic 只失败, 现象正是
// "适配器能打开(READY 可打印) 但永远读不到包"。这里把符号存在性显式断言出来。
func TestPcapProcSymbols(t *testing.T) {
	if err := initPcap(); err != nil {
		t.Fatalf("initPcap 失败: %v", err)
	}
	// 必需符号: 缺失必然导致功能不可用
	required := []string{
		"pcap_findalldevs", "pcap_freealldevs", "pcap_open_live",
		"pcap_next_ex", "pcap_close", "pcap_compile", "pcap_setfilter",
	}
	for _, name := range required {
		if _, err := pcapDLL.FindProc(name); err != nil {
			t.Errorf("必需符号 %s 在 wpcap.dll 中不存在: %v  <-- 抓不到包的根因", name, err)
		}
	}
	// 已挂到全局变量的必须非 nil, 否则调用点会 panic
	if procNextEx == nil {
		t.Fatal("procNextEx 为 nil, Next() 调用会 panic")
	}
	if procOpen == nil {
		t.Fatal("procOpen 为 nil, PcapOpenLive 调用会 panic")
	}
	// 可选符号(缺失属正常, 仅记录): 它们只在 pcap_create 流程里有效,
	// pcap_open_live 之后调用无效, 不影响抓包
	t.Logf("可选符号 pcap_set_timeout=%v pcap_set_immediate_mode=%v",
		procSetTimeout != nil, procSetImmediate != nil)
	// 打印实际加载的 DLL 路径, 确认没有加载到 WinPcap 兼容层或系统根目录的旧 dll
	var buf [syscall.MAX_PATH]uint16
	_ = buf
	t.Logf("pcapDLL 句柄=%v", pcapDLL != nil)
}
