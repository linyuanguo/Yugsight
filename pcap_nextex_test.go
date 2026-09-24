//go:build windows

package main

import (
	"os"
	"testing"
	"time"
)

// TestPcapNextExFillsCapLen 验证 Next() 能从适配器读到**非空且长度合理**的报文。
//
// 【回归用例: 这个 bug 静默了整整一个功能】
// 曾经 Next() 把 pcap_next_ex 的第二个参数当成 `struct pcap_pkthdr *` 传, 而 libpcap
// 的原型是 `struct pcap_pkthdr **`(回写内部头部地址)。传错层级后:
//   - 返回值仍是 1(成功)、data 指针非空 —— 所有错误检查都通过;
//   - 但 CapLen/Len 读到的是垃圾(实测恒为 0), 于是每个包都被 `CapLen == 0` 当空包丢弃;
//   - 驱动侧统计"收到上万个包", 而 worker 写出的 stdout 是 0 字节。
// 表现在界面上就是"选对了适配器、显示正在抓包, 却一个包都没有", 层级完全看不出问题。
//
// 本用例断言"确实能取到非空报文", 一旦调用约定再被改错就会立即失败。
//
// 默认跳过(会真实占用网卡), 用 YUGSIGHT_PCAP_DIAG=1 开启。
func TestPcapNextExFillsCapLen(t *testing.T) {
	if os.Getenv("YUGSIGHT_PCAP_DIAG") != "1" {
		t.Skip("需 YUGSIGHT_PCAP_DIAG=1 显式开启(会真实占用网卡)")
	}
	devs, err := PcapDevices()
	if err != nil || len(devs) == 0 {
		t.Skip("本机无可用抓包适配器")
	}
	// 回环最稳: 不需要外部网络就能持续产生流量
	pick := devs[0]
	for _, d := range devs {
		if d.Name == `\Device\NPF_Loopback` {
			pick = d
			break
		}
	}
	h, err := PcapOpenLive(pick.Name, 65535, "")
	if err != nil {
		t.Fatalf("打开 %s 失败: %v", pick.Name, err)
	}
	defer h.Close()

	// 造回环流量, 保证有包可读
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if c, e := dialLoopbackUDP(); e == nil {
				_, _ = c.Write([]byte("yugsight-nextex-regression"))
				_ = c.Close()
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	defer close(stop)

	var ok int
	var maxCap uint32
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && ok < 5 {
		pkt, got := h.Next()
		if got && len(pkt) > 0 {
			ok++
			capLen, _, _ := h.LastHdr()
			if capLen > maxCap {
				maxCap = capLen
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	recv, to, negerr := h.ReadStats()
	t.Logf("链路类型=%d 收到=%d 超时=%d 错误=%d; 取到非空报文=%d 个, 最大 caplen=%d",
		h.LinkType(), recv, to, negerr, ok, maxCap)

	if ok == 0 {
		t.Fatalf("Next() 一个非空报文都没取到(收到=%d 超时=%d) —— "+
			"若'收到'很大却全是空包, 说明 pcap_next_ex 的头部指针层级又传错了"+
			"(必须传 **pcapPkthdr, 不是 *pcapPkthdr)", recv, to)
	}
	// 长度合理性: 以太网帧最小 60 字节(不含 FCS), 抓到的包不该小到离谱
	if maxCap < 14 {
		t.Errorf("最大 caplen 仅 %d 字节, 小于以太网头长度, 头部解析可能仍有偏移", maxCap)
	}
}
