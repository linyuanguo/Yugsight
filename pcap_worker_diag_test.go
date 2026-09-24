//go:build windows

package main

import (
	"net"
	"os"
	"testing"
	"time"
)

// dialLoopbackUDP 向本机回环发一个 UDP 包, 用于在回环网卡上稳定制造可见流量。
// 用 UDP 而非 ICMP(ping): 部分环境下 Npcap 对回环 ICMP 不作捕获, 会让诊断得出
// "读不到包"的错误结论。
func dialLoopbackUDP() (net.Conn, error) {
	return net.Dial("udp", "127.0.0.1:9")
}

// TestPcapWorkerPathDiag 模拟 worker 的调用路径(单次 OpenLive + 循环 Next),
// 与 TestPcapDiagNextReturn 的区别是: 不预先打开另一个 handle。
//
// 【为什么要单独测这条路径】TestPcapDiagNextReturn 里先 OpenLive 一次做 nextRaw 统计,
// 再 OpenLive 第二次测 Next() —— 两次打开。worker 只打开一次。若"第一次可用、第二次
// 才有数据"这种诡异时序存在, 前者会掩盖后者。这里严格复刻 worker: 一次打开, 直接循环。
// 【默认跳过, 必须显式开启】与 TestPcapDiagNextReturn 同理: 会真实占用网卡,
// 默认跑会与并发测试抢资源。手动排查: YUGSIGHT_PCAP_DIAG=1 go test -run WorkerPathDiag -v .
func TestPcapWorkerPathDiag(t *testing.T) {
	if os.Getenv("YUGSIGHT_PCAP_DIAG") != "1" {
		t.Skip("诊断用例: 需 YUGSIGHT_PCAP_DIAG=1 显式开启(会真实占用网卡)")
	}
	devs, err := PcapDevices()
	if err != nil || len(devs) == 0 {
		t.Skip("无可用适配器")
	}
	pick := devs[0]
	for _, d := range devs {
		if d.Name == `\Device\NPF_Loopback` {
			pick = d
			break
		}
	}
	t.Logf("适配器: %s", pick.Name)

	// 无过滤器 —— 完全等价于 worker 收到 filter="" 的情形
	h, err := PcapOpenLive(pick.Name, 65535, "")
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer h.Close()

	stop := make(chan struct{})
	go func() {
		tk := time.NewTicker(100 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				// 回环流量: UDP 自发自收, 比 ping 更稳(ICMP 可能在回环上不被 Npcap 捕获)
				c, err := dialLoopbackUDP()
				if err == nil {
					_, _ = c.Write([]byte("yugsight-diag"))
					_ = c.Close()
				}
			}
		}
	}()

	var got, raw0, rawNeg, other int
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && got < 5 {
		switch r := h.nextRaw(); {
		case r == 1:
			got++
		case r == 0:
			raw0++
		case r == -1:
			rawNeg++
		default:
			other++
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	t.Logf("原始统计: 有包=%d 超时=%d 错误=%d 其它=%d", got, raw0, rawNeg, other)

	// 再测带 arp or ip 过滤器(与 worker 默认一致)
	h2, err := PcapOpenLive(pick.Name, 65535, "arp or ip")
	if err != nil {
		t.Logf("带过滤器打开失败(符合预期, 回环无 ARP): %v", err)
		return
	}
	defer h2.Close()
	got2 := 0
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && got2 < 3 {
		if h2.nextRaw() == 1 {
			got2++
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("带 'arp or ip' 过滤器读到 %d 个报文", got2)
}
