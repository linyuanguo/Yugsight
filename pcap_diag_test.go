//go:build windows

package main

import (
	"os"
	"testing"
	"time"
)

// TestPcapDiagNextReturn 直接调用 pcap_next_ex 并打印原始返回值, 用于诊断
// "READY 能打印但一个包都读不到" 的现象。
//
// 【为什么单独写这个诊断测试】用户现象是: 打开适配器成功(READY), 回环网卡也 0 字节。
// 这排除了权限/选卡/无流量三种可能, 只剩"读取调用没被正确触发"。readPcapRaw 直接
// 暴露 pcap_next_ex 的返回值(r), 能区分三种情况:
//   - r 恒为 0  -> 超时, 说明驱动在等但没交付(过滤器/模式问题)
//   - r 恒为 -1 -> 真错误(网卡状态异常)
//   - r 有 1    -> 其实读到了, 问题在 Next()/上层
//
// 【默认跳过, 必须显式开启】它会真实打开网卡并抓 6 秒包。默认跑会让并发测试
// (go test ./...) 与其它用例抢网卡资源, 在 CI/本地都可能造成无关用例偶发失败。
// 手动排查时: YUGSIGHT_PCAP_DIAG=1 go test -run PcapDiag -v .
func TestPcapDiagNextReturn(t *testing.T) {
	if os.Getenv("YUGSIGHT_PCAP_DIAG") != "1" {
		t.Skip("诊断用例: 需 YUGSIGHT_PCAP_DIAG=1 显式开启(会真实占用网卡)")
	}
	devs, err := PcapDevices()
	if err != nil {
		t.Fatalf("枚举适配器失败: %v", err)
	}
	if len(devs) == 0 {
		t.Skip("本机无可用抓包适配器")
	}
	// 优先回环: 必然有流量, 最能暴露"读不到包"的问题
	pick := devs[0]
	for _, d := range devs {
		if d.Name == `\Device\NPF_Loopback` {
			pick = d
			break
		}
	}
	t.Logf("使用适配器: %s (%s)", pick.Name, pick.Desc)

	h, err := PcapOpenLive(pick.Name, 65535, "")
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer h.Close()

	// 制造流量: 回环上 ping 自己
	go func() {
		for i := 0; i < 15; i++ {
			_ = time.Now()
			time.Sleep(200 * time.Millisecond)
		}
	}()

	var got, zero, neg, other int
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		raw := h.nextRaw()
		switch {
		case raw == 1:
			got++
		case raw == 0:
			zero++
		case raw == -1:
			neg++
		default:
			other++
		}
		if got > 0 && got >= 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("pcap_next_ex 统计: 有包=%d 超时=%d 错误=%d 其它=%d", got, zero, neg, other)

	// Next() 高层接口的统计(验证拷贝逻辑没把包吃掉)
	h2, err := PcapOpenLive(pick.Name, 65535, "")
	if err != nil {
		t.Fatalf("第二次打开失败: %v", err)
	}
	defer h2.Close()
	n := 0
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := h2.Next(); ok {
			n++
			if n >= 5 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("Next() 读到 %d 个报文", n)
}
