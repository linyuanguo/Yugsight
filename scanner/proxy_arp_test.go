package scanner

// buildMACWarnings / dropVirtualARP 单测: "同 MAC 聚集 -> 疑似代理 ARP 代答"。
//
// 背景: 真实用户场景(2026-09-20)—— 192.168.1.224~239 共 16 个并不存在的 IP
// 全部被扫成"存活", 且 MAC 全是同一个虚拟 MAC 01:00:5E:01:A8:C0(网关对整段
// 代理 ARP 代答)。用户明确要求: 这类虚拟 MAC 的 ARP 应答是假的, 不算存活也不
// 展示 —— 故虚拟 MAC 证据在探测阶段直接失效(dropVirtualARP), 提示只留给真实
// MAC 的同 MAC 聚集(一行, 不再长篇解释)。

import (
	"fmt"
	"testing"
)

func TestMACWarningsVirtualMACGroup(t *testing.T) {
	// 16 台共用一个虚拟 MAC(01:00:5E 保留段, 代理 ARP 代答) -> 不提示:
	// 这类"存活"是假阳性, 探测阶段已失效其证据(见 TestDropVirtualARP), 无需再解释
	macs := map[string]string{}
	for i := 224; i <= 239; i++ {
		macs[fmt.Sprintf("192.168.1.%d", i)] = "01:00:5E:01:A8:C0"
	}
	if out := buildMACWarnings(macs); len(out) != 0 {
		t.Fatalf("虚拟 MAC(代理 ARP)组不应产生提示, 实际 %d 条: %v", len(out), out)
	}
}

// TestDropVirtualARP 守住"虚拟 MAC 的 ARP 应答不算存活证据"契约:
// 若有人把失效逻辑删掉, 代理 ARP 代答的整段假主机会再次被计入存活(静默回退)。
func TestDropVirtualARP(t *testing.T) {
	if arp, mac := dropVirtualARP(true, "01:00:5E:01:A8:C0"); arp || mac != "" {
		t.Errorf("虚拟 MAC 应失效, 实际 arp=%v mac=%q", arp, mac)
	}
	if arp, mac := dropVirtualARP(true, "AA:BB:CC:DD:EE:FF"); !arp || mac != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("真实 MAC 应原样保留, 实际 arp=%v mac=%q", arp, mac)
	}
	if arp, mac := dropVirtualARP(false, "01:00:5E:01:A8:C0"); arp || mac != "01:00:5E:01:A8:C0" {
		t.Errorf("无 ARP 应答时应原样返回, 实际 arp=%v mac=%q", arp, mac)
	}
}

func TestMACWarningsRealMACGroup(t *testing.T) {
	// 两台共用普通 MAC -> 提示, 但两种可能(单台多 IP / 代答)都要讲, 不能武断
	macs := map[string]string{
		"192.168.1.100": "AA:BB:CC:DD:EE:FF",
		"192.168.1.101": "AA:BB:CC:DD:EE:FF",
		"192.168.1.102": "11:22:33:44:55:66", // 唯一 MAC, 不应触发
	}
	out := buildMACWarnings(macs)
	if len(out) != 1 {
		t.Fatalf("应产生 1 条提示(唯一 MAC 不触发), 实际 %d 条: %v", len(out), out)
	}
	msg := out[0]
	for _, want := range []string{"AA:BB:CC:DD:EE:FF", "单台多 IP", "代理 ARP"} {
		if !contains(msg, want) {
			t.Fatalf("提示缺少关键信息 %q: %s", want, msg)
		}
	}
}

func TestMACWarningsNoGroup(t *testing.T) {
	// 每台 MAC 都唯一 -> 无提示(正常网络, 不能刷屏)
	macs := map[string]string{
		"192.168.1.10": "AA:00:00:00:00:01",
		"192.168.1.11": "AA:00:00:00:00:02",
		"192.168.1.12": "AA:00:00:00:00:03",
	}
	if out := buildMACWarnings(macs); len(out) != 0 {
		t.Fatalf("每台 MAC 唯一时不应有提示: %v", out)
	}
	// 少于 2 台也永远不提示
	if out := buildMACWarnings(map[string]string{"192.168.1.10": "AA:00:00:00:00:01"}); len(out) != 0 {
		t.Fatalf("单台不应有提示: %v", out)
	}
	if out := buildMACWarnings(nil); len(out) != 0 {
		t.Fatalf("空输入不应有提示: %v", out)
	}
}

func TestMACWarningsMultipleGroups(t *testing.T) {
	// 虚拟 MAC 组 + 真实 MAC 组 -> 只有真实组产生 1 条提示;
	// 唯一 MAC 主机不触发; 顺序稳定(map 遍历顺序不能泄漏到输出)
	macs := map[string]string{
		"10.0.0.2": "01:00:5E:00:00:0A",
		"10.0.0.3": "01:00:5E:00:00:0A",
		"10.0.0.4": "AA:BB:CC:00:00:01",
		"10.0.0.5": "AA:BB:CC:00:00:01",
		"10.0.0.6": "AA:BB:CC:00:00:02",
	}
	out := buildMACWarnings(macs)
	if len(out) != 1 {
		t.Fatalf("应只有真实 MAC 组 1 条提示, 实际 %d 条: %v", len(out), out)
	}
	if !contains(out[0], "AA:BB:CC:00:00:01") {
		t.Fatalf("提示应指向真实 MAC 组: %s", out[0])
	}
	out2 := buildMACWarnings(macs)
	for i := range out {
		if out[i] != out2[i] {
			t.Fatalf("输出不稳定:\n%v\nvs\n%v", out, out2)
		}
	}
}

// contains 小写不敏感的包含判定(提示文案里的引号是直引号, 避免大小写/引号差异导致误判)。
func contains(s, sub string) bool {
	return len(sub) > 0 && indexOfCI(s, sub) >= 0
}

func indexOfCI(s, sub string) int {
	if len(sub) > len(s) {
		return -1
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
