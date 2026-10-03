// scan_any_test.go 存活扫描"全扫(any)"目标展开的契约测试(2026-09-27)。
//
// 守的是"会静默失效"的契约, 不复述实现:
//   - IsAnyAliveTarget: 前端"全扫"按钮写入 target=any, 后端必须识别(大小写/
//     空白容忍) —— 不识别则全扫静默退化成 ParseHosts 报错, 用户看不到原因;
//   - aliveAnyPrefix: 前缀钳制规则(防误扫 /8 大网段、/32 单主机地址按 /24 处理)
//     —— 规则漂移会让全扫范围失控或整段落空;
//   - splitInto24: 必须拆出正确的 /24 子段(数量与首尾) —— 拆错会让
//     ParseHosts 的 4096 上限拦截 /16 网段(全扫静默变空)。
package main

import (
	"net"
	"strings"
	"testing"
)

func TestIsAnyAliveTarget(t *testing.T) {
	for _, s := range []string{"any", "ANY", " Any ", "aNy"} {
		if !IsAnyAliveTarget(s) {
			t.Errorf("IsAnyAliveTarget(%q) 应为 true", s)
		}
	}
	for _, s := range []string{"", "anyx", "192.168.1.0/24", "anyway", "any,10.0.0.1"} {
		if IsAnyAliveTarget(s) {
			t.Errorf("IsAnyAliveTarget(%q) 应为 false", s)
		}
	}
}

func TestAliveAnyPrefixClamp(t *testing.T) {
	cases := map[int]int{
		8: 16,  // /8 大网段 → 放大到 /16(防误扫)
		12: 16,
		16: 16,
		20: 20,
		24: 24,
		28: 24, // /28 小段 → 按所在 /24 处理
		32: 24, // /32 单主机地址 → 按所在 /24 处理
	}
	for in, want := range cases {
		if got := aliveAnyPrefix(in); got != want {
			t.Errorf("aliveAnyPrefix(%d) = %d, 期望 %d", in, got, want)
		}
	}
}

func TestSplitInto24(t *testing.T) {
	// /24 原样返回(不拆)
	if got := splitInto24("192.168.1.0/24"); len(got) != 1 || got[0] != "192.168.1.0/24" {
		t.Fatalf("splitInto24(/24) 应原样返回, 实际 %v", got)
	}
	// /32 单主机地址原样返回
	if got := splitInto24("192.168.1.100/32"); len(got) != 1 || got[0] != "192.168.1.100/32" {
		t.Fatalf("splitInto24(/32) 应原样返回, 实际 %v", got)
	}
	// /23 = 2 个 /24(用对齐的网络地址: 192.168.0.0/23 覆盖 .0.0~.1.255)
	got := splitInto24("192.168.0.0/23")
	if len(got) != 2 || got[0] != "192.168.0.0/24" || got[1] != "192.168.1.0/24" {
		t.Fatalf("splitInto24(/23) 错误: %v", got)
	}
	// /16 = 256 个 /24, 首尾必须对
	got = splitInto24("172.16.0.0/16")
	if len(got) != 256 {
		t.Fatalf("splitInto24(/16) 应拆 256 段, 实际 %d", len(got))
	}
	if got[0] != "172.16.0.0/24" || got[255] != "172.16.255.0/24" {
		t.Fatalf("splitInto24(/16) 首尾错误: %s ... %s", got[0], got[255])
	}
	// 非整段地址(掩码已对齐到网络地址): 172.16.5.77/16 的网络地址是 172.16.0.0
	got = splitInto24("172.16.5.77/16")
	if got[0] != "172.16.0.0/24" {
		t.Fatalf("splitInto24 未按掩码对齐网络地址: %s", got[0])
	}
	// 非法输入不崩, 原样返回
	got = splitInto24("not-a-cidr")
	if len(got) != 1 || got[0] != "not-a-cidr" {
		t.Fatalf("非法输入应原样返回: %v", got)
	}
}

func TestExpandAnyAliveHostsHasHosts(t *testing.T) {
	// 本机(测试机)至少有一个非回环 IPv4 网卡时才断言展开非空;
	// 纯回环环境(容器)下断言明确报错 —— 两种结果都是"如实", 静默空才是缺陷。
	// 断言刻意不依赖具体网段规模(测试机可能是 /24 也可能是 /16):
	// 守"主机无重复 + 每台主机必属于返回的某个网段"两个不变量。
	hosts, cidrs, err := ExpandAnyAliveHosts()
	if err != nil {
		if !strings.Contains(err.Error(), "未检测到本地网段") {
			t.Fatalf("展开错误口径异常: %v", err)
		}
		return
	}
	if len(hosts) == 0 || len(cidrs) == 0 {
		t.Fatalf("有本地网段时展开结果不应为空: hosts=%d cidrs=%v", len(hosts), cidrs)
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipn, e := net.ParseCIDR(c)
		if e != nil {
			t.Fatalf("返回了非法网段: %s", c)
		}
		nets = append(nets, ipn)
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if seen[h] {
			t.Fatalf("主机重复: %s", h)
		}
		seen[h] = true
		ip := net.ParseIP(h)
		if ip == nil || ip.To4() == nil {
			t.Fatalf("非法主机: %s", h)
		}
		inAny := false
		for _, ipn := range nets {
			if ipn.Contains(ip) {
				inAny = true
				break
			}
		}
		if !inAny {
			t.Fatalf("主机 %s 不属于返回的任何网段 %v", h, cidrs)
		}
	}
}
