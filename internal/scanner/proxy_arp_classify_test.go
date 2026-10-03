// proxy_arp_classify_test.go ClassifyArpGhosts 单测: 守"代答幽灵判定"的核心契约。
//
// 重点守两类误伤(都会造成真实资产被误删):
//   - 单台多 IP 主机 / 负载均衡 VIP(同 MAC 但每个 IP 都回 ICMP/有端口)必须全保留;
//   - 全组无真身证据时必须一个都不删(Unresolved), 只提示。
package scanner

import (
	"sort"
	"strconv"
	"strings"
	"testing"
)

func ev(entries ...[3]string) map[string]ArpEvidence {
	// 便捷构造: [ip, mac, "icmp=1,ports=80,443" | "icmp=1" | "ports=22" | ""]
	out := make(map[string]ArpEvidence, len(entries))
	for _, e := range entries {
		a := ArpEvidence{MAC: e[1]}
		// 字段用空格分 token("icmp=1" / "ports=80,443"), token 内端口才按逗号分
		for _, tok := range strings.Fields(e[2]) {
			switch {
			case tok == "icmp=1":
				a.ICMP = true
			case strings.HasPrefix(tok, "ports="):
				for _, p := range strings.Split(tok[len("ports="):], ",") {
					if n, err := strconv.Atoi(p); err == nil && n > 0 {
						a.Ports = append(a.Ports, n)
					}
				}
			}
		}
		out[e[0]] = a
	}
	return out
}

func TestClassifyWholeSubnetProxy(t *testing.T) {
	// 整段代答的典型形态: 1 个真身(有端口) + 5 个仅 ARP 幽灵, 同 MAC
	rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.1", "aa:bb:cc:dd:ee:01", "ports=80"},
		[3]string{"10.1.0.2", "aa:bb:cc:dd:ee:01", ""},
		[3]string{"10.1.0.3", "aa:bb:cc:dd:ee:01", ""},
		[3]string{"10.1.0.4", "aa:bb:cc:dd:ee:01", ""},
		[3]string{"10.1.0.5", "aa:bb:cc:dd:ee:01", ""},
		[3]string{"10.1.0.6", "aa:bb:cc:dd:ee:01", ""},
	))
	if rep == nil || len(rep.Groups) != 1 {
		t.Fatalf("应有 1 个组, got %+v", rep)
	}
	g := rep.Groups[0]
	if len(g.Real) != 1 || g.Real[0] != "10.1.0.1" {
		t.Fatalf("真身应只有 10.1.0.1: %+v", g)
	}
	if len(g.Ghosts) != 5 || len(rep.Ghosts) != 5 {
		t.Fatalf("幽灵应 5 个: %+v", rep)
	}
}

func TestClassifyMultiIPHostKept(t *testing.T) {
	// 单台多 IP 主机: 同 MAC, 每个 IP 都回 ICMP → 无幽灵, 组仍在(供展示)
	rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.1", "aa:bb:cc:dd:ee:01", "icmp=1"},
		[3]string{"10.1.0.2", "aa:bb:cc:dd:ee:01", "icmp=1"},
	))
	if rep == nil || len(rep.Groups) != 1 {
		t.Fatalf("应有 1 个组, got %+v", rep)
	}
	if len(rep.Ghosts) != 0 {
		t.Fatalf("多 IP 主机不应有幽灵: %+v", rep)
	}
	if len(rep.Groups[0].Real) != 2 {
		t.Fatalf("两个 IP 都应是真身: %+v", rep.Groups[0])
	}
}

func TestClassifyVIPKept(t *testing.T) {
	// 负载均衡 VIP 池: 同 MAC, 每个 VIP 都有开放端口 → 全保留(VIP 是真实服务入口)
	rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.10", "aa:bb:cc:dd:ee:02", "ports=443"},
		[3]string{"10.1.0.11", "aa:bb:cc:dd:ee:02", "ports=80"},
	))
	if rep == nil || len(rep.Ghosts) != 0 {
		t.Fatalf("VIP 不应判幽灵: %+v", rep)
	}
}

func TestClassifyNoRealUnresolved(t *testing.T) {
	// 全组无证据(真身 IP 在段外 / 禁 ping): 一个都不删, Unresolved 提示
	rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.1", "aa:bb:cc:dd:ee:03", ""},
		[3]string{"10.1.0.2", "aa:bb:cc:dd:ee:03", ""},
		[3]string{"10.1.0.3", "aa:bb:cc:dd:ee:03", ""},
	))
	if rep == nil || len(rep.Groups) != 1 {
		t.Fatalf("应有 1 个组, got %+v", rep)
	}
	if !rep.Groups[0].Unresolved {
		t.Fatalf("无真身证据应标 Unresolved: %+v", rep.Groups[0])
	}
	if len(rep.Ghosts) != 0 {
		t.Fatalf("无真身证据时绝不能删: %+v", rep)
	}
}

func TestClassifyVirtualMACSkipped(t *testing.T) {
	// 虚拟 MAC(01:00:5E, VRRP 类)组: 证据在探测阶段已失效, 不参与分组
	rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.1", "01:00:5e:01:a8:c0", ""},
		[3]string{"10.1.0.2", "01:00:5e:01:a8:c0", ""},
	))
	if rep != nil {
		t.Fatalf("虚拟 MAC 组应被跳过, got %+v", rep)
	}
}

func TestClassifyMixedGroups(t *testing.T) {
	// 混合场景: 代答组 + 多 IP 主机组 + 无关单台, 各归各的
	rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.1", "aa:bb:cc:dd:ee:01", "icmp=1"}, // 代答真身
		[3]string{"10.1.0.2", "aa:bb:cc:dd:ee:01", ""},       // 幽灵
		[3]string{"10.2.0.1", "cc:dd:ee:ff:00:01", "icmp=1"}, // 多 IP 主机 A
		[3]string{"10.2.0.2", "cc:dd:ee:ff:00:01", "ports=22"},
		[3]string{"10.3.0.1", "11:22:33:44:55:01", "icmp=1"}, // 无关单台(不成组)
	))
	if rep == nil || len(rep.Groups) != 2 {
		t.Fatalf("应有 2 个组, got %+v", rep)
	}
	if len(rep.Ghosts) != 1 || rep.Ghosts[0] != "10.1.0.2" {
		t.Fatalf("幽灵应只有 10.1.0.2: %+v", rep)
	}
}

func TestClassifyMACCaseInsensitive(t *testing.T) {
	// MAC 大小写不一致(不同来源)必须归入同一组
	rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.1", "AA:BB:CC:DD:EE:01", "ports=80"},
		[3]string{"10.1.0.2", "aa:bb:cc:dd:ee:01", ""},
	))
	if rep == nil || len(rep.Ghosts) != 1 {
		t.Fatalf("大小写不一致的 MAC 应同组, got %+v", rep)
	}
}

func TestClassifyNoGroup(t *testing.T) {
	// 无聚集(每台 MAC 唯一) / 数据不足 → nil
	if rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.1", "aa:bb:cc:dd:ee:01", "icmp=1"},
		[3]string{"10.1.0.2", "aa:bb:cc:dd:ee:02", "icmp=1"},
	)); rep != nil {
		t.Fatalf("MAC 唯一不应成组: %+v", rep)
	}
	if rep := ClassifyArpGhosts(nil); rep != nil {
		t.Fatalf("空输入应 nil: %+v", rep)
	}
	if rep := ClassifyArpGhosts(map[string]ArpEvidence{"10.1.0.1": {MAC: "aa:bb:cc:dd:ee:01"},}); rep != nil {
		t.Fatalf("单台不成组: %+v", rep)
	}
	// 无 MAC 的成员不参与分组
	if rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.1", "", "icmp=1"},
		[3]string{"10.1.0.2", "", "icmp=1"},
	)); rep != nil {
		t.Fatalf("无 MAC 不参与分组: %+v", rep)
	}
}

func TestClassifyGhostsSorted(t *testing.T) {
	// 输出稳定(排序): 日志/前端展示不随 map 遍历顺序漂移
	rep := ClassifyArpGhosts(ev(
		[3]string{"10.1.0.9", "aa:bb:cc:dd:ee:01", "icmp=1"},
		[3]string{"10.1.0.3", "aa:bb:cc:dd:ee:01", ""},
		[3]string{"10.1.0.5", "aa:bb:cc:dd:ee:01", ""},
		[3]string{"10.1.0.1", "aa:bb:cc:dd:ee:01", ""},
	))
	if rep == nil || len(rep.Ghosts) != 3 {
		t.Fatalf("应 3 幽灵, got %+v", rep)
	}
	if !sort.StringsAreSorted(rep.Ghosts) {
		t.Fatalf("幽灵列表应排序: %v", rep.Ghosts)
	}
}
