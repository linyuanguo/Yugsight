// proxy_arp_classify.go 代理 ARP 幽灵资产识别(2026-09-26)。
//
// 背景: 网段里存在对整段代答 ARP 的设备(网关/防火墙 proxy-arp/邮件网关静态 IP 池),
// 被代答的 IP 会"ARP 确认存活"并进资产表, 造成资产清单里大量不存在的 IP。
//
// 识别特征: 同一(真实) MAC 应答了多个 IP 的 ARP —— 代答设备对所有幽灵 IP 回的都是
// 自己那张网卡的 MAC。区分"单台多 IP 主机"(真实)与"代答幽灵"靠组内证据: 真身 IP
// 会回 ICMP / 有开放端口, 幽灵 IP 只有 ARP 应答。
//
// 本文件是纯逻辑(不碰网络/不落盘), 供三个落点共用:
//   - 本地扫描落库前剔除(app/scan_persist.go);
//   - 探针结果落库前剔除(app/probe_normalize.go);
//   - 存量资产一次性清理(app/arp_ghost.go)。
package scanner

import (
	"sort"
	"strings"
)

// ArpEvidence 单台主机本轮的 ARP 相关证据(代答分组判定用)。
//
// 为什么三者齐备: 只有 MAC 无法区分多 IP 主机与代答; ICMP/端口是"这台机器真的在"
// 的独立证据(代答设备只对别人的 IP 代答 ARP, 不会替别人回 ICMP/开端口)。
type ArpEvidence struct {
	MAC   string // ARP 应答的 MAC(空 = 本轮无 ARP 应答)
	ICMP  bool   // 是否收到 ICMP 应答
	Ports []int  // 开放端口(非空即算证据)
}

// ArpGroup 一个"同 MAC 聚集"组的判定结果。
type ArpGroup struct {
	MAC        string   `json:"mac"`
	IPs        []string `json:"ips"`    // 全部成员(排序)
	Real       []string `json:"real"`   // 带证据成员(真身候选, 排序)
	Ghosts     []string `json:"ghosts"` // 仅 ARP 成员(幽灵, 排序)
	Unresolved bool     `json:"unresolved"` // 无带证据成员: 无法定位真身, 不删只提示
}

// ArpGhostReport 一次分组判定的汇总。
type ArpGhostReport struct {
	Groups []ArpGroup `json:"groups"` // 全部 ≥2 台的同 MAC 组(含无幽灵的, 供展示/复核)
	Ghosts []string   `json:"ghosts"` // 应删幽灵全集(排序)
}

// ClassifyArpGhosts 按 MAC 分组识别代理 ARP 幽灵(纯函数, 不碰网络, 可单测)。
//
// 规则:
//  1. 只收"有 ARP 证据"(MAC 非空)的主机进组; 无 MAC 的不参与(无应答, 或虚拟 MAC
//     证据已在探测阶段失效, 见 dropVirtualARP);
//  2. 同 MAC ≥2 台构成组(单台多 IP 主机与代答在此分流, 由组内证据判定);
//  3. 组内成员有 ICMP 或开放端口 = 真身候选, 保留;
//  4. 仅 ARP 的成员 = 幽灵, 进 Ghosts;
//  5. 全组无带证据成员 → Unresolved=true 且不产生幽灵(宁可漏删不可误删:
//     真身 IP 可能在段外或禁 ping, 此时"删掉无证据成员"等于把真身连同幽灵一起删);
//  6. 虚拟 MAC(01:00:5E)组跳过: 那类应答在探测阶段已按"目标主机不存在"处理,
//     不再参与分组(正常流不会带着 MAC 进这里, 此处是兜底)。
//
// 返回 nil = 无任何 ≥2 台的同 MAC 组(无代答嫌疑)。
func ClassifyArpGhosts(ev map[string]ArpEvidence) *ArpGhostReport {
	if len(ev) < 2 {
		return nil
	}
	groups := map[string][]string{}
	for ip, e := range ev {
		mac := normMAC(e.MAC)
		if mac == "" {
			continue
		}
		groups[mac] = append(groups[mac], ip)
	}
	rep := &ArpGhostReport{}
	for mac, ips := range groups {
		if len(ips) < 2 || isVirtualMAC(mac) {
			continue
		}
		sort.Strings(ips)
		g := ArpGroup{MAC: mac, IPs: ips}
		for _, ip := range ips {
			e := ev[ip]
			if e.ICMP || len(e.Ports) > 0 {
				g.Real = append(g.Real, ip)
			} else {
				g.Ghosts = append(g.Ghosts, ip)
			}
		}
		if len(g.Real) == 0 {
			// 无真身参照: 不删(安全口径, 见函数注释 5)
			g.Unresolved = true
			g.Ghosts = nil
		}
		rep.Groups = append(rep.Groups, g)
		rep.Ghosts = append(rep.Ghosts, g.Ghosts...)
	}
	if len(rep.Groups) == 0 {
		return nil
	}
	sort.Strings(rep.Ghosts)
	sort.Slice(rep.Groups, func(i, j int) bool { return rep.Groups[i].MAC < rep.Groups[j].MAC })
	return rep
}

// normMAC MAC 归一化(小写+去空白): 不同来源的 MAC 大小写可能不一致,
// 不归一化会把同一台设备拆成两个"组", 聚集特征直接丢失。
func normMAC(mac string) string {
	return strings.ToLower(strings.TrimSpace(mac))
}
