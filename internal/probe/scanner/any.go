// any.go 探针端"全扫(any)"目标展开(2026-09-27)。
//
// 中心端下发存活任务 target="any" 时, 探针自动枚举自己网卡的全部网段
// (与中心端 app/scan_any.go 同一口径: 前缀钳制在 [16,24]), 对这些网段内
// 全部主机做存活探测 —— 即"探测探针所在网络环境下的所有存活主机",
// 无需预先指定目标网段。
//
// 为什么探针端自己实现而不复用中心端函数: 探针只依赖 probe + scanner +
// normalizer + 标准库(见 scan.go 头部依赖边界), 不能引 main 包。口径必须
// 与中心端保持一致(前缀钳制规则), 改动任一端时两端同步。
package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IsAnyTarget 判断是否为"全扫"目标(target=any, 大小写不敏感)。
func IsAnyTarget(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "any")
}

// anyAlivePrefix 全扫网段前缀钳制: <16 放大到 16(防误扫 /8、/12),
// >24 收窄到 24(/32 单主机地址按所在 /24 处理)。与中心端同口径。
func anyAlivePrefix(ones int) int {
	switch {
	case ones < 16:
		return 16
	case ones > 24:
		return 24
	}
	return ones
}

// AnyAliveCIDRs 枚举本机全部非回环 IPv4 网卡, 返回各网卡所在网段 CIDR(去重)。
func AnyAliveCIDRs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLoopback() {
				continue
			}
			ones, bits := ipn.Mask.Size()
			p := anyAlivePrefix(ones)
			cidr := ipn.IP.To4().Mask(net.CIDRMask(p, bits)).String() + "/" + strconv.Itoa(p)
			if !seen[cidr] {
				seen[cidr] = true
				out = append(out, cidr)
			}
		}
	}
	return out
}

// splitInto24 把一段 CIDR 拆成若干 /24 子段(与中心端 app/scan_any.go 同口径):
// ExpandTargets 有 4096 台/次上限, /16 直接展开会被拒, /24 子段每段 ≤254 台。
func splitInto24(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return []string{cidr}
	}
	ones, _ := ipnet.Mask.Size()
	if ones >= 24 {
		return []string{cidr}
	}
	ip4 := ipnet.IP.To4()
	base := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	n := uint32(1) << uint(24-ones)
	out := make([]string, 0, n)
	for i := uint32(0); i < n; i++ {
		v := base + i*0x100
		out = append(out, fmt.Sprintf("%d.%d.%d.0/24", v>>24, (v>>16)&0xff, (v>>8)&0xff))
	}
	return out
}

// ExpandAnyAliveHosts 把"全扫"展开为主机列表(拆 /24 逐段 ExpandTargets + 去重)。
// 未检测到本地网段时返回错误 —— 必须明确失败, 不能让中心端把"能力缺失"
// 误读成"无存活主机"(与 arp/trivy 的失败口径一致)。
func ExpandAnyAliveHosts() ([]string, error) {
	cidrs := AnyAliveCIDRs()
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("未检测到本地网段(网卡均为回环或无 IPv4 地址), 无法执行全扫")
	}
	seen := map[string]bool{}
	var hosts []string
	for _, c := range cidrs {
		for _, sub := range splitInto24(c) {
			hs, err := ExpandTargets(sub)
			if err != nil {
				continue // 单段展开失败不中断整体
			}
			for _, h := range hs {
				if !seen[h] {
					seen[h] = true
					hosts = append(hosts, h)
				}
			}
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("全扫网段展开为空")
	}
	return hosts, nil
}
