// scan_any.go 存活扫描"全扫(any)"目标展开(2026-09-27)。
//
// 语义: 目标填 "any"(大小写不敏感)时无需预先指定网段 —— 执行节点自动枚举
// 自己网卡的所有网段(前缀钳制在 [16,24]), 对这些网段内全部主机做存活探测:
//   - 本地执行: 枚举中心端网卡(本文件);
//   - 探针执行: 枚举探针网卡(internal/probe/scanner/any.go, 同一口径);
//   - 前端入口: 控制台"快速发现"的「全扫」按钮(Console.vue), 点按钮即写入
//     target=any 并自动勾选"仅存活检查"后启动(全扫=存活探测, 不枚举端口)。
//
// 口径: 每段 /24(或实际前缀, 最小 /16, 最大 /24) ——
//   - 小于 /16(如 /8、/12)放大到 /16, 防误把整个大网段全扫掉;
//   - 大于 /24(如 /32 单主机地址)收窄到 /24, 按"在某个 /24 网段上"处理。
// 每段单独走 scanner.ParseHosts(每段 ≤256 台), 天然满足其 4096 单次安全上限;
// 多网卡重叠网段按主机去重。
package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"yugsight/internal/scanner"
)

// IsAnyAliveTarget 判断是否为"全扫"目标(target=any, 大小写不敏感)。
func IsAnyAliveTarget(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "any")
}

// aliveAnyPrefix 全扫网段前缀钳制: <16 放大到 16(防误扫 /8、/12),
// >24 收窄到 24(/32 单主机地址按所在 /24 处理)。
func aliveAnyPrefix(ones int) int {
	switch {
	case ones < 16:
		return 16
	case ones > 24:
		return 24
	}
	return ones
}

// AnyAliveCIDRs 枚举本机全部非回环 IPv4 网卡, 返回各网卡所在网段 CIDR
// (前缀经 aliveAnyPrefix 钳制, 去重)。无可用网卡时返回空切片。
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
			cidr := ipn.IP.To4().Mask(net.CIDRMask(aliveAnyPrefix(ones), bits)).String() + "/" + strconv.Itoa(aliveAnyPrefix(ones))
			if !seen[cidr] {
				seen[cidr] = true
				out = append(out, cidr)
			}
		}
	}
	return out
}

// splitInto24 把一段 CIDR 拆成若干 /24 子段。
//
// 为什么要拆: scanner.ParseHosts 有 4096 台/次 的安全上限, /16(65536)直接
// 展开会被拒; /24 子段每段 ≤254 台天然在上限内, 拆完逐段展开即可。
// /24 及以上(/24、/32)原样返回(不拆)。
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
	n := uint32(1) << uint(24-ones) // 该段包含的 /24 个数
	out := make([]string, 0, n)
	for i := uint32(0); i < n; i++ {
		v := base + i*0x100
		out = append(out, fmt.Sprintf("%d.%d.%d.0/24", v>>24, (v>>16)&0xff, (v>>8)&0xff))
	}
	return out
}

// ExpandAnyAliveHosts 把"全扫"展开为具体主机列表:
// 每段先拆 /24 子段再逐段 ParseHosts, 跨段去重。返回 (主机列表, 实际网段, 错误);
// 未检测到任何本地网段时 err 非空(调用方必须如实报错, 不能静默空扫)。
func ExpandAnyAliveHosts() ([]string, []string, error) {
	cidrs := AnyAliveCIDRs()
	if len(cidrs) == 0 {
		return nil, nil, fmt.Errorf("未检测到本地网段(网卡均为回环或无 IPv4 地址), 无法执行全扫")
	}
	seen := map[string]bool{}
	var hosts []string
	for _, c := range cidrs {
		for _, sub := range splitInto24(c) {
			hs, err := scanner.ParseHosts(sub)
			if err != nil {
				continue // 单段展开失败不中断整体(降级语义, 与其它段独立)
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
		return nil, cidrs, fmt.Errorf("全扫网段展开为空")
	}
	return hosts, cidrs, nil
}
