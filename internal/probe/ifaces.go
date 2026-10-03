// ifaces.go 网卡端口采样(2026-10-02 用户要求: "探针 / SSH / WinRM 主机也要能看
// 有几个网卡端口, 并能基于端口查看速率")。
//
// 与 MetricsSample(整机汇总速率)的区别: 这里是**按网卡**的明细, 拓扑端口详情表
// 与"链路绑定端口"都用它。速率口径与整机一致 —— 累计字节两拍差分 ÷ 窗口(字节/秒)。
//
// 首拍只有基线没有差值: 速率出 0 但**清单照出**(用户要的是"有几个口", 不该为
// 了等第二轮差分而先显示空白); 平台拿不到的数据(如 Windows 的端口状态)留空,
// 由 UI 显示 '-' —— 不猜、不编造。
package probe

import (
	"strings"
	"time"
)

// IfaceSample 单个网卡端口的采样。
type IfaceSample struct {
	Name   string  `json:"name"`
	MAC    string  `json:"mac,omitempty"`
	IP     string  `json:"ip,omitempty"`
	State  string  `json:"state,omitempty"` // up / down; 空 = 本平台未提供状态(UI 显示 '-')
	InBps  float64 `json:"inBps"`           // 下行(接收)字节/秒
	OutBps float64 `json:"outBps"`          // 上行(发送)字节/秒
	// Speed 端口带宽(bps); 0 = 未知(Linux 读 /sys/class/net/<if>/speed, Windows
	// PDH 不给带宽)。有带宽才能算利用率, 没有就显示 '-' 而不是按 1G 假算。
	Speed int64 `json:"speed,omitempty"`
}

// SampleIfaces 采样网卡端口明细。平台不支持/采集失败返回 nil(调用方保留
// "暂无端口数据"提示, 不降级成空表)。
func SampleIfaces(interval time.Duration) []IfaceSample {
	return sampleIfaces(interval)
}

// ifaceCum 一个网卡的累计收发字节(/proc/net/dev 口径, 解析与平台无关 ——
// 解析放共享文件而非 ifaces_linux.go, 让 Windows 开发机也能单测契约)。
type ifaceCum struct{ rx, tx uint64 }

// parseNetDev 解析 /proc/net/dev 文本: 每行 "  eth0: rx_bytes ... tx_bytes ..."
// (16 列, 收=第 1 列, 发=第 9 列)。lo 回环不是"网卡端口", 剔除; 残行/表头跳过。
func parseNetDev(text string) map[string]ifaceCum {
	out := map[string]ifaceCum{}
	for _, ln := range strings.Split(text, "\n") {
		colon := strings.Index(ln, ":")
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:colon])
		if name == "" || name == "lo" {
			continue
		}
		f := strings.Fields(ln[colon+1:])
		if len(f) < 9 {
			continue
		}
		out[name] = ifaceCum{rx: parseU64(f[0]), tx: parseU64(f[8])}
	}
	return out
}

// parseU64 宽容无符号整数: 首个非数字即停(内核格式稳定, 防御性截断而非报错)。
func parseU64(s string) uint64 {
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + uint64(c-'0')
	}
	return v
}
