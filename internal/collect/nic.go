// nic.go 主机侧网卡端口采集(2026-10-02 用户要求: "SSH / WinRM 主机也要能看到
// 有几个网卡端口, 并能基于端口查看速率")。
//
// 口径(与探针端 internal/probe/ifaces.go 对齐, 避免两套展示逻辑):
//   - 采集端只报**累计字节 + 静态属性**(名称/状态/MAC/IP/带宽), 速率由展示层对
//     最近两轮样本做差分 —— 与交换机 SNMP 接口表在前端差分的口径完全一致;
//   - 一条网卡 = 一条 Metric{Name:"nic"}, 字符串属性走 Labels(Metric.Value 是
//     float64, 与既有 boot_time / sys_descr 的 "Value:0 + Labels" 口径一致);
//   - 拿不到速率(只有一轮样本)时速率显示 0, 但端口清单照出 —— 用户要的是
//     "有几个口", 不该因为差分还没成立就显示空白。
package collect

import (
	"context"
	"strconv"
	"strings"

	"yugsight/internal/monitor"
	"yugsight/internal/snmp"
)

// nicMetric 网卡指标名(展示层据此聚合"端口详情")。
const nicMetric = "nic"

// nicMetricFromLinux 组装 Linux 网卡指标:
//   devText  = /proc/net/dev 原文(累计收发字节)
//   infoText = "iface|operstate|mac|speed(Mbps)" 每行一条
//   ipText   = "iface ip" 每行一条(ip -4 -o addr)
func nicMetricFromLinux(r *Round, devText, infoText, ipText string) {
	type cum struct{ rx, tx uint64 }
	byName := map[string]cum{}
	for _, ln := range strings.Split(devText, "\n") {
		colon := strings.Index(ln, ":")
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:colon])
		if name == "" || name == "lo" {
			continue // 回环不是"网卡端口"
		}
		f := strings.Fields(ln[colon+1:])
		if len(f) < 9 {
			continue
		}
		byName[name] = cum{rx: nicAtoi(f[0]), tx: nicAtoi(f[8])}
	}
	if len(byName) == 0 {
		return
	}
	// 静态属性: 状态 / MAC / 带宽
	state, mac, speed := map[string]string{}, map[string]string{}, map[string]int64{}
	for _, ln := range strings.Split(infoText, "\n") {
		parts := strings.Split(strings.TrimSpace(ln), "|")
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		n := parts[0]
		if len(parts) > 1 {
			state[n] = nicState(strings.TrimSpace(parts[1]))
		}
		if len(parts) > 2 {
			mac[n] = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			// /sys/class/net/<if>/speed 单位 Mbit/s; 负数 = 未协商(虚拟口常见)
			if v, err := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64); err == nil && v > 0 {
				speed[n] = v * 1_000_000
			}
		}
	}
	ip := map[string]string{}
	for _, ln := range strings.Split(ipText, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		// "eth0 172.31.21.51/20" → 去掉掩码
		addr := strings.Split(f[1], "/")[0]
		if _, ok := ip[f[0]]; !ok {
			ip[f[0]] = addr
		}
	}
	for name, c := range byName {
		r.Metrics = append(r.Metrics, Metric{
			Name: nicMetric, Value: 0,
			Labels: map[string]string{
				"iface": name,
				"state": state[name],
				"mac":   mac[name],
				"ip":    ip[name],
				"speed": strconv.FormatInt(speed[name], 10),
				"rx":    strconv.FormatUint(c.rx, 10),
				"tx":    strconv.FormatUint(c.tx, 10),
			},
		})
	}
}

// nicMetricsFromWindows 组装 Windows 网卡指标(PowerShell 采集的 JSON 已解析)。
func nicMetricsFromWindows(r *Round, nics []nicWin) {
	for _, n := range nics {
		if strings.TrimSpace(n.Name) == "" {
			continue
		}
		r.Metrics = append(r.Metrics, Metric{
			Name: nicMetric, Value: 0,
			Labels: map[string]string{
				"iface": n.Name,
				"state": nicState(n.State),
				"mac":   n.Mac,
				"speed": strconv.FormatInt(nicSpeedFromLink(n.Speed), 10),
				"rx":    strconv.FormatInt(n.Rx, 10),
				"tx":    strconv.FormatInt(n.Tx, 10),
			},
		})
	}
}

// nicWin Get-NetAdapter + Get-NetAdapterStatistics 的单条输出。
type nicWin struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Mac   string `json:"mac"`
	Speed string `json:"speed"` // 原始 LinkSpeed 文本, 如 "1 Gbps" / "100 Mbps"
	Rx    int64  `json:"rx"`    // 累计接收字节
	Tx    int64  `json:"tx"`    // 累计发送字节
}

// nicSpeedFromLink "1 Gbps" / "100 Mbps" → bps; 无法识别返回 0(未知, 不猜)。
func nicSpeedFromLink(s string) int64 {
	low := strings.ToLower(strings.TrimSpace(s))
	if low == "" {
		return 0
	}
	num := ""
	for _, c := range low {
		if c >= '0' && c <= '9' {
			num += string(c)
		}
	}
	if num == "" {
		return 0
	}
	v, err := strconv.ParseInt(num, 10, 64)
	if err != nil || v <= 0 {
		return 0
	}
	switch {
	case strings.Contains(low, "gbps"):
		return v * 1_000_000_000
	case strings.Contains(low, "mbps"):
		return v * 1_000_000
	case strings.Contains(low, "kbps"):
		return v * 1_000
	}
	return 0
}

// snmpIfaceRow ifTable walk 结果的一行(先聚行, 再统一修带宽, 最后出指标 ——
// 拆开是因为 ifHighSpeed 修正需要一次批量 GET, 不能在逐行时做)。
type snmpIfaceRow struct {
	Index string
	Name  string
	Oper  int // ifOperStatus: 1=up 2=down 3=testing
	Speed int64
	Rx    uint64
	Tx    uint64
	MAC   string
}

// nicMetricsFromSNMPRows 主机 SNMP 的 ifTable 行 → nic 指标(2026-10-02 需求 1:
// 主机 SNMP 与 SSH/WinRM 同口径, 前端端口详情三分支统一消费)。
//
// snmp.Collect 的表库本来就 walk ifTable(monitor 交换机与主机 SNMP 共用同一
// 采集器), 这里只做提取, 不增加任何采集往返。万兆口 ifSpeed 溢出由调用方
// 先用 monitor.FixIfSpeedOverflow 修正(rows 传进来时 Speed 已是终值)。
func nicMetricsFromSNMPRows(r *Round, rows []snmpIfaceRow) {
	for _, row := range rows {
		name := strings.TrimSpace(row.Name)
		if name == "" || strings.ToLower(name) == "lo" {
			// 空名剔除; lo 回环不是"网卡端口"(与 Linux /proc/net/dev 路径同口径)
			continue
		}
		mac := strings.TrimSpace(row.MAC)
		if mac == "00:00:00:00:00:00" {
			mac = "" // 逻辑接口常见全零 MAC, 当无值(与 monitor 同口径)
		}
		r.Metrics = append(r.Metrics, Metric{
			Name: nicMetric, Value: 0,
			Labels: map[string]string{
				"iface": name,
				"state": nicState(snmpOperText(row.Oper)),
				"mac":   mac,
				"speed": strconv.FormatInt(row.Speed, 10),
				"rx":    strconv.FormatUint(row.Rx, 10),
				"tx":    strconv.FormatUint(row.Tx, 10),
			},
		})
	}
}

// snmpOperText ifOperStatus(1/2/3) → 文本; 未知值走 "unknown"(展示层 '-')。
func snmpOperText(oper int) string {
	switch oper {
	case 1:
		return "up"
	case 2:
		return "down"
	default:
		return "unknown"
	}
}

// collectSNMPIfaces 从 ifTable 的 walk 结果聚行, 修正万兆带宽溢出后出 nic 指标。
//
// 为什么单独一个函数(而非在 collectSNMP 的 switch 里内联): 提取+修正是两段
// (先聚行 → 批量 GET ifHighSpeed → 出指标), 内联会让表抽取的 switch 变得
// 不可单测; 纯行聚部分 nicSNMPRows 可离线测。
func collectSNMPIfaces(ctx context.Context, c *snmp.Client, r *Round, rows []snmp.TableRow) {
	parsed := make([]snmpIfaceRow, 0, len(rows))
	for _, row := range rows {
		name := strings.TrimSpace(row.Cells["ifDescr"])
		if name == "" {
			continue
		}
		it := snmpIfaceRow{Index: row.Index, Name: name, MAC: row.Cells["ifPhysAddress"]}
		it.Speed, _ = strconv.ParseInt(row.Cells["ifSpeed"], 10, 64)
		it.Oper, _ = strconv.Atoi(row.Cells["ifOperStatus"])
		it.Rx, _ = strconv.ParseUint(row.Cells["ifInOctets"], 10, 64)
		it.Tx, _ = strconv.ParseUint(row.Cells["ifOutOctets"], 10, 64)
		parsed = append(parsed, it)
	}
	if len(parsed) == 0 {
		return
	}
	// ifSpeed 是 32 位 gauge, 万兆口必然溢出(与交换机 v242 同一坑), 用
	// ifHighSpeed 覆盖 —— 直接复用 monitor 已测的分批 GET 实现。
	samples := make([]monitor.IfaceSample, 0, len(parsed))
	for i := range parsed {
		samples = append(samples, monitor.IfaceSample{
			Index: parsed[i].Index, Name: parsed[i].Name,
			Speed: parsed[i].Speed, Oper: parsed[i].Oper,
		})
	}
	monitor.FixIfSpeedOverflow(ctx, c, samples)
	for i := range parsed {
		parsed[i].Speed = samples[i].Speed
	}
	nicMetricsFromSNMPRows(r, parsed)
}

// nicState 归一化状态: up / down; 未知返回 "unknown"(展示层显示 '-')。
func nicState(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "up":
		return "up"
	case "down", "lowerlayerdown", "notpresent", "disconnected":
		return "down"
	case "unknown", "testing", "dormant":
		return "unknown"
	}
	return "unknown"
}

func nicAtoi(s string) uint64 {
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
