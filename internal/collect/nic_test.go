// nic_test.go 网卡端口指标契约测试(全部离线, 不发起真实网络)。
//
// 只守"改坏会静默失效"的契约:
//   - Linux /proc/net/dev + /sys 文本 → nic 指标(lo 剔除、列位、带宽换算);
//   - Windows Get-NetAdapter JSON → nic 指标(LinkSpeed 文本解析);
//   - 主机 SNMP ifTable 行 → nic 指标(oper 归一化、全零 MAC 当无值);
//   - 状态/带宽文本解析: 解析错=端口详情全错, 是硬契约。
package collect

import (
	"strings"
	"testing"
	"time"
)

// 真实 /proc/net/dev 片段(16 列: 收 8 列 + 发 8 列, 收=第 1 列, 发=第 9 列)。
const sampleNetDev = `Inter-|   Receive packets |  Transmit packets 
face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567      987    0    0    0     0          0         0  1234567      987    0    0    0     0       0          0
  eth0: 987654321   12345    0    0    0     0          0         0  123456789    9876    0    0    0     0       0          0
  eth1: 0           0       0    0    0     0          0         0  0           0      0    0    0    0     0       0          0
`

const sampleSysInfo = "eth0|up|aa:bb:cc:dd:ee:ff|1000\n" +
	"eth1|down||-1\n"

const sampleIP = "eth0 172.16.101.51/24\n" +
	"eth1 10.0.0.5/24\n"

func TestNicMetricFromLinux(t *testing.T) {
	r := newRound(Task{}, time.Now())
	nicMetricFromLinux(r, sampleNetDev, sampleSysInfo, sampleIP)
	got := nicByName(r.Metrics)
	if len(got) != 2 {
		t.Fatalf("应出 2 条 nic(eth0/eth1), lo 必须剔除, got %d: %v", len(got), got)
	}
	e0, e1 := got["eth0"], got["eth1"]
	if e0 == nil || e1 == nil {
		t.Fatalf("eth0/eth1 缺失: %v", got)
	}
	// 累计字节列位(收=第 1 列, 发=第 9 列): 列号错=速率全错
	if e0["rx"] != "987654321" || e0["tx"] != "123456789" {
		t.Fatalf("eth0 累计字节错: rx=%s tx=%s", e0["rx"], e0["tx"])
	}
	// 带宽: /sys 单位 Mbit/s → bps
	if e0["speed"] != "1000000000" {
		t.Fatalf("eth0 带宽应为 1000Mbps=1000000000bps, got %s", e0["speed"])
	}
	// 状态/MAC/IP
	if e0["state"] != "up" || e0["mac"] != "aa:bb:cc:dd:ee:ff" || e0["ip"] != "172.16.101.51" {
		t.Fatalf("eth0 静态属性错: %v", e0)
	}
	// speed=-1(虚拟口未协商) 必须归 0 = 未知, 不能出负带宽
	if e1["speed"] != "0" || e1["state"] != "down" || e1["mac"] != "" {
		t.Fatalf("eth1 应 speed=0 state=down mac=空: %v", e1)
	}
}

func TestNicMetricFromWindows(t *testing.T) {
	r := newRound(Task{}, time.Now())
	nicMetricsFromWindows(r, []nicWin{
		{Name: "Ethernet", State: "Up", Mac: "aa-bb-cc-dd-ee-ff", Speed: "1 Gbps", Rx: 1000, Tx: 2000},
		{Name: "Wi-Fi", State: "Disconnected", Mac: "", Speed: "866 Mbps", Rx: 0, Tx: 0},
		{Name: "  ", State: "Up", Mac: "", Speed: "100 Mbps", Rx: 1, Tx: 1}, // 空名剔除
	})
	got := nicByName(r.Metrics)
	if len(got) != 2 {
		t.Fatalf("应出 2 条(空名剔除), got %d: %v", len(got), got)
	}
	if got["Ethernet"]["speed"] != "1000000000" || got["Ethernet"]["state"] != "up" {
		t.Fatalf("Ethernet 解析错: %v", got["Ethernet"])
	}
	if got["Wi-Fi"]["speed"] != "866000000" || got["Wi-Fi"]["state"] != "down" {
		t.Fatalf("Wi-Fi 解析错: %v", got["Wi-Fi"])
	}
}

func TestNicSpeedFromLink(t *testing.T) {
	cases := map[string]int64{
		"1 Gbps":   1_000_000_000,
		"10 Gbps":  10_000_000_000,
		"100 Mbps": 100_000_000,
		"1000 kbps": 1_000_000,
		"":          0,
		"unknown":   0,
		"0 Gbps":    0,
	}
	for in, want := range cases {
		if got := nicSpeedFromLink(in); got != want {
			t.Fatalf("nicSpeedFromLink(%q)=%d, want %d", in, got, want)
		}
	}
}

func TestNicState(t *testing.T) {
	cases := map[string]string{
		"up":             "up",
		"UP":             "up",
		"down":           "down",
		"lowerlayerdown": "down",
		"notpresent":     "down",
		"disconnected":   "down",
		"unknown":        "unknown",
		"dormant":        "unknown",
		"testing":        "unknown",
		"garbage":        "unknown",
	}
	for in, want := range cases {
		if got := nicState(in); got != want {
			t.Fatalf("nicState(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestNicMetricsFromSNMPRows(t *testing.T) {
	r := newRound(Task{}, time.Now())
	nicMetricsFromSNMPRows(r, []snmpIfaceRow{
		{Index: "2", Name: "eth0", Oper: 1, Speed: 1000000000, Rx: 100, Tx: 200, MAC: "aa:bb:cc:dd:ee:ff"},
		{Index: "3", Name: "lo", Oper: 1, Speed: 0, Rx: 1, Tx: 1, MAC: "00:00:00:00:00:00"}, // 全零 MAC=无值
		{Index: "4", Name: "  ", Oper: 1, Speed: 0, Rx: 1, Tx: 1, MAC: "x"},                 // 空名剔除
		{Index: "5", Name: "eth1", Oper: 2, Speed: 100000000, Rx: 0, Tx: 0, MAC: ""},        // down
		{Index: "6", Name: "eth2", Oper: 3, Speed: 0, Rx: 0, Tx: 0, MAC: ""},                // testing=unknown
	})
	got := nicByName(r.Metrics)
	if len(got) != 3 {
		t.Fatalf("应出 3 条(空名剔除), got %d: %v", len(got), got)
	}
	if got["eth0"]["state"] != "up" || got["eth0"]["speed"] != "1000000000" ||
		got["eth0"]["rx"] != "100" || got["eth0"]["tx"] != "200" || got["eth0"]["mac"] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("eth0 指标错: %v", got["eth0"])
	}
	if got["lo"]["mac"] != "" {
		t.Fatalf("全零 MAC 必须当无值, got %q", got["lo"]["mac"])
	}
	if got["eth1"]["state"] != "down" {
		t.Fatalf("oper=2 应为 down, got %q", got["eth1"]["state"])
	}
	if got["eth2"]["state"] != "unknown" {
		t.Fatalf("oper=3(testing) 应为 unknown, got %q", got["eth2"]["state"])
	}
}

func TestSNMPOperText(t *testing.T) {
	if snmpOperText(1) != "up" || snmpOperText(2) != "down" || snmpOperText(3) != "unknown" || snmpOperText(0) != "unknown" {
		t.Fatalf("ifOperStatus 归一化错: 1=%q 2=%q 3=%q 0=%q",
			snmpOperText(1), snmpOperText(2), snmpOperText(3), snmpOperText(0))
	}
}

// nicByName 从一轮指标里抽 nic 指标按 iface 索引。
func nicByName(ms []Metric) map[string]map[string]string {
	out := map[string]map[string]string{}
	for i := range ms {
		if ms[i].Name != nicMetric || ms[i].Labels == nil {
			continue
		}
		iface := ms[i].Labels["iface"]
		if strings.TrimSpace(iface) == "" {
			continue
		}
		l := make(map[string]string, len(ms[i].Labels))
		for k, v := range ms[i].Labels {
			l[k] = v
		}
		out[iface] = l
	}
	return out
}
