// ifaces_test.go 网卡端口采样契约测试(平台无关部分: /proc/net/dev 解析)。
//
// 只守"改坏会静默失效"的契约: 内核格式列位错=所有探针 Linux 端速率全错且
// 无任何报错(静默失效), 是硬契约。解析放 ifaces.go 共享文件, 任何平台可测。
package probe

import (
	"testing"
)

// 真实 /proc/net/dev 片段(16 列: 收 8 列 + 发 8 列; 收=第 1 列, 发=第 9 列)。
const sampleNetDev = `Inter-|   Receive packets |  Transmit packets 
face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567      987    0    0    0     0          0         0  1234567      987    0    0    0     0       0          0
  eth0: 987654321   12345    0    0    0     0          0         0  123456789    9876    0    0    0     0       0          0
  vlan100: 42          3      0    0    0     0          0         0  7               1      0    0    0     0       0          0
`

func TestParseNetDev(t *testing.T) {
	got := parseNetDev(sampleNetDev)
	if len(got) != 2 {
		t.Fatalf("应出 2 个网卡(eth0/vlan100), lo 回环必须剔除, got %d: %v", len(got), got)
	}
	// 列位契约: 收=第 1 列, 发=第 9 列 —— 列号错=速率全错(静默)
	if got["eth0"].rx != 987654321 || got["eth0"].tx != 123456789 {
		t.Fatalf("eth0 累计字节错: rx=%d tx=%d", got["eth0"].rx, got["eth0"].tx)
	}
	if got["vlan100"].rx != 42 || got["vlan100"].tx != 7 {
		t.Fatalf("vlan100 累计字节错: rx=%d tx=%d", got["vlan100"].rx, got["vlan100"].tx)
	}
	if _, ok := got["lo"]; ok {
		t.Fatal("lo 回环不得进入清单")
	}
}

func TestParseNetDevMalformed(t *testing.T) {
	// 表头(无冒号)/残行(列不足)/空行: 全部安全跳过, 不 panic 不报错
	got := parseNetDev("no colon line\n  eth0: 1 2\n\n   x: 123456789 1 0 0 0 0 0 0 987654321 1 0 0 0 0 0 0\n")
	if len(got) != 1 || got["x"].rx != 123456789 || got["x"].tx != 987654321 {
		t.Fatalf("残行应跳过且合法行正常解析, got %v", got)
	}
}

func TestParseU64(t *testing.T) {
	if parseU64("12345") != 12345 || parseU64("") != 0 || parseU64("12ab34") != 12 || parseU64("-5") != 0 {
		t.Fatalf("parseU64 边界错: %d %d %d %d",
			parseU64("12345"), parseU64(""), parseU64("12ab34"), parseU64("-5"))
	}
}
