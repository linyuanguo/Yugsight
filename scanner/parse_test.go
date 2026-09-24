package scanner

import (
	"net"
	"sort"
	"testing"
	"time"
)

func TestParseHosts(t *testing.T) {
	hosts, err := ParseHosts("192.168.1.0/30")
	if err != nil {
		t.Fatalf("CIDR: %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if len(hosts) != len(want) || hosts[0] != want[0] || hosts[1] != want[1] {
		t.Fatalf("CIDR /30 = %v, want %v", hosts, want)
	}

	hosts, err = ParseHosts("192.168.1.10-13")
	if err != nil || len(hosts) != 4 || hosts[0] != "192.168.1.10" || hosts[3] != "192.168.1.13" {
		t.Fatalf("range = %v, err=%v", hosts, err)
	}

	hosts, err = ParseHosts("10.0.0.1")
	if err != nil || len(hosts) != 1 {
		t.Fatalf("single = %v, err=%v", hosts, err)
	}

	if _, err = ParseHosts("10.0.0.0/8"); err == nil {
		t.Fatal("CIDR /8 应当报错(网段过大)")
	}
	if _, err = ParseHosts("abc"); err == nil {
		t.Fatal("非法输入应当报错")
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("22,80,1000-1002")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !sort.IntsAreSorted(ports) || len(ports) != 5 || ports[0] != 22 || ports[4] != 1002 {
		t.Fatalf("ports = %v", ports)
	}
	// 括号包裹的列表+范围混合格式
	ports, err = ParsePorts("(80,443,500-600)")
	if err != nil {
		t.Fatalf("括号格式 parse: %v", err)
	}
	if len(ports) != 103 || ports[0] != 80 || ports[1] != 443 || ports[2] != 500 || ports[len(ports)-1] != 600 {
		t.Fatalf("括号格式 ports = %v", ports)
	}
	if _, err = ParsePorts("（80，443）"); err != nil {
		t.Fatalf("全角括号 parse: %v", err)
	}
	if _, err = ParsePorts("abc"); err == nil {
		t.Fatal("非法端口应当报错")
	}
	if _, err = ParsePorts("80-22"); err == nil {
		t.Fatal("倒序范围应当报错")
	}
}

// 回环连通性: 沙箱可能拦截回环, 被拦截时跳过
func TestLoopbackDial(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8420", 2*time.Second)
	if err != nil {
		t.Skipf("回环被沙箱拦截, 跳过: %v", err)
	}
	conn.Close()
}
