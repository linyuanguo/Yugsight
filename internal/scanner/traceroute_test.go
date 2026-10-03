package scanner

// 路由跟踪的匹配契约测试(离线纯函数)。
// 守的是"改坏会静默失效"的边界: 匹配偏移错 1 字节, 跟踪就会把别人的 ping 应答
// 当成中间跳、或永远判定"未到达"——而这两种故障在正常网络下都不报任何错。

import (
	"encoding/binary"
	"testing"
)

type fakeErr struct{ s string }

func (e *fakeErr) Error() string { return e.s }

func TestMatchHopPacket(t *testing.T) {
	const id = uint16(0x7A3B)
	const seq = uint16(3)

	// echo reply(id 匹配) → 目标到达
	reply := make([]byte, 8+16)
	reply[0] = 0
	binary.BigEndian.PutUint16(reply[4:], id)
	binary.BigEndian.PutUint16(reply[6:], seq)
	if got := matchHopPacket(reply, id, seq); got != "reply" {
		t.Fatalf("echo reply 应判 reply, got %q", got)
	}

	// echo reply(id 不匹配 = 其他进程的 ping) → 必须忽略, 否则别人的应答会误报"到达"
	other := make([]byte, 8+16)
	other[0] = 0
	binary.BigEndian.PutUint16(other[4:], id+1)
	if got := matchHopPacket(other, id, seq); got != "" {
		t.Fatalf("他进程 echo reply 应忽略, got %q", got)
	}

	// time exceeded(内嵌 id/seq 匹配) → 中间跳
	hop := make([]byte, 8+20+8)
	hop[0] = 11
	binary.BigEndian.PutUint16(hop[8+20+4:], id)
	binary.BigEndian.PutUint16(hop[8+20+6:], seq)
	if got := matchHopPacket(hop, id, seq); got != "hop" {
		t.Fatalf("time exceeded 应判 hop, got %q", got)
	}

	// time exceeded(seq 不匹配 = 其他跳的迟到响应) → 忽略
	wrongSeq := make([]byte, 8+20+8)
	wrongSeq[0] = 11
	binary.BigEndian.PutUint16(wrongSeq[8+20+4:], id)
	binary.BigEndian.PutUint16(wrongSeq[8+20+6:], seq+1)
	if got := matchHopPacket(wrongSeq, id, seq); got != "" {
		t.Fatalf("迟到 time exceeded 应忽略, got %q", got)
	}

	// 短包不得越界
	if got := matchHopPacket([]byte{0, 0, 0}, id, seq); got != "" {
		t.Fatalf("短包应忽略, got %q", got)
	}

	// 非 ICMP 错误类型(如 type 3 不可达)不属于跟踪匹配范围
	unreach := make([]byte, 8+20+8)
	unreach[0] = 3
	binary.BigEndian.PutUint16(unreach[8+20+4:], id)
	if got := matchHopPacket(unreach, id, seq); got != "" {
		t.Fatalf("type 3 不应参与 hop 匹配, got %q", got)
	}
}

func TestStripIPHeader(t *testing.T) {
	// 带外层 IP 头(Linux 读回) → 剥 20 字节
	withHdr := make([]byte, 20+8)
	withHdr[0] = 0x45 // v4, IHL=5
	if got := stripIPHeader(withHdr); len(got) != 8 {
		t.Fatalf("应剥掉 20 字节 IP 头, got len=%d", len(got))
	}
	// 无外层 IP 头(Windows 读回) → 原样
	noHdr := []byte{8, 0, 0, 0, 0, 0, 0, 0, 1, 2}
	if got := stripIPHeader(noHdr); len(got) != 10 || got[0] != 8 {
		t.Fatalf("无头包应原样返回, got len=%d", len(got))
	}
	// 空包不 panic
	if got := stripIPHeader(nil); len(got) != 0 {
		t.Fatalf("空包应原样, got len=%d", len(got))
	}
}

func TestIsRefused(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"connectex: No connection could be made because the target machine actively refused it.", true}, // Windows 措辞
		{"dial tcp 1.2.3.4:23: connect: connection refused", true},                                        // Linux 措辞
		{"dial tcp4 1.2.3.4:23: i/o timeout", false},
		{"dial tcp4 1.2.3.4:23: no route to host", false},
	}
	for _, c := range cases {
		if got := isRefused(&fakeErr{c.msg}); got != c.want {
			t.Errorf("isRefused(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
	if isRefused(nil) {
		t.Error("nil 不应判 refused")
	}
}
