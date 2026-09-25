package weakpass

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
)

// hexLower 小写十六进制（测试断言用）。
func hexLower(b []byte) string { return hex.EncodeToString(b) }

// readFullBestEffort 尽力读满（替身服务容忍客户端提前关闭）。
func readFullBestEffort(c net.Conn, buf []byte) (int, error) {
	n, err := io.ReadFull(c, buf)
	return n, err
}

// readFullBestEffortErr 同上（带错误返回的显式形式）。
func readFullBestEffortErr(c net.Conn, buf []byte) (int, error) {
	return io.ReadFull(c, buf)
}

// TestNTLMNTHash 守 NT-Hash = MD5(UTF16LE(pass)) 口径（RFC/公开已知向量）。
// 口径错（如误用 UTF-8）会让所有 NTLMv2 响应全错，结果与"口令错误"无法区分。
func TestNTLMNTHash(t *testing.T) {
	if got := hexLower(ntlmNTHash("password")); got != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatalf("NT-Hash(password) = %s", got)
	}
	if got := hexLower(ntlmNTHash("")); got != "31d6cfe0d16ae931b73c59d7e0c089c0" {
		t.Fatalf("NT-Hash(\"\") = %s", got)
	}
}

// TestHMACMD5 RFC 2202 官方向量：NTLMv2 响应的核心运算必须与标准一致。
func TestHMACMD5(t *testing.T) {
	cases := []struct{ key, msg, want string }{
		{"", "", "74e6f7298a9c2d168935f58c001bad88"},
		{"Jefe", "what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738"},
	}
	for _, c := range cases {
		if got := hexLower(hmacMD5([]byte(c.key), []byte(c.msg))); got != c.want {
			t.Errorf("HMAC-MD5(%q,%q) = %s, 期望 %s", c.key, c.msg, got, c.want)
		}
	}
}

// TestVNCReverseBits 守 RFC 6143 位序反转：漏做或做错方向会让正确口令也判失败。
func TestVNCReverseBits(t *testing.T) {
	for _, c := range [][2]byte{{0x80, 0x01}, {0x01, 0x80}, {0xB1, 0x8D}, {0x55, 0xAA}} {
		if got := vncReverseBits(c[0]); got != c[1] {
			t.Errorf("vncReverseBits(0x%02X)=0x%02X, 期望 0x%02X", c[0], got, c[1])
		}
		if vncReverseBits(vncReverseBits(c[0])) != c[0] {
			t.Errorf("vncReverseBits 自逆性不成立: 0x%02X", c[0])
		}
	}
}

// TestPGMD5Pass 守 PostgreSQL md5 串口径："md5"+hex(md5(hex(md5(pass+user))+salt))。
func TestPGMD5Pass(t *testing.T) {
	salt := []byte{1, 2, 3, 4}
	got := pgMD5Pass("secret", "admin", salt)
	if len(got) != 35 || got[:3] != "md5" {
		t.Fatalf("格式错误: %q", got)
	}
	if got == pgMD5Pass("secret2", "admin", salt) || got == pgMD5Pass("secret", "root", salt) {
		t.Fatal("换口令/用户后结果应变化")
	}
}

// TestNTLMType3Shape Type3 消息偏移自洽性：偏移算错会被服务端当成口令错误。
func TestNTLMType3Shape(t *testing.T) {
	msg, err := ntlmBuildType3("user", "pass", []byte{1, 2, 3, 4, 5, 6, 7, 8}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(msg[8:12]) != ntlmAuth {
		t.Fatal("NTLMSSP 头错误")
	}
	// 每个 SecBuf: offset+len 不得越界
	for _, off := range []int{12, 20, 28, 36, 44, 52} {
		l := int(binary.LittleEndian.Uint16(msg[off : off+2]))
		o := int(binary.LittleEndian.Uint32(msg[off+4 : off+8]))
		if l > 0 && (o < 64 || o+l > len(msg)) {
			t.Errorf("SecBuf@%d 越界: off=%d len=%d msglen=%d", off, o, l, len(msg))
		}
	}
}

// TestVNCAuthNoAuthType VNC 安全类型 1(None)=未授权访问，必须判命中。
func TestVNCAuthNoAuthType(t *testing.T) {
	dial := pipeDialer(t, func(c net.Conn) {
		defer c.Close()
		_, _ = c.Write([]byte("RFB 003.008\n"))
		ver := make([]byte, 12)
		_, _ = readFullBestEffort(c, ver)
		_, _ = c.Write([]byte{1, 1}) // 1 种安全类型: None
		sel := make([]byte, 1)
		_, _ = readFullBestEffort(c, sel)
	})
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate}, dial)
	res := e.Check(t.Context(), Target{Host: "192.168.1.10", Port: 5900, Service: "vnc"})
	if !res.OK || res.Stopped != "found" {
		t.Fatalf("VNC None 应判命中, 实际 ok=%v stopped=%s err=%s", res.OK, res.Stopped, res.Error)
	}
}

// TestPGSCRAMNoFalsePositive scram-sha-256 分支不得判命中（不伪造结论）。
func TestPGSCRAMNoFalsePositive(t *testing.T) {
	dial := pipeDialer(t, func(c net.Conn) {
		defer c.Close()
		hdr := make([]byte, 4)
		if _, err := readFullBestEffortErr(c, hdr); err != nil {
			return
		}
		rest := make([]byte, int(binary.BigEndian.Uint32(hdr))-4)
		_, _ = readFullBestEffortErr(c, rest)
		buf := []byte{'R', 0, 0, 0, 8, 0, 0, 0, pgAuthSASL}
		_, _ = c.Write(buf)
	})
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate}, dial)
	res := e.Check(t.Context(), Target{Host: "192.168.1.10", Port: 5432, Service: "postgresql"})
	if res.OK {
		t.Fatal("scram 分支不得判命中")
	}
}
