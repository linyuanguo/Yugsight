package scanner

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildArpFrame 构造一条以太网 + ARP 帧(测试用)。
// opcode 1=请求 2=应答; 全零 MAC 用零值表示。
func buildArpFrame(opcode uint16, sha, spa, tha, tpa []byte) []byte {
	f := make([]byte, 42) // 14 以太网头 + 28 ARP
	// 以太网头
	copy(f[0:6], tha) // dst MAC
	copy(f[6:12], sha) // src MAC
	binary.BigEndian.PutUint16(f[12:14], 0x0806) // ethertype = ARP
	// ARP 头
	binary.BigEndian.PutUint16(f[14:16], 1)      // hwtype = 以太网
	binary.BigEndian.PutUint16(f[16:18], 0x0800) // protype = IPv4
	f[18] = 6                                     // hlen
	f[19] = 4                                     // plen
	binary.BigEndian.PutUint16(f[20:22], opcode)
	copy(f[22:28], sha)
	copy(f[28:32], spa)
	copy(f[32:38], tha)
	copy(f[38:42], tpa)
	return f
}

func mac(s string) []byte {
	switch s {
	case "":
		return []byte{0, 0, 0, 0, 0, 0}
	case "aa":
		return []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	case "bb":
		return []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
	default:
		return []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	}
}

func ip(s string) []byte {
	switch s {
	case "1.1.1.1":
		return []byte{1, 1, 1, 1}
	case "2.2.2.2":
		return []byte{2, 2, 2, 2}
	case "0.0.0.0":
		return []byte{0, 0, 0, 0}
	default:
		return []byte{192, 168, 1, 10}
	}
}

func TestParseArpFrame(t *testing.T) {
	// 合法请求
	f := buildArpFrame(1, mac("aa"), ip("1.1.1.1"), mac(""), ip("0.0.0.0"))
	got, ok := parseArpFrame(f)
	if !ok {
		t.Fatal("应解析出合法 ARP 请求")
	}
	if got.Opcode != 1 {
		t.Fatalf("Opcode = %d, want 1", got.Opcode)
	}
	if got.SenderMAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("SenderMAC = %q, want aa:bb:cc:dd:ee:01", got.SenderMAC)
	}
	if got.SenderIP != "1.1.1.1" {
		t.Fatalf("SenderIP = %q, want 1.1.1.1", got.SenderIP)
	}
	if got.TargetIP != "0.0.0.0" {
		t.Fatalf("TargetIP = %q, want 0.0.0.0", got.TargetIP)
	}

	// 非法: 非 ARP ethertype
	f2 := buildArpFrame(1, mac("aa"), ip("1.1.1.1"), mac(""), ip("0.0.0.0"))
	binary.BigEndian.PutUint16(f2[12:14], 0x0800) // IPv4 而非 ARP
	if _, ok := parseArpFrame(f2); ok {
		t.Fatal("非 ARP ethertype 应被拒绝")
	}

	// 非法: 过短
	if _, ok := parseArpFrame(f[:10]); ok {
		t.Fatal("过短帧应被拒绝")
	}

	// 非法: 畸形 hlen
	f3 := buildArpFrame(1, mac("aa"), ip("1.1.1.1"), mac(""), ip("0.0.0.0"))
	f3[18] = 200 // hlen 异常
	if _, ok := parseArpFrame(f3); ok {
		t.Fatal("畸形 hlen 应被拒绝")
	}
}

// detect 用一组辅助: 直接构造观测 map 喂给 detectArpAnomalies
func TestDetectConflict(t *testing.T) {
	base := time.Now()
	obs := map[string][]macObs{
		"10.0.0.5": {
			{mac: "aa", ts: base},
			{mac: "bb", ts: base.Add(10 * time.Second)}, // 10s 后另一 MAC 出现 -> 区间重叠
			{mac: "aa", ts: base.Add(20 * time.Second)},
		},
	}
	got := detectArpAnomalies(obs, nil, 10*time.Second, 5)
	if len(got) != 1 {
		t.Fatalf("应检测到 1 条异常, got %d", len(got))
	}
	if got[0].Kind != "ip_conflict" {
		t.Fatalf("应为 ip_conflict, got %s", got[0].Kind)
	}
	if got[0].Severity != "high" {
		t.Fatalf("冲突应为 high, got %s", got[0].Severity)
	}
}

func TestDetectDrift(t *testing.T) {
	base := time.Now()
	obs := map[string][]macObs{
		"10.0.0.5": {
			{mac: "aa", ts: base},
			{mac: "aa", ts: base.Add(30 * time.Second)},
			// 间隔 >60s 后才出现新 MAC -> 区间不重叠 = 漂移
			{mac: "bb", ts: base.Add(300 * time.Second)},
		},
	}
	got := detectArpAnomalies(obs, nil, 10*time.Second, 5)
	if len(got) != 1 {
		t.Fatalf("应检测到 1 条异常, got %d", len(got))
	}
	if got[0].Kind != "mac_drift" {
		t.Fatalf("应为 mac_drift, got %s", got[0].Kind)
	}
	if got[0].Severity != "medium" {
		t.Fatalf("漂移应为 medium, got %s", got[0].Severity)
	}
}

func TestDetectLoop(t *testing.T) {
	base := time.Now()
	// 同一条 ARP 请求在 10s 内出现 5 次 -> 环路
	sig := "aa|10.0.0.5|ff|0.0.0.0"
	reqs := map[string][]time.Time{
		sig: {
			base, base.Add(1*time.Second), base.Add(2*time.Second),
			base.Add(3*time.Second), base.Add(4*time.Second),
		},
	}
	got := detectArpAnomalies(nil, reqs, 10*time.Second, 5)
	if len(got) != 1 {
		t.Fatalf("应检测到 1 条环路异常, got %d", len(got))
	}
	if got[0].Kind != "loop" || got[0].Count != 5 {
		t.Fatalf("环路异常不符: kind=%s count=%d", got[0].Kind, got[0].Count)
	}
	// 只有 4 次 -> 不报
	reqs2 := map[string][]time.Time{sig: {base, base.Add(time.Second), base.Add(2 * time.Second), base.Add(3 * time.Second)}}
	if g2 := detectArpAnomalies(nil, reqs2, 10*time.Second, 5); len(g2) != 0 {
		t.Fatalf("4 次不应报环路, got %d", len(g2))
	}
}

func TestDetectClean(t *testing.T) {
	base := time.Now()
	obs := map[string][]macObs{
		"10.0.0.1": {{mac: "aa", ts: base}, {mac: "aa", ts: base.Add(time.Minute)}},
		"10.0.0.2": {{mac: "bb", ts: base}, {mac: "bb", ts: base.Add(time.Minute)}},
	}
	// 每条请求只出现 1 次
	reqs := map[string][]time.Time{"aa|10.0.0.1|ff|0.0.0.0": {base}}
	if got := detectArpAnomalies(obs, reqs, 10*time.Second, 5); len(got) != 0 {
		t.Fatalf("干净流量不应有异常, got %d: %+v", len(got), got)
	}
}

// TestRunArpWatchNoCollector 无采集器时必须明确失败(不静默返回空结果)。
func TestRunArpWatchNoCollector(t *testing.T) {
	old := CurrentCollector()
	SetCollector(nil)
	defer SetCollector(old)

	_, err := RunArpWatch(t.Context(), ArpWatchConfig{DurationSec: 1}, nil)
	if err == nil {
		t.Fatal("无采集器时 RunArpWatch 应返回明确错误")
	}
}
