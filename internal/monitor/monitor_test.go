// monitor_test.go 离线单测: 回环 UDP 假 SNMP 设备 + 采集引擎行为。
//
// 守的契约:
//  1. CollectTarget 从 snmp.Collect 的 Report 里正确抽出标量/接口/CPU/内存
//     (字段映射错了监控页全是 0, 用户会以为功能没生效);
//  2. 设备不可达时 OK=false 且带人话错误(不能把"设备哑了"当"采集成功");
//  3. 空目标 = 零活动(不触发落库、无轮次结果) —— "默认开但空目标零行为"
//     这个产品口径的回归防线;
//  4. 速率差分: 计数器回绕(设备重启清零)归 0 而非负值。
//  5. 接口按"名字"对齐两帧差分(ifIndex 重启后会变, 按索引对齐会算出错误速率)。
package monitor

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"yugsight/internal/snmp"
)

// ===== 假设备: 手写 BER 响应(不依赖 snmp 包未导出符号) =====

func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	if len(content) < 0x80 {
		out = append(out, byte(len(content)))
	} else {
		out = append(out, 0x81, byte(len(content)))
	}
	return append(out, content...)
}

func intField(v int) []byte {
	return tlv(0x02, []byte{byte(v)})
}

func varbind(oid string, tag byte, content []byte) []byte {
	arc, err := snmp.ParseOID(oid)
	if err != nil {
		return nil
	}
	// OID 必须包 0x06 TLV(parseResponse 按 TLV 解析, 裸字节首弧 0x2b 会被当 tag 拒收)
	var inner []byte
	inner = append(inner, tlv(0x06, snmp.EncodeOID(arc))...)
	inner = append(inner, tlv(tag, content)...)
	return tlv(0x30, inner)
}

// pduTag 从请求首字节序列定位 PDU tag(GET=0xa0 / GETBULK=0xa5)。
// 外层 SEQ 长度可能是 BER 长格式(>127 字节时 0x81/0x82 前缀), 必须按实际
// 长度编码推进偏移, 否则 8 个 OID 的标量 GET(~210B) 会定位错位置不回复。
func pduTag(b []byte) int {
	if len(b) < 4 || b[0] != 0x30 {
		return -1
	}
	i := 1
	switch {
	case b[i] < 0x80:
		i += 1
	case b[i] == 0x81:
		i += 2
	case b[i] == 0x82:
		i += 3
	default:
		return -1
	}
	if b[i] != 0x02 || b[i+1] != 1 { // version INTEGER 1
		return -1
	}
	i += 3
	if b[i] != 0x04 { // community OCTET STRING
		return -1
	}
	clen := int(b[i+1])
	i += 2 + clen
	if i >= len(b) {
		return -1
	}
	return int(b[i])
}

// fakeResp 回环假 SNMP 设备:
//   - GET      → 回三个标量(sysDescr/sysUpTime/ifNumber)
//   - GETBULK  → 回 endOfMibView(表全部"不支持", 走降级路径)
type fakeResp struct {
	pc    net.PacketConn
	gets  int
	bulks int
	mu    sync.Mutex
}

func startFakeResp(t *testing.T) *fakeResp {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("回环 UDP 不可用, 由真机联调覆盖: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	f := &fakeResp{pc: pc}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			f.mu.Lock()
			switch pduTag(buf[:n]) {
			case 0xa0:
				f.gets++
			case 0xa5:
				f.bulks++
			}
			f.mu.Unlock()
			switch pduTag(buf[:n]) {
			case 0xa0:
				resp := responseSeq([]byte{
					0x02, 0x01, 0x01, // version=1
				}, "pub", 0xa2, func() []byte {
					// 三个标量: sysDescr=integer, sysUpTime=timeticks(300000 百分秒=3000s), ifNumber=integer
					body := varbind("1.3.6.1.2.1.1.1.0", 0x02, []byte{100})
					body = append(body, varbind("1.3.6.1.2.1.1.3.0", 0x43, be32(300000))...)
					body = append(body, varbind("1.3.6.1.2.1.2.1.0", 0x02, []byte{13})...)
					return tlv(0x30, body)
				})
				pc.WriteTo(resp, addr)
			case 0xa5:
				resp := responseSeq([]byte{
					0x02, 0x01, 0x01,
				}, "pub", 0xa2, func() []byte {
					return tlv(0x30, varbind("1.3.6.1.2.1.2.2.1.1.1", 0x82, nil)) // endOfMibView
				})
				pc.WriteTo(resp, addr)
			}
		}
	}()
	return f
}

// responseSeq 构造 v2c getResponse: seq(version, community, pdu(reqid,0,0,varbinds))。
// 用临时缓冲逐段 append —— Go 语法不允许一个调用里混用裸字面量与多个 "..." 展开,
// 嵌套 append(a, b..., c...) 会报 "unexpected [", 逐段拼最稳。
func responseSeq(version []byte, community string, pduTagByte byte, varbinds func() []byte) []byte {
	var body []byte
	body = append(body, intField(1)...) // reqid
	body = append(body, intField(0)...) // error-status
	body = append(body, intField(0)...) // error-index
	body = append(body, varbinds()...)
	pdu := tlv(pduTagByte, body)

	var msg []byte
	msg = append(msg, version...)
	msg = append(msg, tlv(0x04, []byte(community))...)
	msg = append(msg, pdu...)
	return tlv(0x30, msg)
}

func be32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func addrOf(pc net.PacketConn) string {
	return pc.LocalAddr().String()
}

// ===== 用例 =====

// TestCollectTargetFakeDevice 字段抽取契约: 标量/接口表缺省路径。
func TestCollectTargetFakeDevice(t *testing.T) {
	f := startFakeResp(t)
	tgt := Target{ID: "t1", Name: "假设备", Addr: addrOf(f.pc), Community: "pub", TimeoutMs: 2000}

	s := CollectTarget(context.Background(), tgt)
	if !s.OK {
		t.Fatalf("应采集成功, got OK=false err=%q", s.Err)
	}
	if s.SysDescr != "100" {
		t.Fatalf("sysDescr 应为 100, got %q", s.SysDescr)
	}
	if s.UptimeSec != 3000 {
		t.Fatalf("sysUpTime 300000 百分秒应换算为 3000 秒, got %d", s.UptimeSec)
	}
	if s.IfNumber != 13 {
		t.Fatalf("ifNumber 应为 13, got %d", s.IfNumber)
	}
	if len(s.Ifaces) != 0 {
		t.Fatalf("表全部 endOfMibView 时接口应为空, got %d 条", len(s.Ifaces))
	}
	if s.CpuLoad != 0 || s.MemTotal != 0 {
		t.Fatalf("不支持的设备 CPU/内存应为 0, got cpu=%d mem=%d", s.CpuLoad, s.MemTotal)
	}
	f.mu.Lock()
	gets, bulks := f.gets, f.bulks
	f.mu.Unlock()
	if gets < 1 {
		t.Fatal("应至少一次标量 GET")
	}
	if bulks < 1 {
		t.Fatal("应至少一次表 walk(GETBULK)")
	}
}

// TestCollectTargetUnreachable 设备不可达: OK=false 且错误非空
// (把"设备哑了"当成功是监控的致命错误 —— 大屏会显示绿色在线)。
func TestCollectTargetUnreachable(t *testing.T) {
	tgt := Target{ID: "dead", Name: "哑设备", Addr: "127.0.0.1:1", Community: "pub", TimeoutMs: 300}
	s := CollectTarget(context.Background(), tgt)
	if s.OK {
		t.Fatal("不可达设备不应标记 OK")
	}
	if s.Err == "" {
		t.Fatal("不可达必须给出错误文本")
	}
}

// TestMonitorEmptyTargetsZeroActivity 空目标 = 零活动:
// 不触发落库、无轮次结果。这是"默认开但零行为"口径的回归防线。
func TestMonitorEmptyTargetsZeroActivity(t *testing.T) {
	var writes int
	var wmu sync.Mutex
	m := New(Config{Enabled: true, IntervalSec: 60}, func() Config {
		return Config{Enabled: true, IntervalSec: 60}
	}, func(samples []*Sample) {
		wmu.Lock()
		writes += len(samples)
		wmu.Unlock()
	})
	m.Start()
	time.Sleep(150 * time.Millisecond)
	m.Stop()

	if r := m.LastRound(); r != nil {
		t.Fatalf("空目标不应产生轮次结果, got %+v", r)
	}
	wmu.Lock()
	defer wmu.Unlock()
	if writes != 0 {
		t.Fatalf("空目标不应落库, 实际 %d 条", writes)
	}
}

// TestMonitorCollectNow 手动采集: 落库回调收到样本, latest/prev 两帧正确
// (第二轮后 prev = 第一轮)。
func TestMonitorCollectNow(t *testing.T) {
	f := startFakeResp(t)
	cfg := Config{Enabled: true, IntervalSec: 60, Targets: []Target{
		{ID: "t1", Name: "假设备", Addr: addrOf(f.pc), Community: "pub", TimeoutMs: 2000},
	}}
	var mu sync.Mutex
	var got []*Sample
	m := New(cfg, func() Config { return cfg }, func(samples []*Sample) {
		mu.Lock()
		got = append(got, samples...)
		mu.Unlock()
	})

	res := m.CollectNow(context.Background())
	if res == nil || res.OKCount != 1 || res.Total != 1 {
		t.Fatalf("应 1/1 成功, got %+v", res)
	}
	if l := m.Latest()["t1"]; l == nil || !l.OK {
		t.Fatal("latest 应记录成功样本")
	}
	if p := m.Prev()["t1"]; p != nil {
		t.Fatalf("第一轮后 prev 应为空, got %+v", p)
	}

	m.CollectNow(context.Background())
	if p := m.Prev()["t1"]; p == nil || !p.OK {
		t.Fatal("第二轮后 prev 应为第一轮样本")
	}
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("两轮应落库 2 条, got %d", n)
	}
}

// TestIfaceRate 速率差分: 正常差分 / 回绕归零 / 缺帧归零。
func TestIfaceRate(t *testing.T) {
	prev := &IfaceSample{In: 1000, Out: 500}
	cur := &IfaceSample{In: 2000, Out: 700}
	in, out := IfaceRate(cur, prev)
	if in != 1000 || out != 200 {
		t.Fatalf("差分错误: in=%d out=%d", in, out)
	}
	// 计数器回绕(设备重启清零): 不报负速率
	cur2 := &IfaceSample{In: 50, Out: 10}
	in2, out2 := IfaceRate(cur2, prev)
	if in2 != 0 || out2 != 0 {
		t.Fatalf("回绕应归零, got in=%d out=%d", in2, out2)
	}
	if in3, out3 := IfaceRate(nil, prev); in3 != 0 || out3 != 0 {
		t.Fatal("缺帧应归零")
	}
}

// TestEffectiveInterval 间隔钳制: 0/过小值回落默认 60s。
func TestEffectiveInterval(t *testing.T) {
	cases := map[int]time.Duration{
		0:   60 * time.Second,
		3:   60 * time.Second,
		30:  30 * time.Second,
		3600: 3600 * time.Second,
	}
	for in, want := range cases {
		if got := EffectiveInterval(in); got != want {
			t.Fatalf("EffectiveInterval(%d) = %v, 期望 %v", in, got, want)
		}
	}
}

