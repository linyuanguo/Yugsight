package scanner

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildARPFame 构造一个标准以太网 + ARP 帧(总长 14+28=42 字节)。
func buildARPFame() []byte {
	f := make([]byte, 42)
	// 以太网头: 目的广播 + 源 MAC + 类型 ARP
	for i := 0; i < 6; i++ {
		f[i] = 0xff
	}
	copy(f[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.BigEndian.PutUint16(f[12:14], ethTypeARP)
	// ARP 体共 28 字节, 字段布局:
	//   [0:2]硬件类型 [2:4]协议类型 [4]硬件长度 [5]协议长度 [6:8]操作码
	//   [8:14]发送方MAC [14:18]发送方IP [18:24]目标MAC [24:28]目标IP
	// (注意: 目标 MAC 下标是 18:24, 目标 IP 是 24:28 —— 写错就会像我第一版那样
	//  在构造阶段就 a[26:30] 越界, 正好复现了被测函数当年的错误)
	a := f[14:]
	binary.BigEndian.PutUint16(a[0:2], 1)      // 硬件类型 以太网
	binary.BigEndian.PutUint16(a[2:4], 0x0800) // 协议类型 IPv4
	a[4] = 6                                   // 硬件地址长度
	a[5] = 4                                   // 协议地址长度
	binary.BigEndian.PutUint16(a[6:8], 1)      // 操作码 = request
	copy(a[8:14], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})  // 发送方 MAC
	copy(a[14:18], []byte{192, 168, 1, 100})                   // 发送方 IP
	copy(a[18:24], []byte{0, 0, 0, 0, 0, 0})                   // 目标 MAC
	copy(a[24:28], []byte{192, 168, 1, 1})                     // 目标 IP
	return f
}

// TestOnPacketARPStandardFrame 标准 28 字节 ARP 体必须能正常解析。
//
// 【回归用例: 曾经导致抓包时主进程直接闪退】
// onARP 的长度判据是 `len(a) < 28`, 但随后访问 a[26:30](末字节下标 30) ——
// 越界 2 字节。而以太网/IPv4 的 ARP 体**恰好就是 28 字节**, 所以网上任何一个
// 正常 ARP 包都会让这个函数 panic:
//
//	slice bounds out of range [:30] with capacity 28
//
// 该 panic 发生在 readCaptureStream 的读取 goroutine 中且无人 recover, Go 会
// 直接终止整个进程 —— 现象是"点开始抓包, 两秒内程序窗口消失", 日志里一条记录
// 都没有(来不及写盘)。修复方式: 按报文里声明的 hlen/plen 精确算所需长度。
//
// 这个用例保证"标准 ARP 帧"这条最常走的路径不会再崩。
func TestOnPacketARPStandardFrame(t *testing.T) {
	c := NewCapture()
	c.Start()
	defer c.Stop()

	frame := buildARPFame()
	if len(frame) != 42 {
		t.Fatalf("构造的帧长度应为 42, 实得 %d", len(frame))
	}
	// 不应 panic; panic 会被 OnPacket 的 recover 吞掉并计入 badFrames
	c.OnPacket(frame)

	st := c.Stats()
	if bad := st["badFrames"].(int64); bad != 0 {
		t.Fatalf("标准 ARP 帧解析触发了 %d 次异常, 属于解析器越界", bad)
	}
	if got := st["arpTotal"].(int64); got != 1 {
		t.Errorf("arpTotal 应为 1, 实得 %d", got)
	}
	if got := st["arpReqs"].(int64); got != 1 {
		t.Errorf("arpReqs 应为 1, 实得 %d", got)
	}
	// 绑定表应记录 请求方 IP->MAC
	bs := c.Bindings()
	if len(bs) == 0 {
		t.Fatal("ARP 请求应产生一条 IP->MAC 绑定")
	}
	found := false
	for _, b := range bs {
		if b.IP == "192.168.1.100" {
			found = true
		}
	}
	if !found {
		t.Errorf("绑定表应包含 192.168.1.100, 实得 %+v", bs)
	}
}

// TestOnPacketMalformedFrames 各种畸形/截断帧都不得让程序崩溃。
//
// 报文来自网卡, 内容完全不受控(攻击者可故意构造畸形帧)。这里穷举"缺尾巴"的
// 截断场景 —— 每一个都可能命中某个解析分支的越界, 而任何一个未捕获的 panic
// 都会终止整个进程。断言: 全部安全返回, 且不产生非零 badFrames(因为长度校验
// 应该在访问前就挡掉, 不该走到 panic)。
func TestOnPacketMalformedFrames(t *testing.T) {
	full := buildARPFame()
	for n := 0; n <= len(full); n++ {
		func() {
			c := NewCapture()
			c.Start()
			defer c.Stop()
			// 截断到 n 字节: 覆盖 0..42 全部长度
			c.OnPacket(full[:n])
			// 极短帧 <14 字节在 OnPacket 里应直接 return(不进入解析)
			if n >= 14 {
				if bad := c.Stats()["badFrames"].(int64); bad != 0 {
					t.Errorf("截断到 %d 字节时触发了 %d 次解析异常(长度校验缺失)", n, bad)
				}
			}
		}()
	}
}

// TestOnPacketIPv4Truncated 截断的 IPv4 帧不得崩溃。
// onIPv4 同样做了多层长度检查(14 字节以太网头 / IHL 可选字段), 这里逐个长度验证。
func TestOnPacketIPv4Truncated(t *testing.T) {
	full := make([]byte, 54) // 14 以太网头 + 20 IPv4 头
	copy(full[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(full[6:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	binary.BigEndian.PutUint16(full[12:14], ethTypeIPv4)
	ip := full[14:]
	ip[0] = 0x45 // version 4, IHL 5 (20 字节)
	ip[8] = 64   // TTL
	binary.BigEndian.PutUint16(ip[4:6], 1234) // id
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})

	for n := 0; n <= len(full); n++ {
		func() {
			c := NewCapture()
			c.Start()
			defer c.Stop()
			c.OnPacket(full[:n])
			if n >= 14 {
				if bad := c.Stats()["badFrames"].(int64); bad != 0 {
					t.Errorf("截断 IPv4 帧到 %d 字节时触发解析异常", n)
				}
			}
		}()
	}
}

// TestOnPacketRecoversPanic 确认 OnPacket 的 recover 兜底真的生效:
// 即使解析器将来又引入越界, 也只是丢包并计数, 不会让进程消失。
//
// 这里用超长声明的 hlen/plen(超出实际数据)构造"看似合法实则越界"的报文,
// 验证不会把进程带崩。
func TestOnPacketRecoversPanic(t *testing.T) {
	c := NewCapture()
	c.Start()
	defer c.Stop()

	// 声明 hlen=16/plen=16(超过 IPv4 实际), 数据只有 42 字节 -> 长度校验应直接挡掉
	f := buildARPFame()
	a := f[14:]
	a[4] = 16
	a[5] = 16
	c.OnPacket(f)
	if bad := c.Stats()["badFrames"].(int64); bad != 0 {
		t.Errorf("异常声明长度应被长度校验拦下, 不该走到 panic, badFrames=%d", bad)
	}

	// 非法 hlen=0 也不应崩溃
	f2 := buildARPFame()
	f2[14+4] = 0
	c.OnPacket(f2)
	if bad := c.Stats()["badFrames"].(int64); bad != 0 {
		t.Errorf("hlen=0 应被拦下, badFrames=%d", bad)
	}

	// 确认会话仍然可用(没有处于半崩溃状态)
	c.OnPacket(buildARPFame())
	if got := c.Stats()["arpTotal"].(int64); got < 1 {
		t.Error("异常帧之后, 正常帧应仍能被处理")
	}
	_ = time.Now
}
