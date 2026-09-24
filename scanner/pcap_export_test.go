package scanner

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// TestBuildPcapLayout 守 pcap 文件格式契约: 魔数/版本/snaplen/链路类型/时间戳/帧长。
// 任何一个字段错位, Wireshark 打开就是乱包或拒收 —— 用户侧表现为"导出的文件打不开",
// 而界面看不出原因, 故用逐字节断言锁死。
func TestBuildPcapLayout(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, 100)
	rec := PacketRecord{
		Seq:    1,
		TimeMS: 1_700_000_000_123,
		Length: 100,
		Raw:    raw,
	}
	data := BuildPcap([]PacketRecord{rec})

	if len(data) != 24+16+100 {
		t.Fatalf("文件长度 = 全局头24 + 记录头16 + 帧100, 实际 %d", len(data))
	}
	if binary.LittleEndian.Uint32(data[0:4]) != 0xa1b2c3d4 {
		t.Errorf("魔数错误: 0x%08x", binary.LittleEndian.Uint32(data[0:4]))
	}
	if binary.LittleEndian.Uint16(data[4:6]) != 2 || binary.LittleEndian.Uint16(data[6:8]) != 4 {
		t.Errorf("版本应为 2.4, 实际 %d.%d",
			binary.LittleEndian.Uint16(data[4:6]), binary.LittleEndian.Uint16(data[6:8]))
	}
	if binary.LittleEndian.Uint32(data[16:20]) != 65535 {
		t.Errorf("snaplen 应为 65535, 实际 %d", binary.LittleEndian.Uint32(data[16:20]))
	}
	if binary.LittleEndian.Uint32(data[20:24]) != 1 {
		t.Errorf("链路类型应为 1(以太网), 实际 %d", binary.LittleEndian.Uint32(data[20:24]))
	}

	sec := binary.LittleEndian.Uint32(data[24:28])
	usec := binary.LittleEndian.Uint32(data[28:32])
	if sec != 1700000000 || usec != 123000 {
		t.Errorf("时间戳错误: sec=%d usec=%d (期望 1700000000/123000)", sec, usec)
	}
	if binary.LittleEndian.Uint32(data[32:36]) != 100 {
		t.Errorf("incl_len 应为 100, 实际 %d", binary.LittleEndian.Uint32(data[32:36]))
	}
	if binary.LittleEndian.Uint32(data[36:40]) != 100 {
		t.Errorf("orig_len 应为 100, 实际 %d", binary.LittleEndian.Uint32(data[36:40]))
	}
	if !bytes.Equal(data[40:], raw) {
		t.Errorf("原始帧字节不一致")
	}
}

// TestBuildPcapSkipsNoRaw 只有 256 字节摘要(Payload)而无完整帧(Raw)的记录
// 不得写入: 截断帧在 Wireshark 里既看不懂又误导排障。
func TestBuildPcapSkipsNoRaw(t *testing.T) {
	recs := []PacketRecord{
		{Seq: 1, TimeMS: 1000, Length: 50, Raw: bytes.Repeat([]byte{1}, 50)},
		{Seq: 2, TimeMS: 2000, Length: 60, Payload: bytes.Repeat([]byte{2}, 60)},
	}
	data := BuildPcap(recs)
	if len(data) != 24+16+50 {
		t.Fatalf("应只写带完整帧的记录, 实际 %d 字节", len(data))
	}
}

// TestBuildPcapEmpty 无报文时仍输出合法的全局头(前端拿到 24 字节而非空响应,
// 与端点的 404 语义配合: 端点先判空, 这里是双保险)。
func TestBuildPcapEmpty(t *testing.T) {
	if got := len(BuildPcap(nil)); got != 24 {
		t.Errorf("空输入应只有 24 字节全局头, 实际 %d", got)
	}
}

// TestPacketLogAppendKeepsFullFrame 环形缓冲留存完整帧(供导出), 且是拷贝而非
// 引用: 上游 readCaptureStream 的帧缓冲会被复用, 引用会让所有记录指向最后一个包。
func TestPacketLogAppendKeepsFullFrame(t *testing.T) {
	log := NewPacketLog()
	frame1 := bytes.Repeat([]byte{0x11}, 200)
	frame2 := bytes.Repeat([]byte{0x22}, 300)
	log.Append(frame1, mustTime(t, 1000))
	// 模拟上游复用同一块内存写第二个包
	copy(frame1, frame2[:len(frame1)])
	log.Append(frame2, mustTime(t, 2000))

	recs := log.Since(0, 0)
	if len(recs) != 2 {
		t.Fatalf("应留 2 条, 实际 %d", len(recs))
	}
	// 第 1 条必须在上游内存被覆盖前拷走 0x11 原文(若误用引用, 这里会是 0x22)
	if len(recs[0].Raw) != 200 || recs[0].Raw[0] != 0x11 {
		t.Errorf("第 1 条 Raw 被上游内存复用污染: len=%d 首字节=%v", len(recs[0].Raw), recs[0].Raw[:4])
	}
	if len(recs[1].Raw) != 300 || recs[1].Raw[0] != 0x22 {
		t.Errorf("第 2 条 Raw 异常: len=%d 首字节=%v", len(recs[1].Raw), recs[1].Raw[:4])
	}
}

func mustTime(t *testing.T, ms int64) time.Time {
	t.Helper()
	return time.UnixMilli(ms).UTC()
}
