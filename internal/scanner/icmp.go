package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// errICMP 表示 ICMP 原始套接字不可用(通常因为未以管理员身份运行)
var errICMP = fmt.Errorf("ICMP 不可用(需要管理员权限)")

// icmpState 共享的 ICMPv4 发送/接收状态。
// 采用单读协程 + seq 分发, 避免多协程竞争同一个原始套接字导致的应答错配。
type icmpState struct {
	mu        sync.Mutex
	init      bool
	ok        bool
	conn      net.PacketConn
	id        uint16
	waiters   map[uint16]chan int64 // seq -> 等待 RTT(ms) 的通道
	sendTimes map[uint16]time.Time  // seq -> 发送时间
}

var gICMP = &icmpState{
	waiters:   make(map[uint16]chan int64),
	sendTimes: make(map[uint16]time.Time),
}

// InitICMP 尝试打开共享 ICMPv4 原始套接字并启动读取协程。
// 返回 true 表示可用, false 表示不可用(需要管理员权限)。
func InitICMP() bool {
	gICMP.mu.Lock()
	defer gICMP.mu.Unlock()
	if gICMP.init {
		return gICMP.ok
	}
	gICMP.init = true
	gICMP.id = uint16(os.Getpid() & 0xffff)
	conn, err := net.ListenPacket("ip4:1", "0.0.0.0")
	if err != nil {
		gICMP.ok = false
		return false
	}
	gICMP.conn = conn
	gICMP.ok = true
	go gICMP.readLoop()
	return true
}

// readLoop 单一读协程: 读取所有 ICMP 应答, 按 seq 分发给对应等待者
func (s *icmpState) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if from == nil || n < 8 {
			continue
		}
		// 不同平台读回的数据可能带 IP 头, 也可能直接是 ICMP 数据
		data := buf
		if buf[0]&0xf0 == 0x40 { // 首字节为 IP 头(version 4)
			iphdr := int(buf[0]&0x0f) * 4
			if iphdr < 20 || n < iphdr+8 {
				continue
			}
			data = buf[iphdr:]
		}
		if data[0] != 0 { // 0 = echo reply
			continue
		}
		id := binary.BigEndian.Uint16(data[4:])
		seq := binary.BigEndian.Uint16(data[6:])
		if id != s.id {
			continue
		}
		s.mu.Lock()
		ch, okWait := s.waiters[seq]
		var rtt int64
		if okWait {
			if t, okT := s.sendTimes[seq]; okT {
				rtt = time.Since(t).Milliseconds()
			}
			delete(s.waiters, seq)
			delete(s.sendTimes, seq)
		}
		s.mu.Unlock()
		if okWait {
			select {
			case ch <- rtt:
			default:
			}
		}
	}
}

// PingICMP 向 ip 发送一个 ICMPv4 echo 请求并等待应答。
// seq 必须在本次扫描内唯一。返回是否存活、RTT(毫秒)、错误。
func PingICMP(ip string, seq uint16, timeout time.Duration) (bool, int64, error) {
	if !InitICMP() {
		return false, 0, errICMP
	}
	gICMP.mu.Lock()
	if !gICMP.ok {
		gICMP.mu.Unlock()
		return false, 0, errICMP
	}
	ch := make(chan int64, 1)
	gICMP.waiters[seq] = ch
	gICMP.sendTimes[seq] = time.Now()
	gICMP.mu.Unlock()

	cleanup := func() {
		gICMP.mu.Lock()
		delete(gICMP.waiters, seq)
		delete(gICMP.sendTimes, seq)
		gICMP.mu.Unlock()
	}
	defer cleanup()

	dest, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false, 0, err
	}

	const payload = 32
	pkt := make([]byte, 8+payload)
	pkt[0] = 8 // echo request
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[4:], gICMP.id)
	binary.BigEndian.PutUint16(pkt[6:], seq)
	for i := 8; i < len(pkt); i++ {
		pkt[i] = byte(i)
	}
	binary.BigEndian.PutUint16(pkt[2:], icmpChecksum(pkt))

	gICMP.mu.Lock()
	gICMP.conn.SetWriteDeadline(time.Now().Add(timeout))
	_, werr := gICMP.conn.WriteTo(pkt, dest)
	gICMP.mu.Unlock()
	if werr != nil {
		return false, 0, werr
	}

	select {
	case rtt := <-ch:
		return true, rtt, nil
	case <-time.After(timeout):
		return false, 0, nil
	}
}

// icmpChecksum 计算 ICMP 校验和(16 位反码和)
func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}
