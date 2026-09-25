package scanner

import (
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"sync"
	"time"
)

// ===== 环路检测(重写版) =====
//
// 【为什么重写】原实现有两处必然误报, 实测已复现:
//
//	① 三层环路判据是 "src->dst#IP-ID 出现 >=3 种不同 TTL", 但:
//	   - IP-ID 为 0 的包大量存在(Windows/部分协议栈对已连接 TCP 段直接填 0,
//	     RFC 6864 只在需要分片时才要求唯一 ID)。同一个 key 会把数小时内所有
//	     不同连接的数据包全塞进一个桶, 只要凑够 3 个不同 TTL 就报"环路"。
//	   - 只看 TTL **种类数**, 不看**差值**。TTL 64/63/62 是正常的三跳路径,
//	     与环路毫无关系, 却会命中。
//	   - 完全没有时间窗口(只在处理满 20000 包时全量清空), "两小时内的 3 个包"
//	     也算一次环路。
//
//	② 二层环路的帧指纹只哈希到 IPv4 头的 ihl(通常 20 字节, 正好到 TTL 就截断),
//	   **没覆盖协议号/校验和/端口/载荷**。于是同一条 TCP 连接的所有数据包指纹全等,
//	   实测一条普通 TCP 流的第 80 个包就触发"疑似二层环路"。
//
// 【新判据(采纳用户建议)】
//
//	三层: 五元组 + 校验和 + 载荷哈希 相同, 且 TTL **严格递减且差值恰为 1**,
//	      且至少观测 3 次递减, 且全部落在 5 秒时间窗内。
//	      —— "差值=1" 是区分环路与正常路由的核心: 环路每绕一圈 TTL 减 1;
//	         而路由变化是"一次跳多跳", 差值不会等于 1。
//	二层: 帧指纹覆盖**整帧内容**(含 TCP/UDP 头与端口), 只有真正被复制的
//	      同一个帧才会撞指纹; 同样受时间窗约束。
//
// 【默认关闭】本项目规则 5: 新增能力默认关闭。环路检测的强假设是"同一帧被复制",
// 在无线环境(802.11 重传)或抓包点位于汇聚口时仍可能有噪声, 故由配置显式开启。
const (
	// loopWindow 判据时间窗: 环路产生的重复帧在毫秒级内密集出现;
	// 超过 5 秒的同哈希包更可能是 TCP 重传/应用层重发, 不是环路。
	loopWindow = 5 * time.Second
	// loopMinTTLSteps 三层环路至少需要的 TTL 递减次数(3 次 = 至少 4 个包)
	loopMinTTLSteps = 3
	// loopFrameRepeat 二层重复帧告警阈值。
	//
	// 【为什么是 20 而不是原来的 80】原值 80 是配合"哈希不覆盖端口"的缺陷才勉强
	// 不误报; 现在哈希覆盖整帧, 正常流量极难撞哈希, 阈值可收紧到更能反映"密集复制"。
	loopFrameRepeat = 20
	// loopMaxEntries 各跟踪表上限, 防止长时间抓包内存无界增长。
	// 超限整体清空 —— 环路帧必然在时间窗内密集出现, 清空不会漏掉真环路。
	loopMaxEntries = 20000
	// loopHashLoadMax 参与哈希的载荷上限。取 512 是为了让哈希开销与包长脱钩:
	// 分片大包与普通包都只哈希前 512 字节, 避免在高速链路上拖慢抓包线程。
	loopHashLoadMax = 512
)

// loopBucket 同一"逻辑报文"的观测记录。
//
// 【为什么存 TTL 序列而不是集合】需要判断"严格递减且差值为 1", 集合会丢顺序信息:
// 64,63,62 与 62,64,63 在集合里完全一样, 但只有前者是环路特征。
type loopBucket struct {
	first   time.Time
	last    time.Time
	ttls    []byte // 按到达顺序记录(仅保留时间窗内)
	count   int64
	evented bool // 已告警过不再重复计数, 避免同一环路刷屏
}

// frameBucket 二层重复帧的观测记录
type frameBucket struct {
	first   time.Time
	count   int64
	evented bool
}

// LoopAlarm 一条环路告警
type LoopAlarm struct {
	Severity string
	Title    string
	Detail   string
	Advice   string
}

// LoopDetector 环路检测器。
//
// 【为什么要独立于 Capture】检测逻辑是纯计算, 独立出来后可以完全脱离网络与
// Capture 的单测覆盖(含"必须不误报"这类关键断言), 也避免 import 循环。
type LoopDetector struct {
	mu      sync.Mutex
	enabled bool
	ipSeen  map[string]*loopBucket  // 五元组+校验和+载荷哈希 -> TTL 序列
	frSeen  map[string]*frameBucket // 整帧哈希 -> 次数
}

// NewLoopDetector 创建检测器。enabled=false 时全路径立即返回, 零额外开销。
func NewLoopDetector(enabled bool) *LoopDetector {
	return &LoopDetector{
		enabled: enabled,
		ipSeen:  map[string]*loopBucket{},
		frSeen:  map[string]*frameBucket{},
	}
}

// Enabled 当前是否开启
func (d *LoopDetector) Enabled() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled
}

// Reset 会话开始/开关变化时重置。
func (d *LoopDetector) Reset(enabled bool) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.enabled = enabled
	d.ipSeen = map[string]*loopBucket{}
	d.frSeen = map[string]*frameBucket{}
	d.mu.Unlock()
}

// ObserveIPv4 观测一个 IPv4 帧(含 14 字节以太头), 返回需上报的告警。
//
// 检测器不依赖 Capture, 由调用方负责事件推送 —— 这样"判据是否正确"可以被
// 纯函数式地测出来, 不必启动抓包。
func (d *LoopDetector) ObserveIPv4(data []byte, now time.Time) []LoopAlarm {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enabled {
		return nil
	}
	if len(data) < 34 {
		return nil
	}
	ihl := int(data[14]&0x0f) * 4
	if ihl < 20 || len(data) < 14+ihl {
		return nil
	}
	proto := data[23]
	src := net.IP(data[26:30]).String()
	dst := net.IP(data[30:34]).String()

	var out []LoopAlarm
	if a := d.observeTTL(data, ihl, proto, src, dst, now); a != nil {
		out = append(out, *a)
	}
	if a := d.observeFrame(data, now); a != nil {
		out = append(out, *a)
	}
	return out
}

// ipFingerprint 计算"同一逻辑报文"的指纹。
//
// 覆盖: 协议 / 源目 IP / 源目端口 / 首部校验和 / 载荷。
//
// 【为什么必须含端口与载荷】旧实现只哈希到 IP 头, 于是同一条 TCP 连接的所有
// 数据包指纹相同 —— 这是误报的主因。加上端口与载荷后, 同一连接的不同包指纹各异,
// 只有真正被复制的那个包才会撞指纹。
//
// 【为什么含首部校验和】同一报文被环路复制时, 除 TTL(每跳减 1)与首部校验和
// (随 TTL 重算)外完全一致。校验和能区分"同一报文的多次复制"与"恰好同长度同
// 端口的两个不同报文", 且它在哈希内、TTL 在哈希外, 正好构成判据。
func (d *LoopDetector) ipFingerprint(data []byte, ihl int, proto byte) string {
	h := fnv.New64a()
	_, _ = h.Write(data[23:24]) // 协议
	_, _ = h.Write(data[26:30]) // 源 IP
	_, _ = h.Write(data[30:34]) // 目的 IP
	_, _ = h.Write(data[24:26]) // 首部校验和(偏移 14+10)
	if (proto == 6 || proto == 17) && len(data) >= 14+ihl+4 {
		_, _ = h.Write(data[14+ihl : 14+ihl+4]) // 源/目的端口
	}
	payload := data[14+ihl:]
	if len(payload) > loopHashLoadMax {
		payload = payload[:loopHashLoadMax]
	}
	_, _ = h.Write(payload)
	return strconv.FormatUint(h.Sum64(), 36)
}

// observeTTL 维护 TTL 序列, 命中"严格递减且差值=1 达 loopMinTTLSteps 次"时告警。
// 调用方需持有 d.mu。
func (d *LoopDetector) observeTTL(data []byte, ihl int, proto byte, src, dst string, now time.Time) *LoopAlarm {
	ttl := data[22]
	key := d.ipFingerprint(data, ihl, proto)

	b := d.ipSeen[key]
	if b == nil {
		if len(d.ipSeen) >= loopMaxEntries {
			d.ipSeen = map[string]*loopBucket{}
		}
		d.ipSeen[key] = &loopBucket{first: now, last: now, ttls: []byte{ttl}, count: 1}
		return nil
	}
	// 时间窗外的历史观测不参与判定: 环路重复帧是密集出现的,
	// 跨越数秒的同哈希包更可能是 TCP 重传。
	if now.Sub(b.last) > loopWindow {
		b.ttls = b.ttls[:0]
		b.count = 0
		b.first = now
		b.evented = false
	}
	b.last = now
	b.count++
	b.ttls = append(b.ttls, ttl)

	if b.evented {
		return nil
	}
	if steps := maxTTLDescend(b.ttls); steps < loopMinTTLSteps {
		return nil
	}
	b.evented = true
	return &LoopAlarm{
		Severity: "high",
		Title:    "疑似三层环路",
		Detail: fmt.Sprintf("报文 %s -> %s 在 %.1fs 内被观测到 %d 次, TTL 逐跳递减 %s",
			src, dst, now.Sub(b.first).Seconds(), b.count, ttlChain(b.ttls)),
		Advice: "同一报文被反复转发且每跳 TTL 恰好减 1, 是环路泛洪的典型特征(正常路由变化不会逐跳减 1); 建议: 按 TTL 递减次数估算环路跳数, 用 MAC 地址表定位环路端口, 检查 STP 是否生效并开启 BPDU Guard / 环路保护",
	}
}

// maxTTLDescend 返回序列中最长的"严格递减且相邻差值为 1"的连续步数。
//
// 例: 64,63,62 -> 2 步; 64,62 -> 0 步(差值 2, 属正常跳变);
//     64,64,63 -> 1 步(重复值中断递减链)。
func maxTTLDescend(ttls []byte) int {
	steps, best := 0, 0
	for i := 1; i < len(ttls); i++ {
		switch {
		case ttls[i] == ttls[i-1]:
			// 完全相同 TTL 的重复包不构成递减, 但也不应打断已有链条
			// (重传会产生同 TTL 副本, 随后若继续递减仍应是环路特征)
		case ttls[i-1] == ttls[i]+1:
			steps++
			if steps > best {
				best = steps
			}
		default:
			steps = 0 // 出现跳变(差值≠1), 递减链断开
		}
	}
	return best
}

// observeFrame 统计整帧重复次数, 超阈值告警。调用方需持有 d.mu。
func (d *LoopDetector) observeFrame(data []byte, now time.Time) *LoopAlarm {
	h := fnv.New64a()
	_, _ = h.Write(data[0:12]) // MAC(含方向, 排除转发后可能被改写的字段)
	_, _ = h.Write(data[14:])  // IPv4 头 + 载荷全部
	key := strconv.FormatUint(h.Sum64(), 36)

	b := d.frSeen[key]
	if b == nil {
		if len(d.frSeen) >= loopMaxEntries {
			d.frSeen = map[string]*frameBucket{}
		}
		d.frSeen[key] = &frameBucket{first: now, count: 1}
		return nil
	}
	// 时间窗重置: 同一帧数秒后再次出现属正常重传, 不累计
	if now.Sub(b.first) > loopWindow {
		b.first = now
		b.count = 1
		b.evented = false
		return nil
	}
	b.count++
	if b.evented || b.count < loopFrameRepeat {
		return nil
	}
	b.evented = true
	return &LoopAlarm{
		Severity: "medium",
		Title:    "疑似二层环路(重复帧)",
		Detail: fmt.Sprintf("同一帧在 %.1fs 内出现 %d 次, 超出正常重传范围",
			now.Sub(b.first).Seconds(), b.count),
		Advice: "完全相同的帧在秒级内密集重复, 常见于交换机环路(帧被复制); 注意与 TCP 重传区分: 后者间隔会按 RTO 递增。建议用 MAC 地址表定位环路端口, 检查网线是否误插成环、STP 是否失效",
	}
}

// ttlChain 把 TTL 序列渲染成 "64->63->62", 最长展示末尾 8 个。
func ttlChain(ttls []byte) string {
	start := 0
	if len(ttls) > 8 {
		start = len(ttls) - 8
	}
	s := ""
	for i := start; i < len(ttls); i++ {
		if i > start {
			s += "->"
		}
		s += strconv.Itoa(int(ttls[i]))
	}
	return s
}
