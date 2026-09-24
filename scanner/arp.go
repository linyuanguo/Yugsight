package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ethTypeARP  = 0x0806
	ethTypeIPv4 = 0x0800
)

// ArpBinding IP->MAC 绑定记录
type ArpBinding struct {
	IP        string   `json:"ip"`
	MAC       string   `json:"mac"`
	Count     int64    `json:"count"`
	FirstSeen string   `json:"firstSeen"`
	LastSeen  string   `json:"lastSeen"`
	LastOp    string   `json:"lastOp"`
	Flapping  bool     `json:"flapping"`
	FlapMACs  []string `json:"flapMACs"`
}

// CapEvent 检测告警事件
type CapEvent struct {
	Seq      int64  `json:"seq"`
	Time     string `json:"time"`
	Severity string `json:"severity"` // high / medium / low
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Advice   string `json:"advice"`
}

// Capture 抓包会话: 统计 + ARP 绑定 + 环路/风暴/漂移检测
type Capture struct {
	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	started time.Time
	endAt   time.Time
	device  string

	total, arpTotal, arpReqs, arpReplies, ipv4, broadcast int64
	arpTimes                                              []time.Time
	brTimes                                               []time.Time

	bindings map[string]*ArpBinding
	flapMACs map[string]map[string]time.Time // ip -> mac -> lastSeen

	// loop 环路检测器(默认关闭, 由配置开启)。
	//
	// 【为什么拆成独立结构体】旧的 frameDups/ttlSeen 直接内联在这里, 判据与
	// Capture 的状态耦合, 无法脱离抓包单测, 导致"必然误报"的缺陷长期没被发现。
	// 现在判据独立在 loop_detect.go, 可用纯单测覆盖(含"不得误报"的反向断言)。
	loop *LoopDetector

	// pkts 报文环形缓冲: 页面"报文列表"的数据源。
	//
	// 【为什么必须留存报文】原实现只做计数与告警, 不留原始报文, 页面上只有
	// 统计数字 —— 而"谁在跟谁通信、发了什么"才是抓包工具的核心价值。
	pkts *PacketLog

	events   []CapEvent
	lastSeq  int64
	cooldown map[string]time.Time

	// badFrames 解析时触发 panic 被 recover 的畸形帧数。
	// 正常情况下应为 0; 非 0 说明有畸形报文(或解析器仍有越界), 需在界面上可见,
	// 否则"抓包统计少了几个包"这种问题永远不会被发现。
	badFrames int64
}

func NewCapture() *Capture {
	return &Capture{
		bindings: map[string]*ArpBinding{},
		flapMACs: map[string]map[string]time.Time{},
		loop:     NewLoopDetector(loopDetectDefault),
		pkts:     NewPacketLog(),
		cooldown: map[string]time.Time{},
	}
}

// Packets 返回报文缓冲(供 API 拉取列表)。
//
// 返回的是缓冲对象本身(内部有锁), 调用方只应通过它的方法读取, 不要直接碰字段。
func (c *Capture) Packets() *PacketLog { return c.pkts }

// PacketsSince 返回 seq > since 的报文记录
func (c *Capture) PacketsSince(since int64, limit int) []PacketRecord {
	return c.pkts.Since(since, limit)
}

// PacketsTail 返回最近 limit 条报文
func (c *Capture) PacketsTail(limit int) []PacketRecord {
	return c.pkts.Tail(limit)
}

// SetLoopDetect 开启/关闭环路检测(默认关闭, 见 loopDetectDefault)。
//
// 【为什么默认关闭】环路检测的强假设是"同一帧被复制", 在 802.11 重传、抓包点
// 位于汇聚口等场景仍可能产生噪声。而误报的代价很高 —— 一条"疑似环路"告警会让
// 运维去拔网线排查, 比不报警糟糕得多。故按项目规则 5 由配置显式开启。
func (c *Capture) SetLoopDetect(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loop.Reset(on)
}

// LoopDetectEnabled 当前是否开启环路检测
func (c *Capture) LoopDetectEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loop.Enabled()
}

// loopDetectDefault 环路检测默认开关。默认关闭, 由 capture_api 读配置后覆盖。
var loopDetectDefault = false

func (c *Capture) Start() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return
	}
	c.running = true
	c.stopCh = make(chan struct{})
	c.started = time.Now()
	c.endAt = time.Time{}
	c.total, c.arpTotal, c.arpReqs, c.arpReplies, c.ipv4, c.broadcast = 0, 0, 0, 0, 0, 0
	c.badFrames = 0
	c.arpTimes, c.brTimes = nil, nil
	c.bindings = map[string]*ArpBinding{}
	c.flapMACs = map[string]map[string]time.Time{}
	// 保留当前的环路检测开关设置, 只清空统计状态(否则每次开始抓包都会把
	// 用户在配置里的开关重置掉)
	c.loop.Reset(c.loop.Enabled())
	c.pkts.Reset()
	c.events = nil
	c.lastSeq = 0
	c.cooldown = map[string]time.Time{}
}

func (c *Capture) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return
	}
	c.running = false
	c.endAt = time.Now()
	close(c.stopCh)
}

func (c *Capture) StopCh() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopCh
}

func (c *Capture) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// SetDevice 记录使用的适配器
func (c *Capture) SetDevice(d string) {
	c.mu.Lock()
	c.device = d
	c.mu.Unlock()
}

// OnPacket 处理一个以太网帧
//
// 【必须容错: 一个畸形报文不能让整个程序消失】
// 报文来自网卡, 内容完全不受控(攻击者可以故意构造畸形帧)。这里对解析过程加
// recover 兜底 —— 捕包 goroutine 里的 panic 会直接终止整个进程(不是只结束该
// goroutine), 而抓包场景恰恰最容易喂进畸形数据。曾有 onARP 的长度判据少算 2 字节
// 导致越界, 后果是"一点开始抓包主程序就闪退", 且日志无任何痕迹, 极难定位。
// 宁可丢掉这一个包并记一条日志, 也不能让整个服务被一个报文打挂。
func (c *Capture) OnPacket(data []byte) {
	defer func() {
		if r := recover(); r != nil {
			c.mu.Lock()
			c.badFrames++
			c.mu.Unlock()
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	now := time.Now()
	// 报文留存: 解码成结构化记录供页面展示。
	//
	// 【放在长度检查之前】即使是不足 14 字节的残帧也要让 PacketLog 记一笔,
	// 否则"统计里有这个包、列表里却没有"会让人怀疑工具本身不靠谱。
	// PacketLog 内部对畸形帧只计数不 panic(网络来的数据完全不受控)。
	c.pkts.Append(data, now)
	if len(data) < 14 {
		return
	}
	srcMAC := data[6:12]
	dstMAC := data[0:6]
	ether := binary.BigEndian.Uint16(data[12:14])

	isBr := dstMAC[0] == 0xff && dstMAC[1] == 0xff && dstMAC[2] == 0xff &&
		dstMAC[3] == 0xff && dstMAC[4] == 0xff && dstMAC[5] == 0xff
	if isBr {
		c.broadcast++
		c.brTimes = pruneTimes(c.brTimes, now, 5*time.Second)
		c.brTimes = append(c.brTimes, now)
		if len(c.brTimes) > 300 {
			c.pushEvent("medium", "广播风暴",
				fmt.Sprintf("最近 5 秒广播帧 %d 个 (%.0f/秒)", len(c.brTimes), float64(len(c.brTimes))/5),
				"广播帧速率异常, 可能由环路或广播型攻击引起; 建议检查 STP 状态并定位广播源 MAC 所在端口")
		}
	}

	switch ether {
	case ethTypeARP:
		c.onARP(data[14:], now)
	case ethTypeIPv4:
		c.onIPv4(data, srcMAC, now)
	default:
		// Npcap 回环适配器帧无以太网头(前 4 字节地址族 + 裸 IP 包), 走不到
		// ethTypeIPv4 分支。回环流量(ping 本机 IP / 127.0.0.1)只出现在回环
		// 适配器上 —— 只计 IPv4 统计, 否则"抓自己的 ping"场景报文列表有包而
		// 统计显示 IPv4: 0, AI 分析会把"有流量"误判成"没有流量"。
		// 环路检测不套用: 判据基于逐跳 TTL 递减, 对回环流量无意义。
		if off, ok := loopbackIPOffset(data); ok && data[off]&0xf0 == 0x40 {
			c.ipv4++
		}
	}
}

func (c *Capture) onARP(a []byte, now time.Time) {
	// 长度校验必须覆盖**最后访问的字段**, 不是"标准最小长度"。
	//
	// 【曾越界崩溃】原判据是 len(a) < 28, 而下面要读 a[26:30](目标协议地址结束于
	// 下标 30) —— 恰好越界 2 字节。以太网/IPv4 的 ARP 报文正好 28 字节, 于是
	// **几乎每个正常 ARP 包都会触发 slice bounds out of range**。该 panic 发生在
	// readCaptureStream 的读取 goroutine 里且无人 recover, 结果是整个主进程直接消失:
	// 现象为"点开始抓包, 2 秒内程序窗口就没了", 日志里没有任何记录(panic 来不及落盘)。
	//
	// 这里按 "固定头部 + 两个可变的地址长度" 精确计算所需长度:
	// [硬件类型2][协议类型2][硬件长度1][协议长度1][操作码2] = 8
	// [发送方MAC hlen][发送方IP plen][目标MAC hlen][目标IP plen]
	// 标准以太网/IPv4 时 hlen=6, plen=4 => 8+6+4+6+4 = 28。
	if len(a) < 8 {
		return
	}
	hlen := int(a[4]) // 硬件地址长度(以太网为 6)
	plen := int(a[5]) // 协议地址长度(IPv4 为 4)
	if hlen == 0 || plen == 0 || hlen > 16 || plen > 16 {
		return // 异常声明长度: 不解析, 避免后续按畸形长度切分
	}
	// 需要容纳 发送方MAC+发送方IP+目标MAC+目标IP
	if len(a) < 8+2*hlen+2*plen {
		return
	}
	op := binary.BigEndian.Uint16(a[6:8])
	sha := net.HardwareAddr(a[8 : 8+hlen]).String()
	spa := net.IP(a[8+hlen : 8+hlen+plen]).String()
	tha := net.HardwareAddr(a[8+hlen+plen : 8+2*hlen+plen]).String()
	tpa := net.IP(a[8+2*hlen+plen : 8+2*hlen+2*plen]).String()

	c.arpTotal++
	if op == 1 {
		c.arpReqs++
	} else if op == 2 {
		c.arpReplies++
	}
	c.arpTimes = pruneTimes(c.arpTimes, now, 5*time.Second)
	c.arpTimes = append(c.arpTimes, now)
	if len(c.arpTimes) > 100 {
		c.pushEvent("high", "ARP 风暴",
			fmt.Sprintf("最近 5 秒 ARP 报文 %d 个 (%.0f/秒), 阈值 100/5s", len(c.arpTimes), float64(len(c.arpTimes))/5),
			"ARP 报文速率严重超限, 典型原因: 二层环路 / ARP 欺骗攻击 / 网卡故障; 建议立即定位高频源 MAC 对应交换机端口并隔离, 同时检查 STP")
	}

	// 绑定表: 请求方 SPA->SHA; 应答中的目标方 TPA->THA
	c.updateBinding(spa, sha, opName(op), now)
	if op == 2 && tha != "00:00:00:00:00:00" {
		c.updateBinding(tpa, tha, "reply", now)
	}
}

func opName(op uint16) string {
	if op == 1 {
		return "request"
	}
	return "reply"
}

func (c *Capture) updateBinding(ip, mac, op string, now time.Time) {
	b := c.bindings[ip]
	if b == nil {
		b = &ArpBinding{IP: ip, MAC: mac, FirstSeen: now.Format("15:04:05")}
		c.bindings[ip] = b
	}
	b.Count++
	b.LastSeen = now.Format("15:04:05")
	b.LastOp = op

	// 漂移检测: 60 秒窗口内同一 IP 出现多个 MAC
	m := c.flapMACs[ip]
	if m == nil {
		m = map[string]time.Time{}
		c.flapMACs[ip] = m
	}
	m[mac] = now
	for k, t := range m {
		if now.Sub(t) > 60*time.Second {
			delete(m, k)
		}
	}
	if len(m) > 1 {
		var ss []string
		for k := range m {
			ss = append(ss, k)
		}
		sort.Strings(ss)
		b.Flapping = true
		b.FlapMACs = ss
		c.pushEvent("high", "ARP 地址漂移",
			fmt.Sprintf("%s 在 60s 内出现 %d 个 MAC: %s", ip, len(ss), strings.Join(ss, ", ")),
			"同一 IP 对应多个 MAC, 可能原因: 私接设备 / ARP 欺骗 / VLAN 或 Trunk 配置错误; 建议: 在交换机上用 MAC 地址表定位各 MAC 端口, 开启 DHCP Snooping + DAI + 动态 ARP 检测")
	} else {
		b.Flapping = false
	}
}

// onIPv4 IPv4 帧处理。
//
// 【环路检测为何在此处只做转发】判据全部在 LoopDetector 里(loop_detect.go),
// 这里只负责统计与事件推送。旧实现把判据内联在这个函数里, 用的是
// "src->dst#IP-ID 凑够 3 种 TTL" 和"只哈希 IP 头的帧指纹"两套必然误报的规则
// (IP-ID 为 0 的包会撞桶; 同连接的包指纹全等), 实测一条正常 TCP 流就能双双触发。
func (c *Capture) onIPv4(data []byte, _ []byte, now time.Time) {
	if len(data) < 34 {
		return
	}
	c.ipv4++
	ihl := int(data[14]&0x0f) * 4
	if len(data) < 14+ihl {
		return
	}
	// 环路检测(默认关闭): 命中才推事件
	for _, a := range c.loop.ObserveIPv4(data, now) {
		c.pushEvent(a.Severity, a.Title, a.Detail, a.Advice)
	}
}

func (c *Capture) pushEvent(sev, title, detail, advice string) {
	// 同标题 60 秒内不重复告警
	if t, ok := c.cooldown[title]; ok && time.Since(t) < 60*time.Second {
		return
	}
	c.cooldown[title] = time.Now()
	c.lastSeq++
	c.events = append(c.events, CapEvent{
		Seq:      c.lastSeq,
		Time:     time.Now().Format("15:04:05"),
		Severity: sev,
		Title:    title,
		Detail:   detail,
		Advice:   advice,
	})
	if len(c.events) > 200 {
		c.events = c.events[len(c.events)-200:]
	}
}

func pruneTimes(ts []time.Time, now time.Time, w time.Duration) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) > w {
		i++
	}
	return ts[i:]
}

// elapsed 抓包时长(秒)
func (c *Capture) elapsed() float64 {
	end := time.Now()
	if !c.running && !c.endAt.IsZero() {
		end = c.endAt
	}
	if c.started.IsZero() || end.Before(c.started) {
		return 0
	}
	return end.Sub(c.started).Seconds()
}

// Stats 当前统计
func (c *Capture) Stats() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	dur := c.elapsed()
	return map[string]any{
		"running":     c.running,
		"device":      c.device,
		"durationSec": int64(dur),
		"total":       c.total,
		"pps":         pps(c.total, dur),
		"arpTotal":    c.arpTotal,
		"arpReqs":     c.arpReqs,
		"arpReplies":  c.arpReplies,
		"arpPps":      pps(c.arpTotal, dur),
		"ipv4":        c.ipv4,
		"broadcast":   c.broadcast,
		"bindings":    len(c.bindings),
		// 畸形帧计数: 正常情况下恒为 0。非 0 说明有报文让解析器抛了异常(被 recover
		// 兜住), 需要在界面上可见 —— 否则"统计比实际少几个包"永远不会被发现。
		"badFrames": c.badFrames,
		// 报文留存的容量与条数: 前端据此提示"缓冲已满, 只保留最近 N 条"
		"pktBuffered": c.pkts.Len(),
		"pktCapacity": pktLogCap,
		"pktTotal":    c.pkts.Count(),
		// 解码失败被列表跳过的条数(与 badFrames 口径不同: 这里是"帧合法但内容
		// 无法识别", 如截断帧)
		"pktUndecodable": c.pkts.Filtered(),
		"loopDetect":     c.loop.Enabled(),
	}
}

func pps(n int64, dur float64) float64 {
	if dur < 1 {
		return 0
	}
	return float64(n) / dur
}

// EventsSince 返回 seq 大于 since 的事件
func (c *Capture) EventsSince(since int64) []CapEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []CapEvent
	for _, e := range c.events {
		if e.Seq > since {
			out = append(out, e)
		}
	}
	return out
}

// Bindings 返回绑定表(按次数降序, 最多 200 条)
func (c *Capture) Bindings() []ArpBinding {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bindingsLocked()
}

func (c *Capture) bindingsLocked() []ArpBinding {
	var out []ArpBinding
	for _, b := range c.bindings {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// Analysis 内置智能分析引擎(离线规则专家系统), 输出运维可读报告
func (c *Capture) Analysis() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var sb strings.Builder
	dur := c.elapsed()
	if dur < 1 {
		dur = 1
	}
	sb.WriteString("===== Yugsight 抓包智能分析报告 =====\n")
	sb.WriteString(fmt.Sprintf("抓包时长: %.0fs | 总报文: %d | 平均速率: %.1f pps\n", dur, c.total, float64(c.total)/dur))
	sb.WriteString(fmt.Sprintf("ARP 报文: %d (请求 %d / 应答 %d) | ARP 速率: %.1f/s | IPv4: %d | 广播帧: %d\n",
		c.arpTotal, c.arpReqs, c.arpReplies, float64(c.arpTotal)/dur, c.ipv4, c.broadcast))

	if len(c.bindings) > 0 {
		sb.WriteString("\n【ARP 绑定表】(按报文量排序, 最多 30 条)\n")
		bs := c.bindingsLocked()
		if len(bs) > 30 {
			bs = bs[:30]
		}
		for _, b := range bs {
			line := fmt.Sprintf("  %-16s -> %s  (%d 次, 最近 %s)", b.IP, b.MAC, b.Count, b.LastSeen)
			if b.Flapping {
				line += "  [!漂移: " + strings.Join(b.FlapMACs, ", ") + "]"
			}
			sb.WriteString(line + "\n")
		}
	}

	sb.WriteString("\n【安全检测告警】\n")
	if len(c.events) == 0 {
		sb.WriteString("  未检测到异常。\n")
	} else {
		for _, e := range c.events {
			sb.WriteString(fmt.Sprintf("  [%s] %s %s\n", sevName(e.Severity), e.Title, e.Detail))
		}
	}

	sb.WriteString("\n【智能分析结论】\n")
	if len(c.events) == 0 {
		sb.WriteString(fmt.Sprintf("  本次抓包未见 ARP 风暴 / 二层环路 / ARP 地址漂移特征。ARP 速率 %.1f/s 在正常范围(经验阈值 <100/s)。\n", float64(c.arpTotal)/dur))
	} else {
		high := 0
		for _, e := range c.events {
			if e.Severity == "high" {
				high++
			}
		}
		if high > 0 {
			sb.WriteString(fmt.Sprintf("  检测到 %d 项高危异常, 网络存在活跃问题, 建议立即按下方步骤排查。\n", high))
		} else {
			sb.WriteString("  检测到中低危异常, 建议结合现场拓扑确认。\n")
		}
	}

	sb.WriteString("\n【运维排查建议】\n")
	if hasTitle(c.events, "ARP 风暴") || hasTitle(c.events, "广播风暴") {
		sb.WriteString("  1. 在交换机上执行 MAC 地址表查询, 定位高频源 MAC 所在端口: display mac-address-table dynamic | include <MAC>\n")
		sb.WriteString("  2. 隔离该端口, 观察风暴是否消失; 检查该端口链路对端设备(网卡/交换机)是否故障\n")
		sb.WriteString("  3. 检查 STP 状态: display stp brief, 确认无端口频繁在 Listening/Learning 间震荡\n")
	}
	if hasTitle(c.events, "疑似三层环路") || hasTitle(c.events, "疑似二层环路(重复帧)") {
		sb.WriteString("  4. 环路处置: 物理检查网线是否误插成环; 确认 STP 生效, 开启 BPDU Guard / Root Guard / 环路保护\n")
		sb.WriteString("  5. 对确认环路端口执行 err-disable, 修复后 no shutdown 恢复\n")
	}
	if hasTitle(c.events, "ARP 地址漂移") {
		sb.WriteString("  6. 对漂移 IP 的每个 MAC 分别定位端口, 核查是否存在私接设备 / 伪造 ARP 的主机\n")
		sb.WriteString("  7. 配置 DHCP Snooping + DAI + 动态 ARP 检测, 并在核心交换配置 ARP 绑定防欺骗\n")
	}
	if len(c.events) == 0 {
		sb.WriteString("  网络状态良好。建议: 保持本工具定期巡检, 抓包时长建议 >=5 分钟以获得准确速率统计。\n")
	}
	sb.WriteString("  注: 本报告由内置规则引擎生成, 阈值为经验值, 请结合网络规模与拓扑人工确认。\n")
	return sb.String()
}

func hasTitle(events []CapEvent, t string) bool {
	for _, e := range events {
		if e.Title == t {
			return true
		}
	}
	return false
}

func sevName(s string) string {
	switch s {
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	}
	return s
}
