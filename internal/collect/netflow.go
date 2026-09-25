// netflow.go NetFlow v5 / IPFIX 流量接收 —— 网络侧。
//
// 形态: 被动接收(中心端监听 UDP, 交换机/防火墙导出流量到本端), 不是主动
// 轮询 —— 引擎对账时按"有启用的 netflow 任务就保证监听在"维护 UDP 连接,
// 任务到期时取走一个聚合窗口的流量统计(白名单对监听任务不判定, 见
// engine.go 的说明: 接收端不是采集对象)。
//
// 协议口径:
//   - NetFlow v5: 24 字节头 + 48 字节/记录(RFC 3954);
//   - IPFIX:     16 字节消息头 + 模板集/数据集(RFC 7011), 按模板解码。
//
// 速率口径: v5 的 InBytes/InPkts 是"流生命周期累计计数器", 必须对同一流
// 做两次差分才得到区间流量; 本实现维护每流缓存(上次值 → 差分), 计数器
// 回绕(小于上次值)归 0 不报负值。IPFIX 记录值即"导出区间聚合", 直接累加。
//
// 资源边界: 每流缓存上限 flowCacheCap(20000 条), 超限的新流只计数不入
// 缓存 —— 流量采集是监控功能, 不能因为一个攻击者打满流表把中心端内存吃光。
package collect

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	Register(ProtoNetFlow, collectNetFlow)
}

const flowCacheCap = 20000

// flowStat 单流累计(差分基准 + 本窗口增量)。
type flowStat struct {
	srcIP, dstIP string
	sport, dport int
	proto        string
	lastBytes    uint64 // v5 累计计数器基准
	lastPkts     uint64
	hasBase      bool
	deltaBytes   uint64 // 本窗口增量
	deltaPkts    uint64
	isV5Counter  bool
	lastSeen     time.Time
}

// flowAgg 一个监听地址的窗口聚合。
type flowAgg struct {
	mu      sync.Mutex
	flows   map[string]*flowStat
	dropped int // 超缓存上限被丢弃的流数
}

func newFlowAgg() *flowAgg {
	return &flowAgg{flows: map[string]*flowStat{}}
}

// flowListener 全部 UDP 监听的生命周期管理(引擎对账调用)。
type flowListener struct {
	mu    sync.Mutex
	conns map[string]*net.UDPConn
	aggs  map[string]*flowAgg
	logf  func(string)
}

func newFlowListener() *flowListener {
	return &flowListener{
		conns: map[string]*net.UDPConn{},
		aggs:  map[string]*flowAgg{},
	}
}

func (l *flowListener) logLine(s string) {
	if l.logf != nil {
		l.logf(s)
	}
}

// reconcile 保证监听与配置一致: 有启用的 netflow 任务就监听, 没有就全关。
// 由引擎在配置应用时调用(持引擎锁前自行获取, 这里独立加锁)。
func (l *flowListener) reconcile(tasks []Task, enabled bool, defListen string, logf func(string)) {
	l.logf = logf
	l.mu.Lock()
	defer l.mu.Unlock()

	// 收集本次需要的监听地址(任务没写监听地址的归到默认地址; 先归一再入表,
	// 否则空目标任务的 key 与存储 key 不一致, 对账会把监听反复开关)。
	need := map[string]bool{}
	for _, t := range tasks {
		if !t.Enabled || t.Protocol != ProtoNetFlow {
			continue
		}
		a := strings.TrimSpace(t.Target)
		if a == "" {
			a = defListen
		}
		need[a] = true
	}
	if !enabled {
		need = map[string]bool{}
	}
	// 关多余的
	for addr, c := range l.conns {
		if !need[addr] {
			_ = c.Close()
			delete(l.conns, addr)
			delete(l.aggs, addr)
			l.logLine("NetFlow 监听已关闭: " + addr)
		}
	}
	// 开缺的
	for addr := range need {
		if _, ok := l.conns[addr]; ok {
			continue
		}
		conn, err := net.ListenPacket("udp4", addr)
		if err != nil {
			l.logLine("NetFlow 监听启动失败 " + addr + ": " + err.Error())
			continue
		}
		agg := newFlowAgg()
		l.conns[addr] = conn.(*net.UDPConn)
		l.aggs[addr] = agg
		l.logLine("NetFlow/IPFIX 监听已启动: " + addr)
		go l.readLoop(addr, conn.(*net.UDPConn), agg)
	}
}

// agg 获取指定监听地址的聚合器(线程安全, 供采集器取窗口用)。
func (l *flowListener) agg(addr string) *flowAgg {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.aggs[addr]
}

// listening 当前活跃的监听地址(状态接口展示用)。
func (l *flowListener) listening() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.conns))
	for a := range l.conns {
		out = append(out, a)
	}
	return out
}

// stopAll 关闭全部监听(引擎停止时)。
func (l *flowListener) stopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for addr, c := range l.conns {
		_ = c.Close()
		delete(l.conns, addr)
		delete(l.aggs, addr)
	}
}

// readLoop UDP 读取: 单包处理失败只丢包继续(网络数据不受控, 绝不 panic)。
func (l *flowListener) readLoop(addr string, conn *net.UDPConn, agg *flowAgg) {
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return // 连接已关(正常退出路径)
		}
		if n < 4 {
			continue
		}
		ver := int(binary.BigEndian.Uint16(buf[0:2]))
		switch {
		case ver == 5 && n >= 24:
			agg.addV5(buf[:n])
		case ver == 10 && n >= 16:
			agg.addIPFIX(buf[:n])
		default:
			// 未知版本(IPFIX 之外的 v9 等): 只记一次日志不刷屏
			l.logLine("收到未知版本的流量包(version=" + strconv.Itoa(ver) + ", " + addr + "), 已忽略")
		}
	}
}

// addV5 解析并累加一个 NetFlow v5 包。
//
// 真实 v5 线格式(Cisco NetFlow Export Datagram Format):
//   头 24B: version(2) count(2) sysUptime(4) unixSecs(4) unixNsecs(4)
//           flowSequence(4) engineType(1) engineId(1) reserved(2)
//   记录 48B: protocol(1) srcaddr(4) dstaddr(4) nexthop(4) input(2) output(2)
//             pkts(4) bytes(4) first(4) last(4) srcport(2) dstport(2) pad(1)
//             tcpFlags(1) protocol(1) tos(1) srcAS(2) dstAS(2) srcMask(1)
//             dstMask(1) pad(1)
// 字段偏移按此取: pkts@17 bytes@21 srcport@33 dstport@35(偏移取错=流量全错)。
func (a *flowAgg) addV5(p []byte) {
	count := int(binary.BigEndian.Uint16(p[2:4]))
	off := 24
	for i := 0; i < count; i++ {
		if off+48 > len(p) {
			return // 残包, 丢弃
		}
		rec := p[off : off+48]
		off += 48
		proto := protoName(int(rec[0]))
		src := net.IPv4(rec[1], rec[2], rec[3], rec[4]).String()
		dst := net.IPv4(rec[5], rec[6], rec[7], rec[8]).String()
		sport := int(binary.BigEndian.Uint16(rec[33:35]))
		dport := int(binary.BigEndian.Uint16(rec[35:37]))
		pkts := binary.BigEndian.Uint32(rec[17:21])
		bytes := binary.BigEndian.Uint32(rec[21:25])
		a.addFlow(src, sport, dst, dport, proto, uint64(pkts), uint64(bytes), true)
	}
}

// addIPFIX 解析并累加一个 IPFIX 消息(模板缓存 + 数据集聚合)。
func (a *flowAgg) addIPFIX(p []byte) {
	msgLen := int(binary.BigEndian.Uint16(p[2:4]))
	if msgLen > len(p) {
		return
	}
	p = p[:msgLen]
	off := 16
	for off+4 <= len(p) {
		setID := int(binary.BigEndian.Uint16(p[off : off+2]))
		setLen := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		if off+setLen > len(p) {
			return
		}
		body := p[off+4 : off+setLen]
		off += setLen
		switch setID {
		case 0, 2: // 模板集 / 模板选项集
			a.applyTemplate(body)
		default:
			a.applyData(body, setID)
		}
	}
}

// ---- 模板缓存(IPFIX 模板集, setID → 字段表) ----
//
// 按 setID 全局缓存(不按监听地址区分): 同一网段内同一 setID 的模板字段
// 定义是一致的(导出端行为一致), 这样数据包无需携带"来自哪个监听"就能解码。
// 模板数量恒小, 无淘汰。

var (
	tplMu    sync.Mutex
	tplCache = map[int][]tplField{} // setID -> 有序字段列表(顺序即记录内布局, 不能打乱)
)

type tplField struct {
	id   int
	size int
}

func (a *flowAgg) applyTemplate(body []byte) {
	off := 0
	for off+4 <= len(body) {
		tid := int(binary.BigEndian.Uint16(body[off : off+2]))
		fields := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		fs := make([]tplField, 0, fields)
		ok := true
		for i := 0; i < fields; i++ {
			if off+4 > len(body) {
				ok = false
				break
			}
			fid := int(binary.BigEndian.Uint16(body[off : off+2]))
			size := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
			off += 4
			fs = append(fs, tplField{id: fid, size: size})
		}
		if !ok {
			return
		}
		tplMu.Lock()
		tplCache[tid] = fs // 保持模板字段顺序
		tplMu.Unlock()
	}
}

// 标准 IPFIX 信息元素 ID(RFC 7011): 1=byteCount 2=packetCount
// 30=srcPort 31=dstPort 7=protocol 33=srcIPv4 34=dstIPv4
const (
	ielBytes   = 1
	ielPkts    = 2
	ielSrcPort = 30
	ielDstPort = 31
	ielProto   = 7
	ielSrcIPv4 = 33
	ielDstIPv4 = 34
)

func (a *flowAgg) applyData(body []byte, setID int) {
	tplMu.Lock()
	tm := tplCache[setID]
	tplMu.Unlock()
	if tm == nil {
		return // 模板未见过(导出端只发数据不发模板, 或模板包丢失), 无法解码
	}
	a.decodeRecord(body, tm)
}

func (a *flowAgg) decodeRecord(body []byte, tm []tplField) {
	// 记录长度未知 —— 数据集里记录按模板字段总长切分
	recLen := 0
	for _, f := range tm {
		recLen += f.size
	}
	if recLen <= 0 {
		return
	}
	off := 0
	for off+recLen <= len(body) {
		rec := body[off : off+recLen]
		off += recLen
		var src, dst string
		var sport, dport int
		var protoID int
		var bytes, pkts uint64
		roff := 0
		for _, f := range tm {
			if roff+f.size > len(rec) {
				break
			}
			v := rec[roff : roff+f.size]
			roff += f.size
			switch f.id {
			case ielSrcIPv4:
				if len(v) >= 4 {
					src = net.IPv4(v[0], v[1], v[2], v[3]).String()
				}
			case ielDstIPv4:
				if len(v) >= 4 {
					dst = net.IPv4(v[0], v[1], v[2], v[3]).String()
				}
			case ielSrcPort, ielDstPort:
				if len(v) == 2 {
					p := int(binary.BigEndian.Uint16(v))
					if f.id == ielSrcPort {
						sport = p
					} else {
						dport = p
					}
				}
			case ielProto:
				protoID = int(firstByte(v))
			case ielBytes:
				bytes = beUint(v)
			case ielPkts:
				pkts = beUint(v)
			}
		}
		if src == "" || dst == "" {
			continue
		}
		a.addFlow(src, sport, dst, dport, protoName(protoID), pkts, bytes, false)
	}
}

// firstByte 取字节切片的首字节(空切片 0)。
func firstByte(v []byte) byte {
	if len(v) == 0 {
		return 0
	}
	return v[0]
}

// beUint 大端无符号(按长度取低 64 位, 超长截断)。
func beUint(v []byte) uint64 {
	var x uint64
	for i := 0; i < len(v) && i < 8; i++ {
		x = x<<8 | uint64(v[i])
	}
	return x
}

func protoName(id int) string {
	switch id {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 0:
		return "unknown"
	default:
		return strconv.Itoa(id)
	}
}

// addFlow 单流累加: v5 走累计计数器差分; IPFIX 值即区间聚合直接累加。
func (a *flowAgg) addFlow(src string, sport int, dst string, dport int, proto string, pkts, bytes uint64, v5 bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := fmt.Sprintf("%s:%d|%s:%d|%s", src, sport, dst, dport, proto)
	f := a.flows[key]
	now := time.Now()
	if f == nil {
		if len(a.flows) >= flowCacheCap {
			a.dropped++
			return
		}
		f = &flowStat{srcIP: src, sport: sport, dstIP: dst, dport: dport, proto: proto, isV5Counter: v5}
		a.flows[key] = f
	}
	if v5 {
		// v5 是累计计数器: 首条观测以 0 为基准(该值即本区间增量), 之后与
		// 上次值做差分。漏掉首条建基线会让 hasBase 永远为 false, 差分永不
		// 生效, 窗口统计恒 0(页面永远显示无流量)。
		if !f.hasBase {
			f.deltaBytes += bytes
			f.deltaPkts += pkts
		} else {
			// 值回退(导出端重启/计数器回绕)不产生负增量, 只更新基准。
			if bytes >= f.lastBytes {
				f.deltaBytes += bytes - f.lastBytes
			}
			if pkts >= f.lastPkts {
				f.deltaPkts += pkts - f.lastPkts
			}
		}
		f.hasBase = true
		f.lastBytes, f.lastPkts = bytes, pkts
	} else {
		f.deltaBytes += bytes
		f.deltaPkts += pkts
	}
	f.lastSeen = now
}

// flowEvictAfter 流缓存淘汰时限: 超过 3 个采集窗口(默认 60s)没再出现的
// 流认为已结束, 淘汰防缓存被长连接占满。
const flowEvictAfter = 3 * time.Minute

// takeWindow 取走当前窗口统计并清零(返回: 流数、总增量、TOP 流)。
func (a *flowAgg) takeWindow() (int, uint64, uint64, []flowTop) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	var totalB, totalP uint64
	top := make([]flowTop, 0, 5)
	for k, f := range a.flows {
		if now.Sub(f.lastSeen) > flowEvictAfter {
			// 按"最后出现时间"淘汰, 不能按"本窗口无增量"淘汰: v5 长连接
			// 某窗口可能真的 0 增量, 若此时淘汰, 下一条记录会被当新流
			// (基准=0), 把整个累计值当成增量, 流量指标瞬间虚高数倍。
			delete(a.flows, k)
			continue
		}
		totalB += f.deltaBytes
		totalP += f.deltaPkts
		top = append(top, flowTop{key: k, bytes: f.deltaBytes, pkts: f.deltaPkts, proto: f.proto, src: f.srcIP, sport: f.sport, dst: f.dstIP, dport: f.dport})
		f.deltaBytes, f.deltaPkts = 0, 0
	}
	sort.Slice(top, func(i, j int) bool { return top[i].bytes > top[j].bytes })
	if len(top) > 5 {
		top = top[:5]
	}
	return len(a.flows), totalB, totalP, top
}

type flowTop struct {
	key, src, dst, proto string
	sport, dport         int
	bytes, pkts          uint64
}

// collectNetFlow 一轮 = 取走一个聚合窗口。
func collectNetFlow(ctx context.Context, e *Engine, t Task) *Round {
	r := newRound(t, time.Now())
	listen := strings.TrimSpace(t.Target)
	cfg := e.Config()
	if listen == "" {
		listen = cfg.NetFlow.Listen
	}
	// 走 flowListener 的线程安全访问器(内部 l.mu), 不能直接读 e.flows.aggs ——
	// reconcile 在 l.mu 下改这个 map, 跨锁直读是数据竞争。
	agg := e.flows.agg(listen)
	if agg == nil {
		r.OK = false
		r.Err = "NetFlow 接收端未运行(检查 collect.netflow.enabled 与监听地址)"
		return r
	}
	active, totalB, totalP, top := agg.takeWindow()

	// 窗口时长: 上一轮时间到本轮(首轮用任务间隔)
	window := cfg.TaskInterval(t).Seconds()
	if prev := e.Store().PrevOf(t.ID); prev != nil {
		if dt := time.Since(prev.At).Seconds(); dt > 1 {
			window = dt
		}
	}
	r.OK = true
	r.Metrics = append(r.Metrics,
		Metric{Name: "flows_active", Value: float64(active), Unit: ""},
		Metric{Name: "in_rate_bps", Value: float64(totalB) * 8 / window, Unit: "bps"},
		Metric{Name: "in_rate_pps", Value: float64(totalP) / window, Unit: "pps"},
	)
	for _, f := range top {
		r.Metrics = append(r.Metrics, Metric{
			Name: "top_flow", Value: float64(f.bytes) * 8 / window, Unit: "bps",
			Labels: map[string]string{
				"src": f.src, "sport": strconv.Itoa(f.sport),
				"dst": f.dst, "dport": strconv.Itoa(f.dport), "proto": f.proto,
			},
		})
	}
	return r
}

// 引擎侧对账入口(在 engine.go 的 applyConfigLocked 里调)。
func (e *Engine) reconcileNetFlowLocked(c Config) {
	e.flows.reconcile(c.Tasks, c.NetFlow.Enabled, c.NetFlow.Listen, e.logLine)
}
