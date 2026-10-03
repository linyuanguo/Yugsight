package scanner

// arpwatch.go 探针端 ARP 异常监测(2026-09-27 用户口径: 探针要能检测自己所在
// 系统的 ARP 信息有没有异常 —— 环路 / IP 冲突 / MAC 漂移)。
//
// 工作方式: 探针在本机网卡上抓 ARP 帧(Windows 走 Npcap, Linux 走 AF_PACKET
// 原始套接字, 见 collector_linux.go), 记录监测窗口内"IP -> MAC"观测序列,
// 结束时按以下口径输出异常:
//
//	IP 冲突   同一 IP 的 ARP 源 MAC 观测时间区间相互重叠(即短时间内两个不同 MAC
//	          都在"声称"这个 IP) —— 典型 ARP 欺骗 / 重复地址配置特征。高危。
//	MAC 漂移  某 IP 的源 MAC 在监测期内发生切换, 但新旧 MAC 的观测区间不重叠
//	          (变化后旧的不再出现) —— 主机换网卡/重配置、交换机端口迁移。中危。
//	环路     同一条 ARP 请求(同 源MAC+源IP+目的MAC+目的IP)在短窗口(默认 10s)
//	          内重复出现达到阈值(默认 5 次) —— 广播环路下 ARP 请求被反复转发。高危。
//
// 为什么不复用中心端 scanner.LoopDetector: 那套判据基于 IP 包 TTL 严格递减 1,
// 面向中心端抓包链路; 探针端这里只抓 ARP 层(Windows BPF 过滤 "arp"), 没有
// IP 包 TTL 参考, 故用"ARP 请求重复计数"口径。两者互补不冲突。
//
// 检测核心(detectArpAnomalies)是纯函数, 离线可单测; 抓包编排依赖平台采集器,
// 采集器缺失时明确失败(项目规则: 能力缺失要明确标, 不能静默返回空结果让
// 中心端把"能力缺失"误读成"无异常")。
//
// 内存保护: 监测窗口内的观测序列/IP 数/请求签名数都有上限, 广播风暴下不会
// 把探针内存吃光(超限按"保留首末 + 修剪过期"策略, 不影响冲突/漂移/环路判定)。

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"yugsight/internal/normalizer"
)

const (
	// arpWatchDefaultSec 默认监测时长
	arpWatchDefaultSec = 60
	// arpWatchMaxSec 监测时长上限(防误操作把探针挂死)
	arpWatchMaxSec = 600
	// conflictWindow 判定"两个 MAC 同时在声称同一 IP"的时间区间重叠口径,
	// 直接以观测区间重叠判定, 无额外窗口参数。
	// maxTrackedIPs 同时跟踪的 IP 数上限
	maxTrackedIPs = 5000
	// maxObsPerIP 单 IP 的 MAC 观测序列上限(超限保留首条 + 最近若干条)
	maxObsPerIP = 200
	// maxReqSignatures ARP 请求签名数上限(超限全量修剪一次)
	maxReqSignatures = 10000
)

// ArpWatchConfig 一轮 ARP 监测的参数。
type ArpWatchConfig struct {
	// Device 网卡名(空或 "local" = 自动选第一个非回环、非虚口、带 IP 的网卡)
	Device string
	// DurationSec 监测时长(秒; 0 取默认 60, 上限 600)
	DurationSec int
	// LoopWindow 环路判定窗口(默认 10s)
	LoopWindow time.Duration
	// LoopCount 窗口内同一条 ARP 请求的出现次数阈值(默认 5)
	LoopCount int
}

func (c ArpWatchConfig) withDefaults() ArpWatchConfig {
	if c.DurationSec <= 0 {
		c.DurationSec = arpWatchDefaultSec
	}
	if c.DurationSec > arpWatchMaxSec {
		c.DurationSec = arpWatchMaxSec
	}
	if c.LoopWindow <= 0 {
		c.LoopWindow = 10 * time.Second
	}
	if c.LoopCount <= 0 {
		c.LoopCount = 5
	}
	return c
}

// ArpFrame 一条解析出的 ARP 帧(只保留判定所需字段)。
type ArpFrame struct {
	Opcode    uint16 // 1=请求 2=应答
	SenderMAC string // 源 MAC(小写)
	SenderIP  string // 源 IP
	TargetMAC string // 目的 MAC
	TargetIP  string // 目的 IP
}

// parseArpFrame 解析以太网帧中的 ARP 报文。
//
// 布局: [0:14] 以太网头(ethertype 在 [12:14]), [14:22] ARP 头
// (hwtype2+protype2+hlen1+plen1+opcode2), [22:42] SHA(6)+SPA(4)+THA(6)+TPA(4)。
// 只处理最普通的 hwtype=1(以太网)/protype=0x0800(IPv4)/hlen=6/plen=4 形态,
// 其它(令牌环/非 IPv4)返回 false 跳过 —— 判定目标就是 IPv4 网的 ARP 异常。
//
// 网络数据完全不受控, 全程边界检查, 畸形帧绝不 panic。
func parseArpFrame(frame []byte) (ArpFrame, bool) {
	// 最小长度 = 以太网头 14 + ARP 头 8 + SHA6+SPA4+THA6+TPA4(20) = 42
	if len(frame) < 42 {
		return ArpFrame{}, false
	}
	ethertype := binary.BigEndian.Uint16(frame[12:14])
	if ethertype != 0x0806 { // 0x0806 = ARP
		return ArpFrame{}, false
	}
	hwtype := binary.BigEndian.Uint16(frame[14:16])
	protype := binary.BigEndian.Uint16(frame[16:18])
	hlen := frame[18]
	plen := frame[19]
	opcode := binary.BigEndian.Uint16(frame[20:22])
	if hwtype != 1 || protype != 0x0800 || hlen != 6 || plen != 4 {
		return ArpFrame{}, false
	}
	if len(frame) < 14+8+int(hlen)*2+int(plen)*2 {
		return ArpFrame{}, false
	}
	base := 14 + 8
	sha := frame[base : base+6]
	spa := frame[base+6 : base+10]
	tha := frame[base+10 : base+16]
	tpa := frame[base+16 : base+20]
	return ArpFrame{
		Opcode:    opcode,
		SenderMAC: fmtMac(sha),
		SenderIP:  net.IP(spa).String(),
		TargetMAC: fmtMac(tha),
		TargetIP:  net.IP(tpa).String(),
	}, true
}

func fmtMac(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// macObs 一条 "IP -> MAC" 观测。
type macObs struct {
	mac string
	ts  time.Time
}

// ArpWatcher 一轮监测的观测记录(并发安全: 采集 sink 与统计协程并发访问)。
type ArpWatcher struct {
	mu        sync.Mutex
	frames    int // 收到的帧数(含非 ARP)
	arpFrames int // 解析成功的 ARP 帧数

	macObs map[string][]macObs        // IP -> MAC 观测序列(时间升序)
	reqTimes map[string][]time.Time   // ARP 请求签名 -> 窗口内出现时刻

	loopWindow time.Duration
	loopCount  int
}

func newArpWatcher(loopWindow time.Duration, loopCount int) *ArpWatcher {
	return &ArpWatcher{
		macObs:     make(map[string][]macObs),
		reqTimes:   make(map[string][]time.Time),
		loopWindow: loopWindow,
		loopCount:  loopCount,
	}
}

// recordFrame 处理一帧(采集 sink 回调)。恒返回 true(下游正常)。
func (w *ArpWatcher) recordFrame(frame []byte) bool {
	f, ok := parseArpFrame(frame)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames++
	if !ok {
		return true
	}
	w.arpFrames++
	now := time.Now()
	// 只记录"源"信息(源是 ARP 声明者); 目的字段是查询/广播侧, 不构成归属证据。
	// 全零 MAC 是无意义占位(如目的 MAC 未解析), 跳过。
	if f.SenderIP != "" && f.SenderMAC != "00:00:00:00:00:00" {
		w.addObsLocked(f.SenderIP, f.SenderMAC, now)
	}
	// 环路只看请求: 请求才是环路上被反复转发的东西, 应答不会自发重复。
	if f.Opcode == 1 {
		sig := fmt.Sprintf("%s|%s|%s|%s", f.SenderMAC, f.SenderIP, f.TargetMAC, f.TargetIP)
		ts := append(w.reqTimes[sig], now)
		cutoff := now.Add(-w.loopWindow)
		if i := sort.Search(len(ts), func(i int) bool { return !ts[i].Before(cutoff) }); i > 0 {
			ts = ts[i:]
		}
		w.reqTimes[sig] = ts
		if len(w.reqTimes) > maxReqSignatures {
			w.pruneReqsLocked(cutoff)
		}
	}
	return true
}

func (w *ArpWatcher) addObsLocked(ip, mac string, ts time.Time) {
	obs := w.macObs[ip]
	if len(obs) == 0 && len(w.macObs) >= maxTrackedIPs {
		return // 超限不再跟踪新 IP(已有 IP 的判定不受影响)
	}
	if len(obs) >= maxObsPerIP {
		// 保留首条(漂移判定的"旧 MAC"基线) + 最近 maxObsPerIP-2 条
		keep := maxObsPerIP - 2
		obs = append(obs[:1], obs[len(obs)-keep:]...)
	}
	w.macObs[ip] = append(obs, macObs{mac: mac, ts: ts})
}

func (w *ArpWatcher) pruneReqsLocked(cutoff time.Time) {
	for sig, ts := range w.reqTimes {
		i := sort.Search(len(ts), func(i int) bool { return !ts[i].Before(cutoff) })
		if i >= len(ts) {
			delete(w.reqTimes, sig)
		} else {
			w.reqTimes[sig] = ts[i:]
		}
	}
}

// ArpAnomaly 一条 ARP 异常。
type ArpAnomaly struct {
	Kind     string    // "ip_conflict" | "mac_drift" | "loop"
	IP       string    // 冲突/漂移的 IP; 环路为请求源 IP
	MACs     []string  // 涉及的 MAC(去重)
	Count    int       // 环路: 窗口内重复次数; 其它: 0
	Severity string    // high / medium
	Title    string
	Detail   string
	FirstAt  time.Time
	LastAt   time.Time
}

// ArpWatchResult 一轮监测的结果。
type ArpWatchResult struct {
	Device    string
	Duration  time.Duration
	Frames    int
	ArpFrames int
	IPEntries int           // 观测到的 IP 数
	IPMACs    map[string]string // 观测到的 IP -> 最后出现的源 MAC(供登记资产)
	Anomalies []ArpAnomaly
}

// Summary 一行摘要(任务结果/进度展示)。
func (r *ArpWatchResult) Summary() string {
	if len(r.Anomalies) == 0 {
		return fmt.Sprintf("ARP 监测完成(%s, %s): 帧 %d / ARP %d / IP %d, 未发现异常",
			r.Device, r.Duration.Round(time.Second), r.Frames, r.ArpFrames, r.IPEntries)
	}
	return fmt.Sprintf("ARP 监测完成(%s, %s): 帧 %d / ARP %d / IP %d, 发现异常 %d 条",
		r.Device, r.Duration.Round(time.Second), r.Frames, r.ArpFrames, r.IPEntries, len(r.Anomalies))
}

// RunArpWatch 执行一轮 ARP 监测(阻塞直到时长结束或 ctx 取消), 返回监测结果。
//
// 失败语义: 平台无采集器 / 网卡打不开(缺 Npcap、缺 CAP_NET_RAW) 时返回明确
// 错误, 由上层转成任务失败回传 —— 不能静默返回"0 异常"。
func RunArpWatch(ctx context.Context, cfg ArpWatchConfig, progress Progress) (*ArpWatchResult, error) {
	cfg = cfg.withDefaults()
	col := CurrentCollector()
	if col == nil {
		return nil, fmt.Errorf("当前平台无报文采集能力, 无法进行 ARP 监测(Windows 需安装 Npcap, Linux 需 root/CAP_NET_RAW 权限)")
	}
	w := newArpWatcher(cfg.LoopWindow, cfg.LoopCount)

	ccfg := CaptureConfig{Enabled: true, Device: cfg.Device, Filter: "arp"}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.DurationSec)*time.Second)
	defer cancel()

	colDone := make(chan error, 1)
	go func() {
		colDone <- col.Start(runCtx, ccfg, w.recordFrame)
	}()
	defer col.Stop()

	start := time.Now()
	device := cfg.Device
	if device == "" || device == "local" {
		device = "auto"
	}

	// 等采集结束(时长到 / 上层取消 / 采集通道异常), 期间每 5s 报一条进度
	// (长监测时中心端能区分"还在跑"和"卡死了")。
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	ended := false
	var startErr error
	for !ended {
		select {
		case err := <-colDone:
			ended = true
			startErr = err
		case <-runCtx.Done():
			ended = true
			// 上层取消或时长到: 采集协程会随 ctx 很快退出, 这里不再等它
		case <-tick.C:
			fr, af := w.counts()
			progress.Emit(fmt.Sprintf("ARP 监测中: %s/%s, 帧 %d (ARP %d)",
				time.Since(start).Round(time.Second),
				time.Duration(cfg.DurationSec)*time.Second, fr, af))
		}
	}
	if startErr != nil {
		// 采集启动失败(无适配器/无权限): 明确失败
		return nil, fmt.Errorf("ARP 监测采集启动失败: %w", startErr)
	}
	if ctx.Err() != nil {
		// 上层取消(任务被取消): 不能按"成功"回传部分结果(会被误读为"监测完成无异常")
		return nil, fmt.Errorf("ARP 监测被取消(任务取消或探针断开)")
	}
	// 采集提前结束(适配器异常): 全程没收到帧才算失败, 否则按已有数据统计
	fr0, af0 := w.counts()
	if fr0 == 0 && af0 == 0 && time.Since(start) < time.Duration(cfg.DurationSec)*time.Second/2 {
		return nil, fmt.Errorf("ARP 监测采集通道提前结束且未收到任何帧(网卡异常或被移出)")
	}

	w.mu.Lock()
	frames, arpFrames := w.frames, w.arpFrames
	macObs := make(map[string][]macObs, len(w.macObs))
	for k, v := range w.macObs {
		macObs[k] = v
	}
	reqTimes := make(map[string][]time.Time, len(w.reqTimes))
	for k, v := range w.reqTimes {
		reqTimes[k] = v
	}
	w.mu.Unlock()

	// IP -> 最后观测到的源 MAC(登记资产用: 这些是探针本地网段真实在线的主机)
	ipMACs := make(map[string]string, len(macObs))
	for ip, seq := range macObs {
		ipMACs[ip] = seq[len(seq)-1].mac
	}

	anomalies := detectArpAnomalies(macObs, reqTimes, cfg.LoopWindow, cfg.LoopCount)
	return &ArpWatchResult{
		Device:    device,
		Duration:  time.Since(start),
		Frames:    frames,
		ArpFrames: arpFrames,
		IPEntries: len(macObs),
		IPMACs:    ipMACs,
		Anomalies: anomalies,
	}, nil
}

// counts 帧计数(测试/进度用)。
func (w *ArpWatcher) counts() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.frames, w.arpFrames
}

// ===== 检测核心(纯函数, 离线单测) =====

// macRange 某 MAC 的观测时间区间。
type macRange struct {
	mac   string
	first time.Time
	last  time.Time
	count int
}

// compressMacRanges 把 IP 的 MAC 观测序列按 MAC 聚合为时间区间(保序: 按首次出现)。
func compressMacRanges(seq []macObs) []macRange {
	idx := map[string]int{}
	var out []macRange
	for _, o := range seq {
		i, ok := idx[o.mac]
		if !ok {
			idx[o.mac] = len(out)
			out = append(out, macRange{mac: o.mac, first: o.ts, last: o.ts, count: 1})
			continue
		}
		out[i].last = o.ts
		out[i].count++
	}
	return out
}

// detectArpAnomalies 从观测数据判定三类 ARP 异常。
//
// 冲突 vs 漂移的区分口径: 两个 MAC 的观测时间区间重叠 = 冲突(两者都在同一时段
// 声称该 IP); 区间不重叠 = 漂移(旧 MAC 的观测结束后新 MAC 才出现)。
// 多 MAC(>=3) 只要存在任一对重叠即判冲突, 否则按漂移。
func detectArpAnomalies(obs map[string][]macObs, reqs map[string][]time.Time, loopWindow time.Duration, loopCount int) []ArpAnomaly {
	var out []ArpAnomaly

	// IP 冲突 / MAC 漂移
	ips := make([]string, 0, len(obs))
	for ip := range obs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		seq := obs[ip]
		ranges := compressMacRanges(seq)
		if len(ranges) < 2 {
			continue
		}
		// 找任意一对时间区间重叠的 MAC
		conflict := false
		var a, b macRange
		for i := 0; i < len(ranges) && !conflict; i++ {
			for j := i + 1; j < len(ranges); j++ {
				// 区间重叠: a.last >= b.first && b.last >= a.first
				if !ranges[i].last.Before(ranges[j].first) && !ranges[j].last.Before(ranges[i].first) {
					conflict = true
					a, b = ranges[i], ranges[j]
					break
				}
			}
		}
		macs := make([]string, 0, len(ranges))
		first, last := seq[0].ts, seq[len(seq)-1].ts
		for _, r := range ranges {
			macs = append(macs, r.mac)
		}
		if conflict {
			out = append(out, ArpAnomaly{
				Kind:     "ip_conflict",
				IP:       ip,
				MACs:     macs,
				Severity: "high",
				Title:    fmt.Sprintf("IP 冲突: %s 存在多个 MAC 同时声称", ip),
				Detail: fmt.Sprintf("监测窗口内 IP %s 至少有两个不同 MAC 的 ARP 源观测在时间上重叠: %s(%d 次, %s ~ %s) 与 %s(%d 次, %s ~ %s)。"+
					"常见原因: ARP 欺骗攻击、同网段重复地址配置、代理 ARP 配置错误。建议: 核对相关主机 IP 配置, 排查 ARP 欺骗。",
					ip, a.mac, a.count, a.first.Format("15:04:05"), a.last.Format("15:04:05"),
					b.mac, b.count, b.first.Format("15:04:05"), b.last.Format("15:04:05")),
				FirstAt: first,
				LastAt:  last,
			})
		} else {
			// 漂移: 按首次出现排序取"旧 -> 新"
			sorted := make([]macRange, len(ranges))
			copy(sorted, ranges)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i].first.Before(sorted[j].first) })
			oldR, newR := sorted[0], sorted[len(sorted)-1]
			out = append(out, ArpAnomaly{
				Kind:     "mac_drift",
				IP:       ip,
				MACs:     macs,
				Severity: "medium",
				Title:    fmt.Sprintf("MAC 漂移: %s 的 MAC 发生切换", ip),
				Detail: fmt.Sprintf("IP %s 的 ARP 源 MAC 在监测期内由 %s 切换为 %s(首次 %s, 切换后 %s), 新旧观测区间不重叠。"+
					"常见原因: 主机更换网卡/重新配置、设备迁移到交换机另一端口。若未做上述变更, 需排查 ARP 欺骗。",
					ip, oldR.mac, newR.mac, oldR.first.Format("15:04:05"), newR.first.Format("15:04:05")),
				FirstAt: first,
				LastAt:  last,
			})
		}
	}

	// 环路: 同一条 ARP 请求在窗口内重复达到阈值
	sigs := make([]string, 0, len(reqs))
	for sig := range reqs {
		sigs = append(sigs, sig)
	}
	sort.Strings(sigs)
	for _, sig := range sigs {
		ts := reqs[sig]
		if len(ts) < loopCount {
			continue
		}
		// sig = "srcMac|srcIP|dstMac|dstIP"
		parts := strings.SplitN(sig, "|", 4)
		srcIP, srcMAC := "", ""
		if len(parts) >= 2 {
			srcMAC, srcIP = parts[0], parts[1]
		}
		out = append(out, ArpAnomaly{
			Kind:     "loop",
			IP:       srcIP,
			MACs:     []string{srcMAC},
			Count:    len(ts),
			Severity: "high",
			Title:    fmt.Sprintf("疑似环路: ARP 请求重复 %d 次/%s", len(ts), loopWindow.Round(time.Second)),
			Detail: fmt.Sprintf("同一条 ARP 请求(源 %s %s)在 %s 内出现 %d 次。"+
				"常见原因: 二层环路(交换机环路/网线误接成环)、广播风暴。建议: 检查该网段交换机端口与网线连接。",
				srcMAC, srcIP, loopWindow.Round(time.Second), len(ts)),
			FirstAt: ts[0],
			LastAt:  ts[len(ts)-1],
		})
	}

	// 严重级别降序, 同级按 IP
	sort.Slice(out, func(i, j int) bool {
		ri, rj := 0, 0
		if out[i].Severity == "high" {
			ri = 1
		}
		if out[j].Severity == "high" {
			rj = 1
		}
		if ri != rj {
			return ri > rj
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// scanArp 执行一轮本机 ARP 异常监测(kind=arp), 把异常转成漏洞、把观测到的
// IP+MAC 登记为资产。
//
// 目标语义: Task.Target 是网卡名或 "local"(自动选网卡); 不是远端主机。
// 返回错误表示采集无法进行(能力缺失/权限不足), 由 Run() 转成任务失败回传。
func (t *Task) scanArp(ctx context.Context, progress Progress) error {
	progress.Emit("开始 ARP 异常监测: " + t.Target + ", 时长 " +
		fmt.Sprintf("%ds", t.cfg.ArpDurationSec))
	res, err := RunArpWatch(ctx, ArpWatchConfig{
		Device:      t.Target,
		DurationSec: t.cfg.ArpDurationSec,
	}, progress)
	if err != nil {
		progress.Emit("ARP 监测失败: " + err.Error())
		return err
	}

	// 观测到的 IP+MAC 登记为资产(探针本地网段真实在线主机; 上限 500 防风暴灌爆)
	registered := 0
	for ip, mac := range res.IPMACs {
		if registered >= 500 {
			break
		}
		t.addAsset(normalizer.ProbeAsset{IP: ip, MAC: mac, Tags: []string{"arp-watch"}})
		registered++
	}

	// 异常 -> 漏洞(走既有 addVuln 去重/汇总口径)
	for _, a := range res.Anomalies {
		conf := 60
		if a.Severity == "high" {
			conf = 80
		}
		t.addVuln(normalizer.ProbeVuln{
			IP:          a.IP,
			Title:       a.Title,
			Severity:    a.Severity,
			Description: a.Detail,
			Evidence:    fmt.Sprintf("监测窗口 %s / 设备 %s / 帧 %d (ARP %d) / 观测 IP %d",
				res.Duration.Round(time.Second), res.Device, res.Frames, res.ArpFrames, res.IPEntries),
			Confidence: conf,
			FoundAt:     a.FirstAt,
		})
	}

	progress.Emit(res.Summary())
	for _, a := range res.Anomalies {
		progress.Emit("[异常] " + a.Title + " | " + a.Detail)
	}
	return nil
}

