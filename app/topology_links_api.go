package main

// topology_links_api.go 2D 拓扑链路真实数据聚合(2026-09-29, 阶段 B)。
//
// 借鉴 Zabbix"主机间链路"概念, 但落到本项目既有事实来源, 零新增采集:
//   - 节点 = 设备台账口径(探针 P_ + 资产 A_, 与前端 dashData 的主键约定同源,
//     前端按 deviceId 直接定位, 不引入第二套节点标识);
//   - 边 = 确定性生成(无随机, 便于测试与心智模型):
//     ① 资产↔探针: 资产 ProbeNode 非空(探针纳管了该资产);
//     ② 同 /24 网段: 星型挂段代表(最小 IP, 避免 O(N²) 全互联把画布拖满);
//     ③ 跨网段: 各段代表按段排序链式相连(O(段数), 全互联边数 O(S²) 拖垮画布);
//   - 链路状态 = 两端节点最高严重度(down > warn > normal)—— Zabbix 同口径:
//     链路本身不采集, 端点有问题链路才红;
//     2026-09-30 口径修正(用户反馈"设备上线检测在线, 线却一直红"):
//     ① SNMP 近期(3min 内)采集成功 = 在线权威证据, 资产端点由 down 升 normal
//       (Asset.Alive 是扫描存活快照, 长期不扫就过期, 不能当实时在线口径);
//     ② 两端 online 的链路由中心端后台真实探测两端(自动连通测试, 30s 缓存 +
//       单飞 + 并发上限)——"上线检测过但连接测试失败"同样红, 绿线必须是实测结果;
//   - 流量 = monitor 包 SNMP 接口表两轮样本 ifIn/OutOctets 差分(字节/秒),
//     未覆盖 SNMP 的链路只回状态、不回流(前端按无数据渲染, 不编造流量);
//     2026-09-30 增 inMps/outMps(每方向真实上下行速率) + trafficSide(被采样端
//     的 deviceId)—— 前端据此定向线上的上/下传箭头与双向光点(方向无数据=不画)。
//
// 关键口径(与前端约定, 详见 dashData.js 的 LINKS_ENDPOINT 注释):
// 链路"集合"仍由前端掌控(Mock 生成 + 用户手增删, localStorage 持久化),
// 本接口只提供按 (fromDeviceId, toDeviceId) 匹配的流量/状态字段 —— 前端
// 只把接口数据"覆盖"到已有链路上, 不删不增。否则每次轮询重生成边集合,
// 用户手工删掉的链路会"又回来了"(设计文档明示的坑)。
//
// SSE: 节点状态变化(collect 事件 / SNMP 轮次完成)时广播 topolink 快照,
// 5s 节流 —— 前端轮询(15s)兜底, SSE 只负责"状态翻转更快可见"。

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"yugsight/internal/collect"
	"yugsight/internal/monitor"
	"yugsight/internal/scanner"
	"yugsight/internal/server"
	"yugsight/internal/sse"
)

var (
	topoLinkPubMu sync.Mutex
	topoLinkPubAt time.Time
)

// topoEndpoint 一个链路端点(节点)及其严重度。
type topoEndpoint struct {
	deviceID string
	ip       string
	level    string // normal | warn | down
}

// linkRate 一个 IP 的接口聚合速率(bps)。
type linkRate struct {
	inBps, outBps, bw float64
}

// buildTopologyLinks 聚合当前链路快照。ok=false = 依赖数据不可用(降级, 不报错)。
func buildTopologyLinks() (list []map[string]any, ok bool) {
	d := v2DB()
	if d == nil {
		return nil, false
	}
	probeDAO, assetDAO := d.Probes(), d.Assets()
	if probeDAO == nil || assetDAO == nil {
		return nil, false
	}
	probes, err := probeDAO.List()
	if err != nil {
		return nil, false
	}
	assets, err := assetDAO.List()
	if err != nil {
		return nil, false
	}

	// ---- 节点集合 + 严重度 ----
	endpoints := map[string]*topoEndpoint{}
	ipToDev := map[string]string{} // IP -> deviceId(探针/资产同 IP 时先入者优先)
	addEp := func(ep *topoEndpoint) {
		if ep.deviceID == "" || endpoints[ep.deviceID] != nil {
			return
		}
		endpoints[ep.deviceID] = ep
		if ep.ip != "" {
			if _, done := ipToDev[ep.ip]; !done {
				ipToDev[ep.ip] = ep.deviceID
			}
		}
	}
	bumpWarn := func(deviceID string) {
		if ep := endpoints[deviceID]; ep != nil && levelRank(ep.level) < 1 {
			ep.level = "warn"
		}
	}

	// 探针: 离线 = down(链路端点不可达); CPU 高负载不算链路问题(节点颜色已表达)
	for i := range probes {
		p := probes[i]
		lv := "normal"
		if !strings.EqualFold(p.Status, "online") {
			lv = "down"
		}
		addEp(&topoEndpoint{deviceID: "P_" + p.ID, ip: hostPart(p.Addr), level: lv})
	}

	// 资产: 只收 IP 合法的条目(资产口径契约: SCA 工件不是主机, 不进拓扑)
	type assetRef struct {
		deviceID, ip, probe string
	}
	assetRefs := make([]assetRef, 0, len(assets))
	for i := range assets {
		a := assets[i]
		if net.ParseIP(a.IP) == nil {
			continue
		}
		lv := "normal"
		if !a.Alive {
			lv = "down"
		}
		id := a.ID
		if id == "" {
			id = a.IP
		}
		assetRefs = append(assetRefs, assetRef{deviceID: "A_" + id, ip: a.IP, probe: a.ProbeNode})
		addEp(&topoEndpoint{deviceID: "A_" + id, ip: a.IP, level: lv})
	}

	// 节点监控目标(M_* 前缀, 与前端设备表 S.devices 同源同主键): SNMP 监控设备同样
	// 是链路节点 —— 用户绑定的"交换机"节点常常是监控目标而非资产表条目; 不收它,
	// 交换机关联的链路就永远没有能承载 SNMP 速率的端点(2026-10-01 真机: 172.16.199.1
	// 锐捷交换机是监控目标不在资产表, 链路恒无速率)。同 IP 去重与前端同口径
	// (探针/资产优先, 同 IP 不生成两个节点)。
	type monRef struct {
		deviceID, ip string
	}
	monRefs := make([]monRef, 0)
	if m := instanceMonitor(); m != nil {
		for _, t := range m.Config().Targets {
			ip := hostPart(t.Addr)
			if net.ParseIP(ip) == nil || ipToDev[ip] != "" {
				continue
			}
			monRefs = append(monRefs, monRef{"M_" + t.ID, ip})
			addEp(&topoEndpoint{deviceID: "M_" + t.ID, ip: ip, level: "normal"})
		}
	}

	// 严重度叠加: 采集引擎最新样本(CPU/内存 >=90 = warn) + SNMP 最近一轮(采集失败 = warn)
	if e := instanceCollect(); e != nil {
		targetOf := map[string]string{}
		for _, t := range e.Config().Tasks {
			if t.Target != "" {
				targetOf[t.ID] = t.Target
			}
		}
		for taskID, r := range e.Store().Latest() {
			if r == nil {
				continue
			}
			ip := targetOf[taskID]
			if ip == "" {
				continue
			}
			if collect.MetricValue(r, "cpu") >= 90 {
				bumpWarn(ipToDev[ip])
			}
			if collect.MetricValue(r, "mem_used_pct") >= 90 {
				bumpWarn(ipToDev[ip])
			}
		}
	}
	if m := instanceMonitor(); m != nil {
		for id, s := range m.Latest() {
			if s != nil && !s.OK {
				bumpWarn(ipToDev[targetIP(m, id)])
			}
		}
	}

	// 2026-09-30 用户反馈"设备上线检测在线, 拓扑线却一直红": Asset.Alive 是扫描存活
	// 快照(长期不扫描就过期), 而 SNMP 采集是实时在线状态 —— 近期(3min 内)采集成功
	// 即设备可达(能回 SNMP 必在线), 端点由 down 升 normal, 存活快照不否决实时证据。
	if m := instanceMonitor(); m != nil {
		for id, s := range m.Latest() {
			if s == nil || !s.OK || time.Since(s.At) > 3*time.Minute {
				continue
			}
			if ip := targetIP(m, id); ip != "" {
				if ep := endpoints[ipToDev[ip]]; ep != nil && ep.level == "down" {
					ep.level = "normal"
				}
			}
		}
	}

	// ---- 边生成(确定性) ----
	type edgeKey struct{ a, b string } // 字典序小的在前
	edges := map[edgeKey]struct{}{}
	addEdge := func(x, y string) {
		if x == "" || y == "" || x == y || endpoints[x] == nil || endpoints[y] == nil {
			return
		}
		if x > y {
			x, y = y, x
		}
		edges[edgeKey{x, y}] = struct{}{}
	}

	// ① 资产 ↔ 探针(ProbeNode 纳管关系)
	for _, ref := range assetRefs {
		if ref.probe != "" {
			addEdge(ref.deviceID, "P_"+ref.probe)
		}
	}

	// ② 同 /24 网段星型(段代表=数值最小 IP): 交换机直连的常见形态, 用户可再手调。
	// 用数值比较而非字典序: "192.168.1.9" 字典序 > "192.168.1.10", 但数值更小。
	// 节点 = 资产 + 节点监控目标(2026-10-01: 用户绑定的交换机常是监控目标, 它所在的
	// /24 段代表与跨段链式边都要覆盖它); 探针不参与(其 Addr 是 agent 上报地址,
	// 与交换机直连形态无关, 且探针↔资产已有 ① 纳管边)。
	type segDev struct {
		deviceID, ip string
	}
	segDevs := make([]segDev, 0, len(assetRefs)+len(monRefs))
	for _, ref := range assetRefs {
		segDevs = append(segDevs, segDev{ref.deviceID, ref.ip})
	}
	for _, ref := range monRefs {
		segDevs = append(segDevs, segDev{ref.deviceID, ref.ip})
	}
	bySubnet := map[string][]string{}
	repOf := map[string]string{} // subnet -> 段代表 deviceID
	repNum := map[string]uint32{}
	for _, dev := range segDevs {
		ip4 := net.ParseIP(dev.ip).To4()
		if ip4 == nil {
			continue
		}
		key := fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		bySubnet[key] = append(bySubnet[key], dev.deviceID)
		num := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		if cur, ok := repNum[key]; !ok || num < cur {
			repNum[key] = num
			repOf[key] = dev.deviceID
		}
	}
	for key, devs := range bySubnet {
		rep := repOf[key]
		for _, dev := range devs {
			if dev != rep {
				addEdge(dev, rep)
			}
		}
	}
	// ③ 跨网段: 段代表按段排序链式相连
	if len(bySubnet) > 1 {
		keys := make([]string, 0, len(bySubnet))
		for k := range bySubnet {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i := 0; i+1 < len(keys); i++ {
			addEdge(repOf[keys[i]], repOf[keys[i+1]])
		}
	}

	// ---- 流量: monitor 接口差分(IP -> inBps/outBps/bandwidthBps) ----
	rateByIP := map[string]linkRate{}
	if m := instanceMonitor(); m != nil {
		prevAll := m.Prev()
		for id, s := range m.Latest() {
			if s == nil || !s.OK {
				continue
			}
			prev := prevAll[id]
			if prev == nil || s.At.Before(prev.At) || s.At.Sub(prev.At) <= 0 {
				continue
			}
			dt := s.At.Sub(prev.At).Seconds()
			var inB, outB, bw float64
			for i := range s.Ifaces {
				cur := &s.Ifaces[i]
				old := findIface(prev, cur.Index)
				if old == nil || cur.Oper != 1 {
					continue
				}
				if dIn := cur.In - old.In; dIn > 0 {
					inB += float64(dIn) / dt
				}
				if dOut := cur.Out - old.Out; dOut > 0 {
					outB += float64(dOut) / dt
				}
				if cur.Speed > 0 {
					bw += float64(cur.Speed)
				}
			}
			if ip := targetIP(m, id); ip != "" {
				rateByIP[ip] = linkRate{inBps: inB, outBps: outB, bw: bw}
			}
		}
	}

	// ---- 组装(按端点字典序输出, 确定性) ----
	list = make([]map[string]any, 0, len(edges))
	for k := range edges {
		ea, eb := endpoints[k.a], endpoints[k.b]
		status := ea.level
		if levelRank(eb.level) > levelRank(status) {
			status = eb.level
		}
		// 自动连通测试(2026-09-30): 两端都 online 的链路才测(端点 down 必红, 不必测);
		// 检查失败 = down(上线检测过但连接测试失败), 通过 = 保持端点推导状态(绿线)。
		var chk autoCheckRes
		hasChk := false
		if status != "down" && ea.ip != "" && eb.ip != "" {
			key := linkCheckKey(k.a, k.b)
			maybeAutoCheck(key, ea.ip, eb.ip)
			if r, fresh := autoCheckFresh(key); fresh {
				chk, hasChk = r, true
				if !r.ok {
					status = "down"
				}
			}
		}
		// 流量取两端较高者(链路真实流量无法从两端接口和还原, 取 max 是保守近似);
		// trafficSide 记录被采样端, 前端据此定向线上上/下传方向(采样端 in=流向该端, out=流向对端)
		r := rateByIP[ea.ip]
		trafficSide := ea.deviceID
		if utilOf(rateByIP[eb.ip]) > utilOf(r) {
			r = rateByIP[eb.ip]
			trafficSide = eb.deviceID
		}
		l := map[string]any{
			"linkId":       "lk_" + k.a + "~" + k.b,
			"fromDeviceId": k.a,
			"toDeviceId":   k.b,
			"status":       status,
			"packetLoss":   0,
			"delay":        0,
			"pps":          0,
		}
		if hasChk {
			l["tested"] = true
			l["rttMs"] = chk.rtt
		}
		if r.bw > 0 {
			used := (r.inBps + r.outBps) * 8
			util := used / r.bw * 100
			if util > 100 {
				util = 100
			}
			l["bandwidth"] = int64(r.bw / 1e6)
			l["bandwidthUsed"] = round1(used / 1e6)
			l["utilPct"] = round1(util)
			l["pps"] = int64((r.inBps + r.outBps) / 1400) // 按平均 1400B/包近似
			// 每方向真实上下行速率(2026-09-30: 前端线上箭头/双向光点按此定向, 无数据不画)
			l["inMps"] = round2(r.inBps * 8 / 1e6)
			l["outMps"] = round2(r.outBps * 8 / 1e6)
			l["trafficSide"] = trafficSide
		}
		list = append(list, l)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		return a["fromDeviceId"].(string)+a["toDeviceId"].(string) < b["fromDeviceId"].(string)+b["toDeviceId"].(string)
	})
	return list, true
}

func utilOf(r linkRate) float64 {
	if r.bw <= 0 {
		return 0
	}
	u := (r.inBps + r.outBps) * 8 / r.bw * 100
	if u > 100 {
		return 100
	}
	return u
}

func levelRank(s string) int {
	switch s {
	case "down":
		return 2
	case "warn":
		return 1
	default:
		return 0
	}
}

func findIface(prev *monitor.Sample, index string) *monitor.IfaceSample {
	for i := range prev.Ifaces {
		if prev.Ifaces[i].Index == index {
			return &prev.Ifaces[i]
		}
	}
	return nil
}

// targetIP 监控目标 Addr("host:port") -> IP(host 部分)。
func targetIP(m *monitor.Monitor, targetID string) string {
	for _, t := range m.Config().Targets {
		if t.ID == targetID {
			return hostPart(t.Addr)
		}
	}
	return ""
}

func hostPart(addr string) string {
	h := strings.TrimSpace(addr)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func round1(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}

// round2 两位小数(Mbps 小速率如 0.42 需要更细粒度, 前端再按 M/K 格式化)。
func round2(f float64) float64 {
	return math.Round(f*100) / 100
}

// hTopologyLinks GET /api/v2/topology/links
// 契约见文件头 + dashData.js 注释: 前端按 (fromDeviceId,toDeviceId) 对已有
// 链路做字段覆盖, 不依赖本接口的边集合做增删。
func hTopologyLinks(w http.ResponseWriter, r *http.Request) {
	list, ok := buildTopologyLinks()
	if !ok {
		server.FailInternal(w, "链路聚合失败: 数据层不可用")
		return
	}
	server.OK(w, map[string]any{
		"list":   list,
		"count":  len(list),
		"at":     time.Now().UTC().Format(time.RFC3339),
		"source": "api",
	})
}

// ===== 链路连通性测试(2026-09-29 用户要求: "连接起来后就要测试连通, 没连上不算通") =====
//
// POST /api/v2/topology/links/check  body: {"ips":["1.2.3.4","5.6.7.8"]} (1-2 个 IP)
// 返回: {results:[{ip,up,rttMs,method}], ok, at}
//
// 前端手动连线只表示"拓扑关系", 不算连通 —— 本页对链路画线后必须经本接口
// 由中心端真实探测两端: ICMP echo 优先(中心默认 UAC 提权可用), ICMP 不可用时
// 降级 TCP 常见端口探测(22/80/443/161/3389, 任一开放即可达)。两端都可达才算
// "已连通"(ok=true), 任一不可达即"未连通"。结果与时间戳由前端存回链路记录。

var topoCheckSeq uint32

func hTopologyLinkCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		server.FailBadRequest(w, "请求体非法: "+err.Error())
		return
	}
	if len(body.IPs) < 1 || len(body.IPs) > 2 {
		server.FailBadRequest(w, "ips 需为 1-2 个 IP")
		return
	}
	results := make([]map[string]any, 0, len(body.IPs))
	ok := true
	for _, ip := range body.IPs {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) == nil {
			server.FailBadRequest(w, "非法 IP: "+ip)
			return
		}
		up, rtt, method := probeEndpointReachable(ip)
		if !up {
			ok = false
		}
		results = append(results, map[string]any{"ip": ip, "up": up, "rttMs": rtt, "method": method})
	}
	server.OK(w, map[string]any{
		"results": results,
		"ok":      ok,
		"at":      time.Now().UTC().Format(time.RFC3339),
	})
}

// probeEndpointReachable 单 IP 可达性探测: ICMP echo(最多 2 轮)优先,
// ICMP 不可用(无管理员权限等, PingICMP 返回 error)降级 TCP 常见端口探测。
// 返回是否可达、最小 RTT(ms, TCP 降级为 0)、实际命中的方式。
func probeEndpointReachable(ip string) (bool, int64, string) {
	var best int64
	icmpOK := false
	for i := 0; i < 2; i++ {
		seq := uint16(atomic.AddUint32(&topoCheckSeq, 1) & 0x7fff)
		if seq == 0 {
			seq = 1
		}
		up, rtt, err := scanner.PingICMP(ip, seq, 1200*time.Millisecond)
		if err != nil {
			break // ICMP 不可用 → 交给 TCP 探测, 不视为"失败"
		}
		if up {
			icmpOK = true
			if best == 0 || rtt < best {
				best = rtt
			}
			break // 已回包, 无需第二轮
		}
	}
	if icmpOK {
		return true, best, "icmp"
	}
	for _, port := range []int{22, 80, 443, 161, 3389} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 800*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true, 0, "tcp"
		}
	}
	return false, 0, "icmp+tcp"
}

// ===== 自动连通测试(2026-09-30 用户要求: 设备上线后应自动发起连接测试, 通过=绿线, 失败=红线) =====
//
// 口径: 只测"两端都非 down 且有 IP"的链路(端点已 down 的链路必红, 不必测);
// 结果内存缓存 30s(前端 15s 轮询 + SSE 5s 节流, 足够覆盖), 单飞(每链路至多一个
// 在途探测) + 全局并发上限 8, 全部后台执行 —— buildTopologyLinks 永不阻塞在探测上,
// API/SSE 快照保持快速。链路刚出现还没有检查结果时不降级(保持端点推导的状态),
// 后台探测完成后下一帧快照给出真实结果。

var (
	topoAutoCheckMu sync.Mutex
	topoAutoCheck   = map[string]autoCheckRes{} // linkKey -> 最近一次探测结果
	topoAutoBusy    = map[string]struct{}{}      // 在途单飞标记
	topoAutoSlots   = make(chan struct{}, 8)     // 全局并发上限
)

type autoCheckRes struct {
	ok     bool
	rtt    int64 // 两端最小 RTT(ms; TCP 降级或不可达为 0)
	at     time.Time
	method string
}

// topoAutoCheckTTL 自动检查结果有效期: 30s 覆盖 15s 轮询 + 5s SSE 节流,
// 又不让探测频率高到打扰目标设备。
const topoAutoCheckTTL = 30 * time.Second

// linkCheckKey 端点对的字典序键(与 edgeKey 排序一致, 同链路双向取同一键)。
func linkCheckKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "~" + b
}

func autoCheckFresh(key string) (autoCheckRes, bool) {
	topoAutoCheckMu.Lock()
	defer topoAutoCheckMu.Unlock()
	r, ok := topoAutoCheck[key]
	if !ok || time.Since(r.at) > topoAutoCheckTTL {
		return autoCheckRes{}, false
	}
	return r, true
}

// maybeAutoCheck 缓存过期时触发一次后台重测(不阻塞调用方)。
func maybeAutoCheck(key, ipA, ipB string) {
	topoAutoCheckMu.Lock()
	if _, busy := topoAutoBusy[key]; busy {
		topoAutoCheckMu.Unlock()
		return
	}
	if r, ok := topoAutoCheck[key]; ok && time.Since(r.at) <= topoAutoCheckTTL {
		topoAutoCheckMu.Unlock()
		return
	}
	topoAutoBusy[key] = struct{}{}
	topoAutoCheckMu.Unlock()

	select {
	case topoAutoSlots <- struct{}{}:
	default: // 并发上限已满: 跳过本轮(下一帧快照自然重试)
		topoAutoCheckMu.Lock()
		delete(topoAutoBusy, key)
		topoAutoCheckMu.Unlock()
		return
	}
	go func() {
		defer func() {
			<-topoAutoSlots
			topoAutoCheckMu.Lock()
			delete(topoAutoBusy, key)
			topoAutoCheckMu.Unlock()
		}()
		up1, rtt1, m1 := topoAutoProbe(ipA)
		up2, rtt2, m2 := topoAutoProbe(ipB)
		rtt := rtt1
		if rtt1 == 0 || rtt2 < rtt {
			rtt = rtt2
		}
		method := m1
		if m2 != m1 {
			method = m1 + "+" + m2
		}
		topoAutoCheckMu.Lock()
		topoAutoCheck[key] = autoCheckRes{ok: up1 && up2, rtt: rtt, at: time.Now(), method: method}
		topoAutoCheckMu.Unlock()
	}()
}

// topoAutoProbe 自动测试用的探测函数。变量化供单测注入假探测(单测不发真实
// ICMP/TCP); 生产恒为真实实现 probeEndpointReachableFast。
var topoAutoProbe = probeEndpointReachableFast

// SetTopoAutoProbeForTest 单测注入假探测, 返回还原函数(t.Cleanup 用)。
func SetTopoAutoProbeForTest(f func(ip string) (bool, int64, string)) func() {
	prev := topoAutoProbe
	topoAutoProbe = f
	return func() { topoAutoProbe = prev }
}

// probeEndpointReachableFast 自动测试路径的轻量探测: 1 轮 ICMP(800ms) + 2 个常见
// TCP 端口(23/161/80, 各 500ms)。手动"测试连通"按钮仍走更严格的 probeEndpointReachable
// (2 轮 ICMP + 5 端口) —— 自动路径要求快(单端最坏 ~2.3s), 手动路径要求全。
func probeEndpointReachableFast(ip string) (bool, int64, string) {
	seq := uint16(atomic.AddUint32(&topoCheckSeq, 1) & 0x7fff)
	if seq == 0 {
		seq = 1
	}
	if up, rtt, err := scanner.PingICMP(ip, seq, 800*time.Millisecond); err == nil && up {
		return true, rtt, "icmp"
	}
	for _, port := range []int{23, 161, 80} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true, 0, "tcp"
		}
	}
	return false, 0, "icmp+tcp"
}

// publishTopoLinks SSE 广播链路快照(5s 节流)。
// 触发点: SNMP 轮次完成(monitorOnRound) + 采集事件(collectOnEvent)。
// 失败静默(SSE 是增强通道, 前端 15s 轮询兜底)。
func publishTopoLinks() {
	topoLinkPubMu.Lock()
	if time.Since(topoLinkPubAt) < 5*time.Second {
		topoLinkPubMu.Unlock()
		return
	}
	topoLinkPubAt = time.Now()
	topoLinkPubMu.Unlock()

	list, ok := buildTopologyLinks()
	if !ok || list == nil {
		return
	}
	_ = sse.Default().PublishJSON("topolink", map[string]any{
		"links": list,
		"at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// registerTopologyLinksRoutes 装配(挂 /api/v2 子树, 与资产/漏洞同一鉴权口径)。
func registerTopologyLinksRoutes(srv *server.Server) {
	srv.Get("/api/v2/topology/links", requireAuth(hTopologyLinks))
	// 链路连通性测试(手动连线后"测连通", 前端按结果标记 已连通/未连通)
	srv.Post("/api/v2/topology/links/check", requireAuth(hTopologyLinkCheck))
}

// resetTopologyLinksForTest 测试复位(节流时间戳)。
func resetTopologyLinksForTest() {
	topoLinkPubMu.Lock()
	topoLinkPubAt = time.Time{}
	topoLinkPubMu.Unlock()
}
