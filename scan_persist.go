package main

// scan_persist.go 本地扫描结果落 v2 库(单机模式下 v2 表不再全空)。
//
// 背景: runScanPipeline 原本只把 finding 推 SSE, 唯一落库路径(probe_normalize.go)
// 只覆盖探针回传 —— 单机模式下 v2 的 14 张表全空, 报告/大屏/资产/漏洞页无数据来源。
//
// 本文件在扫描收尾时把「已过白名单 / 已标误报」的 finding 与资产归一化后 upsert 到 v2 库:
//
//	finding 事件 → normalizer.RawVuln → NormalizeWithOptions(统一合并键) → models.Vuln
//	port / host / web 资产 → normalizer.RawAsset → models.Asset
//
// 为什么统一走 normalizer 而不是直接字段映射: 漏洞的"跨扫描不重复增长"依赖
// models.Vuln 的稳定 ID(资产+协议:端口+标题 / CVE), 手写映射迟早与探针链路漂移。
//
// 约束(项目规则 3/4):
//   - v2DB() 可能为 nil(未启用/初始化失败), db.Close() 还会把各 DAO 置 nil ——
//     装箱进接口后 `== nil` 判不出来(必须反射), 一律记日志跳过, 绝不 panic;
//   - 不改动既有 SSE 事件与扫描行为, 只在收尾追加一次落库。

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"yugsight/db"
	"yugsight/models"
	"yugsight/normalizer"
	"yugsight/scanner"
)

// scanSink 一次本地扫描的落库收集器(并发安全: 扫描器在多个 goroutine 里 emit)。
//
// 为什么不在 emit 里逐条写库: 归一化需要跨条合并(同资产 + 同漏洞只增长 LastSeen),
// 逐条写会绕过 normalizer 的合并键, 也会把"每次全表落盘"放大成 O(n) 次。
type scanSink struct {
	mu     sync.Mutex
	req    scanReq
	ip     string // 目标 IP(finding 未带 host 时的兜底)
	port   int    // 目标端口(finding 未带 port 时的兜底)
	finds  []scanFinding
	assets []normalizer.RawAsset
	// alive 本轮存活判定(ip 事件): ip -> 判定结果。
	// 功能审计 §2-3: 存活扫描的结论此前从未回写资产表, 大屏 assetsAlive 恒为 0。
	alive map[string]aliveRecord
	// ports 开放端口明细(port 事件): ip -> 端口列表。
	// 统一扫描(unified)的端口细节只经 emit 事件流出, 不经函数返回值 ——
	// 从事件收集是它能进资产台账的唯一途径(与 finding 事件同口径)。
	ports map[string][]portOpenRec
}

// aliveRecord 单台主机本轮的存活判定(源: ip 事件)。
type aliveRecord struct {
	alive bool
	mac   string
}

// portOpenRec 一条开放端口明细(源: port 事件, 仅 state=open)。
type portOpenRec struct {
	port    int
	service string
	banner  string
}

// scanFinding 收集到的一条 finding(已过白名单过滤, 可能带误报标记)。
type scanFinding struct {
	source string // finding 自带来源(nuclei / nuclei-builtin / engine), 空 = 内置规则
	raw    scanFindingJSON
}

// scanFindingJSON finding 事件的字段视图。
//
// 事件体有三种形态(scanner.Finding / scanner.NucleiFinding / withFPFlag 后的 map),
// 统一按 JSON 解一次即可, 不必为每种类型写一份转换(新增字段只加一行)。
type scanFindingJSON struct {
	Severity      string `json:"severity"`
	Title         string `json:"title"`
	Detail        string `json:"detail"`
	Fix           string `json:"fix,omitempty"`
	Source        string `json:"source,omitempty"`
	CVE           string `json:"cve,omitempty"`
	Path          string `json:"path,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port"`
	TemplateID    string `json:"templateId,omitempty"`
	RawRequest    string `json:"rawRequest,omitempty"`
	RawResponse   string `json:"rawResponse,omitempty"`
	Request       string `json:"request,omitempty"`
	Response      string `json:"response,omitempty"`
	FalsePositive bool   `json:"falsePositive,omitempty"`
	FPNote        string `json:"fpNote,omitempty"`
}

// newScanSink 构造收集器(ip/port 为 finding 缺字段时的兜底目标)。
func newScanSink(req scanReq, ip string, port int) *scanSink {
	return &scanSink{
		req:   req,
		ip:    strings.TrimSpace(ip),
		port:  port,
		alive: make(map[string]aliveRecord),
		ports: make(map[string][]portOpenRec),
	}
}

// observe 收集扫描事件: finding(漏洞) / ip(存活判定) / port(开放端口明细)。
// 其余事件原样忽略, 零开销。
func (s *scanSink) observe(event string, data any) {
	if data == nil {
		return
	}
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	switch event {
	case "finding":
		var f scanFindingJSON
		if json.Unmarshal(b, &f) != nil {
			return
		}
		if strings.TrimSpace(f.Title) == "" {
			return // 无标题的提示类事件(如"未发现开放端口")不入库
		}
		s.mu.Lock()
		s.finds = append(s.finds, scanFinding{source: strings.TrimSpace(f.Source), raw: f})
		s.mu.Unlock()
	case "ip":
		// 存活判定回写源(功能审计 §2-3)。excludedByStrict = 严格模式下
		// 仅端口开放的主机, 不计入存活 —— 但在收集期就归一, flush 只管写。
		var ev struct {
			IP               string `json:"ip"`
			Alive            bool   `json:"alive"`
			MAC              string `json:"mac"`
			ExcludedByStrict bool   `json:"excludedByStrict"`
		}
		if json.Unmarshal(b, &ev) != nil || strings.TrimSpace(ev.IP) == "" {
			return
		}
		s.mu.Lock()
		s.alive[models.NormIP(ev.IP)] = aliveRecord{alive: ev.Alive && !ev.ExcludedByStrict, mac: ev.MAC}
		s.mu.Unlock()
	case "port":
		var ev struct {
			IP      string `json:"ip"`
			Port    int    `json:"port"`
			State   string `json:"state"`
			Service string `json:"service"`
			Banner  string `json:"banner"`
		}
		if json.Unmarshal(b, &ev) != nil || ev.State != "open" || ev.Port <= 0 {
			return
		}
		ip := strings.TrimSpace(ev.IP)
		if ip == "" {
			return
		}
		s.mu.Lock()
		s.ports[models.NormIP(ip)] = append(s.ports[models.NormIP(ip)],
			portOpenRec{port: ev.Port, service: ev.Service, banner: ev.Banner})
		s.mu.Unlock()
	}
}

// addPortResults 端口扫描结果 → 资产(只记开放端口; 全关则不产生资产)。
func (s *scanSink) addPortResults(ip string, rs []scanner.PortResult) {
	ra := normalizer.RawAsset{IP: ip, FoundAt: time.Now()}
	for _, r := range rs {
		if r.State != "open" {
			continue
		}
		ra.Ports = append(ra.Ports, r.Port)
		if ra.Service == "" {
			ra.Service = r.Service
		}
		if ra.Banner == "" {
			ra.Banner = r.Banner
		}
	}
	if len(ra.Ports) == 0 {
		return
	}
	s.mu.Lock()
	s.assets = append(s.assets, ra)
	s.mu.Unlock()
}

// addServiceAssets 主机/Web 扫描的服务指纹 → 资产(同 IP 多端口合并为一个资产)。
func (s *scanSink) addServiceAssets(as []scanner.ServiceAsset) {
	byIP := make(map[string]*normalizer.RawAsset)
	order := make([]string, 0, len(as))
	for _, a := range as {
		if strings.TrimSpace(a.IP) == "" {
			continue
		}
		ra, ok := byIP[a.IP]
		if !ok {
			ra = &normalizer.RawAsset{IP: a.IP, FoundAt: time.Now()}
			byIP[a.IP] = ra
			order = append(order, a.IP)
		}
		if a.Port > 0 {
			ra.Ports = append(ra.Ports, a.Port)
		}
		if ra.Service == "" {
			ra.Service = a.Product
		}
		if ra.Version == "" {
			ra.Version = a.Version
		}
		if ra.Banner == "" {
			ra.Banner = a.Banner
		}
	}
	if len(order) == 0 {
		return
	}
	s.mu.Lock()
	for _, ip := range order {
		s.assets = append(s.assets, *byIP[ip])
	}
	s.mu.Unlock()
}

// addModelAssets 已归一化的资产(引擎编排产物)直接并入收集器。
func (s *scanSink) addModelAssets(as []*models.Asset) {
	now := time.Now()
	out := make([]normalizer.RawAsset, 0, len(as))
	for _, a := range as {
		if a == nil || strings.TrimSpace(a.IP) == "" {
			continue
		}
		out = append(out, normalizer.RawAsset{
			IP: a.IP, MAC: a.MAC, Hostname: a.Hostname, OS: a.OS, Ports: a.Ports,
			Service: a.Service, Version: a.Version, Banner: a.Banner, Tags: a.Tags, FoundAt: now,
		})
	}
	if len(out) == 0 {
		return
	}
	s.mu.Lock()
	s.assets = append(s.assets, out...)
	s.mu.Unlock()
}

// rawPayload 本轮收集的原始结果快照(报告中心"原始报告"的数据源)。
//
// 口径与落库一致: 只含已过白名单过滤 / 已标误报的 finding —— 报告中心存的是
// "这次扫描真实产出的结构化结果", 不是被过滤掉的全过程。切片整体复制,
// 调用方持有期间即使扫描侧再收数据也不会串改。
func (s *scanSink) rawPayload() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	finds := make([]scanFindingJSON, 0, len(s.finds))
	for _, f := range s.finds {
		finds = append(finds, f.raw)
	}
	assets := make([]normalizer.RawAsset, len(s.assets))
	copy(assets, s.assets)
	alive := make(map[string]aliveRecord, len(s.alive))
	for k, v := range s.alive {
		alive[k] = v
	}
	ports := make(map[string][]portOpenRec, len(s.ports))
	for k, v := range s.ports {
		cp := make([]portOpenRec, len(v))
		copy(cp, v)
		ports[k] = cp
	}
	return map[string]any{
		"findings": finds,
		"assets":   assets,
		"alive":    alive,
		"ports":    ports,
	}
}

// normalize 收集到的 finding + 资产 → 统一归一化结果(纯函数, 便于单测)。
// 无数据返回 nil(不触发落库, 避免无意义写盘)。
func (s *scanSink) normalize() *normalizer.Result {
	s.mu.Lock()
	finds := append([]scanFinding(nil), s.finds...)
	assets := append([]normalizer.RawAsset(nil), s.assets...)
	ip, port := s.ip, s.port
	s.mu.Unlock()
	if len(finds) == 0 && len(assets) == 0 {
		return nil
	}
	scanID := "local-" + time.Now().UTC().Format("20060102-150405")
	defSrc := localScanSource(s.req.Type)
	// 资产一批; 漏洞按来源分批(finding 自带 nuclei/engine 来源时保留, 否则按扫描类型兜底)
	batches := []*normalizer.RawBatch{{Source: defSrc, ScanID: scanID, Assets: assets}}
	bySrc := make(map[string][]normalizer.RawVuln)
	srcOrder := make([]string, 0, 2)
	fpNotes := make(map[string]string) // 合并键 → 误报备注
	for _, f := range finds {
		src := f.source
		if src == "" {
			src = defSrc
		}
		if _, ok := bySrc[src]; !ok {
			srcOrder = append(srcOrder, src)
		}
		rv := f.raw.rawVuln(ip, port)
		bySrc[src] = append(bySrc[src], rv)
		if f.raw.FalsePositive {
			fpNotes[vulnMergeKey(rv)] = f.raw.FPNote
		}
	}
	for _, src := range srcOrder {
		batches = append(batches, &normalizer.RawBatch{Source: src, ScanID: scanID, Vulns: bySrc[src]})
	}
	res := normalizer.NormalizeWithOptions(normalizer.Options{ScanID: scanID}, batches...)
	if res == nil {
		return nil
	}
	// 误报标记回填: emitAI 已在事件上打了 falsePositive, 归一化后按同一合并键还原
	for _, v := range res.Vulns {
		if note, ok := fpNotes[v.MergeKey()]; ok {
			v.FalsePositive = true
			v.FPNote = note
		}
	}
	return res
}

// mergePortEvents 把 port 事件收集到的开放端口并入资产集。
//
// 同 IP 多条 RawAsset 由 normalizer 的 mergeRawAsset 按 IP 合并(端口并集、
// 字段首非空), 与 host/web 的 addServiceAssets 产物重复时无需额外去重。
func (s *scanSink) mergePortEvents() {
	s.mu.Lock()
	byIP := s.ports
	s.mu.Unlock()
	for ip, recs := range byIP {
		if len(recs) == 0 {
			continue
		}
		ra := normalizer.RawAsset{IP: ip, FoundAt: time.Now()}
		for _, r := range recs {
			ra.Ports = append(ra.Ports, r.port)
			if ra.Service == "" {
				ra.Service = r.service
			}
			if ra.Banner == "" {
				ra.Banner = r.banner
			}
		}
		s.mu.Lock()
		s.assets = append(s.assets, ra)
		s.mu.Unlock()
	}
}

// applyAliveState 把本轮存活判定回写资产 Alive 字段(功能审计 §2-3)。
//
// 两条路径, 缺一不可:
//  1. 已有数据的资产(端口/服务/漏洞) → 直接置 Alive;
//  2. 仅有存活判定的 IP(无开放端口、无 finding) → 生成最小资产入账 ——
//     "在线但没有开放探测端口"同样是真实资产, 大屏"在线资产"统计依赖它。
//
// 只判定的 IP 集为空时原样返回(纯 web/host 单点扫描无 ip 事件, 零影响)。
func (s *scanSink) applyAliveState(res *normalizer.Result) *normalizer.Result {
	s.mu.Lock()
	alive := make(map[string]aliveRecord, len(s.alive))
	for ip, rec := range s.alive {
		alive[ip] = rec
	}
	s.mu.Unlock()
	if len(alive) == 0 {
		return res
	}
	if res == nil {
		res = &normalizer.Result{
			ScanID: "local-" + time.Now().UTC().Format("20060102-150405"),
			Assets: []*models.Asset{},
		}
	}
	covered := make(map[string]bool, len(res.Assets))
	for _, a := range res.Assets {
		if a == nil {
			continue
		}
		ip := models.NormIP(a.IP)
		covered[ip] = true
		if rec, ok := alive[ip]; ok {
			a.Alive = rec.alive
			// 端口事件路径生成的资产不带 MAC(只有 ip 事件才有), 顺带补齐。
			if a.MAC == "" && rec.mac != "" {
				a.MAC = rec.mac
			}
		}
	}
	now := time.Now()
	for ip, rec := range alive {
		if covered[ip] {
			continue
		}
		a := &models.Asset{
			IP:      ip,
			MAC:     rec.mac,
			Alive:   rec.alive,
			FoundAt: now,
		}
		a.ID = a.StableID()
		res.Assets = append(res.Assets, a)
	}
	return res
}

// flush 归一化并落库(失败只记日志, 不影响扫描结果推送)。
func (s *scanSink) flush() {
	s.mergePortEvents()
	res := s.normalize()
	res = s.applyAliveState(res)
	if res == nil {
		return
	}
	assets, vulns, failed := persistScanResult(v2DB(), res)
	if assets+vulns+failed == 0 {
		return
	}
	logLine(fmt.Sprintf("本地扫描结果落库: 任务 %s, 资产 %d, 漏洞 %d, 失败 %d",
		res.ScanID, assets, vulns, failed))
}

// localScanSource 本地扫描 finding 的默认来源标记。
//
// 端口类沿用 normalizer 的 portscan; host/web 的内置规则库 finding 用 "builtin",
// 与 nuclei / nuclei-builtin / engine / probe 等来源在同一字段上区分(漏洞页可按来源筛选)。
func localScanSource(typ string) string {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "ip", "alive", "port", "unified":
		return normalizer.SourcePortScan
	default:
		return "builtin"
	}
}

// rawVuln finding 字段 → 归一化原始漏洞(ip/port 为兜底目标)。
func (f scanFindingJSON) rawVuln(ip string, port int) normalizer.RawVuln {
	desc := strings.TrimSpace(f.Detail)
	if fix := strings.TrimSpace(f.Fix); fix != "" {
		// 修复建议并入描述: models.Vuln 无独立 fix 字段, 而报告页要能看到处理建议
		desc = strings.TrimSpace(desc + "\n修复建议: " + fix)
	}
	host := strings.TrimSpace(f.Host)
	if host == "" {
		host = ip
	}
	p := f.Port
	if p == 0 {
		p = port
	}
	ev := firstNonEmpty(f.RawResponse, f.Response)
	return normalizer.RawVuln{
		AssetIP:     host,
		Port:        p,
		CVE:         f.CVE,
		Title:       strings.TrimSpace(f.Title),
		Severity:    f.Severity,
		Description: desc,
		Evidence:    ev,
		Request:     firstNonEmpty(f.RawRequest, f.Request),
		Response:    ev,
		FoundAt:     time.Now(),
	}
}

// vulnMergeKey 与 models.Vuln.MergeKey 同口径的键(用于把事件级标记还原到归一化结果)。
func vulnMergeKey(rv normalizer.RawVuln) string {
	return (&models.Vuln{
		AssetIP:  rv.AssetIP,
		Port:     rv.Port,
		Protocol: rv.Protocol,
		CVE:      rv.CVE,
		Title:    rv.Title,
	}).MergeKey()
}

// persistScanResult 归一化结果落 v2 库, 返回 (资产数, 漏洞数, 失败数)。
//
// 三重守卫, 缺一不可(与 probe_normalize.go 的探针落库同口径):
//  1. d == nil                 —— 数据库未启用或初始化失败
//  2. Assets()/Vulns() typed-nil —— 数据库已 Close(Close 把各 DAO 置 nil;
//     装箱进接口后 `== nil` 判不出来, 必须用反射 —— 这是插件式落库最常见的崩溃点)
//  3. 单条写入失败               —— 只计数 + 记日志, 不影响其余条目
func persistScanResult(d *db.Database, res *normalizer.Result) (assets, vulns, failed int) {
	if res == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			logLine(fmt.Sprintf("本地扫描结果落库异常(已恢复): %v", p))
		}
	}()
	if d == nil {
		logLine("本地扫描结果未落库: 数据库不可用(未启用或初始化失败)")
		return
	}
	assetDAO, vulnDAO := d.Assets(), d.Vulns()
	if isNilDAO(assetDAO) || isNilDAO(vulnDAO) {
		logLine("本地扫描结果未落库: 数据库已关闭或表未就绪")
		return
	}
	// 复用探针链路的幂等 upsert(同为"同资产/同漏洞跨扫描不重复增长");
	// probeID 传空 = 本机扫描(资产不归属任何探针节点), ScanTaskID 用本轮 scanID。
	for _, a := range res.Assets {
		if a == nil || strings.TrimSpace(a.IP) == "" {
			continue
		}
		if err := upsertProbeAsset(assetDAO, "", a); err != nil {
			failed++
			logLine("本地扫描资产落库失败: " + err.Error())
			continue
		}
		assets++
	}
	for _, v := range res.Vulns {
		if v == nil || strings.TrimSpace(v.AssetIP) == "" || strings.TrimSpace(v.Title) == "" {
			continue
		}
		if err := upsertProbeVuln(vulnDAO, res.ScanID, v); err != nil {
			failed++
			logLine("本地扫描漏洞落库失败: " + err.Error())
			continue
		}
		vulns++
	}
	return
}

// isNilDAO 判断 DAO 是否为 typed-nil(动态类型存在但值为 nil 的指针)。
//
// 与 db.isNilAny 同口径 —— 那份实现未导出, 故在本包复刻一份:
// db.Close() 会把 *AssetDAO / *VulnDAO 置 nil, 装箱进接口后 `dao == nil` 为 false,
// 直接调用方法会 nil 解引用崩溃(进程静默消失, recover 都拦不住的那种)。
func isNilDAO(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan:
		return rv.IsNil()
	}
	return false
}
