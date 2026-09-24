// Package scanner 探针本地扫描能力集(任务 6.4)。
//
// 定位: probe/agentexec 的"扫描实现层" —— 把中心端下发的任务参数落到本机扫描能力上,
// 产出**归一化后的探针报告**(normalizer.ProbeReport 口径), 由 agentexec 回传中心端,
// 中心端统一送入 normalizer 归一化模块处理(models.Asset / models.Vuln)。
//
// 依赖边界(关键): 只依赖 probe + scanner + normalizer + models + 标准库。
//
//	不依赖 db / engine / sse / http / main 包 —— 因此可以被独立的 yugsight-agent
//	二进制安全引用, 保证探针产物小、零入站端口、无 Web 攻击面(见 cmd/agent)。
//
// 能力集:
//
//	1. 主机存活探测: ICMP ping + TCP ping + ARP 探测(ARP 仅 Windows, 三重互补)
//	2. 端口扫描:    Go 原生全连接扫描; bin/nmapcore 存在时可切 nmap(SYN/服务识别)
//	3. 服务识别:    端口 Banner 读取 + 服务名 + 版本指纹; nmap 存在时用 nmap -sV
//	4. 漏洞验证:    内置 Nuclei 模板执行(POC); trivycore/zapcore 存在时增强扫描
//	5. 任务生命周期: 进度上报 / 取消(context) / 超时(由 client 层控制)
//
// 归一化口径(与中心端 normalizer/probe.go 严格对齐, 勿随意改名):
//
//	ProbeReport{nodeId, scanId, time, assets[], vulns[]}
//	ProbeAsset{ip, mac, hostname, os, ports[], service, version, banner, tags[]}
//	ProbeVuln {ip, port, protocol, cve, title, severity, description, evidence,
//	           request, response, cvss, confidence, pcapFile, foundAt}
//
// 默认全部能力可用但可关; 外部引擎(./bin/)缺失时静默降级为内置能力, 不报错(项目规则 3)。
package scanner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"yugsight/models"
	"yugsight/normalizer"
	"yugsight/scanner"
)

// ===== 配置 =====

// Timeouts 探针扫描超时参数(集中定义便于按网络质量调整)。
type Timeouts struct {
	Dial       time.Duration // 单端口 TCP 连接超时
	ICMP       time.Duration // 单次 ICMP 应答等待
	BannerRead time.Duration // Banner 读取超时
	Engine     time.Duration // 单个外部引擎执行超时
}

// DefaultTimeouts 默认超时(与主程序 handleScan 口径接近, 便于结果一致)。
func DefaultTimeouts() Timeouts {
	return Timeouts{
		Dial:       1200 * time.Millisecond,
		ICMP:       800 * time.Millisecond,
		BannerRead: 1200 * time.Millisecond,
		Engine:     5 * time.Minute,
	}
}

// Config 探针扫描配置。
//
// 零值即"内置能力全开 + 外部引擎自动探测", 不需要额外配置即可工作;
// 中心端可通过 TaskAssign.Args 覆盖(如 {"noNuclei": true, "noArp": true})。
type Config struct {
	// NodeID 探针标识(写入报告 nodeId, 中心端据此归档来源节点)
	NodeID string
	// ScanID 扫描任务 ID(写入报告 scanId; 空则用 TaskID)
	ScanID string
	// Ports 端口列表(空则用 DefaultPorts)
	Ports []int
	// Concurrency 并发度(端口/主机级; 0 取 200)
	Concurrency int
	// Timeout 各类超时(零值取 DefaultTimeouts)
	Timeout Timeouts

	// EnableNuclei 执行内置 Nuclei 模板做 POC 验证(默认 true)
	EnableNuclei bool
	// NucleiTags / NucleiTagsExclude 模板 tag 黑白名单(如 "cisa-kev,critical")
	NucleiTags        []string
	NucleiTagsExclude []string

	// EnableArp ARP 存活探测(仅 Windows 生效; 默认 true, 平台不支持时自动跳过)
	EnableArp bool
	// EnableSynScan SYN 半开扫描(仅 Windows + 管理员权限; 默认 false)。
	// 不支持的平台/权限自动降级为全连接扫描(记日志, 不报错), 见 syn.go。
	EnableSynScan bool
	// EnableExternal 允许调用 ./bin/ 下的外部引擎增强(nmapcore/trivycore/zapcore)
	EnableExternal bool
	// ExtraArgs 外部引擎追加参数, 由中心端经 TaskAssign.Args 下发。
	//
	// 例: {"nmapArgs": ["-sS","-A"], "trivyArgs": ["--severity","HIGH"]}
	// 允许中心端按目标特性微调引擎行为, 无需探针端升级。
	ExtraArgs map[string]any
}

// withDefaults 补齐零值(不修改调用方结构体)。
func (c Config) withDefaults() Config {
	if len(c.Ports) == 0 {
		c.Ports = DefaultPorts
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 200
	}
	d := DefaultTimeouts()
	if c.Timeout.Dial <= 0 {
		c.Timeout.Dial = d.Dial
	}
	if c.Timeout.ICMP <= 0 {
		c.Timeout.ICMP = d.ICMP
	}
	if c.Timeout.BannerRead <= 0 {
		c.Timeout.BannerRead = d.BannerRead
	}
	if c.Timeout.Engine <= 0 {
		c.Timeout.Engine = d.Engine
	}
	return c
}

// DefaultPorts 探针默认端口集(与主机扫描口径一致)。
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445, 465, 587,
	993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 11211, 27017,
}

// ErrCanceled 任务被中心端取消(与 context.Canceled 区分, 便于上层给出友好提示)。
var ErrCanceled = errors.New("探针任务已取消")

// ArpHardwareAvailable 本机是否具备 ARP 存活探测能力(仅 Windows 为 true)。
//
// 转发 scanner 的实现, 让 agentexec 只需依赖本包就能拿到全部能力信息
// (避免上层同时引 scanner 与 probe/scanner 两个包)。
//
// 注意: 这里**不能**写成 `return ArpHardwareAvailable()` —— 那是自身递归调用,
// 会栈溢出崩溃; 必须显式限定 scanner 包名。
func ArpHardwareAvailable() bool { return scanner.ArpHardwareAvailable() }

// ===== 进度回调 =====

// Progress 进度回调: 一条人类可读消息(经 MsgTaskProgress 实时上报中心端)。
// 允许为 nil(不关心进度的调用方直接传 nil)。
type Progress func(string)

// Emit 安全发送进度(nil 安全 + 限长, 防止超长消息撑爆协议单行 JSON 上限)。
//
// 导出以便上层(agentexec / 测试)构造进度回调时不必各自判空。
func (p Progress) Emit(msg string) {
	if p == nil || strings.TrimSpace(msg) == "" {
		return
	}
	// 协议单条消息上限 4MB, 但进度消息没必要很长; 截断避免异常内容放大传输
	if len(msg) > 500 {
		msg = msg[:500] + "..."
	}
	p(msg)
}

// ===== 任务上下文 =====

// Task 一次探针扫描任务的运行上下文。
type Task struct {
	Kind   string // ip / port / web / host / alive
	Target string // 目标 IP / CIDR / URL
	cfg    Config

	// progress 进度回调(由 Run 注入; 内部降级提示走它, 保证中心端能看到"为什么慢了")。
	// nil 安全(Emit 方法内判空), 直接构造 Task 调用内部方法的场景不受影响。
	progress Progress

	// cap 抓包会话(未启用时为 nil; 见 pcap.go 的 MVP 骨架)
	cap *Capture

	mu      sync.Mutex
	assets  map[string]*assetAcc // ip -> 累计资产
	vulns   map[string]*normalizer.ProbeVuln
	scanned int // 已处理目标数(进度用)
	events  int // 产出的发现数
}

// assetAcc 单主机资产累加器(多阶段扫描同一 IP 时合并端口/指纹)。
type assetAcc struct {
	normalizer.ProbeAsset
	portSet map[int]bool
}

// NewTask 创建任务上下文。
func NewTask(kind, target string, cfg Config) *Task {
	cfg = cfg.withDefaults()
	if cfg.ScanID == "" {
		cfg.ScanID = fmt.Sprintf("probe-%d", time.Now().UnixNano())
	}
	return &Task{
		Kind:   strings.ToLower(strings.TrimSpace(kind)),
		Target: strings.TrimSpace(target),
		cfg:    cfg,
		assets: make(map[string]*assetAcc),
		vulns:  make(map[string]*normalizer.ProbeVuln),
	}
}

// addAsset 登记/合并一个资产(同 IP 合并端口并集, 非空字段优先保留)。
func (t *Task) addAsset(a normalizer.ProbeAsset) {
	ip := models.NormIP(a.IP)
	if ip == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	acc, ok := t.assets[ip]
	if !ok {
		acc = &assetAcc{ProbeAsset: normalizer.ProbeAsset{IP: ip}, portSet: map[int]bool{}}
		t.assets[ip] = acc
	}
	for _, p := range a.Ports {
		if p > 0 && !acc.portSet[p] {
			acc.portSet[p] = true
			acc.Ports = append(acc.Ports, p)
		}
	}
	if acc.MAC == "" {
		acc.MAC = strings.TrimSpace(a.MAC)
	}
	if acc.Hostname == "" {
		acc.Hostname = strings.TrimSpace(a.Hostname)
	}
	if acc.OS == "" {
		acc.OS = strings.TrimSpace(a.OS)
	}
	if acc.Service == "" {
		acc.Service = strings.TrimSpace(a.Service)
	}
	if acc.Version == "" {
		acc.Version = strings.TrimSpace(a.Version)
	}
	if acc.Banner == "" {
		acc.Banner = strings.TrimSpace(a.Banner)
	}
	for _, tag := range a.Tags {
		if tag = strings.TrimSpace(tag); tag != "" && !containsStr(acc.Tags, tag) {
			acc.Tags = append(acc.Tags, tag)
		}
	}
}

// addVuln 登记一条漏洞(同资产+同 CVE/标题去重, 保留置信度更高的证据)。
func (t *Task) addVuln(v normalizer.ProbeVuln) {
	ip := models.NormIP(v.IP)
	if ip == "" {
		return
	}
	v.IP = ip
	if v.FoundAt.IsZero() {
		v.FoundAt = time.Now()
	}
	key := vulnKey(v)
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.vulns[key]; ok {
		// 保留更完整的证据: 已有 request/response 时不覆盖; 否则补全
		if old.Request == "" && v.Request != "" {
			old.Request = v.Request
		}
		if old.Response == "" && v.Response != "" {
			old.Response = v.Response
		}
		if old.Evidence == "" && v.Evidence != "" {
			old.Evidence = v.Evidence
		}
		if v.Confidence > old.Confidence {
			old.Confidence = v.Confidence
		}
		return
	}
	vuln := v
	t.vulns[key] = &vuln
}

// Report 汇总为探针报告(可直接 JSON 序列化回传中心端, 也可被
// normalizer.FromProbeJSON 解析 —— 两者字段口径完全一致)。
func (t *Task) Report() normalizer.ProbeReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	rep := normalizer.ProbeReport{
		NodeID: t.cfg.NodeID,
		ScanID: t.cfg.ScanID,
		Time:   time.Now(),
	}
	ips := make([]string, 0, len(t.assets))
	for ip := range t.assets {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ipLess(ips[i], ips[j]) })
	for _, ip := range ips {
		acc := t.assets[ip]
		sort.Ints(acc.Ports)
		rep.Assets = append(rep.Assets, acc.ProbeAsset)
	}
	// 漏洞按严重级别降序输出, 便于中心端展示与用户阅读
	vulns := make([]normalizer.ProbeVuln, 0, len(t.vulns))
	for _, v := range t.vulns {
		vulns = append(vulns, *v)
	}
	sort.Slice(vulns, func(i, j int) bool {
		if vulns[i].Severity != vulns[j].Severity {
			return models.SeverityRank(vulns[i].Severity) > models.SeverityRank(vulns[j].Severity)
		}
		if vulns[i].IP != vulns[j].IP {
			return vulns[i].IP < vulns[j].IP
		}
		return vulns[i].Port < vulns[j].Port
	})
	rep.Vulns = vulns
	return rep
}

// Stats 统计摘要(供"存活 N / 开放端口 M / 漏洞 K"一句话总结)。
func (t *Task) Stats() (alive, openPorts, vulns int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	alive = len(t.assets)
	for _, a := range t.assets {
		openPorts += len(a.Ports)
	}
	vulns = len(t.vulns)
	return
}

// ===== 主入口 =====

// Run 执行一次探针扫描任务(按 Kind 分派), 返回归一化前的探针报告。
//
// Kind 取值(与中心端 dispatchToProbe 下发口径一致):
//
//	"ip"   网段/单机存活探测(ICMP + TCP + ARP)
//	"port" 单机端口扫描 + Banner/服务识别
//	"web"  Web 探测(HTTP 头/TLS 证书/Web 端口风险) + Nuclei 模板
//	"host" 主机综合扫描(端口 + 服务指纹 + 配置风险 + Nuclei 模板)
//	"alive" 同 "ip"(别名, 兼容旧下发)
//	"collect" 本机枚举(进程 / 服务 / 已安装软件 / 监听端口), 不触网
//
// 取消: ctx 取消时尽快返回(长循环每步检查 ctx); 已收集的结果不丢弃,
// 由调用方决定是否回传(agentexec 会把部分结果一并带回, 便于中心端定位中断点)。
//
// 返回值第二个元素为 (report, error); report 在出错时也可能非空(部分结果)。
func Run(ctx context.Context, task *Task, progress Progress) (normalizer.ProbeReport, error) {
	if task == nil {
		return normalizer.ProbeReport{}, errors.New("探针任务为空")
	}
	if task.Target == "" {
		return normalizer.ProbeReport{}, errors.New("探针任务目标为空")
	}
	task.cfg = task.cfg.withDefaults()
	task.progress = progress

	switch task.Kind {
	case "ip", "alive":
		task.scanAlive(ctx, progress)
	case "port":
		task.scanPort(ctx, progress)
	case "web", "host":
		task.scanHost(ctx, progress)
	case "collect":
		task.scanCollect(ctx, progress)
	default:
		return task.Report(), fmt.Errorf("探针不支持的任务类型: %s", task.Kind)
	}
	if err := ctx.Err(); err != nil {
		return task.Report(), fmt.Errorf("%w: %v", ErrCanceled, err)
	}
	return task.Report(), nil
}

// StartCapture 按配置开启抓包骨架(可选能力, 默认关闭)。
//
// 平台采集器未注入(无 Npcap / 非 Windows)时: 仍创建一个"摘要模式"会话,
// 记录扫描交互文字证据 —— 保证证据链在该平台完整, 只是没有原始报文。
// 返回是否启用了抓包。
func (t *Task) StartCapture(cfg CaptureConfig) bool {
	if !cfg.Enabled {
		return false
	}
	t.cap = NewCapture(cfg)
	if t.cap.Enabled() {
		t.cap.Note("扫描任务 %s %s 开始", t.Kind, t.Target)
	}
	return t.cap.Enabled()
}

// CaptureResult 结束抓包并返回结果摘要(未启用时返回空结构)。
//
// 由调用方(agentexec)在任务结束时调用, 把 PCAP 摘要随结果回传中心端,
// 中心端再绑定到对应资产/漏洞证据(models.Vuln.PcapFile / Evidence)。
func (t *Task) CaptureResult() CaptureResult {
	if t.cap == nil {
		return CaptureResult{}
	}
	res := t.cap.Stop()
	if res.Enabled {
		res.Notes = append(res.Notes, fmt.Sprintf("扫描结束: 资产 %d, 漏洞 %d", len(t.Report().Assets), len(t.Report().Vulns)))
	}
	return res
}

// captureNote 记录一条抓包交互摘要(内部使用, nil 安全)。
func (t *Task) captureNote(format string, args ...any) {
	if t.cap != nil {
		t.cap.Note(format, args...)
	}
}

// scanAlive 网段存活探测: ICMP + TCP + ARP 三路互补。
func (t *Task) scanAlive(ctx context.Context, progress Progress) {
	hosts, err := ExpandTargets(t.Target)
	if err != nil || len(hosts) == 0 {
		hosts = []string{t.Target}
	}
	progress.Emit(fmt.Sprintf("存活探测 %s (%d 个目标, ICMP+TCP+ARP)", t.Target, len(hosts)))

	// probePorts: 存活判定的 TCP 探针端口(与中心端口径一致)
	probePorts := []int{80, 443, 445, 3389, 22}
	icmpOK := scanner.InitICMP()
	if !icmpOK {
		progress.Emit("ICMP 不可用(需管理员权限), 本次使用 TCP + ARP 探测")
	}
	arpOK := t.cfg.EnableArp && scanner.ArpHardwareAvailable()
	if t.cfg.EnableArp && !arpOK {
		progress.Emit("ARP 探测不可用(非 Windows 或系统接口缺失), 已跳过")
	}

	sem := make(chan struct{}, t.cfg.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	aliveCount := 0

	for i, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := t.probeHost(ctx, host, probePorts, uint16(idx), icmpOK, arpOK)
			if !res.alive {
				return
			}
			mu.Lock()
			aliveCount++
			mu.Unlock()
			a := normalizer.ProbeAsset{IP: host, Ports: res.openPorts, MAC: res.mac, Tags: []string{"存活"}}
			if res.icmp {
				a.Tags = append(a.Tags, "ICMP应答")
			}
			if res.arp {
				a.Tags = append(a.Tags, "ARP应答")
			}
			t.addAsset(a)
			progress.Emit("存活: " + host + res.describe())
		}(i, host)
	}
	wg.Wait()
	progress.Emit(fmt.Sprintf("存活探测完成: %d/%d 台主机存活", aliveCount, len(hosts)))
}

// hostProbe 单主机存活探测结果。
type hostProbe struct {
	alive     bool
	icmp      bool
	arp       bool
	rttMs     int64
	mac       string
	openPorts []int
}

func (h hostProbe) describe() string {
	var parts []string
	if h.icmp {
		parts = append(parts, fmt.Sprintf("ICMP %dms", h.rttMs))
	}
	if h.arp {
		parts = append(parts, "ARP "+h.mac)
	}
	if len(h.openPorts) > 0 {
		parts = append(parts, fmt.Sprintf("开放端口 %v", h.openPorts))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// probeHost 单主机三路探测: ICMP / TCP / ARP 任一成功即视为存活。
//
// 三路并行而不是串行: 单路最坏都要等一个超时, 串行会让大网段扫描耗时变成 3 倍;
// 并行后整体耗时取决于最快的成功路径(通常是 ARP, 局域网内毫秒级)。
func (t *Task) probeHost(ctx context.Context, host string, ports []int, seq uint16, icmpOK, arpOK bool) hostProbe {
	var (
		mu  sync.Mutex
		res hostProbe
		wg  sync.WaitGroup
	)
	if icmpOK {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, rtt, _ := scanner.PingICMP(host, seq, t.cfg.Timeout.ICMP); ok {
				mu.Lock()
				res.alive, res.icmp, res.rttMs = true, true, rtt
				mu.Unlock()
			}
		}()
	}
	if arpOK {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// ARP 是链路层探测, 无应答属正常(跨网段/目标关机): 只按 MAC 非空判定存活
			mac, err := scanner.ArpProbeOne(host, 1000)
			if err == nil && mac != "" {
				mu.Lock()
				res.alive, res.arp, res.mac = true, true, mac
				mu.Unlock()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		opens := t.tcpProbe(ctx, host, ports)
		mu.Lock()
		if len(opens) > 0 {
			res.alive = true
		}
		res.openPorts = opens
		mu.Unlock()
	}()
	wg.Wait()
	return res
}

// tcpProbe 并发 TCP 全连接探测若干端口, 返回开放端口(升序)。
func (t *Task) tcpProbe(ctx context.Context, host string, ports []int) []int {
	results := t.scanPortsRaw(ctx, host, ports, false)
	var out []int
	for _, r := range results {
		if r.State == "open" {
			out = append(out, r.Port)
		}
	}
	sort.Ints(out)
	return out
}
