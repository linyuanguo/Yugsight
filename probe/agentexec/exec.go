// Package agentexec 探针任务执行器: 把中心端下发的 TaskAssign 落到本地扫描能力上。
//
// 设计动机(2026-09-16 拆分):
//
//	原先这段逻辑写在根包 probe_api.go 里, 导致探针端必须跟随主程序一起构建 ——
//	探针机器因此被迫携带完整 Web UI / Vue 前端 / 规则库 / 引擎编排等与扫描无关的重量。
//	抽成独立包后, yugsight-agent 与 yugsight 主程序共用同一份执行实现(不会双份漂移),
//	而 agent 二进制只需链接 probe + probe/scanner + scanner + 标准库。
//
// 依赖边界: 本包只依赖 probe(协议模型) + probe/scanner(本地扫描能力集),
// 不触碰 db/engine/parsers/sse/http, 因此可以被独立 agent 入口安全引用。
//
// 任务类型支持(2026-09-17 任务 6.4 扩展):
//
//	ip / alive  网段存活探测(ICMP + TCP + ARP)
//	port        端口扫描 + Banner/服务识别 + 内置 Nuclei POC
//	web          Web 探测 + Nuclei 模板
//	host         主机综合扫描(端口 + 服务指纹 + 风险 + Nuclei + 外部引擎)
//	capture     可选附加: 扫描过程抓包(PCAP 骨架), 由 Args.capture=true 触发
//	collect     本机枚举(进程 / 服务 / 已安装软件 / 监听端口), 不触网
//
// 结果口径: 统一产出 normalizer.ProbeReport(资产 + 漏洞), 中心端收到后
// 直接送 normalizer.FromProbeReport 归一化为 models.Asset / models.Vuln ——
// 这是"探针 → 中心端 → 归一化模块"的单一路径, 避免探针侧自造一套模型。
package agentexec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"yugsight/normalizer"
	"yugsight/probe"
	pscan "yugsight/probe/scanner"
)

// DefaultPorts 探针主机扫描默认端口集(与经典页主机扫描口径一致)。
var DefaultPorts = pscan.DefaultPorts

// Run 探针任务执行入口。
//
// 说明: 探针只做"扫描 + 归一化", 不写中心端数据库; 结果统一回传中心端落库,
// 保证分布式场景下数据只有一个写入方(中心端), 避免双写冲突。
//
// 兼容性: 早期实现直接返回 probe.TaskResult.Findings(扁平发现列表);
// 现在改为在 Result.Report 里携带结构化报告(资产 + 漏洞), 同时保留 Findings
// 供旧版中心端展示 —— 中心端优先读 Report, 缺失时回落到 Findings。
func Run(t *probe.TaskAssign, progress func(string)) (*probe.TaskResult, error) {
	return RunContext(context.Background(), t, progress)
}

// RunContext 带 context 的任务执行(支持中心端取消 / 上层超时)。
//
// context 的价值: 长扫描(大网段)收到 MsgTaskCancel 后能立刻停止,
// 而不是等整轮跑完 —— 探针跑在远端机器上, 用户无法直接 kill。
// 语义约定: 本函数**永不返回 error**(始终返回 nil 的 error), 一律通过
// TaskResult.Status/Error 表达失败 —— 探针的任务失败也是"一种结果", 必须回传
// 中心端落库; 返回 error 会让调用方把结果整个丢掉, 中心端只能看到"超时无响应"。
// 唯一的例外是任务本身非法(空任务/空目标), 此时连结果都无法构造, 才返回 error。
func RunContext(ctx context.Context, t *probe.TaskAssign, progress func(string)) (res *probe.TaskResult, err error) {
	if t == nil {
		return nil, fmt.Errorf("任务为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p := pscan.Progress(progress)

	// 顶层 recover: 扫描链路异常必须转成"失败结果"回传, 而不是让 agent 崩溃
	// (panic 逃出会带走整个探针进程, 中心端只看到节点离线, 无法定位原因)
	defer func() {
		if r := recover(); r != nil {
			if res == nil {
				res = &probe.TaskResult{TaskID: t.TaskID}
			}
			res.Status = probe.TaskFailed
			res.Error = fmt.Sprintf("探针执行异常: %v", r)
			res.Summary = "执行异常, 无有效结果"
			p.Emit(res.Error)
		}
	}()

	res = &probe.TaskResult{TaskID: t.TaskID, Status: probe.TaskDone}
	kind := strings.ToLower(strings.TrimSpace(t.Kind))
	target := strings.TrimSpace(t.Target)
	res.StartedAt = time.Now().UnixMilli()
	defer func() {
		res.FinishedAt = time.Now().UnixMilli()
		res.DurationMs = res.FinishedAt - res.StartedAt
	}()

	p.Emit(fmt.Sprintf("开始执行: %s %s", kind, target))

	// 任务非法必须明确回传失败(静默返回空结果会让中心端把"能力缺失/参数错误"
	// 误读为"扫描无发现", 用户看到的就是"扫了但没漏洞"这种危险结论)。
	if target == "" {
		res.Status = probe.TaskFailed
		res.Error = "任务目标为空"
		res.Summary = "未执行: 目标为空"
		p.Emit(res.Error)
		return res, nil
	}

	// 按任务参数构建扫描配置(中心端可经 Args 覆盖端口/并发/能力开关)
	cfg := pscan.OptionsFromArgs(t.Args, pscan.Config{
		NodeID: t.TaskID, // 上层回传时会被中心端替换为真实探针 ID
		ScanID: t.TaskID,
	})
	if len(cfg.Ports) == 0 {
		cfg.Ports = DefaultPorts
	}
	if cfg.NodeID == "" {
		cfg.NodeID = t.TaskID
	}

	task := pscan.NewTask(kind, target, cfg)

	// 任务类型校验前置: 不支持的 Kind 立即失败, 不做无意义的端口扫描
	if !supportedKind(task.Kind) {
		res.Status = probe.TaskFailed
		res.Error = fmt.Sprintf("探针不支持的任务类型: %s", kind)
		res.Summary = res.Error
		p.Emit(res.Error)
		return res, nil
	}

	// 任务级超时(协议里 TimeoutSec 由中心端下发, 0 表示不限制)
	runCtx := ctx
	var cancel context.CancelFunc
	if t.TimeoutSec > 0 {
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(t.TimeoutSec)*time.Second)
		defer cancel()
	}

	// 可选抓包骨架: 默认关闭, 由 Args.capture=true 触发(项目规则 5)
	if captureRequested(t.Args) {
		if task.StartCapture(captureConfig(t)) {
			p.Emit("抓包已开启: 采集本次扫描交互数据")
		} else {
			p.Emit("抓包未能开启(配置关闭或平台不支持), 继续扫描")
		}
	}

	// 扫描(内部所有失败路径都降级, 不 panic)
	report, scanErr := pscan.Run(runCtx, task, p)
	capture := task.CaptureResult()
	if capture.Enabled {
		p.Emit(capture.Summary())
	}

	// 抓包结果绑定到漏洞证据: 同目标漏洞统一带上 PCAP 文件路径,
	// 便于中心端在漏洞详情里直接关联报文片段(models.Vuln.PcapFile)。
	attachCapture(&report, capture)

	// 把结构化报告序列化进 Raw(协议 Raw 字段是字符串), 同时保留扁平 Findings
	res.Report = &report
	res.Raw = marshalReport(report)
	res.Findings = flattenFindings(report)
	alive, ports, vulns := task.Stats()
	res.Summary = fmt.Sprintf("%s %s: 资产 %d, 开放端口 %d, 风险 %d 条",
		kind, target, alive, ports, vulns)

	if scanErr != nil {
		// 部分结果仍然回传: 中心端能看到"扫到哪中断了", 比全丢更有价值
		res.Status = probe.TaskFailed
		res.Error = scanErr.Error()
		res.Summary = "中断: " + res.Summary
		p.Emit("任务中断: " + scanErr.Error())
		return res, nil
	}
	p.Emit(res.Summary)
	return res, nil
}

// supportedKind 探针支持的扫描类型(与 probe/scanner.Run 的 switch 分支保持一致)。
//
// 集中在此判定: 中心端可能下发新类型(如未来的 "synscan"), 探针必须先校验再执行,
// 而不是在 pscan.Run 里靠 error 兜底 —— 提前拒绝能避免"先做了一轮无谓扫描再报错"。
func supportedKind(kind string) bool {
	switch kind {
	case "ip", "alive", "port", "web", "host", "collect":
		return true
	}
	return false
}

// captureRequested Args.capture 是否为真(默认关闭)。
func captureRequested(args map[string]any) bool {
	if len(args) == 0 {
		return false
	}
	v, ok := args["capture"]
	if !ok || v == nil {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// captureConfig 按任务参数构建抓包配置。
func captureConfig(t *probe.TaskAssign) pscan.CaptureConfig {
	cfg := pscan.CaptureConfig{Enabled: true}
	if t.Args == nil {
		return cfg
	}
	if s, ok := t.Args["captureDevice"].(string); ok {
		cfg.Device = s
	}
	if s, ok := t.Args["captureFilter"].(string); ok {
		cfg.Filter = s
	}
	if n, ok := t.Args["captureMaxBytes"].(float64); ok && n > 0 {
		cfg.MaxBytes = int64(n)
	}
	// 未指定过滤条件时按目标生成 BPF: 只抓本次扫描交互, 避免把整网流量都录下来
	if cfg.Filter == "" {
		cfg.Filter = bpfForTarget(t.Target)
	}
	return cfg
}

// bpfForTarget 按扫描目标生成 BPF 过滤表达式。
//
// CIDR 用 net 段; 单 IP 用 host; URL 抽出主机名。生成失败返回空串(抓全量)。
func bpfForTarget(target string) string {
	host := pscan.ParseTargetHost(target)
	if host == "" {
		return ""
	}
	// 去掉端口部分("10.0.0.5:8080" -> "10.0.0.5")
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i+1:], "]") {
		host = host[:i]
	}
	if strings.Contains(host, "/") {
		return "net " + host
	}
	if host == "" {
		return ""
	}
	return "host " + host
}

// attachCapture 把抓包结果绑定到漏洞证据(仅绑定同一目标的漏洞)。
func attachCapture(rep *normalizer.ProbeReport, cap pscan.CaptureResult) {
	if rep == nil || !cap.Enabled || cap.FilePath == "" {
		return
	}
	for i := range rep.Vulns {
		if rep.Vulns[i].PcapFile == "" {
			rep.Vulns[i].PcapFile = cap.FilePath
		}
	}
}

// marshalReport 序列化探针报告(Raw 字段用; 失败返回空串不阻断任务)。
func marshalReport(rep normalizer.ProbeReport) string {
	b, err := json.Marshal(rep)
	if err != nil {
		return ""
	}
	// 协议单条消息上限 4MB: 报告过大时回退为"仅摘要", 避免回传失败
	if len(b) > 3<<20 {
		b, err = json.Marshal(normalizer.ProbeReport{
			NodeID: rep.NodeID, ScanID: rep.ScanID, Time: rep.Time,
			Assets: rep.Assets, // 资产通常很小, 保留; 漏洞证据会很大, 丢弃
		})
		if err != nil {
			return ""
		}
	}
	return string(b)
}

// flattenFindings 把结构化报告压成扁平发现列表(旧版中心端展示兼容)。
func flattenFindings(rep normalizer.ProbeReport) []probe.Finding {
	out := make([]probe.Finding, 0, len(rep.Assets)+len(rep.Vulns))
	for _, a := range rep.Assets {
		ports := make([]string, 0, len(a.Ports))
		for _, p := range a.Ports {
			ports = append(ports, fmt.Sprintf("%d", p))
		}
		detail := strings.TrimSpace(a.Service)
		if a.Banner != "" {
			detail += " " + a.Banner
		}
		if len(ports) > 0 {
			detail = fmt.Sprintf("开放端口 %s; %s", strings.Join(ports, ","), detail)
		}
		out = append(out, probe.Finding{
			Severity: "info",
			Title:    a.IP + " 资产",
			Detail:   strings.TrimSpace(detail),
			Asset:    a.IP,
		})
	}
	for _, v := range rep.Vulns {
		out = append(out, probe.Finding{
			Severity: v.Severity,
			Title:    v.Title,
			Detail:   v.Description,
			CVE:      v.CVE,
			Asset:    v.IP,
		})
	}
	return out
}

// ===== 导出便捷函数(供中心端"本地执行"与测试直接调用) =====
//
// 说明: 这三个函数是 Run 的简化封装 —— 不带任务参数、无超时、结果只返回扁平发现列表。
// 中心端 -probe=both 同机联调与单元测试用它们即可, 无需构造完整 TaskAssign。

// ScanPorts 端口扫描并归一化为探针回传的发现条目。
func ScanPorts(host string, ports []int, progress func(string)) []probe.Finding {
	p := pscan.Progress(progress)
	task := pscan.NewTask("port", host, pscan.Config{Ports: ports})
	rep, err := pscan.Run(context.Background(), task, p)
	if err != nil {
		p.Emit("端口扫描失败: " + err.Error())
	}
	return flattenFindings(rep)
}

// ScanAlive 网段存活探测。
func ScanAlive(cidr string, progress func(string)) []probe.Finding {
	p := pscan.Progress(progress)
	task := pscan.NewTask("ip", cidr, pscan.Config{})
	rep, err := pscan.Run(context.Background(), task, p)
	if err != nil {
		p.Emit("存活探测失败: " + err.Error())
	}
	return flattenFindings(rep)
}

// ScanHost 主机 / Web 扫描。
func ScanHost(target, kind string, progress func(string)) ([]probe.Finding, string, error) {
	p := pscan.Progress(progress)
	task := pscan.NewTask(kind, target, pscan.Config{})
	rep, err := pscan.Run(context.Background(), task, p)
	if err != nil {
		return flattenFindings(rep), "扫描失败: " + err.Error(), err
	}
	alive, ports, vulns := task.Stats()
	summary := fmt.Sprintf("%s %s 扫描完成: 资产 %d, 开放端口 %d, 风险 %d 条",
		kind, target, alive, ports, vulns)
	return flattenFindings(rep), summary, nil
}

// CapabilitySummary 本地扫描能力一句话摘要(agent 启动日志 / 排障用)。
//
// 为什么需要: 探针是无人值守部署的, 出问题时(如"中心端下发抓包任务但不生效")
// 无法登录机器逐项排查; 启动即打印能力清单能让用户一眼看出缺什么。
// 各项含义:
//
//	端口/服务  内置引擎全连接扫描 + Banner/服务识别(全平台必有的基础能力)
//	Nuclei POC 内置模板引擎(打包在二进制内, 不依赖外部文件)
//	存活探测   ICMP + TCP + ARP(ARP 仅 Windows, 无需管理员)
//	抓包       Npcap 报文采集(仅 Windows 且安装了 Npcap)
//	外部引擎   ./bin/ 下的 nmapcore / trivycore / zapcore(可选增强)
func CapabilitySummary() string {
	parts := []string{"端口/服务扫描", "Nuclei POC 验证", "存活探测(ICMP+TCP)", "本机枚举(进程/服务/软件)"}
	if pscan.ArpHardwareAvailable() {
		parts = append(parts, "ARP 探测")
	}
	if pscan.CaptureSupported() {
		parts = append(parts, "PCAP 抓包")
	}
	if bin := pscan.EngineBinPath("nmap"); bin != "" {
		parts = append(parts, "nmapcore(增强)")
	}
	if bin := pscan.EngineBinPath("trivy"); bin != "" {
		parts = append(parts, "trivycore(增强)")
	}
	if bin := pscan.EngineBinPath("zap"); bin != "" {
		parts = append(parts, "zapcore(增强)")
	}
	return strings.Join(parts, " / ")
}

// ParseTargetHost 从目标串里剥离 scheme 前缀并取主机(含端口), 供端口扫描使用。
func ParseTargetHost(s string) string { return pscan.ParseTargetHost(s) }

// ParsePortsParam 解析端口参数("80,443" / "1-1024" / 混合), 空值给常用端口。
func ParsePortsParam(s string) []int {
	ports, err := pscan.ParsePortsParam(s)
	if err != nil || len(ports) == 0 {
		return []int{80, 443}
	}
	return ports
}

// ExpandCIDR 展开网段为 IP 列表(CIDR / 单 IP / 逗号分隔)。
func ExpandCIDR(s string) ([]string, error) { return pscan.ExpandTargets(s) }
