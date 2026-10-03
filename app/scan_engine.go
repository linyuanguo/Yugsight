package main

// scan_engine.go 引擎编排接入本地扫描管线(任务: 默认关闭, 关闭时零行为变化)。
//
// 背景: engine/parsers 的 Orchestrator(执行 → 解析 → 归一化 → 降级)早已就绪,
// 但只在 /api/engine/status 挂了个状态接口, 扫描管线从不调用它。
//
// 接线口径:
//   - 总开关 engine.enabled(默认启用) 且类型可编排时, host/port/web 默认走
//     编排器(Kind 与 parsers.engineForKind 对齐); useEngine 显式传值可覆盖默认;
//   - 引擎产出的漏洞转成既有 finding 事件格式推送(source="engine"), 与 nuclei/builtin 区分;
//   - 降级(引擎缺失 / 执行失败 / 无输出 / 解析失败)一律回落既有内置流程, 只记日志不报错;
//   - 超时/取消刻意不回落(编排器语义: 再跑一遍内置既浪费又改变结论)。
//
// 关闭时本文件不产生任何调用(开关在 runScanPipeline 入口判定)。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"yugsight/internal/engine"
	"yugsight/internal/engine/parsers"
	"yugsight/internal/models"
	"yugsight/internal/scanner"
)

// engineScanType 该扫描类型是否可交给外部引擎编排(与 parsers.engineForKind 对齐)。
// image/fs/container 为 trivy 的 SCA 维度(本地文件/镜像/容器依赖扫描, 非远程主机端口)。
func engineScanType(typ string) bool {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "host", "port", "web", "image", "fs", "container":
		return true
	}
	return false
}

// engineScanActive 本次扫描是否走外部引擎编排(单一口径, main 扫描入口与原始报告共用)。
// 委托 resolveScanEngine 解析"用哪个引擎"(显式 Engine > 老 UseEngine > 默认内置)。
func engineScanActive(req scanReq) bool {
	_, external := resolveScanEngine(req)
	return external
}

// engineNameForScanType 扫描类型 → 该类型的默认外部引擎名(与 parsers.engineForKind /
// engine 常量对齐): host/port 用 nmap, web 用 zap, image/fs/container 用 trivy。
// 用于执行前预判该引擎二进制是否已安装, 以及 UseEngine=true(老字段)时的默认引擎。
func engineNameForScanType(typ string) string {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "host", "port":
		return engine.NameNmap
	case "web":
		return engine.NameZap
	case "image", "fs", "container":
		return engine.NameTrivy
	}
	return ""
}

// typeAllowsEngine 该扫描类型是否允许指定引擎(防止 host 类型误选 zap 等类型错配)。
// 口径: 类型默认引擎 == 指定引擎(host/port 只许 nmap, web 只许 zap, image/fs 只许 trivy)。
func typeAllowsEngine(typ, eng string) bool {
	return engineNameForScanType(typ) == eng
}

// resolveScanEngine 解析本次扫描实际要用的"探测/主引擎"(2026-09-26: 让用户按类型自选)。
//
// 优先级: req.Engine(显式) > req.UseEngine(老布尔兼容) > 默认内置。
//   - Engine = "builtin"/"built-in"/"internal" → 内置
//   - Engine = "nmap"/"zap"/"trivy" 且 typeAllowsEngine 通过 → 对应外部引擎
//   - Engine 与类型错配(如 host 选 zap) → 回落内置(不误用不匹配的引擎)
//   - UseEngine=true 且类型可编排 → 该类型默认外部引擎(兼容老脚本)
//   - 其余 → 内置: 默认用内置(快), 外部引擎需显式传 Engine 才启用 —— 这解决了
//     "默认 nmap 拖慢网段扫描、感觉比内置慢"的反馈, 也符合"自己选引擎"的诉求。
//
// 总开关 engine.enabled=false 时一律内置(外部引擎整体禁用, 与旧语义一致)。
// 返回 (engineName, external): external=true 走 runEngineScan(外部引擎), 否则走内置 switch。
func resolveScanEngine(req scanReq) (engineName string, external bool) {
	typ := strings.ToLower(strings.TrimSpace(req.Type))
	if !engineScanType(typ) {
		return "", false // ip/alive/unified 无对应引擎 kind, 只能内置
	}
	// trivy SCA(image/fs/container) 无内置替代: 强制走 trivy, 不受 Engine/总开关影响。
	// trivy 未装或目标无效时由 main.go 的 image/fs 分支给明确报错, 不"降级内置"(内置无此能力)。
	if typ == "image" || typ == "fs" || typ == "container" {
		return engine.NameTrivy, true
	}
	if !engineEnabled() {
		return "", false // 总开关关闭, 外部引擎整体禁用
	}
	// 1. 显式 Engine(最高优先级)
	if e := strings.ToLower(strings.TrimSpace(req.Engine)); e != "" {
		switch e {
		case "builtin", "built-in", "internal":
			return "", false
		}
		if typeAllowsEngine(typ, e) {
			return e, true
		}
		return "", false // 类型与引擎错配, 回落内置
	}
	// 2. 老字段 UseEngine(兼容脚本: true=走该类型默认外部引擎)
	if req.UseEngine != nil {
		if *req.UseEngine {
			return engineNameForScanType(typ), true
		}
		return "", false
	}
	// 3. 默认内置(未显式指定 → 内置, 快; 外部引擎需显式 Engine 选择)
	return "", false
}

// resolveScanEngineList 解析本次扫描的引擎列表(2026-09-26 多选)。
//
// 返回约定:
//   - 单引擎模式(老语义, 含 Engines 只填 1 项): 恰好 1 个元素。
//     "" = 内置; 外部引擎名 = 该引擎(由 resolveScanEngine 按老优先级解析,
//     行为与改造前完全一致, 含"外部失败回落内置"语义)。
//   - 多引擎模式(Engines 含 2+ 有效项): 多个元素, "" = 内置, 顺序 = 用户勾选顺序。
//     多引擎模式下每个引擎独立执行、互不回落(用户显式选了就要各自跑,
//     nmap 失败不该连带跳过内置, 反之亦然)。
//
// SCA(image/fs/container) 恒为 ["trivy"](无内置替代, 与 resolveScanEngine 同口径);
// 总开关 engine.enabled=false 时一律内置(外部引擎整体禁用, 老语义)。
func resolveScanEngineList(req scanReq) []string {
	typ := strings.ToLower(strings.TrimSpace(req.Type))
	if typ == "image" || typ == "fs" || typ == "container" {
		return []string{engine.NameTrivy}
	}
	if !engineEnabled() {
		return []string{""}
	}
	// 显式多选(新字段 Engines): 按类型过滤 + 去重, 保留用户顺序
	if len(req.Engines) > 0 {
		seen := map[string]bool{}
		out := make([]string, 0, len(req.Engines))
		for _, e := range req.Engines {
			e = strings.ToLower(strings.TrimSpace(e))
			switch e {
			case "", "builtin", "built-in", "internal":
				e = "" // 统一用空串表达内置
			default:
				if !typeAllowsEngine(typ, e) {
					continue // 类型错配(如 host 勾 zap) → 忽略, 不误用不匹配的引擎
				}
			}
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
		if len(out) >= 2 {
			return out // 多引擎模式
		}
		if len(out) == 1 {
			// 恰好 1 项有效: 走老单引擎语义(含外部失败回落内置)
			if out[0] == "" {
				return []string{""}
			}
			r := req
			r.Engine = out[0]
			if name, external := resolveScanEngine(r); external {
				return []string{name}
			}
			return []string{""}
		}
		return []string{""} // 全是无效项 → 内置兜底
	}
	// 老单引擎路径(Engine / UseEngine / 默认内置), 行为不变
	name, external := resolveScanEngine(req)
	if external {
		return []string{name}
	}
	return []string{""}
}

// engineProbe 引擎二进制探测(默认经全局 executor 查 bin/ 与系统 PATH)。
// 抽成变量是为了让测试注入"始终可用"(配合 Exec 替身模拟引擎逻辑可用), 与
// engine.pathLookup 可注入手法一致 —— 否则测试机没有真实引擎时, 预判会误拦
// 已注入替身的用例(如 TestRunEngineScanZapFindings)。
var engineProbe = func(name string) (string, error) {
	if engExec == nil {
		return "", errors.New("外部引擎执行器未初始化")
	}
	return engExec.BinPath(name)
}

// runEngineScan 用外部引擎编排器执行本次扫描。
//
// 返回 true = 已由引擎处理完成(或超时/取消刻意不重扫), 调用方跳过内置流程;
// 返回 false = 发生降级, 调用方回落既有内置流程。失败一律只记日志(项目规则 4)。
func runEngineScan(ctx context.Context, req scanReq, sink *scanSink, emit func(string, any)) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	o := instanceOrchestrator()
	if o == nil || sink == nil || emit == nil {
		return false
	}
	// 引擎二进制缺失时直接回落内置(不进入 orchestrator): 避免 orchestrator 的降级
	// 兜底(builtinRunner)先跑一遍端口探测、再由 main 内置流程重扫 —— 默认启用后
	// "还没装引擎"是常见初始状态, 每次扫描重复探测不划算。
	// 用 resolveScanEngine 解析出的实际引擎名做预判(而非类型默认引擎): 用户显式选了
	// 哪个引擎, 就预判哪个 —— 与下方 preq.Kind 传给 orchestrator 的引擎保持一致。
	if en, _ := resolveScanEngine(req); en != "" {
		if _, err := engineProbe(en); err != nil {
			engineLog("外部引擎未安装(" + en + "), 回落内置引擎")
			emit("status", map[string]any{"msg": "外部引擎未安装(" + en + "), 回落内置引擎"})
			return false
		}
	}
	preq := parsers.Request{
		Kind:    strings.ToLower(strings.TrimSpace(req.Type)),
		Target:  engineTarget(req),
		Ports:   enginePorts(req),
		Timeout: time.Duration(effectiveTimeoutSec()) * time.Second,
	}
	if strings.TrimSpace(preq.Target) == "" {
		return false
	}
	// ZAP 的报告只能落文件(不支持 stdout): 由 ZapArtifact 统一给出路径/读取/清理,
	// 必须 defer cleanup, 否则每轮扫描在临时目录留一份报告。
	if strings.EqualFold(preq.Kind, "web") {
		args, read, cleanup := parsers.ZapArtifact(os.TempDir(), engineScanID(req))
		defer cleanup()
		// 真正下发给 ZAP 的开关名是 -quickout(parsers.buildArgs 口径), 必须与 ZapArtifact
		// 的报告文件是同一路径: 否则 buildArgs 会再补一个默认路径, read 读到空文件 → 误判"引擎无输出"。
		if len(args) >= 2 {
			preq.Args = []string{"-quickout", args[len(args)-1]}
		} else {
			preq.Args = args
		}
		preq.ReadArtifact = read
	}
	// Nmap 同理: Windows 版 nmap 的 -oJ(stdout/文件) 均不可用(实测, 见
	// parsers.buildArgs 注释), 统一 XML 落临时文件, Run 完读回后自动清理。
	if strings.EqualFold(preq.Kind, "host") || strings.EqualFold(preq.Kind, "port") {
		args, read, cleanup := parsers.NmapArtifact(os.TempDir(), engineScanID(req))
		defer cleanup()
		preq.Args = args
		preq.ReadArtifact = read
	}
	emit("status", map[string]any{"msg": "外部引擎编排扫描中: " + preq.Target})
	out, err := o.Run(ctx, preq)
	if err != nil {
		// 超时 / 取消: 编排器刻意不降级重扫, 这里也不再跑内置流程
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			emit("status", map[string]any{"msg": "外部引擎已取消/超时, 不再重复扫描"})
			return true
		}
		engineLog("引擎编排失败, 回落内置引擎: " + err.Error())
		emit("status", map[string]any{"msg": "外部引擎不可用, 回落内置引擎"})
		return false
	}
	if out == nil {
		engineLog("引擎编排未返回结果, 回落内置引擎")
		return false
	}
	if out.Degraded {
		engineLog(fmt.Sprintf("引擎降级(%s), 回落内置引擎", out.DegradeReason))
		emit("status", map[string]any{"msg": "外部引擎降级, 回落内置引擎: " + out.DegradeReason})
		return false
	}
	if out.Result == nil {
		emit("status", map[string]any{"msg": "外部引擎无结果"})
		return true
	}
	// 引擎资产并入本轮落库; 漏洞转成既有 finding 事件(前端与报告零改动)
	sink.addModelAssets(out.Result.Assets)
	n := emitEngineFindings(out.Result.Vulns, emit)
	// 探测/漏洞分离(2026-09-26): nmap 只负责探测(端口/服务), 漏洞引擎(nuclei)独立叠加 ——
	// 对探测到的 web 端口资产补跑 nuclei 模板(用户选 nmap 探测时也能用 nuclei 查漏洞)。
	// 内置规则漏洞(CPE)依赖服务版本, nmap -sT 不探版本, 故此处只叠加 nuclei(对 web 端口发请求)。
	if strings.EqualFold(preq.Kind, "host") && req.EnableNuclei && nucleiOn {
		svcAssets := serviceAssetsFromModel(out.Result.Assets)
		if len(svcAssets) > 0 {
			runNucleiScan(svcAssets, req, emit)
		}
	}
	emit("status", map[string]any{"msg": fmt.Sprintf("外部引擎 %s 完成: 资产 %d, 漏洞 %d, 耗时 %s",
		out.Source, len(out.Result.Assets), n, out.Duration.Round(time.Millisecond))})
	return true
}

// engineFinding 引擎漏洞 → SSE finding 事件体(字段与内置 finding 对齐)。
type engineFinding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Source   string `json:"source,omitempty"` // 固定 engine, 与 nuclei/builtin/probe 区分
	CVE      string `json:"cve,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`
}

// engineFindingSource 引擎来源标记(落库后漏洞页可按该来源筛选)。
const engineFindingSource = "engine"

// emitEngineFindings 引擎结果 → finding 事件, 返回推送条数。
// 走调用方传入的 emit(生产为 emitAI): 白名单/误报过滤与落库收集随之生效。
func emitEngineFindings(vulns []*models.Vuln, emit func(string, any)) int {
	n := 0
	for _, v := range vulns {
		if v == nil || strings.TrimSpace(v.Title) == "" {
			continue
		}
		detail := strings.TrimSpace(v.Description)
		if detail == "" {
			detail = strings.TrimSpace(v.Evidence)
			if len([]rune(detail)) > 1000 {
				detail = string([]rune(detail)[:1000]) + "..."
			}
		}
		emit("finding", engineFinding{
			Severity: v.Severity,
			Title:    v.Title,
			Detail:   detail,
			Source:   engineFindingSource,
			CVE:      v.CVE,
			Host:     v.AssetIP,
			Port:     v.Port,
		})
		n++
	}
	return n
}

// serviceAssetsFromModel 把 nmap 探测出的资产(models.Asset, 资产级 Service/Version)按开放
// 端口展开成 ServiceAsset 列表, 供 nuclei 模板执行消费(探测/漏洞分离, 2026-09-26)。
//
// nmap -sT 不探服务版本, 故 Version 多为空; nuclei 只对 IsWebPort 发 HTTP 请求并按请求
// 特征匹配模板(不完全依赖版本), 故 nmap 探测 + nuclei 漏洞叠加仍可成立。
func serviceAssetsFromModel(assets []*models.Asset) []scanner.ServiceAsset {
	var out []scanner.ServiceAsset
	for _, a := range assets {
		if a == nil || strings.TrimSpace(a.IP) == "" {
			continue
		}
		for _, p := range a.Ports {
			scheme := "http"
			if p == 443 || p == 8443 || p == 993 || p == 995 || p == 465 {
				scheme = "https"
			}
			out = append(out, scanner.ServiceAsset{
				IP: a.IP, Port: p, Scheme: scheme,
				Product: a.Service, Version: a.Version, Banner: a.Banner,
			})
		}
	}
	return out
}

// engineTarget 按扫描类型取引擎目标(host/port 用 IP, web 用完整 URL, image/fs 用 trivy 目标)。
func engineTarget(req scanReq) string {
	typ := strings.ToLower(strings.TrimSpace(req.Type))
	if typ == "web" {
		return strings.TrimSpace(req.URL)
	}
	// trivy SCA: 目标带 image:/fs: 前缀(parsers.buildArgs 据此切 trivy 子命令)。
	// 用户可能已自带前缀(兼容直传), 否则按类型(image/fs)补前缀。
	if typ == "image" || typ == "fs" || typ == "container" {
		t := strings.TrimSpace(req.TrivyTarget)
		if t == "" {
			return ""
		}
		lt := strings.ToLower(t)
		if strings.HasPrefix(lt, "image:") || strings.HasPrefix(lt, "fs:") || strings.HasPrefix(lt, "container:") {
			return t
		}
		// 按类型补前缀(parsers.buildArgs 据此切 trivy 子命令): 镜像→image / 运行中容器→container / 其余→fs
		switch typ {
		case "image":
			return "image:" + t
		case "container":
			return "container:" + t
		default:
			return "fs:" + t
		}
	}
	if ip := strings.TrimSpace(req.IP); ip != "" {
		return ip
	}
	return strings.TrimSpace(req.CIDR)
}

// enginePorts 引擎端口列表(用户未指定时给一份默认集, 与内置流程口径一致)。
func enginePorts(req scanReq) []int {
	ports, err := scanner.ParsePorts(req.Ports)
	if err != nil || len(ports) == 0 {
		ports, _ = scanner.ParsePorts(defaultHostPorts)
	}
	return ports
}

// engineScanID 本轮引擎任务标识(用于 ZAP 报告文件名, 需避开路径分隔符)。
func engineScanID(req scanReq) string {
	return fmt.Sprintf("%s-%d", strings.ToLower(strings.TrimSpace(req.Type)), time.Now().UnixMilli())
}
