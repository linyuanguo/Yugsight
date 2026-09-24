package main

// scan_engine.go 引擎编排接入本地扫描管线(任务: 默认关闭, 关闭时零行为变化)。
//
// 背景: engine/parsers 的 Orchestrator(执行 → 解析 → 归一化 → 降级)早已就绪,
// 但只在 /api/engine/status 挂了个状态接口, 扫描管线从不调用它。
//
// 接线口径:
//   - scanReq.UseEngine(默认 false) 且 engine 总开关 enabled=true 同时成立时,
//     host/port/web 改走编排器(Kind 与 parsers.engineForKind 对齐);
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

	"yugsight/engine/parsers"
	"yugsight/models"
	"yugsight/scanner"
)

// engineScanType 该扫描类型是否可交给外部引擎编排(与 parsers.engineForKind 对齐)。
func engineScanType(typ string) bool {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "host", "port", "web":
		return true
	}
	return false
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

// engineTarget 按扫描类型取引擎目标(host/port 用 IP, web 用完整 URL)。
func engineTarget(req scanReq) string {
	if strings.EqualFold(strings.TrimSpace(req.Type), "web") {
		return strings.TrimSpace(req.URL)
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
