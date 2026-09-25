package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"yugsight/internal/models"
	"yugsight/internal/normalizer"
	"yugsight/internal/scanner"
)

// ===== 主机综合扫描(host / web) =====

// scanHost 主机扫描: 端口/服务指纹 → 系统推断 → Nuclei POC 验证 → 外部引擎增强。
//
// 流程与主程序 handleScan 的 host 分支同源, 但完全独立实现(探针不能依赖 main 包):
//
//	1. 端口扫描 + Banner/服务识别(内置引擎)
//	2. 主机身份(反向 DNS)与系统推断
//	3. TLS 证书风险 + 端口级配置风险
//	4. Nuclei 内置模板 POC 验证(EnableNuclei)
//	5. ./bin/ 外部引擎增强: nmapcore / trivycore / zapcore
func (t *Task) scanHost(ctx context.Context, progress Progress) {
	hosts, err := ExpandTargets(t.Target)
	if err != nil || len(hosts) == 0 {
		hosts = []string{ParseTargetHost(t.Target)}
	}
	progress.Emit(fmt.Sprintf("%s 扫描 %s (%d 个目标, %d 个端口)",
		t.Kind, t.Target, len(hosts), len(t.cfg.Ports)))

	for _, host := range hosts {
		if ctx.Err() != nil {
			return
		}
		if host = strings.TrimSpace(host); host == "" {
			continue
		}
		t.scanOneHost(ctx, host, progress)
	}
	alive, ports, vulns := t.Stats()
	progress.Emit(fmt.Sprintf("%s 扫描完成: 资产 %d, 开放端口 %d, 风险 %d 条", t.Kind, alive, ports, vulns))
}

// scanOneHost 单主机完整扫描。
func (t *Task) scanOneHost(ctx context.Context, host string, progress Progress) {
	progress.Emit("扫描主机 " + host)

	// ---- 1) 端口 + 服务识别 ----
	results := t.scanPortsRaw(ctx, host, t.cfg.Ports, true)
	var open []scanner.PortResult
	for _, r := range results {
		if r.State == "open" {
			open = append(open, r)
		}
	}
	if len(open) == 0 {
		progress.Emit(host + " 无开放端口, 跳过后续识别")
		return
	}
	t.ingestPorts(host, open, progress)

	// ---- 2) 主机身份(反向 DNS)与系统推断 ----
	var tags []string
	if names, err := lookupAddr(host); err == nil && len(names) > 0 {
		tags = append(tags, "PTR:"+truncate(names[0], 60))
		progress.Emit(fmt.Sprintf("%s 反向解析: %s", host, names[0]))
	}
	if osName := guessOSByPorts(open); osName != "" {
		tags = append(tags, "OS:"+osName)
		progress.Emit(fmt.Sprintf("%s 系统推断: %s", host, osName))
	}
	if len(tags) > 0 {
		asset := normalizerProbeAsset(host)
		asset.Tags = tags
		t.addAsset(asset)
	}

	// ---- 3) TLS 证书风险 + 端口级配置风险 ----
	t.emitTLSRisks(host, open, progress)
	t.emitServiceRisks(host, open, progress)

	// ---- 4) Nuclei 内置模板 POC 验证 ----
	if t.cfg.EnableNuclei {
		t.runNuclei(ctx, host, open, progress)
	} else {
		progress.Emit("Nuclei 模板验证已关闭(enableNuclei=false)")
	}

	// ---- 5) 外部引擎增强(./bin/ 存在时才调用) ----
	if t.cfg.EnableExternal {
		t.runExternalEngines(ctx, host, progress)
	}
}

// emitTLSRisks TLS 证书风险(过期/自签名)。
//
// 复用 scanner.TLSCertInfo(纯标准库实现), 探针不重复造证书解析。
func (t *Task) emitTLSRisks(host string, open []scanner.PortResult, progress Progress) {
	for _, r := range open {
		switch r.Port {
		case 443, 8443, 993, 995, 465, 636:
		default:
			continue
		}
		info, err := scanner.TLSCertInfo(host, r.Port)
		if err != nil || info == "" {
			continue
		}
		progress.Emit(fmt.Sprintf("%s:%d TLS 证书: %s", host, r.Port, truncate(info, 120)))

		sev, title := "", ""
		switch {
		case strings.Contains(info, "证书已过期"):
			sev, title = "high", fmt.Sprintf("端口 %d TLS 证书已过期", r.Port)
		case strings.Contains(info, "自签名证书"):
			sev, title = "medium", fmt.Sprintf("端口 %d 使用自签名证书", r.Port)
		}
		if title != "" {
			t.addVuln(newProbeVuln(host, r.Port, sev, title, info, info, ""))
		}
	}
}

// guessOSByPorts 按开放端口组合推断操作系统(粗粒度, 与 scanner/host.go 同逻辑)。
func guessOSByPorts(open []scanner.PortResult) string {
	win, nix := 0, 0
	for _, r := range open {
		switch r.Port {
		case 135, 139, 445, 3389, 5985:
			win++
		case 22, 111, 2049:
			nix++
		}
	}
	switch {
	case win >= 2:
		return "Windows"
	case win >= 1 && nix >= 1:
		return "Windows/Unix(混合特征)"
	case nix >= 2:
		return "Linux / Unix"
	}
	return ""
}

// ===== Nuclei 内置模板 POC 验证 =====

// runNuclei 对开放 Web 端口执行 Nuclei 模板(HTTP-only), 命中即作为漏洞证据。
//
// 关键约束(与主程序一致):
//   - 只对 Web 端口执行(避免向 SSH/Redis 等非 HTTP 服务发 HTTP 请求);
//   - 模板集 = 内置(exe 打包) + 外部 templates/ 目录(可选, 缺失即只有内置);
//   - 命中带 RawRequest/RawResponse 作为证据, 中心端归一化后可直接展示报文。
func (t *Task) runNuclei(ctx context.Context, host string, open []scanner.PortResult, progress Progress) {
	assets := scanner.BuildServiceAssets(host, open)
	var webAssets []scanner.ServiceAsset
	for _, a := range assets {
		if scanner.IsWebPort(a.Port) {
			webAssets = append(webAssets, a)
		}
	}
	if len(webAssets) == 0 {
		return
	}
	all, errs := scanner.LoadAllTemplates(templateDir())
	for _, e := range errs {
		progress.Emit("Nuclei 模板警告: " + truncate(e, 200))
	}
	if len(all) == 0 {
		progress.Emit("无可用 Nuclei 模板, 跳过 POC 验证")
		return
	}
	tpls := scanner.FilterTemplatesByTags(all, t.cfg.NucleiTags, t.cfg.NucleiTagsExclude)
	if len(tpls) == 0 {
		progress.Emit("Nuclei 模板经 tag 过滤后为空, 跳过 POC 验证")
		return
	}
	progress.Emit(fmt.Sprintf("Nuclei POC 验证: %s, %d 个 Web 服务, %d 个模板",
		host, len(webAssets), len(tpls)))

	runner := scanner.NewNucleiRunner(scanner.DefaultRunnerConfig())
	total := 0
	for _, a := range webAssets {
		if ctx.Err() != nil {
			return
		}
		// emit 传 nil: 探针端不需要流式推送单条命中(结果统一在任务结束时回传),
		// 传 nil 让 runner 跳过事件组装, 少一次编码开销。
		hits := runner.RunNucleiTemplates(a, tpls, nil)
		for _, h := range hits {
			t.addVuln(nucleiToProbeVuln(host, h))
			total++
		}
	}
	if total > 0 {
		progress.Emit(fmt.Sprintf("Nuclei POC 命中 %d 条(已去重)", total))
	}
}

// nucleiToProbeVuln Nuclei 命中 → 探针漏洞(带原始请求/响应证据)。
func nucleiToProbeVuln(host string, h scanner.NucleiFinding) normalizer.ProbeVuln {
	sev := h.Severity
	if sev == "" {
		sev = "info"
	}
	return normalizer.ProbeVuln{
		IP:          host,
		Port:        h.Port,
		Protocol:    protocolOf(h.Port),
		CVE:         firstCVE(h.CVE),
		Title:       h.Title,
		Severity:    sev,
		Description: h.Detail,
		Evidence:    truncate(h.Detail, 2000),
		Request:     truncate(h.RawRequest, 8000),
		Response:    truncate(h.RawResponse, 8000),
		// 模板命中 = 主动验证成功, 置信度最高(与 scanctl 打分口径一致: 只有 POC 成功才给满分)
		Confidence: 100,
		FoundAt:    time.Now(),
	}
}

// firstCVE 取第一个 CVE(模板可能带多个, 逗号分隔: "CVE-2021-1,CVE-2021-2")。
func firstCVE(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, ",; "); i > 0 {
		s = s[:i]
	}
	return models.NormalizeCVE(s)
}
