package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"yugsight/scanner"
)

// ===== 端口扫描 + 服务识别 =====

// scanPort 单机端口扫描: 全连接扫描 + Banner 读取 + 服务名/版本指纹,
// 并做配置风险提示(与主机扫描共用 scanner 的规则库)。
func (t *Task) scanPort(ctx context.Context, progress Progress) {
	host := ParseTargetHost(t.Target)
	if host == "" {
		progress.Emit("目标无法解析: " + t.Target)
		return
	}
	progress.Emit(fmt.Sprintf("端口扫描 %s (%d 个端口)", host, len(t.cfg.Ports)))
	results := t.scanPortsRaw(ctx, host, t.cfg.Ports, true)

	var open []scanner.PortResult
	for _, r := range results {
		if r.State == "open" {
			open = append(open, r)
		}
	}
	t.ingestPorts(host, open, progress)

	// 服务配置风险(23/445/6379 等端口暴露) + CPE 版本漏洞匹配:
	// 复用 scanner 内置规则库, 探针无需重复实现判定逻辑
	t.emitServiceRisks(host, open, progress)
	progress.Emit(fmt.Sprintf("端口扫描完成: %s 开放 %d 个端口", host, len(open)))
}

// scanPortsRaw 并发端口扫描(内部实现)。
//
// withBanner=true 时对开放端口读取 Banner 并识别服务(慢, 但主机/端口扫描需要);
// 存活探测路径传 false(只关心端口通不通, 不读横幅, 避免为大网段增加大量等待)。
//
// SYN 模式(Args{"synscan":true}, 默认关闭): 平台与权限具备时走半开扫描,
// 结果字段与全连接完全一致(仅多一种 filtered 状态); 不可用或失败则降级为全连接,
// 只记进度日志, 不让任务失败(见 syn.go 头部说明)。
func (t *Task) scanPortsRaw(ctx context.Context, host string, ports []int, withBanner bool) []scanner.PortResult {
	if t.cfg.EnableSynScan {
		if res, err := synScanPorts(ctx, host, ports, t.cfg.Timeout.Dial); err == nil && len(res) > 0 {
			t.progress.Emit(fmt.Sprintf("SYN 半开扫描 %s (%d 个端口)", host, len(ports)))
			return res
		} else if err != nil {
			t.progress.Emit(fmt.Sprintf("SYN 扫描不可用(%v), 已降级为全连接扫描", err))
		}
	}
	sem := make(chan struct{}, t.cfg.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := make([]scanner.PortResult, 0, len(ports))

	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := scanner.PortResult{IP: host, Port: port, State: "closed"}
			start := time.Now()
			conn, err := dialTCP(host, port, t.cfg.Timeout.Dial)
			if err != nil {
				mu.Lock()
				out = append(out, r)
				mu.Unlock()
				return
			}
			r.State = "open"
			r.Service = scanner.ServiceName(port)
			r.LatencyMs = time.Since(start).Milliseconds()
			if withBanner {
				r.Banner = readBanner(conn, t.cfg.Timeout.BannerRead)
				// Web 端口主动请求拿 Server 头(比被动横幅更准, 能带出产品与版本)
				if isWebPort(port) {
					if hdr := probeHTTP(host, port, t.cfg.Timeout.Dial); hdr != "" {
						r.Banner = strings.TrimSpace(r.Banner + " " + hdr)
					}
				}
			}
			_ = conn.Close()
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// ingestPorts 把开放端口并入资产表(含服务/版本指纹推导)。
func (t *Task) ingestPorts(host string, open []scanner.PortResult, progress Progress) {
	if len(open) == 0 {
		t.addAsset(normalizerProbeAsset(host))
		return
	}
	var (
		ports   []int
		svcs    []string
		version string
		banner  string
		tags    []string
	)
	for _, r := range open {
		ports = append(ports, r.Port)
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}
		svcs = append(svcs, fmt.Sprintf("%d/%s", r.Port, svc))
		if banner == "" && r.Banner != "" {
			banner = r.Banner
		}
		if v := versionOf(r.Banner); v != "" && version == "" {
			version = v
		}
		if isWebPort(r.Port) {
			tags = appendUniqueStr(tags, "web")
		}
	}
	asset := normalizerProbeAsset(host)
	asset.Ports = ports
	asset.Service = strings.Join(svcs, ",")
	asset.Version = version
	asset.Banner = truncate(banner, 500)
	asset.Tags = tags
	t.addAsset(asset)
	for _, r := range open {
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}
		progress.Emit(fmt.Sprintf("开放端口 %s:%d (%s) %s", host, r.Port, svc, shortVer(r.Banner)))
	}
}

// emitServiceRisks 端口级风险提示: 与主机扫描(host.go serviceRisks)同口径的
// 子集, 避免探针重复维护规则库 —— 有 open 端口就按端口给出通用加固建议。
//
// 说明: 这里只做"暴露面提示"(不带 CVE), 具体 CVE 由内置 Nuclei 模板验证;
// 若本机装了 nmapcore, 其 NSE 脚本结果会带来更精确的漏洞条目。
func (t *Task) emitServiceRisks(host string, open []scanner.PortResult, progress Progress) {
	for _, r := range open {
		sev, title, detail := portRisk(r.Port)
		if title == "" {
			continue
		}
		t.addVuln(newProbeVuln(host, r.Port, sev, title, detail, r.Banner, ""))
	}
}

// portRisk 高危端口风险库(与 scanner/host.go 的 serviceRisks 保持同语义,
// 但只保留"无需进一步探测即可判定"的条目, 避免探针出现误报)。
func portRisk(port int) (severity, title, detail string) {
	switch port {
	case 23:
		return "high", "Telnet 服务开放", "Telnet 明文传输账号口令, 建议改为 SSH"
	case 21:
		return "medium", "FTP 服务开放", "FTP 明文传输凭据; 确认是否允许匿名登录, 建议改用 SFTP"
	case 445:
		return "high", "SMB 文件共享开放", "SMB 是勒索病毒主要入口, 请确认已修补 MS17-010 且禁用 SMBv1"
	case 3389:
		return "medium", "RDP 远程桌面开放", "存在爆破与 BlueKeep(CVE-2019-0708)风险, 建议启用 NLA 并限制来源"
	case 6379:
		return "high", "Redis 端口开放", "Redis 未授权访问可导致服务器被控, 请设置密码并限制来源"
	case 27017:
		return "high", "MongoDB 端口开放", "请确认已启用认证, 否则全库数据可被直接读取"
	case 9200:
		return "high", "Elasticsearch 端口开放", "请确认已开启安全认证, 否则索引数据可被直接读取"
	case 2375:
		return "high", "Docker 未加密 API 开放", "等同于把主机 root 权限暴露到网络, 请立即关闭或改 2376+TLS"
	case 3306:
		return "high", "MySQL 数据库端口开放", "数据库不应直接对外; 请限制来源并检查 root 弱口令"
	case 1433:
		return "high", "MSSQL 数据库端口开放", "数据库不应直接对外; 请限制来源并检查 sa 弱口令"
	case 5432:
		return "high", "PostgreSQL 端口开放", "请确认 pg_hba.conf 未对 0.0.0.0/0 开放 trust"
	case 11211:
		return "high", "Memcached 端口开放", "未授权访问可被用于反射放大攻击, 请限制来源并绑定内网"
	case 5900:
		return "medium", "VNC 远程桌面开放", "VNC 口令易被爆破且默认无加密, 建议改用 RDP/SSH 隧道"
	case 7001:
		return "high", "WebLogic 端口开放", "WebLogic 历史反序列化漏洞较多, 请确认版本已升级并限制访问"
	case 139, 135:
		return "medium", "NetBIOS/MSRPC 端口开放", "常被用于横向移动与信息收集, 建议防火墙限制来源"
	}
	return "", "", ""
}

// ===== 服务识别工具 =====

// isWebPort 常见 Web 端口(与 scanner.IsWebPort 同口径)。
func isWebPort(p int) bool {
	switch p {
	case 80, 443, 8080, 8443, 8000, 8888, 9000, 3000:
		return true
	}
	return false
}

// readBanner 读取服务横幅(限额 512 字节并做可打印化处理)。
//
// 抽出来单独实现而不是直接用 scanner.grabBanner: 后者是包私有函数,
// 且这里需要传入可配置超时(探针可能部署在高延迟链路)。
func readBanner(conn interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	b := buf[:n]
	for i, c := range b {
		if c < 32 && c != '\t' && c != '\r' && c != '\n' {
			b[i] = '.'
		}
	}
	return truncate(strings.TrimSpace(string(b)), 200)
}

// shortVer 从横幅里抠出简短版本描述(日志用)。
func shortVer(banner string) string {
	v := versionOf(banner)
	if v == "" {
		return ""
	}
	return "[" + v + "]"
}

// truncate 限长截断(超长内容不进报告, 防止单条消息撑爆协议上限)。
func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func appendUniqueStr(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
