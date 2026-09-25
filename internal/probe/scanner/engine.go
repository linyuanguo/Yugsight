package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"yugsight/internal/engine/parsers"
	"yugsight/internal/normalizer"
)

// ===== 外部引擎增强(./bin/, 可选) =====
//
// 设计原则(项目规则 3/5): 探针默认不依赖任何外部引擎 —— bin/ 缺失时静默降级为
// 内置引擎能力, 不报错不影响扫描。当用户把 nmapcore / trivycore / zapcore 放进
// exe 同目录 bin/ 后, 探针即可用它们增强扫描结果:
//
//	nmapcore:  SYN 扫描(需权限) + 服务版本识别(-sV) + NSE 脚本, 输出 XML 解析
//	trivycore: 对本地文件系统/镜像做漏洞与配置扫描(探针按 target 解释为路径/镜像)
//	zapcore:   对 Web 目标做主动扫描(结果落 JSON 报告文件)
//
// 解析统一走 engine/parsers(任务 6.2 已有 nmap XML/JSON、trivy、zap 三套解析器),
// 探针不重复实现输出解析 —— 但 engine/parsers 依赖面较大(引 engine 执行器),
// 这里只用其纯解析函数(Parse / ParseNmap), 不引入进程编排, 保证 agent 体积可控。

// EngineBinPath 返回 bin/ 下指定前缀的引擎路径(供外部探测/能力上报复用)。
//
// 与 probe 包 binengine.go 同算法: 精确 <前缀>[.exe] 优先, 否则前缀匹配;
// Windows 只认 .exe(engine.findBin 的既有约定, 避免误把 .sh/.py 当可执行引擎)。
func EngineBinPath(prefix string) string { return engineBinPath(prefix) }

// engineBinPath 返回 bin/ 下指定前缀的引擎路径(内部实现)。
func engineBinPath(prefix string) string {
	dir := exeSubDir("bin")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	isWin := runtime.GOOS == "windows"
	var loose string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.ToLower(e.Name())
		if isWin && !strings.HasSuffix(n, ".exe") {
			continue
		}
		if !isWin && strings.Contains(n, ".") {
			continue
		}
		if n == prefix || n == prefix+".exe" {
			return filepath.Join(dir, e.Name())
		}
		if strings.HasPrefix(n, prefix) && loose == "" {
			loose = filepath.Join(dir, e.Name())
		}
	}
	return loose
}

// exeSubDir exe 同目录的子目录路径(获取不到 exe 路径时退化为相对目录)。
func exeSubDir(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return name
	}
	return filepath.Join(filepath.Dir(exe), name)
}

// templateDir 外部 Nuclei 模板目录(探针端 exe 同目录 templates/)。
// 注: 探针是独立二进制, 目录布局与中心端 dist/ 的整理(vuln/ res/ data/)无关,
// 保持原样以免影响存量探针部署。
//
// 目录不存在时 LoadAllTemplates 只返回内置模板(打包进 exe), 不报错 ——
// 探针裸部署(只丢一个 exe)也能做 POC 验证, 这是内置模板的价值所在。
func templateDir() string { return exeSubDir("templates") }

// runExternalEngines 按目标类型选择合适的外部引擎增强扫描。
//
// 判定顺序: 先 trivy(本地路径/镜像) → 再 zap(URL) → 最后 nmap(IP)。
// 三者互不冲突, 但同一目标可能同时是 URL 与 IP, 因此按"最具体的目标形态"优先。
func (t *Task) runExternalEngines(ctx context.Context, host string, progress Progress) {
	raw := strings.TrimSpace(t.Target)

	if bin := engineBinPath("trivy"); bin != "" && isTrivyTarget(raw) {
		t.runTrivy(ctx, bin, raw, progress)
	}
	if bin := engineBinPath("zap"); bin != "" && isURLTarget(raw) {
		t.runZap(ctx, bin, raw, progress)
	}
	if bin := engineBinPath("nmap"); bin != "" && host != "" {
		t.runNmap(ctx, bin, host, progress)
	}
}

// isURLTarget 目标是否为 http(s) URL(决定是否适合 zap)。
func isURLTarget(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// isTrivyTarget 目标是否为 trivy 可处理形态(本地路径 / 镜像名, 非裸 IP)。
//
// 裸 IP 交给 nmap; 路径(含 / 或以 . 开头)与镜像名(含 :tag 且非 IP:port)交给 trivy。
func isTrivyTarget(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if isURLTarget(s) {
		return false
	}
	// 本地路径形态: 绝对路径 / 相对路径 / windows 盘符
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") ||
		(len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/')) {
		return true
	}
	// 镜像名形态: 含 ":" 但不含 "."(排除 IP:port) 或含 "/" 命名空间
	if strings.Contains(s, ":") && !ipPortRe.MatchString(s) {
		return true
	}
	return false
}

// ipPortRe 匹配 "IP:端口" 串(用于把镜像名与 IP:port 区分开)。
var ipPortRe = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}:\d+$`)

// runNmap 用 nmapcore 做服务版本识别扫描, XML 输出解析后并入结果。
//
// 参数: -sT(TCP 连接扫描, 不需要原始套接字权限; 有权限的目标机可自行改 -sS)
// 通过 Args 追加: 中心端可在 TaskAssign.Args 里传 {"nmapArgs":["-sS","-A"]} 覆盖。
func (t *Task) runNmap(ctx context.Context, bin, host string, progress Progress) {
	args := t.nmapArgs(host)
	progress.Emit(fmt.Sprintf("外部引擎 nmapcore: %s %s", host, strings.Join(args, " ")))
	out, err := runCmd(ctx, t.cfg.Timeout.Engine, bin, args...)
	if err != nil {
		progress.Emit("nmapcore 执行失败(降级内置结果): " + truncate(err.Error(), 200))
		return
	}
	batch, perr := parsers.ParseNmap(out)
	if perr != nil {
		progress.Emit("nmapcore 输出解析失败(降级内置结果): " + truncate(perr.Error(), 200))
		return
	}
	n := t.ingestParsedBatch(host, batch)
	progress.Emit(fmt.Sprintf("nmapcore 完成: 合并资产 %d 项, 漏洞 %d 条", n.assets, n.vulns))
}

// nmapArgs nmap 扫描参数(-oX - 输出 XML, 含服务版本与默认 NSE)。
//
// 用 XML 而非 JSON(-oJ): nmap 的 -oJ 是遗留格式, 不含 hostscript/NSE 结果,
// 而 NSE 恰恰是 nmap 漏洞结论的主要来源(引擎 6.2 的解析器也以 XML 为主路径)。
func (t *Task) nmapArgs(host string) []string {
	args := []string{
		"-sT",                     // TCP 连接扫描(无需特权, 探针不要求提权)
		"-sV",                     // 服务版本识别
		"-p", joinPorts(t.cfg.Ports),
		"--version-light",         // 轻量版本探测: 探针扫描讲究速度, 不必全量探针
		"--open",                  // 只报开放端口
		"-oX", "-",                // XML 到 stdout
		"--host-timeout", "300s",  // 单主机上限, 防死主机拖住整个任务
	}
	if extra := t.extraArgs("nmapArgs"); len(extra) > 0 {
		args = append(args, extra...)
	}
	return append(args, host)
}

// runTrivy 用 trivycore 扫描本地文件系统/镜像, JSON 输出解析后并入结果。
func (t *Task) runTrivy(ctx context.Context, bin, target string, progress Progress) {
	isImage := strings.Contains(target, ":") && !strings.HasPrefix(target, "/") &&
		!(len(target) > 2 && target[1] == ':')
	args := []string{"fs", "-f", "json", "-q"}
	if isImage {
		args = []string{"image", "-f", "json", "-q"}
	}
	if extra := t.extraArgs("trivyArgs"); len(extra) > 0 {
		args = append(args, extra...)
	}
	args = append(args, target)

	progress.Emit("外部引擎 trivycore: " + strings.Join(args, " "))
	out, err := runCmd(ctx, t.cfg.Timeout.Engine, bin, args...)
	if err != nil {
		progress.Emit("trivycore 执行失败(降级内置结果): " + truncate(err.Error(), 200))
		return
	}
	batch, perr := parsers.ParseTrivy(out)
	if perr != nil {
		progress.Emit("trivycore 输出解析失败(降级内置结果): " + truncate(perr.Error(), 200))
		return
	}
	n := t.ingestParsedBatch("", batch)
	progress.Emit(fmt.Sprintf("trivycore 完成: 合并资产 %d 项, 漏洞 %d 条", n.assets, n.vulns))
}

// runZap 用 zapcore 扫描 Web 目标。
//
// ZAP 的 JSON 报告不支持输出到 stdout, 必须落文件(-J <file>): 用临时文件承接,
// 读完即删(探针机器上不留残包)。
func (t *Task) runZap(ctx context.Context, bin, target string, progress Progress) {
	report := filepath.Join(os.TempDir(), "yugsight-probe-zap-"+strconv.FormatInt(time.Now().UnixNano(), 36)+".json")
	defer func() { _ = os.Remove(report) }()

	// -g 0 关闭 ZAP 自检, -J 落 JSON 报告; 主动扫描用 -t 指定目标
	args := []string{"-g", "0", "-t", target, "-J", report}
	if extra := t.extraArgs("zapArgs"); len(extra) > 0 {
		args = append(args, extra...)
	}
	progress.Emit("外部引擎 zapcore: " + strings.Join(args, " "))
	if _, err := runCmd(ctx, t.cfg.Timeout.Engine, bin, args...); err != nil {
		progress.Emit("zapcore 执行失败(降级内置结果): " + truncate(err.Error(), 200))
		return
	}
	data, rerr := os.ReadFile(report)
	if rerr != nil || len(data) == 0 {
		progress.Emit("zapcore 未产出报告文件(降级内置结果)")
		return
	}
	batch, perr := parsers.ParseZap(data)
	if perr != nil {
		progress.Emit("zapcore 报告解析失败(降级内置结果): " + truncate(perr.Error(), 200))
		return
	}
	n := t.ingestParsedBatch("", batch)
	progress.Emit(fmt.Sprintf("zapcore 完成: 合并资产 %d 项, 漏洞 %d 条", n.assets, n.vulns))
}

// ingestCount 一次外部引擎并入的条目数(日志用)。
type ingestCount struct {
	assets int
	vulns  int
}

// ingestParsedBatch 把外部引擎解析结果并入任务上下文。
//
// fallbackIP 非空时用于补齐解析结果里缺失的 IP(如 nmap XML 一般自带 IP,
// 而某些解析结果缺 IP 时需要按扫描目标回填, 否则条目会被丢弃)。
func (t *Task) ingestParsedBatch(fallbackIP string, b *parsers.Batch) ingestCount {
	var n ingestCount
	if b == nil {
		return n
	}
	for _, a := range b.AllAssets() {
		ip := strings.TrimSpace(a.IP)
		if ip == "" {
			ip = fallbackIP
		}
		if ip == "" {
			continue
		}
		t.addAsset(normalizer.ProbeAsset{
			IP:       ip,
			MAC:      a.MAC,
			Hostname: a.Hostname,
			OS:       a.OS,
			Ports:    a.Ports,
			Service:  a.Service,
			Version:  a.Version,
			Banner:   truncate(a.Banner, 500),
			Tags:     appendUniqueStr(a.Tags, "外部引擎"),
		})
		n.assets++
	}
	for _, v := range b.Vulns {
		ip := strings.TrimSpace(v.AssetIP)
		if ip == "" {
			ip = fallbackIP
		}
		if ip == "" {
			continue
		}
		t.addVuln(normalizer.ProbeVuln{
			IP:          ip,
			Port:        v.Port,
			Protocol:    v.Protocol,
			CVE:         firstCVE(v.CVE),
			Title:       v.Title,
			Severity:    v.Severity,
			Description: v.Description,
			Evidence:    truncate(v.Evidence, 2000),
			Request:     truncate(v.Request, 8000),
			Response:    truncate(v.Response, 8000),
			CVSS:        v.CVSS,
			Confidence:  v.Confidence,
			FoundAt:     time.Now(),
		})
		n.vulns++
	}
	return n
}

// extraArgs 从任务参数里取外部引擎追加参数(中心端下发 Args 时可带)。
//
// 例: {"nmapArgs": ["-sS","-A"]} —— 允许中心端按目标特性微调引擎行为,
// 而不需要探针端升级。参数只允许字符串数组, 其它类型忽略(防御性)。
func (t *Task) extraArgs(key string) []string {
	if t.cfg.ExtraArgs == nil {
		return nil
	}
	raw, ok := t.cfg.ExtraArgs[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// joinPorts 端口列表拼成 nmap 风格串(超长时用范围压缩)。
//
// nmap 支持 "80,443,8000-8100" 形式的列表; 探针默认端口集里含 27017 之类
// 不连续端口, 因此只做"连续段压缩"而不整体取范围, 避免扩大扫描面。
func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return "80,443"
	}
	sorted := append([]int(nil), ports...)
	sortInts(sorted)
	var sb strings.Builder
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] == sorted[j]+1 {
			j++
		}
		if sb.Len() > 0 {
			sb.WriteByte(',')
		}
		if j-i >= 2 { // 连续 3 个以上才压缩成范围(nmap 语义: a-b)
			sb.WriteString(strconv.Itoa(sorted[i]) + "-" + strconv.Itoa(sorted[j]))
		} else {
			for k := i; k <= j; k++ {
				if k > i {
					sb.WriteByte(',')
				}
				sb.WriteString(strconv.Itoa(sorted[k]))
			}
		}
		i = j + 1
	}
	return sb.String()
}

// sortInts 简单插入/快速排序替代(避免为一个小工具引入 sort 依赖的额外 import 噪音)。
func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// execCommandContext 执行命令(单独包一层便于测试替换)。
func execCommandContext(ctx context.Context, bin string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, bin, args...)
}
