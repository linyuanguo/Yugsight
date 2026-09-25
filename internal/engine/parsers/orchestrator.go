package parsers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"yugsight/internal/normalizer"
)

// 引擎输出解析编排 + 自动降级(任务 6.2)。
//
// 职责: 把「执行外部引擎 → 解析输出 → 归一化为标准模型」串成一条可容错流水线,
// 并在任一环节失败时自动降级到内置引擎能力, 记录降级日志, 不中断扫描任务。
//
// 降级触发条件(逐级判定, 全部记日志):
//
//	1. 引擎未启用 / 引擎文件缺失     → 跳过外部引擎, 直接用内置引擎
//	2. 引擎执行失败(非零退出/崩溃)   → 换内置引擎
//	3. 执行超时 / 任务被取消         → 不降级(避免重复扫描), 直接返回
//	4. 输出被截断(超捕获上限)        → 换内置引擎(JSON 不完整无法解析)
//	5. 输出解析失败 / 解析结果为空   → 换内置引擎
//
// 内置引擎由调用方以 Runner 注入(避免本包反向依赖 scanner 造成耦合),
// 未注入时降级为空结果 + 日志提示, 不影响主服务。

// Runner 内置引擎能力(降级兜底)。由调用方注入(通常是 scanner 包的封装)。
type Runner func(ctx context.Context, req Request) (*normalizer.RawBatch, error)

// ExecFunc 外部引擎执行函数(签名与 engine.Executor.Run 对齐, 便于直接传入)。
// 返回 stdout / 是否被截断 / 错误。
type ExecFunc func(ctx context.Context, engineName string, args []string) (stdout []byte, truncated bool, err error)

// Request 一次扫描请求(外部引擎与内置引擎共用)。
type Request struct {
	// Target 扫描目标(IP / CIDR / 镜像 / 路径 / URL, 按 Kind 解释)
	Target string
	// Ports 端口列表(nmap / zap 用)
	Ports []int
	// Kind 扫描类型: nmap | trivy | zap(决定用哪个引擎与解析器)
	Kind string
	// Args 追加的引擎参数(覆盖默认行为)
	Args []string
	// Timeout 单引擎超时
	Timeout time.Duration
	// ExtraFiles 引擎产出在文件而非 stdout 时的读文件回调(zap 报告)
	// 返回文件内容; 为空表示该引擎不落文件
	ReadArtifact func() ([]byte, error)
}

// Outcome 单次编排结果。
type Outcome struct {
	// Source 实际生效的来源: normalizer.SourceNmap / Trivy / ZAP, 降级时为 SourcePortScan
	Source string `json:"source"`
	// Result 归一化后的标准结果(资产 + 漏洞), 可直接送报告 / 大屏 / API
	Result *normalizer.Result `json:"result"`
	// Degraded 是否发生降级
	Degraded bool `json:"degraded"`
	// DegradeReason 降级原因(未降级为空)
	DegradeReason string `json:"degradeReason,omitempty"`
	// EngineError 外部引擎的失败原因(未失败为空)
	EngineError string `json:"engineError,omitempty"`
	// Warnings 非致命问题(解析警告 / 降级提示)
	Warnings []string `json:"warnings,omitempty"`
	// Duration 总耗时
	Duration time.Duration `json:"duration"`
}

// Orchestrator 引擎编排器: 执行 + 解析 + 归一化 + 降级。
// 并发安全; 可全局共享。默认启用降级(DisableFallback 可关闭)。
type Orchestrator struct {
	// Exec 外部引擎执行函数(nil = 无外部引擎, 直接降级)
	Exec ExecFunc
	// Fallback 内置引擎能力(nil = 无兜底, 降级为空结果)
	Fallback Runner
	// DisableFallback 关闭自动降级(仅调试用: 失败直接返回错误)
	DisableFallback bool
	// NormalizeOpts 归一化选项(基线对比 / ScanID 等)
	NormalizeOpts normalizer.Options

	mu         sync.RWMutex
	log        func(string)
	lastSource string // 最近一次实际生效的来源(诊断用)
	degradeCnt int
}

// NewOrchestrator 创建编排器(exec / fallback 可为 nil, 后续用 SetXxx 注入)。
func NewOrchestrator(exec ExecFunc, fallback Runner) *Orchestrator {
	return &Orchestrator{Exec: exec, Fallback: fallback, log: func(string) {}}
}

// SetLogger 注入主程序日志函数(并入 yugsight.log)。
func (o *Orchestrator) SetLogger(f func(string)) {
	if f == nil {
		return
	}
	o.mu.Lock()
	o.log = f
	o.mu.Unlock()
}

// SetExec 注入外部引擎执行函数。
func (o *Orchestrator) SetExec(f ExecFunc) {
	o.mu.Lock()
	o.Exec = f
	o.mu.Unlock()
}

// SetFallback 注入内置引擎兜底。
func (o *Orchestrator) SetFallback(f Runner) {
	o.mu.Lock()
	o.Fallback = f
	o.mu.Unlock()
}

// Stats 编排统计(供引擎状态面板展示)。
type Stats struct {
	LastSource    string `json:"lastSource"`
	DegradeCount  int    `json:"degradeCount"`
	FallbackReady bool   `json:"fallbackReady"`
	ExecReady     bool   `json:"execReady"`
}

// Stats 返回编排统计。
func (o *Orchestrator) Stats() Stats {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return Stats{
		LastSource:    o.lastSource,
		DegradeCount:  o.degradeCnt,
		FallbackReady: o.Fallback != nil,
		ExecReady:     o.Exec != nil,
	}
}

func (o *Orchestrator) logf(format string, args ...any) {
	o.mu.RLock()
	f := o.log
	o.mu.RUnlock()
	if f != nil {
		f(fmt.Sprintf(format, args...))
	}
}

// Run 执行一次「外部引擎 → 解析 → 归一化」, 失败自动降级内置引擎。
// 全程不 panic: 异常转错误 + 日志 + 降级。
func (o *Orchestrator) Run(ctx context.Context, req Request) (out *Outcome, err error) {
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			o.logf("引擎编排内部异常(kind=%s): %v, 已降级内置引擎", req.Kind, r)
			fb, ferr := o.runFallback(ctx, req, fmt.Sprintf("编排内部异常: %v", r))
			if out == nil {
				out = fb
			}
			if ferr != nil && err == nil {
				err = ferr
			}
			if out != nil {
				out.Duration = time.Since(start)
			}
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}

	engineName, parseName, ok := engineForKind(req.Kind)
	if !ok {
		return nil, fmt.Errorf("未知引擎类型: %s", req.Kind)
	}

	// 1) 无外部引擎可用 → 直接降级
	o.mu.RLock()
	exec := o.Exec
	noFallback := o.DisableFallback
	o.mu.RUnlock()
	if exec == nil {
		out, ferr := o.runFallback(ctx, req, "未配置外部引擎执行器")
		if out != nil {
			out.Duration = time.Since(start)
		}
		return out, ferr
	}

	// 2) 执行外部引擎
	args, tempFiles := o.buildArgs(engineName, req)
	// 兜底报告文件(buildArgs 自动注入)统一落系统临时目录且无人读取, Run 退出时
	// 删除 —— 否则会在临时目录无限累积。调用方经 NmapArtifact/ZapArtifact 注入的
	// 文件由调用方自行 cleanup, 这里不动。
	defer func() {
		for _, f := range tempFiles {
			_ = os.Remove(f)
		}
	}()
	ectx := ctx
	var cancel context.CancelFunc
	if req.Timeout > 0 {
		ectx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	stdout, truncated, eerr := exec(ectx, engineName, args)
	// 引擎改为落文件时(如 zap -J): 用回调取回内容
	if eerr == nil {
		o.mu.RLock()
		read := req.ReadArtifact
		o.mu.RUnlock()
		if read != nil {
			fileData, ferr := read()
			if ferr != nil {
				eerr = fmt.Errorf("读取引擎报告文件失败: %w", ferr)
			} else if len(fileData) > 0 {
				stdout = fileData
				truncated = false
			}
		}
	}

	// 3) 执行失败判定
	if eerr != nil {
		// 超时 / 取消: 不降级(重复扫描无意义, 且可能再次超时)
		if errors.Is(eerr, context.DeadlineExceeded) || errors.Is(eerr, context.Canceled) ||
			errors.Is(ectx.Err(), context.DeadlineExceeded) || errors.Is(ectx.Err(), context.Canceled) {
			o.logf("引擎 %s 被取消/超时, 不再降级重扫: %v", engineName, eerr)
			return &Outcome{
				Source:      "none",
				Degraded:    false,
				EngineError: eerr.Error(),
				Duration:    time.Since(start),
			}, eerr
		}
		if noFallback {
			return &Outcome{Source: "none", EngineError: eerr.Error(), Duration: time.Since(start)}, eerr
		}
		o.logf("引擎 %s 执行失败(%v), 自动降级内置引擎", engineName, eerr)
		out, ferr := o.runFallback(ctx, req, "引擎执行失败: "+eerr.Error())
		if out != nil {
			out.Duration = time.Since(start)
		}
		return out, ferr
	}
	if truncated {
		o.logf("引擎 %s 输出超限被截断(JSON 不完整), 自动降级内置引擎", engineName)
		if noFallback {
			return &Outcome{Source: "none", Degraded: true, DegradeReason: "输出被截断",
				Duration: time.Since(start)}, errors.New("引擎输出被截断")
		}
		out, ferr := o.runFallback(ctx, req, "引擎输出超出捕获上限被截断")
		if out != nil {
			out.Duration = time.Since(start)
		}
		return out, ferr
	}
	if len(strings.TrimSpace(string(stdout))) == 0 {
		o.logf("引擎 %s 无输出, 自动降级内置引擎", engineName)
		out, ferr := o.runFallback(ctx, req, "引擎无输出")
		if out != nil {
			out.Duration = time.Since(start)
		}
		return out, ferr
	}

	// 4) 解析(用引擎输出格式对应的解析器)
	batch, perr := Parse(parseName, stdout)
	if perr != nil {
		if noFallback {
			return &Outcome{Source: "none", EngineError: perr.Error(), Duration: time.Since(start)}, perr
		}
		o.logf("引擎 %s 输出解析失败(%v), 自动降级内置引擎", parseName, perr)
		out, ferr := o.runFallback(ctx, req, "解析失败: "+perr.Error())
		if out != nil {
			out.Duration = time.Since(start)
		}
		return out, ferr
	}

	// 5) 解析结果为空(引擎没扫到东西): 视为"空结果"而非失败 ——
	// 目标确实没有开放端口/漏洞是正常情况, 不降级重扫
	if len(batch.Assets) == 0 && len(batch.Vulns) == 0 && len(batch.SetupAssets) == 0 {
		o.logf("引擎 %s 解析成功但无结果(目标可能无开放端口/漏洞)", parseName)
		res := normalizer.NormalizeWithOptions(o.normOpts(), batch.RawBatch())
		o.markSource(batch.Source)
		out = &Outcome{
			Source:   batch.Source,
			Result:   res,
			Warnings: append(batch.Warnings, "引擎执行成功但未发现任何资产/漏洞"),
			Duration: time.Since(start),
		}
		return out, nil
	}

	// 6) 归一化: 解析结果统一转标准 Asset / Vuln
	raw := batch.RawBatch()
	assets := batch.AllAssets()
	raw.Assets = assets
	res := normalizer.NormalizeWithOptions(o.normOpts(), raw)
	o.markSource(batch.Source)
	o.logf("引擎 %s 解析成功: 资产 %d, 漏洞 %d, 警告 %d", batch.Source,
		len(res.Assets), len(res.Vulns), len(batch.Warnings))
	out = &Outcome{
		Source:   batch.Source,
		Result:   res,
		Warnings: batch.Warnings,
		Duration: time.Since(start),
	}
	return out, nil
}

// RunToStore 执行编排并把成功结果写入 Store(供 Web / 报告读取)。
// 失败时返回 outcome(degraded 标记) 与错误, 不覆盖 store 中原有结果。
func (o *Orchestrator) RunToStore(ctx context.Context, req Request, store *normalizer.Store) (*Outcome, error) {
	out, err := o.Run(ctx, req)
	if out != nil && out.Result != nil && store != nil {
		store.Set(out.Result)
	}
	return out, err
}

// runFallback 降级到内置引擎能力; 未配置兜底时返回空结果 + 警告(不报错, 不阻断)。
func (o *Orchestrator) runFallback(ctx context.Context, req Request, reason string) (*Outcome, error) {
	o.mu.Lock()
	fb := o.Fallback
	o.degradeCnt++
	o.lastSource = normalizer.SourcePortScan
	o.mu.Unlock()

	out := &Outcome{
		Source:        normalizer.SourcePortScan,
		Degraded:      true,
		DegradeReason: reason,
		Warnings:      []string{"已自动降级为内置引擎能力: " + reason},
	}
	if o.DisableFallback {
		return out, errors.New(reason)
	}
	if fb == nil {
		o.logf("降级内置引擎失败: 未注入内置 Runner (原因: %s)", reason)
		out.Warnings = append(out.Warnings, "内置引擎能力未接入, 本次返回空结果")
		out.Result = normalizer.NormalizeWithOptions(o.normOpts(), &normalizer.RawBatch{
			Source: normalizer.SourcePortScan,
		})
		return out, nil
	}

	raw, err := fb(ctx, req)
	if err != nil {
		o.logf("内置引擎降级扫描失败: %v (原由: %s)", err, reason)
		out.Warnings = append(out.Warnings, "内置引擎失败: "+err.Error())
		return out, err
	}
	if raw == nil {
		raw = &normalizer.RawBatch{Source: normalizer.SourcePortScan}
	}
	if strings.TrimSpace(raw.Source) == "" {
		raw.Source = normalizer.SourcePortScan
	}
	out.Result = normalizer.NormalizeWithOptions(o.normOpts(), raw)
	out.Source = raw.Source
	o.logf("降级内置引擎完成: 资产 %d, 漏洞 %d (原由: %s)",
		len(out.Result.Assets), len(out.Result.Vulns), reason)
	return out, nil
}

func (o *Orchestrator) normOpts() normalizer.Options {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.NormalizeOpts
}

func (o *Orchestrator) markSource(src string) {
	o.mu.Lock()
	o.lastSource = src
	o.mu.Unlock()
}

// engineForKind 扫描类型 → (执行器用的引擎名, 解析器用的引擎名)。
func engineForKind(kind string) (engineName, parseName string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "nmap", "port", "portscan", "host":
		return "nmap", "nmap", true
	case "trivy", "fs", "image", "container":
		return "trivy", "trivy", true
	case "zap", "web", "url":
		return "zap", "zap", true
	default:
		return "", "", false
	}
}

// tempFileSeq 兜底报告文件序号: 并发扫描时保证唯一(时间戳同纳秒的兜底)。
var tempFileSeq uint64

// uniqueTempFile 在系统临时目录生成唯一报告文件路径(前缀 + 目标 + 纳秒 + 序号)。
//
// 【为什么不能只按目标命名】同一目标会反复/并发扫描, 按目标命名后写的覆盖先写的;
// 更关键的是兜底文件无人读取, 写一次就在临时目录留一次, 会无限累积。唯一命名
// 是"统一落临时目录 + 用完即删"能成立的前提。
func uniqueTempFile(prefix, target, ext string) string {
	seq := atomic.AddUint64(&tempFileSeq, 1)
	name := fmt.Sprintf("%s-%s-%d-%d.%s", prefix, sanitizeName(target), time.Now().UnixNano(), seq, ext)
	return filepath.Join(os.TempDir(), name)
}

// buildArgs 组装引擎默认参数(与 normalizer 适配器的输出格式口径一致)。
// 返回 args 与 tempFiles: 后者是本函数在调用方未显式指定输出路径时自动注入的
// 兜底报告文件(nmap -oX / zap -quickout), 统一落系统临时目录, 由 Run 退出时删除;
// 空切片表示未创建兜底文件。
// 本包不依赖 engine 包, 因此参数模板在此复刻; 调用方可用 req.Args 覆盖/追加。
//
// 【zap 参数为什么长这样(实测修正, 勿改回)】原实现是 `-g 0 -t <url>`, 有双重问题:
//
//	缺 -cmd     → ZAP 以 Swing GUI 模式启动, 弹窗并常驻等用户操作;
//	-t 不可用   → ZAP 2.17 的 -help 里没有 -t/-J, 传了只会打印帮助后退出,
//	              既不扫描也不出报告(表现为"跑了但没结果")。
//
// 2026-09 用 ZAP 2.17.0 实测通过的正确形态是:
//
//	zap -cmd -quickurl <url> -quickout <报告文件>
//
// -quickurl 一次跑完 spider + 主动扫描; -quickout 的报告类型由**文件扩展名**决定,
// 故这里固定用 .json, 与 normalizer.FromZAPJSON / ParseZap 对接。
//
// 报告路径: 用 req.ExtraFiles 之外的约定 —— 调用方(Dashboard/任务层)经 ZapArtifact
// 生成路径并通过 req.Args 传入 -quickout, 这里给不传时的兜底(系统临时目录)。
func (o *Orchestrator) buildArgs(engineName string, req Request) (args []string, tempFiles []string) {
	target := strings.TrimSpace(req.Target)
	switch engineName {
	case "nmap":
		// 【为什么是 -oX 落文件而不是 -oJ - (stdout), 实测修正勿改回】
		// Windows 版 nmap(7.94 官方构建, 2026-09-20 实测): "-oJ -" 与 "-oJ <file>"
		// 的值都会被当成扫描目标(报 Failed to resolve "-"/"...json"), 即 -oJ 在
		// Windows 构建上完全不可用; -oX/-oN 落文件正常。Linux 上 "-oX -" 可用,
		// 但为跨平台一致(且 XML 含 hostscript NSE 信息量更大), 统一 XML 落文件。
		//
		// 【为什么加 -Pn】Windows nmap 默认主机发现走 pcap 嗅探, 在 VPN 虚拟网卡/
		// 无 Npcap/非管理员环境下 pcap_create 失败 3 次直接 QUITTING。产品内置
		// 引擎口径本就是"无主机发现, 直接端口探测", 开放端口即活性证据, 语义一致。
		args = []string{"-sT", "-Pn", "-p", joinPorts(req.Ports), "--open"}
		// 调用方(runEngineScan)经 NmapArtifact 注入的 -oX 优先(带 scanID 唯一);
		// 兜底唯一命名落临时文件(Run 退出时自动删除), 宁可文件没人读也不能让 -oJ 坏参数上线。
		if !hasFlag(req.Args, "-oX") && !hasFlag(req.Args, "-oN") &&
			!hasFlag(req.Args, "-oJ") && !hasFlag(req.Args, "-oA") {
			f := uniqueTempFile("yugsight-nmap", target, "xml")
			args = append(args, "-oX", f)
			tempFiles = append(tempFiles, f)
		}
		args = append(args, req.Args...)
		return append(args, target), tempFiles
	case "trivy":
		// 目标形如 "image:nginx:1.21" / "fs:/app" 时按前缀切换子命令
		sub := "fs"
		if strings.HasPrefix(strings.ToLower(target), "image:") {
			sub = "image"
			target = target[len("image:"):]
		} else if strings.HasPrefix(strings.ToLower(target), "fs:") {
			target = target[len("fs:"):]
		}
		args = []string{sub, "-f", "json"}
		args = append(args, req.Args...)
		return append(args, target), nil
	default: // zap
		// 调用方若已通过 req.Args 指定了 -quickout(配合 ZapArtifact), 就别再补一个,
		// 否则 ZAP 收到两个 -quickout, 报告写到哪取决于解析顺序, 且 read 回调会读到空文件。
		args = []string{"-cmd", "-quickurl", target}
		if !hasFlag(req.Args, "-quickout") {
			f := uniqueTempFile("yugsight-zap", target, "json")
			args = append(args, "-quickout", f)
			tempFiles = append(tempFiles, f)
		}
		args = append(args, req.Args...)
		return args, tempFiles
	}
}

// hasFlag 判断追加参数里是否已包含某个选项(用于避免重复补默认值)。
// 只比对选项名本身, 不关心其取值形式(-quickout X 与 -quickout=X 都算)。
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return "80,443"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			parts = append(parts, fmt.Sprint(p))
		}
	}
	if len(parts) == 0 {
		return "80,443"
	}
	return strings.Join(parts, ",")
}
