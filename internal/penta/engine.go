// engine.go 轻量验证执行引擎: 按模板逐步执行观测型探针, 产出三态结论与证据。
//
// 执行语义:
//
//   - 每一步是独立的观测(发请求/交互/试探), 命中 = 观测到漏洞行为;
//   - 全部命中 = 可利用(exploitable); 部分命中 = 部分利用(partial);
//     正常执行但无命中 = 不可利用(not_exploitable);
//   - 所有步骤都执行失败(目标不可达/服务未起) = 无法下结论, 任务记失败 ——
//     "连不上"不能得出"没有漏洞"的结论(结论方向错误比没有结论更危险);
//   - 单步错误不中断整轮(与 weakpass 的批量语义一致), 但错误单独计数并留存。
//
// 可注入依赖(测试全部离线):
//
//   - Dial: 建连函数(tcp 步骤直用, weakpass 步骤同步透传其 SetDialer);
//   - Doer: HTTP 执行函数(http 步骤; 默认 http.Client);
//   - Exec: 外部引擎执行器(external 步骤; 复用 engine 包的进程树管理)。
package penta

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"yugsight/internal/engine"
	"yugsight/internal/weakpass"
)

// EventFunc 实时事件回调(装配层用于 SSE 推送与审计)。
type EventFunc func(event string, data any)

// Doer HTTP 执行函数(测试注入假传输层, 离线验证 http 步骤逻辑)。
type Doer func(ctx context.Context, req *http.Request) (*http.Response, error)

// Engine 验证执行引擎(无全局状态, 可安全复用)。
type Engine struct {
	// BinsDir exe 同目录 bin/(external 步骤找引擎二进制的基准)
	BinsDir string
	// Now 时间源(测试注入固定时钟)
	Now func() time.Time
	// Dial 建连函数(nil = 默认 net.Dialer; 测试注入 net.Pipe 替身)
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Doer HTTP 执行函数(nil = 默认客户端)
	Doer Doer
	// Exec 外部引擎执行器(nil = external 步骤报"外部引擎不可用")
	Exec *engine.Executor
}

// NewEngine 默认引擎(外部引擎执行器用全局单例)。
func NewEngine(binsDir string) *Engine {
	return &Engine{BinsDir: binsDir, Now: time.Now, Exec: engine.Default()}
}

// substitute 展开模板占位符 {target}/{port}/{cve}。
func (t *Task) substitute(s string) string {
	r := strings.NewReplacer(
		"{target}", t.Target,
		"{port}", strconv.Itoa(t.Port),
		"{cve}", t.CVE,
	)
	return r.Replace(s)
}

// stepTimeout 单步超时(0 = 默认 10s, 上限 120s)。
func stepTimeout(ms int) time.Duration {
	if ms <= 0 {
		return defaultStepTimeout
	}
	d := time.Duration(ms) * time.Millisecond
	if d > maxStepTimeout {
		return maxStepTimeout
	}
	return d
}

// clip 截断到 n 字节(超长加标记, 证据要能看出"被截了"而不是"本来这么短")。
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("\n...[截断, 共 %d 字节]", len(s))
}

// Run 对任务执行一次模板验证, 返回完整结果(所有异常路径均填充, 永不返回 error:
// 执行结果是数据, 失败语义写在 RunOutcome 里 —— 与 weakpass.Result 同口径)。
func (e *Engine) Run(ctx context.Context, t *Task, tpl *Template, emit EventFunc) *RunOutcome {
	out := &RunOutcome{OK: true}
	if e.Now == nil {
		e.Now = time.Now
	}
	if emit == nil {
		emit = func(string, any) {}
	}
	var logBuf strings.Builder
	line := func(s string) {
		if logBuf.Len() < maxRunLog {
			logBuf.WriteString(s)
			logBuf.WriteByte('\n')
		}
		emit("penta.line", map[string]any{"line": s})
	}

	line(fmt.Sprintf("=== 开始验证 任务=%s 目标=%s:%d 协议=%s 模板=%s(%d 步) ===",
		t.ID, t.Target, t.Port, orDash(t.Protocol), tpl.ID, len(tpl.Steps)))
	start := e.Now()
	hitCount, errCount := 0, 0

	for i, spec := range tpl.Steps {
		if err := ctx.Err(); err != nil {
			out.OK = false
			out.Summary = fmt.Sprintf("执行被中止: 完成 %d/%d 步", i, len(tpl.Steps))
			line("[中止] " + err.Error())
			break
		}
		emit("penta.step", map[string]any{"index": i, "name": spec.Name, "type": spec.Type, "phase": "start"})
		t0 := e.Now()
		res := e.runStep(ctx, t, spec, line)
		res.DurationMs = e.Now().Sub(t0).Milliseconds()
		out.Steps = append(out.Steps, res)
		if res.Hit {
			hitCount++
		}
		if res.Err != "" {
			errCount++
		}
		line(fmt.Sprintf("[步骤 %s/%s] 命中=%v 耗时=%dms%s",
			spec.Name, spec.Type, res.Hit, res.DurationMs, errSuffix(res.Err)))
		emit("penta.step", map[string]any{
			"index": i, "name": spec.Name, "type": spec.Type,
			"phase": "done", "hit": res.Hit, "err": res.Err,
			"output": res.Output, "durationMs": res.DurationMs,
		})
	}

	dur := e.Now().Sub(start)
	switch {
	case !out.OK:
		if out.Summary == "" {
			out.Summary = fmt.Sprintf("执行未完成(用时 %s)", dur.Round(time.Millisecond))
		}
	case hitCount == 0:
		if errCount == len(out.Steps) {
			// 全错 = 目标不可达/服务未起: 无法下结论(而不是"不可利用")
			out.OK = false
			out.Summary = fmt.Sprintf("目标不可达, 无法得出验证结论(%d 步全部执行失败, 用时 %s)", errCount, dur.Round(time.Millisecond))
		} else {
			out.Exploitability = NotExploitable
			out.Summary = fmt.Sprintf("验证未命中: %d 步正常执行, 未观测到漏洞行为(用时 %s)", len(out.Steps)-errCount, dur.Round(time.Millisecond))
		}
	case hitCount == len(out.Steps):
		out.Exploitability = Exploitable
		out.Summary = fmt.Sprintf("验证命中: %d 步全部命中, 漏洞行为确认(用时 %s)", hitCount, dur.Round(time.Millisecond))
	default:
		out.Exploitability = Partial
		out.Summary = fmt.Sprintf("部分命中: %d/%d 步命中(用时 %s)", hitCount, len(out.Steps), dur.Round(time.Millisecond))
	}
	out.Log = logBuf.String()
	return out
}

func errSuffix(err string) string {
	if err == "" {
		return ""
	}
	return " err=" + err
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// runStep 按类型分发执行单步(每步独立超时, 互不拖累)。
func (e *Engine) runStep(ctx context.Context, t *Task, s StepSpec, line func(string)) StepResult {
	cctx, cancel := context.WithTimeout(ctx, stepTimeout(s.TimeoutMs))
	defer cancel()
	switch s.Type {
	case StepHTTP:
		return e.runHTTP(cctx, t, s, line)
	case StepTCP:
		return e.runTCP(cctx, t, s, line)
	case StepWeakPass:
		return e.runWeakPass(cctx, t, s, line)
	case StepExternal:
		return e.runExternal(cctx, t, s, line)
	default:
		return StepResult{Name: s.Name, Type: s.Type, Err: "未知步骤类型: " + s.Type}
	}
}

// targetOf 步骤目标解析: 步骤显式值优先, 空 = 任务目标; 展开占位符。
func targetOf(t *Task, host string, port int) (string, int) {
	h := strings.TrimSpace(host)
	if h == "" {
		h = t.Target
	}
	h = t.substitute(h)
	p := port
	if p == 0 {
		p = t.Port
	}
	return h, p
}

// runHTTP HTTP 观测探针。
//
// ExpectHeader 语义 = OR(任一列出头部匹配即满足): 版本暴露类检查里
// Server 与 X-Powered-By 通常只出现其一, AND 语义会把正常的单头暴露判成未命中。
func (e *Engine) runHTTP(ctx context.Context, t *Task, s StepSpec, line func(string)) StepResult {
	res := StepResult{Name: s.Name, Type: StepHTTP}
	host, port := targetOf(t, s.Host, s.Port)
	scheme := "http"
	if strings.EqualFold(t.Protocol, "https") {
		scheme = "https"
	}
	path := strings.TrimSpace(s.Path)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	method := strings.ToUpper(strings.TrimSpace(s.Method))
	if method == "" {
		method = http.MethodGet
	}
	url := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		res.Err = err.Error()
		line("[步骤 " + s.Name + "] 构造请求失败: " + err.Error())
		return res
	}
	for k, v := range s.Headers {
		req.Header.Set(k, t.substitute(v))
	}

	var resp *http.Response
	if e.Doer != nil {
		resp, err = e.Doer(ctx, req)
	} else {
		var client http.Client
		resp, err = client.Do(req)
	}
	if err != nil {
		res.Err = err.Error()
		line("[步骤 " + s.Name + "] 请求失败: " + err.Error())
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	res.Output = clip(string(body), maxStepOutput)

	var ev strings.Builder
	fmt.Fprintf(&ev, "%s %s -> %s\n", method, url, resp.Status)
	for k, v := range resp.Header {
		fmt.Fprintf(&ev, "%s: %s\n", k, strings.Join(v, ", "))
	}
	res.Evidence = clip(ev.String(), maxStepEvidence)

	hit := true
	if s.ExpectStatus > 0 && resp.StatusCode != s.ExpectStatus {
		hit = false
	}
	if s.ExpectBody != "" {
		re, rerr := regexp.Compile(t.substitute(s.ExpectBody))
		if rerr != nil {
			res.Err = "expectBody 正则非法: " + rerr.Error()
			return res
		}
		if !re.Match(body) {
			hit = false
		}
	}
	if len(s.ExpectHeader) > 0 {
		anyMatch := false
		for k, pat := range s.ExpectHeader {
			re, rerr := regexp.Compile(pat)
			if rerr == nil && re.MatchString(resp.Header.Get(k)) {
				anyMatch = true
				break
			}
		}
		hit = hit && anyMatch
	}
	res.Hit = hit
	line(fmt.Sprintf("[步骤 %s] %s %s -> %s 命中=%v", s.Name, method, url, resp.Status, res.Hit))
	return res
}

// runTCP TCP 协议交互探针(发送原始字节 + 读响应断言)。
func (e *Engine) runTCP(ctx context.Context, t *Task, s StepSpec, line func(string)) StepResult {
	res := StepResult{Name: s.Name, Type: StepTCP}
	host, port := targetOf(t, s.Host, s.Port)
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dial := e.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		res.Err = err.Error()
		line("[步骤 " + s.Name + "] 连接失败 " + addr + ": " + err.Error())
		return res
	}
	defer conn.Close()
	if derr := conn.SetDeadline(e.Now().Add(stepTimeout(s.TimeoutMs))); derr != nil {
		res.Err = derr.Error()
		return res
	}

	if send := t.substitute(s.Send); send != "" {
		if _, werr := io.WriteString(conn, send); werr != nil {
			res.Err = "发送失败: " + werr.Error()
			line("[步骤 " + s.Name + "] " + res.Err)
			return res
		}
	}
	buf := make([]byte, 4096)
	n, rerr := conn.Read(buf)
	data := buf[:n]
	res.Output = clip(string(data), maxStepOutput)
	res.Evidence = clip(fmt.Sprintf("target=%s\nsend=%s\nrecv=%s",
		addr, t.substitute(s.Send), string(data)), maxStepEvidence)

	expect := t.substitute(s.Expect)
	switch {
	case n == 0:
		// 连接成功但无响应数据(banner 缺失的服务 / 读取超时)
		if expect == "" {
			res.Hit = true // 约定: 空 Expect = 连接成功即命中
		} else {
			res.Err = "无响应数据"
			if rerr != nil {
				res.Err = "读取超时: " + rerr.Error()
			}
		}
	case expect == "":
		res.Hit = true
	default:
		re, perr := regexp.Compile(expect)
		if perr != nil {
			res.Err = "expect 正则非法: " + perr.Error()
			return res
		}
		res.Hit = re.Match(data)
	}
	line(fmt.Sprintf("[步骤 %s] %s 响应 %d 字节 命中=%v%s",
		s.Name, addr, n, res.Hit, errSuffix(res.Err)))
	return res
}

// runWeakPass 弱口令登录试探(复用 weakpass 引擎: 白名单=本任务目标, 限速, 只试登录)。
//
// 与"弱口令检测"模块(批量扫描)的分界: 这里每次只验证一个已知漏洞任务对应的
// 单个服务实例, 口令来自界面显式输入(未输入则用内置 top100 字典, 与弱口令模块同口径)。
func (e *Engine) runWeakPass(ctx context.Context, t *Task, s StepSpec, line func(string)) StepResult {
	res := StepResult{Name: s.Name, Type: StepWeakPass}
	host, port := targetOf(t, s.Host, s.Port)
	service := strings.TrimSpace(s.Service)
	if service == "" {
		service = strings.ToLower(t.Protocol)
	}
	if service == "http" || service == "https" || service == "" {
		res.Err = "weakpass 步骤需要明确 service(redis/ftp/ssh/mysql/...), 任务协议 http 不适用登录试探"
		line("[步骤 " + s.Name + "] " + res.Err)
		return res
	}

	dict := s.Passwords
	maxTry := len(dict) + 2 // 显式口令 + 空口令 + 1 余量
	if len(dict) == 0 {
		maxTry = weakpass.DefaultMaxTry + 1 // 内置 top100 字典 + 空口令
	}
	cfg := weakpass.Config{
		Enabled:   true,
		Targets:   []string{host}, // 白名单 = 本任务目标(fail-closed 语义天然满足)
		Rate:      1,              // 保守限速: 避免触发目标侧登录风控
		MaxTry:    maxTry,
		TimeoutMs: 5000,
	}
	weng := weakpass.New(cfg)
	if e.Dial != nil {
		weng.SetDialer(e.Dial)
	}
	weng.SetNow(e.Now)
	emptyPass := true
	user := t.substitute(s.User)
	wres := weng.CheckWith(ctx, weakpass.Target{Host: host, Port: port, Service: service, User: user},
		weakpass.Options{User: user, Dict: dict, EmptyPass: &emptyPass, Timeout: stepTimeout(s.TimeoutMs)})

	res.Output = fmt.Sprintf("service=%s user=%s 尝试=%d 结束=%s", service, orDash(user), wres.Attempts, wres.Stopped)
	switch {
	case wres.Unsupported:
		res.Err = "协议不支持: " + wres.Error
	case wres.OK:
		res.Hit = true
		if wres.EmptyPass {
			res.Evidence = "空口令/免认证: 未提供口令即登录成功"
		} else {
			res.Evidence = fmt.Sprintf("弱口令命中: user=%s password=%s(口令仅在命中时展示, 与弱口令模块审计口径一致)", user, wres.Password)
		}
	case wres.Stopped == "canceled":
		res.Err = "执行被取消: " + orDash(wres.Error)
	default:
		// 未命中是正常结论而非执行错误(登录失败 = 漏洞不成立的证据),
		// 不能置 Err —— 否则"单步未命中"会被 Run 的"全步骤失败"分支
		// 误判成"目标不可达、无法下结论"(结论方向错误)。
	}
	line(fmt.Sprintf("[步骤 %s] %s:%d %s 尝试 %d 次 命中=%v%s",
		s.Name, host, port, service, wres.Attempts, res.Hit, errSuffix(res.Err)))
	return res
}

// runExternal 外部渗透引擎(可选通道): 调用 bin/ 下用户自备的引擎二进制。
//
// 合规口径: 外部引擎是用户自行部署的第三方工具, 其命令语义由用户负责;
// 平台侧保证: 仅 admin 可触发、全程审计留痕、超时与进程树终止由 engine 包兜底。
func (e *Engine) runExternal(ctx context.Context, t *Task, s StepSpec, line func(string)) StepResult {
	res := StepResult{Name: s.Name, Type: StepExternal}
	if e.Exec == nil {
		res.Err = "外部引擎执行器不可用(external 步骤未启用)"
		return res
	}
	args := make([]string, 0, len(s.Args))
	for _, a := range s.Args {
		args = append(args, t.substitute(a))
	}
	line(fmt.Sprintf("[步骤 %s] 外部引擎 %s 参数 %v", s.Name, s.Bin, args))
	r, err := e.Exec.Run(ctx, engine.Spec{
		Engine:  s.Bin,
		Args:    args,
		Timeout: stepTimeout(s.TimeoutMs),
	})
	if r == nil {
		r = &engine.Result{}
	}
	if err != nil {
		res.Err = err.Error()
		line("[步骤 " + s.Name + "] 外部引擎执行失败: " + err.Error())
		return res
	}
	res.DurationMs = r.Duration.Milliseconds()
	res.Output = clip(r.Stdout, maxStepOutput)
	res.Evidence = clip(fmt.Sprintf("engine=%s args=%v exit=%d\nstdout=%s\nstderr=%s",
		r.Bin, args, r.ExitCode, r.Stdout, r.Stderr), maxStepEvidence)
	if r.Error != "" {
		res.Err = r.Error
		return res
	}
	if !r.OK {
		res.Err = fmt.Sprintf("引擎退出码 %d(非零)", r.ExitCode)
		return res
	}
	expect := t.substitute(s.Expect)
	if expect == "" {
		res.Hit = true // 空 Expect = 引擎成功退出即命中
	} else {
		re, perr := regexp.Compile(expect)
		if perr != nil {
			res.Err = "expect 正则非法: " + perr.Error()
			return res
		}
		res.Hit = re.MatchString(r.Stdout)
	}
	return res
}
