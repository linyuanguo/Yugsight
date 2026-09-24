package main

// 弱口令 / 空口令检测(weakpass 包)在 main 包的唯一接线点。
//
// 合规底线(与 weakpass 包头部注释同口径, 改动前必读):
//
//  1. 默认关闭: authcheck.enabled 缺失或为 false 时, 本文件不发任何连接、
//     不起任何后台任务; 程序行为与没有这个功能时完全一致(项目规则 5)。
//  2. 白名单: 目标必须在 authcheck.targets(CIDR)内, 否则接口直接拒绝。
//  3. 限速 + 上限: 由 weakpass.Engine 的令牌桶与 MaxTry 保证。
//  4. 审计: 每次尝试经 SetAuditSink 落 yugsight.log(前缀 [authcheck])。
//
// 接口(全部 requireAuth):
//
//	GET  /api/authcheck/status  配置与运行状态(含最近一次结果)
//	POST /api/authcheck/start   提交一批目标, 后台执行
//	POST /api/authcheck/stop    中止正在执行的批次

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/weakpass"
)


// AuthCheckConfig 弱口令检测配置(settings.json 的 authcheck 节)。
type AuthCheckConfig struct {
	// Enabled 总开关, 默认 false
	Enabled bool `json:"enabled"`
	// DictFile 用户字典文件路径(相对 exe 同目录或绝对路径)
	DictFile string `json:"dictFile"`
	// Targets 目标白名单(CIDR / 单 IP), 为空即拒绝一切
	Targets []string `json:"targets"`
	// Rate 每目标每秒尝试数
	Rate float64 `json:"rate"`
	// MaxTry 每目标尝试上限
	MaxTry int `json:"maxTry"`
	// TimeoutMs 单次交互超时
	TimeoutMs int `json:"timeoutMs"`
}

// toWeakpass 转成 weakpass 包配置(相对路径字典按 exe 同目录解析)。
func (c AuthCheckConfig) toWeakpass(exeDir string) weakpass.Config {
	p := strings.TrimSpace(c.DictFile)
	if p != "" && !filepath.IsAbs(p) {
		p = filepath.Join(exeDir, p)
	}
	return weakpass.Config{
		Enabled:   c.Enabled,
		DictFile:  p,
		Targets:   c.Targets,
		Rate:      c.Rate,
		MaxTry:    c.MaxTry,
		TimeoutMs: c.TimeoutMs,
	}
}

var (
	authCheckOnce sync.Once
	authCheckEng  *weakpass.Engine
	authCheckCfg  AuthCheckConfig

	authCheckMu      sync.Mutex
	authCheckRunning bool
	authCheckCancel  context.CancelFunc
	authCheckLast    *authCheckRun
	authCheckSeq     int
)

// authCheckRun 一次批次的运行结果。
//
// 字段由后台 goroutine(authCheckRunBatch)写、status 接口并发读, 因此**自带锁**:
// 不能指望调用方都记得先拿 authCheckMu —— 那把锁管的是"当前批次指针/取消函数"
// 这类全局状态, 与单次运行的内容是两回事, 混用必然漏掉一两条路径。
//
// 读取一律走 snapshot()/finished() 拿副本, 直接读字段在 -race 下就是 DATA RACE。
type authCheckRun struct {
	mu sync.Mutex

	ID        string             `json:"id"`
	StartedAt time.Time          `json:"startedAt"`
	Finished  bool               `json:"finished"`
	Stopped   bool               `json:"stopped"`
	Summary   string             `json:"summary"`
	Results   []weakpass.Result  `json:"results"`
	Audit     []weakpass.Attempt `json:"audit,omitempty"`
}

// snapshot 取一份可安全读取/序列化的副本(切片也一起拷, 否则等于没加锁)。
func (r *authCheckRun) snapshot() *authCheckRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &authCheckRun{
		ID:        r.ID,
		StartedAt: r.StartedAt,
		Finished:  r.Finished,
		Stopped:   r.Stopped,
		Summary:   r.Summary,
		Results:   append([]weakpass.Result(nil), r.Results...),
		Audit:     append([]weakpass.Attempt(nil), r.Audit...),
	}
}

// finished 批次是否已结束(轮询用, 避免为此拷一遍结果集)。
func (r *authCheckRun) finished() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Finished
}

// addResult 追加一个目标的结果, 返回当前已完成数。
func (r *authCheckRun) addResult(res weakpass.Result) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Results = append(r.Results, res)
	return len(r.Results)
}

// finish 标记结束并写入总结(中止路径也走这里, 保证 Finished 一定会置上)。
func (r *authCheckRun) finish(summary string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Finished = true
	r.Summary = summary
}

// setAudit 写入本次批次的审计记录快照。
func (r *authCheckRun) setAudit(a []weakpass.Attempt) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Audit = a
}

// markStopped 标记"被用户中止"。
func (r *authCheckRun) markStopped() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Stopped = true
}

// authCheckExeDir exe 所在目录(相对路径字典文件的基准)。
func authCheckExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// instanceAuthCheck 全局引擎(懒加载单例)。
//
// 配置解析失败时降级为"关闭"(Enabled=false): 配置文件写错不该让程序起不来,
// 更不该让一个安全能力以错误的白名单悄悄生效。
func instanceAuthCheck() *weakpass.Engine {
	authCheckOnce.Do(func() {
		cfg := loadAuthCheckConfig()
		authCheckCfg = cfg
		authCheckEng = weakpass.New(cfg.toWeakpass(authCheckExeDir()))
		authCheckEng.SetAuditSink(func(a weakpass.Attempt) {
			logLine(authCheckAuditLine(a))
		})
		// 字典联动: 执行任务时全量加载 weak_password_dict 表(内置 349 + 页面自定义)。
		// weakpass 不 import db, 这里闭包是唯一连接点; 数据库不可用/表为空返回 nil,
		// 引擎自动降级为嵌入内置字典(规则 3 外部资源可选, 弱口令检测不因此中断)。
		authCheckEng.SetDictSource(func() []string {
			d := v2DB()
			if d == nil || d.WeakPassDict() == nil {
				return nil
			}
			list, err := d.WeakPassDict().List()
			if err != nil || len(list) == 0 {
				return nil
			}
			out := make([]string, 0, len(list))
			for _, e := range list {
				out = append(out, e.Password)
			}
			return out
		})
		if !cfg.Enabled {
			logLine("弱口令检测: 未启用(authcheck.enabled 未配置或为 false), 不会发起任何连接")
			return
		}
		logLine("弱口令检测: 已启用, 白名单 " + strings.Join(cfg.Targets, ","))
	})
	return authCheckEng
}

// authCheckAuditLine 审计记录的日志文本。
//
// 口令只在命中时出现(weakpass 的约定), 失败尝试只记目标与账号 —— 日志文件
// 不能退化成一份明文口令清单。
func authCheckAuditLine(a weakpass.Attempt) string {
	s := "[authcheck] " + a.Time.Format("15:04:05") + " " + a.Target + " " + a.Service
	if a.User != "" {
		s += " user=" + a.User
	}
	switch {
	case a.OK && a.Password == "":
		s += " 命中(空口令/免认证)"
	case a.OK:
		s += " 命中(弱口令)"
	}
	if a.Err != "" {
		s += " err=" + a.Err
	}
	return s
}

// loadAuthCheckConfig 读配置: settings.json 的 authcheck 节优先, 回退 authcheck.json。
//
// 走 section() 而不是自己 ReadFile: BOM 剥离与"显式 null 视为未配置"的口径
// 必须和全项目一致(统一配置中心约定)。
func loadAuthCheckConfig() AuthCheckConfig {
	var cfg AuthCheckConfig
	data, ok := section(secAuthCheck, "")
	if !ok {
		return cfg
	}
	if json.Unmarshal(data, &cfg) != nil {
		logLine("authcheck 配置解析失败, 按未启用处理")
		return AuthCheckConfig{}
	}
	return cfg
}

// resetAuthCheck 重置单例与运行态(仅供测试)。
func resetAuthCheck() {
	authCheckStop()
	authCheckMu.Lock()
	authCheckLast = nil
	authCheckMu.Unlock()
	authCheckOnce = sync.Once{}
	authCheckEng = nil
	authCheckCfg = AuthCheckConfig{}
}

// ===== API =====

// authCheckReq 启动请求体。
type authCheckReq struct {
	// Targets 待检测目标(必填)
	Targets []weakpass.Target `json:"targets"`
	// User 覆盖用户名(为空则用每个目标自带的 user)
	User string `json:"user,omitempty"`
	// Dict 覆盖字典(为空则按 BuiltinOnly 选 内置 或 全量)
	Dict []string `json:"dict,omitempty"`
	// BuiltinOnly 仅使用内置字典(页面"仅使用内置字典"开关; 默认 false = 全量"内置+自定义")
	BuiltinOnly bool `json:"builtinOnly,omitempty"`
}

// handleAuthCheckStatus GET /api/authcheck/status
func handleAuthCheckStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	e := instanceAuthCheck()
	cfg := e.Config()
	authCheckMu.Lock()
	run := authCheckLast
	running := authCheckRunning
	authCheckMu.Unlock()
	// 取副本再序列化: 直接把 run 交给 json.Marshal 等于在锁外读正在被写的字段
	var result any
	if run != nil {
		result = run.snapshot()
	}

	jsonOK(w, map[string]any{
		"enabled":      cfg.Enabled,
		"dictFile":     cfg.DictFile,
		"targets":      cfg.Targets,
		"rate":         cfg.Rate,
		"maxTry":       cfg.MaxTry,
		"timeoutMs":    cfg.TimeoutMs,
		"supported":    weakpass.Supported(),
		"unsupported":  weakpass.UnsupportedProtocols(),
		"dictSize":     len(weakpass.BuiltinDict()),
		"dictStats":    weakPassDictStats(),
		"running":      running,
		"result":       result,
		"auditCount":   e.AuditCount(),
	})
}

// handleAuthCheckStart POST /api/authcheck/start
//
// 未启用 / 白名单为空时明确拒绝(400), 不做"先跑一遍再说": 这个功能一旦跑起来
// 就是对目标发起真实认证请求, 静默执行是不可接受的。
func handleAuthCheckStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	e := instanceAuthCheck()
	if !e.Enabled() {
		jsonErr(w, http.StatusBadRequest, "弱口令检测未启用(settings.json 的 authcheck.enabled=true 后重启)")
		return
	}
	if len(e.Config().Targets) == 0 {
		jsonErr(w, http.StatusBadRequest, "authcheck.targets 白名单为空, 已拒绝执行(不限制等于无差别测试)")
		return
	}
	var req authCheckReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	if len(req.Targets) == 0 {
		jsonErr(w, http.StatusBadRequest, "targets 为空")
		return
	}
	if len(req.Targets) > 200 {
		jsonErr(w, http.StatusBadRequest, "单次目标数上限 200")
		return
	}

	authCheckMu.Lock()
	if authCheckRunning {
		authCheckMu.Unlock()
		jsonErr(w, http.StatusConflict, "已有批次在执行, 请先停止")
		return
	}
	authCheckSeq++
	id := time.Now().Format("20060102-150405") + "-" + strconv.Itoa(authCheckSeq)
	run := &authCheckRun{ID: id, StartedAt: time.Now()}
	authCheckLast = run
	authCheckRunning = true
	ctx, cancel := context.WithCancel(context.Background())
	authCheckCancel = cancel
	authCheckMu.Unlock()

	go authCheckRunBatch(ctx, e, req, run)

	jsonOK(w, map[string]any{"ok": true, "id": id, "count": len(req.Targets)})
}

// handleAuthCheckStop POST /api/authcheck/stop
func handleAuthCheckStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !authCheckStop() {
		jsonOK(w, map[string]any{"ok": true, "stopped": false, "msg": "当前没有执行中的批次"})
		return
	}
	jsonOK(w, map[string]any{"ok": true, "stopped": true})
}

// authCheckStop 中止执行中的批次, 返回是否真的中止了。
func authCheckStop() bool {
	authCheckMu.Lock()
	cancel := authCheckCancel
	running := authCheckRunning
	authCheckCancel = nil
	if authCheckLast != nil && running {
		authCheckLast.markStopped()
	}
	authCheckMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return running
}

// authCheckRunBatch 后台执行一批目标(目标间串行: 单目标内部的节奏由限速器控制)。
func authCheckRunBatch(ctx context.Context, e *weakpass.Engine, req authCheckReq, run *authCheckRun) {
	defer func() {
		authCheckMu.Lock()
		authCheckRunning = false
		authCheckCancel = nil
		authCheckMu.Unlock()
	}()
	opt := weakpass.Options{User: req.User, Dict: req.Dict, BuiltinOnly: req.BuiltinOnly}
	found, unsupported, done := 0, 0, 0
	for _, tg := range req.Targets {
		if ctx.Err() != nil {
			run.finish("已中止: 完成 " + strconv.Itoa(done) + "/" +
				strconv.Itoa(len(req.Targets)) + " 个目标")
			// 报告中心二期: 中止也算一次执行完成, 部分结果同样留档
			if rr := buildRawWeakpassReport(run); rr != nil {
				autoSaveRawReport(v2DB(), rr)
			}
			return
		}
		res := e.CheckWith(ctx, tg, opt)
		done = run.addResult(*res)
		if res.OK {
			found++
		}
		if res.Unsupported {
			unsupported++
		}
	}
	run.setAudit(e.Audit(200))
	summary := "完成 " + strconv.Itoa(done) + " 个目标, 命中 " +
		strconv.Itoa(found) + " 个, 不支持的协议 " + strconv.Itoa(unsupported) + " 个"
	run.finish(summary)
	logLine("弱口令检测 " + run.ID + ": " + summary)
	// 报告中心二期: 批次完成 → 原始弱口令报告自动存档(best-effort 异步)
	if rr := buildRawWeakpassReport(run); rr != nil {
		autoSaveRawReport(v2DB(), rr)
	}
}
