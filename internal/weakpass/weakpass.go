// Package weakpass 弱口令 / 空口令字典测试(纯标准库)。
//
// ===== 定位与合规边界(硬性, 改动前必读) =====
//
// 本包是**内网安全自查工具**的一个能力: 用于核查"自己运维的机器"上开放服务
// 是否使用了弱口令或未授权访问。因此合规设计不是可选项, 而是这个包存在的
// 前提条件:
//
//  1. 默认关闭: Config.Enabled=false 时 Check 立即返回, **不发起任何连接**
//     (项目规则 5: 新增功能默认关闭, 配置开关启用, 不影响原有流程)。
//  2. 白名单强制: 目标 IP 必须落在 Config.Targets(CIDR 列表)内, 否则直接拒绝。
//     白名单为空 = 拒绝一切(fail-closed), 不提供"扫全网"的旁路。
//  3. 限速 + 上限: 每目标独立令牌桶(Config.Rate 次/秒)与总尝试上限
//     (Config.MaxTry), 避免对目标造成登录失败风暴与账号锁定。
//  4. 审计留痕: 每一次尝试(含失败)都写审计记录, 可通过 Audit 取回。
//
// ===== 协议覆盖: 只做标准库能真正实现的, 其余明确不支持 =====
//
//	redis       AUTH / PING(RESP 文本协议, 一行一应答)
//	mysql       协议握手 + mysql_native_password 加密认证
//	postgresql  消息协议 v3 + 明文/md5 认证(scram 明确不支持)
//	telnet      类文本登录服务(login/password 提示符交互)
//	ftp         USER / PASS(230 登录成功)
//	ssh         SSH-2.0 握手(curve25519 / dh-group14)+ password 认证
//	smb         SMB1 Negotiate + NTLMv2 响应, 按状态码判定
//	vnc         RFB 3.3/3.7/3.8 + VNC 认证(DES), 含"无需认证"识别
//	rdp         X.224 协商 + TLS 可达性(受限管理员模式边界见 rdp.go)
//	oracle      TNS Connect 可达性(O3LOGON 口令校验明确不支持)
//
// mssql 仍返回 ErrUnsupported(TDS 预登录 + 版本差异过大, 不做不可靠判定)。
//
// 刻意保留的能力边界(**不伪造结果、不静默跳过**): 遇到标准库覆盖不到的分支
// (scram-sha-256、RDP 的 NLA 通道绑定、Oracle 口令校验等)一律返回
// ErrUnsupported 并在错误信息里说明原因, 由调用方明确告知用户"该协议/该分支
// 未支持" —— 给出"扫过了、没弱口令"的假结论比不扫更危险。
//
// 测试约定: 单测一律离线 —— 用 net.Pipe 造替身服务或注入 Dialer, 不依赖真实网络。
package weakpass

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUnsupported 协议不被支持(标准库无法实现或实现成本过高)。
//
// 与"扫描失败"是两类事情: 调用方必须把 ErrUnsupported 明确呈现给用户,
// 而不是当成"检测通过"。用 errors.Is 判定。
var ErrUnsupported = errors.New("weakpass: 该协议未在标准库能力内实现")

// ErrDisabled 功能未启用(Check 不会发起任何连接)。
var ErrDisabled = errors.New("weakpass: 弱口令检测未启用")

// ErrNotAllowed 目标不在白名单内(拒绝执行, 未发起连接)。
var ErrNotAllowed = errors.New("weakpass: 目标不在配置白名单内")

// Config 弱口令检测配置(对应 settings.json 的 authcheck 节)。
type Config struct {
	// Enabled 总开关。false(默认)时 Check 立即返回 ErrDisabled, 零连接、零行为变化。
	Enabled bool `json:"enabled"`
	// DictFile 用户字典文件路径(exe 同目录相对路径或绝对路径)。
	// 为空时只用内置字典。文件不存在时降级为内置字典 + 审计提示(项目规则 3)。
	DictFile string `json:"dictFile"`
	// Targets 允许检测的目标白名单(CIDR 或单 IP)。**为空即拒绝一切**。
	Targets []string `json:"targets"`
	// Rate 每目标每秒允许的尝试数(令牌桶速率)。<=0 表示不限速。
	Rate float64 `json:"rate"`
	// MaxTry 每目标最多尝试次数。<=0 取 DefaultMaxTry。
	MaxTry int `json:"maxTry"`
	// TimeoutMs 单次连接/交互超时(毫秒)。<=0 取 DefaultTimeoutMs。
	TimeoutMs int `json:"timeoutMs"`
}

const (
	// DefaultRate 默认限速: 每目标每秒 1 次尝试。
	//
	// 为什么这么保守: 口令检测的副作用是"目标侧产生大量失败登录", 会被目标
	// 自身的风控判定为暴力破解并锁账号 / 封 IP。自查工具首先要保证不破坏被查系统。
	DefaultRate = 1.0
	// DefaultMaxTry 默认每目标尝试上限(内置字典规模)。
	DefaultMaxTry = 100
	// DefaultTimeoutMs 默认单次交互超时。
	DefaultTimeoutMs = 1500
)

// withDefaults 补齐零值(不修改调用方结构体)。
func (c Config) withDefaults() Config {
	if c.Rate <= 0 {
		c.Rate = DefaultRate
	}
	if c.MaxTry <= 0 {
		c.MaxTry = DefaultMaxTry
	}
	if c.TimeoutMs <= 0 {
		c.TimeoutMs = DefaultTimeoutMs
	}
	return c
}

// Dialer 建立网络连接(可被测试注入, 默认 net.Dialer.DialContext)。
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Target 一次检测的目标(服务实例, 不是主机)。
type Target struct {
	// Host 目标 IP(白名单按此判定; 域名请先自行解析)
	Host string `json:"host"`
	// Port 端口
	Port int `json:"port"`
	// Service 服务类型: redis / mysql / telnet / ftp / ssh ...
	Service string `json:"service"`
	// User 用户名(telnet/ftp 用; redis 无用户名, mysql 用它做握手)
	User string `json:"user,omitempty"`
}

// Addr 目标地址(host:port)。
func (t Target) Addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// Key 目标唯一键(限速/上限按此维度, 而非按服务)。
//
// 刻意用 host:port 而不是 host: 同一台机器上 Redis 与 MySQL 是两套口令体系,
// 共用一个上限会让第二个服务拿不到额度, 表现为"第二个服务一个口令都没试"。
func (t Target) Key() string { return t.Addr() }

// Result 单个目标的检测结果。
type Result struct {
	Target
	// OK 是否发现弱口令 / 未授权访问
	OK bool
	// Password 命中的口令(未命中为空串)。空串口令命中时此处也是空串,
	// 需结合 EmptyPass 判定 —— 见下方字段。
	Password string
	// EmptyPass 命中的是"空口令 / 免认证"(比弱口令更严重)
	EmptyPass bool
	// Attempts 实际尝试次数
	Attempts int
	// Stopped 结束原因: disabled / not-allowed / unsupported / found /
	// maxtry / canceled / error
	Stopped string
	// Unsupported 协议未支持(不伪造结果)
	Unsupported bool
	// Error 错误说明(成功且无异常时为空)
	Error string
}

// Engine 弱口令检测引擎(配置 + 限速器 + 审计缓冲)。
//
// 零值不可用, 请用 New 构造。并发安全。
type Engine struct {
	cfg Config

	// now 时间源(测试注入以便不依赖真实时钟)
	now func() time.Time
	// dial 建连函数(测试注入 net.Pipe 替身)
	dial Dialer
	// auditSink 审计落地回调(可选, 为空时只进内存缓冲)
	auditSink func(Attempt)

	mu         sync.Mutex
	buckets    map[string]*bucket
	audit      []Attempt
	dictSource DictSource // 全量字典源(装配层注入 db 字典读取; nil = 用内置 + 用户文件)
}

const auditMax = 2000

// New 构造引擎。cfg 零值即"关闭"(Check 返回 ErrDisabled)。
func New(cfg Config) *Engine {
	return &Engine{
		cfg:     cfg.withDefaults(),
		now:     time.Now,
		dial:    defaultDialer(),
		buckets: map[string]*bucket{},
	}
}

// defaultDialer 默认建连器(net.Dialer 自带超时由调用方通过 ctx/SetDeadline 控制)。
func defaultDialer() Dialer {
	var d net.Dialer
	return d.DialContext
}

// Config 返回生效配置(已补默认值), 供状态接口展示。
//
// 加锁快照: SetConfig 可在运行期整体替换 cfg, 无锁读会与它构成数据竞争
// (Config 是多字段结构体, 拆开的逐字段读不是原子快照)。
func (e *Engine) Config() Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// Enabled 是否启用。
func (e *Engine) Enabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.Enabled
}

// SetConfig 整体替换运行时配置(补默认值后立即生效, 含目标白名单)。
//
// 供管理接口使用: 页面增删白名单后写 settings.json 再调这里热生效, 免重启。
// 只支持整体替换、不支持增量改 —— 白名单是合规红线(空=拒绝一切), 逐条
// 修改的中间态(改了一半)比任何确定状态都危险, 整份替换让"生效瞬间"唯一。
// 与 New 同样经 withDefaults: 管理端提交的 Rate/MaxTry 为 0 时不会把限速
// 打开放宽, 而是回落到安全默认。
func (e *Engine) SetConfig(cfg Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg.withDefaults()
}

// SetDialer 注入建连器(测试用 net.Pipe 替身; 传 nil 恢复默认)。
func (e *Engine) SetDialer(d Dialer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d == nil {
		e.dial = defaultDialer()
		return
	}
	e.dial = d
}

// SetNow 注入时间源(测试用固定时钟; 传 nil 恢复真实时钟)。
func (e *Engine) SetNow(f func() time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f == nil {
		e.now = time.Now
		return
	}
	e.now = f
}

// SetAuditSink 注入审计落地回调(每次尝试调用一次; 为空则只进内存缓冲)。
func (e *Engine) SetAuditSink(f func(Attempt)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.auditSink = f
}

// DictSource 全量字典源(装配层注入, 典型实现是"读 weak_password_dict 表"的闭包)。
//
// 设计口径: weakpass 是纯标准库叶包, 不 import db —— 字典"存在哪"由装配层
// 决定, 引擎只拿到一个"给我本次爆破的全量口令列表"的函数。
//
// 语义约定(与 loadDict 的降级链绑定):
//   - 返回非空列表 = 以此为准(列表本身应已含内置 + 自定义且去重, 引擎仍会再兜底去重);
//   - 返回空 / nil = 视为"字典源不可用", 回退 内置 + 用户文件(规则 3 外部资源可选)。
//     这个区分是刻意的: 用户把自定义条目删光时, 表里仍留有 349 条内置,
//     源不可能"合法地空" —— 空只可能是读失败, 而读失败时宁可退回内置也不该拿空字典跑。
type DictSource func() []string

// SetDictSource 注入全量字典源(传 nil 恢复为 内置 + 用户文件 的原始行为)。
func (e *Engine) SetDictSource(f DictSource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dictSource = f
}

// Allowed 目标 IP 是否在白名单内。
//
// 白名单为空 = 全部拒绝(fail-closed): "没配白名单"绝不能解释成"不限制",
// 那会让这个能力退化成无差别口令爆破, 与本包定位直接冲突。
func (e *Engine) Allowed(host string) bool {
	return e.allowHost(host) == ""
}

// allowHost 返回拒绝原因(空串=放行)。
//
// 白名单快照在锁内取: 判定必须基于"同一份"列表, 否则 SetConfig 在两次读取
// 之间替换时, "空判定"与"成员判定"会基于不同列表, 结论可能自相矛盾。
func (e *Engine) allowHost(host string) string {
	e.mu.Lock()
	targets := e.cfg.Targets
	e.mu.Unlock()
	if len(targets) == 0 {
		return "白名单为空(不限制等于无差别测试, 已按拒绝处理)"
	}
	return allowIn(host, targets)
}

// Check 对单个目标做弱口令检测。
//
// 返回值**永远非 nil**(除非目标本身为空), 失败语义写在 Result.Stopped/Error 里:
// 调用方要的是"每个目标都有结论", 而不是靠 error 中断整批任务。
func (e *Engine) Check(ctx context.Context, tg Target) *Result {
	return e.CheckWith(ctx, tg, Options{})
}

// Options 单次检测的额外选项。
type Options struct {
	// Dict 覆盖字典(为空则按 BuiltinOnly 选 内置 或 全量)。每项是一次尝试的口令。
	// 显式传了 Dict 时 BuiltinOnly 不生效(调用方已给出精确意图)。
	Dict []string
	// BuiltinOnly 仅使用内置字典(不含数据库自定义条目与用户字典文件)。
	// 默认 false = 全量"内置 + 自定义"(任务默认行为); true = 页面"仅使用内置字典"开关。
	BuiltinOnly bool
	// User 覆盖用户名(为空则用 Target.User)
	User string
	// EmptyPass 是否先试空口令 / 免认证(默认 true)。
	//
	// 刻意默认开启: "服务根本不要口令"比"口令弱"严重得多, 且开销只有一次尝试。
	EmptyPass *bool
	// Timeout 覆盖单次交互超时(<=0 用配置值)
	Timeout time.Duration
}

// CheckWith 带选项的检测。
func (e *Engine) CheckWith(ctx context.Context, tg Target, opt Options) *Result {
	// 单次检测使用同一份配置快照: 限速/上限/开关在检测中途被 SetConfig 替换时,
	// 本目标的行为仍按进入时的一致状态执行(避免"用 A 配置的额度配 B 配置的
	// 超时"这类混合态)。
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()

	res := &Result{Target: tg}
	host := strings.TrimSpace(tg.Host)
	tg.Host = host
	res.Host = host
	if host == "" {
		res.Stopped, res.Error = "error", "目标地址为空"
		return res
	}
	if !cfg.Enabled {
		res.Stopped, res.Error = "disabled", ErrDisabled.Error()
		return res
	}
	if reason := e.allowHost(host); reason != "" {
		res.Stopped = "not-allowed"
		res.Error = ErrNotAllowed.Error() + ": " + reason
		return res
	}
	svc := normalizeService(tg.Service)
	tg.Service = svc
	res.Service = svc
	ck := checkerOf(svc)
	if ck == nil {
		res.Unsupported = true
		res.Stopped = "unsupported"
		res.Error = ErrUnsupported.Error() + ": " + svc +
			"(仅 mssql 未实现: TDS 预登录与版本差异过大, 不做不可靠判定)"
		return res
	}

	user := opt.User
	if user == "" {
		user = tg.User
	}
	dict := e.resolveDict(opt)
	// 空口令优先: 一次尝试就能得到最高价值的结论
	if opt.EmptyPass == nil || *opt.EmptyPass {
		dict = append([]string{""}, dict...)
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = time.Duration(cfg.TimeoutMs) * time.Millisecond
	}

	limit := cfg.MaxTry
loop:
	for _, pass := range dict {
		if res.Attempts >= limit {
			res.Stopped = "maxtry"
			break
		}
		if err := ctx.Err(); err != nil {
			res.Stopped, res.Error = "canceled", err.Error()
			break
		}
		// 限速: 先取令牌, 不足则等待一个令牌周期后再取一次(等待可被 ctx 中断)
		wait, reason := e.take(tg.Key())
		if reason == "rate" {
			if !sleepCtx(ctx, wait) {
				res.Stopped, res.Error = "canceled", context.Canceled.Error()
				break
			}
			if wait, reason = e.take(tg.Key()); reason != "" {
				if reason == "maxtry" {
					res.Stopped = "maxtry"
				} else {
					res.Stopped, res.Error = "error", "等待限速令牌后仍未获得额度"
				}
				break
			}
		}
		if reason == "maxtry" {
			res.Stopped = "maxtry"
			break loop
		}
		res.Attempts++
		ok, err := e.tryOnce(ctx, tg, ck, user, pass, timeout)
		// 审计: 口令只在命中时落记录 —— 审计日志要能追责, 但不能变成一份明文口令库。
		rec := Attempt{
			Time:    e.timeNow(),
			Target:  tg.Addr(),
			Service: svc,
			User:    user,
			OK:      ok,
		}
		if err != nil {
			rec.Err = err.Error()
		}
		if ok {
			rec.Password = pass
		}
		e.record(rec)

		if err != nil {
			// 单次失败不终止整轮(网络抖动很常见), 但连续失败到最后也没成功
			// 时要有结论: 记在 Error 里, Stopped 仍为 error。
			res.Error = err.Error()
			continue
		}
		if ok {
			res.OK = true
			res.Password = pass
			res.EmptyPass = pass == ""
			res.Stopped = "found"
			res.Error = ""
			break
		}
	}
	if res.Stopped == "" {
		if res.Error != "" {
			res.Stopped = "error"
		} else {
			res.Stopped = "done"
		}
	}
	return res
}

// tryOnce 一次完整的"建连 → 尝试 → 断开"。
func (e *Engine) tryOnce(ctx context.Context, tg Target, ck Checker, user, pass string, timeout time.Duration) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := e.dialContext(cctx, "tcp", tg.Addr())
	if err != nil {
		return false, fmt.Errorf("连接失败: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	ok, err := ck.TryAuth(cctx, conn, user, pass)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func (e *Engine) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	e.mu.Lock()
	d := e.dial
	e.mu.Unlock()
	if d == nil {
		d = defaultDialer()
	}
	return d(ctx, network, addr)
}

func (e *Engine) timeNow() time.Time {
	e.mu.Lock()
	f := e.now
	e.mu.Unlock()
	if f == nil {
		return time.Now()
	}
	return f()
}

// sleepCtx 可中断的等待(取消时立即返回 false)。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
