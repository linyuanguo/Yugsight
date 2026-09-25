package server

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Middleware 中间件: 对 http.Handler 的装饰。
// 链式组装时列表顺序 = 执行顺序(列表第一个最外层)。
type Middleware func(http.Handler) http.Handler

// statusWriter 记录响应状态码(用于日志/异常捕获判断响应是否已写出)。
type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.written {
		s.status = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.written {
		s.status = http.StatusOK
		s.written = true
	}
	return s.ResponseWriter.Write(b)
}

// Recover 全局异常捕获中间件: 捕获任意 handler 的 panic,
// 记录日志并返回统一 500 响应(若响应尚未写出), 保证单个接口 panic 不导致服务宕机。
func Recover(logf func(string)) Middleware {
	if logf == nil {
		logf = func(string) {}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				if p := recover(); p != nil {
					logf(fmt.Sprintf("接口处理 panic(%s %s): %v", r.Method, r.URL.Path, p))
					if !sw.written {
						FailInternal(sw, "服务内部错误, 已记录日志")
					}
				}
			}()
			next.ServeHTTP(sw, r)
		})
	}
}

// CORS 跨域支持中间件。allowOrigin 为空默认 "*"。
// OPTIONS 预检请求直接 204 应答, 不进入路由。
func CORS(allowOrigin string) Middleware {
	if allowOrigin == "" {
		allowOrigin = "*"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With")
			w.Header().Set("Access-Control-Max-Age", "86400")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Logging 请求日志中间件: 记录 方法 / 路径 / 状态码 / 耗时。
//
// 【为什么需要聚合 —— 以及旧实现为什么没做到】
// 前端面板会以秒级间隔轮询状态接口(探针面板每 5s 打 /api/v2/probe/status 与
// /api/v2/probe/list)。这些请求本身正确、状态码恒为 200, 却会把真正有价值的日志
// (引擎安装、任务调度、错误)一行行冲走 —— 实测一次 nmap 安装的 27 秒里, 有效日志
// 只有 6 行, 其余全是轮询噪音。
//
// 旧实现只维护"上一条"记录, 遇到**交替轮询**就完全失效:
//
//	list -> 记为 A; status -> 刷出 A, 记为 B; list -> 刷出 B, 记为 A ...
//
// 每 2 次请求就 flush 一条, 实测日志仍是每 5s 两行 —— 聚合等于没做。
// (这个缺陷只有真机跑起来看日志才会暴露: 单测里轮询的是同一个路径, 连续相同,
//  聚合完美生效, 所以测试全绿也挡不住。)
//
// 现在的做法有两层:
//  1. 按 (方法, 路径, 状态码) 分别聚合到 map, 不再只认"上一条", 交替轮询各自计数;
//  2. 静音名单: 纯展示型的轮询接口**默认完全不记**(silentPaths), 其它接口在
//     flushInterval 到期时把累计条目刷出去。
//
// 【为什么静音名单要按"是否真实事件"来划分】用户的诉求很明确: 轮询不该占日志,
// 但**探针上线/下线这种真实事件必须看得见**。而这两类信息恰好落在不同接口上:
// 轮询走 GET /probe/list|status(纯读取, 每次都一样), 真实事件走 probe 包的
// logf(上线/离线/连接失败, 见 probe/server.go)。所以静音只针对前者, 后者照常记录。
func Logging(logf func(string)) Middleware {
	return LoggingWithOptions(logf, DefaultLoggingOptions())
}

// LoggingOptions 请求日志的行为开关。
type LoggingOptions struct {
	// SilentPaths 完全不出现在日志里的路径(默认见 DefaultSilentPaths)。
	//
	// 【为什么用"静音"而不是"聚合"】前端轮询是固定节奏的常驻行为, 只要页面开着就
	// 每 5s 打两条, 聚合后仍然是每 5s 两条日志 —— 聚合解决不了这类噪音。它们能提供的
	// 全部信息就是"接口还活着", 而这个信息在用户真正需要看日志时(排障)毫无价值,
	// 反而把有价值的内容挤走。故直接静音, 需要时看浏览器 Network 面板更直观。
	SilentPaths map[string]bool
	// Interval 聚合刷新周期(落盘节奏)。<=0 时用默认值。
	//
	// 【为什么必须有定时刷新, 不能只在"路径变化"时刷】轮询会长期占据请求流, 若只在
	// 出现不同路径时才 flush, 一条错误日志可能要等下一个非轮询请求才落盘 —— 用户
	// 恰恰是在"刚出了错"的时候看日志, 延时落盘等于看不到。
	Interval time.Duration
}

// DefaultSilentPaths 默认静音的前端轮询接口。
//
// 只放"前端定时轮询且不含业务事件"的只读接口。判断标准: 这个接口被调用上千次,
// 有没有任何一次是用户想知道的信息? 若答案为否, 就属于静音范围。
// 反面例子(故**不**在此列): 引擎下载进度、扫描任务状态 —— 那些接口被轮询时,
// 返回内容确实在推进, 是用户主动触发的操作, 日志里有价值。
func DefaultSilentPaths() map[string]bool {
	return map[string]bool{
		// 探针面板 5s 轮询(Probes.vue 的 load()): 纯读取在线列表与状态
		"/api/v2/probe/list":   true,
		"/api/v2/probe/status": true,
		// 探针任务列表: 仅在用户打开详情弹窗时轮询, 但仍是纯展示
		"/api/v2/probe/tasks": true,
		// 大屏 15s 自刷新(纯只读聚合)
		"/api/v2/screen/overview": true,
		// 数据库状态卡片轮询
		"/api/v2/db/status": true,
	}
}

// DefaultLoggingOptions 默认请求日志配置。
func DefaultLoggingOptions() LoggingOptions {
	return LoggingOptions{SilentPaths: DefaultSilentPaths(), Interval: 10 * time.Second}
}

// loggingEntry 单个 (方法,路径,状态码) 的累计条目。
type loggingEntry struct {
	status  int
	n       int
	firstAt time.Time
	lastAt  time.Time
	last    time.Duration
}

// LoggingWithOptions 可配置的请求日志中间件(logf 为空时不记录)。
func LoggingWithOptions(logf func(string), opt LoggingOptions) Middleware {
	if logf == nil {
		logf = func(string) {}
	}
	if opt.SilentPaths == nil {
		opt.SilentPaths = DefaultSilentPaths()
	}
	iv := opt.Interval
	if iv <= 0 {
		iv = 10 * time.Second
	}

	var (
		mu      sync.Mutex
		pending = map[string]*loggingEntry{} // key -> 累计
		stop    = make(chan struct{})
		once    sync.Once
	)

	// spawnFlusher 惰性启动定时刷新协程。
	//
	// 【为什么惰性启动】中间件是纯函数式的组装件, 在 New() 时被构造出来; 若在构造
	// 时就起协程, 测试里每次 New 都会漏一个 goroutine(测试进程不退出, 无法被回收)。
	// 只在第一个请求进来时启动, 就能让"没被真正挂载/没被调用"的实例不产生任何副作用。
	spawnFlusher := func() {
		once.Do(func() {
			go func() {
				tk := time.NewTicker(iv)
				defer tk.Stop()
				for {
					select {
					case <-stop:
						return
					case <-tk.C:
						flushLogging(&mu, pending, logf)
					}
				}
			}()
		})
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			if opt.SilentPaths[r.URL.Path] {
				// 静音: 直接放过, 连计时与计数都不做(轮询量最大, 省掉这部分开销)
				next.ServeHTTP(sw, r)
				return
			}
			start := time.Now()
			next.ServeHTTP(sw, r)
			cost := time.Since(start)
			key := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
			now := time.Now()

			mu.Lock()
			e := pending[key]
			var spill *loggingEntry
			if e == nil {
				e = &loggingEntry{status: sw.status, firstAt: now}
				pending[key] = e
			} else if e.status != sw.status {
				// 状态码变化: 把旧条目"挤出去"而不是覆盖丢弃。
				//
				// 【为什么不直接覆盖】同一接口"先 200 后 500"是典型的故障现场
				// (前半段正常、后半段开始报错)。若直接覆盖, 那条 200 记录会被静默
				// 吃掉, 用户看到的日志里这个接口从未成功过 —— 与事实相反, 且恰好
				// 丢掉了最关键的"何时开始坏"的时间点。所以先渲染旧条目再换新的。
				spill = e
				e = &loggingEntry{status: sw.status, firstAt: now}
				pending[key] = e
			}
			e.n++
			e.lastAt = now
			e.last = cost
			mu.Unlock()

			if spill != nil {
				logf(renderEntry(key, spill))
			}
			spawnFlusher()
		})
	}
}

// renderEntry 把一条累计条目渲染成日志文本。
//
// 单独抽出来是为了让"定时 flush"与"状态码变化时挤出旧条目"两条路径共用同一口径 ——
// 否则两处各写一份格式化, 迟早出现"聚合行标注次数、挤出行的不标注"这类不一致。
func renderEntry(key string, e *loggingEntry) string {
	if e.n == 1 {
		return fmt.Sprintf("HTTP %s -> %d (%s)", key, e.status, e.last.Round(time.Millisecond))
	}
	// 重复行标注次数与跨距: 同一接口短时间被打 N 次本身可能是个信号
	// (如前端 bug 导致请求风暴), 保留数字比"只出现一行"更有诊断价值。
	return fmt.Sprintf("HTTP %s -> %d (重复 %d 次, 跨 %s)",
		key, e.status, e.n, e.lastAt.Sub(e.firstAt).Round(time.Second))
}

// flushLogging 把累计条目刷成日志行并清空。
//
// mu 必须是指针: 按值传递会复制锁(vet 会直接报 "copies lock value") —— 复制出来的
// 是一把新锁, 与真正保护 pending 的那把无关, 等于完全没加锁, 且 go vet 拦下它正是
// 因为它属于"看起来能跑但语义已经错了"的一类问题。
func flushLogging(mu *sync.Mutex, pending map[string]*loggingEntry, logf func(string)) {
	mu.Lock()
	defer mu.Unlock()
	if len(pending) == 0 {
		return
	}
	for key, e := range pending {
		logf(renderEntry(key, e))
		delete(pending, key)
	}
}
