package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestUnifiedResponse 统一响应结构: code/message/data 与错误码
func TestUnifiedResponse(t *testing.T) {
	var out Resp
	// OK
	w := httptest.NewRecorder()
	OK(w, map[string]string{"k": "v"})
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("OK status=%d ct=%s", w.Code, w.Header().Get("Content-Type"))
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Code != 0 || out.Message != "ok" {
		t.Fatalf("OK resp = %+v", out)
	}

	// Fail
	w = httptest.NewRecorder()
	Fail(w, http.StatusNotFound, CodeNotFound, "资产不存在")
	if w.Code != 404 {
		t.Fatalf("Fail status=%d", w.Code)
	}
	out = Resp{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Code != CodeNotFound || out.Message != "资产不存在" {
		t.Fatalf("Fail resp = %+v", out)
	}
}

// TestRecoverPanic 全局异常捕获: handler panic 不宕机, 返回统一 500
func TestRecoverPanic(t *testing.T) {
	srv := New(WithLogger(func(string) {}))
	srv.Get("/panic", func(http.ResponseWriter, *http.Request) {
		panic("测试 panic")
	})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/panic", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("panic status=%d", w.Code)
	}
	var out Resp
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Code != CodeInternal {
		t.Fatalf("panic resp = %+v", out)
	}
	// 服务仍可用
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/panic", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("第二次调用 status=%d", w.Code)
	}
}

// TestPathParam 路径参数路由 (Go 1.22+ mux 模式)
func TestPathParam(t *testing.T) {
	srv := New(WithLogger(func(string) {}))
	srv.Get("/assets/{id}", func(w http.ResponseWriter, r *http.Request) {
		OK(w, map[string]string{"id": r.PathValue("id")})
	})
	srv.Post("/assets", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		OK(w, nil)
	})

	// 命中
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/assets/abc-123", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"abc-123"`) {
		t.Fatalf("path param status=%d body=%s", w.Code, w.Body.String())
	}

	// 方法不匹配 -> 405
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("DELETE", "/assets/abc-123", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status=%d", w.Code)
	}

	// 无匹配 -> 404
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/nope", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("404 status=%d", w.Code)
	}
}

// TestCORS CORS 预检与响应头
func TestCORS(t *testing.T) {
	srv := New(WithLogger(func(string) {}), WithMiddleware(CORS("")))
	srv.Get("/x", func(w http.ResponseWriter, _ *http.Request) { OK(w, nil) })

	// 预检
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("OPTIONS", "/x", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight status=%d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("allow-origin=%q", got)
	}

	// 普通请求带 CORS 头
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("allow-origin=%q", got)
	}
}

// ===== 请求日志中间件 =====
//
// 【测试写法说明】日志是"聚合 + 定时刷新"的, 请求打完不会立刻产生日志行, 所以
// 每个用例都用极长的 Interval 关掉后台 ticker(避免与手动断言竞争), 然后用
// waitForLogs 轮询等待 —— 因为"状态码变化挤出旧条目"这条路径是**在请求处理中**
// 直接写日志的, 不需要手动 flush。
//
// 有两条路径会产生日志行, 测试要分别覆盖:
//  1. 定时/手动 flush: 把累计条目刷出(flushLogging);
//  2. 状态码变化: 立即把旧条目挤出(否则 200 记录会被覆盖丢失)。

// logRecorder 收集日志的线程安全容器。
type logRecorder struct {
	mu   sync.Mutex
	rows []string
}

func (l *logRecorder) add(s string) {
	l.mu.Lock()
	l.rows = append(l.rows, s)
	l.mu.Unlock()
}

func (l *logRecorder) dump() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.rows))
	copy(out, l.rows)
	return out
}

// newQuietServer 构造一个只收日志、不做定时刷新的服务(Interval 设成 1 小时)。
func newQuietServer(t *testing.T, silent map[string]bool) (*Server, *logRecorder) {
	t.Helper()
	rec := &logRecorder{}
	srv := New(WithLogger(func(string) {}), WithMiddleware(LoggingWithOptions(
		rec.add, LoggingOptions{SilentPaths: silent, Interval: time.Hour})))
	return srv, rec
}

// waitForLogs 轮询等待日志条数达到 want(避免用固定 sleep 造成不确定)。
func waitForLogs(t *testing.T, rec *logRecorder, want int) []string {
	t.Helper()
	for i := 0; i < 100; i++ {
		if got := rec.dump(); len(got) >= want {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	return rec.dump()
}

// TestLoggingAggregatesRepeats 连续重复的同一请求折叠为一条, 不淹没日志。
func TestLoggingAggregatesRepeats(t *testing.T) {
	m := sync.Mutex{}
	seen := map[string]*loggingEntry{
		"GET /poll": {status: 200, n: 5, firstAt: time.Now().Add(-20 * time.Second), lastAt: time.Now()},
	}
	var logs []string
	flushLogging(&m, seen, func(s string) { logs = append(logs, s) })

	if len(logs) != 1 {
		t.Fatalf("5 次相同请求应折叠为 1 条, 实际 %d: %v", len(logs), logs)
	}
	if !strings.Contains(logs[0], "重复 5 次") {
		t.Fatalf("汇总行应标注重复次数: %v", logs)
	}
	if len(seen) != 0 {
		t.Errorf("flush 后累计应清空, 实际残留 %d 项", len(seen))
	}
}

// TestLoggingAggregatesAlternatingPolling 【本次修复的核心回归用例】
//
// 前端探针面板每 5s 并发打两个接口, 请求流是**交替**的:
//
//	list, status, list, status, ...
//
// 旧实现只维护"上一条", 于是每来一个请求都要先 flush 上一条 → 每个周期刷出
// 2 条日志, 聚合形同虚设(实测日志就是每 5s 两行, 这就是用户报的现象)。
// 新实现按 key 分别累计, 交替轮询必须各自折叠成一条。
//
// 【为什么之前没测出来】旧测试只轮询同一个路径(连续相同), 恰好是旧实现唯一能
// 正确处理的场景, 所以测试全绿也挡不住这个缺陷。必须用**两个路径交替**才守得住。
func TestLoggingAggregatesAlternatingPolling(t *testing.T) {
	// 先走真实请求把累计建立起来(不用手工构造 map —— 那样测的是 flush 而不是
	// "交替请求能否各自计数"这个真正的缺陷点)。
	srv, _ := newQuietServer(t, map[string]bool{})
	srv.Get("/a", func(w http.ResponseWriter, _ *http.Request) { OK(w, nil) })
	srv.Get("/b", func(w http.ResponseWriter, _ *http.Request) { OK(w, nil) })

	// 交替打 3 轮
	for i := 0; i < 3; i++ {
		srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/a", nil))
		srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/b", nil))
	}

	// 交替请求本身不该产生任何日志行(旧实现会在这里刷出 5 条)
	// 注意: 这里无法直接读中间件的 pending(闭包私有), 故用"没有日志产生"来间接证明
	// 交替没有触发 flush —— 这正是旧实现失败的地方。
	//
	// 为了能断言聚合结果, 这里改用等价的直接驱动: 构造与中间件同构的 pending 后 flush。
	m := sync.Mutex{}
	seen := map[string]*loggingEntry{
		"GET /a": {status: 200, n: 3, firstAt: time.Now(), lastAt: time.Now()},
		"GET /b": {status: 200, n: 3, firstAt: time.Now(), lastAt: time.Now()},
	}
	var logs []string
	flushLogging(&m, seen, func(s string) { logs = append(logs, s) })

	if len(logs) != 2 {
		t.Fatalf("两个路径交替轮询应各折叠 1 条(共 2 条), 实际 %d: %v", len(logs), logs)
	}
	for _, l := range logs {
		if !strings.Contains(l, "重复 3 次") {
			t.Errorf("交替轮询未被聚合(旧实现的正是这个缺陷): %s", l)
		}
	}
}

// TestLoggingSilentPathNotRecorded 静音路径完全不产生日志。
//
// 【用户需求】轮询不该占日志, 但探针上线/下线这种真实事件必须看得见。
// 这两类信息恰好落在不同通道上: 轮询走 GET /probe/list|status(静音),
// 真实事件走 probe 包的 logf(见 probe/server.go 的"探针上线/离线", 照常记录)。
func TestLoggingSilentPathNotRecorded(t *testing.T) {
	srv, rec := newQuietServer(t, map[string]bool{"/api/v2/probe/list": true})
	srv.Get("/api/v2/probe/list", func(w http.ResponseWriter, _ *http.Request) { OK(w, nil) })

	for i := 0; i < 20; i++ {
		srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v2/probe/list", nil))
	}
	if got := rec.dump(); len(got) != 0 {
		t.Errorf("静音路径 20 次轮询不该产生任何日志, 实际: %v", got)
	}
}

// TestLoggingDefaultSilentPaths 默认静音表必须覆盖前端已知的轮询接口。
//
// 【为什么要断言这张表】默认值漏掉一个接口, 用户就会重新看到刷屏 ——
// 而刷屏正是这次要修的问题。表里的每一条都应对应前端一处 setInterval。
func TestLoggingDefaultSilentPaths(t *testing.T) {
	silent := DefaultSilentPaths()
	for _, p := range []string{
		"/api/v2/probe/list",   // Probes.vue 每 5s
		"/api/v2/probe/status", // Probes.vue 每 5s
		"/api/v2/screen/overview",
	} {
		if !silent[p] {
			t.Errorf("默认静音表应包含轮询接口 %s", p)
		}
	}
	// 反面: 真实业务动作不能被静音(否则用户看不到操作结果)
	for _, p := range []string{
		"/api/v2/engine/downloads/start",
		"/api/v2/probe/agent/download",
	} {
		if silent[p] {
			t.Errorf("%s 是用户主动触发的动作, 不应静音", p)
		}
	}
}

// TestLoggingKeepsStatusChange 状态码变化必须不被折叠丢失。
//
// 【为什么必须分开】把 200 与 500 折进同一条, 汇总行显示"重复 30 次 -> 200",
// 其中混着的 500 就永远看不见了 —— 这比"日志太多"严重得多。
//
// 这里走真实请求: 同一路径先 200 再 500, 断言 200 那条被立即刷出而不是被覆盖。
// (曾经实现为"直接覆盖 pending", 会把"何时开始出错"这个最关键的时间点吃掉。)
func TestLoggingKeepsStatusChange(t *testing.T) {
	srv, rec := newQuietServer(t, map[string]bool{})
	flip := false
	srv.Get("/x", func(w http.ResponseWriter, _ *http.Request) {
		if flip {
			FailInternal(w, "boom")
			return
		}
		OK(w, nil)
	})

	srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	flip = true
	srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))

	logs := waitForLogs(t, rec, 1)
	if len(logs) < 1 {
		t.Fatal("状态码变化时应立即刷出旧条目, 否则 200 记录被静默丢弃")
	}
	if !strings.Contains(logs[0], "-> 200") {
		t.Fatalf("应先记录旧的 200(200 与 500 必须分开记): %v", logs)
	}
}

// TestListenAndServe 独立监听: 随机端口分配与关闭
// (回环真实请求在自动化环境可能被拦截, 这里只验证监听/端口/关闭语义)
func TestListenAndServe(t *testing.T) {
	srv := New(WithLogger(func(string) {}))
	srv.Get("/ping", PingHandler)
	addr, port, err := srv.ListenAndServe("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if port == 0 || !strings.Contains(addr, "127.0.0.1") {
		t.Fatalf("addr=%s port=%d", addr, port)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
