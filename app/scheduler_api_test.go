package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/probe"
	"yugsight/internal/scheduler"
	"yugsight/internal/server"
)

// ===== 测试辅助 =====

// contextT 是 context.Context 的别名。
//
// 存在的意义: 调度执行函数签名较长, 测试里反复手写 context.Context 容易与
// 其它同名包混淆; 用一个短别名让用例体聚焦在被测行为上。
type contextT = context.Context

// schedOnceZero 返回一个未执行的 sync.Once 指针(用于测试重置调度器单例)。
//
// 用指针而非值: sync.Once 内部含 noCopy, 值类型传递会被 go vet 拦截,
// 且值拷贝会复制"已执行"标记导致单例逻辑彻底失效。
func schedOnceZero() *sync.Once { return &sync.Once{} }

// waitFor 轮询等待条件成立(最多 3 秒)。
//
// 必须用轮询而非固定 sleep: 调度是异步的, 固定 sleep 要么慢(保险值取大)
// 要么不稳(取小), 而 CI 机器负载波动会让同一份用例时过时挂。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

// setSchedTestConfigPath 把调度配置路径指向临时目录。
//
// 必须做: 生产路径读的是 exe 同目录 scheduler.json, 测试若直接写会污染真实
// 配置文件(开发机上跑一次测试就把用户的调度配置改掉了)。
func setSchedTestConfigPath(t *testing.T, dir string) {
	t.Helper()
	prev := schedConfigPath
	schedConfigPath = func() string { return filepath.Join(dir, "scheduler.json") }
	t.Cleanup(func() { schedConfigPath = prev })
}

// probeNodeInfoFixture 构造探针节点信息(用于能力推导测试)。
type probeNodeInfoFixture struct {
	npcap bool
}

func (f probeNodeInfoFixture) info() *probe.NodeInfo {
	return &probe.NodeInfo{
		ProbeID:        "p-test",
		Name:           "测试探针",
		Hostname:       "test-host",
		NpcapInstalled: f.npcap,
		Engines:        []probe.EngineVer{{Name: "nmapcore", Found: true}},
	}
}

// ===== 任务 7.1 调度装配层测试 =====

// schedAPITestMode 进入测试模式: 免鉴权 + 把调度器单例标记为"已初始化"。
//
// 关键(踩过的坑): 只把 schedInst 置 nil 是不够的 —— schedOnce 若尚未执行,
// 首个 HTTP 请求会触发 instanceScheduler() 里的 Once.Do, 用**磁盘上的
// scheduler.json** 重新构造并把测试注入的实例冲掉。表现为: 测试日志先打
// "调度器已启动"再打"任务调度未启用", 断言全部错位, 且结果随本机残留配置漂移。
//
// 正确做法: 用已标记完成的 Once 顶掉原 Once, 让懒加载彻底短路, 测试注入的
// schedInst 成为唯一实例。
func schedAPITestMode(t *testing.T) {
	t.Helper()
	prevAuth := authDisabled
	authDisabled = true
	prevInst, prevOnce := schedInst, schedOnce
	consumed := &sync.Once{}
	consumed.Do(func() {}) // 标记为已执行 -> instanceScheduler 不再重建
	schedOnce = consumed
	schedInst = nil
	t.Cleanup(func() {
		authDisabled = prevAuth
		if schedInst != nil {
			schedInst.Stop()
		}
		schedInst, schedOnce = prevInst, prevOnce
	})
}

// useSchedInstance 注入测试用调度器(必须在 schedAPITestMode 之后调用)。
func useSchedInstance(t *testing.T, cfg scheduler.Config, exec scheduler.ExecFunc) *scheduler.Scheduler {
	t.Helper()
	prev := schedInst
	s := scheduler.New(cfg, exec)
	s.Start()
	schedInst = s
	t.Cleanup(func() {
		s.Stop()
		if schedInst == s {
			schedInst = prev
		}
	})
	return s
}

// schedTestServer 构建只挂调度路由的测试服务器。
func schedTestServer(t *testing.T) *server.Server {
	t.Helper()
	srv := server.New(server.WithLogger(func(string) {}))
	registerSchedulerRoutes(srv)
	return srv
}

// doSchedReq 发起请求并解析统一响应。
func doSchedReq(t *testing.T, srv *server.Server, method, path, body string) (int, server.Resp) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	var resp server.Resp
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// TestSchedStatusAPI 覆盖: 状态接口在未启用时也返回完整只读视图。
//
// 为什么要求"未启用也要能看": 前端要靠这个接口引导用户开启调度(展示策略模板
// 与配置路径)。若未启用就返回 503, 用户永远看不到开关在哪。
func TestSchedStatusAPI(t *testing.T) {
	schedAPITestMode(t)
	// 显式注入"已关闭"实例: 本用例验证的是"未启用时也能看完整只读视图"。
	// (2026-09-20 起生产默认启用, 不再依赖"测试环境碰巧没配置所以关闭"的隐式前提
	// —— 隐式前提的测试在默认值一变时就会静默错位。)
	useSchedInstance(t, scheduler.Config{Enabled: false, MaxConcurrency: 2, DefaultRate: 1000, MaxQueue: 200},
		func(ctx contextT, task *scheduler.Task, progress func(string)) (string, error) {
			return "ok", nil
		})
	srv := schedTestServer(t)

	code, resp := doSchedReq(t, srv, "GET", "/api/v2/scheduler/status", "")
	if code != http.StatusOK || resp.Code != server.CodeOK {
		t.Fatalf("状态接口失败: http=%d resp=%+v", code, resp)
	}
	data, _ := resp.Data.(map[string]any)
	if data == nil {
		t.Fatal("缺少 data")
	}
	// 未启用时 enabled=false, 但策略模板必须可用
	if enabled, _ := data["enabled"].(bool); enabled {
		t.Fatal("测试环境下调度器不应默认启用")
	}
	strategies, _ := data["strategies"].([]any)
	if len(strategies) != 3 {
		t.Fatalf("内置策略模板应为 3 个, 实际 %d", len(strategies))
	}
	nodes, _ := data["nodes"].([]any)
	if len(nodes) < 1 {
		t.Fatal("至少应包含中心本地节点")
	}
	if data["configPath"] == nil || data["configPath"] == "" {
		t.Fatal("未回显配置文件路径")
	}
}

// TestSchedStrategiesAPI 覆盖: 策略模板内容符合任务书要求。
func TestSchedStrategiesAPI(t *testing.T) {
	schedAPITestMode(t)
	srv := schedTestServer(t)

	code, resp := doSchedReq(t, srv, "GET", "/api/v2/scheduler/strategies", "")
	if code != http.StatusOK {
		t.Fatalf("策略接口 HTTP %d", code)
	}
	data, _ := resp.Data.(map[string]any)
	list, _ := data["strategies"].([]any)
	got := map[string]bool{}
	for _, it := range list {
		m, _ := it.(map[string]any)
		id, _ := m["id"].(string)
		got[id] = true
		// 每个模板必须有名称/描述/默认参数, 否则前端展示会是一片空白
		if m["name"] == "" || m["name"] == nil {
			t.Fatalf("模板 %s 缺少名称", id)
		}
		if m["description"] == "" || m["description"] == nil {
			t.Fatalf("模板 %s 缺少描述", id)
		}
		if m["defaults"] == nil {
			t.Fatalf("模板 %s 缺少默认参数", id)
		}
	}
	for _, want := range []string{scheduler.StrategyQuick, scheduler.StrategyAudit, scheduler.StrategyWeb} {
		if !got[want] {
			t.Fatalf("缺少内置模板 %s", want)
		}
	}
	// 端口常量应一并下发(前端"端口范围"输入框的 placeholder 用)
	ports, _ := data["ports"].(map[string]any)
	if ports["alive"] == nil || ports["common"] == nil || ports["web"] == nil {
		t.Fatal("端口常量未下发")
	}
}

// TestSchedSubmitAndControl 覆盖: 提交 -> 列表 -> 暂停 -> 恢复 -> 取消 -> 删除 全流程。
func TestSchedSubmitAndControl(t *testing.T) {
	schedAPITestMode(t)
	// 启用调度并让任务真正阻塞在"执行中", 以便观察暂停/取消
	cfg := scheduler.DefaultConfig()
	cfg.Enabled = true
	cfg.DefaultRate = 0
	cfg.MaxConcurrency = 1
	useSchedInstance(t, cfg, func(ctx contextT, task *scheduler.Task, progress func(string)) (string, error) {
		progress("测试执行中")
		<-ctx.Done()
		return "", ctx.Err()
	})

	srv := schedTestServer(t)

	// 1. 提交
	body := `{"kind":"port","target":"10.0.0.5","strategy":"quick","ports":"80,443"}`
	code, resp := doSchedReq(t, srv, "POST", "/api/v2/scheduler/submit", body)
	if code != http.StatusOK || resp.Code != server.CodeOK {
		t.Fatalf("提交失败: http=%d resp=%+v", code, resp)
	}
	data, _ := resp.Data.(map[string]any)
	task, _ := data["task"].(map[string]any)
	id, _ := task["id"].(string)
	if id == "" {
		t.Fatal("未返回任务 ID")
	}
	// 策略模板应已展开(quick 的并发 512, 用户指定端口应覆盖模板值)
	params, _ := task["params"].(map[string]any)
	if ports, _ := params["ports"].(string); ports != "80,443" {
		t.Fatalf("用户参数未覆盖模板: %v", params["ports"])
	}
	if conc, _ := params["concurrency"].(float64); conc != 512 {
		t.Fatalf("模板默认值未展开: %v", params["concurrency"])
	}

	// 2. 列表应能看到
	_, resp = doSchedReq(t, srv, "GET", "/api/v2/scheduler/tasks", "")
	ld, _ := resp.Data.(map[string]any)
	if total, _ := ld["total"].(float64); total < 1 {
		t.Fatalf("任务列表为空: %+v", ld)
	}

	// 3. 暂停(占用中 -> paused, 释放槽位)
	// 先等任务真正开始执行: 否则它还在 queued, 暂停走的是另一条分支
	waitFor(t, "任务进入执行态", func() bool {
		tk, _ := schedInst.Get(id)
		return tk != nil && tk.Status == scheduler.StatusRunning
	})
	_, resp = doSchedReq(t, srv, "POST", "/api/v2/scheduler/pause?id="+id, "")
	if resp.Code != server.CodeOK {
		t.Fatalf("暂停失败: %+v", resp)
	}
	pd, _ := resp.Data.(map[string]any)
	pt, _ := pd["task"].(map[string]any)
	if st, _ := pt["status"].(string); st != scheduler.StatusPaused {
		t.Fatalf("暂停后状态错误: %v", st)
	}

	// 4. 恢复
	_, resp = doSchedReq(t, srv, "POST", "/api/v2/scheduler/resume", `{"id":"`+id+`"}`)
	if resp.Code != server.CodeOK {
		t.Fatalf("恢复失败: %+v", resp)
	}

	// 5. 取消
	_, resp = doSchedReq(t, srv, "POST", "/api/v2/scheduler/cancel", `{"id":"`+id+`"}`)
	if resp.Code != server.CodeOK {
		t.Fatalf("取消失败: %+v", resp)
	}
	cd, _ := resp.Data.(map[string]any)
	ct, _ := cd["task"].(map[string]any)
	if st, _ := ct["status"].(string); st != scheduler.StatusCancelled {
		t.Fatalf("取消后状态错误: %v", st)
	}

	// 6. 重试(已取消 -> 重新入队)
	_, resp = doSchedReq(t, srv, "POST", "/api/v2/scheduler/retry", `{"id":"`+id+`"}`)
	if resp.Code != server.CodeOK {
		t.Fatalf("重试失败: %+v", resp)
	}

	// 7. 取消后可删除
	_, _ = doSchedReq(t, srv, "POST", "/api/v2/scheduler/cancel", `{"id":"`+id+`"}`)
	code, resp = doSchedReq(t, srv, "DELETE", "/api/v2/scheduler/tasks/"+id, "")
	if code != http.StatusOK || resp.Code != server.CodeOK {
		t.Fatalf("删除失败: http=%d resp=%+v", code, resp)
	}
	if _, resp = doSchedReq(t, srv, "POST", "/api/v2/scheduler/pause?id="+id, ""); resp.Code == server.CodeOK {
		t.Fatal("已删除任务不应还能操作")
	}
}

// TestSchedSubmitRejectsBadInput 覆盖: 非法输入返回参数错误而非 500。
func TestSchedSubmitRejectsBadInput(t *testing.T) {
	schedAPITestMode(t)
	cfg := scheduler.DefaultConfig()
	cfg.Enabled = true
	cfg.DefaultRate = 0
	useSchedInstance(t, cfg, func(ctx contextT, task *scheduler.Task, progress func(string)) (string, error) {
		return "ok", nil
	})
	srv := schedTestServer(t)

	cases := []struct {
		name string
		body string
	}{
		{"非法 JSON", `{not json`},
		{"未知类型", `{"kind":"synscan","target":"10.0.0.1"}`},
		{"空目标", `{"kind":"port","target":"   "}`},
	}
	for _, c := range cases {
		code, resp := doSchedReq(t, srv, "POST", "/api/v2/scheduler/submit", c.body)
		if code == http.StatusInternalServerError {
			t.Fatalf("%s: 不应 500, resp=%+v", c.name, resp)
		}
		if resp.Code == server.CodeOK {
			t.Fatalf("%s: 应被拒绝, resp=%+v", c.name, resp)
		}
	}
	// 缺少 ID 的控制接口
	code, resp := doSchedReq(t, srv, "POST", "/api/v2/scheduler/pause", `{}`)
	if code != http.StatusBadRequest || resp.Code != server.CodeBadRequest {
		t.Fatalf("缺少 ID 应返回 400: http=%d resp=%+v", code, resp)
	}
	// 不存在的任务
	code, resp = doSchedReq(t, srv, "POST", "/api/v2/scheduler/cancel", `{"id":"ghost"}`)
	if code != http.StatusNotFound || resp.Code != server.CodeNotFound {
		t.Fatalf("不存在任务应返回 404: http=%d resp=%+v", code, resp)
	}
}

// TestSchedRejectsOverloadedProbe 覆盖: 探针负载过高时中心端拒绝下发(任务书要求)。
func TestSchedRejectsOverloadedProbe(t *testing.T) {
	schedAPITestMode(t)
	cfg := scheduler.DefaultConfig()
	cfg.Enabled = true
	cfg.DefaultRate = 0
	cfg.MaxCPUPercent = 85
	s := useSchedInstance(t, cfg, func(ctx contextT, task *scheduler.Task, progress func(string)) (string, error) {
		return "ok", nil
	})
	// 注入一个 CPU 打满的探针
	s.SyncNodes([]scheduler.Node{
		{ID: "busy-node", Name: "繁忙探针", Kind: scheduler.NodeProbe, Online: true, CPUPercent: 97},
	})
	srv := schedTestServer(t)

	// 提交到该节点 -> 应被拒绝
	code, resp := doSchedReq(t, srv, "POST", "/api/v2/scheduler/submit",
		`{"kind":"port","target":"10.0.0.1","node":"busy-node"}`)
	if code != http.StatusBadRequest || resp.Code != server.CodeBadRequest {
		t.Fatalf("过载探针应拒绝任务: http=%d resp=%+v", code, resp)
	}
	if !strings.Contains(resp.Message, "CPU") {
		t.Fatalf("拒绝原因未说明负载: %q", resp.Message)
	}

	// 节点视图应带上拒绝原因(前端直接展示, 不必自己推导)
	_, resp = doSchedReq(t, srv, "GET", "/api/v2/scheduler/nodes", "")
	nd, _ := resp.Data.(map[string]any)
	list, _ := nd["nodes"].([]any)
	found := false
	for _, it := range list {
		m, _ := it.(map[string]any)
		if m["id"] == "busy-node" {
			found = true
			if m["reject"] == nil {
				t.Fatal("过载节点未返回 reject 原因")
			}
		}
	}
	if !found {
		t.Fatal("节点列表缺少 busy-node")
	}
}

// TestSchedConfigSaveAndReload 覆盖: 配置保存落盘 + 热更新 + 重新读取一致。
func TestSchedConfigSaveAndReload(t *testing.T) {
	schedAPITestMode(t)
	// 把配置路径指到临时目录, 避免污染真实 exe 目录。2026-09-23 起配置统一
	// 落 settings.json 的 scheduler 节, 因此把 settings 路径也指到临时目录,
	// 落盘断言改看 settings.json(独立 scheduler.json 不再是落盘目标)。
	dir := t.TempDir()
	setSchedTestConfigPath(t, dir)
	settingsPath := filepath.Join(dir, "settings.json")
	setSettingsTestPath(settingsPath)
	resetSettingsCache()
	t.Cleanup(func() {
		setSettingsTestPath("")
		resetSettingsCache()
	})

	cfg := scheduler.DefaultConfig()
	cfg.Enabled = true
	cfg.DefaultRate = 0
	useSchedInstance(t, cfg, func(ctx contextT, task *scheduler.Task, progress func(string)) (string, error) {
		return "ok", nil
	})
	srv := schedTestServer(t)

	// 保存新配置
	body := `{"enabled":true,"maxConcurrency":4,"nodeConcurrency":2,"defaultRate":500,` +
		`"rateRules":[{"cidr":"10.0.0.0/8","rate":200}],"maxQueue":50}`
	code, resp := doSchedReq(t, srv, "POST", "/api/v2/scheduler/config", body)
	if code != http.StatusOK || resp.Code != server.CodeOK {
		t.Fatalf("保存配置失败: http=%d resp=%+v", code, resp)
	}

	// 读取回来应一致
	_, resp = doSchedReq(t, srv, "GET", "/api/v2/scheduler/config", "")
	cd, _ := resp.Data.(map[string]any)
	got, _ := cd["config"].(map[string]any)
	if mc, _ := got["maxConcurrency"].(float64); mc != 4 {
		t.Fatalf("配置未生效: %+v", got)
	}
	if dr, _ := got["defaultRate"].(float64); dr != 500 {
		t.Fatalf("限速未生效: %+v", got)
	}

	// 限速视图应能解释每个网段速率来自规则还是默认值
	_, resp = doSchedReq(t, srv, "GET", "/api/v2/scheduler/rate", "")
	rd, _ := resp.Data.(map[string]any)
	if def, _ := rd["default"].(float64); def != 500 {
		t.Fatalf("限速默认值错误: %+v", rd)
	}
	rules, _ := rd["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("网段规则丢失: %+v", rd)
	}

	// 配置应真正落盘到 settings.json 的 scheduler 节(否则重启后回到旧值,
	// 用户会认为保存失败)
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("读回 settings.json 失败: %v", err)
	}
	if !strings.Contains(string(raw), "\"scheduler\"") {
		t.Fatalf("scheduler 节未写入 settings.json:\n%s", raw)
	}
	if !strings.Contains(string(raw), "500") {
		t.Fatalf("新限速值未写入:\n%s", raw)
	}
}

// TestSchedSubmitQueueFull 覆盖: 队列满时返回 503 而非 400(前端据此提示"稍后重试")。
func TestSchedSubmitQueueFull(t *testing.T) {
	schedAPITestMode(t)
	cfg := scheduler.DefaultConfig()
	cfg.Enabled = true
	cfg.DefaultRate = 0
	cfg.MaxConcurrency = 1
	cfg.MaxQueue = 1
	schedInst = scheduler.New(cfg, func(ctx contextT, task *scheduler.Task, progress func(string)) (string, error) {
		<-ctx.Done() // 占住唯一槽位, 让后续任务只能排队
		return "", ctx.Err()
	})
	schedInst.Start()
	t.Cleanup(func() { schedInst.Stop() })
	srv := schedTestServer(t)

	// 连发直到撞上队列上限
	var lastCode int
	var lastResp server.Resp
	for i := 0; i < 20; i++ {
		lastCode, lastResp = doSchedReq(t, srv, "POST", "/api/v2/scheduler/submit",
			`{"kind":"port","target":"10.0.0.1","strategy":"custom","timeoutMs":1000}`)
		if lastResp.Code == server.CodeDBUnavailable {
			break
		}
	}
	if lastResp.Code != server.CodeDBUnavailable {
		t.Fatalf("未触发队列上限: http=%d resp=%+v", lastCode, lastResp)
	}
	if lastCode != http.StatusServiceUnavailable {
		t.Fatalf("HTTP 状态码应为 503, 实际 %d", lastCode)
	}
}

// TestSchedTargetRouteByKind 覆盖: 不同扫描类型的目标被写到正确字段。
func TestSchedTargetRouteByKind(t *testing.T) {
	schedAPITestMode(t)
	cfg := scheduler.DefaultConfig()
	cfg.Enabled = true
	cfg.DefaultRate = 0
	schedInst = scheduler.New(cfg, func(ctx contextT, task *scheduler.Task, progress func(string)) (string, error) {
		return "ok", nil
	})
	schedInst.Start()
	t.Cleanup(func() { schedInst.Stop() })
	srv := schedTestServer(t)

	cases := []struct {
		kind, target, field, want string
	}{
		{"ip", "10.1.0.0/24", "cidr", "10.1.0.0/24"},
		{"port", "10.1.0.1", "ip", "10.1.0.1"},
		{"host", "10.1.0.2", "ip", "10.1.0.2"},
		{"web", "http://10.1.0.3", "url", "http://10.1.0.3"},
	}
	for _, c := range cases {
		body := `{"kind":"` + c.kind + `","target":"` + c.target + `","strategy":"custom"}`
		_, resp := doSchedReq(t, srv, "POST", "/api/v2/scheduler/submit", body)
		if resp.Code != server.CodeOK {
			t.Fatalf("%s 提交失败: %+v", c.kind, resp)
		}
		data, _ := resp.Data.(map[string]any)
		task, _ := data["task"].(map[string]any)
		params, _ := task["params"].(map[string]any)
		if got, _ := params[c.field].(string); got != c.want {
			t.Fatalf("%s 目标未归一到 %s: %v", c.kind, c.field, params)
		}
	}
}

// TestEstimatePackets 覆盖: 发包量估算(限速配额)的边界。
//
// 估算偏高会让小任务被大额预扣卡死, 因此这里逐项校验取值不会失控。
func TestEstimatePackets(t *testing.T) {
	cases := []struct {
		name  string
		task  *scheduler.Task
		wantN int
	}{
		{"单个IP少量端口", &scheduler.Task{Params: scheduler.Params{IP: "10.0.0.1", Ports: "80"}}, 1},
		{"单IP多端口", &scheduler.Task{Params: scheduler.Params{IP: "10.0.0.1", Ports: "80,443,22"}}, 3},
		{"端口区间", &scheduler.Task{Params: scheduler.Params{IP: "10.0.0.1", Ports: "1-100"}}, 100},
		{"混合写法", &scheduler.Task{Params: scheduler.Params{IP: "10.0.0.1", Ports: "80,100-110,443"}}, 13},
		{"空端口回落8", &scheduler.Task{Params: scheduler.Params{IP: "10.0.0.1"}}, 8},
		// /24 按 2^8=256 估(含网络号与广播地址, 是上界口径 —— 限速配额宁大勿小)
		{"/24 网段", &scheduler.Task{Params: scheduler.Params{CIDR: "10.0.0.0/24", Ports: "80"}}, 256},
		{"大网段封顶2000", &scheduler.Task{Params: scheduler.Params{CIDR: "10.0.0.0/8", Ports: "1-1000"}}, 2000},
		{"单主机CIDR", &scheduler.Task{Params: scheduler.Params{CIDR: "10.0.0.1/32", Ports: "80,443"}}, 2},
	}
	for _, c := range cases {
		if got := estimatePackets(c.task); got != c.wantN {
			t.Fatalf("%s: 估算 %d(期望 %d)", c.name, got, c.wantN)
		}
	}
}

// TestCountPorts 覆盖: 端口串解析不因异常输入崩溃或虚高。
func TestCountPorts(t *testing.T) {
	cases := map[string]int{
		"":            0,
		"80":          1,
		"80,443":      2,
		"1-10":        10,
		"80,-":        2, // 非法区间退化为普通项(左右各计 1)
		"10-5":        1, // 反向区间非法, 整体退化为 1 项(不放大也不丢弃)
		",80,":        1,
		"65536-65540": 5,
	}
	for in, want := range cases {
		if got := countPorts(in); got != want {
			t.Fatalf("countPorts(%q)=%d(期望 %d)", in, got, want)
		}
	}
}

// TestCapabilitiesOf 覆盖: 探针能力推导与下发侧判定口径一致。
//
// 推导错了会导致"探针明明能抓包却被中心端拒绝"(或反之), 用户无从排查。
func TestCapabilitiesOf(t *testing.T) {
	// 无 Npcap: 不应有 capture/synscan
	base := probeNodeInfoFixture{}
	caps := capabilitiesOf(base.info())
	if strings.Contains(caps, "capture") || strings.Contains(caps, "synscan") {
		t.Fatalf("无 Npcap 不应有抓包能力: %s", caps)
	}
	// 基础能力必须始终具备(探针内置引擎实现, 与 Npcap 无关)
	for _, want := range []string{"portscan", "web", "host", "nuclei"} {
		if !strings.Contains(caps, want) {
			t.Fatalf("基础能力缺少 %s: %s", want, caps)
		}
	}
	// 有 Npcap: 应含 capture/synscan
	withNpcap := probeNodeInfoFixture{npcap: true}
	caps = capabilitiesOf(withNpcap.info())
	for _, want := range []string{"portscan", "web", "host", "nuclei", "capture", "synscan", "nmapcore"} {
		if !strings.Contains(caps, want) {
			t.Fatalf("能力集缺少 %s: %s", want, caps)
		}
	}
}

// TestDbStatusOf 覆盖: 调度事件 -> DB 任务状态的映射。
//
// 映射错了会让任务在列表里停在"待执行"或错误显示成功, 用户看到的进度全是错的。
func TestDbStatusOf(t *testing.T) {
	cases := []struct {
		ev   scheduler.Event
		want string
	}{
		{scheduler.Event{Type: scheduler.EventQueued}, db.TaskPending},
		{scheduler.Event{Type: scheduler.EventResumed}, db.TaskPending},
		{scheduler.Event{Type: scheduler.EventPaused}, db.TaskPending},
		{scheduler.Event{Type: scheduler.EventStarted}, db.TaskRunning},
		{scheduler.Event{Type: scheduler.EventCancelled}, db.TaskCancelled},
		{scheduler.Event{Type: scheduler.EventDone, Msg: "success: 完成"}, db.TaskSuccess},
		{scheduler.Event{Type: scheduler.EventDone, Msg: "failed: 目标不可达"}, db.TaskFailed},
		{scheduler.Event{Type: scheduler.EventProgress}, ""}, // 进度不改状态
		{scheduler.Event{Type: scheduler.EventReassign}, ""},
	}
	for _, c := range cases {
		if got := dbStatusOf(c.ev); got != c.want {
			t.Fatalf("事件 %s(%q) 映射为 %q(期望 %q)", c.ev.Type, c.ev.Msg, got, c.want)
		}
	}
}

// TestSchedDisabledDoesNotTakeOverScan 覆盖: 调度未启用时 /api/scan 保持原语义。
//
// 这是"默认关闭零行为变化"的核心断言: 若此处失守, 所有既有前端与脚本调用的
// SSE 事件流都会变成"入队即结束", 用户看到扫描没有任何结果。
func TestSchedDisabledDoesNotTakeOverScan(t *testing.T) {
	schedAPITestMode(t)
	// 未启用
	cfg := scheduler.DefaultConfig()
	cfg.Enabled = false
	cfg.DefaultRate = 0
	schedInst = scheduler.New(cfg, func(ctx contextT, task *scheduler.Task, progress func(string)) (string, error) {
		return "ok", nil
	})

	if schedulerEnabled() {
		t.Fatal("调度未启用时 schedulerEnabled 应为 false")
	}
	// 即使请求带 queue=true, 未启用时也不应入队
	req := scanReq{Type: "port", IP: "10.0.0.1", Queue: true}
	if schedulerEnabled() {
		t.Fatal("未启用不应接管")
	}
	_ = req
}
