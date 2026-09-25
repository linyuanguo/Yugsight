package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/weakpass"
)

// installAuthCheckEngine 把测试引擎装进全局单例(绕过磁盘配置读取)。
//
// 为什么不写 settings.json: 根包用例共享 exe 同目录那一份 settings.json,
// 写它会污染其它用例(项目 settings_test.go 已为此专门加串行锁)。这里只测
// "装配层与接口的合规判定", 不需要真的走配置读取路径。
func installAuthCheckEngine(t *testing.T, cfg weakpass.Config) *weakpass.Engine {
	t.Helper()
	prevEng, prevCfg := authCheckEng, authCheckCfg
	authCheckOnce.Do(func() {}) // 标记单例已初始化, 后续 instanceAuthCheck 直接返回
	e := weakpass.New(cfg)
	e.SetAuditSink(func(weakpass.Attempt) {}) // 审计不写日志, 避免用例间噪声
	authCheckEng, authCheckCfg = e, AuthCheckConfig{Enabled: cfg.Enabled, Targets: cfg.Targets}
	authCheckMu.Lock()
	authCheckLast, authCheckRunning, authCheckCancel = nil, false, nil
	authCheckMu.Unlock()
	// 报告中心二期: 批次完成/中止会触发原始报告自动存档(走 v2DB())。
	// 不注入的话 v2DB 会懒开 exe 同目录真实库(dir=.\data), 污染开发目录。
	// 这里的 cleanup 注册在下方 authCheckStop 之前: LIFO 下 authCheckStop
	// 先执行(中止触发的存档同样落临时库), 再排空异步写入并还原注入 ——
	// 排空必须先于 TempDir 清理, 否则迟到的写入让 RemoveAll 目录非空失败。
	tmp, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	prevProvider := v2DBProvider
	v2DBProviderMu.Lock()
	v2DBProvider = func() *db.Database { return tmp }
	v2DBProviderMu.Unlock()
	t.Cleanup(func() {
		waitRawSaves()
		_ = tmp.Close()
		v2DBProviderMu.Lock()
		v2DBProvider = prevProvider
		v2DBProviderMu.Unlock()
	})
	// Once 保持"已初始化"状态并直接还原指针: 不重置 Once, 否则后续用例调用
	// instanceAuthCheck 会真的去读 exe 同目录 settings.json, 与其它用例抢文件。
	t.Cleanup(func() {
		authCheckStop()
		authCheckEng, authCheckCfg = prevEng, prevCfg
		authCheckMu.Lock()
		authCheckLast = nil
		authCheckMu.Unlock()
	})
	return e
}

// TestAuthCheckDisabledRefusesStart 守"默认关闭零影响"这条硬约束在接口层的表现:
// 未启用时 status 报 enabled=false, start 直接 400(不建连、不起后台任务)。
func TestAuthCheckDisabledRefusesStart(t *testing.T) {
	installAuthCheckEngine(t, weakpass.Config{})

	rec := httptest.NewRecorder()
	handleAuthCheckStatus(rec, httptest.NewRequest(http.MethodGet, "/api/authcheck/status", nil))
	var st map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("状态接口返回非 JSON: %v", err)
	}
	if st["enabled"] != false {
		t.Fatalf("未启用时 status.enabled 应为 false, 实际 %v", st["enabled"])
	}
	if _, ok := st["supported"]; !ok {
		t.Fatal("status 应带上支持的协议清单")
	}

	rec = httptest.NewRecorder()
	handleAuthCheckStart(rec, httptest.NewRequest(http.MethodPost, "/api/authcheck/start",
		strings.NewReader(`{"targets":[{"host":"192.168.1.10","port":6379,"service":"redis"}]}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未启用时 start 应返回 400, 实际 %d", rec.Code)
	}
	authCheckMu.Lock()
	running := authCheckRunning
	authCheckMu.Unlock()
	if running {
		t.Fatal("未启用时不得启动后台批次")
	}
}

// TestAuthCheckEmptyWhitelistRefuses 白名单为空必须拒绝执行(fail-closed)。
func TestAuthCheckEmptyWhitelistRefuses(t *testing.T) {
	installAuthCheckEngine(t, weakpass.Config{Enabled: true, Rate: 1000})
	rec := httptest.NewRecorder()
	handleAuthCheckStart(rec, httptest.NewRequest(http.MethodPost, "/api/authcheck/start",
		strings.NewReader(`{"targets":[{"host":"192.168.1.10","port":6379,"service":"redis"}]}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("白名单为空时 start 应返回 400, 实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "白名单") {
		t.Fatalf("拒绝原因应说明白名单问题, 实际: %s", rec.Body.String())
	}
}

// TestAuthCheckStartAndStop 接口层跑一个批次: 替身建连器立即失败(不触网),
// 断言结果落进 status, 且 stop 能中止。
func TestAuthCheckStartAndStop(t *testing.T) {
	e := installAuthCheckEngine(t, weakpass.Config{
		Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: 1000, MaxTry: 2, TimeoutMs: 200,
	})
	e.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, net.ErrClosed
	})

	rec := httptest.NewRecorder()
	handleAuthCheckStart(rec, httptest.NewRequest(http.MethodPost, "/api/authcheck/start",
		strings.NewReader(`{"targets":[
			{"host":"192.168.1.10","port":6379,"service":"redis"},
			{"host":"192.168.1.11","port":22,"service":"ssh"}]}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("start 应成功, 实际 %d: %s", rec.Code, rec.Body.String())
	}

	// 等批次结束(后台 goroutine, 轮询而非固定 sleep)
	deadline := time.Now().Add(3 * time.Second)
	for {
		authCheckMu.Lock()
		run := authCheckLast
		authCheckMu.Unlock()
		if run != nil && run.finished() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("批次未在预期时间内结束")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 结果字段由后台 goroutine 写, 必须经 snapshot 取副本读(直接读字段 = DATA RACE)
	authCheckMu.Lock()
	run := authCheckLast
	authCheckMu.Unlock()
	run = run.snapshot()
	if len(run.Results) != 2 {
		t.Fatalf("应有 2 个目标的结果, 实际 %d", len(run.Results))
	}
	// ssh 已由 weakpass/ssh.go 实现(纯标准库 SSH-2.0 + password 认证), 不再走"不支持"分支。
	// 这里守的是"别退回不支持"——若有人改动协议注册表把 ssh 移出支持列表, 此断言立刻失败。
	if run.Results[1].Unsupported {
		t.Fatal("ssh 已支持, 不应再标记为不支持")
	}
	if run.Results[0].Attempts != 2 {
		t.Fatalf("单目标尝试次数应受 MaxTry 约束为 2, 实际 %d", run.Results[0].Attempts)
	}

	// stop 在无批次执行时也应安全返回(不 panic、不谎报)
	rec = httptest.NewRecorder()
	handleAuthCheckStop(rec, httptest.NewRequest(http.MethodPost, "/api/authcheck/stop", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("stop 应返回 200, 实际 %d", rec.Code)
	}
}

// TestAuthCheckAuditLine 审计行的口径: 失败不写口令、仅有 err 时不得报"命中"。
func TestAuthCheckAuditLine(t *testing.T) {
	line := authCheckAuditLine(weakpass.Attempt{
		Target: "192.168.1.10:6379", Service: "redis", Err: "口令错误",
	})
	if strings.Contains(line, "命中") {
		t.Fatalf("失败尝试不得记为命中: %s", line)
	}
	hit := authCheckAuditLine(weakpass.Attempt{
		Target: "192.168.1.10:6379", Service: "redis", OK: true,
	})
	if !strings.Contains(hit, "空口令") {
		t.Fatalf("空口令命中应点明: %s", hit)
	}
}

// TestAuthCheckConfigWhitelist 白名单管理完整链路: 校验(去重) → 合并写
// settings.json(同节其它字段保留) → 引擎热生效(免重启) → status 回读。
func TestAuthCheckConfigWhitelist(t *testing.T) {
	withTempExeDir(t)
	// 预置 authcheck 节带"非 targets"字段: 守合并写 —— 白名单保存不得抹掉
	// 用户手写的 rate/maxTry/timeoutMs(整节替换是 settings.json 的已知坑)
	writeTestSettings(t, `{"authcheck":{"enabled":true,"rate":2.5,"maxTry":50,"timeoutMs":800}}`)
	e := installAuthCheckEngine(t, weakpass.Config{Enabled: true, Targets: []string{"10.0.0.0/8"}})

	rec := httptest.NewRecorder()
	handleAuthCheckConfig(rec, httptest.NewRequest(http.MethodPut, "/api/authcheck/config",
		strings.NewReader(`{"targets":["192.168.1.0/24","172.16.1.10","192.168.1.0/24"]}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应非 JSON: %v", err)
	}
	if c, _ := out["count"].(float64); c != 2 {
		t.Fatalf("重复条目应去重为 2, 实际 %v", out["count"])
	}

	// 引擎热生效: 旧目标失权, 新目标放行
	if e.Allowed("10.1.1.1") {
		t.Fatal("替换后旧白名单 10.0.0.0/8 不得继续放行")
	}
	if !e.Allowed("192.168.1.99") || !e.Allowed("172.16.1.10") {
		t.Fatal("新白名单应放行 192.168.1.99 与 172.16.1.10")
	}

	// 落盘: authcheck 节新 targets + 其它字段原样保留
	raw, err := os.ReadFile(settingsFilePath())
	if err != nil {
		t.Fatalf("读 settings.json 失败: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("settings.json 损坏: %v", err)
	}
	var ac map[string]any
	if err := json.Unmarshal(doc[secAuthCheck], &ac); err != nil {
		t.Fatalf("authcheck 节解析失败: %v", err)
	}
	targets, _ := ac["targets"].([]any)
	if len(targets) != 2 {
		t.Fatalf("落盘 targets 应为 2 条, 实际 %v", ac["targets"])
	}
	if ac["rate"] != 2.5 || ac["maxTry"] != float64(50) || ac["timeoutMs"] != float64(800) {
		t.Fatalf("合并写必须保留同节其它字段, 实际 %v", ac)
	}

	// status 接口回读新列表(前端依赖它渲染白名单区)
	rec = httptest.NewRecorder()
	handleAuthCheckStatus(rec, httptest.NewRequest(http.MethodGet, "/api/authcheck/status", nil))
	var st map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st["enabled"] != true {
		t.Fatalf("status.enabled 应保持 true, 实际 %v", st["enabled"])
	}
	if ts, _ := st["targets"].([]any); len(ts) != 2 {
		t.Fatalf("status 应回读 2 条白名单, 实际 %v", st["targets"])
	}
}

// TestAuthCheckConfigValidation 非法条目整体拒绝(400): 不写盘、不动引擎。
// "跳过坏条目继续写"会让用户以为改成功了而防线少一道 —— 必须整体失败。
func TestAuthCheckConfigValidation(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{}`)
	e := installAuthCheckEngine(t, weakpass.Config{Enabled: true, Targets: []string{"10.0.0.0/8"}})

	bad := []string{
		`{"targets":["192.168.1.*"]}`, // 通配写法: 宽泛到不可接受
		`{"targets":["not-an-ip"]}`,
		`{"targets":["192.168.1.0/24","10.0.0.256"]}`, // 一条坏, 整批拒
	}
	for _, body := range bad {
		rec := httptest.NewRecorder()
		handleAuthCheckConfig(rec, httptest.NewRequest(http.MethodPut, "/api/authcheck/config", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s 应 400, 实际 %d: %s", body, rec.Code, rec.Body.String())
		}
	}

	// 超量同样拒绝(防一次请求塞进巨量列表)
	big := make([]string, authCheckMaxTargets+1)
	for i := range big {
		big[i] = fmt.Sprintf(`"%d.0.0.0/8"`, i%256)
	}
	rec := httptest.NewRecorder()
	handleAuthCheckConfig(rec, httptest.NewRequest(http.MethodPut, "/api/authcheck/config",
		strings.NewReader(`{"targets":[`+strings.Join(big, ",")+`]}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超 %d 条应 400, 实际 %d", authCheckMaxTargets, rec.Code)
	}

	// 校验失败不得改变任何状态
	if !e.Allowed("10.1.1.1") {
		t.Fatal("校验失败后原白名单不得被改动")
	}
	raw, _ := os.ReadFile(settingsFilePath())
	if strings.Contains(string(raw), "targets") {
		t.Fatalf("校验失败不得写盘, 实际 settings.json: %s", raw)
	}
}

// TestAuthCheckDictRelativePath 相对路径字典按 exe 同目录解析。
func TestAuthCheckDictRelativePath(t *testing.T) {
	root := "C:" + string(filepath.Separator) // 跨平台构造绝对路径(C:\ 或 /... 视平台)
	exeDir := filepath.Join(root, "exe")
	got := (AuthCheckConfig{DictFile: "mydict.txt"}).toWeakpass(exeDir)
	if want := filepath.Join(exeDir, "mydict.txt"); got.DictFile != want {
		t.Fatalf("相对路径字典应解析到 exe 同目录, 实际 %q 期望 %q", got.DictFile, want)
	}
	abs := filepath.Join(root, "dicts", "d.txt")
	if got := (AuthCheckConfig{DictFile: abs}).toWeakpass(exeDir); got.DictFile != abs {
		t.Fatalf("绝对路径字典不应被改写, 实际 %q", got.DictFile)
	}
}
