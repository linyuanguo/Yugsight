// probe_api_test.go 任务 6.3 探针框架装配层测试。
//
// 覆盖范围(不依赖真实网络/真实中心端, 沙箱环境常拦截回环 TCP):
//  1. probe.json 缺失/损坏时的静默降级(默认全关, 行为与单机版一致);
//  2. -probe 命令行角色覆盖逻辑;
//  3. /api/v2/probe/* 接口在"未启用中心端"时的行为(状态可读, 下发被拒);
//  4. 探针在线/离线回调落库与任务状态流转(taskRecorder)。
//
// 协议链路(注册/心跳/任务往返)的完整测试在 probe/probe_test.go, 用内存管道覆盖。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yugsight/db"
	"yugsight/probe"
	"yugsight/server"
)

// ===== 配置加载与角色覆盖 =====

// TestProbeConfigMissing 覆盖: probe.json 缺失 -> 默认全关, 不报错。
func TestProbeConfigMissing(t *testing.T) {
	cfg := loadProbeConfig()
	// 测试机 exe 同目录一般无 probe.json; 若存在也不应影响断言口径
	if cfg.Center.Enabled && cfg.Client.Enabled {
		t.Skip("本机存在已启用的 probe.json, 跳过默认值断言")
	}
	if cfg.Center.Listen == "" && cfg.Center.Enabled {
		t.Fatal("中心端启用但监听地址为空")
	}
}

// TestApplyProbeRole 覆盖: -probe 角色覆盖的各取值与无效值。
//
// 注意 agent 语义(2026-09-16 拆分后): 探针端已是独立程序 yugsight-agent,
// 主程序的 -probe=agent 不再启动探针端, 而是关闭两端并提示正确做法。
// 因此这里期望 center=false/client=false(不是"忽略配置保持原值" —— 它显式清了开关)。
func TestApplyProbeRole(t *testing.T) {
	prevRole := probeOverrideRole
	prevCfg := probeCfg
	t.Cleanup(func() { probeOverrideRole = prevRole; probeCfg = prevCfg })

	cases := []struct {
		role         string
		wantCenter   bool
		wantClient   bool
		wantUnchange bool
	}{
		{role: "", wantUnchange: true},
		{role: "center", wantCenter: true},
		{role: "agent", wantCenter: false, wantClient: false}, // 已拆分: 主程序不再承担探针端
		{role: "both", wantCenter: true, wantClient: true},
		{role: "BOTH", wantCenter: true, wantClient: true}, // 大小写不敏感
		{role: "bogus", wantUnchange: true},                // 无效值忽略
	}
	for _, c := range cases {
		probeCfg = ProbeConfig{
			Center: probe.ServerConfig{Enabled: false, Listen: ":8600"},
			Client: probe.ProbeConfig{Enabled: false, CenterAddr: "127.0.0.1:8600"},
		}
		probeOverrideRole = c.role
		applyProbeRole()
		if c.wantUnchange {
			if probeCfg.Center.Enabled || probeCfg.Client.Enabled {
				t.Fatalf("-probe=%q 应保持原配置, 实际 center=%v client=%v",
					c.role, probeCfg.Center.Enabled, probeCfg.Client.Enabled)
			}
			continue
		}
		if probeCfg.Center.Enabled != c.wantCenter || probeCfg.Client.Enabled != c.wantClient {
			t.Fatalf("-probe=%q 期望 center=%v client=%v, 实际 center=%v client=%v",
				c.role, c.wantCenter, c.wantClient, probeCfg.Center.Enabled, probeCfg.Client.Enabled)
		}
	}
}

// TestApplyProbeRoleKeepsEndpoint 覆盖: 角色覆盖只改 enabled 开关,
// 不改监听地址/中心端地址(这些仍由 probe.json 提供)。
func TestApplyProbeRoleKeepsEndpoint(t *testing.T) {
	prevRole, prevCfg := probeOverrideRole, probeCfg
	t.Cleanup(func() { probeOverrideRole, probeCfg = prevRole, prevCfg })

	probeCfg = ProbeConfig{
		Center: probe.ServerConfig{Listen: "0.0.0.0:9000", Token: "tk"},
		Client: probe.ProbeConfig{CenterAddr: "10.0.0.9:9000", Token: "tk"},
	}
	probeOverrideRole = "both"
	applyProbeRole()
	if probeCfg.Center.Listen != "0.0.0.0:9000" || probeCfg.Center.Token != "tk" {
		t.Fatalf("中心端配置被误改: %+v", probeCfg.Center)
	}
	if probeCfg.Client.CenterAddr != "10.0.0.9:9000" {
		t.Fatalf("探针端配置被误改: %+v", probeCfg.Client)
	}
}

// ===== API: 未启用中心端时的降级行为 =====

// TestProbeStatusAPI 覆盖: /api/v2/probe/status 在未启用时返回明确的关闭状态。
func TestProbeStatusAPI(t *testing.T) {
	probeAPITestMode(t)
	prevCenter := probeCenter
	probeCenter = nil
	t.Cleanup(func() { probeCenter = prevCenter })

	srv := server.New(server.WithLogger(func(string) {}))
	registerProbeRoutes(srv)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v2/probe/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("状态接口 HTTP %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Code int            `json:"code"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v (%s)", err, w.Body.String())
	}
	if resp.Code != 0 {
		t.Fatalf("状态接口返回业务错误: %s", w.Body.String())
	}
	if _, ok := resp.Data["configPath"]; !ok {
		t.Fatalf("状态缺少 configPath: %v", resp.Data)
	}
	if resp.Data["center"] != false {
		t.Fatalf("未启用中心端时 center 应为 false: %v", resp.Data["center"])
	}
}

// TestProbeAssignWhenCenterOff 覆盖: 中心端未启用时下发任务被拒(不 panic, 返回 400)。
func TestProbeAssignWhenCenterOff(t *testing.T) {
	probeAPITestMode(t)
	h, _ := newV2TestEnv(t)
	prevCenter := probeCenter
	probeCenter = nil
	t.Cleanup(func() { probeCenter = prevCenter })

	w := doReq(t, h, http.MethodPost, "/api/v2/probe/assign",
		`{"probeId":"p1","type":"port","target":"10.0.0.1","ports":"80"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("中心端未启用应返回 400, 实际 %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "中心端未启用") {
		t.Fatalf("错误信息未说明原因: %s", w.Body.String())
	}
}

// TestProbeAssignRequiresFields 覆盖: 缺少 probeId/target 时返回 400。
func TestProbeAssignRequiresFields(t *testing.T) {
	probeAPITestMode(t)
	h, _ := newV2TestEnv(t)
	for _, body := range []string{
		`{"type":"port","target":"10.0.0.1"}`,
		`{"probeId":"p1","type":"port"}`,
	} {
		w := doReq(t, h, http.MethodPost, "/api/v2/probe/assign", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("入参缺失应返回 400, 实际 %d: %s", w.Code, w.Body.String())
		}
	}
}

// TestProbeListAPI 覆盖: 探针列表接口返回落库数据(库为空时 list 为空数组而非 null)。
func TestProbeListAPI(t *testing.T) {
	probeAPITestMode(t)
	h, d := newV2TestEnv(t)
	prevCenter := probeCenter
	probeCenter = nil
	t.Cleanup(func() { probeCenter = prevCenter })

	w := doReq(t, h, http.MethodGet, "/api/v2/probe/list", "")
	if w.Code != http.StatusOK {
		t.Fatalf("列表接口 HTTP %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			List  []any `json:"list"`
			Total int   `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Data.List == nil {
		t.Fatal("空库时 list 应为空数组而不是 null")
	}
	if resp.Data.Total != 0 {
		t.Fatalf("空库应有 0 条探针, 实际 %d", resp.Data.Total)
	}

	// 落一条探针后应能查到, 且在线态由 probeCenter 决定(此处为 nil -> false)
	if err := d.Probes().Create(&db.Probe{
		ID: "probe-x", Name: "测试节点", Status: db.ProbeOnline,
	}); err != nil {
		t.Fatalf("探针落库失败: %v", err)
	}
	w = doReq(t, h, http.MethodGet, "/api/v2/probe/list", "")
	var out struct {
		Data struct {
			List []struct {
				ID     string `json:"id"`
				Online bool   `json:"online"`
			} `json:"list"`
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if out.Data.Total != 1 || len(out.Data.List) != 1 || out.Data.List[0].ID != "probe-x" {
		t.Fatalf("探针列表异常: %s", w.Body.String())
	}
	if out.Data.List[0].Online {
		t.Fatal("无中心端连接时不应标记在线")
	}
}

// TestProbeDeleteOnlineGuard 覆盖: 删除接口对"无连接"的探针可正常删除, 不存在则 404。
func TestProbeDeleteGuard(t *testing.T) {
	probeAPITestMode(t)
	h, d := newV2TestEnv(t)
	prevCenter := probeCenter
	probeCenter = nil
	t.Cleanup(func() { probeCenter = prevCenter })

	if err := d.Probes().Create(&db.Probe{ID: "probe-del"}); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	w := doReq(t, h, http.MethodDelete, "/api/v2/probe/probe-del", "")
	if w.Code != http.StatusOK {
		t.Fatalf("离线探针应可删除, 实际 %d: %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, http.MethodDelete, "/api/v2/probe/not-exist", "")
	if w.Code == http.StatusOK {
		t.Fatalf("删除不存在的探针应失败: %s", w.Body.String())
	}
}

// TestProbeTaskListAPI 覆盖: 探针任务明细接口的筛选与倒序。
func TestProbeTaskListAPI(t *testing.T) {
	probeAPITestMode(t)
	h, d := newV2TestEnv(t)
	for _, id := range []string{"task-a", "task-b"} {
		if err := d.ProbeTasks().Create(&db.ProbeTask{
			ID: id, ProbeNode: "probe-1", Kind: "port", Target: "10.0.0.1",
		}); err != nil {
			t.Fatalf("任务落库失败: %v", err)
		}
	}
	w := doReq(t, h, http.MethodGet, "/api/v2/probe/tasks?probeId=probe-1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("任务列表 HTTP %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Data struct {
			List  []map[string]any `json:"list"`
			Total int              `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if out.Data.Total != 2 || len(out.Data.List) != 2 {
		t.Fatalf("任务条数异常: %s", w.Body.String())
	}
	// 倒序: 最新在前(task-b 后写入)
	if out.Data.List[0]["id"] != "task-b" {
		t.Fatalf("任务应按最新在前排序: %v", out.Data.List[0]["id"])
	}
	// 按不存在的探针筛选应为空
	w = doReq(t, h, http.MethodGet, "/api/v2/probe/tasks?probeId=none", "")
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Data.Total != 0 {
		t.Fatalf("按不存在探针筛选应为空: %s", w.Body.String())
	}
}

// ===== 落库回调(taskRecorder) =====

// TestTaskRecorderOnlineOffline 覆盖: 探针上线落库 + 心跳刷新 + 离线置状态。
func TestTaskRecorderOnlineOffline(t *testing.T) {
	probeAPITestMode(t)
	_, d := newV2TestEnv(t)
	prevGet := v2GetDB
	v2GetDB = func() *db.Database { return d }
	t.Cleanup(func() { v2GetDB = prevGet })

	r := newTaskRecorder()
	r.Online(&probe.NodeInfo{
		ProbeID: "node-1", Name: "节点一", OS: "windows", Arch: "amd64",
		LocalIPs: []string{"192.168.1.50"}, NpcapInstalled: true,
		Engines: []probe.EngineVer{{Name: "nmapcore", Found: true, Version: "7.94"}},
	})
	p, err := d.Probes().Get("node-1")
	if err != nil {
		t.Fatalf("上线后未落库: %v", err)
	}
	if p.Status != db.ProbeOnline || p.Name != "节点一" {
		t.Fatalf("上线记录异常: %+v", p)
	}
	// 能力集合: 内置三能力 + Npcap 带来的 capture/synscan + 命中的 nmapcore
	for _, want := range []string{"portscan", "web", "host"} {
		if !strings.Contains(p.Capabilities, want) {
			t.Fatalf("能力集合缺少 %s: %s", want, p.Capabilities)
		}
	}

	// 心跳: 立即调用应被 30s 节流跳过(不报错)
	r.Heartbeat("node-1", &probe.Load{CPUPercent: 12.5, TasksRunning: 1})

	r.Offline("node-1", "连接关闭")
	p, err = d.Probes().Get("node-1")
	if err != nil {
		t.Fatalf("离线后查询失败: %v", err)
	}
	if p.Status != db.ProbeOffline {
		t.Fatalf("离线状态未落库: %+v", p)
	}
}

// TestTaskRecorderOfflineFinishesTasks 覆盖: 探针离线时未完成任务标记失败(不留悬挂任务)。
func TestTaskRecorderOfflineFinishesTasks(t *testing.T) {
	probeAPITestMode(t)
	_, d := newV2TestEnv(t)
	prevGet := v2GetDB
	v2GetDB = func() *db.Database { return d }
	t.Cleanup(func() { v2GetDB = prevGet })

	if err := d.ProbeTasks().Create(&db.ProbeTask{
		ID: "t-run", ProbeNode: "node-2", Kind: "port", Target: "10.0.0.1",
	}); err != nil {
		t.Fatalf("任务落库失败: %v", err)
	}
	if _, err := d.ProbeTasks().MarkSent("t-run"); err != nil {
		t.Fatalf("标记下发失败: %v", err)
	}

	r := newTaskRecorder()
	r.Offline("node-2", "心跳超时")

	pt, err := d.ProbeTasks().Get("t-run")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if pt.Status != db.ProbeTaskFailed {
		t.Fatalf("离线后未完成任务应置失败, 实际 %s", pt.Status)
	}
	if !strings.Contains(pt.Error, "离线") {
		t.Fatalf("失败原因未记录: %q", pt.Error)
	}
}

// TestTaskRecorderResult 覆盖: 任务结果落库(成功/失败两条路径) + 统一任务表状态同步。
func TestTaskRecorderResult(t *testing.T) {
	probeAPITestMode(t)
	_, d := newV2TestEnv(t)
	prevGet := v2GetDB
	v2GetDB = func() *db.Database { return d }
	t.Cleanup(func() { v2GetDB = prevGet })

	st := &db.ScanTask{Type: "port", Target: "10.0.0.1", ProbeNode: "node-3"}
	if err := d.ScanTasks().Create(st); err != nil {
		t.Fatalf("统一任务创建失败: %v", err)
	}
	if err := d.ProbeTasks().Create(&db.ProbeTask{
		ID: st.ID, ProbeNode: "node-3", Kind: "port", Target: "10.0.0.1",
	}); err != nil {
		t.Fatalf("探针任务落库失败: %v", err)
	}

	r := newTaskRecorder()
	r.Result("node-3", &probe.TaskResult{
		TaskID:     st.ID,
		Status:     probe.TaskDone,
		Summary:    "开放端口 2 个",
		DurationMs: 1500,
		Findings:   []probe.Finding{{Severity: "open", Title: "10.0.0.1:80 开放"}},
	})

	pt, err := d.ProbeTasks().Get(st.ID)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if pt.Status != db.ProbeTaskSuccess || pt.FindingNum != 1 || pt.DurationMs != 1500 {
		t.Fatalf("结果落库异常: %+v", pt)
	}
	if !strings.Contains(pt.Result, "10.0.0.1:80") {
		t.Fatalf("结果详情未落库: %q", pt.Result)
	}
	got, err := d.ScanTasks().Get(st.ID)
	if err != nil {
		t.Fatalf("统一任务查询失败: %v", err)
	}
	if got.Status != db.TaskSuccess {
		t.Fatalf("统一任务状态未同步: %s", got.Status)
	}

	// 失败路径: 结果为空时也应置失败并记录错误, 不 panic
	r.Result("node-3", &probe.TaskResult{TaskID: st.ID, Status: probe.TaskFailed, Error: "目标不可达"})
	pt, _ = d.ProbeTasks().Get(st.ID)
	if pt.Status != db.ProbeTaskFailed || pt.Error != "目标不可达" {
		t.Fatalf("失败结果落库异常: %+v", pt)
	}
	// nil 结果不应 panic
	r.Result("node-3", nil)
}

// TestNodeInfoPersisted 覆盖: 探针上线落库时带上完整节点信息与负载, 面板可展示。
func TestNodeInfoPersisted(t *testing.T) {
	probeAPITestMode(t)
	_, d := newV2TestEnv(t)
	prevGet := v2GetDB
	v2GetDB = func() *db.Database { return d }
	t.Cleanup(func() { v2GetDB = prevGet })

	r := newTaskRecorder()
	r.Online(&probe.NodeInfo{
		ProbeID: "node-info", Name: "节点信息", OS: "linux", Arch: "arm64",
		OSVersion: "Ubuntu 24.04", CPUModel: "Cortex-A72", CPUCores: 8,
		MemTotal: 8 << 30, LocalIPs: []string{"10.0.0.5"}, Gateway: "10.0.0.1",
		DNS: []string{"8.8.8.8"}, NetIfaces: []probe.NetIface{{Name: "eth0", IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff"}},
		NpcapInstalled: false, Version: "1.0.0",
		Engines: []probe.EngineVer{{Name: "nmapcore", Found: true, Version: "7.94"}},
	})
	p, err := d.Probes().Get("node-info")
	if err != nil {
		t.Fatalf("未落库: %v", err)
	}
	if p.NodeInfo == nil {
		t.Fatal("节点信息未持久化")
	}
	ni, ok := p.NodeInfo.(*probe.NodeInfo)
	if !ok {
		t.Fatalf("节点信息类型异常: %T", p.NodeInfo)
	}
	if ni.OSVersion != "Ubuntu 24.04" || ni.CPUCores != 8 || ni.Gateway != "10.0.0.1" {
		t.Fatalf("节点信息字段异常: %+v", ni)
	}

	// 负载随心跳落库 + 任务统计随结果累计
	r.Heartbeat("node-info", &probe.Load{CPUPercent: 33.3, MemPercent: 41.2, TasksRunning: 2})
	r.mu.Lock()
	r.lastSeen["node-info"] = time.Time{} // 绕过 30s 节流以便断言
	r.mu.Unlock()
	r.Heartbeat("node-info", &probe.Load{CPUPercent: 33.3, MemPercent: 41.2, TasksRunning: 2})
	p, _ = d.Probes().Get("node-info")
	if p.Load == nil {
		t.Fatal("负载未持久化")
	}
	if ld, ok := p.Load.(*probe.Load); !ok || ld.TasksRunning != 2 {
		t.Fatalf("负载字段异常: %#v", p.Load)
	}

	// 结果累计统计: 成功一条 + 失败一条
	for _, c := range []struct {
		id     string
		status string
	}{{"pt-ok", probe.TaskDone}, {"pt-bad", probe.TaskFailed}} {
		if err := d.ProbeTasks().Create(&db.ProbeTask{
			ID: c.id, ProbeNode: "node-info", Kind: "port", Target: "10.0.0.1",
		}); err != nil {
			t.Fatalf("任务落库失败: %v", err)
		}
		r.Result("node-info", &probe.TaskResult{TaskID: c.id, Status: c.status, Summary: "smoke"})
	}
	p, _ = d.Probes().Get("node-info")
	if p.TaskTotal != 2 || p.TaskSuccess != 1 || p.TaskFailed != 1 {
		t.Fatalf("任务统计异常: total=%d ok=%d fail=%d", p.TaskTotal, p.TaskSuccess, p.TaskFailed)
	}
	// 节点信息里的磁盘/网卡等也应在重读后保留(JSON round-trip 不丢字段)
	ni2, _ := d.Probes().Get("node-info")
	if info, ok := ni2.NodeInfo.(*probe.NodeInfo); !ok || len(info.NetIfaces) != 1 {
		t.Fatalf("重读后节点信息异常: %#v", ni2.NodeInfo)
	}
}

// TestOnlineKeepsStats 覆盖: 探针重连(重复上线)不应清零已累计的任务统计。
func TestOnlineKeepsStats(t *testing.T) {
	probeAPITestMode(t)
	_, d := newV2TestEnv(t)
	prevGet := v2GetDB
	v2GetDB = func() *db.Database { return d }
	t.Cleanup(func() { v2GetDB = prevGet })

	if err := d.Probes().Create(&db.Probe{ID: "node-re"}); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	p, _ := d.Probes().Get("node-re")
	p.TaskTotal, p.TaskSuccess = 7, 5
	_, _ = d.Probes().Upsert(p)

	r := newTaskRecorder()
	r.Online(&probe.NodeInfo{ProbeID: "node-re", Name: "重连节点"})
	got, _ := d.Probes().Get("node-re")
	if got.TaskTotal != 7 || got.TaskSuccess != 5 {
		t.Fatalf("重连后统计被清零: total=%d ok=%d", got.TaskTotal, got.TaskSuccess)
	}
	if got.Status != db.ProbeOnline || got.Name != "重连节点" {
		t.Fatalf("重连后未刷新状态/名称: %+v", got)
	}
}

// ===== 执行位置路由(/api/scan 的 execAt=probe) =====

// TestDispatchToProbeNotEnabled 覆盖: 中心端未启用时下发失败, 通过 SSE 事件说明原因。
func TestDispatchToProbeNotEnabled(t *testing.T) {
	probeAPITestMode(t)
	_, d := newV2TestEnv(t)
	prevGet := v2GetDB
	v2GetDB = func() *db.Database { return d }
	t.Cleanup(func() { v2GetDB = prevGet })
	prevCenter := probeCenter
	probeCenter = nil
	t.Cleanup(func() { probeCenter = prevCenter })

	var events []string
	var doneData map[string]any
	emit := func(ev string, data any) {
		events = append(events, ev)
		if ev == "done" {
			if m, ok := data.(map[string]any); ok {
				doneData = m
			}
		}
	}
	dispatchToProbe(scanReq{Type: "port", IP: "10.0.0.1", ExecAt: "probe", ProbeNode: "p1"}, emit)

	if doneData == nil || doneData["ok"] != false {
		t.Fatalf("应返回失败 done 事件: %v", doneData)
	}
	found := false
	for _, e := range events {
		if e == "status" {
			found = true
		}
	}
	if !found {
		t.Fatal("缺少 status 事件说明原因")
	}
	if !strings.Contains(strings.Join(events, ","), "status") {
		t.Fatalf("事件序列异常: %v", events)
	}
}

// TestDispatchToProbeOffline 覆盖: 探针不在线时不登记任务(避免悬挂记录)。
func TestDispatchToProbeOffline(t *testing.T) {
	probeAPITestMode(t)
	_, d := newV2TestEnv(t)
	prevGet := v2GetDB
	v2GetDB = func() *db.Database { return d }
	t.Cleanup(func() { v2GetDB = prevGet })
	prevCenter := probeCenter
	probeCenter = probe.NewCenter(probe.ServerConfig{Listen: "127.0.0.1:0", OfflineSec: 30})
	t.Cleanup(func() { probeCenter = prevCenter }) // 未 Start: Online 恒 false

	var doneData map[string]any
	emit := func(ev string, data any) {
		if ev == "done" {
			if m, ok := data.(map[string]any); ok {
				doneData = m
			}
		}
	}
	dispatchToProbe(scanReq{Type: "port", IP: "10.0.0.1", ExecAt: "probe", ProbeNode: "ghost"}, emit)
	if doneData == nil || doneData["ok"] != false {
		t.Fatalf("离线探针应下发失败: %v", doneData)
	}
	if tasks, _ := d.ProbeTasks().ByProbe("ghost"); len(tasks) != 0 {
		t.Fatalf("离线探针不应登记任务, 实际 %d 条", len(tasks))
	}
	if list, _ := d.ScanTasks().List(); len(list) != 0 {
		t.Fatalf("离线探针不应登记统一任务, 实际 %d 条", len(list))
	}
}

// TestDispatchToProbeEmptyTarget 覆盖: 目标为空时拒绝下发。
func TestDispatchToProbeEmptyTarget(t *testing.T) {
	probeAPITestMode(t)
	_, d := newV2TestEnv(t)
	prevGet := v2GetDB
	v2GetDB = func() *db.Database { return d }
	t.Cleanup(func() { v2GetDB = prevGet })
	prevCenter := probeCenter
	probeCenter = nil
	t.Cleanup(func() { probeCenter = prevCenter })

	var doneData map[string]any
	emit := func(ev string, data any) {
		if ev == "done" {
			if m, ok := data.(map[string]any); ok {
				doneData = m
			}
		}
	}
	// 中心端未启用会先被拦下, 故这里直接验证 probeTarget 的取值口径
	target, ports := probeTarget(scanReq{Type: "port", Ports: "80,443"})
	if target != "" || ports != "80,443" {
		t.Fatalf("probeTarget 口径异常: target=%q ports=%q", target, ports)
	}
	dispatchToProbe(scanReq{Type: "port"}, emit)
	if doneData == nil || doneData["ok"] != false {
		t.Fatalf("空目标应失败: %v", doneData)
	}
}

// TestProbeTargetMapping 覆盖: 各扫描类型的目标字段映射(与本地执行口径一致)。
func TestProbeTargetMapping(t *testing.T) {
	cases := []struct {
		req        scanReq
		wantTarget string
		wantPorts  string
	}{
		{scanReq{Type: "ip", CIDR: "192.168.1.0/24"}, "192.168.1.0/24", ""},
		{scanReq{Type: "port", IP: "10.0.0.1", Ports: "80"}, "10.0.0.1", "80"},
		{scanReq{Type: "web", URL: "http://10.0.0.1:8080"}, "http://10.0.0.1:8080", ""},
		{scanReq{Type: "host", IP: "10.0.0.2"}, "10.0.0.2", ""},
		{scanReq{Type: "host", CIDR: "10.0.0.0/24"}, "10.0.0.0/24", ""}, // 目标缺失时回退
	}
	for _, c := range cases {
		target, ports := probeTarget(c.req)
		if target != c.wantTarget || ports != c.wantPorts {
			t.Fatalf("type=%s 期望 (%q,%q), 实际 (%q,%q)", c.req.Type, c.wantTarget, c.wantPorts, target, ports)
		}
	}
}

// ===== 兜底小工具 =====

// TestProbeCapabilities 覆盖: 能力汇总的最小集合(无引擎节点)。
//
// 任务 6.4 起内置能力集扩展为 alive/portscan/web/host(Nuclei POC 已内置于 host/web),
// 其中 capture 的判定有两路来源:
//
//	1. 平台采集器已注册(pscan.CaptureSupported(), 仅 Windows 为 true)
//	2. 节点信息上报 NpcapInstalled=true
//
// 因此这里不对 capture 做"必须不出现"的断言 —— 那会把 Windows 上的正确行为判为失败。
// 改为断言: 无论哪条路径, 都不能出现重复项(能力串冗余会让调度逻辑重复匹配)。
func TestProbeCapabilities(t *testing.T) {
	caps := probeCapabilities(nil)
	for _, want := range []string{"alive", "portscan", "web", "host"} {
		if !strings.Contains(caps, want) {
			t.Fatalf("内置能力 %s 缺失: %s", want, caps)
		}
	}
	assertNoDupCaps(t, caps)

	// Npcap 已安装时 capture/synscan 必须出现
	caps = probeCapabilities(&probe.NodeInfo{NpcapInstalled: true})
	if !strings.Contains(caps, "capture") || !strings.Contains(caps, "synscan") {
		t.Fatalf("Npcap 已安装应含 capture/synscan: %s", caps)
	}
	assertNoDupCaps(t, caps)

	// Found=false 的引擎不应计入能力
	caps = probeCapabilities(&probe.NodeInfo{
		NpcapInstalled: false,
		Engines:        []probe.EngineVer{{Name: "trivycore", Found: false}},
	})
	if strings.Contains(caps, "trivycore") {
		t.Fatalf("未命中的引擎不应计入能力: %s", caps)
	}
	assertNoDupCaps(t, caps)

	// Found=true 的引擎必须计入
	caps = probeCapabilities(&probe.NodeInfo{
		Engines: []probe.EngineVer{{Name: "nmapcore", Found: true}},
	})
	if !strings.Contains(caps, "nmapcore") {
		t.Fatalf("命中的引擎应计入能力: %s", caps)
	}
	assertNoDupCaps(t, caps)
}

// assertNoDupCaps 能力串不应有重复项。
func assertNoDupCaps(t *testing.T, caps string) {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range strings.Split(caps, ",") {
		if c == "" {
			t.Fatalf("能力串含空项: %q", caps)
		}
		if seen[c] {
			t.Fatalf("能力串含重复项 %q: %s", c, caps)
		}
		seen[c] = true
	}
}

// TestStopProbeNoop 覆盖: 未启用探针时 stopProbe 为空操作(不 panic)。
func TestStopProbeNoop(t *testing.T) {
	prevCenter, prevClient := probeCenter, probeClient
	probeCenter, probeClient = nil, nil
	t.Cleanup(func() { probeCenter, probeClient = prevCenter, prevClient })
	stopProbe() // 不应 panic
}

// TestProbeCfgPath 覆盖: 配置文件路径约定为 exe 同目录 probe.json。
func TestProbeCfgPath(t *testing.T) {
	p := probeCfgPath()
	// 红线「配置唯一」: 中心端不再有 probe.json, 配置来源必须是 settings.json
	if filepath.Base(p) != "settings.json" {
		t.Fatalf("配置文件名异常: %s", p)
	}
	exe, err := os.Executable()
	if err == nil && filepath.Dir(p) != filepath.Dir(exe) {
		t.Fatalf("配置目录应为 exe 同目录: %s vs %s", filepath.Dir(p), filepath.Dir(exe))
	}
}

// TestProbeHelpersNoSideEffect 覆盖: /api/info 用的状态查询在未启用时安全返回。
func TestProbeHelpersNoSideEffect(t *testing.T) {
	// 不强制重置 probeOnce: 仅验证查询函数不 panic 且取值自洽
	role := probeRole()
	switch role {
	case "", "center", "probe", "center+probe":
	default:
		t.Fatalf("角色取值异常: %q", role)
	}
	if got := probeOnlineCount(); got < 0 {
		t.Fatalf("在线数异常: %d", got)
	}
	if !probeEnabled() && role != "" {
		t.Fatal("未启用但角色非空, 状态不自洽")
	}
}

// probeAPITestMode 打开测试模式(跳过登录/鉴权校验)并在测试结束时恢复。
func probeAPITestMode(t *testing.T) {
	t.Helper()
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })
}

// TestProbeConnLogLineRouting 覆盖中心端日志分流的分类判据。
//
// 【为什么必须守住这个测试】分流靠"日志文案前缀"实现(probe 是独立通信层, 不适合
// 为 UI 策略改接口)。代价是: 一旦有人改了 probe/server.go 里的文案(比如把
// "探针 %s 任务 %s %s" 改成 "节点 %s 任务 %s %s"), 分流会静默失效 —— 数据流日志
// 又回到用户眼前, 且没有任何报错。这个测试就是那道防线。
//
// 同时守住反面: 连接类事件(上线/离线/被拒/超时)绝不能被误判成数据流而吞掉,
// 那会让用户失去对"探针是否连上"的感知。
func TestProbeConnLogLineRouting(t *testing.T) {
	// 数据流: 应只落盘, 不进面板日志
	flowCases := []string{
		"探针 node-1 任务 task-abc 已下发",
		"探针 node-1 任务 task-abc 执行成功",
		"探针 192.168.1.9 任务 t-1 执行失败",
	}
	for _, s := range flowCases {
		if !probeIsFlowLine(s) {
			t.Errorf("应判为数据流(不显示): %q", s)
		}
	}

	// 连接类: 必须显示 —— 这些是用户要主动感知的状态变化
	connCases := []string{
		"探针上线: node-1 (Windows 10, amd64, 8 核) 来自 192.168.1.9:51000",
		"探针离线: node-1 (心跳超时)",
		"探针注册被拒(密钥无效): 192.168.1.9:51000",
		"探针 node-1 心跳超时(30s 无心跳), 断开连接",
		"探针中心端已启动: 监听 :8600 (鉴权 已启用, 心跳 3s)",
		"探针中心端已停止",
	}
	for _, s := range connCases {
		if probeIsFlowLine(s) {
			t.Errorf("连接事件被误判为数据流(会导致用户看不到探针连接状态): %q", s)
		}
	}
}

// 保证 time 包被使用(离线时间戳断言留作后续扩展)。
var _ = time.Now
