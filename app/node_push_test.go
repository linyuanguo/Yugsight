package main

// node_push_test.go 节点告警推送闭环测试(2026-09-28)。
//
// 覆盖: 时间窗/免打扰判定(纯函数) / 消息模板三平台(离线断言) /
// 目标 CRUD 与规则保存(HTTP) / 告警→推送→日志全链路(假 Webhook, 离线)。
// Webhook 用 httptest 替身, 全程不发真实外连; 推送异步用轮询等待(无固定 sleep)。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yugsight/internal/collect"
	"yugsight/internal/db"
)

// ===== 测试环境: 根 mux + 注入临时库 + 临时 settings 路径 =====

func newPushTestEnv(t *testing.T) (*http.ServeMux, *db.Database) {
	t.Helper()
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })
	prevGet := v2GetDB
	prevProvider := v2DBProvider
	t.Cleanup(func() { v2GetDB = prevGet; v2DBProvider = prevProvider })

	d, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	v2GetDB = func() *db.Database { return d }
	v2DBProviderMu.Lock()
	v2DBProvider = func() *db.Database { return d }
	v2DBProviderMu.Unlock()

	dir := t.TempDir()
	setSettingsTestPath(filepath.Join(dir, "settings.json"))
	t.Cleanup(func() { setSettingsTestPath(""); resetSettingsCache() })

	mux := http.NewServeMux()
	registerNodePushRoutes(mux)
	return mux, d
}

// writeNodePushSettings 直接写临时 settings.json 的 nodepush 节(测试预置配置)。
func writeNodePushSettings(t *testing.T, cfg nodePushConfig) {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	doc := `{"nodepush":` + string(b) + `}`
	if err := os.WriteFile(settingsFilePath(), []byte(doc), 0o644); err != nil {
		t.Fatalf("写 settings: %v", err)
	}
	resetSettingsCache()
}

// setTestUIURL 测试注入 UI 地址(详情链接断言用)。
func setTestUIURL(t *testing.T, u string) {
	t.Helper()
	uiURLMu.Lock()
	uiURLValue = u
	uiURLMu.Unlock()
	t.Cleanup(func() {
		uiURLMu.Lock()
		uiURLValue = ""
		uiURLMu.Unlock()
	})
}

func pushDoReq(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// 轮询等待复用 scheduler_api_test.go 的 waitFor(3s 固定超时; 本用例延迟=0, 毫秒级完成)。

// webhookRec 假 Webhook(线程安全: 推送在 AfterFunc goroutine 里发)。
type webhookRec struct {
	mu   sync.Mutex
	fail bool // fail=true 时回 errcode=93000
	body string
	n    int
}

func (r *webhookRec) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.body = string(b)
		r.n++
		fail := r.fail
		r.mu.Unlock()
		if fail {
			_, _ = w.Write([]byte(`{"errcode":93000,"errmsg":"invalid webhook key"}`))
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}
}

func (r *webhookRec) snapshot() (string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body, r.n
}

func (r *webhookRec) setFail(f bool) {
	r.mu.Lock()
	r.fail = f
	r.mu.Unlock()
}

func (r *webhookRec) reset() {
	r.mu.Lock()
	r.body = ""
	r.n = 0
	r.mu.Unlock()
}

// ===== 时间窗 / 免打扰判定 =====

func TestPushTimeWindow(t *testing.T) {
	at := func(h, m int) time.Time {
		return time.Date(2026, 9, 28, h, m, 0, 0, time.Local)
	}

	// 工作时段 09:00-18:00
	r := defaultPushRules()
	r.Window = "work"
	r.WorkStart, r.WorkEnd = "09:00", "18:00"
	if !inPushWindow(r, at(10, 0)) {
		t.Fatal("10:00 应在工作时段内")
	}
	if inPushWindow(r, at(20, 0)) {
		t.Fatal("20:00 不应在工作时段内")
	}

	// 自定义跨天 21:00-08:00
	r.Window = "custom"
	r.CustomStart, r.CustomEnd = "21:00", "08:00"
	if !inPushWindow(r, at(23, 0)) || !inPushWindow(r, at(7, 0)) {
		t.Fatal("跨天窗口: 23:00 与 07:00 都应在窗内")
	}
	if inPushWindow(r, at(12, 0)) {
		t.Fatal("跨天窗口: 12:00 不应在窗内")
	}

	// 时间解析失败 = 全天(不误伤)
	r.CustomStart = "9:000"
	if !inPushWindow(r, at(12, 0)) {
		t.Fatal("非法时间应视为全天")
	}

	// 免打扰补发: 22:00-08:00
	cases := []struct {
		now time.Time
		want string // "now" = 原样; 否则为 "HH:MM"+偏移天数
	}{
		{at(23, 0), "2026-09-29 08:00"}, // 晚段 → 次日早段结束
		{at(7, 0), "2026-09-28 08:00"},  // 早段 → 当天结束
		{at(12, 0), "now"},              // 窗外 → 不延迟
	}
	for _, c := range cases {
		got := nextOutsideDnd(c.now, "22:00", "08:00")
		want := c.want
		if want == "now" {
			want = c.now.Format("2006-01-02 15:04")
		}
		if got.Format("2006-01-02 15:04") != want {
			t.Fatalf("nextOutsideDnd(%s) = %s, 期望 %s", c.now, got, want)
		}
	}
}

// ===== 消息模板(三平台 × 三级卡片色) =====

func TestBuildPushBody(t *testing.T) {
	setTestUIURL(t, "http://192.168.1.10:8420")
	a := &db.NodeAlert{
		ID: "na-t1-1-x", Device: "核心交换机A", IP: "172.16.199.1",
		Level: "critical", Content: "CPU 使用率 98% 超过阈值 90%",
		At: time.Date(2026, 9, 28, 10, 0, 0, 0, time.Local),
	}
	tgt := pushTarget{ID: "pt-1", Name: "群", Type: "wecom", Webhook: "http://127.0.0.1:1/hook"}

	mustContain := func(t *testing.T, s string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(s, w) {
				t.Fatalf("消息缺少 %q:\n%s", w, s)
			}
		}
	}

	// 企业微信: 五要素 + 详情链接
	body, err := buildPushBody(tgt, a)
	if err != nil {
		t.Fatalf("wecom: %v", err)
	}
	var wecom map[string]any
	_ = json.Unmarshal(body, &wecom)
	md := wecom["markdown"].(map[string]any)["content"].(string)
	mustContain(t, md, "【紧急告警】", "核心交换机A (172.16.199.1)", "CPU 使用率 98% 超过阈值 90%",
		"2026-09-28 10:00:00", "alertId=na-t1-1-x")

	// 钉钉: 红色十六进制色(json.Marshal 会把 < 转义成 \u003c, 必须解包后断言)
	tgt.Type = "dingtalk"
	body, err = buildPushBody(tgt, a)
	if err != nil {
		t.Fatalf("dingtalk: %v", err)
	}
	var dd map[string]any
	if err := json.Unmarshal(body, &dd); err != nil {
		t.Fatalf("dingtalk decode: %v", err)
	}
	ddText := dd["markdown"].(map[string]any)["text"].(string)
	if !strings.Contains(ddText, `<font color="#FF5252">`) {
		t.Fatalf("钉钉紧急级别应为红色: %s", ddText)
	}

	// 飞书: 卡片模板色 红/橙/蓝 对应 紧急/重要/提示
	tgt.Type = "feishu"
	checkFeishu := func(level, color string) {
		t.Helper()
		a2 := *a
		a2.Level = level
		b, err := buildPushBody(tgt, &a2)
		if err != nil {
			t.Fatalf("feishu %s: %v", level, err)
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		card := m["card"].(map[string]any)
		got := card["header"].(map[string]any)["template"].(string)
		if got != color {
			t.Fatalf("feishu %s 卡片色 = %s, 期望 %s", level, got, color)
		}
	}
	checkFeishu("critical", "red")
	checkFeishu("warning", "orange")
	checkFeishu("info", "blue")

	// 未知类型 → 错误(不静默吞)
	tgt.Type = "slack"
	if _, err := buildPushBody(tgt, a); err == nil {
		t.Fatal("未知推送类型应报错")
	}
}

// ===== 目标 CRUD + 规则保存 =====

func TestPushTargetCRUD(t *testing.T) {
	mux, _ := newPushTestEnv(t)

	// 创建: 合法
	w := pushDoReq(t, mux, "POST", "/api/node/push/target",
		`{"name":"安全运营群","type":"wecom","webhook":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc","note":"主群","enabled":true}`)
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	// 响应体是 Resp 信封, data 里才是 Target
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("create resp decode: %v", err)
	}
	var created pushTarget
	if err := json.Unmarshal(env.Data, &created); err != nil {
		t.Fatalf("create data decode: %v", err)
	}
	if created.ID == "" {
		t.Fatal("创建后应有后端生成的 ID")
	}

	// 创建: 非法(非 http 协议 / 未知类型 / 空名称)
	if w := pushDoReq(t, mux, "POST", "/api/node/push/target",
		`{"name":"x","type":"wecom","webhook":"ftp://1.2.3.4/hook"}`); w.Code != 400 {
		t.Fatalf("非法 Webhook 应 400: %d", w.Code)
	}
	if w := pushDoReq(t, mux, "POST", "/api/node/push/target",
		`{"name":"x","type":"slack","webhook":"http://1.2.3.4/hook"}`); w.Code != 400 {
		t.Fatalf("未知类型应 400: %d", w.Code)
	}
	if w := pushDoReq(t, mux, "POST", "/api/node/push/target",
		`{"name":"  ","type":"wecom","webhook":"http://1.2.3.4/hook"}`); w.Code != 400 {
		t.Fatalf("空名称应 400: %d", w.Code)
	}

	// 列表: 1 条
	w = pushDoReq(t, mux, "GET", "/api/node/push/targets", "")
	if !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("列表应 1 条: %s", w.Body.String())
	}

	// 更新: 改名
	w = pushDoReq(t, mux, "PUT", "/api/node/push/target/"+created.ID,
		`{"name":"安全运营群-改","type":"wecom","webhook":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc","enabled":true}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "安全运营群-改") {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	// 更新: 不存在
	if w := pushDoReq(t, mux, "PUT", "/api/node/push/target/pt-none",
		`{"name":"x","type":"wecom","webhook":"http://1.2.3.4/hook"}`); w.Code != 404 {
		t.Fatalf("更新不存在应 404: %d", w.Code)
	}

	// 级联清理: 规则先关联该目标, 删目标后关联应被清除
	pushDoReq(t, mux, "PUT", "/api/node/push/rules",
		`{"levels":["critical"],"delaySec":0,"window":"all","workStart":"09:00","workEnd":"18:00","customStart":"09:00","customEnd":"18:00","dnd":false,"dndStart":"22:00","dndEnd":"08:00","targetIds":["`+created.ID+`"]}`)
	w = pushDoReq(t, mux, "DELETE", "/api/node/push/target/"+created.ID, "")
	if w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	w = pushDoReq(t, mux, "GET", "/api/node/push/rules", "")
	if strings.Contains(w.Body.String(), created.ID) {
		t.Fatalf("删目标后规则关联应被级联清除: %s", w.Body.String())
	}
}

func TestPushRulesSave(t *testing.T) {
	mux, _ := newPushTestEnv(t)

	// 未保存 = 默认值(与前端 defaultRules 同口径)
	w := pushDoReq(t, mux, "GET", "/api/node/push/rules", "")
	if !strings.Contains(w.Body.String(), `"delaySec":30`) ||
		!strings.Contains(w.Body.String(), `"window":"all"`) {
		t.Fatalf("默认规则: %s", w.Body.String())
	}

	// 保存(含跨天自定义时段 + 免打扰)
	w = pushDoReq(t, mux, "PUT", "/api/node/push/rules",
		`{"levels":["critical","warning"],"delaySec":5,"window":"custom","workStart":"09:00","workEnd":"18:00","customStart":"21:00","customEnd":"08:00","dnd":true,"dndStart":"22:00","dndEnd":"08:00","targetIds":["pt-不存在"]}`)
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	w = pushDoReq(t, mux, "GET", "/api/node/push/rules", "")
	body := w.Body.String()
	if !strings.Contains(body, `"delaySec":5`) || !strings.Contains(body, `"customStart":"21:00"`) ||
		!strings.Contains(body, `"dnd":true`) {
		t.Fatalf("回读: %s", body)
	}
	if strings.Contains(body, "pt-不存在") {
		t.Fatalf("不存在的目标 id 应被过滤: %s", body)
	}

	// 校验: 延迟越界 / 非法时段 / 非法时间
	if w := pushDoReq(t, mux, "PUT", "/api/node/push/rules",
		`{"levels":[],"delaySec":99999,"window":"all","targetIds":[]}`); w.Code != 400 {
		t.Fatalf("延迟越界应 400: %d", w.Code)
	}
	if w := pushDoReq(t, mux, "PUT", "/api/node/push/rules",
		`{"levels":[],"delaySec":0,"window":"lunch","targetIds":[]}`); w.Code != 400 {
		t.Fatalf("非法时段应 400: %d", w.Code)
	}
	if w := pushDoReq(t, mux, "PUT", "/api/node/push/rules",
		`{"levels":[],"delaySec":0,"window":"custom","customStart":"25:99","customEnd":"18:00","targetIds":[]}`); w.Code != 400 {
		t.Fatalf("非法时间应 400: %d", w.Code)
	}
	if w := pushDoReq(t, mux, "PUT", "/api/node/push/rules",
		`{"levels":["urgent"],"delaySec":0,"window":"all","targetIds":[]}`); w.Code != 400 {
		t.Fatalf("非法级别应 400: %d", w.Code)
	}
}

// ===== 告警 → 推送 → 日志 全链路(假 Webhook) =====

func TestAlertPushFlow(t *testing.T) {
	mux, d := newPushTestEnv(t)
	setTestUIURL(t, "http://192.168.1.10:8420")

	wh := &webhookRec{}
	whSrv := httptest.NewServer(wh.handler())
	defer whSrv.Close()

	// 预置: 1 个目标 + 规则(级别全选 / 延迟 0 / 全天 / 免打扰关 / 关联该目标)
	writeNodePushSettings(t, nodePushConfig{
		Targets: []pushTarget{{ID: "pt-1", Name: "安全运营群", Type: "wecom", Webhook: whSrv.URL, Enabled: true}},
		Rules:   pushRules{Levels: []string{"critical", "warning", "info"}, DelaySec: 0, Window: "all", TargetIds: []string{"pt-1"}},
	})

	// 采集引擎事件(warn → 前端口径 warning) → 告警落表 + 自动推送
	ev := &collect.Event{
		ID: "e-icmp-1-1", TaskID: "icmp-192.168.250.1", Side: collect.SideNet,
		Target: "192.168.250.1", At: time.Now(),
		Level: collect.EvtWarn, Type: collect.EvtHighCPU, Msg: "CPU 95.0% 超过阈值 90%",
	}
	onNodeAlert(ev)

	// 等推送完成(延迟 0, AfterFunc 毫秒级)
	var rows []*db.NodeAlert
	waitFor(t, "告警推送完成(pushed)", func() bool {
		r, _ := d.NodeAlerts().TailNewest(10)
		rows = r
		return len(r) == 1 && r[0].PushStatus == alertPushed
	})
	if len(rows) != 1 {
		t.Fatalf("应生成 1 条告警, 实际 %d", len(rows))
	}
	a := rows[0]
	if a.Level != "warning" {
		t.Fatalf("warn 应映射为 warning, 实际 %s", a.Level)
	}
	if a.Source != "link" {
		t.Fatalf("net 侧事件来源应为 link, 实际 %s", a.Source)
	}
	if a.IP != "192.168.250.1" {
		t.Fatalf("IP 提取: %s", a.IP)
	}
	if a.PushedAt == nil {
		t.Fatal("推送成功应记录 PushedAt")
	}

	// 推送日志: 1 条 success, 关联告警 ID
	logs, _ := d.PushLogs().ListNewest(10)
	if len(logs) != 1 {
		t.Fatalf("应 1 条推送日志, 实际 %d", len(logs))
	}
	if logs[0].AlertID != a.ID || logs[0].Status != logSuccess || logs[0].Target != "安全运营群" {
		t.Fatalf("日志内容不符: %+v", logs[0])
	}

	// Webhook 收到的消息含五要素
	body, n := wh.snapshot()
	if n != 1 {
		t.Fatalf("Webhook 应收到 1 次, 实际 %d", n)
	}
	for _, want := range []string{"【重要告警】", "192.168.250.1", "CPU 95.0% 超过阈值 90%", "alertId=" + a.ID} {
		if !strings.Contains(body, want) {
			t.Fatalf("Webhook 消息缺少 %q:\n%s", want, body)
		}
	}

	// 告警列表接口: 带推送状态
	w := pushDoReq(t, mux, "GET", "/api/node/push/alerts", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"pushStatus":"pushed"`) {
		t.Fatalf("alerts 接口: %d %s", w.Code, w.Body.String())
	}
	// 处理标记: 确认 → 回读
	w = pushDoReq(t, mux, "POST", "/api/node/push/alerts/"+a.ID+"/handled", `{"handled":"confirmed"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"handled":"confirmed"`) {
		t.Fatalf("handled: %d %s", w.Code, w.Body.String())
	}
	if a2, _ := d.NodeAlerts().Get(a.ID); a2.Handled != "confirmed" {
		t.Fatal("处理标记应落库")
	}
}

func TestAlertRetryFailedThenSuccess(t *testing.T) {
	mux, d := newPushTestEnv(t)

	wh := &webhookRec{}
	wh.setFail(true) // 第一轮: Webhook 拒绝
	whSrv := httptest.NewServer(wh.handler())
	defer whSrv.Close()

	writeNodePushSettings(t, nodePushConfig{
		Targets: []pushTarget{{ID: "pt-1", Name: "值班群", Type: "dingtalk", Webhook: whSrv.URL, Enabled: true}},
		Rules:   pushRules{Levels: []string{"critical"}, DelaySec: 0, Window: "all", TargetIds: []string{"pt-1"}},
	})

	ev := &collect.Event{
		ID: "e-t-2-1", TaskID: "snmp-10.0.0.1", Side: collect.SideHost,
		Target: "10.0.0.1:161", At: time.Now(),
		Level: collect.EvtCritical, Type: collect.EvtOffline, Msg: "采集连续 3 次失败, 判定离线",
	}
	onNodeAlert(ev)

	// 推送失败: 状态 failed + 日志 failed(含原因)
	var rows []*db.NodeAlert
	waitFor(t, "告警推送失败(failed)", func() bool {
		r, _ := d.NodeAlerts().TailNewest(10)
		rows = r
		return len(r) == 1 && r[0].PushStatus == alertFailed
	})
	a := rows[0]
	if a.Source != "device" {
		t.Fatalf("host 侧事件来源应为 device, 实际 %s", a.Source)
	}
	if a.IP != "10.0.0.1" {
		t.Fatalf("host:port 应提取出 IP: %s", a.IP)
	}
	logs, _ := d.PushLogs().ListNewest(10)
	if len(logs) != 1 || logs[0].Status != logFailed {
		t.Fatalf("应有 1 条 failed 日志: %+v", logs)
	}
	if !strings.Contains(logs[0].Reason, "93000") {
		t.Fatalf("失败原因应含平台错误码: %s", logs[0].Reason)
	}

	// 手动重推: 仍失败(目标未变)
	w := pushDoReq(t, mux, "POST", "/api/node/push/retry", `{"alertId":"`+a.ID+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"failed"`) {
		t.Fatalf("retry: %d %s", w.Code, w.Body.String())
	}

	// Webhook 恢复 → 再重推 → 成功
	wh.setFail(false)
	wh.reset()
	w = pushDoReq(t, mux, "POST", "/api/node/push/retry", `{"alertId":"`+a.ID+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"pushed"`) {
		t.Fatalf("retry2: %d %s", w.Code, w.Body.String())
	}
	if a2, _ := d.NodeAlerts().Get(a.ID); a2.PushStatus != alertPushed {
		t.Fatal("重推成功后告警状态应为 pushed")
	}
	logs, _ = d.PushLogs().ListNewest(10)
	if len(logs) != 3 {
		t.Fatalf("应有 3 条日志(2 失败 + 1 成功), 实际 %d", len(logs))
	}
	// 日志按级别/目标筛选: critical 全中, 目标"值班群"全中, 目标"不存在"零
	if w := pushDoReq(t, mux, "GET", "/api/node/push/logs?level=critical", ""); !strings.Contains(w.Body.String(), `"total":3`) {
		t.Fatalf("level 筛选: %s", w.Body.String())
	}
	if w := pushDoReq(t, mux, "GET", "/api/node/push/logs?level=info", ""); !strings.Contains(w.Body.String(), `"total":0`) {
		t.Fatalf("level 筛选(无命中): %s", w.Body.String())
	}
	if w := pushDoReq(t, mux, "GET", "/api/node/push/logs?target=%E5%80%BC%E7%8F%AD%E7%BE%A4", ""); !strings.Contains(w.Body.String(), `"total":3`) {
		t.Fatalf("target 筛选: %s", w.Body.String())
	}

	// 重推不存在告警 → 404
	if w := pushDoReq(t, mux, "POST", "/api/node/push/retry", `{"alertId":"na-none"}`); w.Code != 404 {
		t.Fatalf("重推不存在应 404: %d", w.Code)
	}
}

func TestPushTestEndpoint(t *testing.T) {
	mux, _ := newPushTestEnv(t)
	wh := &webhookRec{}
	whSrv := httptest.NewServer(wh.handler())
	defer whSrv.Close()
	writeNodePushSettings(t, nodePushConfig{
		Targets: []pushTarget{{ID: "pt-1", Name: "测试群", Type: "feishu", Webhook: whSrv.URL, Enabled: true}},
	})

	// 成功
	w := pushDoReq(t, mux, "POST", "/api/node/push/test", `{"targetId":"pt-1"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("test ok: %d %s", w.Code, w.Body.String())
	}
	// 测试推送应产生无主日志(无关联告警)
	logs, _ := dbPushLogList()
	if len(logs) != 1 || logs[0].AlertID != "" {
		t.Fatalf("测试推送应写 1 条无主日志: %+v", logs)
	}

	// 失败回执
	wh.setFail(true)
	w = pushDoReq(t, mux, "POST", "/api/node/push/test", `{"targetId":"pt-1"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"success":false`) ||
		!strings.Contains(w.Body.String(), "93000") {
		t.Fatalf("test fail: %d %s", w.Code, w.Body.String())
	}
}

// dbPushLogList 测试辅助: 直读注入库的推送日志。
func dbPushLogList() ([]*db.PushLog, error) {
	return v2DB().PushLogs().ListNewest(100)
}

// ===== 告警推送总开关 + 状态概览(2026-09-28: 大屏轻量入口契约) =====

func TestPushSwitchAndStat(t *testing.T) {
	mux, d := newPushTestEnv(t)

	wh := &webhookRec{}
	whSrv := httptest.NewServer(wh.handler())
	defer whSrv.Close()
	writeNodePushSettings(t, nodePushConfig{
		Targets: []pushTarget{{ID: "pt-1", Name: "值班群", Type: "wecom", Webhook: whSrv.URL, Enabled: true}},
		Rules:   pushRules{Levels: []string{"critical", "warning", "info"}, DelaySec: 0, Window: "all", TargetIds: []string{"pt-1"}},
	})

	statOf := func() (enabled bool, pushed, failed int) {
		w := pushDoReq(t, mux, "GET", "/api/node/push/stat", "")
		if w.Code != 200 {
			t.Fatalf("stat: %d %s", w.Code, w.Body.String())
		}
		var env struct {
			Data struct {
				Enabled     bool `json:"enabled"`
				TodayPushed int  `json:"todayPushed"`
				TodayFailed int  `json:"todayFailed"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatalf("stat decode: %v", err)
		}
		return env.Data.Enabled, env.Data.TodayPushed, env.Data.TodayFailed
	}

	// 1) 未写 enabled(存量配置) = 开, 行为与升级前一致
	if en, _, _ := statOf(); !en {
		t.Fatal("nodepush 节未写 enabled 时应视为开(不改变存量用户推送行为)")
	}

	// 2) 关闭: 告警落表但不推送(无日志), 重推被拒
	w := pushDoReq(t, mux, "PUT", "/api/node/push/switch", `{"enabled":false}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("switch off: %d %s", w.Code, w.Body.String())
	}
	ev := &collect.Event{
		ID: "e-sw-1-1", TaskID: "snmp-10.1.1.1", Side: collect.SideHost,
		Target: "10.1.1.1:161", At: time.Now(),
		Level: collect.EvtCritical, Type: collect.EvtOffline, Msg: "离线",
	}
	onNodeAlert(ev)
	time.Sleep(300 * time.Millisecond) // 延迟 0 的推送毫秒级完成; 若被误推这里已能观察到
	logs, _ := d.PushLogs().ListNewest(10)
	if len(logs) != 0 {
		t.Fatalf("总开关关闭不应产生推送日志, 实际 %d 条", len(logs))
	}
	rows, _ := d.NodeAlerts().TailNewest(10)
	if len(rows) != 1 || rows[0].PushStatus != alertUnpushed {
		t.Fatalf("开关关闭时告警应落表且停在未推送: %+v", rows)
	}
	if w := pushDoReq(t, mux, "POST", "/api/node/push/retry", `{"alertId":"`+rows[0].ID+`"}`); w.Code != http.StatusConflict {
		t.Fatalf("开关关闭时重推应 409: %d %s", w.Code, w.Body.String())
	}
	if en, _, _ := statOf(); en {
		t.Fatal("关闭后 stat.enabled 应为 false")
	}

	// 3) 打开: 同一告警手动重推成功, 计数进入"今日"
	w = pushDoReq(t, mux, "PUT", "/api/node/push/switch", `{"enabled":true}`)
	if w.Code != 200 {
		t.Fatalf("switch on: %d %s", w.Code, w.Body.String())
	}
	w = pushDoReq(t, mux, "POST", "/api/node/push/retry", `{"alertId":"`+rows[0].ID+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"pushed"`) {
		t.Fatalf("switch on 后重推应成功: %d %s", w.Code, w.Body.String())
	}

	// 4) stat 计数: 重推产生的 1 条今日 success; 再补 1 条今日 failed + 1 条今日
	//    skipped + 1 条昨日 success —— 只有 success/failed 计入, skipped 与跨天不算
	now := time.Now()
	seed := func(at time.Time, status string) {
		_, err := d.PushLogs().Upsert(&db.PushLog{
			ID: fmt.Sprintf("pl-seed-%d-%s", at.UnixMilli(), status),
			At: at, Level: "info", Content: "seed", Target: "值班群", Status: status,
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(now, logFailed)
	seed(now.Add(time.Second), logSkipped)
	seed(now.Add(-25*time.Hour), logSuccess)
	if en, pushed, failed := statOf(); !en || pushed != 1 || failed != 1 {
		t.Fatalf("stat 计数 = enabled:%t pushed:%d failed:%d, 期望 true/1/1", en, pushed, failed)
	}
}
