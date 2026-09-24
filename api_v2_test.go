package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"yugsight/db"
	"yugsight/models"
	"yugsight/server"
)

// newV2TestEnv 构建 v2 测试环境: 独立临时库 + 测试模式(跳过登录)。
func newV2TestEnv(t *testing.T) (http.Handler, *db.Database) {
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
	srv := server.New(server.WithLogger(func(string) {}))
	registerV2Routes(srv, func() *db.Database { return d })
	return srv.Handler(), d
}

func doReq(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
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

func decodeResp(t *testing.T, w *httptest.ResponseRecorder) server.Resp {
	t.Helper()
	var out server.Resp
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("resp decode: %v body=%.300s", err, w.Body.String())
	}
	return out
}

// TestAuditConfigAPI 审计: 保存天数默认/保存落盘/回读一致/范围校验 + 列表筛选分页
func TestAuditConfigAPI(t *testing.T) {
	h, d := newV2TestEnv(t)
	// 配置路径指到临时目录, 避免污染真实 exe 目录的 settings.json
	dir := t.TempDir()
	setSettingsTestPath(filepath.Join(dir, "settings.json"))
	t.Cleanup(func() { setSettingsTestPath("") })

	// GET: 默认 90 天
	w := doReq(t, h, "GET", "/api/v2/audit/config", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"retentionDays":90`) {
		t.Fatalf("config get: %d %s", w.Code, w.Body.String())
	}

	// POST: 保存 7 天 -> 落盘 + 回读一致
	w = doReq(t, h, "POST", "/api/v2/audit/config", `{"retentionDays":7}`)
	if w.Code != 200 {
		t.Fatalf("config set: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "settings.json")); err != nil {
		t.Fatalf("settings 应落盘: %v", err)
	}
	w = doReq(t, h, "GET", "/api/v2/audit/config", "")
	if !strings.Contains(w.Body.String(), `"retentionDays":7`) {
		t.Fatalf("保存后回读应为 7: %s", w.Body.String())
	}

	// 范围校验
	if w := doReq(t, h, "POST", "/api/v2/audit/config", `{"retentionDays":-1}`); w.Code != 400 {
		t.Fatalf("负数应 400: %d", w.Code)
	}
	if w := doReq(t, h, "POST", "/api/v2/audit/config", `{"retentionDays":99999}`); w.Code != 400 {
		t.Fatalf("超上限应 400: %d", w.Code)
	}

	// 列表筛选: 两用户各一条, 按用户过滤只命中一条
	_ = d.Audits().Append(db.AuditLog{UserID: "alice", Action: "scan.start", Target: "10.0.0.1"})
	_ = d.Audits().Append(db.AuditLog{UserID: "bob", Action: "login.success", Target: "bob"})
	w = doReq(t, h, "GET", "/api/v2/audit?user=alice", "")
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "scan.start") || strings.Contains(body, "login.success") {
		t.Fatalf("user 筛选: %s", body)
	}
	// 分页: size=1 -> total=3(两条测试数据 + 上面 POST 配置保存的 audit.config.save,
	// 恰好验证"保存配置这个操作本身也被审计")
	w = doReq(t, h, "GET", "/api/v2/audit?page=1&size=1", "")
	if !strings.Contains(w.Body.String(), `"total":3`) {
		t.Fatalf("分页 total: %s", w.Body.String())
	}
}

// TestV2Health 健康检查(免登录)
func TestV2Health(t *testing.T) {
	h, _ := newV2TestEnv(t)
	w := doReq(t, h, "GET", "/api/v2/health", "")
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	out := decodeResp(t, w)
	if out.Code != server.CodeOK || !strings.Contains(w.Body.String(), "Yugsight") {
		t.Fatalf("resp=%+v", out)
	}
}

// TestV2AssetCRUD 资产: 创建 / 查询 / 更新 / 标签 / 删除
func TestV2AssetCRUD(t *testing.T) {
	h, d := newV2TestEnv(t)
	// 创建
	w := doReq(t, h, "POST", "/api/v2/assets", `{"ip":"192.168.1.10","hostname":"srv","os":"linux","ports":[80,443],"tags":["prod"]}`)
	out := decodeResp(t, w)
	if w.Code != 200 || out.Code != 0 {
		t.Fatalf("create status=%d resp=%+v", w.Code, out)
	}
	id, _ := jsonPath(w.Body.String(), "asset.id")
	if id == "" {
		t.Fatal("asset id 为空")
	}
	// 幂等 upsert(同 IP 不新增)
	doReq(t, h, "POST", "/api/v2/assets", `{"ip":"192.168.1.10","hostname":"srv2"}`)
	if n, _ := d.Assets().Count(); n != 1 {
		t.Fatalf("upsert 后 count=%d", n)
	}
	// 查询
	w = doReq(t, h, "GET", "/api/v2/assets/"+id, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "srv2") {
		t.Fatalf("get status=%d", w.Code)
	}
	// 更新
	w = doReq(t, h, "PUT", "/api/v2/assets/"+id, `{"mac":"aa:bb:cc:dd:ee:ff","service":"nginx"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "aa:bb:cc:dd:ee:ff") {
		t.Fatalf("update status=%d", w.Code)
	}
	// 标签增删
	w = doReq(t, h, "POST", "/api/v2/assets/"+id+"/tags", `{"tags":["db"]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"db"`) {
		t.Fatalf("tags add status=%d", w.Code)
	}
	w = doReq(t, h, "DELETE", "/api/v2/assets/"+id+"/tags", `{"tags":["prod"]}`)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"prod"`) {
		t.Fatalf("tags remove status=%d", w.Code)
	}
	// 按标签查询
	w = doReq(t, h, "GET", "/api/v2/assets?tag=db", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("query tag=%d", w.Code)
	}
	// 删除
	w = doReq(t, h, "DELETE", "/api/v2/assets/"+id, "")
	if w.Code != 200 {
		t.Fatalf("delete status=%d", w.Code)
	}
	w = doReq(t, h, "GET", "/api/v2/assets/"+id, "")
	if w.Code != 404 {
		t.Fatalf("get after delete status=%d", w.Code)
	}
	// 参数校验
	w = doReq(t, h, "POST", "/api/v2/assets", `{}`)
	if w.Code != 400 {
		t.Fatalf("empty ip status=%d", w.Code)
	}
}

// jsonPath 从 JSON 响应中提取 data 下的路径(测试辅助, 支持数组下标如 list.0.id)。
func jsonPath(body, path string) (string, bool) {
	var m map[string]any
	if json.Unmarshal([]byte(body), &m) != nil {
		return "", false
	}
	var cur any = m["data"]
	for _, key := range strings.Split(path, ".") {
		switch v := cur.(type) {
		case map[string]any:
			cur = v[key]
		case []any:
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= len(v) {
				return "", false
			}
			cur = v[idx]
		default:
			return "", false
		}
	}
	s, _ := cur.(string)
	return s, true
}

// TestV2VulnQuery 漏洞: 分页 / 多维筛选 / 详情 / 状态更新
func TestV2VulnQuery(t *testing.T) {
	h, d := newV2TestEnv(t)
	// 经 DAO 预置数据(模拟扫描结果回传)
	for _, v := range []struct{ ip, cve, title, sev string }{
		{"10.0.0.1", "CVE-2021-44228", "Log4j2 RCE", "critical"},
		{"10.0.0.1", "CVE-2021-45047", "Spring4Shell", "high"},
		{"10.0.0.2", "", "默认口令", "medium"},
	} {
		vv := models.Vuln{AssetIP: v.ip, CVE: v.cve, Title: v.title, Severity: v.sev, Source: "builtin"}
		if err := d.Vulns().Create(&db.Vuln{Vuln: vv}); err != nil {
			t.Fatalf("seed %s: %v", v.title, err)
		}
	}
	// 全量分页
	w := doReq(t, h, "GET", "/api/v2/vulns?page=1&size=2", "")
	out := decodeResp(t, w)
	if w.Code != 200 || out.Code != 0 {
		t.Fatalf("list status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"total":3`) || !strings.Contains(w.Body.String(), `"size":2`) {
		t.Fatalf("list body=%s", w.Body.String())
	}
	// 按等级筛选
	w = doReq(t, h, "GET", "/api/v2/vulns?severity=critical", "")
	if !strings.Contains(w.Body.String(), `"total":1`) || !strings.Contains(w.Body.String(), "CVE-2021-44228") {
		t.Fatalf("sev filter body=%s", w.Body.String())
	}
	// 按 IP + 标题关键字
	w = doReq(t, h, "GET", "/api/v2/vulns?ip=10.0.0.2&title=口令", "")
	if !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("ip+title body=%s", w.Body.String())
	}
	// 详情
	id, _ := jsonPath(doReq(t, h, "GET", "/api/v2/vulns?cve=CVE-2021-44228", "").Body.String(), "list.0.id")
	if id == "" {
		t.Fatal("vuln id 为空")
	}
	w = doReq(t, h, "GET", "/api/v2/vulns/"+id, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Log4j2") {
		t.Fatalf("detail status=%d", w.Code)
	}
	// 状态更新(标记修复)
	w = doReq(t, h, "PUT", "/api/v2/vulns/"+id, `{"status":"fixed"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"fixed"`) {
		t.Fatalf("update status=%d", w.Code)
	}
	// 按状态筛选
	w = doReq(t, h, "GET", "/api/v2/vulns?status=fixed", "")
	if !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("status filter body=%s", w.Body.String())
	}
	// 删除
	w = doReq(t, h, "DELETE", "/api/v2/vulns/"+id, "")
	if w.Code != 200 {
		t.Fatalf("delete status=%d", w.Code)
	}
	// 写入(回传)
	w = doReq(t, h, "POST", "/api/v2/vulns", `{"assetIp":"10.0.0.9","title":"SSH 弱口令","severity":"HIGH"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"created":true`) {
		t.Fatalf("upsert status=%d", w.Code)
	}
}

// TestV2Whitelist 白名单: 添加 / 列表 / 启停 / 删除
func TestV2Whitelist(t *testing.T) {
	h, d := newV2TestEnv(t)
	w := doReq(t, h, "POST", "/api/v2/whitelist", `{"type":"ip","match":"192.168.1.99","reason":"测试机"}`)
	out := decodeResp(t, w)
	if w.Code != 200 || out.Code != 0 {
		t.Fatalf("add status=%d", w.Code)
	}
	id, _ := jsonPath(w.Body.String(), "id")
	// 非法类型
	w = doReq(t, h, "POST", "/api/v2/whitelist", `{"type":"xxx","match":"1"}`)
	if w.Code != 400 {
		t.Fatalf("bad type status=%d", w.Code)
	}
	// 列表
	w = doReq(t, h, "GET", "/api/v2/whitelist", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("list status=%d", w.Code)
	}
	// 启停
	w = doReq(t, h, "PUT", "/api/v2/whitelist/"+id, `{"enabled":false}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("update status=%d", w.Code)
	}
	// 删除
	w = doReq(t, h, "DELETE", "/api/v2/whitelist/"+id, "")
	if w.Code != 200 {
		t.Fatalf("delete status=%d", w.Code)
	}
	if n, _ := d.Whitelists().Count(); n != 0 {
		t.Fatalf("count=%d", n)
	}
}

// TestV2ScanTask 扫描任务: 创建 / 列表 / 状态查询 / 状态流转
func TestV2ScanTask(t *testing.T) {
	h, _ := newV2TestEnv(t)
	w := doReq(t, h, "POST", "/api/v2/scans", `{"type":"host","target":"10.0.0.5","params":{"ports":"80,443"}}`)
	out := decodeResp(t, w)
	if w.Code != 200 || out.Code != 0 {
		t.Fatalf("create status=%d", w.Code)
	}
	id, _ := jsonPath(w.Body.String(), "id")
	if !strings.Contains(w.Body.String(), `"status":"pending"`) {
		t.Fatalf("task=%s", w.Body.String())
	}
	// 缺目标
	w = doReq(t, h, "POST", "/api/v2/scans", `{"type":"host"}`)
	if w.Code != 400 {
		t.Fatalf("bad create status=%d", w.Code)
	}
	// 列表
	w = doReq(t, h, "GET", "/api/v2/scans", "")
	if !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("list body=%s", w.Body.String())
	}
	// 状态查询
	w = doReq(t, h, "GET", "/api/v2/scans/"+id, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), id) {
		t.Fatalf("get status=%d", w.Code)
	}
	// 状态流转
	w = doReq(t, h, "POST", "/api/v2/scans/"+id+"/status", `{"status":"running"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"startedAt"`) {
		t.Fatalf("running body=%s", w.Body.String())
	}
	w = doReq(t, h, "POST", "/api/v2/scans/"+id+"/status", `{"status":"success","result":"发现 2 个漏洞"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"finishedAt"`) {
		t.Fatalf("success body=%s", w.Body.String())
	}
	// 按状态筛选
	w = doReq(t, h, "GET", "/api/v2/scans?status=success", "")
	if !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("filter body=%s", w.Body.String())
	}
	// 删除
	w = doReq(t, h, "DELETE", "/api/v2/scans/"+id, "")
	if w.Code != 200 {
		t.Fatalf("delete status=%d", w.Code)
	}
}

// TestV2Sessions 用户会话: 列表 / 吊销
func TestV2Sessions(t *testing.T) {
	h, _ := newV2TestEnv(t)
	// 注入一个会话(模拟登录, admin 角色)
	authMu.Lock()
	sessions["testtoken1234567890"] = sessionRec{exp: time.Now().Add(time.Hour), user: "tester", role: db.RoleAdmin}
	authMu.Unlock()
	t.Cleanup(func() {
		authMu.Lock()
		delete(sessions, "testtoken1234567890")
		authMu.Unlock()
	})
	// 列表(token 脱敏: 仅前 8 位)
	w := doReq(t, h, "GET", "/api/v2/sessions", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "testtoke...") {
		t.Fatalf("list body=%s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "testtoken1234567890") {
		t.Fatal("token 未脱敏")
	}
	// 吊销(前缀匹配)
	w = doReq(t, h, "DELETE", "/api/v2/sessions/testtoken123", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"removed":1`) {
		t.Fatalf("revoke body=%s", w.Body.String())
	}
	// 重复吊销 -> 404
	w = doReq(t, h, "DELETE", "/api/v2/sessions/testtoken123", "")
	if w.Code != 404 {
		t.Fatalf("revoke again status=%d", w.Code)
	}
}

// TestV2AuditAndDB 审计日志落库 + 数据库状态
func TestV2AuditAndDB(t *testing.T) {
	h, d := newV2TestEnv(t)
	// 触发一次写操作
	doReq(t, h, "POST", "/api/v2/whitelist", `{"type":"port","match":"8080"}`)
	// 审计查询
	w := doReq(t, h, "GET", "/api/v2/audit?limit=10", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "whitelist.add") {
		t.Fatalf("audit body=%s", w.Body.String())
	}
	if n, _ := d.Audits().Count(); n != 1 {
		t.Fatalf("audit count=%d", n)
	}
	// 数据库状态
	w = doReq(t, h, "GET", "/api/v2/db/status", "")
	if w.Code != 200 {
		t.Fatalf("db status=%d", w.Code)
	}
	for _, want := range []string{`"type":"sqlite"`, `"assets"`, `"audit_logs"`, `"probes"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("db/status 缺少 %s: %s", want, w.Body.String())
		}
	}
}

// TestV2PanicRecover 全局异常捕获: 数据库不可用返回统一 503, 服务不宕机
func TestV2PanicRecover(t *testing.T) {
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })
	// 注入永远返回 nil 的 db provider
	srv := server.New(server.WithLogger(func(string) {}))
	registerV2Routes(srv, func() *db.Database { return nil })
	h := srv.Handler()
	// 恢复生产入口(provider 必须一并复位, 否则后续测试会继续拿到 nil)
	t.Cleanup(func() {
		v2GetDB = v2DB
		v2DBProviderMu.Lock()
		v2DBProvider = nil
		v2DBProviderMu.Unlock()
	})
	w := doReq(t, h, "GET", "/api/v2/assets", "")
	// db 不可用 -> 503 统一响应(不 panic)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", w.Code)
	}
	out := decodeResp(t, w)
	if out.Code != server.CodeDBUnavailable {
		t.Fatalf("resp=%+v", out)
	}
	// 服务仍可用
	w = doReq(t, h, "GET", "/api/v2/health", "")
	if w.Code != 200 {
		t.Fatalf("health after 503 status=%d", w.Code)
	}
}

// TestV2DBNoSelfRecursion 回归: v2DB 不得因 provider 指向自身而无限自递归。
//
// 背景(2026-09-16 真机联调发现): 生产路径 registerV2Routes(srv, v2DB) 曾把
// v2DB 自身记为 v2DBProvider, v2DB() 读到非 nil 就调用它 -> 自递归 -> 1GB
// 栈耗尽 -> fatal error: stack overflow。该崩溃属原生级, recover 拦不住、
// yugsight.log 也无记录, 现场只表现为"进程静默消失"(探针一上线中心端即死)。
//
// 本用例必须能在修复前失败: 修复前调用 v2DB() 会直接栈溢出杀掉测试进程。
func TestV2DBNoSelfRecursion(t *testing.T) {
	// 还原生产装配方式: 传 v2DB 自身
	prevGet := v2GetDB
	prevProvider := v2DBProvider
	t.Cleanup(func() {
		v2GetDB = prevGet
		v2DBProviderMu.Lock()
		v2DBProvider = prevProvider
		v2DBProviderMu.Unlock()
	})
	srv := server.New(server.WithLogger(func(string) {}))
	registerV2Routes(srv, v2DB)

	// 自身 provider 不应被记录(否则 v2DB() 递归)
	v2DBProviderMu.RLock()
	injected := v2DBProvider
	v2DBProviderMu.RUnlock()
	if isSelfProvider(injected) {
		t.Fatal("v2DB 自身被记为 provider, 会导致无限自递归")
	}
	// 注: v2GetDB 默认值本就是 v2DB(var v2GetDB = v2DB), 那是 HTTP 入口的正常
	// 默认语义(经 v2NeedDB 调用即走懒加载), 不构成递归, 故此处不断言。
	// 能正常返回(不递归); 无 config.json 时按默认目录初始化, 失败也仅返回 nil 不崩
	_ = v2DB()
}

// TestIsSelfProvider 自识别判定: 自身返回 true, 外部 provider 返回 false。
func TestIsSelfProvider(t *testing.T) {
	if !isSelfProvider(v2DB) {
		t.Fatal("v2DB 未被识别为自身")
	}
	if isSelfProvider(nil) {
		t.Fatal("nil 不应被判为自身")
	}
	if isSelfProvider(func() *db.Database { return nil }) {
		t.Fatal("匿名 provider 被误判为自身")
	}
}
