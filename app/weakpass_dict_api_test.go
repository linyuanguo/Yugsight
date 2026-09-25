package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yugsight/internal/db"
	"yugsight/internal/server"
)

// installDictTestDB 注入临时库 + 免登录(与 penta/weakpass_api_test 同手法)。
//
// 为什么用免登录而非真登录: 权限边界(adminOnly/requireAuth)由 rbac 既有测试守,
// 这里只测 handler 的业务逻辑(增删改查/幂等/降级), 免登录直通最干净。
func installDictTestDB(t *testing.T) *db.Database {
	t.Helper()
	d, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })
	v2DBProviderMu.Lock()
	prevProvider := v2DBProvider
	v2DBProvider = func() *db.Database { return d }
	v2DBProviderMu.Unlock()
	t.Cleanup(func() {
		v2DBProviderMu.Lock()
		v2DBProvider = prevProvider
		v2DBProviderMu.Unlock()
	})
	return d
}

// dictTestRouter 构建与 main.go 同款的字典路由(经真实 v2 mux, r.PathValue 可用)。
// 挂 requireAuth + adminOnly 以贴近生产中间件链; 免登录下两者直通。
func dictTestRouter() http.Handler {
	srv := server.New()
	registerWeakPassDictRoutes(srv)
	return srv.Handler()
}

func callDict(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	dictTestRouter().ServeHTTP(w, req)
	return w
}

// decodeDictResp 拆 v2 信封并返回 data(map)。
func decodeDictData(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var resp struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非 JSON: %v, body=%.200s", err, w.Body.String())
	}
	if resp.Code != 0 {
		t.Fatalf("业务码=%d message=%s", resp.Code, resp.Message)
	}
	var m map[string]any
	if len(resp.Data) > 0 {
		if err := json.Unmarshal(resp.Data, &m); err != nil {
			t.Fatalf("data 非对象: %v", err)
		}
	}
	return m
}

// TestWeakPassDictSeedIdempotent 守"首次启动自动内置 349 条, 重复启动不重复写入"。
func TestWeakPassDictSeedIdempotent(t *testing.T) {
	d := installDictTestDB(t)

	// 首次: 空库 → 写入 349
	ensureWeakPassDict(d)
	n, _ := d.WeakPassDict().CountByType(db.WeakDictBuiltin)
	if n != 349 {
		t.Fatalf("首次初始化应写入 349 条内置, 实际 %d", n)
	}

	// 重复调用: 幂等, 不再增长
	ensureWeakPassDict(d)
	n2, _ := d.WeakPassDict().CountByType(db.WeakDictBuiltin)
	total, _ := d.WeakPassDict().Count()
	if n2 != 349 || total != 349 {
		t.Fatalf("重复初始化应幂等(仍 349), 实际 builtin=%d total=%d", n2, total)
	}
}

// TestWeakPassDictLifecycle 字典管理全生命周期: 列表/搜索/新增(单+批+判重)/
// 删除(内置拒绝+自定义可删)/批量删除/重置恢复 349。
func TestWeakPassDictLifecycle(t *testing.T) {
	d := installDictTestDB(t)
	ensureWeakPassDict(d)

	// 1) 列表: 默认分页 20 条, 总数 349, 内置 349 自定义 0
	w := callDict(t, "GET", "/api/v2/weakpass/dict?page=1&size=20", "")
	data := decodeDictData(t, w)
	if data["total"].(float64) != 349 {
		t.Fatalf("total 应为 349, 实际 %v", data["total"])
	}
	if data["builtinCount"].(float64) != 349 || data["customCount"].(float64) != 0 {
		t.Fatalf("builtinCount/customCount 应为 349/0, 实际 %v/%v", data["builtinCount"], data["customCount"])
	}
	items, _ := data["items"].([]any)
	if len(items) != 20 {
		t.Fatalf("size=20 应返回 20 条, 实际 %d", len(items))
	}

	// 2) 搜索: q=123456 应命中且 total 变小
	w = callDict(t, "GET", "/api/v2/weakpass/dict?q=123456", "")
	data = decodeDictData(t, w)
	if data["total"].(float64) == 0 {
		t.Fatal("搜索 123456 应命中")
	}

	// 3) 新增单条 + 批量
	w = callDict(t, "POST", "/api/v2/weakpass/dict", `{"passwords":["mycustom1"]}`)
	data = decodeDictData(t, w)
	if data["added"].(float64) != 1 {
		t.Fatalf("新增单条应 added=1, 实际 %v", data["added"])
	}
	w = callDict(t, "POST", "/api/v2/weakpass/dict", `{"passwords":["mycustom2","mycustom3","mycustom2"]}`)
	data = decodeDictData(t, w)
	if data["added"].(float64) != 2 {
		t.Fatalf("批量新增(含 1 重复)应 added=2, 实际 %v", data["added"])
	}
	// 重复新增已存在的 mycustom1 → 跳过
	w = callDict(t, "POST", "/api/v2/weakpass/dict", `{"passwords":["mycustom1"]}`)
	data = decodeDictData(t, w)
	if data["added"].(float64) != 0 {
		t.Fatalf("重复新增应 added=0, 实际 %v", data["added"])
	}
	if sk, _ := data["skipped"].([]any); len(sk) != 1 {
		t.Fatalf("重复新增应 skipped=1, 实际 %v", data["skipped"])
	}

	// 4) 取一条自定义 ID, 验证删除; 内置 ID 删除应被拒
	w = callDict(t, "GET", "/api/v2/weakpass/dict?q=mycustom1&size=50", "")
	data = decodeDictData(t, w)
	items, _ = data["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("应取到 mycustom1, 实际 %d", len(items))
	}
	entryType := itemField(t, items[0], "type")
	if entryType != db.WeakDictCustom {
		t.Fatalf("新增条目 type 应为 custom, 实际 %s", entryType)
	}
	entryID := itemField(t, items[0], "id")
	// 删除自定义 → 成功
	w = callDict(t, "DELETE", "/api/v2/weakpass/dict/"+entryID, "")
	data = decodeDictData(t, w)
	if data["deleted"].(float64) != 1 {
		t.Fatalf("删除自定义应 deleted=1, 实际 %v", data["deleted"])
	}
	// 删除内置 → 400 拒绝
	w = callDict(t, "GET", "/api/v2/weakpass/dict?q=123456&size=1", "")
	data = decodeDictData(t, w)
	items, _ = data["items"].([]any)
	if len(items) != 1 {
		t.Fatal("应取到内置条目")
	}
	builtinID := itemField(t, items[0], "id")
	w = callDict(t, "DELETE", "/api/v2/weakpass/dict/"+builtinID, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("删除内置应 400, 实际 %d: %s", w.Code, w.Body.String())
	}

	// 5) 批量删除(混选内置 + 自定义): 复用步骤 3 遗留的 mycustom2 / mycustom3
	//    (mycustom1 已在步骤 4 删除), 避免新口令与内置条目子串冲突。
	getID := func(q string) string {
		w := callDict(t, "GET", "/api/v2/weakpass/dict?q="+q+"&size=1", "")
		data := decodeDictData(t, w)
		items, _ := data["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("应取到 %s, 实际 %d", q, len(items))
		}
		return itemField(t, items[0], "id")
	}
	c1ID, c2ID := getID("mycustom2"), getID("mycustom3")
	// 混入一个内置 id
	batchBody := `{"ids":[` + quote(c1ID) + "," + quote(c2ID) + "," + quote(builtinID) + `]}`
	w = callDict(t, "POST", "/api/v2/weakpass/dict/batch-delete", batchBody)
	data = decodeDictData(t, w)
	if data["deleted"].(float64) != 2 {
		t.Fatalf("批量删除应删 2 条自定义, 实际 %v", data["deleted"])
	}
	if data["skippedBuiltin"].(float64) != 1 {
		t.Fatalf("批量删除应跳过 1 条内置, 实际 %v", data["skippedBuiltin"])
	}

	// 6) 重置: 恢复内置 349, 自定义清零
	w = callDict(t, "POST", "/api/v2/weakpass/dict/reset", "")
	data = decodeDictData(t, w)
	if data["builtin"].(float64) != 349 {
		t.Fatalf("重置应恢复内置 349, 实际 %v", data["builtin"])
	}
	w = callDict(t, "GET", "/api/v2/weakpass/dict", "")
	data = decodeDictData(t, w)
	if data["total"].(float64) != 349 || data["customCount"].(float64) != 0 {
		t.Fatalf("重置后应 total=349 custom=0, 实际 total=%v custom=%v", data["total"], data["customCount"])
	}
}

// TestWeakPassDictDBDown 库不可用时列表接口降级为 503(不 panic)。
func TestWeakPassDictDBDown(t *testing.T) {
	// 免登录直通 requireAuth, 让请求真正走到 v2NeedDB 的降级分支
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })
	// 注入一个返回 nil 的 provider, 模拟数据库初始化失败
	v2DBProviderMu.Lock()
	prevProvider := v2DBProvider
	v2DBProvider = func() *db.Database { return nil }
	v2DBProviderMu.Unlock()
	t.Cleanup(func() {
		v2DBProviderMu.Lock()
		v2DBProvider = prevProvider
		v2DBProviderMu.Unlock()
	})
	w := callDict(t, "GET", "/api/v2/weakpass/dict", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("库不可用应 503, 实际 %d", w.Code)
	}
}

// quote 把字符串包成 JSON 字符串字面量(小工具, 避免引依赖)。
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// itemID 从已解码的条目 map 取字段值(data 已 Unmarshal 成 map, items[i] 是 map 而非 RawMessage)。
func itemField(t *testing.T, item any, key string) string {
	t.Helper()
	m, ok := item.(map[string]any)
	if !ok {
		t.Fatalf("条目不是对象: %T", item)
	}
	s, _ := m[key].(string)
	return s
}
