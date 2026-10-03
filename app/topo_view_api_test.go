package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTopoViewTestEnv v2 环境 + 视图文件指到临时目录(避免写真实 exe 目录);
// 回传文件路径供落盘断言(再调 t.TempDir 会拿到新目录)。
func newTopoViewTestEnv(t *testing.T) (http.Handler, string) {
	t.Helper()
	h, _ := newV2TestEnv(t)
	p := filepath.Join(t.TempDir(), "topo_views.json")
	setTopoViewTestPath(p)
	t.Cleanup(func() { setTopoViewTestPath("") })
	return h, p
}

const topoViewTestBody = `{
  "updatedAt": 1000,
  "baseUpdatedAt": 0,
  "active": "默认视图",
  "views": [{"name": "默认视图", "nodes": [{"deviceId": "M_1", "name": "交换机", "ip": "172.16.199.1"}], "links": [], "boxes": []}]
}`

// TestTopoViewPutGet 空库回空文档; PUT 落盘; GET 回读一致(含中文视图名)。
func TestTopoViewPutGet(t *testing.T) {
	h, p := newTopoViewTestEnv(t)

	// 无数据: updatedAt=0 空文档(前端据此判定"服务器还没有视图")
	w := doReq(t, h, "GET", "/api/v2/topo/views", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"updatedAt":0`) {
		t.Fatalf("空库应回空文档: %d %s", w.Code, w.Body.String())
	}

	// PUT 保存
	w = doReq(t, h, "PUT", "/api/v2/topo/views", topoViewTestBody)
	if w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	// 原子写落盘
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("应落盘: %v", err)
	}

	// GET 回读一致
	w = doReq(t, h, "GET", "/api/v2/topo/views", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"updatedAt":1000`) ||
		!strings.Contains(w.Body.String(), "默认视图") || !strings.Contains(w.Body.String(), "172.16.199.1") {
		t.Fatalf("回读不一致: %s", w.Body.String())
	}
}

// TestTopoViewConflictLastWriteWins 并发口径: 旧客户端(base 落后)被 409 并回当前服务器
// 版本; 合法的新版本照常覆盖。守"Chrome/Edge 双浏览器并发编辑时后写覆盖先写、旧快照不
// 回滚服务器"契约 —— 冲突回滚会让两个浏览器互相覆盖成死循环。
func TestTopoViewConflictLastWriteWins(t *testing.T) {
	h, _ := newTopoViewTestEnv(t)

	w := doReq(t, h, "PUT", "/api/v2/topo/views", topoViewTestBody)
	if w.Code != 200 {
		t.Fatalf("first put: %d %s", w.Code, w.Body.String())
	}

	// 浏览器 B 拿着旧 base(0) 试图写更旧的时间戳 → 409 + 当前服务器版本
	stale := strings.Replace(topoViewTestBody, `"updatedAt": 1000`, `"updatedAt": 999`, 1)
	w = doReq(t, h, "PUT", "/api/v2/topo/views", stale)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale put 应 409: %d %s", w.Code, w.Body.String())
	}
	var env struct {
		Data struct {
			UpdatedAt int64 `json:"updatedAt"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.Data.UpdatedAt != 1000 {
		t.Fatalf("409 应回当前服务器版本(1000): %s", w.Body.String())
	}

	// 合法新版本(base=1000, upd=2000) → 覆盖成功
	fresh := strings.Replace(topoViewTestBody, `"updatedAt": 1000`, `"updatedAt": 2000`, 1)
	fresh = strings.Replace(fresh, `"baseUpdatedAt": 0`, `"baseUpdatedAt": 1000`, 1)
	w = doReq(t, h, "PUT", "/api/v2/topo/views", fresh)
	if w.Code != 200 {
		t.Fatalf("fresh put: %d %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/v2/topo/views", "")
	if !strings.Contains(w.Body.String(), `"updatedAt":2000`) {
		t.Fatalf("新版本应落库: %s", w.Body.String())
	}
}

// TestTopoViewValidation 坏请求 400(非法 JSON / 缺 updatedAt / 空视图集)。
func TestTopoViewValidation(t *testing.T) {
	h, _ := newTopoViewTestEnv(t)

	if w := doReq(t, h, "PUT", "/api/v2/topo/views", `{bad json`); w.Code != 400 {
		t.Fatalf("坏 JSON 应 400: %d", w.Code)
	}
	if w := doReq(t, h, "PUT", "/api/v2/topo/views", `{"baseUpdatedAt":0,"active":"v","views":[{"name":"v"}]}`); w.Code != 400 {
		t.Fatalf("缺 updatedAt 应 400: %d", w.Code)
	}
	if w := doReq(t, h, "PUT", "/api/v2/topo/views", `{"updatedAt":1000,"baseUpdatedAt":0,"active":"v","views":[]}`); w.Code != 400 {
		t.Fatalf("空视图集应 400: %d", w.Code)
	}
}
