package main

// topo_view_api.go 拓扑视图服务端持久化(2026-10-02 用户要求: "chrome和edge显示网络拓扑
// 不一样, edge老是显示老缓存不会自动更新")。
//
// 【根因】拓扑视图(多套文档: 节点/链路/框)此前只存各浏览器 localStorage
// (yugsight_topo_views_v2) —— 同一地址不同浏览器各自一份(Edge 里画过路由器, Chrome
// 里没有), 一边编辑另一边永远看不到, 浏览器里的旧视图又表现为"老缓存不更新"。
// 【改法】中心端 data/topo_views.json 成为跨浏览器唯一事实来源; 浏览器 localStorage
// 只保留两个用途: 首帧立即渲染 + 离线兜底(规则 3: 降级不报错)。
//
// 同步模型(last-write-wins + 冲突检测, 前端口径见 topoViews.js 头部):
//   - 客户端记住最近看到的服务器版本(baseUpdatedAt); PUT 时 base < 服务器当前值
//     (另一个浏览器已写入更新的版本) → 409 并回当前服务器版本, 客户端弃本地旧快照直接
//     采用服务器版本(视图是用户手工摆的文档, 无字段级合并价值, 整包取舍最简单);
//   - 客户端 30s 轮询: 服务器版本比本地新 → 采用(跨浏览器自动更新, 无需刷新页面)。
//
// 单文档原子写(tmp+rename, 与 settings.json 同口径); 体积上限 2MB(视图是手绘拓扑,
// 正常几十 KB, 上限防 localStorage 溢出时代的历史脏数据被推上来占盘)。

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"yugsight/internal/server"
)

// topoViewsMaxSize 视图文档体积上限(含 views 数组全文)。
const topoViewsMaxSize = 2 * 1024 * 1024

// topoViewDoc 整份拓扑视图仓库(与前端 yugsight_topo_views_v2 的 active/views 同构;
// updatedAt 是客户端 Date.now() 毫秒时间戳, 只用来比新旧, 不当绝对时间用)。
// BaseUpdatedAt 只进不出: PUT 请求里客户端带上"我最近看到的服务器版本", 服务器据此
// 判冲突; 持久化的文档里它是 0, 无意义。
type topoViewDoc struct {
	UpdatedAt     int64          `json:"updatedAt"`
	BaseUpdatedAt int64          `json:"baseUpdatedAt"`
	Active        string         `json:"active"`
	Views         []map[string]any `json:"views"`
}

// topoViewPathOverride 测试注入口(与 testSettingsPath 同手法): 单测把文件指到
// t.TempDir, 避免写到真实 exe 目录。
var topoViewPathOverride atomic.Value // string

func setTopoViewTestPath(p string) { topoViewPathOverride.Store(p) }

func topoViewPath() string {
	if v, ok := topoViewPathOverride.Load().(string); ok && v != "" {
		return v
	}
	return filepath.Join(exeDir(), "data", "topo_views.json")
}

var topoViewMu sync.RWMutex

// loadTopoViewDoc 读盘(无文件/坏 JSON = 空, 降级不报错)。
func loadTopoViewDoc() *topoViewDoc {
	topoViewMu.RLock()
	defer topoViewMu.RUnlock()
	return loadTopoViewDocLocked()
}

// saveTopoViewDoc 原子写(tmp+rename, 崩溃不留半截 JSON)。
func saveTopoViewDoc(d *topoViewDoc) error {
	topoViewMu.Lock()
	defer topoViewMu.Unlock()
	return saveTopoViewDocLocked(d)
}

// hTopoViewsGet GET /api/v2/topo/views
// 返回整份仓库; 无数据时回 updatedAt=0 空文档(前端据此判定"服务器还没有视图"
// —— 首次部署时本地视图要主动推上去, 而不是被空文档覆盖)。
func hTopoViewsGet(w http.ResponseWriter, r *http.Request) {
	d := loadTopoViewDoc()
	if d == nil {
		server.OK(w, map[string]any{"updatedAt": 0, "active": "", "views": []any{}})
		return
	}
	server.OK(w, d)
}

// hTopoViewsPut PUT /api/v2/topo/views
// body: {updatedAt, baseUpdatedAt, active, views}
//   - updatedAt=0 或 views 为空 → 400(至少一套视图是前端硬约束, 删光不合法);
//   - baseUpdatedAt < 服务器当前 updatedAt → 409 + 当前服务器版本(冲突, 客户端采用);
//   - 其余 → 覆盖保存并回保存后的文档。
func hTopoViewsPut(w http.ResponseWriter, r *http.Request) {
	var body topoViewDoc
	// LimitReader 兜体积上限: 超限直接解码失败 → 400(不整包读进内存)
	if err := json.NewDecoder(io.LimitReader(r.Body, topoViewsMaxSize)).Decode(&body); err != nil {
		server.FailBadRequest(w, "请求体非法或超过 2MB 上限: "+err.Error())
		return
	}
	if body.UpdatedAt <= 0 {
		server.FailBadRequest(w, "updatedAt 必填(客户端毫秒时间戳)")
		return
	}
	if len(body.Views) == 0 {
		server.FailBadRequest(w, "至少需要一套视图")
		return
	}

	topoViewMu.Lock()
	cur := loadTopoViewDocLocked()
	if cur != nil && body.BaseUpdatedAt < cur.UpdatedAt {
		// 冲突: 另一个浏览器在我们上次拉取之后写入了更新的版本。
		// 回当前服务器版本(客户端整包采用), 不报错语义 —— 这是预期内的并发, 不是故障。
		topoViewMu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    0,
			"message": "conflict",
			"data":    cur,
		})
		return
	}
	if err := saveTopoViewDocLocked(&body); err != nil {
		topoViewMu.Unlock()
		server.FailInternal(w, "视图保存失败: "+err.Error())
		return
	}
	topoViewMu.Unlock()
	server.OK(w, body)
}

// loadTopoViewDocLocked 无锁读(调用方持 topoViewMu)。
func loadTopoViewDocLocked() *topoViewDoc {
	data, err := os.ReadFile(topoViewPath())
	if err != nil {
		return nil
	}
	var d topoViewDoc
	if err := json.Unmarshal(data, &d); err != nil || len(d.Views) == 0 {
		return nil
	}
	return &d
}

// saveTopoViewDocLocked 无锁写(调用方持 topoViewMu)。
func saveTopoViewDocLocked(d *topoViewDoc) error {
	dir := filepath.Dir(topoViewPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	tmp := topoViewPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, topoViewPath())
}

// registerTopoViewRoutes 装配(挂 /api/v2 子树, 与链路接口同一鉴权口径)。
func registerTopoViewRoutes(srv *server.Server) {
	srv.Get("/api/v2/topo/views", requireAuth(hTopoViewsGet))
	srv.Put("/api/v2/topo/views", requireAuth(hTopoViewsPut))
}
