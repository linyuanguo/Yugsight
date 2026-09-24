package main

// weakpass_dict_api.go 弱口令字典可视化管理(装配层, 与 scanctl_api/report_raw_api 同角色)。
//
// 数据: weak_password_dict 表(第 21 表, data/weak_password_dict.jsonl)。
//   - 首次启动自动写入 349 条内置常用弱口令(type=default), 幂等不重复;
//   - 页面新增为 type=custom; 内置条目不可删除, 重置 = 删自定义 + 恢复内置 349;
//   - 弱口令引擎执行时经 DictSource 全量加载"内置 + 自定义"(weakpass 包不 import db,
//     本文件是唯一连接点; 数据库不可用时引擎降级为嵌入内置字典, 功能不断)。
//
// 接口(全部经 /api/v2/ 前缀走 v2 统一信封, 在 registerV2Routes 内注册, 与其它 v2 路由同装配点):
//
//	GET    /api/v2/weakpass/dict              列表(分页 + 口令模糊搜索 + 类型统计)   [登录即可]
//	POST   /api/v2/weakpass/dict              新增(单条/批量)                        [admin]
//	DELETE /api/v2/weakpass/dict/{id}         删除单条(内置条目拒绝)                  [admin]
//	POST   /api/v2/weakpass/dict/batch-delete 批量删除(仅自定义)                      [admin]
//	POST   /api/v2/weakpass/dict/reset        重置为默认内置字典                      [admin]
//
// 权限口径(与任务要求一致): 读 = requireAuth(登录用户均可查看, 含操作员);
// 写 = adminOnly(编辑/重置是配置级动作, 操作员只读)。

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"yugsight/db"
	"yugsight/server"
	"yugsight/weakpass"
)

const (
	dictMaxPerBatch = 500  // 单次批量新增上限(防误粘贴整本 rockyou)
	dictMaxBatchDel = 1000 // 单次批量删除上限
)

// ===== 内置字典初始化(首次启动) =====

// ensureWeakPassDict 首次启动批量写入内置弱口令字典(幂等, best-effort)。
//
// 幂等口径: 表内已存在 type=default 条目即视为"已初始化", 整体跳过 ——
// 重复启动不重复写入(任务硬要求)。兜底场景是"表被外部清空/篡改": 此时下次
// 启动重新初始化, 内置字典是保底数据, 可恢复是任务硬要求。
//
// 挂在 v2DB() 懒加载成功路径(而非 main 启动): 数据库本身就是懒加载的,
// "首次启动"的准确语义是"数据库首次打开"。best-effort: 失败只记日志,
// 弱口令检测退回嵌入字典照常可用(规则 4 降级不崩溃)。
func ensureWeakPassDict(d *db.Database) {
	if d == nil || d.WeakPassDict() == nil {
		return
	}
	dao := d.WeakPassDict()
	n, err := dao.CountByType(db.WeakDictBuiltin)
	if err != nil || n > 0 {
		return
	}
	seeds := weakpass.BuiltinDict()
	if len(seeds) == 0 {
		logLine("弱口令字典初始化: 嵌入内置字典为空, 跳过初始化(二进制可能被裁剪, 请检查 top100.txt)")
		return
	}
	c, serr := dao.SeedBuiltin(seeds)
	if serr != nil {
		logLine("弱口令字典初始化失败(弱口令检测仍可用嵌入字典): " + serr.Error())
		return
	}
	if c > 0 {
		logLine("弱口令字典首次初始化完成: 写入内置常用弱口令 " + strconv.Itoa(c) + " 条")
	}
}

// ===== 路由注册 =====

// registerWeakPassDictRoutes 在 v2 路由组内注册字典管理接口(读 requireAuth, 写 adminOnly)。
func registerWeakPassDictRoutes(srv *server.Server) {
	srv.Get("/api/v2/weakpass/dict", requireAuth(hWeakPassDictList))
	srv.Post("/api/v2/weakpass/dict", requireAuth(adminOnly(hWeakPassDictAdd)))
	srv.Delete("/api/v2/weakpass/dict/{id}", requireAuth(adminOnly(hWeakPassDictDelete)))
	srv.Post("/api/v2/weakpass/dict/batch-delete", requireAuth(adminOnly(hWeakPassDictBatchDelete)))
	srv.Post("/api/v2/weakpass/dict/reset", requireAuth(adminOnly(hWeakPassDictReset)))
}

// weakPassDictStats 字典类型统计(供 /api/authcheck/status 的 dictStats 字段)。
// 降级口径: 库不可用 / DAO 为空返回全 0 结构(不报错), 前端据此显示"内置 N · 自定义 0"。
func weakPassDictStats() map[string]int {
	out := map[string]int{"builtin": 0, "custom": 0}
	d := v2DB()
	if d == nil || d.WeakPassDict() == nil {
		return out
	}
	if n, err := d.WeakPassDict().CountByType(db.WeakDictBuiltin); err == nil {
		out["builtin"] = n
	}
	if n, err := d.WeakPassDict().CountByType(db.WeakDictCustom); err == nil {
		out["custom"] = n
	}
	return out
}

// weakPassDictDAO 取字典 DAO(统一降级: 库不可用返回 503 而非 panic)。
func weakPassDictDAO(w http.ResponseWriter) *db.WeakPassDictDAO {
	d := v2NeedDB(w)
	if d == nil {
		return nil
	}
	dao := d.WeakPassDict()
	if dao == nil {
		server.FailInternal(w, "弱口令字典表不可用")
		return nil
	}
	return dao
}

// ===== 接口实现 =====

// hWeakPassDictList GET /api/v2/weakpass/dict?page=&size=&q=
//
// 响应: items(页内) + total(搜索后总数) + builtinCount/customCount(全量类型统计,
// 供前端"内置 349 · 自定义 N"徽标)。搜索=口令大小写不敏感包含; 分页在搜索后做。
func hWeakPassDictList(w http.ResponseWriter, r *http.Request) {
	dao := weakPassDictDAO(w)
	if dao == nil {
		return
	}
	q := r.URL.Query().Get("q")
	page, size := parsePage(r.URL.Query())

	var (
		all []*db.WeakPassDictEntry
		err error
	)
	if strings.TrimSpace(q) == "" {
		all, err = dao.List()
	} else {
		all, err = dao.Search(q)
	}
	if err != nil {
		server.FailInternal(w, "字典列表读取失败: "+err.Error())
		return
	}
	bc, _ := dao.CountByType(db.WeakDictBuiltin)
	cc, _ := dao.CountByType(db.WeakDictCustom)
	server.OK(w, map[string]any{
		"items":        paginate(all, page, size),
		"total":        len(all),
		"page":         page,
		"size":         size,
		"builtinCount": bc,
		"customCount":  cc,
	})
}

// hWeakPassDictAdd POST /api/v2/weakpass/dict  body: {"passwords": ["a", "b"]}
//
// 单条即长度 1 的数组, 单条/批量共用一条接口(任务要求)。
// 语义: 批内去重 + 与库存精确判重; 已存在的口令跳过并在响应里列明(skipped),
// 不让用户以为"添加成功"实际没进去。新增一律 type=custom。
func hWeakPassDictAdd(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	dao := d.WeakPassDict()
	if dao == nil {
		server.FailInternal(w, "弱口令字典表不可用")
		return
	}
	var in struct {
		Passwords []string `json:"passwords"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Passwords) == 0 {
		server.FailBadRequest(w, "passwords 为空")
		return
	}
	if len(in.Passwords) > dictMaxPerBatch {
		server.FailBadRequest(w, "单次批量新增上限 "+strconv.Itoa(dictMaxPerBatch)+" 条")
		return
	}
	added, skipped, err := dictAddEntries(dao, in.Passwords)
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	total, _ := dao.Count()
	logAudit(d, r, "weakpass.dict.add", "", "新增弱口令 "+strconv.Itoa(added)+" 条, 跳过重复 "+strconv.Itoa(len(skipped)))
	server.OK(w, map[string]any{
		"added":   added,
		"skipped": skipped,
		"total":   total,
	})
}

// dictAddEntries 判重 + 写入(抽出供单测)。返回(新增数, 被跳过的口令, 错误)。
func dictAddEntries(dao *db.WeakPassDictDAO, passwords []string) (int, []string, error) {
	skipped := []string{}
	added := 0
	for _, raw := range passwords {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if len(p) > db.WeakDictMaxPasswordLen {
			skipped = append(skipped, p[:min(len(p), 16)]+"…(超长)")
			continue
		}
		// 批内去重: 同批里重复的口令只写一次
		if containsDictPassword(skipped, p) {
			continue
		}
		if existing, _ := dao.FindByPassword(p); existing != nil {
			skipped = append(skipped, p)
			continue
		}
		e := &db.WeakPassDictEntry{Password: p, Type: db.WeakDictCustom, CreateTime: time.Now()}
		if err := dao.Create(e); err != nil {
			return added, skipped, err
		}
		added++
	}
	return added, skipped, nil
}

func containsDictPassword(list []string, p string) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

// hWeakPassDictDelete DELETE /api/v2/weakpass/dict/{id}
//
// 内置条目拒绝删除(任务硬要求): 400 明确告知, 而不是静默成功。
func hWeakPassDictDelete(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	dao := d.WeakPassDict()
	if dao == nil {
		server.FailInternal(w, "弱口令字典表不可用")
		return
	}
	id := r.PathValue("id")
	e, err := dao.Get(id)
	if err != nil {
		server.FailNotFound(w, "条目不存在")
		return
	}
	if e.Type == db.WeakDictBuiltin {
		server.FailBadRequest(w, "内置条目不可删除(需要恢复默认请用重置)")
		return
	}
	ok, err := dao.Delete(id)
	if err != nil {
		server.FailInternal(w, "删除失败: "+err.Error())
		return
	}
	if !ok {
		server.FailNotFound(w, "条目不存在(可能已被并发删除)")
		return
	}
	logAudit(d, r, "weakpass.dict.delete", id, "删除自定义弱口令: "+e.Password)
	server.OK(w, map[string]any{"deleted": 1})
}

// hWeakPassDictBatchDelete POST /api/v2/weakpass/dict/batch-delete  body: {"ids": [...]}
//
// 混合选择时的口径: 内置条目不删、计数告知(skippedBuiltin), 自定义条目照删。
// 前端本就不允许勾选内置行, 这里是对 API 直调的兜底。
func hWeakPassDictBatchDelete(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	dao := d.WeakPassDict()
	if dao == nil {
		server.FailInternal(w, "弱口令字典表不可用")
		return
	}
	var in struct {
		IDs []string `json:"ids"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.IDs) == 0 {
		server.FailBadRequest(w, "ids 为空")
		return
	}
	if len(in.IDs) > dictMaxBatchDel {
		server.FailBadRequest(w, "单次批量删除上限 "+strconv.Itoa(dictMaxBatchDel)+" 条")
		return
	}
	deleted, skippedBuiltin := 0, 0
	for _, id := range in.IDs {
		e, err := dao.Get(id)
		if err != nil {
			continue // 不存在(已删/无效 ID) 静默跳过, 不阻断整批
		}
		if e.Type == db.WeakDictBuiltin {
			skippedBuiltin++
			continue
		}
		if ok, _ := dao.Delete(id); ok {
			deleted++
		}
	}
	logAudit(d, r, "weakpass.dict.batch-delete", "", "批量删除弱口令 "+strconv.Itoa(deleted)+" 条, 内置跳过 "+strconv.Itoa(skippedBuiltin))
	server.OK(w, map[string]any{"deleted": deleted, "skippedBuiltin": skippedBuiltin})
}

// hWeakPassDictReset POST /api/v2/weakpass/dict/reset
//
// 重置 = 清空全表 + 重灌内置 349: 比"只删自定义"更强, 覆盖内置条目被外部
// 篡改/删缺的场景, 保证重置后字典必然回到"内置 349 条"的确定状态(任务硬要求)。
func hWeakPassDictReset(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	dao := d.WeakPassDict()
	if dao == nil {
		server.FailInternal(w, "弱口令字典表不可用")
		return
	}
	cc, _ := dao.CountByType(db.WeakDictCustom)
	cleared, err := dao.Clear()
	if err != nil {
		server.FailInternal(w, "重置失败: "+err.Error())
		return
	}
	seeds := weakpass.BuiltinDict()
	restored, err := dao.SeedBuiltin(seeds)
	if err != nil {
		server.FailInternal(w, "重置失败(清空已生效, 内置恢复失败, 请重试): "+err.Error())
		return
	}
	logAudit(d, r, "weakpass.dict.reset", "",
		"重置弱口令字典: 清空 "+strconv.Itoa(cleared)+" 条(含自定义 "+strconv.Itoa(cc)+"), 恢复内置 "+strconv.Itoa(restored))
	server.OK(w, map[string]any{
		"deleted":  cleared,
		"custom":   cc,
		"builtin":  restored,
	})
}
