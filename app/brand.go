// brand.go 品牌自定义(brand 节)与原始项目合规常量。
//
// 品牌自定义(2026-09-28):
//   - brand 节是标准节式管理(与 engine/auth 等节平级): 缺失时用默认值
//     (原始项目名/版权)运行, 已有配置升级后 brand 节缺失不影响正常运行;
//     保存走 writeSection(secBrand, ...) 合并写, 保存后立即生效, 无需重启
//     服务(前端在页面渲染时取品牌值, 不落进程级缓存)。
//   - originalName / originalCopyright 是全局只读常量(代码内写死, 不暴露配置
//     入口): 页面页脚固定显示「基于 Yugsight 御视 引擎构建」, 用于合规保留
//     对原始项目的署名 —— 这是固定表述, 与品牌配置无关, 也不占用配置项。
//
// 显示位置(仅替换现有位置, 不新增页面/UI 元素):
//   - 浏览器标签页标题(Vue index.html 静态兜底 + 运行时 /api/info 覆盖;
//     经典页 JS 同步覆盖)
//   - Vue 侧边栏顶部系统名称(Layout.vue brand 区)
//   - 全局页脚(经典页 footer: 主行 = copyright, 下方极小字 = 原始项目署名)
//
// API(授权与模型页「品牌自定义」面板):
//   - GET  /api/v2/brand  品牌读取(requireAuth, 登录角色均可查看)
//   - POST /api/v2/brand  品牌保存(requireAuth + adminOnly —— 授权与模型页
//     是管理员专属域, 与同页用户管理/审计配置同一权限口径)

package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"yugsight/internal/server"
)

// originalName 原始项目名(全局只读常量, 合规展示用, 不可配置)。
const originalName = "Yugsight 御视"

// originalCopyright 原始项目版权(全局只读常量, 合规展示用, 不可配置)。
const originalCopyright = "Copyright © 2026 Yugsight"

// brandConfig brand 节配置(标准节式管理, 节约定见 settings.go 文件头)。
type brandConfig struct {
	SystemName string `json:"system_name"` // 系统显示名称(默认 = originalName)
	Copyright  string `json:"copyright"`   // 页脚版权文字(默认 = originalCopyright)
}

// loadBrand 读 brand 节; 缺失/解析失败时返回原始项目品牌(默认值)。
//
// 每次调用实时读配置中心(不缓存): 与 /api/v2/config/reload 的热重载机制
// 天然兼容 —— 保存后下一个请求即可读到新值, 无需重启。
func loadBrand() brandConfig {
	cfg := brandConfig{SystemName: originalName, Copyright: originalCopyright}
	data, ok := section(secBrand, "")
	if !ok {
		return cfg
	}
	var raw brandConfig
	if json.Unmarshal(data, &raw) != nil {
		logLine("brand 节解析失败, 使用默认品牌")
		return cfg
	}
	if s := strings.TrimSpace(raw.SystemName); s != "" {
		cfg.SystemName = s
	}
	if c := strings.TrimSpace(raw.Copyright); c != "" {
		cfg.Copyright = c
	}
	return cfg
}

// brandPublic 只读品牌对象(original_name 供页脚署名展示, 不可配置)。
func brandPublic() map[string]any {
	b := loadBrand()
	return map[string]any{
		"system_name":   b.SystemName,
		"copyright":     b.Copyright,
		"original_name": originalName,
	}
}

// RegisterBrandRoutes 注册品牌自定义路由(v2 装配时调用)。
func RegisterBrandRoutes(srv *server.Server) {
	srv.Get("/api/v2/brand", requireAuth(hBrandGet))
	srv.Post("/api/v2/brand", requireAuth(adminOnly(hBrandSave)))
}

// hBrandGet GET /api/v2/brand 当前品牌配置。
func hBrandGet(w http.ResponseWriter, r *http.Request) {
	server.OK(w, brandPublic())
}

// brandFieldMaxLen 品牌字段长度上限(防止把超长文本塞进标题/页脚)。
const brandFieldMaxLen = 120

// hBrandSave POST /api/v2/brand 保存品牌(adminOnly)。
//
// writeSection 合并写: 只替换 brand 节, 其它节(含用户手写注释)字节原样
// 保留 —— 与 saveAuth 等所有节保存同一红线口径。
func hBrandSave(w http.ResponseWriter, r *http.Request) {
	var req brandConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		server.FailBadRequest(w, "请求体解析失败: "+err.Error())
		return
	}
	req.SystemName = strings.TrimSpace(req.SystemName)
	req.Copyright = strings.TrimSpace(req.Copyright)
	if req.SystemName == "" || req.Copyright == "" {
		server.FailBadRequest(w, "系统名称与版权信息不能为空")
		return
	}
	if len([]rune(req.SystemName)) > brandFieldMaxLen || len([]rune(req.Copyright)) > brandFieldMaxLen {
		server.FailBadRequest(w, "系统名称/版权信息长度不能超过 120 字符")
		return
	}
	if err := writeSection(secBrand, req); err != nil {
		server.FailInternal(w, "品牌配置保存失败: "+err.Error())
		return
	}
	// 立即生效: writeSection 只落盘, 内存缓存仍是旧快照, 必须重置 ——
	// 否则下一个 GET 读到的还是旧品牌(与 ai/weakpass 保存同一口径)。
	resetSettingsCache()
	logLine("品牌自定义已保存: system_name=" + req.SystemName)
	server.OK(w, brandPublic())
}
