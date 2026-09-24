package main

// vue_ui.go 任务 4.3: Vue3 前端(frontend/)构建产物经 go:embed 嵌入主程序。
//
// - 前端工程在 frontend/ (Vite + Vue3 + vue-router, hash 路由), 构建产物 frontend/dist/
//   是 go:embed 的嵌入源, 必须先构建 dist 再 go build(缺失时编译失败, 属预期行为)
// - 单文件 exe 离线即可加载 Web 界面, 零外部静态资源依赖
// - 挂载点 /app/: 静态文件直出, 其余路径回退 index.html(SPA 兜底; hash 路由下非必需)
// - 主页 / 默认仍是经典单文件页(web/index.html); -ui=vue 启动时主页切换到 Vue3 前端
//   (新功能默认关闭, 不影响原有流程)
//
// 构建顺序: cd frontend && npm install && npm run build && go build .

import (
	"embed"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed all:frontend/dist
// 【为什么必须写 all: 前缀】go:embed 默认排除以 "_" 或 "." 开头的文件。
// Vite 会产出 assets/_plugin-vue_export-helper-<hash>.js(SFC 复用的公共 helper),
// 不加 all: 就被悄悄排除 → 服务端对该文件 404 → 所有静态 import 它的页面 chunk
// 加载失败(浏览器报 "Failed to fetch dynamically imported module") → 点菜单没反应;
// 不引用它的页面照常打开, 且静态请求不进 HTTP 日志, 极难发现。
var vueFS embed.FS

// vueMime 静态资源的 Content-Type, 带本地兜底表。
//
// 【为什么不用 mime.TypeByExtension 直接返回】Go 的 mime 包在 Windows 上会从
// 注册表(HKCR\.ext\Content Type)加载映射 —— 实测用户机器上 .js 的注册表项被
// 其他软件改动/清空, TypeByExtension(".js") 返回 "", 响应头 Content-Type 为空。
// 浏览器对 <script type="module"> 强制校验 MIME(HTML 规范 strict MIME checking),
// 空 MIME → 拒绝执行 → Vue 不挂载 → 整页黑屏, 而服务端 curl 验证一切"正常"。
// 因此前端产物类型必须本地硬编码, 注册表只作未知扩展名的最后兜底。
func vueMime(p string) string {
	switch strings.ToLower(path.Ext(p)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json", ".map":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".ico":
		return "image/x-icon"
	case ".webp":
		return "image/webp"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".wasm":
		return "application/wasm"
	case ".txt":
		return "text/plain; charset=utf-8"
	}
	if m := mime.TypeByExtension(strings.ToLower(path.Ext(p))); m != "" {
		return m
	}
	return "application/octet-stream"
}

// handleVueApp 处理 /app 与 /app/*:
// /app -> 302 /app/; 已嵌入的静态文件 -> 直出(assets 长缓存, index.html 不缓存);
// 其余路径 -> index.html(SPA 兜底)。
func handleVueApp(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/app" {
		http.Redirect(w, r, "/app/", http.StatusFound)
		return
	}
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/app"), "/")
	if p != "" && !strings.HasPrefix(p, "..") {
		if data, err := vueFS.ReadFile("frontend/dist/" + p); err == nil {
			w.Header().Set("Content-Type", vueMime(p))
			if strings.HasPrefix(p, "assets/") {
				// vite 产物文件名带内容 hash, 可长缓存
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			w.Write(data)
			return
		}
		// assets/ 下未命中必须 404, 不能落进 SPA 兜底返回 index.html:
		// <script type="module"> 拿到一段 HTML 会解析成 JS 语法错误, 整页黑屏
		// 且无任何报错线索(升级后旧标签页引用旧 hash 资源正是这条路径)。
		// 404 让浏览器控制台直接给出可定位的错, 前端自愈脚本也依赖它触发刷新。
		if strings.HasPrefix(p, "assets/") {
			http.NotFound(w, r)
			return
		}
	}
	// 兜底: index.html
	data, err := vueFS.ReadFile("frontend/dist/index.html")
	if err != nil {
		http.Error(w, "Vue3 前端未嵌入(frontend/dist 缺失, 请先 npm run build)", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}
