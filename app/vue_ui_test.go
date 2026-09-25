package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// 前端构建产物必须嵌入二进制(单文件运行加载 Web 界面的前提)
func TestVueFSEmbedded(t *testing.T) {
	if _, err := fs.Stat(vueFS, "frontend/dist/index.html"); err != nil {
		t.Fatalf("frontend/dist/index.html 未嵌入: %v (先执行 cd frontend && npm install && npm run build)", err)
	}
}

// 嵌入内容必须与磁盘 dist **逐文件一致**, 一个都不能少。
//
// 【为什么必须守这条】go:embed 默认排除以 "_" 或 "." 开头的文件(目录模式与 glob 均如此),
// 必须写 `all:` 前缀才会包含。Vite 会产出 assets/_plugin-vue_export-helper-<hash>.js,
// 被悄悄排除后: 服务端对该文件 404 → 所有静态 import 它的页面 chunk 加载失败
// (Chrome 报 "Failed to fetch dynamically imported module") → 点菜单没反应,
// 而不引用它的页面照常打开, 极难从服务端日志发现(静态请求不进 HTTP 日志)。
// 这条契约静默失效过一次(2026-09-22 9 个页面点不开), 故用"磁盘全量比对"钉死。
func TestVueFSEmbeddedMatchesDisk(t *testing.T) {
	walkErr := fs.WalkDir(os.DirFS("frontend/dist"), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if _, statErr := fs.Stat(vueFS, "frontend/dist/"+p); statErr != nil {
			t.Errorf("磁盘 frontend/dist/%s 未嵌入(go:embed 是否漏了 all: 前缀?): %v", p, statErr)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("遍历磁盘 frontend/dist 失败: %v", walkErr)
	}
}

func TestHandleVueAppServesIndex(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app/", nil)
	w := httptest.NewRecorder()
	handleVueApp(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d: %s", w.Code, w.Body.String()[:min(200, w.Body.Len())])
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	if !strings.Contains(w.Body.String(), "<div id=\"app\">") {
		t.Fatalf("index.html 内容异常: 缺少挂载节点")
	}
}

func TestHandleVueAppRedirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	w := httptest.NewRecorder()
	handleVueApp(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expect 302, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/app/" {
		t.Fatalf("location = %q", loc)
	}
}

// SPA 兜底: 未知路径回退 index.html
func TestHandleVueAppSPAFallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app/some/unknown/route", nil)
	w := httptest.NewRecorder()
	handleVueApp(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expect 200 (SPA fallback), got %d", w.Code)
	}
}

// assets 下不存在的文件必须 404, 绝不能落进 SPA 兜底返回 index.html:
// <script type="module"> 拿到 HTML 会解析成 JS 语法错误 → 整页黑屏且无报错线索。
// 升级后旧标签页引用旧 hash 资源正是这条路径(实测用户现场黑屏的根因)。
func TestHandleVueAppMissingAssetIs404(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app/assets/definitely-not-exist-000.js", nil)
	w := httptest.NewRecorder()
	handleVueApp(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expect 404, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "<div id=\"app\">") {
		t.Fatal("404 响应体不得包含 index.html 内容(会把 HTML 毒化进 <script>)")
	}
}

// index.html 必须自带"资源加载失败自动刷新"自愈脚本 —— 升级后旧标签页的唯一
// 无感恢复手段, 丢了用户就得手动强刷才能看到页面。
func TestHandleVueAppIndexHasHealScript(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app/", nil)
	w := httptest.NewRecorder()
	handleVueApp(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "yugsight_heal") || !strings.Contains(body, "location.reload()") {
		t.Fatal("index.html 缺少资源加载失败自愈脚本(旧标签页黑屏无法自动恢复)")
	}
}

// JS 的 Content-Type 必须是 text/javascript 且不得依赖 Windows 注册表:
// mime.TypeByExtension 在注册表 .js 项被其他软件改动/清空时返回空字符串,
// 浏览器对 <script type="module"> 强制校验 MIME(HTML 规范), 空 MIME → 拒绝
// 执行 → Vue 不挂载 → 整页黑屏(实测用户现场黑屏的真正根因)。
func TestHandleVueAppJSMimeType(t *testing.T) {
	entries, err := fs.ReadDir(vueFS, "frontend/dist/assets")
	if err != nil {
		t.Fatalf("assets 目录不存在(先 npm run build): %v", err)
	}
	name := ""
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".js") {
			name = e.Name()
			break
		}
	}
	if name == "" {
		t.Fatal("assets 下没有任何 .js 产物")
	}
	req := httptest.NewRequest(http.MethodGet, "/app/assets/"+name, nil)
	w := httptest.NewRecorder()
	handleVueApp(w, req)
	if ct := w.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Fatalf("JS Content-Type = %q, 必须 text/javascript; charset=utf-8 (空 MIME 会导致浏览器拒绝执行, 页面黑屏)", ct)
	}
}
