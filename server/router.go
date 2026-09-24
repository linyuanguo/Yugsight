package server

import (
	"net/http"
	"strings"
)

// HandlerFunc 路由处理函数(与 http.HandlerFunc 同形)。
type HandlerFunc = http.HandlerFunc

// Router 路由表: http.ServeMux 的薄封装(Go 1.22+ 内置支持
// "METHOD /path/{param}" 模式, 路径参数经 r.PathValue 获取)。
//
// 统一路由前缀: v2 API 组约定挂 /api/v2/ 前缀, 本路由不强制前缀,
// 由调用方在 pattern 中显式携带, 便于多组 API 共存。
type Router struct {
	mux *http.ServeMux
}

// NewRouter 创建空路由表。
func NewRouter() *Router {
	return &Router{mux: http.NewServeMux()}
}

// Mux 暴露底层 ServeMux(供需要直接 Handle 子树的场景)。
func (r *Router) Mux() *http.ServeMux {
	return r.mux
}

// normPattern 规范化路径: 保证以 / 开头。
func normPattern(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// Route 注册路由。method 为空表示匹配全部方法。
//
// pattern 支持 Go 1.22+ 路径参数, 例: "GET /api/v2/assets/{id}"。
func (r *Router) Route(method, pattern string, h HandlerFunc) {
	p := normPattern(pattern)
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		r.mux.HandleFunc(p, h)
		return
	}
	r.mux.HandleFunc(m+" "+p, h)
}

// Get 注册 GET 路由。
func (r *Router) Get(pattern string, h HandlerFunc) {
	r.Route(http.MethodGet, pattern, h)
}

// Post 注册 POST 路由。
func (r *Router) Post(pattern string, h HandlerFunc) {
	r.Route(http.MethodPost, pattern, h)
}

// Put 注册 PUT 路由。
func (r *Router) Put(pattern string, h HandlerFunc) {
	r.Route(http.MethodPut, pattern, h)
}

// Delete 注册 DELETE 路由。
func (r *Router) Delete(pattern string, h HandlerFunc) {
	r.Route(http.MethodDelete, pattern, h)
}
