package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// Server Web 服务: 路由表 + 中间件链 + 生命周期(启动/停止)。
//
// 两种使用方式:
//  1. Handler() 生成最终 http.Handler, 挂载到既有 mux(子树前缀, 与旧接口共存);
//  2. ListenAndServe 独立监听端口(中心管理端独立部署场景)。
//
// 全局异常捕获(Recover)由 Handler() 内置在最外层, 无需手动添加;
// 其余中间件经 WithMiddleware 注入。
type Server struct {
	router *Router
	mws    []Middleware
	logf   func(string)
	ln     net.Listener
}

// Option 服务配置项。
type Option func(*Server)

// WithLogger 注入日志函数(缺省写 stderr)。
func WithLogger(f func(string)) Option {
	return func(s *Server) {
		if f != nil {
			s.logf = f
		}
	}
}

// WithMiddleware 追加中间件(按传入顺序组装, 第一个最外层)。
func WithMiddleware(mws ...Middleware) Option {
	return func(s *Server) {
		s.mws = append(s.mws, mws...)
	}
}

// New 创建服务(默认中间件: 仅内置全局 recover)。
func New(opts ...Option) *Server {
	s := &Server{
		router: NewRouter(),
		logf:   func(msg string) { fmt.Fprintln(os.Stderr, "[server] "+msg) },
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Log 暴露日志函数(中间件/路由使用)。
func (s *Server) Log() func(string) { return s.logf }

// Router 暴露路由表。
func (s *Server) Router() *Router { return s.router }

// Route 注册路由(透传路由表)。
func (s *Server) Route(method, pattern string, h HandlerFunc) { s.router.Route(method, pattern, h) }

// Get 注册 GET 路由。
func (s *Server) Get(pattern string, h HandlerFunc) { s.router.Get(pattern, h) }

// Post 注册 POST 路由。
func (s *Server) Post(pattern string, h HandlerFunc) { s.router.Post(pattern, h) }

// Put 注册 PUT 路由。
func (s *Server) Put(pattern string, h HandlerFunc) { s.router.Put(pattern, h) }

// Delete 注册 DELETE 路由。
func (s *Server) Delete(pattern string, h HandlerFunc) { s.router.Delete(pattern, h) }

// Handler 组装最终处理器: 全局 recover(最外层) -> 用户中间件 -> 路由。
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.router.mux
	for i := len(s.mws) - 1; i >= 0; i-- {
		h = s.mws[i](h)
	}
	return Recover(s.logf)(h)
}

// ListenAndServe 独立监听: 从 startPort 起尝试 20 个端口(与主服务行为一致),
// 返回实际监听地址与端口。startPort=0 表示由系统随机分配端口。
func (s *Server) ListenAndServe(host string, startPort int) (string, int, error) {
	for i := 0; i < 20; i++ {
		p := startPort + i
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		s.ln = ln
		actual := ln.Addr().String() // 端口 0 时系统随机分配, 取实际端口
		_, actualPort, _ := net.SplitHostPort(actual)
		port := p
		if n, aerr := strconv.Atoi(actualPort); aerr == nil {
			port = n
		}
		go func() {
			if err := http.Serve(ln, s.Handler()); err != nil {
				s.logf("HTTP 服务异常: " + err.Error())
			}
		}()
		return actual, port, nil
	}
	return "", 0, fmt.Errorf("端口 %d-%d 均被占用, 请关闭占用程序后重试", startPort, startPort+19)
}

// Close 停止服务(仅独立监听模式有效)。
func (s *Server) Close() error {
	if s.ln == nil {
		return nil
	}
	err := s.ln.Close()
	s.ln = nil
	return err
}

// PingHandler 默认健康检查 handler(示例)。
func PingHandler(w http.ResponseWriter, _ *http.Request) {
	OK(w, map[string]any{"ok": true, "time": time.Now().Format(time.RFC3339)})
}
