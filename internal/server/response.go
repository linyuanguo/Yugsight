// Package server Yugsight 第二阶段 Web 服务基础框架(任务 4.1)。
//
// 职责: 统一路由、统一响应结构、错误码、全局异常捕获、中间件链。
//
// 设计原则(对齐项目硬约束: 纯 Go 标准库、零第三方依赖、单二进制跨平台):
//   - 路由基于 Go 1.22+ net/http 内置的 "方法 + 路径参数" 模式,
//     如 "GET /api/v2/assets/{id}", 无需第三方路由库
//   - 统一响应结构 Resp{code,message,data} + 业务错误码,
//     业务 handler 只需调用 OK / Fail, 不再手写 JSON
//   - 全局异常捕获: 任意 handler 的 panic 被中间件捕获并返回 500 统一响应,
//     不导致服务宕机
//   - 中间件链可组合: recover(内置) -> CORS -> 请求日志 -> 路由
//
// 本包仅依赖 Go 标准库。
package server

import (
	"encoding/json"
	"net/http"
)

// Resp 统一 API 响应结构。
//
// Code=0 表示成功; 非 0 为业务错误码(见下方常量, 前缀对齐 HTTP 状态码语义)。
// 旧 /api/* 接口(报告/扫描 SSE 等)保持原有格式不受影响, 统一格式用于 /api/v2/ 组。
type Resp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// 业务错误码(0 = 成功)。
const (
	CodeOK             = 0     // 成功
	CodeBadRequest     = 40000 // 请求参数错误
	CodeUnauthorized   = 40100 // 未登录 / 会话失效
	CodeForbidden      = 40300 // 无权限
	CodeNotFound       = 40400 // 资源不存在
	CodeMethodNotAllow = 40500 // 请求方法不允许
	CodeConflict       = 40900 // 资源冲突
	CodeInternal       = 50000 // 服务内部错误
	CodeDBUnavailable  = 50300 // 数据库不可用(初始化失败, 降级运行)
)

// OK 返回成功响应(data 可为 nil)。
func OK(w http.ResponseWriter, data any) {
	writeResp(w, http.StatusOK, CodeOK, "ok", data)
}

// Fail 返回错误响应: httpStatus 为 HTTP 状态码, code 为业务错误码, msg 为提示。
func Fail(w http.ResponseWriter, httpStatus, code int, msg string) {
	writeResp(w, httpStatus, code, msg, nil)
}

// FailBadRequest 参数错误(400)
func FailBadRequest(w http.ResponseWriter, msg string) {
	Fail(w, http.StatusBadRequest, CodeBadRequest, msg)
}

// FailNotFound 资源不存在(404)
func FailNotFound(w http.ResponseWriter, msg string) {
	Fail(w, http.StatusNotFound, CodeNotFound, msg)
}

// FailInternal 内部错误(500)
func FailInternal(w http.ResponseWriter, msg string) {
	Fail(w, http.StatusInternalServerError, CodeInternal, msg)
}

func writeResp(w http.ResponseWriter, status, code int, msg string, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Resp{Code: code, Message: msg, Data: data})
}
