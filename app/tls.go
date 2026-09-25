package main

// HTTPS 支持(任务: TLS)。
//
// 背景: 本工具传输登录凭据/2FA 动态码/探针 token, 纯 HTTP 下局域网内任何设备
// 都能抓到明文。TLS 是"凭据不进明文"的底线, 内网自签证书即可, 不需要 CA。
//
// 配置(settings.json 的 tls 节, 默认关闭, 规则 5):
//
//	{
//	  "tls": { "enabled": true, "cert": "cert.pem", "key": "key.pem" }
//	}
//
// cert/key 支持绝对路径或 exe 同目录相对路径。enabled=true 但证书文件缺失/
// 加载失败时**降级为 HTTP 并记日志**(规则 3: 外部资源缺失降级不报错) —— 否则
// 用户配了 TLS 却忘了放证书, 服务直接起不来, 反而丢掉了"能用但明文"的兜底。

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

type tlsConfig struct {
	Enabled bool   `json:"enabled"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
}

// loadTLSConfig 读 tls 节; 缺失/解析失败返回零值(= 不启用)。
func loadTLSConfig() tlsConfig {
	var c tlsConfig
	if data, ok := section(secTLS, "tls.json"); ok && len(data) > 0 {
		_ = json.Unmarshal(data, &c)
	}
	return c
}

// tlsReady 证书可用: enabled 且两文件都能读。返回 (可启用, 原因)。
func (c tlsConfig) tlsReady() (bool, string) {
	if !c.Enabled {
		return false, "未启用"
	}
	if c.Cert == "" || c.Key == "" {
		return false, "缺少 cert/key 路径"
	}
	for _, p := range []string{c.Cert, c.Key} {
		if _, err := os.Stat(p); err != nil {
			return false, "证书文件不可读: " + p
		}
	}
	return true, ""
}

func resolveCertPath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return p
	}
	return filepath.Join(filepath.Dir(exe), p)
}

// startTLSServer 与 startServer 同端口顺延策略, 差别只在监听器带 TLS。
// 证书加载失败由调用方先经 tlsReady 拦截, 这里仍做兜底(加载失败返回错误,
// 调用方降级 HTTP)。
// httpsRedirectTarget 计算 301 跳转目标: 保留用户实际访问的主机(可能是 IP、
// 也可能是绑定域名), 只把 scheme 换成 https、端口换成 HTTPS 主服务端口。
//
// 用 r.Host 而不是本地 IP 拼: 服务可能绑局域网 IP 而用户经另一网卡/别名访问,
// 按访问者视角跳转才能"点一下还停在同一台机器上"。
func httpsRedirectTarget(r *http.Request, httpsPort int) string {
	hostPart := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		hostPart = h
	}
	return "https://" + net.JoinHostPort(hostPart, strconv.Itoa(httpsPort)) + r.URL.RequestURI()
}

// httpsRedirectHandler HTTP→HTTPS 强制跳转处理器(功能审计 1b)。
func httpsRedirectHandler(httpsPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpsRedirectTarget(r, httpsPort), http.StatusMovedPermanently)
	})
}

// startHTTPRedirectServer 起一个纯跳转的 HTTP 监听: 从 startPort 起顺延找空端口
// (HTTPS 主服务已占用起始端口, 通常落在 startPort+1)。
//
// 为什么单独一个监听而不是"同端口协议探测": TLS 握手失败的 HTTP 请求在浏览器里
// 表现为"连接错误"而非"跳转", 用户只会困惑; 给 HTTP 一个明确的端口并 301,
// 行为可预期, 日志也能把两个端口都告诉用户。
func startHTTPRedirectServer(httpsPort, startPort int, host string) (string, int, error) {
	for i := 0; i < 20; i++ {
		p := startPort + i
		if p == httpsPort {
			continue // 与 HTTPS 主服务同端口不可能成立, 防御性跳过
		}
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		go func() {
			if err := http.Serve(ln, httpsRedirectHandler(httpsPort)); err != nil {
				logLine("HTTP 跳转服务异常: " + err.Error())
			}
		}()
		return addr, p, nil
	}
	return "", 0, nil
}

func startTLSServer(mux http.Handler, startPort int, host string, cfg tlsConfig) (string, int, error) {
	cert, err := tls.LoadX509KeyPair(resolveCertPath(cfg.Cert), resolveCertPath(cfg.Key))
	if err != nil {
		return "", 0, err
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	for i := 0; i < 20; i++ {
		p := startPort + i
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		ln, err := tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			continue
		}
		go func() {
			if err := http.Serve(ln, mux); err != nil {
				logLine("HTTPS 服务异常: " + err.Error())
			}
		}()
		return addr, p, nil
	}
	return "", 0, nil // 端口全占用: 调用方改走 startServer 继续顺延
}
