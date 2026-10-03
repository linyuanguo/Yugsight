package main

// 连通性测试(节点配置 → 连通性测试; 2026-09-30 用户反馈后由"前端纯模拟"改为真实探测)。
//
// 背景: 此前 ConnectivityTest.vue 是本地随机模拟(78% 可达 / 12% 超时 / 10% 不可达),
// 不发任何真实报文, 用户测 172.16.199.1 "ICMP 不可达 / TCP 23 可达" 实际是随机结果。
// 本接口在服务端发起真实探测, 前端 simulate() 整体替换为本调用(界面零改动, 见该文件注释)。
//
//   POST /api/v2/node/connectivity
//   body:  { target, proto: 'tcp'|'icmp'|'http', port, timeoutMs }
//   返回:  { status: 'ok'|'timeout'|'fail', latencyMs, detail }
//
// 三态语义(与前端表格 可达/超时/不可达 一致):
//   ok      = 探测成功(TCP 连接建立 / 收到 ICMP 回显 / HTTP 有响应)
//   timeout = 超时窗口内无响应(报文发出但对方不答 —— 典型: 设备管理面限流/过滤 ICMP)
//   fail    = 主动拒绝或能力/参数错误(连接被拒 / ICMP 原始套接字不可用 / 域名解析失败)
//
// ICMP 复用 scanner.PingICMP(原始套接字, 与存活探测同一权限口径: Windows 需提权进程;
// 不可用时如实回 fail 带原因, 不降级不猜测)。探测只发单个报文/一次连接, 对目标无压力。

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"yugsight/internal/scanner"
	"yugsight/internal/server"
)

// connSeq ICMP 标识序列(每次探测取下一个, 避免同 ID 撞包)。
var connSeq uint32

type connTestReq struct {
	Target    string `json:"target"`
	Proto     string `json:"proto"`
	Port      int    `json:"port"`
	TimeoutMs int    `json:"timeoutMs"`
}

type connTestResult struct {
	Status    string `json:"status"`    // ok | timeout | fail
	LatencyMs int64  `json:"latencyMs"` // 仅 ok 有意义
	Detail    string `json:"detail"`
}

// hNodeConnectivity POST /api/v2/node/connectivity —— 单目标真实连通性探测。
func hNodeConnectivity(w http.ResponseWriter, r *http.Request) {
	var in connTestReq
	if !decodeJSON(w, r, &in) {
		return
	}
	target := strings.TrimSpace(in.Target)
	if target == "" {
		server.FailBadRequest(w, "目标地址必填")
		return
	}
	proto := in.Proto
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "icmp" && proto != "http" {
		server.FailBadRequest(w, "协议仅支持 tcp / icmp / http")
		return
	}
	port := in.Port
	if port <= 0 {
		port = 161 // 与前端默认端口一致(SNMP, 网络设备最常见)
	}
	if proto != "icmp" && (port < 1 || port > 65535) {
		server.FailBadRequest(w, "端口需在 1 - 65535 之间")
		return
	}
	timeoutMs := in.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 3000
	}
	if timeoutMs < 100 || timeoutMs > 10000 {
		server.FailBadRequest(w, "超时需在 100 - 10000 ms 之间")
		return
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	var res connTestResult
	switch proto {
	case "tcp":
		res = probeTCP(target, port, timeout)
	case "icmp":
		res = probeICMP(target, timeout)
	case "http":
		res = probeHTTP(target, port, timeout)
	}
	server.OK(w, res)
}

// probeTCP 建立一次 TCP 连接即断开(半连接之外的最小探测, 对目标服务无副作用)。
func probeTCP(target string, port int, timeout time.Duration) connTestResult {
	addr := net.JoinHostPort(target, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return connErrResult("TCP", addr, err)
	}
	rtt := time.Since(start).Milliseconds()
	_ = conn.Close()
	return connTestResult{Status: "ok", LatencyMs: rtt, Detail: "TCP " + addr + " 连接建立"}
}

// probeICMP 发一个 ICMPv4 echo 等回显(复用 scanner 的共享原始套接字)。
func probeICMP(target string, timeout time.Duration) connTestResult {
	seq := uint16(atomic.AddUint32(&connSeq, 1))
	start := time.Now()
	alive, rtt, err := scanner.PingICMP(target, seq, timeout)
	if err != nil {
		// 域名解析失败 / ICMP 原始套接字不可用(Windows 需提权)等 —— 属"不能测", 如实告知
		return connTestResult{Status: "fail", Detail: "ICMP 探测失败: " + err.Error()}
	}
	if !alive {
		return connTestResult{Status: "timeout", Detail: fmt.Sprintf("%dms 内未收到 ICMP 回显(目标可能过滤/限速 ICMP)", timeout.Milliseconds())}
	}
	if rtt <= 0 {
		rtt = time.Since(start).Milliseconds()
	}
	return connTestResult{Status: "ok", LatencyMs: rtt, Detail: "收到 ICMP 回显"}
}

// probeHTTP 发一次 GET, 只要 HTTP 有响应(任意状态码)即视为可达 —— 探的是
// "端口上有 HTTP 服务在应答", 不是"业务 200"。
func probeHTTP(target string, port int, timeout time.Duration) connTestResult {
	client := &http.Client{Timeout: timeout}
	url := "http://" + net.JoinHostPort(target, strconv.Itoa(port)) + "/"
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return connErrResult("HTTP", url, err)
	}
	code := resp.StatusCode
	_ = resp.Body.Close()
	return connTestResult{Status: "ok", LatencyMs: time.Since(start).Milliseconds(), Detail: fmt.Sprintf("HTTP 响应 %d", code)}
}

// connErrResult 把 net 错误映射成 超时/不可达 两态(与前端 chip 口径一致)。
func connErrResult(kind, addr string, err error) connTestResult {
	if isNetTimeout(err) {
		return connTestResult{Status: "timeout", Detail: kind + " " + addr + " 超时未响应"}
	}
	return connTestResult{Status: "fail", Detail: kind + " " + addr + ": " + err.Error()}
}

// isNetTimeout 判定"无响应"(区别于"被拒绝"): net.Error.Timeout() 或消息含 timeout。
// Windows 防火墙静默丢包常表现为超时, Linux 无路由可能直接 "no route to host"(归 fail)。
func isNetTimeout(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

// ===== 路由跟踪(2026-09-30 用户要求: tracert/端口跟踪, ping 与端口两种) =====
//
// POST /api/v2/node/trace
// body:  { target, mode: 'icmp'|'port', port, maxHops, perHopMs }
// 返回:  scanner.TraceResult{target, resolved, port, reached, portState,
//         hopsNeeded, note, hops[{hop,ip,rttMs}], elapsedMs}
//
// 同步执行: 默认 15 跳×1s ≈ 15~20s 最坏, 前端显示"跟踪中"。
// ICMP 逐跳需提权服务(原始 ICMP 套接字, 与存活探测同口径); 能力缺失时回错误说明, 不崩。
// 端口模式的平台限制与两段组合设计见 internal/scanner/traceroute.go 头注释。

type traceReq struct {
	Target   string `json:"target"`
	Mode     string `json:"mode"`
	Port     int    `json:"port"`
	MaxHops  int    `json:"maxHops"`
	PerHopMs int    `json:"perHopMs"`
}

func hNodeTrace(w http.ResponseWriter, r *http.Request) {
	var in traceReq
	if !decodeJSON(w, r, &in) {
		return
	}
	target := strings.TrimSpace(in.Target)
	if target == "" {
		server.FailBadRequest(w, "目标地址必填")
		return
	}
	mode := in.Mode
	if mode == "" {
		mode = "icmp"
	}
	if mode != "icmp" && mode != "port" {
		server.FailBadRequest(w, "模式仅支持 icmp / port")
		return
	}
	port := 0
	if mode == "port" {
		port = in.Port
		if port <= 0 {
			port = 161 // 与连通性测试默认端口一致(SNMP, 网络设备最常见)
		}
		if port > 65535 {
			server.FailBadRequest(w, "端口需在 1 - 65535 之间")
			return
		}
	}
	maxHops := in.MaxHops
	if maxHops <= 0 {
		maxHops = 15
	}
	perHop := time.Duration(in.PerHopMs) * time.Millisecond
	if in.PerHopMs <= 0 {
		perHop = time.Second // 与前端默认一致
	}
	res, err := scanner.TraceRoute(target, port, maxHops, perHop)
	if err != nil {
		server.FailInternal(w, "路由跟踪不可用: "+err.Error())
		return
	}
	server.OK(w, res)
}
