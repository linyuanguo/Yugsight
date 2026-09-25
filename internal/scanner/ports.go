package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Emit 事件回调，用于向前端流式推送扫描结果
type Emit func(event string, data any)

// PortResult 端口扫描结果
type PortResult struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	State     string `json:"state"` // open / closed
	Service   string `json:"service"`
	Banner    string `json:"banner"`
	LatencyMs int64  `json:"latencyMs"`
}

// ParsePorts 解析端口字符串，支持 "22,80,443"、"1-1024"、"22,80,1000-2000"、"(80,443,500-600)"
func ParsePorts(s string) ([]int, error) {
	s = strings.ReplaceAll(s, "（", "(")
	s = strings.ReplaceAll(s, "）", ")")
	s = strings.ReplaceAll(s, "，", ",")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("端口不能为空")
	}
	seen := map[int]bool{}
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "-"); i > 0 {
			lo, err1 := strconv.Atoi(part[:i])
			hi, err2 := strconv.Atoi(part[i+1:])
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("无效端口范围: %s", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("无效端口: %s", part)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("未解析到有效端口")
	}
	sort.Ints(ports)
	return ports, nil
}

var serviceNames = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
	123: "ntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
	389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 515: "lpd",
	587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
	1080: "socks", 1433: "ms-sql-s", 1521: "oracle", 2049: "nfs",
	2181: "zookeeper", 2375: "docker", 3306: "mysql", 3389: "ms-wbt-server",
	5000: "upnp", 5432: "postgresql", 5900: "vnc", 5984: "couchdb",
	6379: "redis", 7001: "weblogic", 8000: "http-alt", 8009: "ajp",
	8080: "http-alt", 8443: "https-alt", 9000: "pgsql", 9090: "zookeeper",
	9200: "elasticsearch", 9300: "elasticsearch", 27017: "mongod",
	3000: "nodejs", 8888: "http-alt",
}

// ServiceName 返回端口的常见服务名
func ServiceName(p int) string {
	return serviceNames[p]
}

// grabBanner 从已建立的 TCP 连接读取服务横幅
func grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	b := buf[:n]
	for i, c := range b {
		if c < 32 && c != '\t' && c != '\r' && c != '\n' {
			b[i] = '.'
		}
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// probeOnePort 对单个 ip:port 做一次 TCP 拨号探测: 开放则读服务名 + banner 并立即
// 关闭连接, 关闭则仅记 closed。这是 c7 统一扫描与端口扫描共用的端口探测原语 ——
// 一次拨号同时拿到"是否开放"与"服务指纹", 让存活判定与端口识别共用同一次连接,
// 不再"存活探测拨一遍、端口探测再拨一遍"(消除重复发包)。
//
// 拨号用 DialContext, 同时尊重单端口 timeout 与整体 ctx 取消: 任务取消后在途拨号
// 立即失败返回, 不会阻塞在已取消的连接上。
func probeOnePort(ctx context.Context, d net.Dialer, ip string, p int, timeout time.Duration) PortResult {
	start := time.Now()
	r := PortResult{IP: ip, Port: p}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
	if err != nil {
		r.State = "closed"
		return r
	}
	defer conn.Close()
	r.State = "open"
	r.Service = ServiceName(p)
	r.Banner = grabBanner(conn)
	r.LatencyMs = time.Since(start).Milliseconds()
	return r
}

// ScanPorts 并发 TCP 端口扫描，通过 emit 实时推送结果。
//
// c7 起委托统一扫描引擎 UnifiedScan(none 模式)实现: 单主机端口扫描 = 多主机
// 扫描的退化形态, 判定/事件/返回口径完全一致 —— 逐端口回传 "port" 事件(开放+
// 关闭), 返回全量结果(开放项含服务名/banner/时延)。emit 经包装层收集统一引擎
// 回传的结果, 旧调用方(main.go / host.go / engine_api.go)签名与语义零改动。
//
// ctx 取消语义: 取消后新端口不再进入队列(sem 等待被 ctx.Done 打断), 在途拨号经
// DialContext 立即返回 —— 整段扫描可被快速终止, 且所有 goroutine 都能退出(不泄漏)。
func ScanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, concurrency int, emit Emit) []PortResult {
	if emit == nil {
		emit = func(string, any) {}
	}
	var mu sync.Mutex
	var results []PortResult
	UnifiedScan(ctx, []string{ip}, ports, AliveModeNone, concurrency, timeout, func(kind string, data any) {
		// none 模式只回传 "port" 事件, 收集全量结果(开放+关闭)保证与旧返回口径一致
		if kind == "port" {
			if r, ok := data.(PortResult); ok {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}
		emit(kind, data)
	})
	return results
}
