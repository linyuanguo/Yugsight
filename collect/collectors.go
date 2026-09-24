// collectors.go 协议适配器注册表 + 采集器接口。
//
// 每个协议一个独立文件(snmp_host.go / icmp.go / winrm.go / ssh.go /
// netflow.go / restconf.go / netconf.go), init() 里注册 —— 主程序只要
// import 本包就全部就位; 新增协议只加文件, 引擎零改动。
package collect

import (
	"context"
	"net/netip"
	"strings"
)

// Collector 协议采集器: 对一个任务跑一轮, 返回标准化 Round(永不返回 nil,
// 失败也填 OK=false + Err —— 与 probe agentexec 的"失败回传不丢结果"同口径)。
type Collector func(ctx context.Context, e *Engine, t Task) *Round

// collectors 注册表(并发安全: 注册只发生在 init 期, 读侧每轮触发)。
var collectors = map[string]Collector{}

// Register 注册协议采集器(同名覆盖; 仅供包内 init 使用)。
func Register(name string, c Collector) {
	collectors[name] = c
}

// hostPort 解析 target 的 host 与 port(缺端口时填 defaultPort)。
// 与 netflow 监听地址切分同一口径: 只切第一个冒号, 后面的原样留(路径不属
// 本协议, restconf 的 URL 由它自己拼)。
func hostPort(target string, defaultPort int) (host string, port int) {
	h := strings.TrimSpace(target)
	if i := strings.IndexByte(h, ':'); i > 0 {
		host = h[:i]
		p := h[i+1:]
		// 端口段可能带路径(restconf 的 URL), 只取数字前缀
		j := 0
		for j < len(p) && p[j] >= '0' && p[j] <= '9' {
			j++
		}
		n := 0
		for _, c := range p[:j] {
			n = n*10 + int(c-'0')
		}
		if n > 0 {
			return host, n
		}
		return host, defaultPort
	}
	return h, defaultPort
}

// addrIP 取 target 的 IP 部分(白名单/日志展示用; 解析失败返回空)。
func addrIP(target string) string {
	h, _ := hostPort(target, 0)
	if h == "" {
		return ""
	}
	a, err := netip.ParseAddr(h)
	if err != nil {
		return h
	}
	return a.String()
}
