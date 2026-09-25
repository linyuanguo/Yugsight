// netconf.go NETCONF 采集器 —— 网络设备(纯标准库)。
//
// 协议口径: NETCONF over TLS(RFC 8012) —— TLS 通道 + 行分隔 XML RPC:
// 每条消息按行发送, 最后一行是单独一个 "]"。NETCONF 强制安全通道, 纯
// 标准库没有 SSH(x/crypto 是第三方依赖), 因此走 TLS 变体(设备需支持
// RFC 8012, 常见于 openconfig 生态; 只支持 SSH 通道(6242)的设备本阶段
// 不支持, 如实报错, 不做假降级)。
//
// 采集: 依次尝试 openconfig interfaces / ietf-interfaces 子树过滤,
// 都失败再退全量 <get/>(限 2MB)。解析用通用 XML token 遍历(不依赖具体
// 命名空间), 提取接口名 / 运行状态 / 数值计数器叶子。
package collect

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"yugsight/internal/monitor"
)

func init() {
	Register(ProtoNETCONF, collectNETCONF)
}

// netconfFilters 子树过滤的尝试顺序(先专用 schema, 最后全量兜底)。
var netconfFilters = []string{
	`<filter type="subtree"><interfaces xmlns="http://openconfig.net/yang/interfaces"/></filter>`,
	`<filter type="subtree"><interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/></filter>`,
	``, // 空 = 全量 get
}

func collectNETCONF(ctx context.Context, e *Engine, t Task) *Round {
	r := newRound(t, time.Now())
	host, port := hostPort(t.Target, 8300)
	if host == "" {
		r.OK = false
		r.Err = "目标不能为空"
		return r
	}
	verify := strings.EqualFold(t.Param("insecure"), "false")
	timeout := e.Config().TaskTimeout(t)

	// 标准库无 tls.DialContext: 先 TCP 拨号(带 ctx 超时)再包 TLS 层。
	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", netJoin(host, port))
	if err != nil {
		r.OK = false
		r.Err = "连接失败: " + err.Error()
		return r
	}
	conn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: !verify, //nolint:gosec // 内网自签常见, 默认不校验
		ServerName:         host,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		r.OK = false
		r.Err = "TLS 握手失败: " + err.Error()
		return r
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	key := monitor.SecretKey()
	login := ``
	if t.User != "" {
		login = `<login xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><username>` +
			xmlEscape(t.User) + `</username><password>` +
			xmlEscape(monitor.DecryptSecret(key, t.AuthPass)) + `</password></login>`
	}

	var lastErr string
	for i, filter := range netconfFilters {
		rpc := fmt.Sprintf(
			`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="%d">%s<get>%s</get></rpc>`,
			i+1, login, filter)
		reply, err := netconfRPC(conn, rpc)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		// 解析接口
		ifaces, ok := netconfInterfaces(reply)
		if !ok {
			// 有响应但没接口(或该 schema 不支持): 试下一个过滤
			lastErr = "响应中未找到接口"
			continue
		}
		if i > 0 {
			// 兜底 schema 成功时留个痕迹, 方便排查设备实际支持的模型
			r.Metrics = append(r.Metrics, Metric{Name: "schema_fallback", Value: 0, Labels: map[string]string{"index": fmt.Sprint(i)}})
		}
		r.OK = true
		fillNetconfMetrics(r, ifaces)
		return r
	}
	r.OK = false
	if lastErr == "" {
		lastErr = "所有过滤尝试均失败"
	}
	r.Err = "NETCONF 采集失败: " + lastErr
	return r
}

// netconfRPC 发送一行分隔的 RPC, 读回完整回复(直到 "]" 行)。
func netconfRPC(conn *tls.Conn, rpc string) (string, error) {
	// 行定向框架(RFC 8012): 消息整体一行, 紧跟一个只含 "]" 的行作为终结。
	payload := rpc + "\n]\n"
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", err
	}
	br := bufio.NewReaderSize(conn, 64*1024)
	var sb strings.Builder
	maxReply := 2 << 20
	for sb.Len() < maxReply {
		b, err := br.ReadBytes('\n')
		if err != nil {
			return "", err
		}
		line := strings.TrimRight(string(b), "\r\n")
		if line == "]" {
			break
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	if sb.Len() >= maxReply {
		return "", fmt.Errorf("回复超过 2MB 上限(设备返回了过大数据)")
	}
	return sb.String(), nil
}

// ---- 通用 XML → 树(不依赖命名空间) ----

type xmlNode struct {
	name     string
	text     string
	children []*xmlNode
}

// parseXMLTree 把 XML 解析成通用树(token 遍历, 畸形 XML 返回 error)。
// 子节点用指针而非值拷贝: 值拷贝在 append 时固定, 后续向该节点挂子元素
// 不会反映到父的 children 上, 整棵树会只剩一层(接口全部找不到)。
func parseXMLTree(data []byte) (*xmlNode, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	root := &xmlNode{name: "#root"}
	stack := []*xmlNode{root}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return root, nil
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xmlNode{name: t.Name.Local}
			stack[len(stack)-1].children = append(stack[len(stack)-1].children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			s := strings.TrimSpace(string(t))
			if s != "" {
				stack[len(stack)-1].text += s
			}
		}
	}
}

// findElements 递归找指定本地名的元素(跨命名空间)。
func findElements(n *xmlNode, name string) []*xmlNode {
	var out []*xmlNode
	for _, c := range n.children {
		if c.name == name {
			out = append(out, c)
		}
		out = append(out, findElements(c, name)...)
	}
	return out
}

// childText 取第一个子元素的文本。
func childText(n *xmlNode, name string) string {
	for _, c := range n.children {
		if c.name == name {
			return c.text
		}
	}
	return ""
}

// netconfInterfaces 从回复 XML 提取接口(名字 + 状态 + 计数器)。
type netconfIface struct {
	name   string
	state  string
	leafs  map[string]string // 计数器键(已去命名空间) → 文本值
}

func netconfInterfaces(reply string) ([]netconfIface, bool) {
	root, err := parseXMLTree([]byte(reply))
	if err != nil {
		return nil, false
	}
	ifaceNodes := findElements(root, "interface")
	if len(ifaceNodes) == 0 {
		return nil, false
	}
	out := make([]netconfIface, 0, len(ifaceNodes))
	for i := range ifaceNodes {
		f := ifaceNodes[i]
		iface := netconfIface{
			name:  childText(f, "name"),
			leafs: map[string]string{},
		}
		// 状态: oper-state(openconfig) 或 state/oper-status(ietf)
		if s := childText(f, "oper-state"); s != "" {
			iface.state = s
		} else {
			for _, c := range f.children {
				if c.name == "state" {
					iface.state = childText(c, "oper-status")
				}
			}
		}
		// 计数器: 找 counters 节点(或 state/counters), 递归收数值叶子。
		// 用 var 先声明再赋值: := 声明的变量作用域从 ShortVarDecl 结束才开始,
		// 函数体内引用自己会报 undefined; var 声明后作用域先于赋值生效。
		var collectCounters func(n *xmlNode)
		collectCounters = func(n *xmlNode) {
			for _, c := range n.children {
				if c.name == "counters" {
					var walk func(x *xmlNode)
					walk = func(x *xmlNode) {
						if x.text != "" {
							if key := cleanCounterKey(x.name); key != "" {
								iface.leafs[key] = x.text
							}
						}
						for _, k := range x.children {
							walk(k)
						}
					}
					walk(c)
					return
				}
				collectCounters(c)
			}
		}
		collectCounters(f)
		if iface.name == "" {
			iface.name = fmt.Sprint(len(out))
		}
		out = append(out, iface)
	}
	return out, true
}

// cleanCounterKey 计数器键规范化(去命名空间前缀 + 小写)。
func cleanCounterKey(raw string) string {
	s := raw
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	if s == "" {
		return ""
	}
	return strings.ToLower(s)
}

// fillNetconfMetrics 接口 → 标准化指标。
func fillNetconfMetrics(r *Round, ifaces []netconfIface) {
	up := 0
	for _, f := range ifaces {
		st := strings.ToLower(f.state)
		if st == "up" {
			up++
		}
		r.Metrics = append(r.Metrics, Metric{
			Name: "if_state", Value: 1,
			Labels: map[string]string{"iface": f.name, "state": st},
		})
		for k, v := range f.leafs {
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue // 非数值叶子(字符串), 跳过
			}
			lk := strings.ToLower(k)
			if strings.Contains(lk, "pkt") || strings.Contains(lk, "octet") || strings.Contains(lk, "byte") {
				r.Metrics = append(r.Metrics, Metric{
					Name: "if_" + strings.ReplaceAll(k, "-", "_"),
					Value:  n,
					Labels: map[string]string{"iface": f.name, "counter": k},
				})
			}
		}
	}
	r.Metrics = append(r.Metrics,
		Metric{Name: "if_count", Value: float64(len(ifaces))},
		Metric{Name: "if_up", Value: float64(up)},
	)
}
