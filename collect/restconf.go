// restconf.go RESTCONF 采集器 —— 网络设备(HTTPS + JSON/YANG, 纯标准库)。
//
// 协议: GET https://host:port/restconf/data/{path}(默认路径 if:interfaces),
// 可选 Basic 认证。YANG 命名空间前缀因设备而异(ietf-interfaces:/
// openconfig-interfaces:), 解析侧按"键后缀"匹配而不是全名, 兼容两种主流
// 数据模型。
//
// 指标口径:
//   - if_count / if_up: 接口总数 / UP 数(设备健康度一眼可见)
//   - 每接口计数器: 递归找键含 pkt/octet/byte 的数值叶子, 名称统一为
//     if_<key 规范化>; 与上一轮差分算速率(名称 <原名>_rate, 前缀一致) ——
//     计数器本身是累计值, 只有差分才有运维意义。
//
// 上一轮数据来自引擎内存时序(Store.PrevOf), 不额外存储。
package collect

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"yugsight/monitor"
)

func init() {
	Register(ProtoRESTCONF, collectRESTCONF)
}

func collectRESTCONF(ctx context.Context, e *Engine, t Task) *Round {
	r := newRound(t, time.Now())
	host, port := hostPort(t.Target, 443)
	if host == "" {
		r.OK = false
		r.Err = "目标不能为空"
		return r
	}
	path := t.Param("path")
	if path == "" {
		path = "if:interfaces"
	}
	scheme := "https"
	if strings.EqualFold(t.Param("tls"), "false") {
		scheme = "http"
	}
	verify := strings.EqualFold(t.Param("insecure"), "false")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verify}, //nolint:gosec // 内网自签常见, 默认不校验
		},
		Timeout: e.Config().TaskTimeout(t),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s://%s/restconf/data/%s", scheme, netJoin(host, port), path), nil)
	if err != nil {
		r.OK = false
		r.Err = err.Error()
		return r
	}
	req.Header.Set("Accept", "application/yang-data+json")
	if t.User != "" {
		key := monitor.SecretKey()
		req.SetBasicAuth(t.User, monitor.DecryptSecret(key, t.AuthPass))
	}
	resp, err := client.Do(req)
	if err != nil {
		r.OK = false
		r.Err = "请求失败: " + err.Error()
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		r.OK = false
		r.Err = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
		return r
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		r.OK = false
		r.Err = "读取响应失败: " + err.Error()
		return r
	}

	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		r.OK = false
		r.Err = "响应不是 JSON: " + err.Error()
		return r
	}

	// 找接口数组: 顶层键以 ":interfaces" 结尾 → 值里有 "interface" 数组
	ifaces, ok := findInterfaces(data)
	if !ok {
		r.OK = false
		r.Err = "响应中未找到接口列表(路径可能不对, 当前: /restconf/data/" + path + ")"
		return r
	}

	r.OK = true
	up := 0
	var counters []struct {
		iface, name string
		value       float64
	}
	for _, item := range ifaces {
		iface, _ := item["name"].(string)
		if iface == "" {
			iface = fmt.Sprint(len(counters))
		}
		st := strings.ToLower(operStateOf(item))
		if st == "up" {
			up++
		}
		// 递归收集计数器叶子(任意深度: ietf 在 counters 下, openconfig 在
		// if:counters/counters 下, 还有 per-direction 嵌套)
		var walk func(v any, prefix string)
		walk = func(v any, prefix string) {
			m, ok := v.(map[string]any)
			if !ok {
				return
			}
			for k, vv := range m {
				key := k
				if i := strings.IndexByte(k, ':'); i >= 0 {
					key = k[i+1:] // 去命名空间前缀
				}
				lk := strings.ToLower(key)
				if num, isNum := toFloat(vv); isNum &&
					(strings.Contains(lk, "pkt") || strings.Contains(lk, "octet") || strings.Contains(lk, "byte")) {
					counters = append(counters, struct {
						iface, name string
						value       float64
					}{iface, normalizeCounter(prefix + "/" + key), num})
				} else if isNum == false {
					walk(vv, key + "/")
				}
			}
		}
		walk(item, "")
	}
	r.Metrics = append(r.Metrics,
		Metric{Name: "if_count", Value: float64(len(ifaces))},
		Metric{Name: "if_up", Value: float64(up)},
	)
	for _, c := range counters {
		r.Metrics = append(r.Metrics, Metric{
			Name: c.name, Value: c.value,
			Labels: map[string]string{"iface": c.iface, "counter": c.name},
		})
	}

	// 速率: 与上一轮"同接口同计数器"差分(上一轮无 = 首次, 不算速率)。
	// 必须带 iface 匹配: 计数器名跨接口重复(eth0/eth1 都有 if_inbound_pkts),
	// 只按名字匹配会把 eth0 的速率算到 eth1 上。
	if prev := e.Store().PrevOf(t.ID); prev != nil && time.Since(prev.At) > time.Second {
		dt := time.Since(prev.At).Seconds()
		for _, m := range prev.Metrics {
			if m.Labels == nil || m.Labels["counter"] == "" {
				continue
			}
			for _, c := range r.Metrics {
				if c.Labels != nil && c.Name == m.Name && c.Labels["iface"] == m.Labels["iface"] {
					if c.Value >= m.Value {
						rate := (c.Value - m.Value) / dt
						r.Metrics = append(r.Metrics, Metric{
							Name: m.Name + "_rate", Value: rate,
							Labels: map[string]string{"iface": c.Labels["iface"], "counter": c.Name + "_rate"},
						})
					}
					break
				}
			}
		}
	}
	return r
}

// findInterfaces 在任意命名空间前缀下找接口数组。
func findInterfaces(data map[string]any) ([]map[string]any, bool) {
	for k, v := range data {
		if !strings.HasSuffix(k, ":interfaces") && k != "interfaces" {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if arr, ok := m["interface"].([]any); ok {
			out := make([]map[string]any, 0, len(arr))
			for _, it := range arr {
				if mm, ok := it.(map[string]any); ok {
					out = append(out, mm)
				}
			}
			return out, true
		}
	}
	return nil, false
}

// operStateOf 找接口运行状态(键: oper-state / oper-status / state/oper-status)。
func operStateOf(item map[string]any) string {
	if s, ok := item["oper-state"].(string); ok {
		return s
	}
	if s, ok := item["oper-status"].(string); ok {
		return s
	}
	if st, ok := item["state"].(map[string]any); ok {
		if s, ok := st["oper-status"].(string); ok {
			return s
		}
		if s, ok := st["oper-state"].(string); ok {
			return s
		}
	}
	return ""
}

// toFloat 数值判定(RESTCONF 计数器都是整数; float 也接受)。
func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, _ := n.Float64()
		return f, true
	}
	return 0, false
}

// normalizeCounter 计数器键规范化: 去前缀/空格 → 小写下划线(同一设备同一
// 计数器每轮名字必须稳定, 否则速率差分对不上)。
func normalizeCounter(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return "if_" + strings.ToLower(s)
}


