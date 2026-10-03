// https_api.go HTTPS 访问白名单(https 节)—— 授权与模型页(License.vue)配置。
//
// 语义:
//   - ips 为空(默认) → 白名单<b>不启用</b>, 不限制任何 IP, 任何来源都可访问;
//   - ips 非空 → <b>启用</b>, 只放行列表内的 IP/CIDR(单 IP 自动补 /32 或 /128,
//     也支持网段如 192.168.1.0/24), 列表外的来源在 TLS 握手阶段被拒
//     (见 tls.go 的 GetCertificate 回调 getCertForHello)。
//
// 热加载: 保存走 writeSection(secHttps, ...) + resetSettingsCache(与 brand 节同口径),
// 保存立即生效、无需重启; tls.go 的 getCertForHello 每次实时读 loadHttpsConfig(),
// 故白名单改动后下一个 TLS 握手即按新规则放行/拒绝。
//
// API(授权与模型页):
//   - GET  /api/v2/https  白名单读取(requireAuth, 登录角色均可查看)
//   - POST /api/v2/https  白名单保存(requireAuth + adminOnly, 与同页品牌/用户管理同权限口径)

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"yugsight/internal/server"
)

// httpsConfig https 节配置: HTTPS 访问白名单。
type httpsConfig struct {
	IPs []string `json:"ips"` // 空 = 不启用(不限制); 非空 = 只放行这些 IP/CIDR
}

// enabled 白名单是否启用(有任一 IP 段 = 启用)。
func (c httpsConfig) enabled() bool { return len(c.IPs) > 0 }

// loadHttpsConfig 读 https 节; 缺失/解析失败返回空(= 不启用, 不限制)。
//
// 每次调用实时读配置中心(不缓存): 与保存后 resetSettingsCache 的热重载天然兼容
// —— 保存后下一个握手即可读到新白名单, 无需重启(与 loadBrand 同口径)。
func loadHttpsConfig() httpsConfig {
	var c httpsConfig
	data, ok := section(secHttps, "")
	if !ok {
		return c
	}
	_ = json.Unmarshal(data, &c)
	return c
}

// normalizeCIDR 单 IP 自动补前缀(/32 或 /128); 网段原样返回。
func normalizeCIDR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "/") {
		return s
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Is4() {
			return s + "/32"
		}
		return s + "/128"
	}
	return s
}

// allowed 判断访问 IP 是否放行: 白名单未启用 → 恒放行; 启用 → 命中任一 IP/CIDR 才放行。
func (c httpsConfig) allowed(ip string) bool {
	if !c.enabled() {
		return true // 空白名单 = 不限制
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false // 非法 IP, 不放行
	}
	for _, s := range c.IPs {
		p, err := netip.ParsePrefix(normalizeCIDR(s))
		if err != nil {
			continue // 配置里某条写错不阻断其余(与 weakpass allowIn 同口径)
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// hHttps /api/v2/https 同路径按方法分发: GET 读(requireAuth), POST 写(adminOnly)。
// 与 /api/v2/users/{name} 同路径按方法分发同口径。
func hHttps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		hHttpsGet(w, r)
	case http.MethodPost:
		adminOnly(hHttpsSave)(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

// hHttpsGet GET /api/v2/https 当前白名单。
func hHttpsGet(w http.ResponseWriter, r *http.Request) {
	server.OK(w, loadHttpsConfig())
}

// hHttpsSave POST /api/v2/https 保存白名单(adminOnly)。
// 校验每条 IP/CIDR 合法(空列表 = 关闭白名单, 允许保存)。
func hHttpsSave(w http.ResponseWriter, r *http.Request) {
	var req httpsConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		server.FailBadRequest(w, "请求体解析失败: "+err.Error())
		return
	}
	clean := make([]string, 0, len(req.IPs))
	seen := map[string]bool{}
	for _, s := range req.IPs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// 校验: 单 IP 或 CIDR 必须合法(网段用 ParsePrefix, 单 IP 用 ParseAddr)
		if strings.Contains(s, "/") {
			if _, err := netip.ParsePrefix(s); err != nil {
				server.FailBadRequest(w, "非法网段: "+s)
				return
			}
		} else {
			if _, err := netip.ParseAddr(s); err != nil {
				server.FailBadRequest(w, "非法 IP: "+s)
				return
			}
		}
		if !seen[s] {
			seen[s] = true
			clean = append(clean, s)
		}
	}
	req.IPs = clean
	if err := writeSection(secHttps, req); err != nil {
		server.FailInternal(w, "HTTPS 白名单保存失败: "+err.Error())
		return
	}
	// 立即生效: 清内存缓存, getCertForHello 下次实时读到新白名单(无需重启)。
	resetSettingsCache()
	state := "启用"
	if !req.enabled() {
		state = "关闭(不限制)"
	}
	logLine(fmt.Sprintf("HTTPS 白名单已保存: %s, %d 条", state, len(req.IPs)))
	server.OK(w, req)
}
