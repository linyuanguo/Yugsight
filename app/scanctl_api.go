//go:build !windows || windows

// scanctl_api.go 扫描管控 Web API: 白名单管理 + 误报管理 + 状态查询。
//
// 路由(均 requireAuth, 在 main.go 注册):
//   - GET  /api/vuln/control/status     管控状态(开关/条目数/打分模型)
//   - GET  /api/vuln/whitelist          白名单列表
//   - POST /api/vuln/whitelist/add      添加白名单 {type,match,reason,expiresAt?}
//   - POST /api/vuln/whitelist/remove   删除白名单 {id}
//   - GET  /api/vuln/fps                误报规则列表
//   - POST /api/vuln/fps/mark           标记误报 {assetIp,cve?,title?,note,markedBy?}
//   - POST /api/vuln/fps/remove         删除误报规则 {id}
//
// 白名单 type 支持: ip / cidr(IP 段) / port / cve / tag(资产标签)。
// 误报按 资产+CVE 匹配(无 CVE 时按 资产+标题), 后续扫描自动标记。
//
// 依赖: 根包既有辅助 + yugsight/scanctl。
package main

import (
	"encoding/json"
	"net/http"
	"time"

	"yugsight/internal/scanctl"
)

// ctlOrFail 取全局管控门面; 不可用时回 400 并返回 nil(调用方直接 return)
func ctlOrFail(w http.ResponseWriter) *scanctl.Controller {
	c := scanctl.Instance()
	if c == nil {
		failJSON(w, "扫描管控模块不可用")
		return nil
	}
	return c
}

// handleCtlStatus 管控状态(开关/条目数/四级打分模型)
func handleCtlStatus(w http.ResponseWriter, r *http.Request) {
	if c := scanctl.Instance(); c != nil {
		jsonOK(w, c.StatusOf())
		return
	}
	jsonOK(w, scanctl.Status{})
}

// handleWhitelistList 白名单列表
func handleWhitelistList(w http.ResponseWriter, r *http.Request) {
	c := ctlOrFail(w)
	if c == nil {
		return
	}
	jsonOK(w, map[string]any{
		"enabled": c.Whitelist().Enabled(),
		"count":   c.Whitelist().Count(),
		"entries": scanctl.SortedByCreated(c.Whitelist().List()),
	})
}

// handleWhitelistAdd 添加白名单
// body: {type: ip|cidr|port|cve|tag, match, reason?, expiresAt?(RFC3339, 可选)}
func handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Type      string `json:"type"`
		Match     string `json:"match"`
		Reason    string `json:"reason"`
		ExpiresAt string `json:"expiresAt"` // RFC3339, 空 = 永不过期
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		failJSON(w, "请求格式错误: "+err.Error())
		return
	}
	e := scanctl.WhitelistEntry{Type: req.Type, Match: req.Match, Reason: req.Reason}
	if req.ExpiresAt != "" {
		t, perr := time.Parse(time.RFC3339, req.ExpiresAt)
		if perr != nil {
			failJSON(w, "有效期格式错误, 应为 RFC3339(如 2027-01-01T00:00:00Z): "+perr.Error())
			return
		}
		e.ExpiresAt = t
	}
	entry, err := ctlOrFail(w).Whitelist().Add(e)
	if err != nil {
		failJSON(w, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "entry": entry})
}

// handleWhitelistRemove 删除白名单条目
func handleWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		failJSON(w, "请求格式错误: "+err.Error())
		return
	}
	ok, err := ctlOrFail(w).Whitelist().Remove(req.ID)
	if err != nil {
		failJSON(w, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "removed": ok})
}

// handleFPSList 误报规则列表
func handleFPSList(w http.ResponseWriter, r *http.Request) {
	c := ctlOrFail(w)
	if c == nil {
		return
	}
	jsonOK(w, map[string]any{
		"count": c.FPS().Count(),
		"rules": scanctl.SortedRulesByCreated(c.FPS().List()),
	})
}

// handleFPSMark 标记误报(带备注)
// body: {assetIp, cve?, title?, note?, markedBy?}
func handleFPSMark(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AssetIP  string `json:"assetIp"`
		CVE      string `json:"cve"`
		Title    string `json:"title"`
		Note     string `json:"note"`
		MarkedBy string `json:"markedBy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		failJSON(w, "请求格式错误: "+err.Error())
		return
	}
	rule, err := ctlOrFail(w).FPS().Mark(req.AssetIP, req.CVE, req.Title, req.Note, req.MarkedBy)
	if err != nil {
		failJSON(w, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "rule": rule})
}

// handleFPSRemove 删除误报规则
func handleFPSRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		failJSON(w, "请求格式错误: "+err.Error())
		return
	}
	ok, err := ctlOrFail(w).FPS().Remove(req.ID)
	if err != nil {
		failJSON(w, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "removed": ok})
}
