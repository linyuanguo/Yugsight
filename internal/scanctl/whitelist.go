//go:build !windows || windows

// whitelist.go 漏洞白名单管理(基于统一 DAO)。
//
// 能力(任务 3.2): 支持按 5 种维度添加白名单 ——
//   - ip   精确 IP
//   - cidr IP 段(如 192.168.1.0/24)
//   - port 端口
//   - cve  CVE 编号(大小写不敏感)
//   - tag  资产标签(大小写不敏感)
//
// 白名单命中的漏洞自动过滤, 不进入报告和统计(调用方以
// Filter 返回值为准, 被过滤项可从 filtered 列表留痕)。
//
// 开关语义(与 scanner/whitelist.go 既有约定一致): 默认关闭,
// 添加条目视为用户显式操作, 自动开启; 关闭时 Match 恒不命中。
// 持久化: 统一 DAO(默认 JSONL 文件, 见 dao.go)。
//
// 依赖: 仅 Go 标准库 + yugsight/models。
package scanctl

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/internal/models"
)

// 白名单条目类型
const (
	WLTypeIP   = "ip"   // 按精确 IP 匹配
	WLTypeCIDR = "cidr" // 按 IP 段匹配(CIDR)
	WLTypePort = "port" // 按端口匹配
	WLTypeCVE  = "cve"  // 按 CVE 编号匹配(大小写不敏感)
	WLTypeTag  = "tag"  // 按资产标签匹配(大小写不敏感)
)

// WhitelistEntry 白名单条目(Entity)
type WhitelistEntry struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // ip / cidr / port / cve / tag
	Match     string    `json:"match"`
	Reason    string    `json:"reason,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"` // 零值 = 永不过期
}

// EntityID Entity 契约
func (e WhitelistEntry) EntityID() string { return e.ID }

// Validate Entity 契约: 类型 / 匹配值 / CIDR / 端口合法性校验
func (e WhitelistEntry) Validate() error {
	t := strings.ToLower(strings.TrimSpace(e.Type))
	switch t {
	case WLTypeIP, WLTypeCVE, WLTypeTag:
	case WLTypeCIDR:
		if _, err := netip.ParsePrefix(strings.TrimSpace(e.Match)); err != nil {
			return fmt.Errorf("IP 段格式无效: %s (应为 CIDR, 如 192.168.1.0/24)", e.Match)
		}
	case WLTypePort:
		p, err := strconv.Atoi(strings.TrimSpace(e.Match))
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("端口格式无效: %s (应为 1-65535)", e.Match)
		}
	default:
		return fmt.Errorf("未知白名单类型: %s (仅支持 %s/%s/%s/%s/%s)",
			e.Type, WLTypeIP, WLTypeCIDR, WLTypePort, WLTypeCVE, WLTypeTag)
	}
	if strings.TrimSpace(e.Match) == "" {
		return fmt.Errorf("白名单匹配值不能为空")
	}
	return nil
}

// Whitelist 白名单管理器(缓存 + DAO 持久化)
type Whitelist struct {
	mu      sync.RWMutex
	dao     DAO[WhitelistEntry]
	entries []WhitelistEntry
	on      bool // 总开关(默认关闭, Add 自动开启)
}

// NewWhitelist 基于 DAO 构建白名单管理器并加载存量条目。
// 存在存量条目 = 用户此前显式配置过, 自动开启开关。
func NewWhitelist(dao DAO[WhitelistEntry]) (*Whitelist, error) {
	w := &Whitelist{dao: dao}
	es, err := dao.List()
	if err != nil {
		return nil, err
	}
	w.entries = es
	w.on = len(es) > 0
	return w, nil
}

// DAO 返回底层 DAO(诊断用)
func (w *Whitelist) DAO() DAO[WhitelistEntry] {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.dao
}

// SetEnabled 设置总开关(默认关闭)。关闭时 Match 恒不命中。
func (w *Whitelist) SetEnabled(on bool) {
	w.mu.Lock()
	w.on = on
	w.mu.Unlock()
}

// Enabled 总开关状态
func (w *Whitelist) Enabled() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.on
}

// Count 条目数
func (w *Whitelist) Count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.entries)
}

// List 全部条目(副本, 按入库顺序)
func (w *Whitelist) List() []WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]WhitelistEntry, len(w.entries))
	copy(out, w.entries)
	return out
}

// Add 新增/覆盖条目并持久化。自动补全 ID / CreatedAt, 新增条目默认启用,
// 并自动开启白名单总开关(显式操作语义)。type/match 非法返回错误不落盘。
func (w *Whitelist) Add(e WhitelistEntry) (WhitelistEntry, error) {
	e.Type = strings.ToLower(strings.TrimSpace(e.Type))
	e.Match = strings.TrimSpace(e.Match)
	if e.Type == WLTypeCVE {
		e.Match = models.NormalizeCVE(e.Match)
	}
	if e.ID == "" {
		e.ID = "wl-" + e.Type + "-" + e.Match
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	e.Enabled = true
	if err := e.Validate(); err != nil {
		return WhitelistEntry{}, err
	}
	if err := w.dao.Add(e); err != nil {
		return WhitelistEntry{}, err
	}
	w.mu.Lock()
	for i := range w.entries {
		if w.entries[i].ID == e.ID {
			w.entries[i] = e
			break
		}
	}
	w.entries = upsertEntry(w.entries, e)
	w.on = true
	w.mu.Unlock()
	return e, nil
}

// Remove 按 ID 删除条目并持久化, 返回是否删除成功
func (w *Whitelist) Remove(id string) (bool, error) {
	removed, err := w.dao.Remove(id)
	if err != nil || !removed {
		return removed, err
	}
	w.mu.Lock()
	for i := range w.entries {
		if w.entries[i].ID == id {
			w.entries = append(w.entries[:i], w.entries[i+1:]...)
			break
		}
	}
	w.mu.Unlock()
	return true, nil
}

func upsertEntry(list []WhitelistEntry, e WhitelistEntry) []WhitelistEntry {
	for i := range list {
		if list[i].ID == e.ID {
			list[i] = e
			return list
		}
	}
	return append(list, e)
}

// entryActive 条目是否生效(启用 + 未过期)
func entryActive(e WhitelistEntry, now time.Time) bool {
	if !e.Enabled {
		return false
	}
	if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
		return false
	}
	return true
}

// matchEntry 单条目匹配判定
func matchEntry(e WhitelistEntry, a *models.Asset, v *models.Vuln) bool {
	switch e.Type {
	case WLTypeIP:
		return a != nil && a.IP != "" && a.IP == models.NormIP(e.Match)
	case WLTypeCIDR:
		if a == nil || a.IP == "" {
			return false
		}
		prefix, err := netip.ParsePrefix(e.Match)
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(a.IP)
		if err != nil {
			return false
		}
		return prefix.Contains(addr)
	case WLTypePort:
		if v != nil && v.Port > 0 && e.Match == strconv.Itoa(v.Port) {
			return true
		}
		// 资产维度: 漏洞未带端口时, 资产开放端口列表命中也算
		if a != nil && a.Ports != nil {
			for _, p := range a.Ports {
				if e.Match == strconv.Itoa(p) {
					return true
				}
			}
		}
		return false
	case WLTypeCVE:
		return v != nil && v.CVE != "" && strings.EqualFold(models.NormalizeCVE(e.Match), v.CVE)
	case WLTypeTag:
		m := strings.ToLower(strings.TrimSpace(e.Match))
		if a == nil || m == "" {
			return false
		}
		for _, t := range a.Tags {
			if strings.ToLower(strings.TrimSpace(t)) == m {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// Match 判断 (资产, 漏洞) 是否命中白名单, 返回 (是否命中, 命中条目)。
// 总开关关闭 / 无条目 / 双 nil 时返回 (false, 零值)。
func (w *Whitelist) Match(a *models.Asset, v *models.Vuln) (bool, WhitelistEntry) {
	if a == nil && v == nil {
		return false, WhitelistEntry{}
	}
	w.mu.RLock()
	on := w.on
	entries := w.entries
	w.mu.RUnlock()
	if !on || len(entries) == 0 {
		return false, WhitelistEntry{}
	}
	now := time.Now()
	for _, e := range entries {
		if entryActive(e, now) && matchEntry(e, a, v) {
			return true, e
		}
	}
	return false, WhitelistEntry{}
}

// Filter 批量过滤: 返回 (保留列表, 被过滤列表)。
// 被过滤的漏洞打 Whitelisted 语义(此处返回独立列表, 原切片不修改)。
func (w *Whitelist) Filter(assets []*models.Asset, vulns []*models.Vuln) (kept, filtered []*models.Vuln) {
	idx := AssetIndex(assets)
	now := time.Now()
	for _, v := range vulns {
		if v == nil {
			continue
		}
		hit := false
		if w.Enabled() {
			w.mu.RLock()
			entries := w.entries
			w.mu.RUnlock()
			for _, e := range entries {
				if entryActive(e, now) && matchEntry(e, idx[v.AssetIP], v) {
					hit = true
					break
				}
			}
		}
		if hit {
			filtered = append(filtered, v)
		} else {
			kept = append(kept, v)
		}
	}
	return kept, filtered
}

// AssetIndex 按 IP 建资产索引(匹配辅助, 同 IP 取首个)
func AssetIndex(assets []*models.Asset) map[string]*models.Asset {
	idx := make(map[string]*models.Asset, len(assets))
	for _, a := range assets {
		if a == nil || a.IP == "" {
			continue
		}
		if _, ok := idx[a.IP]; !ok {
			idx[a.IP] = a
		}
	}
	return idx
}

// SortedByCreated 条目按创建时间降序(UI 展示用)
func SortedByCreated(es []WhitelistEntry) []WhitelistEntry {
	out := make([]WhitelistEntry, len(es))
	copy(out, es)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}
