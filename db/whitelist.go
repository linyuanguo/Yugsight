package db

import (
	"errors"
	"strings"
	"time"

	"net/netip"
)

// 白名单类型常量(与 scanctl 白名单同口径)。
const (
	WLTypeIP   = "ip"
	WLTypeCIDR = "cidr"
	WLTypePort = "port"
	WLTypeCVE  = "cve"
	WLTypeTag  = "tag" // 资产标签
)

// WhitelistEntry 白名单表实体。
// 字段契约与 scanctl.WhitelistEntry 对齐(中心管理端独立存储, 不共用本地文件)。
type WhitelistEntry struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // ip|cidr|port|cve|tag
	Match     string    `json:"match"`
	Reason    string    `json:"reason,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"` // 零值 = 永不过期
}

// EntityID 条目 ID。
func (e *WhitelistEntry) EntityID() string {
	if e.ID == "" {
		e.ID = newID("wl")
	}
	return e.ID
}

// Validate 自检: 类型合法 + 匹配值非空 + CIDR 格式校验。
func (e *WhitelistEntry) Validate() error {
	switch e.Type {
	case WLTypeIP, WLTypeCIDR, WLTypePort, WLTypeCVE, WLTypeTag:
	default:
		return errors.New("白名单类型非法: 需为 ip/cidr/port/cve/tag")
	}
	if strings.TrimSpace(e.Match) == "" {
		return errors.New("白名单匹配值不能为空")
	}
	e.Match = strings.TrimSpace(e.Match)
	if e.Type == WLTypeCIDR {
		if _, err := netip.ParsePrefix(e.Match); err != nil {
			return errors.New("CIDR 格式非法: " + e.Match)
		}
	}
	if e.ID == "" {
		e.ID = newID("wl")
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	return nil
}

// Expired 是否已过期(零值 = 永不过期)。
func (e *WhitelistEntry) Expired() bool {
	return !e.ExpiresAt.IsZero() && time.Now().After(e.ExpiresAt)
}

// WhitelistDAO 白名单管理 DAO: 基础 CRUD + 启停 + 有效条目查询。
type WhitelistDAO struct {
	*Table[*WhitelistEntry]
}

// newWhitelistTable 打开白名单表。
func newWhitelistTable(path string) (*WhitelistDAO, error) {
	t, err := NewTable[*WhitelistEntry]("whitelist", path, func() *WhitelistEntry { return &WhitelistEntry{} })
	if err != nil {
		return nil, err
	}
	return &WhitelistDAO{Table: t}, nil
}

// EnabledOnly 有效(启用且未过期)条目。
func (d *WhitelistDAO) EnabledOnly() ([]*WhitelistEntry, error) {
	return d.Query(func(e *WhitelistEntry) bool { return e.Enabled && !e.Expired() })
}

// SetEnabled 启停条目, 返回更新后的条目。
func (d *WhitelistDAO) SetEnabled(id string, enabled bool) (*WhitelistEntry, error) {
	e, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	e.Enabled = enabled
	if err := d.Update(e); err != nil {
		return e, err
	}
	return e, nil
}
