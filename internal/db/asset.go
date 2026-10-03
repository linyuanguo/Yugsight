package db

import (
	"errors"
	"net"
	"strings"
	"time"

	"yugsight/internal/models"
)

// Asset 资产表实体(主机维度, 一台主机一条)。
// 内嵌 models.Asset 保证与归一化层数据契约完全一致。
type Asset struct {
	models.Asset
	UpdatedAt time.Time `json:"updatedAt"`
}

// NewAsset 构造资产实体(自动归一化 IP 并计算稳定 ID)。
func NewAsset(ip string) *Asset {
	a := &Asset{Asset: *models.NewAsset(ip)}
	a.UpdatedAt = time.Now()
	return a
}

// EntityID 稳定资产 ID(IP 的 SHA1 前 16 位, 跨扫描不变)。
func (a *Asset) EntityID() string {
	if a.ID == "" {
		a.ID = a.StableID()
	}
	return a.ID
}

// Validate 自检: IP 必填, 缺省字段补全。
func (a *Asset) Validate() error {
	if a.IP == "" {
		return errors.New("资产 IP 不能为空")
	}
	a.IP = models.NormIP(a.IP)
	if a.ID == "" {
		a.ID = a.StableID()
	}
	if a.FoundAt.IsZero() {
		a.FoundAt = time.Now()
	}
	a.UpdatedAt = time.Now()
	return nil
}

// AddTags 去重后追加标签。
func (a *Asset) AddTags(tags ...string) {
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		exist := false
		for _, x := range a.Tags {
			if x == tag {
				exist = true
				break
			}
		}
		if !exist {
			a.Tags = append(a.Tags, tag)
		}
	}
}

// RemoveTags 删除标签。
func (a *Asset) RemoveTags(tags ...string) {
	set := map[string]bool{}
	for _, tag := range tags {
		set[strings.TrimSpace(tag)] = true
	}
	out := a.Tags[:0]
	for _, x := range a.Tags {
		if !set[x] {
			out = append(out, x)
		}
	}
	a.Tags = out
}

// AssetDAO 资产管理 DAO: 基础 CRUD + 标签管理 + 维度查询。
type AssetDAO struct {
	*Table[*Asset]
}

// CountAlive 存活资产数量(Alive=true)。
// 与 Count() 的差值即"未探测/未响应"资产, 大屏用这一对指标表达资产覆盖面。
// CountWhere 单遍计数不构造切片(大屏 15s 轮询, 只为一个数字拷贝全表不划算)。
func (d *AssetDAO) CountAlive() (int, error) {
	return d.CountWhere(func(a *Asset) bool { return a.Alive })
}

// CountHosts 主机维度资产数: 只统计 IP 字段是合法 IP 的条目。
//
// 为什么需要单独的口径: 资产表是"资产台账"而非纯主机表 —— Trivy 镜像/文件
// 扫描的工件(镜像名/路径, 见 engine/parsers/trivy.go)也按工件标识入账, 它们是
// 合法资产(SCA 漏洞挂在它上面), 但不是主机。"资产总数(主机维度)"这类统计
// 若用 Count() 会把 nginx:1.25-alpine 之类工件数进主机数, 与资产页"共 N 台
// 主机"对不上, 用户会认为是数据错误。
func (d *AssetDAO) CountHosts() (int, error) {
	return d.CountWhere(func(a *Asset) bool { return net.ParseIP(a.IP) != nil })
}

// DeleteDead 删除所有未存活(Alive=false)资产, 返回删除条数(一次落盘)。
//
// 口径: 存活过的资产 Alive 永不翻案 —— upsertProbeAsset 合并时只有
// `if a.Alive { cur.Alive = true }`(false 不覆盖历史 true), 所以 Alive=false
// 恰好全是"从未存活过"的探测 IP(网段扫描探出来、从没响应过), 批量清理不会
// 误删"扫描时上线、后来下线"的主机(它们 Alive 一直是 true)。
//
// 用 Purge 一次落盘而非逐条 Delete: 未存活动辄上百台, 逐条删 = 上百次全量
// 写盘(O(N^2) IO)。
func (d *AssetDAO) DeleteDead() (int, error) {
	return d.Purge(func(a *Asset) bool { return !a.Alive })
}

// GetMany 按 IP 集合精确取资产(单遍遍历, 找齐即早退)。
//
// 用途: 大屏"风险资产 TOP 榜"只需要榜单上那几十个 IP 的主机名/OS/端口数,
// 全表 List() 拷贝整张资产表是浪费。返回 map 只包含存在的 IP, 调用方对缺失
// IP 自行兜底(榜单上保留 IP 即可, 见 bigscreen.buildTopAssets 的既有口径)。
func (d *AssetDAO) GetMany(ips []string) (map[string]*Asset, error) {
	want := make(map[string]bool, len(ips))
	for _, raw := range ips {
		if ip := models.NormIP(raw); ip != "" {
			want[ip] = true
		}
	}
	out := make(map[string]*Asset, len(want))
	if len(want) == 0 {
		return out, nil
	}
	t := d.Table
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, id := range t.order {
		a := t.items[id]
		if want[a.IP] {
			cp := *a
			out[a.IP] = &cp
			delete(want, a.IP)
			if len(want) == 0 {
				break
			}
		}
	}
	return out, nil
}

// newAssetTable 打开资产表。
func newAssetTable(path string) (*AssetDAO, error) {
	t, err := NewTable[*Asset]("assets", path, func() *Asset { return &Asset{} })
	if err != nil {
		return nil, err
	}
	return &AssetDAO{Table: t}, nil
}

// FindByIP 按 IP(归一化)查资产。
func (d *AssetDAO) FindByIP(ip string) ([]*Asset, error) {
	ip = models.NormIP(ip)
	return d.Query(func(a *Asset) bool { return a.IP == ip })
}

// FindByTag 按标签查资产。
func (d *AssetDAO) FindByTag(tag string) ([]*Asset, error) {
	tag = strings.TrimSpace(tag)
	return d.Query(func(a *Asset) bool {
		for _, x := range a.Tags {
			if x == tag {
				return true
			}
		}
		return false
	})
}

// AddTag 给资产追加标签, 返回更新后的资产。
func (d *AssetDAO) AddTag(id string, tags ...string) (*Asset, error) {
	a, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	a.AddTags(tags...)
	if err := d.Update(a); err != nil {
		return a, err
	}
	return a, nil
}

// RemoveTag 移除资产标签, 返回更新后的资产。
func (d *AssetDAO) RemoveTag(id string, tags ...string) (*Asset, error) {
	a, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	a.RemoveTags(tags...)
	if err := d.Update(a); err != nil {
		return a, err
	}
	return a, nil
}
