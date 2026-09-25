//go:build !windows || windows

// fps.go 人工误报管理(基于统一 DAO)。
//
// 能力(任务 3.2):
//   - Web 端标记漏洞为误报, 支持添加误报备注, 结果经统一 DAO 持久化
//     (任务书要求 SQLite; 因纯标准库硬约束采用等效 JSONL 文件存储,
//      见 dao.go 头部说明, 接口预留 SQLite 实现位)
//   - 后续扫描命中相同资产 + CVE 时自动标记为误报(AutoMark)
//   - 无 CVE 的漏洞退化为"资产 + 标题"匹配(与归一化合并键口径一致)
//
// 依赖: 仅 Go 标准库 + yugsight/models。
package scanctl

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"yugsight/internal/models"
)

// FPSRule 误报规则(Entity): 一条 = "某资产的某漏洞是误报"
type FPSRule struct {
	ID        string    `json:"id"`
	AssetIP   string    `json:"assetIp"`
	CVE       string    `json:"cve,omitempty"`  // 归一化后大写; 空 = 按标题匹配
	Title     string    `json:"title,omitempty"` // CVE 为空时的匹配键
	Note      string    `json:"note,omitempty"`  // 误报备注
	MarkedBy  string    `json:"markedBy,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// FPSKey 误报匹配键: 归一化 IP + "|" + 归一化 CVE; CVE 为空时
// 退化为 归一化 IP + "|||" + 标题(与 models.Vuln.MergeKey 口径一致)。
func FPSKey(ip, cve, title string) string {
	if c := models.NormalizeCVE(cve); c != "" {
		return models.NormIP(ip) + "|" + c
	}
	return models.NormIP(ip) + "|||" + strings.TrimSpace(title)
}

// EntityID Entity 契约
func (r FPSRule) EntityID() string { return r.ID }

// MatchKey 匹配键(归一化)
func (r FPSRule) MatchKey() string { return FPSKey(r.AssetIP, r.CVE, r.Title) }

// Validate Entity 契约: 资产必填, CVE / 标题至少其一
func (r FPSRule) Validate() error {
	if models.NormIP(r.AssetIP) == "" {
		return fmt.Errorf("误报标记: 资产 IP 不能为空")
	}
	if models.NormalizeCVE(r.CVE) == "" && strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("误报标记: CVE 编号与标题至少填写一项")
	}
	return nil
}

// FPS 误报管理器(缓存 + DAO 持久化)
type FPS struct {
	mu    sync.RWMutex
	dao   DAO[FPSRule]
	rules []FPSRule
}

// NewFPS 基于 DAO 构建误报管理器并加载存量规则
func NewFPS(dao DAO[FPSRule]) (*FPS, error) {
	f := &FPS{dao: dao}
	rs, err := dao.List()
	if err != nil {
		return nil, err
	}
	f.rules = rs
	return f, nil
}

// DAO 返回底层 DAO(诊断用)
func (f *FPS) DAO() DAO[FPSRule] {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.dao
}

// Count 规则数
func (f *FPS) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.rules)
}

// List 全部规则(副本, 按入库顺序)
func (f *FPS) List() []FPSRule {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]FPSRule, len(f.rules))
	copy(out, f.rules)
	return out
}

// Mark 标记 (资产 + CVE) 为误报并持久化(带备注)。
// 重复标记同一键时覆盖备注(幂等)。CVE 为空时用 title 兜底匹配。
func (f *FPS) Mark(ip, cve, title, note, markedBy string) (FPSRule, error) {
	r := FPSRule{
		AssetIP:   models.NormIP(ip),
		CVE:       models.NormalizeCVE(cve),
		Title:     strings.TrimSpace(title),
		Note:      strings.TrimSpace(note),
		MarkedBy:  strings.TrimSpace(markedBy),
		CreatedAt: time.Now(),
	}
	if r.CVE == "" && r.Title == "" {
		return FPSRule{}, fmt.Errorf("误报标记: CVE 编号与标题至少填写一项")
	}
	r.ID = "fps-" + shortHash(r.MatchKey())
	if err := r.Validate(); err != nil {
		return FPSRule{}, err
	}
	if err := f.dao.Add(r); err != nil {
		return FPSRule{}, err
	}
	f.mu.Lock()
	for i := range f.rules {
		if f.rules[i].ID == r.ID {
			f.rules[i] = r
			break
		}
	}
	f.rules = upsertRule(f.rules, r)
	f.mu.Unlock()
	return r, nil
}

// Remove 按 ID 删除规则并持久化, 返回是否删除成功
func (f *FPS) Remove(id string) (bool, error) {
	removed, err := f.dao.Remove(id)
	if err != nil || !removed {
		return removed, err
	}
	f.mu.Lock()
	for i := range f.rules {
		if f.rules[i].ID == id {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			break
		}
	}
	f.mu.Unlock()
	return true, nil
}

func upsertRule(list []FPSRule, r FPSRule) []FPSRule {
	for i := range list {
		if list[i].ID == r.ID {
			list[i] = r
			return list
		}
	}
	return append(list, r)
}

func shortHash(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ruleMatch 规则是否命中 (资产, 漏洞):
// 同资产 IP + 同 CVE; 规则无 CVE 时按同资产 + 同标题。
func ruleMatch(r FPSRule, a *models.Asset, v *models.Vuln) bool {
	ip := ""
	if a != nil {
		ip = a.IP
	} else {
		ip = v.AssetIP
	}
	if models.NormIP(ip) != models.NormIP(r.AssetIP) {
		return false
	}
	if r.CVE != "" {
		return v.CVE != "" && models.NormalizeCVE(v.CVE) == r.CVE
	}
	return v.Title != "" && v.Title == r.Title
}

// Match 判断 (资产, 漏洞) 是否命中误报规则, 返回 (是否命中, 命中规则)。
func (f *FPS) Match(a *models.Asset, v *models.Vuln) (bool, FPSRule) {
	if v == nil {
		return false, FPSRule{}
	}
	f.mu.RLock()
	rules := f.rules
	f.mu.RUnlock()
	for _, r := range rules {
		if ruleMatch(r, a, v) {
			return true, r
		}
	}
	return false, FPSRule{}
}

// AutoMark 批量自动标记: 命中误报规则的漏洞就地置
// FalsePositive=true 并写入备注(FPNote), 返回被标记条数。
// 后续扫描命中相同资产 + CVE 时即自动标记为误报。
func (f *FPS) AutoMark(assets []*models.Asset, vulns []*models.Vuln) int {
	f.mu.RLock()
	rules := f.rules
	f.mu.RUnlock()
	if len(rules) == 0 {
		return 0
	}
	idx := AssetIndex(assets)
	n := 0
	for _, v := range vulns {
		if v == nil || v.FalsePositive {
			continue
		}
		if r, hit := f.matchRule(idx[v.AssetIP], v); hit {
			v.FalsePositive = true
			v.FPNote = r.Note
			n++
		}
	}
	return n
}

func (f *FPS) matchRule(a *models.Asset, v *models.Vuln) (FPSRule, bool) {
	f.mu.RLock()
	rules := f.rules
	f.mu.RUnlock()
	for _, r := range rules {
		if ruleMatch(r, a, v) {
			return r, true
		}
	}
	return FPSRule{}, false
}

// SortedByCreated 规则按创建时间降序(UI 展示用)
func SortedRulesByCreated(rs []FPSRule) []FPSRule {
	out := make([]FPSRule, len(rs))
	copy(out, rs)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}
