package db

import (
	"errors"
	"strings"
	"time"

	"yugsight/models"
)

// 规则来源类型常量。
const (
	RuleTypeBuiltin = "builtin" // 内置规则(YUGSIGHT-000X)
	RuleTypeNuclei  = "nuclei"  // Nuclei 模板
	RuleTypeCPE     = "cpe"     // CPE 版本匹配规则
	RuleTypeCustom  = "custom"  // 用户自定义
)

// Rule 规则库表实体(中心管理端规则台账; 实际扫描规则仍由
// scanner 规则包管理器加载, 本表用于审计/同步/展示)。
type Rule struct {
	ID        string    `json:"id"` // 规则 ID(YUGSIGHT-000X / 模板 ID / CPE 规则 ID)
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity,omitempty"`
	CVE       string    `json:"cve,omitempty"`
	Source    string    `json:"source,omitempty"`
	Enabled   bool      `json:"enabled"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// EntityID 规则 ID。
func (r *Rule) EntityID() string {
	if r.ID == "" {
		r.ID = newID("rl")
	}
	return r.ID
}

// Validate 自检: ID / 标题必填, 等级归一化。
func (r *Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return errors.New("规则 ID 不能为空")
	}
	if strings.TrimSpace(r.Title) == "" {
		return errors.New("规则标题不能为空")
	}
	if r.Type == "" {
		r.Type = RuleTypeCustom
	}
	r.Severity = models.NormalizeSeverity(r.Severity)
	r.CVE = models.NormalizeCVE(r.CVE)
	r.UpdatedAt = time.Now()
	return nil
}

// NewRule 构造规则(默认启用)。
func NewRule(id, typ, title string) *Rule {
	return &Rule{ID: id, Type: typ, Title: title, Enabled: true}
}

// RuleDAO 规则库 DAO。
type RuleDAO struct {
	*Table[*Rule]
}

// newRuleTable 打开规则库表。
func newRuleTable(path string) (*RuleDAO, error) {
	t, err := NewTable[*Rule]("rules", path, func() *Rule { return &Rule{} })
	if err != nil {
		return nil, err
	}
	return &RuleDAO{Table: t}, nil
}

// EnabledOnly 启用中的规则。
func (d *RuleDAO) EnabledOnly() ([]*Rule, error) {
	return d.Query(func(r *Rule) bool { return r.Enabled })
}
