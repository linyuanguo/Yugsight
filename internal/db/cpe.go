package db

import (
	"errors"
	"strings"
	"time"
)

// CPE CPE 库表实体(中心管理端 CPE 台账; 实际版本匹配仍由
// scanner CPE 引擎执行, 本表用于审计/同步/展示)。
type CPE struct {
	ID        string    `json:"id"`             // CPE 字符串, 如 cpe:2.3:a:apache:http_server:2.4.49:*
	Part      string    `json:"part,omitempty"` // o(操作系统)|a(应用)|h(硬件)
	Vendor    string    `json:"vendor,omitempty"`
	Product   string    `json:"product,omitempty"`
	Version   string    `json:"version,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// EntityID CPE 字符串。
func (c *CPE) EntityID() string {
	return strings.TrimSpace(c.ID)
}

// Validate 自检: CPE 字符串必填。
func (c *CPE) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return errors.New("CPE 字符串不能为空")
	}
	c.ID = strings.TrimSpace(c.ID)
	c.UpdatedAt = time.Now()
	return nil
}

// CPEDAO CPE 库 DAO。
type CPEDAO struct {
	*Table[*CPE]
}

// newCPETable 打开 CPE 库表。
func newCPETable(path string) (*CPEDAO, error) {
	t, err := NewTable[*CPE]("cpe", path, func() *CPE { return &CPE{} })
	if err != nil {
		return nil, err
	}
	return &CPEDAO{Table: t}, nil
}

// FindByProduct 按产品(大小写不敏感)查 CPE。
func (d *CPEDAO) FindByProduct(product string) ([]*CPE, error) {
	p := strings.ToLower(strings.TrimSpace(product))
	return d.Query(func(c *CPE) bool { return strings.ToLower(c.Product) == p })
}
