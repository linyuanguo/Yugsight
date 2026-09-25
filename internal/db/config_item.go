package db

import (
	"errors"
	"strings"
	"time"
)

// ConfigItem 授权配置表实体(key-value, 如 license.key / 授权期限等)。
type ConfigItem struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Desc      string    `json:"desc,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// EntityID 配置键。
func (c *ConfigItem) EntityID() string {
	return c.Key
}

// Validate 自检: 键必填。
func (c *ConfigItem) Validate() error {
	if strings.TrimSpace(c.Key) == "" {
		return errors.New("配置键不能为空")
	}
	c.Key = strings.TrimSpace(c.Key)
	c.UpdatedAt = time.Now()
	return nil
}

// ConfigDAO 授权配置 DAO: 基础 CRUD + 按键读写。
type ConfigDAO struct {
	*Table[*ConfigItem]
}

// newConfigTable 打开授权配置表。
func newConfigTable(path string) (*ConfigDAO, error) {
	t, err := NewTable[*ConfigItem]("configs", path, func() *ConfigItem { return &ConfigItem{} })
	if err != nil {
		return nil, err
	}
	return &ConfigDAO{Table: t}, nil
}

// GetKey 按键取值(返回完整条目)。
func (d *ConfigDAO) GetKey(key string) (*ConfigItem, error) {
	return d.Get(key)
}

// SetKey 按键写入(新增或覆盖)。
func (d *ConfigDAO) SetKey(key, value, desc string) (*ConfigItem, error) {
	item := &ConfigItem{Key: key, Value: value, Desc: desc}
	if _, err := d.Upsert(item); err != nil {
		return item, err
	}
	return item, nil
}
