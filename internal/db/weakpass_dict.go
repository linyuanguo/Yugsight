package db

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// 弱口令字典条目类型。
//
// default = 内置(程序首次启动自动写入的 349 条常用弱口令, 不可删除);
// custom  = 自定义(页面新增, 可删除, 重置时被清除)。
const (
	WeakDictBuiltin = "default"
	WeakDictCustom  = "custom"
)

// WeakDictMaxPasswordLen 单条口令长度上限。
//
// 为什么要有上限: 口令最终会进爆破循环逐次发送, 一条几十 KB 的"口令"
// 既不是口令也是 DoS 材料; 128 足够覆盖任何真实口令场景。
const WeakDictMaxPasswordLen = 128

// WeakPassDictEntry 弱口令字典表实体(表 weak_password_dict, 第 21 表)。
//
// 设计口径: 字典是弱口令检测模块的"数据资产", 与执行链路解耦 ——
// 引擎每次执行时全量读取(内置在前、自定义在后), 本表只负责存与查。
type WeakPassDictEntry struct {
	ID         string    `json:"id"`
	Password   string    `json:"password"`
	Type       string    `json:"type"` // default | custom
	CreateTime time.Time `json:"createTime"`
}

// EntityID 条目 ID(wp d 前缀, 与报告/模板等 ID 前缀区分)。
func (e *WeakPassDictEntry) EntityID() string {
	if e.ID == "" {
		e.ID = newID("wpd")
	}
	return e.ID
}

// Validate 自检: 口令非空(仅去首尾空白, 口令中间的空格是合法内容) +
// 长度上限 + 类型合法。ID/CreateTime 缺省自动补齐。
func (e *WeakPassDictEntry) Validate() error {
	e.Password = strings.TrimSpace(e.Password)
	if e.Password == "" {
		return errWeakDictEmpty
	}
	if len(e.Password) > WeakDictMaxPasswordLen {
		return errWeakDictTooLong
	}
	switch e.Type {
	case WeakDictBuiltin, WeakDictCustom:
	default:
		return errWeakDictBadType
	}
	if e.ID == "" {
		e.ID = newID("wpd")
	}
	if e.CreateTime.IsZero() {
		e.CreateTime = time.Now()
	}
	return nil
}

// 校验错误(与通用 ErrNotFound/ErrExists 区分, 供 API 层给出可读提示)。
var (
	errWeakDictEmpty   = errors.New("口令不能为空")
	errWeakDictTooLong = errors.New("口令超过 " + strconv.Itoa(WeakDictMaxPasswordLen) + " 字符上限")
	errWeakDictBadType = errors.New("条目类型非法: 需为 default/custom")
)

// WeakPassDictDAO 弱口令字典 DAO: 基础 CRUD(Table 提供) + 字典专用操作。
type WeakPassDictDAO struct {
	*Table[*WeakPassDictEntry]
}

// newWeakPassDictTable 打开弱口令字典表。
func newWeakPassDictTable(path string) (*WeakPassDictDAO, error) {
	t, err := NewTable[*WeakPassDictEntry]("weak_password_dict", path, func() *WeakPassDictEntry {
		return &WeakPassDictEntry{}
	})
	if err != nil {
		return nil, err
	}
	return &WeakPassDictDAO{Table: t}, nil
}

// SeedBuiltin 批量写入内置字典(首次启动初始化用), 一次落盘, 返回写入条数。
//
// 为什么不走循环 Create: 349 条逐条 Create = 349 次全文件重写(O(N^2) IO);
// 直接操作 Table 内部状态(同包可见)一次遍历一次保存, 首启耗时从 ~秒级降到毫秒级。
// 调用方负责幂等判定(ensureWeakPassDict: 表内已有 default 条目则跳过),
// 本方法只做"追加不覆盖": 已存在的口令(按 Password 判重)跳过。
func (d *WeakPassDictDAO) SeedBuiltin(passwords []string) (int, error) {
	if len(passwords) == 0 {
		return 0, nil
	}
	t := d.Table
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	n := 0
	for _, p := range passwords {
		p = strings.TrimSpace(p)
		if p == "" || len(p) > WeakDictMaxPasswordLen {
			continue
		}
		if d.passwordExists(t, p) {
			continue
		}
		e := &WeakPassDictEntry{
			ID:         newID("wpd"),
			Password:   p,
			Type:       WeakDictBuiltin,
			CreateTime: now,
		}
		t.put(e)
		n++
	}
	if n == 0 {
		return 0, nil
	}
	t.bumpVersion()
	return n, t.save()
}

// passwordExists 按口令判重(单遍扫描; 字典规模数百~数千, 建索引不划算)。
// 调用方须持有 Table 写锁。
func (d *WeakPassDictDAO) passwordExists(t *Table[*WeakPassDictEntry], p string) bool {
	for _, id := range t.order {
		if t.items[id].Password == p {
			return true
		}
	}
	return false
}

// FindByPassword 按口令精确取条目(新增判重用); 不存在返回 (nil, nil)。
func (d *WeakPassDictDAO) FindByPassword(p string) (*WeakPassDictEntry, error) {
	list, err := d.Query(func(e *WeakPassDictEntry) bool { return e.Password == p })
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	return list[0], nil
}

// Search 按口令模糊搜索(大小写不敏感的包含匹配)。
func (d *WeakPassDictDAO) Search(q string) ([]*WeakPassDictEntry, error) {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return d.List()
	}
	return d.Query(func(e *WeakPassDictEntry) bool {
		return strings.Contains(strings.ToLower(e.Password), q)
	})
}

// CountByType 按类型计数(default / custom)。
func (d *WeakPassDictDAO) CountByType(typ string) (int, error) {
	return d.CountWhere(func(e *WeakPassDictEntry) bool { return e.Type == typ })
}

// DeleteCustom 批量删除自定义条目(Reset 用): 一次遍历一次落盘, 返回删除数。
// 内置条目绝不被本方法触碰 —— 重置的保底语义是"内置 349 必须回来"。
func (d *WeakPassDictDAO) DeleteCustom() (int, error) {
	return d.Purge(func(e *WeakPassDictEntry) bool { return e.Type == WeakDictCustom })
}
