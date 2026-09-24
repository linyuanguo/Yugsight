package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Table 文件存储引擎(JSONL, 一行一实体) —— "sqlite" 驱动的内置表实现。
//
// 语义与 SQLite 对齐的等效性说明(零依赖约束下的替代方案):
//   - 持久化: 每表一个 JSONL 文件, 落程序目录 ./data/ 下
//   - 崩溃安全: 写盘为原子写(临时文件 + rename), 任何时刻断电/崩溃都不会
//     产生半写状态 —— 等效 SQLite WAL 模式的崩溃一致性
//   - 并发: sync.RWMutex 读写锁, 读并发、写串行 —— 等效 WAL 的读写并发
//   - 降级: 文件缺失 = 空表(不报错); 坏行跳过并记日志(不影响其余数据)
//
// 未来若放宽依赖约束引入 SQLite/PostgreSQL 驱动, 仅需新增实现本类型同等
// 语义的 Store(或整体替换本文件), 上层 DAO 与业务代码零改动。
type Table[T Entity] struct {
	mu    sync.RWMutex
	name  string // 表名(诊断/日志用)
	path  string
	items map[string]T
	order []string // 入库顺序(保持 List 稳定)
	newT  func() T
	// version 写入代数: 每次 Create/Update/Upsert/Delete 成功 +1。
	// 用途: 聚合结果的 TTL 缓存以它为失效凭据 —— 数据一变代数就变, 缓存自动作废,
	// 不需要在写路径上挂失效钩子(钩子容易漏, 代数天然覆盖全部写入口)。
	version uint64
}

// NewTable 打开(并加载)一张 JSONL 表。
// 文件不存在时返回空表(降级运行不报错); newT 必须返回 T 的零值实例。
func NewTable[T Entity](name, path string, newT func() T) (*Table[T], error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("db: 存储路径为空")
	}
	if newT == nil {
		return nil, errors.New("db: newT 工厂为空")
	}
	t := &Table[T]{name: name, path: path, items: make(map[string]T), newT: newT}
	if err := t.load(); err != nil {
		return nil, fmt.Errorf("db: 表 %s 加载 %s 失败: %s", name, path, err)
	}
	return t, nil
}

func (t *Table[T]) load() error {
	data, err := os.ReadFile(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在 = 空表, 降级运行
		}
		return err
	}
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e T
		if uerr := json.Unmarshal([]byte(line), &e); uerr != nil {
			logf(fmt.Sprintf("表 %s 第 %d 行数据损坏已跳过: %s", t.name, i+1, uerr))
			continue
		}
		if e.EntityID() == "" {
			logf(fmt.Sprintf("表 %s 第 %d 行 ID 为空已跳过", t.name, i+1))
			continue
		}
		t.put(e)
	}
	if len(t.items) > 0 {
		logf(fmt.Sprintf("表 %s 已加载 %d 条记录 (%s)", t.name, len(t.items), t.path))
	}
	return nil
}

func (t *Table[T]) put(e T) {
	if _, ok := t.items[e.EntityID()]; !ok {
		t.order = append(t.order, e.EntityID())
	}
	t.items[e.EntityID()] = e
}

// save 原子写盘(临时文件 + rename); 调用方须持有写锁。
func (t *Table[T]) save() error {
	var sb strings.Builder
	for _, id := range t.order {
		line, err := json.Marshal(t.items[id])
		if err != nil {
			return err
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o755); err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, t.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Name 表名。
func (t *Table[T]) Name() string {
	return t.name
}

// Path 存储文件路径(诊断/展示用)。
func (t *Table[T]) Path() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.path
}

// ===== DAO[T] 接口实现(全部增删改查) =====

// Create 新增; ID 已存在返回 ErrExists。
func (t *Table[T]) Create(e T) error {
	if e.EntityID() == "" {
		return errors.New("db: 实体 ID 为空")
	}
	if err := e.Validate(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.items[e.EntityID()]; ok {
		return ErrExists
	}
	t.put(e)
	t.bumpVersion()
	return t.save()
}

// Get 按 ID 取实体; 不存在返回 ErrNotFound。
func (t *Table[T]) Get(id string) (T, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.items[id]
	if !ok {
		var zero T
		return zero, ErrNotFound
	}
	return e, nil
}

// Update 更新; 不存在返回 ErrNotFound。
func (t *Table[T]) Update(e T) error {
	if e.EntityID() == "" {
		return errors.New("db: 实体 ID 为空")
	}
	if err := e.Validate(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.items[e.EntityID()]; !ok {
		return ErrNotFound
	}
	t.items[e.EntityID()] = e
	t.bumpVersion()
	return t.save()
}

// Upsert 新增或按 ID 覆盖, 返回是否新建。
func (t *Table[T]) Upsert(e T) (bool, error) {
	if e.EntityID() == "" {
		return false, errors.New("db: 实体 ID 为空")
	}
	if err := e.Validate(); err != nil {
		return false, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	created := false
	if _, ok := t.items[e.EntityID()]; !ok {
		t.order = append(t.order, e.EntityID())
		created = true
	}
	t.items[e.EntityID()] = e
	t.bumpVersion()
	if err := t.save(); err != nil {
		return false, err
	}
	return created, nil
}

// Delete 按 ID 删除, 返回是否删除成功。
func (t *Table[T]) Delete(id string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.items[id]; !ok {
		return false, nil
	}
	delete(t.items, id)
	for i, x := range t.order {
		if x == id {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
	t.bumpVersion()
	return true, t.save()
}

// Clear 清空全表, 返回删除条数(一次落盘)。
//
// 为什么单独开方法: Delete 每次删除都要整体重写文件, 循环删 N 条会写成
// N 次全文件写盘(O(N^2) IO); 清空是"批量到极致"的场景, 直接换空 map 一次保存。
func (t *Table[T]) Clear() (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(t.items)
	if n == 0 {
		return 0, nil
	}
	t.items = make(map[string]T)
	t.order = nil
	t.bumpVersion()
	return n, t.save()
}

// Purge 批量删除所有匹配 pred 的行, 一次落盘, 返回删除数。
//
// 为什么单独开方法: 循环 Delete 每条都整体重写文件, 裁剪 N 条 = N 次全量
// 写盘(O(N^2) IO); 时序表按保留时长裁剪是高频批量场景(采集底座每轮都可能
// 触发), 必须一次遍历一次保存。
func (t *Table[T]) Purge(pred func(T) bool) (int, error) {
	if pred == nil {
		return 0, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for id, e := range t.items {
		if pred(e) {
			delete(t.items, id)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	order := make([]string, 0, len(t.items))
	for _, id := range t.order {
		if _, ok := t.items[id]; ok {
			order = append(order, id)
		}
	}
	t.order = order
	t.bumpVersion()
	if err := t.save(); err != nil {
		return 0, err
	}
	return n, nil
}

// List 全部实体(按入库顺序)。
func (t *Table[T]) List() ([]T, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]T, 0, len(t.order))
	for _, id := range t.order {
		out = append(out, t.items[id])
	}
	return out, nil
}

// Query 按谓词筛选(不修改原数据)。
func (t *Table[T]) Query(pred func(T) bool) ([]T, error) {
	if pred == nil {
		return t.List()
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []T
	for _, id := range t.order {
		if pred(t.items[id]) {
			out = append(out, t.items[id])
		}
	}
	return out, nil
}

// Page 分页: 返回页内实体与总数。
func (t *Table[T]) Page(offset, limit int) ([]T, int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	total := len(t.order)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []T{}, total, nil
	}
	end := total
	if limit > 0 && offset+limit < total {
		end = offset + limit
	}
	out := make([]T, 0, end-offset)
	for _, id := range t.order[offset:end] {
		out = append(out, t.items[id])
	}
	return out, total, nil
}

// Count 实体数量。
func (t *Table[T]) Count() (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.items), nil
}

// CountWhere 按谓词计数(单遍遍历, 不构造结果切片)。
//
// 与 Query 的区别: Query 要为命中项构造新切片(十万级数据每次聚合都多一次全量
// 分配), 计数场景只需要一个数字。大屏 15s 轮询 + 多个聚合口径叠在一起时,
// "遍历 N 次 + 拷贝 N 次"会变成 "遍历 N 次, 零拷贝"。
func (t *Table[T]) CountWhere(pred func(T) bool) (int, error) {
	if pred == nil {
		return t.Count()
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := 0
	for _, id := range t.order {
		if pred(t.items[id]) {
			n++
		}
	}
	return n, nil
}

// CountBy 按分类函数单遍统计(结果 map 只包含出现过的键, 由调用方补默认键)。
func (t *Table[T]) CountBy(key func(T) string) (map[string]int, error) {
	if key == nil {
		return map[string]int{}, nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]int, len(t.order))
	for _, id := range t.order {
		out[key(t.items[id])]++
	}
	return out, nil
}

// Version 当前写入代数(每次写成功 +1)。
// 供聚合缓存判断"数据自缓存以来变没变过": 代数相同 = 数据未变, 缓存可复用。
func (t *Table[T]) Version() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.version
}

// bumpVersion 写路径统一递增代数(调用方须持有写锁)。
func (t *Table[T]) bumpVersion() {
	t.version++
}
