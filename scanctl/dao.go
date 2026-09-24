//go:build !windows || windows

// dao.go 统一持久化 DAO 接口 + 双存储实现(JSONL 文件 / 内存)。
//
// 设计(任务 3.2 "所有规则持久化存储通过统一 DAO 接口执行, 业务代码不直接
// 编写原生 SQL, 保证双数据库兼容性"):
//   - Entity: 持久化实体契约(ID + 自检), WhitelistEntry / FPSRule 均实现之
//   - DAO[T]: 泛型 CRUD 契约(List/Get/Add/Remove), 业务代码只依赖该接口,
//     不感知底层存储介质 —— 换存储实现时业务零改动
//   - 双存储实现: FileDAO(JSONL 文件, 生产默认) + MemDAO(内存, 测试/降级),
//     同一接口两个后端, 验证 DAO 抽象的存储无关性
//
// 关于 SQLite: 任务书要求误报等结果存入 SQLite。本项目的硬约束是纯 Go
// 标准库、零第三方依赖、单二进制跨平台, 标准库不含 SQLite 驱动
// (go-sqlite3 需 CGO 与 C 编译链, modernc.org/sqlite 为第三方依赖),
// 与任务 1 规则包/CPE 库的 SQLite 决策一致, 采用等效本地文件存储
// (JSONL, 一行一实体, 原子写 tmp+rename), 并以上述 DAO 接口隔离存储层:
// 未来若放宽依赖约束引入 SQLite 驱动, 只需新增一个 sqliteDAO 实现,
// 白名单/误报等业务代码一行不改。
//
// 依赖: 仅 Go 标准库。
package scanctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"yugsight/pathrel"
)

// Entity 持久化实体契约: 有稳定 ID, 能自检合法性。
// (方法名不用 ID, 避免与实体自身的 ID 字段冲突)
type Entity interface {
	EntityID() string
	Validate() error
}

// DAO 统一数据访问接口(泛型): 业务代码只依赖本接口, 不直接操作
// 文件/SQL, 保证双(多)存储后端兼容。
type DAO[T Entity] interface {
	// List 返回全部实体(副本, 按入库顺序)。
	List() ([]T, error)
	// Get 按 ID 取实体(副本); 不存在返回 (零值, ErrNotFound)。
	Get(id string) (T, error)
	// Add 新增或按 ID 覆盖(upsert); 写入前调用 Validate()。
	Add(e T) error
	// Remove 按 ID 删除, 返回是否删除成功。
	Remove(id string) (bool, error)
	// Count 实体数量。
	Count() int
}

// ErrNotFound 实体不存在
var ErrNotFound = errors.New("实体不存在")

var daoLog = slog.Default().With("component", "scanctl.dao")

// ===== 文件存储实现(JSONL) =====

// FileDAO 基于 JSONL 文件的 DAO 实现(一行一个实体 JSON)。
// 线程安全; 写盘为原子写(临时文件 + rename); 文件缺失 = 空集(降级不报错),
// 坏行跳过并记日志(不影响其余实体)。
type FileDAO[T Entity] struct {
	mu    sync.RWMutex
	path  string
	items map[string]T
	order []string // 入库顺序(保持 List 稳定)
	newT  func() T
}

// NewFileDAO 打开(并加载) JSONL 文件存储。
// path 为空返回错误; 文件不存在时返回空存储(nil 错误, 降级运行)。
// newT 必须返回 T 的零值实例(反序列化目标)。
func NewFileDAO[T Entity](path string, newT func() T) (*FileDAO[T], error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("FileDAO: 存储路径为空")
	}
	if newT == nil {
		return nil, errors.New("FileDAO: newT 工厂为空")
	}
	d := &FileDAO[T]{path: path, items: make(map[string]T), newT: newT}
	if err := d.load(); err != nil {
		return nil, fmt.Errorf("FileDAO 加载 %s 失败: %s", path, err)
	}
	return d, nil
}

func (d *FileDAO[T]) load() error {
	data, err := os.ReadFile(d.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在 = 空集, 降级运行不报错
		}
		return err
	}
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e T
		// file 走 pathrel.Short: slog 属性不经过 logLine 的相对化兜底,
		// 控制台口径"出现路径就用相对"
		short := pathrel.Short(d.path)
		if uerr := json.Unmarshal([]byte(line), &e); uerr != nil {
			daoLog.Warn("JSONL 坏行已跳过", "file", short, "line", i+1, "err", uerr.Error())
			continue
		}
		if e.EntityID() == "" {
			daoLog.Warn("JSONL 实体 ID 为空已跳过", "file", short, "line", i+1)
			continue
		}
		d.put(e)
	}
	if len(d.items) > 0 {
		daoLog.Info("存储已加载", "file", pathrel.Short(d.path), "count", len(d.items))
	}
	return nil
}

func (d *FileDAO[T]) put(e T) {
	if _, ok := d.items[e.EntityID()]; !ok {
		d.order = append(d.order, e.EntityID())
	}
	d.items[e.EntityID()] = e
}

// save 原子写盘(临时文件 + rename); 调用方须持有写锁
func (d *FileDAO[T]) save() error {
	var sb strings.Builder
	for _, id := range d.order {
		line, err := json.Marshal(d.items[id])
		if err != nil {
			return err
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(d.path), 0o755); err != nil {
		return err
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, d.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Path 存储文件路径(诊断/展示用)
func (d *FileDAO[T]) Path() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.path
}

func (d *FileDAO[T]) List() ([]T, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]T, 0, len(d.order))
	for _, id := range d.order {
		out = append(out, d.items[id])
	}
	return out, nil
}

func (d *FileDAO[T]) Get(id string) (T, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	e, ok := d.items[id]
	if !ok {
		var zero T
		return zero, ErrNotFound
	}
	return e, nil
}

func (d *FileDAO[T]) Add(e T) error {
	if e.EntityID() == "" {
		return errors.New("实体 ID 为空")
	}
	if err := e.Validate(); err != nil {
		return err
	}
	d.mu.Lock()
	d.put(e)
	err := d.save()
	d.mu.Unlock()
	return err
}

func (d *FileDAO[T]) Remove(id string) (bool, error) {
	d.mu.Lock()
	if _, ok := d.items[id]; !ok {
		d.mu.Unlock()
		return false, nil
	}
	delete(d.items, id)
	for i, x := range d.order {
		if x == id {
			d.order = append(d.order[:i], d.order[i+1:]...)
			break
		}
	}
	err := d.save()
	d.mu.Unlock()
	return true, err
}

func (d *FileDAO[T]) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.items)
}

// ===== 内存存储实现(测试 / 无盘降级) =====

// MemDAO 纯内存 DAO(与 FileDAO 同接口, 双后端兼容性的第二实现)。
type MemDAO[T Entity] struct {
	mu    sync.RWMutex
	items map[string]T
	order []string
	newT  func() T
}

// NewMemDAO 创建内存 DAO(从现有条目初始化, 可传 nil)
func NewMemDAO[T Entity](newT func() T, seed ...T) *MemDAO[T] {
	m := &MemDAO[T]{items: make(map[string]T), newT: newT}
	for _, e := range seed {
		if e.EntityID() != "" {
			m.put(e)
		}
	}
	return m
}

func (m *MemDAO[T]) put(e T) {
	if _, ok := m.items[e.EntityID()]; !ok {
		m.order = append(m.order, e.EntityID())
	}
	m.items[e.EntityID()] = e
}

func (m *MemDAO[T]) List() ([]T, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]T, 0, len(m.order))
	for _, id := range m.order {
		out = append(out, m.items[id])
	}
	return out, nil
}

func (m *MemDAO[T]) Get(id string) (T, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.items[id]
	if !ok {
		var zero T
		return zero, ErrNotFound
	}
	return e, nil
}

func (m *MemDAO[T]) Add(e T) error {
	if e.EntityID() == "" {
		return errors.New("实体 ID 为空")
	}
	if err := e.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	m.put(e)
	m.mu.Unlock()
	return nil
}

func (m *MemDAO[T]) Remove(id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[id]; !ok {
		return false, nil
	}
	delete(m.items, id)
	for i, x := range m.order {
		if x == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	return true, nil
}

func (m *MemDAO[T]) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// ===== 默认数据目录 =====

// DefaultDataDir 默认数据目录: exe 同目录 scanctl/
// (白名单 whitelist.jsonl / 误报 fps.jsonl 存于此; 路径可被测试覆盖)。
func DefaultDataDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "scanctl")
	}
	return "scanctl"
}
