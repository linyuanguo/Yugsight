// Package db Yugsight 第二阶段统一 DAO 数据访问层(任务 4.1)。
//
// 设计(对齐项目硬约束: 纯 Go 标准库、零第三方依赖、单二进制跨平台):
//
// 抽象 DAO 数据访问层:
//   - Entity: 持久化实体契约(稳定 ID + 自检), 覆盖资产/漏洞/白名单/扫描任务/
//     用户账号/会话/授权配置/规则库/CPE 库/审计日志/探针管理全部数据表
//   - DAO[T]: 泛型统一数据访问接口(Create/Get/Update/Upsert/Delete/List/
//     Query/Page/Count), 业务代码只调用 DAO 接口, 完全不感知底层存储介质 ——
//     换驱动实现时业务零改动
//
// 双驱动实现:
//   - "sqlite"(默认): 内置文件存储引擎(见 filestore.go), 数据落程序目录
//     ./data/ 下每表一个 JSONL 文件。Go 标准库不含 SQLite 驱动
//     (go-sqlite3 需 CGO 与 C 编译链, modernc.org/sqlite 为第三方依赖),
//     与任务 1/3.2 的 SQLite 替代决策一致: 文件引擎提供等效持久化语义 ——
//     原子写(tmp+rename)保证崩溃安全(等效 WAL 崩溃一致性), 读写锁保证并发
//   - "postgres"(预留): 驱动接口与连接配置骨架(见 postgres.go), MVP 阶段
//     不做完整实现, 企业级部署时可切换启用
//
// 配置开关: 程序目录 config.json 的 database.type 选项(sqlite / postgres,
// 默认 sqlite), 切换数据库仅修改配置, 业务代码零改动。
//
// 本包仅依赖 Go 标准库与 yugsight/models。
package db

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Entity 持久化实体契约: 有稳定 ID, 能自检合法性。
// (方法名不用 ID, 避免与实体自身 ID 字段冲突, 同 scanctl 约定)
type Entity interface {
	EntityID() string
	Validate() error
}

// DAO 统一数据访问接口(泛型): 封装全部增删改查操作。
// 业务层只依赖本接口, 不直接写 SQL / 不直接操作存储文件。
type DAO[T Entity] interface {
	// Create 新增; ID 已存在返回 ErrExists。写入前调用 Validate()。
	Create(e T) error
	// Get 按 ID 取实体; 不存在返回 (零值, ErrNotFound)。
	Get(id string) (T, error)
	// Update 更新; 不存在返回 ErrNotFound。
	Update(e T) error
	// Upsert 新增或按 ID 覆盖; 返回是否新建。
	Upsert(e T) (bool, error)
	// Delete 按 ID 删除, 返回是否删除成功。
	Delete(id string) (bool, error)
	// List 全部实体(按入库顺序)。
	List() ([]T, error)
	// Query 按谓词筛选。
	Query(pred func(T) bool) ([]T, error)
	// Page 分页: 返回页内实体与总数(offset 从 0 起, limit<=0 取全部)。
	Page(offset, limit int) ([]T, int, error)
	// Count 实体数量。
	Count() (int, error)
}

// 通用错误。
var (
	ErrNotFound = errors.New("记录不存在")
	ErrExists   = errors.New("记录已存在")
)

var (
	dbLog = slog.Default().With("component", "db")
	// logf 模块日志出口(默认 slog); 主程序可经 SetLogger 接入 yugsight.log
	logf = func(msg string) { dbLog.Info(msg) }
)

// SetLogger 注入日志函数(如主程序 logLine, 使 db 日志并入 yugsight.log)。
func SetLogger(f func(string)) {
	if f != nil {
		logf = f
	}
}

// SetConfigReader 注入数据库配置内容来源(优先于 config.json 文件)。
//
// 【为什么需要】配置统一到 settings.json 后, 数据库配置只是其中一个 database 节。
// db 包的定位是"只依赖标准库 + models"的存储层, 不该知道 settings.json 的存在
// (那会让存储层依赖装配层的配置约定)。因此只接受"给我原始 JSON 字节"的函数,
// 由装配层决定从哪取。返回 (内容, 是否存在)。
func SetConfigReader(f func() ([]byte, bool)) {
	if f != nil {
		cfgReadFunc = f
	}
}

// cfgReadFunc 注入的配置读取函数(见 SetConfigReader)。
var cfgReadFunc func() ([]byte, bool)

// newID 生成带前缀的唯一 ID: 前缀 + UnixNano + 随机 3 字节 hex。
func newID(prefix string) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s%d-%s", prefix, time.Now().UnixNano(), hex.EncodeToString(b))
}

// ===== 配置 =====

// PGConfig PostgreSQL 连接配置(预留)。
type PGConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
	DB   string `json:"db"`
}

// Config 数据库配置(来自程序目录 config.json 的 database 段)。
//
//	Type 驱动类型: "sqlite"(默认, 内置文件引擎) | "postgres"(预留骨架)
//	Dir  数据目录: 缺省为程序目录 ./data
type Config struct {
	Type     string   `json:"type"`
	Dir      string   `json:"dir"`
	Postgres PGConfig `json:"postgres"`
}

// 驱动类型常量。
const (
	TypeSQLite   = "sqlite"
	TypePostgres = "postgres"
)

// DefaultDataDir 默认数据目录: 程序目录 ./data
// (任务 4.1: 数据库文件存放于 ./data 文件夹)。
func DefaultDataDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "data")
	}
	return "data"
}

// DefaultConfig 默认配置: sqlite + ./data。
func DefaultConfig() Config {
	return Config{Type: TypeSQLite, Dir: DefaultDataDir()}
}

// LoadConfig 读取程序目录 config.json({ "database": { "type": ..., "dir": ... } }),
// 文件缺失 / 解析失败时返回默认配置并附原因(可选配置, 静默降级不报错)。
func LoadConfig() (Config, error) {
	cfg := DefaultConfig()
	// 优先用注入的来源(装配层注入 = settings.json 的 database 节, 内容直接是
	// Config 结构); 未注入时回退读 config.json 的 database 段(外面包了一层)。
	if cfgReadFunc != nil {
		data, ok := cfgReadFunc()
		if !ok {
			return cfg, nil
		}
		var raw Config
		if err := json.Unmarshal(data, &raw); err != nil {
			return cfg, fmt.Errorf("settings.json 的 database 节解析失败: %s", err)
		}
		if raw.Type != "" {
			cfg.Type = raw.Type
		}
		if raw.Dir != "" {
			cfg.Dir = raw.Dir
		}
		cfg.Postgres = raw.Postgres
		return cfg, nil
	}
	// 红线「配置唯一」(2026-09-23 整改): 不再回退读 config.json。
	// 数据库配置只来自 settings.json 的 database 节(由主程序注入 configReader);
	// 旧 config.json 的 database 节由主程序启动时迁入 settings.json 并改名
	// .migrated。未配置 = 默认内置 SQLite, 不报错。
	return cfg, nil
}
