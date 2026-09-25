package db

import (
	"errors"
	"fmt"
	"strings"
)

// postgres.go PostgreSQL 驱动骨架(预留, 任务 4.1)。
//
// 任务要求: 预留驱动接口与连接配置, 仅做基础骨架, MVP 阶段不做完整实现,
// 企业级部署时可切换启用(仅修改 config.json 的 database.type=postgres)。
//
// 实现规划(待依赖约束放宽后落地):
//  1. 引入纯 Go 驱动(如 github.com/lib/pq / pgx), 经标准库 database/sql 接入;
//  2. 实现与 filestore.go 同等语义的存储层: 每表一张 SQL 表, DDL 由
//     各实体结构映射(列 = 字段, ID = 主键);
//  3. 打开时执行表结构初始化(等效 SQLite 的建表), 支持 WAL/连接池等企业特性;
//  4. 上层 DAO 与业务代码零改动(DAO[T] 接口已隔离存储层)。
//
// 现状: 连接配置解析与校验完整, Connect 返回明确的"未实现"错误,
// 上层据此降级(提示修改配置), 不 panic 不崩溃。
var ErrPostgresNotImplemented = errors.New(
	"postgres 驱动未完整实现(MVP 阶段, 仅预留接口): 请在 config.json 将 database.type 设为 sqlite")

// PostgresStore PostgreSQL 存储骨架。
type PostgresStore struct {
	cfg PGConfig
}

// newPostgresStore 校验连接配置并创建骨架实例。
func newPostgresStore(cfg PGConfig) (*PostgresStore, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("postgres host 为空(需在 config.json 的 database.postgres.host 配置)")
	}
	if cfg.Port == 0 {
		cfg.Port = 5432
	}
	if cfg.DB == "" {
		cfg.DB = "yugsight"
	}
	if cfg.User == "" {
		cfg.User = "yugsight"
	}
	return &PostgresStore{cfg: cfg}, nil
}

// Connect 尝试建立连接。MVP 阶段: 始终返回未实现错误。
func (s *PostgresStore) Connect() error {
	return ErrPostgresNotImplemented
}

// DSN 生成连接串(驱动实现后直接可用)。
func (s *PostgresStore) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		s.cfg.Host, s.cfg.Port, s.cfg.User, s.cfg.Pass, s.cfg.DB)
}

// Ping 连接探活(驱动实现后启用)。
func (s *PostgresStore) Ping() error {
	return ErrPostgresNotImplemented
}
