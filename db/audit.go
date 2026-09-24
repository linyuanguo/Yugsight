package db

import (
	"errors"
	"strings"
	"time"
)

// AuditLog 审计日志表实体(只追加; 超上限自动裁剪最旧记录)。
type AuditLog struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId,omitempty"`
	Action    string    `json:"action"` // 如 asset.create / vuln.query / scan.create
	Target    string    `json:"target,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	ClientIP  string    `json:"clientIp,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// 审计日志上限(防止无限增长; 超出时裁剪最旧记录)。
const maxAuditEntries = 5000

// isProtected 审计记录是否不可删除(合规留痕)。
//
// 主路径已改: 渗透审计(penta.*)现写入独立表 penta_audit(见 penta_audit.go,
// 表结构本身不提供删除路径)。本保护是**兜底**, 防旧版本遗留数据 —— 升级前
// 混存在本表的 penta.* 记录在迁移完成前(或迁移失败时)仍受这里保护,
// 四个删除路径(单条删 / 手工清空 / 按天裁剪 / 超上限自动裁剪)行为一致。
// 不删这个函数: 迁移是一次性 best-effort, 兜底必须比迁移更可靠。
func isProtected(action string) bool {
	return strings.HasPrefix(action, "penta.")
}

// EntityID 日志 ID。
func (l *AuditLog) EntityID() string {
	if l.ID == "" {
		l.ID = newID("al")
	}
	return l.ID
}

// Validate 自检: 动作必填。
func (l *AuditLog) Validate() error {
	if strings.TrimSpace(l.Action) == "" {
		return errors.New("审计动作不能为空")
	}
	if l.ID == "" {
		l.ID = newID("al")
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	return nil
}

// AuditDAO 审计日志 DAO: 追加 + 倒序查询 + 自动裁剪。
type AuditDAO struct {
	*Table[*AuditLog]
}

// newAuditTable 打开审计日志表。
func newAuditTable(path string) (*AuditDAO, error) {
	t, err := NewTable[*AuditLog]("audit_logs", path, func() *AuditLog { return &AuditLog{} })
	if err != nil {
		return nil, err
	}
	return &AuditDAO{Table: t}, nil
}

// Append 追加一条审计日志(自动补 ID/时间, 超上限裁剪最旧)。
func (d *AuditDAO) Append(l AuditLog) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if _, err := d.Upsert(&l); err != nil {
		return err
	}
	if n, err := d.Count(); err == nil && n > maxAuditEntries {
		d.prune(n - maxAuditEntries)
	}
	return nil
}

// Recent 最近 N 条(按时间倒序)。
func (d *AuditDAO) Recent(limit int) ([]*AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	list, err := d.List()
	if err != nil {
		return nil, err
	}
	if len(list) > limit {
		list = list[len(list)-limit:]
	}
	out := make([]*AuditLog, 0, len(list))
	for i := len(list) - 1; i >= 0; i-- {
		out = append(out, list[i])
	}
	return out, nil
}

// AuditFilter 审计查询过滤(全可选, 空 = 不过滤)。
//
// 表上限 5000 条, 内存过滤足够, 不引入 SQL WHERE —— 与其余 DAO 的 List+处理
// 风格一致, 两个驱动(sqlite/postgres)行为也不会分叉。
type AuditFilter struct {
	User    string // 精确匹配用户
	Action  string // 包含匹配动作(如 "scan" 命中 scan.start/scan.finish)
	Keyword string // target/detail/action 模糊(大小写不敏感)
	From    time.Time
	To      time.Time
	Limit   int
	Offset  int
}

// Query 按过滤条件查询, 返回(倒序列表, 命中总数)。
func (d *AuditDAO) Query(f AuditFilter) ([]*AuditLog, int, error) {
	list, err := d.List()
	if err != nil {
		return nil, 0, err
	}
	var m []*AuditLog
	for _, l := range list {
		if f.User != "" && l.UserID != f.User {
			continue
		}
		if f.Action != "" && !strings.Contains(l.Action, f.Action) {
			continue
		}
		if f.Keyword != "" {
			kw := strings.ToLower(f.Keyword)
			if !strings.Contains(strings.ToLower(l.Action), kw) &&
				!strings.Contains(strings.ToLower(l.Target), kw) &&
				!strings.Contains(strings.ToLower(l.Detail), kw) {
				continue
			}
		}
		if !f.From.IsZero() && l.CreatedAt.Before(f.From) {
			continue
		}
		if !f.To.IsZero() && l.CreatedAt.After(f.To) {
			continue
		}
		m = append(m, l)
	}
	total := len(m)
	// List 按时间升序 -> 原地反转为倒序
	for i, j := 0, len(m)-1; i < j; i, j = i+1, j-1 {
		m[i], m[j] = m[j], m[i]
	}
	if f.Offset > 0 {
		if f.Offset >= len(m) {
			m = m[:0]
		} else {
			m = m[f.Offset:]
		}
	}
	if f.Limit > 0 && len(m) > f.Limit {
		m = m[:f.Limit]
	}
	return m, total, nil
}

// Delete 删除单条: 渗透审计记录(penta.*)不可删除, 其余走基类。
//
// 语义与基类 Table.Delete 对齐: 记录不存在 = (false, nil) 而非 error
// (handler 据此回 404 而不是 500); 只有"受保护"才返回 error(400 语义)。
func (d *AuditDAO) Delete(id string) (bool, error) {
	l, err := d.Get(id)
	if err != nil {
		return false, nil
	}
	if isProtected(l.Action) {
		return false, errors.New("渗透审计记录不可删除(penta.* 动作属合规留痕)")
	}
	return d.Table.Delete(id)
}

// PruneOlderThan 删除早于 cutoff 的记录, 返回删除条数(保存天数裁剪用)。
// 保护记录(penta.*)跳过 —— 渗透审计不因保存天数过期。
func (d *AuditDAO) PruneOlderThan(cutoff time.Time) int {
	if cutoff.IsZero() {
		return 0
	}
	list, err := d.List()
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range list {
		if l.CreatedAt.Before(cutoff) && !isProtected(l.Action) {
			if _, err := d.Table.Delete(l.ID); err == nil {
				n++
			}
		}
	}
	return n
}

// DeleteAll 清空审计记录, 返回删除条数(管理员手工清理日志用)。
// 保护记录(penta.*)跳过: "清空日志"不能把渗透留痕一起清掉(合规红线)。
func (d *AuditDAO) DeleteAll() (int, error) {
	return d.Table.Purge(func(l *AuditLog) bool { return !isProtected(l.Action) })
}

// prune 超上限裁剪最旧若干条(内部, 调用方须自行保证串行)。
// 保护记录(penta.*)跳过 —— 5000 条上限预算里渗透留痕优先保留。
func (d *AuditDAO) prune(n int) {
	list, _ := d.List()
	deleted := 0
	for _, l := range list {
		if deleted >= n {
			break
		}
		if isProtected(l.Action) {
			continue
		}
		if _, err := d.Table.Delete(l.ID); err == nil {
			deleted++
		}
	}
}
