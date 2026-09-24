package db

import (
	"errors"
	"strings"
	"time"
)

// PentaAuditLog 渗透审计表实体(独立于通用审计 audit_logs)。
//
// 阶段 5 口径(2026-09-24 调整): 所有渗透命令全程写入审计日志; 记录可被管理员
// 清空(分发给他人/数据交接时需要干净状态, 早期版本靠停服务手工删文件),
// 但清空不是"无痕擦除"——唯一删除路径是 Clear(), 其调用方(penta_api)在清空后
// 必写一条 penta.audit.clear 痕迹(谁/何时/清了多少条), "被清过"永远可审计,
// 与通用审计"清空日志留 audit.clear 痕迹"口径一致。
//
// 早期 penta.* 与通用审计混存一张表, 靠 DAO 层四处保护(单删/清空/按天裁剪/
// 超上限裁剪)防误删 —— 保护逻辑分散, 新增删除路径漏一处就是合规漏洞。
// 现独立成表且不提供通用 Delete/Prune 方法, 删除路径收敛到 Clear() 一处。
//
// 不设上限: 通用审计 5000 条上限 + 可自动裁剪(它是运维日志); 渗透审计是合规
// 留痕, 自动裁剪=变相删除, 只允许管理员显式清空(有留痕)。
// 量级评估: 每次任务生命周期事件 1 条 + 每步验证 1 条, 增长极小。
type PentaAuditLog struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId,omitempty"`
	Action    string    `json:"action"` // penta.task.create / penta.command / penta.task.run ...
	Target    string    `json:"target,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	ClientIP  string    `json:"clientIp,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// EntityID 记录 ID。
func (l *PentaAuditLog) EntityID() string {
	if l.ID == "" {
		l.ID = newID("pa")
	}
	return l.ID
}

// Validate 自检: 动作必填。
func (l *PentaAuditLog) Validate() error {
	if strings.TrimSpace(l.Action) == "" {
		return errors.New("渗透审计动作不能为空")
	}
	if l.ID == "" {
		l.ID = newID("pa")
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	return nil
}

// PentaAuditDAO 渗透审计 DAO: 追加 + 查询 + 管理员清空(唯一删除路径)。
type PentaAuditDAO struct {
	*Table[*PentaAuditLog]
}

// Clear 清空全部渗透审计记录, 一次落盘, 返回被清条数。
//
// 刻意不提供单条 Delete/Prune(与 AuditDAO 的差异): 渗透留痕要么全清要么不清,
// "挑几条删"没有合规语义。本方法是全表唯一删除入口, 调用方(penta_api 的
// hPentaAuditClear, adminOnly)清空后必须写 penta.audit.clear 痕迹 ——
// "留痕由调用方保证"在此集中说明, 不依赖调用者自觉。
func (d *PentaAuditDAO) Clear() (int, error) {
	return d.Table.Clear()
}

// newPentaAuditTable 打开渗透审计表。
func newPentaAuditTable(path string) (*PentaAuditDAO, error) {
	t, err := NewTable[*PentaAuditLog]("penta_audit", path, func() *PentaAuditLog { return &PentaAuditLog{} })
	if err != nil {
		return nil, err
	}
	return &PentaAuditDAO{Table: t}, nil
}

// Append 追加一条渗透审计(自动补 ID/时间; 无上限不裁剪)。
func (d *PentaAuditDAO) Append(l PentaAuditLog) error {
	if err := l.Validate(); err != nil {
		return err
	}
	_, err := d.Upsert(&l)
	return err
}

// Query 按过滤条件查询, 返回(倒序列表, 命中总数)。
// 过滤口径与通用审计 AuditFilter 完全一致(同结构体复用), 前端两页交互无差异。
func (d *PentaAuditDAO) Query(f AuditFilter) ([]*PentaAuditLog, int, error) {
	list, err := d.List()
	if err != nil {
		return nil, 0, err
	}
	var m []*PentaAuditLog
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
	// List 按时间升序 -> 原地反转为倒序(与 AuditDAO.Query 同口径)
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

// MigrateFromGeneralAudit 一次性迁移: 把旧版本混存进通用审计表的 penta.* 记录
// 搬入本表(保留原 ID 与全部字段), 并移除通用表中的对应条目。
//
// 幂等口径: 本表非空即视为"已迁移过", 整体跳过 —— 升级只发生一次, 之后
// 每次启动零开销。注意"搬"不是"删": 记录原样进入新表, 留痕不丢失。
//
// 走基类 Table.Delete 而非 AuditDAO.Delete: 后者的 isProtected 会拒绝
// penta.* 条目(那是防误删的保护, 迁移恰恰需要移走)。
func (d *PentaAuditDAO) MigrateFromGeneralAudit(src *AuditDAO) (int, error) {
	if src == nil || src.Table == nil {
		return 0, nil
	}
	if n, _ := d.Count(); n > 0 {
		return 0, nil
	}
	list, err := src.List()
	if err != nil {
		return 0, err
	}
	moved := 0
	for _, l := range list {
		if !strings.HasPrefix(l.Action, "penta.") {
			continue
		}
		rec := PentaAuditLog{
			ID:        l.ID,
			UserID:    l.UserID,
			Action:    l.Action,
			Target:    l.Target,
			Detail:    l.Detail,
			ClientIP:  l.ClientIP,
			CreatedAt: l.CreatedAt,
		}
		if err := d.Append(rec); err != nil {
			return moved, err
		}
		if _, err := src.Table.Delete(l.ID); err != nil {
			return moved, err
		}
		moved++
	}
	return moved, nil
}
