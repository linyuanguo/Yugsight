package weakpass

import "time"

// Attempt 一次口令尝试的审计记录。
//
// 设计要点: **口令只在命中时记录**。审计的目的是"可追责"(谁在什么时候测了
// 哪个目标、用了什么账号), 如果把每次尝试的明文口令都写进日志, 审计文件本身
// 就变成了一份口令库 —— 那是最糟糕的副作用。命中时记下来则是必要的:
// 报告里必须能说清"到底是哪个口令通了"。
type Attempt struct {
	Time     time.Time `json:"time"`
	Target   string    `json:"target"`
	Service  string    `json:"service"`
	User     string    `json:"user,omitempty"`
	Password string    `json:"password,omitempty"`
	OK       bool      `json:"ok"`
	Err      string    `json:"err,omitempty"`
}

// record 写入审计缓冲并转发给外部落地方(如 slog)。
func (e *Engine) record(a Attempt) {
	e.mu.Lock()
	e.audit = append(e.audit, a)
	if len(e.audit) > auditMax {
		e.audit = e.audit[len(e.audit)-auditMax:]
	}
	sink := e.auditSink
	e.mu.Unlock()
	if sink != nil {
		sink(a)
	}
}

// Audit 取最近 limit 条审计记录(倒序: 最新在前)。limit<=0 返回全部。
func (e *Engine) Audit(limit int) []Attempt {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := len(e.audit)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Attempt, 0, n)
	for i := len(e.audit) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, e.audit[i])
	}
	return out
}

// AuditCount 审计记录总数(受环形上限约束)。
func (e *Engine) AuditCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.audit)
}
