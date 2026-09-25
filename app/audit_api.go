package main

// audit_api.go 审计日志增强(2026-09-20):
//
//   - 保存天数: settings.json 的 audit 节 {"retentionDays": 90}(0 = 不限制, 只受
//     5000 条上限裁剪)。用户诉求"日志保存天数设置"。
//   - 裁剪时机: 启动时 + 每小时一次(定时循环), 以及保存新设置后立即执行一次。
//   - 配置 API: GET/POST /api/v2/audit/config(POST 为 adminOnly, 热保存无需重启)。
//
// 审计"写"侧的覆盖面(2026-09-20 补齐): 系统启动 / 登录成功与失败 / 登出 /
// 扫描开始与结束 / 用户增删改 / 会话吊销 / 白名单与资产漏洞写操作 / 规则库更新
// 与回滚 / 报告生成与下载 / 审计配置保存 —— 即"操作、启动等"全量入审计。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"yugsight/internal/server"
)

// defaultAuditRetentionDays 审计日志默认保存天数。
//
// 90 天是折中: 安全审计惯例至少 90 天(等保 2.0 三级要求审计记录 ≥6 个月,
// 但单文件 5000 条上限决定了长周期靠"条数+天数"双裁剪), 又不会让 data 目录
// 无限增长。0 = 不限制(只受 5000 条上限裁剪)。
const defaultAuditRetentionDays = 90

type auditConfig struct {
	RetentionDays int `json:"retentionDays"` // 保存天数, 0 = 不限制
}

// loadAuditConfig 读取 audit 节; 节缺失/字段缺失用默认值(90 天)。
//
// 直读磁盘而非走 loadSettings 的启动缓存: 本页保存后值立即变化, 走缓存会
// 出现"保存成功但读回还是旧值"的假象(调度器用内存实例读所以没这个问题,
// 这里没有实例, 直接读盘最直白)。
func loadAuditConfig() auditConfig {
	cfg := auditConfig{RetentionDays: defaultAuditRetentionDays}
	data, err := os.ReadFile(settingsFilePath())
	if err != nil || len(data) == 0 {
		return cfg
	}
	var m map[string]json.RawMessage
	if uerr := json.Unmarshal(stripBOM(data), &m); uerr != nil {
		return cfg
	}
	if raw, ok := m[secAudit]; ok && string(raw) != "null" {
		if uerr := json.Unmarshal(raw, &cfg); uerr != nil || cfg.RetentionDays < 0 {
			cfg = auditConfig{RetentionDays: defaultAuditRetentionDays}
		}
	}
	return cfg
}

// auditPruneOnce 按保存天数裁剪一次过期记录(库不可用/未设置天数时静默跳过)。
func auditPruneOnce() {
	d := v2DB()
	if d == nil || d.Audits() == nil {
		return
	}
	cfg := loadAuditConfig()
	if cfg.RetentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)
	if n := d.Audits().PruneOlderThan(cutoff); n > 0 {
		logLine(fmt.Sprintf("审计日志裁剪: 删除 %d 条超过 %d 天的记录", n, cfg.RetentionDays))
	}
}

// startAuditRetentionLoop 启动即裁剪一次, 之后每小时一次(与"启动也要有日志"的
// 诉求配套: 老数据在启动时就被清掉, 不等到下一个小时)。
func startAuditRetentionLoop() {
	go func() {
		auditPruneOnce()
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			auditPruneOnce()
		}
	}()
}

// hV2AuditConfigGet GET /api/v2/audit/config
func hV2AuditConfigGet(w http.ResponseWriter, r *http.Request) {
	server.OK(w, loadAuditConfig())
}

// hV2AuditConfigSet POST /api/v2/audit/config {retentionDays}
//
// 保存后立即裁剪一次: 用户把天数从 365 改到 7 时, 期望"保存即生效",
// 而不是等下一个整点。
func hV2AuditConfigSet(w http.ResponseWriter, r *http.Request) {
	var in auditConfig
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		server.FailBadRequest(w, "请求格式错误")
		return
	}
	if in.RetentionDays < 0 || in.RetentionDays > 3650 {
		server.FailBadRequest(w, "retentionDays 需在 0~3650 之间(0 = 不限制)")
		return
	}
	if err := writeSection(secAudit, in); err != nil {
		server.FailInternal(w, "保存失败: "+err.Error())
		return
	}
	logAudit(v2DB(), r, "audit.config.save", "", fmt.Sprintf("retentionDays=%d", in.RetentionDays))
	auditPruneOnce()
	server.OK(w, in)
}

// hV2AuditClear DELETE /api/v2/audit 清理审计日志(admin)。
//
// ?days=N 只清理 N 天前的记录; 不带参数 = 清空全部。
// 清理动作本身必须留痕: 先清理, 再写一条 audit.clear / audit.prune 记录 ——
// 否则"日志被清空"这件事在审计里完全无迹可查, 与审计存在的意义相悖。
func hV2AuditClear(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	dao := d.Audits()
	if dao == nil {
		server.FailInternal(w, "审计表不可用")
		return
	}
	if days, _ := strconv.Atoi(r.URL.Query().Get("days")); days > 0 {
		n := dao.PruneOlderThan(time.Now().AddDate(0, 0, -days))
		logAudit(d, r, "audit.prune", "", fmt.Sprintf("清理 %d 天前的审计日志 %d 条", days, n))
		server.OK(w, map[string]any{"deleted": n, "days": days})
		return
	}
	n, err := dao.DeleteAll()
	if err != nil {
		server.FailInternal(w, "清空失败: "+err.Error())
		return
	}
	logAudit(d, r, "audit.clear", "", fmt.Sprintf("清空审计日志 %d 条", n))
	server.OK(w, map[string]any{"deleted": n})
}

// hV2AuditDeleteOne DELETE /api/v2/audit/{id} 删除单条审计记录(admin)。
func hV2AuditDeleteOne(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	dao := d.Audits()
	if dao == nil {
		server.FailInternal(w, "审计表不可用")
		return
	}
	id := r.PathValue("id")
	ok, err := dao.Delete(id)
	if err != nil {
		server.FailInternal(w, "删除失败: "+err.Error())
		return
	}
	if !ok {
		server.FailNotFound(w, "审计记录不存在")
		return
	}
	logAudit(d, r, "audit.delete", id, "删除单条审计记录")
	server.OK(w, map[string]any{"deleted": 1})
}
