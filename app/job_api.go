package main

// 任务名登记(2026-09-25 四轮换口径, 用户要求"扫描作业页面去掉"):
// 扫描任务不再是"自动编排作业", 而是**扫描控制台立即扫描 + 任务名**驱动的
// 人工分步流程:
//
//	任务名 + IP/子网(可多个) 快速发现 → 勾选扫出的主机 → 主机漏扫 / web漏扫 /
//	弱口令 / 渗透(各步带同一任务名)
//
// 本文件只保留 scan_jobs 表作为**任务名登记簿**: 带任务名的扫描在
// runScanPipeline 入口自动登记(幂等 upsert, ID = 任务名), 报告中心据此:
//   - "按任务名生成报告"(漏洞 ScanTaskID="job-<任务名>", 资产 Jobs 含 <任务名>);
//   - "原始报告按任务名分类"(原始报告 Job=<任务名>);
//   - 弱口令/渗透按任务名关联(weakpass 批次 / penta 任务带 Job 字段)。
//
// 作业编排(深度扫描→弱口令→渗透自动串跑)已按用户要求删除: 分步由用户在
// 控制台手动发起, 哪一步做、对哪些主机做, 由人决定而不是自动流程。

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"yugsight/internal/db"
	"yugsight/internal/server"
)

// taskNameRe 任务名合法性: 中英文/数字/空格/-_./, 禁路径分隔符与空白串。
// 任务名会进 ScanTaskID("job-<名>")、资产 Jobs、原始报告 Job —— 是跨表关联键,
// 必须稳定可检索。
var taskNameRe = regexp.MustCompile(`^[\p{L}\p{N} .\-_]{1,64}$`)

// validTaskName 任务名校验(报告按它生成/分类, 非法名直接拒绝而不是静默落库)。
func validTaskName(name string) bool {
	return taskNameRe.MatchString(strings.TrimSpace(name))
}

// registerJobRoutes 任务名登记簿路由(报告中心的任务名下拉数据源)。
// 读 requireAuth; 写 adminOrOperator(与扫描能力同口径)。
func registerJobRoutes(srv *server.Server) {
	srv.Get("/api/v2/jobs", requireAuth(hJobList))
	srv.Post("/api/v2/jobs", requireAuth(adminOrOperator(hJobUpsert)))
	srv.Get("/api/v2/jobs/{id}", requireAuth(hJobGet))
	srv.Delete("/api/v2/jobs/{id}", requireAuth(adminOrOperator(hJobDelete)))
}

// hJobList 任务名列表(倒序; 报告中心"按任务名生成报告/分类原始报告"的下拉源)。
func hJobList(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil || d.Jobs() == nil {
		server.FailInternal(w, "任务名登记簿不可用")
		return
	}
	jobs, err := d.Jobs().List()
	if err != nil {
		server.FailInternal(w, "读取任务名列表: "+err.Error())
		return
	}
	items := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		items = append(items, jobToMap(j))
	}
	server.OK(w, map[string]any{"jobs": items, "total": len(items)})
}

// jobToMap 任务名 → 接口对象。
func jobToMap(j *db.ScanJob) map[string]any {
	return map[string]any{
		"id": j.ID, "name": j.Name, "target": j.Target,
		"createdBy": j.CreatedBy, "createdAt": j.CreatedAt,
	}
}

// hJobUpsert 任务名 upsert(幂等: 已存在只刷新最近目标)。
// 主路径其实是 runScanPipeline 的自动登记(registerScanTask), 本接口供
// API/脚本显式登记(如先建任务名再分批扫描)。
func hJobUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Target string `json:"target"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validTaskName(req.Name) {
		server.FailBadRequest(w, "任务名非法(中英文/数字/空格/-_./, 1-64 字)")
		return
	}
	j, err := registerScanTask(strings.TrimSpace(req.Name), strings.TrimSpace(req.Target))
	if err != nil {
		server.FailInternal(w, "登记任务名: "+err.Error())
		return
	}
	server.OK(w, jobToMap(j))
}

// hJobGet 任务名详情。
func hJobGet(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil || d.Jobs() == nil {
		server.FailInternal(w, "任务名登记簿不可用")
		return
	}
	id := r.PathValue("id")
	j, err := d.Jobs().Get(id)
	if err != nil {
		server.FailNotFound(w, "任务名不存在")
		return
	}
	server.OK(w, jobToMap(j))
}

// hJobDelete 删除任务名登记。已生成的报告/原始报告/漏洞/资产不受影响 ——
// 它们按任务名关联, 不依赖登记记录本身(删除后只是从下拉里消失)。
func hJobDelete(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil || d.Jobs() == nil {
		server.FailInternal(w, "任务名登记簿不可用")
		return
	}
	id := r.PathValue("id")
	if _, err := d.Jobs().Delete(id); err != nil {
		server.FailInternal(w, "删除任务名: "+err.Error())
		return
	}
	logLine("删除任务名登记 " + id)
	server.OK(w, map[string]any{"ok": true})
}

// registerScanTask 扫描入口的任务名登记(runScanPipeline 调用, 幂等):
// ID = 任务名(同名 = 同一任务, 后续各步骤的结果都挂到这个任务名下);
// 已存在则刷新最近目标(任务名是跨步骤的聚合键, 目标随步骤变化)。
// 失败只记日志不阻断扫描(登记簿不可用不该让扫描跑不了)。
func registerScanTask(name, target string) (*db.ScanJob, error) {
	d := v2DB()
	if d == nil || d.Jobs() == nil {
		return nil, fmt.Errorf("任务名登记簿不可用")
	}
	// Validate 要求 Target 非空: 弱口令/渗透入口可能没有"目标网段"概念(目标在
	// 各自的表里), 用 "-" 占位 —— Target 字段口径是"最近一次登记的目标", 不是唯一目标
	if target == "" {
		target = "-"
	}
	if j, err := d.Jobs().Get(name); err == nil && j != nil {
		if target != j.Target {
			j.Target = target
			if err := d.Jobs().Update(j); err != nil {
				return nil, err
			}
		}
		return j, nil
	}
	j := &db.ScanJob{
		ID:        name, // ID = 任务名: 报告/原始报告/漏洞/资产全部按任务名关联
		Name:      name,
		Target:    target,
		Status:    db.JobStatusSuccess,
		CreatedBy: currentUser(),
	}
	if err := d.Jobs().Create(j); err != nil {
		return nil, err
	}
	logLine(fmt.Sprintf("登记任务名 %s 目标=%s 发起人=%s", j.Name, j.Target, j.CreatedBy))
	return j, nil
}
