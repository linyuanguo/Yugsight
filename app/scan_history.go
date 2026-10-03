// scan_history.go 扫描历史记录(2026-09-26, 用户口径"扫描记忆")。
//
// 背景: 此前 scan_tasks 表只有两条路径写入 —— 调度器直提交(persistSchedTask)
// 与探针下发(probe_api 建任务), 控制台"立即扫描"从不登记。用户看到的"扫描过
// 的任务"散落在原始报告里, 原始报告一删, 历史就彻底没了; 而报告生成下拉里的
// 任务名登记簿(scan_jobs)只是聚合索引, 不是完整历史。
//
// 本文件补上: ① runScanPipeline 入口把每次立即扫描登记进 scan_tasks(Params 存
// 完整 scanReq JSON, "重扫"= 按原参数重新提交 /api/scan); ② 批量删除选中
// (POST /api/v2/scans/batch-delete, 与 assets/raw 批量删除同口径)。
//
// 单条删除/清空/列表/查询等 API 早已在 api_v2.go 就绪, 这里只补缺口。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"yugsight/internal/db"
	"yugsight/internal/server"
)

// registerScanHistory 登记一条"运行中"的扫描历史, 返回任务 ID(失败返回空串)。
//
// 口径: 失败只记日志不阻断扫描 —— 历史登记是索引不是执行依赖(与任务名登记
// registerScanTask 同约定)。Params 存完整 scanReq JSON(含 engines/ruleMode/
// trivyTarget 等全部参数), 前端"重扫"原样回提交即可复现同一扫描。
func registerScanHistory(req scanReq) string {
	d := v2DB()
	if d == nil || d.ScanTasks() == nil {
		return ""
	}
	rec := &db.ScanTask{
		ID:        randHex(8),
		Type:      req.Type,
		Target:    scanTarget(req),
		// 2026-09-27: 任务名单列(历史页展示 + 报告聚合键, 不再埋在 Params 里)
		JobName:   strings.TrimSpace(req.JobName),
		Status:    db.TaskRunning,
		CreatedBy: currentUser(),
		ProbeNode: req.ProbeNode,
	}
	if raw, err := json.Marshal(req); err == nil {
		rec.Params = raw
	}
	if err := d.ScanTasks().Create(rec); err != nil {
		logLine("扫描历史登记失败(不影响扫描): " + err.Error())
		return ""
	}
	return rec.ID
}

// finishScanHistory 回写扫描历史的终态(成功/失败/取消)。失败只记日志。
func finishScanHistory(id, status, result string) {
	d := v2DB()
	if d == nil || d.ScanTasks() == nil {
		return
	}
	if _, err := d.ScanTasks().UpdateStatus(id, status, result); err != nil {
		logLine("扫描历史状态回写失败: " + err.Error())
	}
}

// cleanupStaleRunningScanTasks 服务启动时把上次残留的"运行中/待执行"扫描任务置失败。
//
// 背景(用户实测): 扫描进程重启后, 本地管线在内存里早已消失, 但 scan_tasks 里
// 的记录永远停在"运行中" —— 用户看到"昨晚的任务到现在还在运行中"。重启即中断
// 是事实, 状态必须如实标记。
//
// 两类残留都覆盖:
//   - 本地任务: 重启后管线没了, 不会再有回写, 置失败是终态;
//   - 探针任务: 探针可能仍在执行, 结果回来时 taskRecorder.Result 会经
//     UpdateStatus 纠正为成功/失败 —— 先置失败再纠正, 最终状态仍正确,
//     且"离线后无结果"的任务不再永久挂起。
//
// 失败只记日志(启动清理是 best-effort, 不阻断启动)。
func cleanupStaleRunningScanTasks() {
	d := v2DB()
	if d == nil || d.ScanTasks() == nil {
		return
	}
	var stale []*db.ScanTask
	if list, err := d.ScanTasks().ByStatus(db.TaskRunning); err == nil {
		stale = append(stale, list...)
	}
	if list, err := d.ScanTasks().ByStatus(db.TaskPending); err == nil {
		stale = append(stale, list...)
	}
	n := 0
	for _, t := range stale {
		if _, err := d.ScanTasks().UpdateStatus(t.ID, db.TaskFailed, "服务重启, 任务已中断"); err == nil {
			n++
		}
	}
	if n > 0 {
		logLine(fmt.Sprintf("启动清理: %d 条重启前残留的运行中扫描任务已置失败", n))
	}
}

// hV2ScanBatchDelete POST /api/v2/scans/batch-delete {ids} 批量删除选中扫描历史。
//
// 与 assets/raw 批量删除同口径: adminOrOperator, 单次上限 500, 逐条删、单条
// 失败不阻断其余, 审计一条汇总留痕。删除只影响任务记录本身 —— 该次扫描已落库
// 的资产/漏洞/原始报告不受影响(与单条删除 hV2ScanDelete 同语义)。
func hV2ScanBatchDelete(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.IDs) == 0 {
		server.FailBadRequest(w, "ids 不能为空")
		return
	}
	if len(in.IDs) > 500 {
		server.FailBadRequest(w, "单次批量上限 500 条")
		return
	}
	seen := make(map[string]bool, len(in.IDs))
	n := 0
	for _, id := range in.IDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if ok, err := d.ScanTasks().Delete(id); err == nil && ok {
			n++
		}
	}
	logAudit(d, r, "scan.batch_delete", "", fmt.Sprintf("批量删除 %d/%d 条", n, len(seen)))
	server.OK(w, map[string]any{"deleted": n})
}

// ===== 扫描取消(2026-09-27, 用户口径: "任务开始了, 去哪里取消?") =====
//
// 统一入口 POST /api/v2/scans/{id}/cancel, 覆盖三条执行路径:
//
//   - 探针任务  -> 向探针发 MsgTaskCancel(探针端 runTask 把取消接到执行 ctx,
//     扫描循环停 + trivy 等外部引擎子进程一并杀掉 —— 2026-09-27 修的取消 BUG);
//   - 本地立即扫描 -> runScanPipeline 登记的取消注册表(ctx 下传扫描引擎, 立即停,
//     状态由收尾逻辑回写 cancelled);
//   - 调度排队任务 -> 转交 scheduler.Cancel(排队/运行均命中; 探针节点的任务由
//     waitProbeCompletion 的 ctx 取消分支通知探针)。
//
// 注册表只登记"本地立即扫描"(调度路径的 ctx 归调度器所有, 不包 —— 包了会切断
// 调度器自己的取消/超时语义)。key 统一是 scan_tasks 的任务 ID。

var scanCancelMu sync.Mutex
var scanCancels = make(map[string]context.CancelFunc)

func registerScanCancel(id string, c context.CancelFunc) {
	scanCancelMu.Lock()
	scanCancels[id] = c
	scanCancelMu.Unlock()
}

func unregisterScanCancel(id string) {
	scanCancelMu.Lock()
	delete(scanCancels, id)
	scanCancelMu.Unlock()
}

// cancelLocalScan 取消运行中的本地立即扫描; 返回 false 表示不在注册表
// (已结束 / 不是立即扫描路径)。
func cancelLocalScan(id string) bool {
	scanCancelMu.Lock()
	c, ok := scanCancels[id]
	scanCancelMu.Unlock()
	if !ok {
		return false
	}
	c()
	return true
}

// hV2ScanCancel POST /api/v2/scans/{id}/cancel 取消运行中的扫描(扫描历史页统一入口)。
//
// 权限 adminOrOperator: 取消是执行链路的写操作(与创建/清空同级)。探针任务把明细
// 标 failed + "中心端取消"(探针任务表无 cancelled 常量, 与 hProbeCancel 同口径),
// 统一任务表的最终状态由探针结果回传按 Cancelled 标记写回 cancelled。
func hV2ScanCancel(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	id := r.PathValue("id")
	task, err := d.ScanTasks().Get(id)
	if err != nil || task == nil {
		server.FailNotFound(w, "任务不存在")
		return
	}
	switch task.Status {
	case db.TaskSuccess, db.TaskFailed, db.TaskCancelled:
		server.FailBadRequest(w, "任务已结束, 无需取消")
		return
	}

	via := ""
	if task.ProbeNode != "" {
		// 探针任务: 通知探针停止(探针端真正中断扫描, 见上方注释)
		if probeCenter == nil {
			server.FailBadRequest(w, "探针中心未启用, 无法取消远端任务")
			return
		}
		if err := probeCenter.CancelTask(task.ProbeNode, id); err != nil {
			server.FailBadRequest(w, "通知探针取消失败: "+err.Error())
			return
		}
		if d.ProbeTasks() != nil {
			_, _ = d.ProbeTasks().Finish(id, db.ProbeTaskFailed, "", "", "中心端取消", 0, 0)
		}
		via = "probe"
	} else if cancelLocalScan(id) {
		via = "local" // 本地立即扫描: ctx 取消, 收尾回写 cancelled
	} else if s := instanceScheduler(); s != nil {
		// 走到这里说明不是立即扫描(注册表未命中) —— 调度器任务
		if err := s.Cancel(id); err == nil {
			via = "scheduler"
		}
	}
	if via == "" {
		server.FailBadRequest(w, "任务当前未在运行(可能刚结束, 或重启后的远端残留记录)")
		return
	}
	logAudit(d, r, "scan.cancel", id, via)
	server.OK(w, map[string]any{"cancelled": true, "via": via})
}
