// penta_api.go 渗透工作台(阶段 5)HTTP 装配层 —— main 包与 penta 包的唯一连接点。
//
// 阶段 5 四条硬规则(改动前必读):
//
//  1. 职责隔离: 扫描模块只做广谱探测发现漏洞, 不做漏洞利用; 本模块只对漏洞
//     管理里已登记的已知漏洞做验证渗透, 不做广谱扫描。
//  2. 权限隔离: 全部接口 requireAuth + adminOnly —— operator/auditor 无入口
//     无权限(渗透是攻击性能力, 权限边界比扫描模块的 adminOrOperator 更严)。
//  3. 审计: 每次执行与每一步探测写 penta.* 审计, 落**独立表 penta_audit**
//     (与通用审计物理隔离: 通用审计 5000 上限可清空, 渗透留痕不可混入可清理
//     池; 记录仅管理员可清空(分发/数据交接场景), 清空动作本身写
//     penta.audit.clear 痕迹, "被清过"永远可审计, 见 db/penta_audit.go)。
//  4. 授权: 每次执行必须携带 ack=true(前端授权确认勾选), 缺失一律拒绝 ——
//     "仅可对授权目标使用"在接口层落地, 不依赖前端自觉。
//
// 路由(均在 main.go 注册, 全部 adminOnly):
//
//	GET  /api/v2/penta/status                 模块状态(开关/模板数/任务数/安全声明)
//	GET  /api/v2/penta/tasks                  任务列表(状态/风险/目标筛选 + 分页)
//	POST /api/v2/penta/tasks                  手动创建任务
//	POST /api/v2/penta/tasks/import           从漏洞管理一键导入(vulnIds)
//	PUT  /api/v2/penta/tasks/{id}             保存验证结果(结论/风险修正/摘要/备注)
//	DELETE /api/v2/penta/tasks/{id}           删除任务
//	POST /api/v2/penta/tasks/batch            批量删除 {ids}
//	POST /api/v2/penta/tasks/export           批量导出 {ids} -> JSON 下载
//	POST /api/v2/penta/tasks/{id}/run         执行验证(SSE 流式回显, 需 ack)
//	GET  /api/v2/penta/tasks/{id}/result      任务执行结果(证据/日志)
//	GET  /api/v2/penta/templates              EXP 模板库(内置+自定义, tag 筛选)
//	POST /api/v2/penta/templates/import       导入自定义 EXP 模板(YAML/JSON)
//	POST /api/v2/penta/tasks/{id}/feedback    一键回传漏洞管理(更新验证状态)
//	GET  /api/v2/penta/audit                  渗透审计列表(独立表)
//	DELETE /api/v2/penta/audit                清空渗透审计(admin 专用, 清空动作留痕)
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"yugsight/db"
	"yugsight/penta"
	"yugsight/server"
)

// ===== 模块配置(默认开启, 见 PentaConfig 注释说明理由) =====

// PentaConfig 渗透模块配置(settings.json 的 penta 节)。
type PentaConfig struct {
	// Enabled 总开关, 默认 true。
	//
	// 为什么不是"默认关闭"(项目规则 5 的适用边界): 本模块无任何自主行为 ——
	// 无后台循环、页面加载零外连、不自动发起任何连接; 全部网络动作都是 admin
	// 显式触发的"执行", 且每次执行都有授权确认(ack)与全程审计(清空亦留痕)。
	// "逐次授权 + 全程留痕"是比配置开关更强的控制, 配置开关在这里只承担
	// "全局熔断"职责(审计期间/失密场景可整体停用执行能力)。
	Enabled bool `json:"enabled"`
}

// loadPentaConfig 读 penta 节(缺失 = 默认开; 显式 enabled=false 才关)。
func loadPentaConfig() PentaConfig {
	cfg := PentaConfig{Enabled: true}
	data, ok := section(secPenta, "")
	if !ok {
		return cfg
	}
	var out struct {
		Enabled *bool `json:"enabled"`
	}
	if json.Unmarshal(stripBOM(data), &out) == nil && out.Enabled != nil {
		cfg.Enabled = *out.Enabled
	}
	return cfg
}

func pentaEnabled() bool { return loadPentaConfig().Enabled }

// pentaStatement 内置安全声明(界面与审计口径共用一份文案)。
// 口径(2026-09-24): 不再宣称"不可删除"——记录可被管理员清空(分发场景),
// 但清空动作本身留痕, 合规承诺落在"被清过永远可审计"上。
const pentaStatement = "本模块仅可用于验证自己拥有或已获书面授权的目标系统。所有渗透命令全程写入审计日志，审计记录仅管理员可清空，且清空操作本身同样留痕；未经授权对他人系统实施渗透可能违反《中华人民共和国网络安全法》及相关法律法规。"

// ===== 引擎与模板单例 =====

var (
	pentaEngOnce sync.Once
	pentaEng     *penta.Engine

	pentaRunningMu sync.Mutex
	pentaRunning   = map[string]bool{} // taskId -> 执行中(防并发重复执行)
)

// instancePenta 全局验证引擎(懒加载; BinsDir = exe 同目录 bin/)。
func instancePenta() *penta.Engine {
	pentaEngOnce.Do(func() {
		pentaEng = penta.NewEngine(filepath.Join(authCheckExeDir(), "bin"))
	})
	return pentaEng
}

// pentaTemplateDir 自定义模板目录(exe 同目录 penta_templates/, 与 vuln/ 同约定)。
func pentaTemplateDir() string {
	return filepath.Join(authCheckExeDir(), penta.CustomTemplateDir)
}

// pentaTemplates 全量模板(内置 + 自定义)与 tag 全集。
func pentaTemplates() (builtin, custom []penta.Template, tags []string) {
	builtin = penta.BuiltinTemplates
	custom = penta.LoadCustom(pentaTemplateDir())
	seen := map[string]bool{}
	addTags := func(ts []string) {
		for _, t := range ts {
			t = strings.TrimSpace(t)
			if t != "" && !seen[t] {
				seen[t] = true
				tags = append(tags, t)
			}
		}
	}
	for _, t := range builtin {
		addTags(t.Tags)
	}
	for _, t := range custom {
		addTags(t.Tags)
	}
	return
}

// findPentaTemplate 按 ID 找模板(自定义优先, 允许自定义覆盖非内置的同 ID)。
func findPentaTemplate(id string) *penta.Template {
	for i := range penta.BuiltinTemplates {
		if penta.BuiltinTemplates[i].ID == id {
			t := penta.BuiltinTemplates[i]
			return &t
		}
	}
	for _, t := range penta.LoadCustom(pentaTemplateDir()) {
		if t.ID == id {
			return &t
		}
	}
	return nil
}

// ===== 通用守卫 =====

// pentaGuard 统一前置检查: 模块开关 + 任务存在。返回 (任务, 是否已回包)。
func pentaGuard(w http.ResponseWriter, d *db.Database, id string) *db.PentaTask {
	if !pentaEnabled() {
		server.Fail(w, http.StatusForbidden, 40300, "渗透工作台已停用(settings.json 的 penta.enabled=false)")
		return nil
	}
	if d == nil || d.PentaTasks() == nil {
		server.FailInternal(w, "渗透任务表不可用")
		return nil
	}
	t, err := d.PentaTasks().Get(id)
	if err != nil {
		server.FailNotFound(w, "渗透任务不存在")
		return nil
	}
	return t
}

// logPentaAudit 写渗透审计(独立表 penta_audit)。
//
// 与通用审计 logAudit 刻意分开: 通用审计有 5000 条上限且允许"清空日志",
// 渗透命令的合规留痕不能进同一个"可被清理"的池子 —— 此前混存靠 DAO 层
// 四处保护, 现在独立表 + 删除路径收敛到 Clear() 一处(清空必留痕)。
// r 可为 nil(非 HTTP 触发事件), 口径同 logAudit。
func logPentaAudit(d *db.Database, r *http.Request, action, target, detail string) {
	if d == nil || d.PentaAudits() == nil {
		return
	}
	ip := ""
	if r != nil {
		ip = clientIP(r)
	}
	rec := db.PentaAuditLog{
		UserID:   currentUser(),
		Action:   action,
		Target:   target,
		Detail:   detail,
		ClientIP: ip,
	}
	if err := d.PentaAudits().Append(rec); err != nil {
		logLine("渗透审计写入失败: " + err.Error())
		return
	}
	// 与 logAudit 同口径: 同时写运行日志, 排障时 yugsight.log 是第一份材料
	logLine(fmt.Sprintf("[渗透审计] %s %s %s %s", rec.UserID, action, target, detail))
}

// ===== API =====

// hPentaStatus GET /api/v2/penta/status
func hPentaStatus(w http.ResponseWriter, r *http.Request) {
	d := v2GetDB()
	b, c, tags := pentaTemplates()
	taskCount := 0
	if d != nil && d.PentaTasks() != nil {
		taskCount, _ = d.PentaTasks().Count()
	}
	vulnCount := 0
	if d != nil && d.Vulns() != nil {
		vulnCount, _ = d.Vulns().Count()
	}
	server.OK(w, map[string]any{
		"enabled":        pentaEnabled(),
		"statement":      pentaStatement,
		"builtinCount":   len(b),
		"customCount":    len(c),
		"taskCount":      taskCount,
		"vulnCount":      vulnCount,
		"tags":           tags,
		"supportedSteps": []string{penta.StepHTTP, penta.StepTCP, penta.StepWeakPass, penta.StepExternal},
	})
}

// hPentaTasks GET 列表 / POST 创建
func hPentaTasks(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	if !pentaEnabled() {
		server.Fail(w, http.StatusForbidden, 40300, "渗透工作台已停用(settings.json 的 penta.enabled=false)")
		return
	}

	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		page := q.Get("page")
		size := q.Get("size")
		pn, sn := 1, 20
		fmt.Sscanf(page, "%d", &pn)
		fmt.Sscanf(size, "%d", &sn)
		list, total, err := d.PentaTasks().SearchPage(db.PentaTaskQuery{
			Status: q.Get("status"),
			Risk:   q.Get("risk"),
			Target: q.Get("target"),
		}, pn, sn)
		if err != nil {
			server.FailInternal(w, err.Error())
			return
		}
		server.OK(w, map[string]any{"list": list, "total": total})

	case http.MethodPost:
		var in struct {
			Name       string `json:"name"`
			Target     string `json:"target"`
			Port       int    `json:"port"`
			Protocol   string `json:"protocol"`
			CVE        string `json:"cve"`
			Title      string `json:"title"`
			TemplateID string `json:"templateId"`
			Note       string `json:"note"`
			Severity   string `json:"severity"` // 初始风险等级(手动创建时自选)
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			server.FailBadRequest(w, "请求格式错误: "+err.Error())
			return
		}
		if strings.TrimSpace(in.Target) == "" {
			server.FailBadRequest(w, "目标不能为空")
			return
		}
		if in.Title == "" {
			in.Title = in.Name
		}
		if in.Title == "" {
			in.Title = "渗透验证 " + in.Target
		}
		if in.TemplateID != "" && findPentaTemplate(in.TemplateID) == nil {
			server.FailBadRequest(w, "EXP 模板不存在: "+in.TemplateID)
			return
		}
		t := &db.PentaTask{Task: penta.Task{
			Name:       in.Name,
			Target:     in.Target,
			Port:       in.Port,
			Protocol:   in.Protocol,
			CVE:        in.CVE,
			Title:      in.Title,
			TemplateID: in.TemplateID,
			RiskLevel:  in.Severity,
			Note:       in.Note,
			Source:     "manual",
			Operator:   currentUser(),
		}}
		if err := d.PentaTasks().Create(t); err != nil {
			server.FailInternal(w, "创建失败: "+err.Error())
			return
		}
		logPentaAudit(d, r, "penta.task.create", t.ID,
			fmt.Sprintf("target=%s:%d cve=%s tpl=%s", t.Target, t.Port, orEmpty(t.CVE), orEmpty(t.TemplateID)))
		server.OK(w, map[string]any{"ok": true, "task": t})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func orEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// hPentaImport POST /api/v2/penta/tasks/import 从漏洞管理一键导入。
//
// body: {vulnIds: ["<vulnId>", ...]}
// 幂等: 已存在同 VulnID 的任务跳过(重复导入不产生重复任务)。
func hPentaImport(w http.ResponseWriter, r *http.Request) {
	if !pentaEnabled() {
		server.Fail(w, http.StatusForbidden, 40300, "渗透工作台已停用(settings.json 的 penta.enabled=false)")
		return
	}
	d := v2NeedDB(w)
	if d == nil || d.Vulns() == nil {
		server.FailInternal(w, "漏洞库不可用")
		return
	}
	var in struct {
		VulnIDs []string `json:"vulnIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.VulnIDs) == 0 {
		server.FailBadRequest(w, "vulnIds 不能为空")
		return
	}
	if len(in.VulnIDs) > 200 {
		server.FailBadRequest(w, "单次导入上限 200 条")
		return
	}
	existing, _ := d.PentaTasks().List()
	imported := map[string]bool{}
	for _, t := range existing {
		if t != nil && t.VulnID != "" {
			imported[t.VulnID] = true
		}
	}

	var created, skipped, missing []*string
	for _, vid := range in.VulnIDs {
		v, err := d.Vulns().Get(vid)
		if err != nil {
			missing = append(missing, &vid)
			continue
		}
		if imported[v.ID] {
			skipped = append(skipped, &vid)
			continue
		}
		t := &db.PentaTask{Task: penta.Task{
			Name:       v.Title,
			Target:     v.AssetIP,
			Port:       v.Port,
			Protocol:   v.Protocol,
			VulnID:     v.ID,
			CVE:        v.CVE,
			Title:      v.Title,
			Source:     "vuln",
			RiskLevel:  v.Severity,
			TemplateID: penta.SuggestTemplate(v.Protocol, v.Port, v.Title),
			Operator:   currentUser(),
		}}
		if err := d.PentaTasks().Create(t); err != nil {
			logLine("渗透任务导入失败(" + vid + "): " + err.Error())
			continue
		}
		imported[v.ID] = true
		created = append(created, &vid)
	}

	logPentaAudit(d, r, "penta.task.import", "",
		fmt.Sprintf("导入 %d 条(跳过已导入 %d, 不存在 %d)", len(created), len(skipped), len(missing)))
	server.OK(w, map[string]any{
		"ok":       true,
		"created":  len(created),
		"skipped":  len(skipped),
		"missing":  len(missing),
		"missingIds": missing,
	})
}

// hPentaTaskManage PUT 保存结果 / DELETE 删除
func hPentaTaskManage(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	id := r.PathValue("id")

	switch r.Method {
	case http.MethodPut:
		t := pentaGuard(w, d, id)
		if t == nil {
			return
		}
		var in struct {
			Exploitability string `json:"exploitability"`
			RiskLevel      string `json:"riskLevel"`
			Summary        string `json:"summary"`
			Note           string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			server.FailBadRequest(w, "请求格式错误: "+err.Error())
			return
		}
		if in.Exploitability != "" && in.Exploitability != penta.Exploitable &&
			in.Exploitability != penta.Partial && in.Exploitability != penta.NotExploitable {
			server.FailBadRequest(w, "exploitability 取值须为 exploitable / partial / not_exploitable")
			return
		}
		if in.RiskLevel != "" && !validRiskLevel(in.RiskLevel) {
			server.FailBadRequest(w, "riskLevel 取值须为 critical / high / medium / low / info")
			return
		}
		if in.Exploitability != "" {
			t.Exploitability = in.Exploitability
		}
		if in.RiskLevel != "" {
			t.RiskLevel = in.RiskLevel
		}
		if in.Summary != "" {
			t.Summary = in.Summary
		}
		if in.Note != "" {
			t.Note = in.Note
		}
		if err := d.PentaTasks().Update(t); err != nil {
			server.FailInternal(w, "保存失败: "+err.Error())
			return
		}
		logPentaAudit(d, r, "penta.task.save", t.ID,
			fmt.Sprintf("target=%s exp=%s risk=%s", t.Target, orEmpty(t.Exploitability), orEmpty(t.RiskLevel)))
		server.OK(w, map[string]any{"ok": true, "task": t})

	case http.MethodDelete:
		t := pentaGuard(w, d, id)
		if t == nil {
			return
		}
		if pentaTaskRunning(t.ID) {
			server.Fail(w, http.StatusConflict, 40900, "任务执行中, 不能删除")
			return
		}
		if ok, err := d.PentaTasks().Delete(t.ID); err != nil || !ok {
			server.FailInternal(w, "删除失败")
			return
		}
		logPentaAudit(d, r, "penta.task.delete", t.ID, "target="+t.Target)
		server.OK(w, map[string]any{"ok": true, "deleted": 1})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// validRiskLevel 风险等级取值校验(与 models.NormalizeSeverity 口径一致)。
func validRiskLevel(s string) bool {
	switch strings.ToLower(s) {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}

// hPentaBatch POST /api/v2/penta/tasks/batch 批量删除 {ids}
func hPentaBatch(w http.ResponseWriter, r *http.Request) {
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
	n := 0
	for _, id := range in.IDs {
		if pentaTaskRunning(id) {
			continue // 执行中的任务跳过, 不阻断其余
		}
		if ok, err := d.PentaTasks().Delete(id); err == nil && ok {
			n++
		}
	}
	logPentaAudit(d, r, "penta.task.batchdelete", "", fmt.Sprintf("批量删除 %d/%d 条", n, len(in.IDs)))
	server.OK(w, map[string]any{"ok": true, "deleted": n})
}

// hPentaExport POST /api/v2/penta/tasks/export 批量导出 {ids}(JSON 下载)
func hPentaExport(w http.ResponseWriter, r *http.Request) {
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
		server.FailBadRequest(w, "单次导出上限 500 条")
		return
	}
	want := map[string]bool{}
	for _, id := range in.IDs {
		want[id] = true
	}
	list, _ := d.PentaTasks().List()
	var out []any
	for _, t := range list {
		if t != nil && want[t.ID] {
			out = append(out, t)
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		server.FailInternal(w, "导出失败: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=penta_tasks_"+time.Now().Format("20060102_150405")+".json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	logPentaAudit(d, r, "penta.task.export", "", fmt.Sprintf("导出 %d 条任务(含证据)", len(out)))
}

// hPentaRun POST /api/v2/penta/tasks/{id}/run 执行验证(SSE 流式回显)。
//
// body: {templateId?, weakpass: {user, passwords[]}, ack: true}
//
// ack 是合规硬门槛: 未勾选"我确认目标已授权"时直接 400 —— 攻击性动作的
// 确认必须逐次发生, 不能一次勾选永久有效。
func hPentaRun(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	t := pentaGuard(w, d, r.PathValue("id"))
	if t == nil {
		return
	}
	var in struct {
		TemplateID string `json:"templateId"`
		WeakPass   struct {
			User      string   `json:"user"`
			Passwords []string `json:"passwords"`
		} `json:"weakpass"`
		Ack bool `json:"ack"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		server.FailBadRequest(w, "请求格式错误: "+err.Error())
		return
	}
	if !in.Ack {
		server.FailBadRequest(w, "请先勾选授权确认(仅可对授权目标实施渗透验证)")
		return
	}
	tplID := in.TemplateID
	if tplID == "" {
		tplID = t.TemplateID
	}
	if tplID == "" {
		server.FailBadRequest(w, "未选择 EXP 模板")
		return
	}
	tpl := findPentaTemplate(tplID)
	if tpl == nil {
		server.FailBadRequest(w, "EXP 模板不存在: "+tplID)
		return
	}

	if pentaTaskRunning(t.ID) {
		server.Fail(w, http.StatusConflict, 40900, "任务已在执行中")
		return
	}
	pentaSetRunning(t.ID, true)

	// 弱口令参数覆盖(界面填的账号口令优先于模板定义)
	runTpl := *tpl
	runTpl.Steps = make([]penta.StepSpec, 0, len(tpl.Steps))
	for _, s := range tpl.Steps {
		if s.Type == penta.StepWeakPass && (in.WeakPass.User != "" || len(in.WeakPass.Passwords) > 0) {
			if in.WeakPass.User != "" {
				s.User = in.WeakPass.User
			}
			if len(in.WeakPass.Passwords) > 0 {
				s.Passwords = in.WeakPass.Passwords
			}
		}
		runTpl.Steps = append(runTpl.Steps, s)
	}

	// SSE 流(与 /api/scan 同一口径: fetch + reader)
	fl, ok := w.(http.Flusher)
	if !ok {
		pentaSetRunning(t.ID, false)
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	var mu sync.Mutex
	emit := func(event string, data any) {
		b, _ := json.Marshal(data)
		mu.Lock()
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		fl.Flush()
		mu.Unlock()
	}

	// 执行开始入渗透审计(独立表, 攻击性动作入口必留痕)
	logPentaAudit(d, r, "penta.task.run", t.ID,
		fmt.Sprintf("target=%s:%d tpl=%s operator=%s", t.Target, t.Port, tplID, currentUser()))
	t.Status = penta.TaskRunning
	t.TemplateID = tplID
	now := time.Now()
	t.StartedAt = now
	_ = d.PentaTasks().Update(t)
	emit("penta.start", map[string]any{"taskId": t.ID, "target": t.Target, "port": t.Port, "template": tplID})

	task := t.Task // 领域模型副本(引擎只认 penta.Task)
	outcome := instancePenta().Run(r.Context(), &task, &runTpl, emit)

	// 每步审计(penta.command): 命令/步骤、目标、结果 —— 全程留痕不可删除
	for _, step := range outcome.Steps {
		errPart := ""
		if step.Err != "" {
			errPart = " err=" + step.Err
		}
		logPentaAudit(d, r, "penta.command", t.ID, fmt.Sprintf(
			"target=%s:%d tpl=%s step=%s type=%s hit=%v%s",
			t.Target, t.Port, tplID, step.Name, step.Type, step.Hit, errPart))
	}

	task.Status = penta.TaskDone
	if !outcome.OK {
		task.Status = penta.TaskFailed
	}
	task.Exploitability = outcome.Exploitability
	task.Summary = outcome.Summary
	task.Evidence = outcome.Steps
	task.RunLog = outcome.Log
	task.FinishedAt = time.Now()
	task.Operator = currentUser()
	merged := &db.PentaTask{Task: task}
	if err := d.PentaTasks().Update(merged); err != nil {
		logLine("渗透任务结果落库失败: " + err.Error())
	}
	pentaSetRunning(t.ID, false)

	logPentaAudit(d, r, "penta.task.finish", t.ID,
		fmt.Sprintf("target=%s status=%s exp=%s %s", t.Target, task.Status, orEmpty(task.Exploitability), outcome.Summary))
	emit("penta.done", map[string]any{
		"taskId": t.ID, "ok": outcome.OK,
		"exploitability": outcome.Exploitability, "summary": outcome.Summary,
		"steps": outcome.Steps,
	})
}

// hPentaResult GET /api/v2/penta/tasks/{id}/result
func hPentaResult(w http.ResponseWriter, r *http.Request) {
	d := v2GetDB()
	if d == nil || d.PentaTasks() == nil {
		server.FailInternal(w, "渗透任务表不可用")
		return
	}
	t, err := d.PentaTasks().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "渗透任务不存在")
		return
	}
	server.OK(w, map[string]any{"task": t, "running": pentaTaskRunning(t.ID)})
}

// hPentaTemplates GET /api/v2/penta/templates?tag=&q=
func hPentaTemplates(w http.ResponseWriter, r *http.Request) {
	builtin, custom, tags := pentaTemplates()
	tag, q := r.URL.Query().Get("tag"), strings.ToLower(r.URL.Query().Get("q"))
	keep := func(t penta.Template) bool {
		if tag != "" && !hasTag(t.Tags, tag) {
			return false
		}
		if q != "" && !strings.Contains(strings.ToLower(t.Name), q) &&
			!strings.Contains(strings.ToLower(t.ID), q) &&
			!strings.Contains(strings.ToLower(t.CVE), q) {
			return false
		}
		return true
	}
	bf, cf := make([]penta.Template, 0, len(builtin)), make([]penta.Template, 0, len(custom))
	for _, t := range builtin {
		if keep(t) {
			bf = append(bf, t)
		}
	}
	for _, t := range custom {
		if keep(t) {
			cf = append(cf, t)
		}
	}
	server.OK(w, map[string]any{"builtin": bf, "custom": cf, "tags": tags})
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// hPentaTplImport POST /api/v2/penta/templates/import 导入自定义 EXP 模板。
//
// body: {content: "<YAML 或 JSON 文本>"} —— 与漏洞规则导入同口径(粘贴即导入)。
// 安全: ID 白名单(小写字母/数字/中划线)即文件名, 杜绝路径穿越; 与内置同 ID 拒绝。
func hPentaTplImport(w http.ResponseWriter, r *http.Request) {
	if !pentaEnabled() {
		server.Fail(w, http.StatusForbidden, 40300, "渗透工作台已停用(settings.json 的 penta.enabled=false)")
		return
	}
	var in struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Content) == "" {
		server.FailBadRequest(w, "content 不能为空(YAML 或 JSON 文本)")
		return
	}
	tpl, path, err := penta.ImportCustom(pentaTemplateDir(), []byte(in.Content))
	if err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	if d := v2GetDB(); d != nil {
		logPentaAudit(d, r, "penta.template.import", tpl.ID,
			fmt.Sprintf("name=%s file=%s steps=%d", tpl.Name, filepath.Base(path), len(tpl.Steps)))
	}
	server.OK(w, map[string]any{"ok": true, "template": tpl, "path": path})
}

// hPentaFeedback POST /api/v2/penta/tasks/{id}/feedback 一键回传漏洞管理。
//
// 联动闭环的最后一步: 把验证结论写回漏洞条目(验证状态 + 风险定级修正),
// 漏洞管理页与报告中心随之可见。只写 penta 专属字段与(用户显式修正时的)
// Severity —— 不改 Status(修复与否是处置动作, 不是验证结论)。
func hPentaFeedback(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil || d.Vulns() == nil {
		server.FailInternal(w, "漏洞库不可用")
		return
	}
	t := pentaGuard(w, d, r.PathValue("id"))
	if t == nil {
		return
	}
	if t.VulnID == "" {
		server.FailBadRequest(w, "该任务未关联漏洞(手动创建的任务无回传目标), 请到漏洞管理查看")
		return
	}
	if t.Exploitability == "" {
		server.FailBadRequest(w, "请先完成验证(无可回传的结论)")
		return
	}
	v, err := d.Vulns().Get(t.VulnID)
	if err != nil {
		server.FailNotFound(w, "关联漏洞不存在(可能已被删除或清空)")
		return
	}
	now := time.Now()
	v.PentaTaskID = t.ID
	v.PentaResult = t.Exploitability
	v.PentaVerifiedAt = &now
	// 风险定级修正: 用户显式修正过才覆盖原等级(空 = 保持扫描时的定级)
	if t.RiskLevel != "" {
		v.Severity = t.RiskLevel
		v.PentaRiskLevel = t.RiskLevel
	}
	if err := d.Vulns().Update(v); err != nil {
		server.FailInternal(w, "回传失败: "+err.Error())
		return
	}
	t.FeedbackAt = now
	if err := d.PentaTasks().Update(t); err != nil {
		logLine("渗透回传标记落库失败: " + err.Error())
	}
	logPentaAudit(d, r, "penta.feedback", t.ID,
		fmt.Sprintf("vuln=%s target=%s exp=%s risk=%s", t.VulnID, t.Target, t.Exploitability, orEmpty(t.RiskLevel)))
	server.OK(w, map[string]any{"ok": true, "vulnId": t.VulnID, "vuln": v})
}

// hPentaAuditList GET /api/v2/penta/audit 渗透审计列表(独立表, 只读)。
//
// 筛选口径与通用审计 /api/v2/audit 完全一致(user/action/keyword/from/to/
// page/size), 前端两个页面的交互无差异。清空走独立 DELETE 路由
// (hPentaAuditClear, adminOnly + 清空动作留痕), 本接口不做写操作。
func hPentaAuditList(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil || d.PentaAudits() == nil {
		server.FailInternal(w, "渗透审计表不可用")
		return
	}
	q := r.URL.Query()
	f := db.AuditFilter{
		User:    q.Get("user"),
		Action:  q.Get("action"),
		Keyword: q.Get("keyword"),
	}
	if s := q.Get("from"); s != "" {
		if t, err := time.Parse("2006-01-02", s); err == nil {
			f.From = t
		}
	}
	if s := q.Get("to"); s != "" {
		if t, err := time.Parse("2006-01-02", s); err == nil {
			f.To = t.Add(24*time.Hour - time.Second) // 含当天(与通用审计同口径)
		}
	}
	page, size := parsePage(q)
	f.Limit, f.Offset = size, (page-1)*size
	list, total, err := d.PentaAudits().Query(f)
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	server.OK(w, map[string]any{"list": list, "total": total, "page": page, "size": size})
}

// hPentaAuditClear DELETE /api/v2/penta/audit 管理员清空全部渗透审计。
//
// 场景: 分发给他人 / 数据交接时需要干净状态(早期版本"不可删除", 唯一办法
// 是停服务手工删文件)。防"无痕擦除": 清空后写一条 penta.audit.clear 痕迹
// (谁/何时/清了几条) —— 记录可以清, 但"被清过"永远查得到, 与通用审计
// "清空日志留 audit.clear 痕迹"同口径。权限 adminOnly(路由层, 与本文件
// 其它 penta 路由一致), 前端另要求输入"清空"二次确认。
func hPentaAuditClear(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil || d.PentaAudits() == nil {
		server.FailInternal(w, "渗透审计表不可用")
		return
	}
	n, err := d.PentaAudits().Clear()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	// 痕迹在 Clear 之后写: 它本身也落在 penta_audit 表里, 清空不会带走它
	logPentaAudit(d, r, "penta.audit.clear", "", fmt.Sprintf("清空了 %d 条渗透审计记录", n))
	server.OK(w, map[string]any{"deleted": n})
}

// ===== 执行中任务跟踪(防并发重复执行) =====

func pentaTaskRunning(id string) bool {
	pentaRunningMu.Lock()
	defer pentaRunningMu.Unlock()
	return pentaRunning[id]
}

func pentaSetRunning(id string, running bool) {
	pentaRunningMu.Lock()
	defer pentaRunningMu.Unlock()
	if running {
		pentaRunning[id] = true
	} else {
		delete(pentaRunning, id)
	}
}
