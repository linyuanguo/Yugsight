package db

import (
	"fmt"
	"path/filepath"
	"reflect"
)

// Database 数据库门面: 按配置打开指定驱动, 完成全部数据表初始化,
// 以类型化 DAO 暴露给业务层(业务代码不感知底层存储)。
type Database struct {
	cfg    Config
	driver string
	dir    string // 数据目录(./data)

	assets     *AssetDAO
	vulns      *VulnDAO
	whitelists *WhitelistDAO
	scanTasks  *ScanTaskDAO
	users      *UserDAO
	sessions   *SessionDAO
	configs    *ConfigDAO
	rules      *RuleDAO
	cpes       *CPEDAO
	audits     *AuditDAO
	probes     *ProbeDAO
	probeTasks *ProbeTaskDAO

	// 任务 7.2 报告引擎: 报告存档 + 自定义模板(两表)
	reports         *ReportDAO
	reportTemplates *ReportTemplateDAO

	// 任务 10a SNMP 监控: 周期采样历史
	monitorSamples *MonitorDAO

	// 节点监控采集底座(阶段 1): 采集轮次时序 + 异常事件
	collectSamples *CollectSampleDAO
	collectEvents  *CollectEventDAO

	// 报告中心二期: 原始结构化报告(业务模块执行后的原始结果 + 多报告合并)
	rawReports *RawReportDAO

	// 阶段 3: AI RAG 知识库文档(非结构化文档的分片向量索引)
	aiDocs *AIDocDAO

	// 阶段 5: 渗透工作台(已知漏洞的验证渗透任务; 与扫描链路物理隔离)
	pentaTasks *PentaTaskDAO

	// 弱口令字典可视化(内置 349 条常用弱口令 + 页面自定义条目; 首次启动自动初始化)
	weakPassDict *WeakPassDictDAO

	// 渗透审计(独立于通用审计: 渗透命令全程留痕, 只增不删, 无删除路径)
	pentaAudit *PentaAuditDAO
}

// Open 按配置打开数据库并完成表结构初始化。
//
//	Type: "sqlite"(默认) = 内置文件引擎, 数据落 ./data/;
//	      "postgres" = 预留骨架, MVP 阶段返回未实现错误(上层降级)。
func Open(cfg Config) (*Database, error) {
	if cfg.Type == "" {
		cfg.Type = TypeSQLite
	}
	if cfg.Dir == "" {
		cfg.Dir = DefaultDataDir()
	}
	switch cfg.Type {
	case TypeSQLite:
		return openFileDB(cfg)
	case TypePostgres:
		st, err := newPostgresStore(cfg.Postgres)
		if err != nil {
			return nil, fmt.Errorf("postgres 配置错误: %s", err)
		}
		if err := st.Connect(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("postgres 驱动连接后不可达(不应发生)")
	default:
		return nil, fmt.Errorf("未知数据库类型: %s(可选 sqlite / postgres)", cfg.Type)
	}
}

// openFileDB 打开内置文件引擎("sqlite" 驱动的完整实现)。
// 数据表: 一表一 JSONL 文件, 缺失 = 空表降级, 坏行跳过。
func openFileDB(cfg Config) (*Database, error) {
	d := &Database{cfg: cfg, driver: TypeSQLite, dir: cfg.Dir}
	table := func(name string) string { return filepath.Join(cfg.Dir, name+".jsonl") }

	var err error
	if d.assets, err = newAssetTable(table("assets")); err != nil {
		return nil, err
	}
	if d.vulns, err = newVulnTable(table("vulns")); err != nil {
		return nil, err
	}
	if d.whitelists, err = newWhitelistTable(table("whitelist")); err != nil {
		return nil, err
	}
	if d.scanTasks, err = newScanTaskTable(table("scan_tasks")); err != nil {
		return nil, err
	}
	if d.users, err = newUserTable(table("users")); err != nil {
		return nil, err
	}
	if d.sessions, err = newSessionTable(table("sessions")); err != nil {
		return nil, err
	}
	if d.configs, err = newConfigTable(table("configs")); err != nil {
		return nil, err
	}
	if d.rules, err = newRuleTable(table("rules")); err != nil {
		return nil, err
	}
	if d.cpes, err = newCPETable(table("cpe")); err != nil {
		return nil, err
	}
	if d.audits, err = newAuditTable(table("audit_logs")); err != nil {
		return nil, err
	}
	if d.probes, err = newProbeTable(table("probes")); err != nil {
		return nil, err
	}
	if d.probeTasks, err = newProbeTaskTable(table("probe_tasks")); err != nil {
		return nil, err
	}
	if d.reports, err = newReportTable(table("reports")); err != nil {
		return nil, err
	}
	if d.reportTemplates, err = newReportTemplateTable(table("report_templates")); err != nil {
		return nil, err
	}
	if d.monitorSamples, err = newMonitorTable(table("monitor_samples")); err != nil {
		return nil, err
	}
	if d.collectSamples, err = newCollectSampleTable(table("collect_samples")); err != nil {
		return nil, err
	}
	if d.collectEvents, err = newCollectEventTable(table("collect_events")); err != nil {
		return nil, err
	}
	if d.rawReports, err = newRawReportTable(table("raw_reports")); err != nil {
		return nil, err
	}
	if d.aiDocs, err = newAITable(table("ai_docs")); err != nil {
		return nil, err
	}
	if d.pentaTasks, err = newPentaTable(table("penta_tasks")); err != nil {
		return nil, err
	}
	if d.weakPassDict, err = newWeakPassDictTable(table("weak_password_dict")); err != nil {
		return nil, err
	}
	if d.pentaAudit, err = newPentaAuditTable(table("penta_audit")); err != nil {
		return nil, err
	}

	// 渗透审计一次性迁移: 旧版本 penta.* 混存通用审计表, 升级到独立表时搬移(幂等)。
	// best-effort: 失败只记日志 —— 老记录留在通用表(其 isProtected 保护仍然生效,
	// 不会丢), 新写入的渗透审计不受影响, 功能不断。
	if n, merr := d.pentaAudit.MigrateFromGeneralAudit(d.audits); merr != nil {
		logf("渗透审计迁移失败(旧记录保留在通用审计表, 新记录不受影响): " + merr.Error())
	} else if n > 0 {
		logf(fmt.Sprintf("渗透审计表迁移完成: 从通用审计表移入 penta.* 记录 %d 条", n))
	}

	logf(fmt.Sprintf("数据库就绪: type=%s dir=%s 表=22(assets/vulns/whitelist/scan_tasks/users/sessions/configs/rules/cpe/audit_logs/probes/probe_tasks/reports/report_templates/monitor_samples/collect_samples/collect_events/raw_reports/ai_docs/penta_tasks/weak_password_dict/penta_audit)",
		d.driver, d.dir))
	return d, nil
}

// Type 驱动类型(sqlite / postgres)。
func (d *Database) Type() string { return d.driver }

// Dir 数据目录。
func (d *Database) Dir() string { return d.dir }

// Config 生效配置。
func (d *Database) Config() Config { return d.cfg }

// Close 关闭数据库(文件引擎数据已随写落盘, 此处仅释放引用)。
func (d *Database) Close() error {
	logf(fmt.Sprintf("数据库已关闭: type=%s dir=%s", d.driver, d.dir))
	d.assets, d.vulns, d.whitelists = nil, nil, nil
	d.scanTasks, d.users, d.sessions = nil, nil, nil
	d.configs, d.rules, d.cpes = nil, nil, nil
	d.audits, d.probes, d.probeTasks = nil, nil, nil
	d.reports, d.reportTemplates = nil, nil
	d.monitorSamples = nil
	d.collectSamples, d.collectEvents = nil, nil
	d.rawReports = nil
	d.aiDocs = nil
	d.pentaTasks = nil
	d.weakPassDict = nil
	d.pentaAudit = nil
	return nil
}

// Stats 各表记录数(诊断/状态展示)。
//
// 守卫说明(踩过的坑): Close() 会把各 DAO 置 nil, 此后若以 nil 调 Count 会直接
// 触发 nil 解引用崩溃(接口方法对 nil 接收者不是安全空操作)。
//
// 注意 **不能** 用 `dao == nil` 判断: 把 *AssetDAO(nil) 传给
// interface{ Count() ... } 形参时, 装箱后的接口是非 nil 的(动态类型存在、
// 值为 nil), 判空会漏过去 → 仍然崩。必须用反射判 typed-nil。
func (d *Database) Stats() map[string]int {
	if d == nil {
		return map[string]int{}
	}
	stats := map[string]int{}
	add := func(name string, dao interface{ Count() (int, error) }) {
		if isNilAny(dao) {
			stats[name] = 0
			return
		}
		n, _ := dao.Count()
		stats[name] = n
	}
	add("assets", d.assets)
	add("vulns", d.vulns)
	add("whitelist", d.whitelists)
	add("scan_tasks", d.scanTasks)
	add("users", d.users)
	add("sessions", d.sessions)
	add("configs", d.configs)
	add("rules", d.rules)
	add("cpe", d.cpes)
	add("audit_logs", d.audits)
	add("probes", d.probes)
	add("probe_tasks", d.probeTasks)
	add("reports", d.reports)
	add("report_templates", d.reportTemplates)
	add("monitor_samples", d.monitorSamples)
	add("collect_samples", d.collectSamples)
	add("collect_events", d.collectEvents)
	add("raw_reports", d.rawReports)
	add("ai_docs", d.aiDocs)
	add("penta_tasks", d.pentaTasks)
	add("weak_password_dict", d.weakPassDict)
	add("penta_audit", d.pentaAudit)
	return stats
}

// isNilAny 判断装箱后的接口是否为 typed-nil(动态类型存在但值为 nil 的指针)。
//
// 场景: 把 (*AssetDAO)(nil) 赋给 interface{ Count() (int, error) } 形参后,
// `dao == nil` 为 false, 直接调用会解引用崩溃。reflect 是标准库中唯一能识别
// 该状态的手段(项目零第三方依赖, 不接受为此引入工具库)。
func isNilAny(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan:
		return rv.IsNil()
	}
	return false
}

// ===== 表访问器(业务层唯一入口) =====

// Assets 资产管理 DAO。
func (d *Database) Assets() *AssetDAO { return d.assets }

// Vulns 漏洞管理 DAO。
func (d *Database) Vulns() *VulnDAO { return d.vulns }

// Whitelists 白名单管理 DAO。
func (d *Database) Whitelists() *WhitelistDAO { return d.whitelists }

// ScanTasks 扫描任务 DAO。
func (d *Database) ScanTasks() *ScanTaskDAO { return d.scanTasks }

// Users 用户账号 DAO。
func (d *Database) Users() *UserDAO { return d.users }

// Sessions 用户会话 DAO。
func (d *Database) Sessions() *SessionDAO { return d.sessions }

// Configs 授权配置 DAO。
func (d *Database) Configs() *ConfigDAO { return d.configs }

// Rules 规则库 DAO。
func (d *Database) Rules() *RuleDAO { return d.rules }

// CPEs CPE 库 DAO。
func (d *Database) CPEs() *CPEDAO { return d.cpes }

// Audits 审计日志 DAO。
func (d *Database) Audits() *AuditDAO { return d.audits }

// Probes 探针管理 DAO。
func (d *Database) Probes() *ProbeDAO { return d.probes }

// ProbeTasks 探针任务 DAO(分布式扫描下发链路明细)。
func (d *Database) ProbeTasks() *ProbeTaskDAO { return d.probeTasks }

// Reports 报告存档 DAO(任务 7.2: 报告存档持久化, 可随时重新下载)。
func (d *Database) Reports() *ReportDAO { return d.reports }

// ReportTemplates 报告模板 DAO(任务 7.2: 自定义页眉页脚模板)。
func (d *Database) ReportTemplates() *ReportTemplateDAO { return d.reportTemplates }

// MonitorSamples 监控采样历史 DAO(任务 10a: SNMP 周期采样)。
func (d *Database) MonitorSamples() *MonitorDAO { return d.monitorSamples }

// CollectSamples 节点采集轮次时序 DAO(节点监控采集底座: 指标时序存储)。
func (d *Database) CollectSamples() *CollectSampleDAO { return d.collectSamples }

// CollectEvents 节点采集异常事件 DAO(节点监控采集底座: 异常事件输出)。
func (d *Database) CollectEvents() *CollectEventDAO { return d.collectEvents }

// RawReports 原始结构化报告 DAO(报告中心二期: 业务模块原始结果 + 多报告合并)。
func (d *Database) RawReports() *RawReportDAO { return d.rawReports }

// AIDocs AI RAG 知识库文档 DAO(阶段 3: 非结构化文档分片向量索引)。
func (d *Database) AIDocs() *AIDocDAO { return d.aiDocs }

// PentaTasks 渗透任务 DAO(阶段 5: 渗透工作台)。
func (d *Database) PentaTasks() *PentaTaskDAO { return d.pentaTasks }

// WeakPassDict 弱口令字典 DAO(内置 349 条 + 自定义; 弱口令检测引擎经此加载全量字典)。
func (d *Database) WeakPassDict() *WeakPassDictDAO { return d.weakPassDict }

// PentaAudits 渗透审计 DAO(独立表, 只增不删; 与通用审计 AuditDAO 物理隔离)。
func (d *Database) PentaAudits() *PentaAuditDAO { return d.pentaAudit }
