package db

import (
	"os"
	"strings"
	"testing"
	"time"
)

// openTestDB 打开临时目录测试库。
func openTestDB(t *testing.T) *Database {
	t.Helper()
	d, err := Open(Config{Type: TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestOpenDefaults 默认配置与表初始化
func TestOpenDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Type != TypeSQLite {
		t.Fatalf("default type=%s", cfg.Type)
	}
	if !strings.HasSuffix(cfg.Dir, "data") {
		t.Fatalf("default dir=%s", cfg.Dir)
	}
	dir := t.TempDir()
	d, err := Open(Config{Type: TypeSQLite, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if d.Type() != TypeSQLite || d.Dir() != dir {
		t.Fatalf("db type=%s dir=%s", d.Type(), d.Dir())
	}
	stats := d.Stats()
	// 19 张表: 任务 4.1 的 11 张 + 任务 6.3 的 probe_tasks
	// + 任务 7.2 的报告存档表 reports 与报告模板表 report_templates
	// + 任务 10a 的监控采样表 monitor_samples
	// + 节点监控采集底座的 collect_samples / collect_events
	// + 报告中心二期的原始结构化报告表 raw_reports
	// + 阶段 3 的 AI RAG 知识库文档表 ai_docs
	// + 阶段 5 的渗透任务表 penta_tasks
	// + 弱口令字典表 weak_password_dict
	// + 渗透审计独立表 penta_audit(与通用审计分离, 只增不删)
	if len(stats) != 22 {
		t.Fatalf("stats 表数=%d, 期望 22: %v", len(stats), stats)
	}
	// 任务 7.2 新增的两张表必须可访问(DAO 非 nil 才能被 v2 接口使用)
	if d.Reports() == nil || d.ReportTemplates() == nil {
		t.Fatal("报告相关 DAO 不应为 nil")
	}
	// 任务 10a 监控采样表同样必须可访问
	if d.MonitorSamples() == nil {
		t.Fatal("监控采样 DAO 不应为 nil")
	}
	// 报告中心二期原始报告表必须可访问
	if d.RawReports() == nil {
		t.Fatal("原始报告 DAO 不应为 nil")
	}
	// 阶段 3 AI 文档库表必须可访问
	if d.AIDocs() == nil {
		t.Fatal("AI 文档库 DAO 不应为 nil")
	}
	// 弱口令字典表必须可访问
	if d.WeakPassDict() == nil {
		t.Fatal("弱口令字典 DAO 不应为 nil")
	}
	// 渗透审计独立表必须可访问
	if d.PentaAudits() == nil {
		t.Fatal("渗透审计 DAO 不应为 nil")
	}
	for name, n := range stats {
		if n != 0 {
			t.Fatalf("表 %s 初始应空, 实际 %d", name, n)
		}
	}
}

// TestPentaAuditAppendQuery 渗透审计独立表: 追加 + 倒序查询 + 过滤(离线契约)。
func TestPentaAuditAppendQuery(t *testing.T) {
	d := openTestDB(t)
	if err := d.PentaAudits().Append(PentaAuditLog{Action: "penta.task.run", Target: "10.0.0.1", Detail: "step1"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := d.PentaAudits().Append(PentaAuditLog{Action: "penta.command", Target: "10.0.0.1", Detail: "step2"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	// 倒序: 最新在前
	list, total, err := d.PentaAudits().Query(AuditFilter{})
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("query total=%d len=%d err=%v", total, len(list), err)
	}
	if list[0].Action != "penta.command" {
		t.Fatalf("倒序应为最新在前, 实际 %s", list[0].Action)
	}
	// 动作过滤(与通用审计同口径)
	list2, total2, _ := d.PentaAudits().Query(AuditFilter{Action: "penta.task"})
	if total2 != 1 || list2[0].Action != "penta.task.run" {
		t.Fatalf("动作过滤 err: total=%d list=%v", total2, list2)
	}
	// 空动作拒绝(实体校验)
	if err := d.PentaAudits().Append(PentaAuditLog{Action: " "}); err == nil {
		t.Fatal("空动作应被拒绝")
	}
}

// TestPentaAuditMigration 旧版本混存通用审计表的 penta.* 记录, 首次打开新库时
// 迁移到独立表; 幂等(重开不重复迁移); 非 penta 记录不受影响。
func TestPentaAuditMigration(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(Config{Type: TypeSQLite, Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// 模拟旧版本数据: 通用审计表混有 penta.* 与普通记录
	_ = d.Audits().Append(AuditLog{Action: "penta.task.run", Target: "10.0.0.1", Detail: "old run"})
	_ = d.Audits().Append(AuditLog{Action: "penta.command", Target: "10.0.0.1", Detail: "old step"})
	_ = d.Audits().Append(AuditLog{Action: "asset.create", Target: "10.0.0.2", Detail: "normal"})
	_ = d.Close()

	// 重新打开 = 升级后首次启动, 应触发迁移
	d2, err := Open(Config{Type: TypeSQLite, Dir: dir})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// 独立表拿到 2 条 penta 记录(字段与 ID 原样保留)
	pl, ptotal, err := d2.PentaAudits().Query(AuditFilter{})
	if err != nil || ptotal != 2 || len(pl) != 2 {
		t.Fatalf("迁移后独立表 total=%d len=%d err=%v", ptotal, len(pl), err)
	}
	// 通用表只剩 1 条普通记录
	ga, gtotal, _ := d2.Audits().Query(AuditFilter{})
	if gtotal != 1 || ga[0].Action != "asset.create" {
		t.Fatalf("通用表应只剩普通记录: total=%d list=%v", gtotal, ga)
	}
	_ = d2.Close()

	// 幂等: 再次打开不重复迁移(独立表非空即跳过, 记录数不变)
	d3, err := Open(Config{Type: TypeSQLite, Dir: dir})
	if err != nil {
		t.Fatalf("reopen2: %v", err)
	}
	defer d3.Close()
	_, ptotal3, _ := d3.PentaAudits().Query(AuditFilter{})
	if ptotal3 != 2 {
		t.Fatalf("幂等失效: 重开后独立表 total=%d", ptotal3)
	}
}

// TestUnknownType 未知驱动类型报错
func TestUnknownType(t *testing.T) {
	_, err := Open(Config{Type: "oracle", Dir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "未知数据库类型") {
		t.Fatalf("err=%v", err)
	}
}

// TestPostgresSkeleton PostgreSQL 骨架: 配置校验 + 未实现错误 + 配置开关生效
func TestPostgresSkeleton(t *testing.T) {
	// host 为空 -> 配置错误
	_, err := Open(Config{Type: TypePostgres, Dir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "postgres 配置错误") {
		t.Fatalf("empty host err=%v", err)
	}
	// host 有效 -> 未实现错误(明确提示改配置)
	_, err = Open(Config{Type: TypePostgres, Dir: t.TempDir(), Postgres: PGConfig{Host: "127.0.0.1"}})
	if err == nil || !strings.Contains(err.Error(), "未完整实现") {
		t.Fatalf("not impl err=%v", err)
	}
	// DSN 生成
	st, err := newPostgresStore(PGConfig{Host: "db.example.com", User: "u", Pass: "p", DB: "yugsight"})
	if err != nil {
		t.Fatal(err)
	}
	dsn := st.DSN()
	for _, want := range []string{"host=db.example.com", "port=5432", "dbname=yugsight", "user=u"} {
		if !strings.Contains(dsn, want) {
			t.Fatalf("dsn=%s 缺少 %s", dsn, want)
		}
	}
}

// TestAssetCRUD 资产表 CRUD + 标签管理
func TestAssetCRUD(t *testing.T) {
	d := openTestDB(t)
	a := NewAsset("192.168.1.10")
	a.Hostname = "srv-1"
	a.OS = "Windows Server 2022"
	a.Ports = []int{80, 443, 3389}
	a.AddTags("prod", "web")
	if err := d.Assets().Create(a); err != nil {
		t.Fatalf("create: %v", err)
	}
	if id := a.EntityID(); len(id) != 16 {
		t.Fatalf("asset id=%s", id)
	}
	// 重复 Create -> ErrExists
	if err := d.Assets().Create(NewAsset("192.168.1.10")); err == nil {
		t.Fatal("重复 Create 应报 ErrExists")
	}
	// Get
	got, err := d.Assets().Get(a.ID)
	if err != nil || got.Hostname != "srv-1" || len(got.Ports) != 3 {
		t.Fatalf("get: %v %+v", err, got)
	}
	// 标签增删
	upd, err := d.Assets().AddTag(a.ID, "db")
	if err != nil || len(upd.Tags) != 3 {
		t.Fatalf("addtag: %v %v", err, upd.Tags)
	}
	upd, _ = d.Assets().RemoveTag(a.ID, "web")
	if len(upd.Tags) != 2 {
		t.Fatalf("removetag: %v", upd.Tags)
	}
	// 查询
	if list, _ := d.Assets().FindByIP("192.168.1.10"); len(list) != 1 {
		t.Fatalf("findbyip=%d", len(list))
	}
	if list, _ := d.Assets().FindByTag("prod"); len(list) != 1 {
		t.Fatalf("findbytag=%d", len(list))
	}
	// 同 IP upsert 不新增
	created, err := d.Assets().Upsert(NewAsset("192.168.1.10"))
	if err != nil || created {
		t.Fatalf("upsert: created=%v err=%v", created, err)
	}
	if n, _ := d.Assets().Count(); n != 1 {
		t.Fatalf("count=%d", n)
	}
	// Delete
	ok, _ := d.Assets().Delete(a.ID)
	if !ok {
		t.Fatal("delete=false")
	}
	if _, err := d.Assets().Get(a.ID); err == nil {
		t.Fatal("删除后仍 Get 到")
	}
	// 空 IP 校验
	if err := d.Assets().Create(&Asset{}); err == nil {
		t.Fatal("空 IP 应校验失败")
	}
}

// TestVulnQueryPage 漏洞表: 多维筛选 + 分页
func TestVulnQueryPage(t *testing.T) {
	d := openTestDB(t)
	mk := func(ip, cve, title, sev, status string) *Vuln {
		v := NewVuln(ip, title, sev)
		v.CVE = cve
		v.Status = status
		v.Source = "builtin"
		return v
	}
	for _, v := range []*Vuln{
		mk("10.0.0.1", "CVE-2021-44228", "Log4j2 远程代码执行", "critical", "new"),
		mk("10.0.0.1", "CVE-2021-45047", "Spring4Shell", "high", "duplicate"),
		mk("10.0.0.2", "CVE-2023-44487", "HTTP/2 Rapid Reset", "medium", "new"),
		mk("10.0.0.2", "", "默认密码", "high", "fixed"),
	} {
		if err := d.Vulns().Create(v); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	// 全量
	if list, err := d.Vulns().Search(VulnQuery{}); err != nil || len(list) != 4 {
		t.Fatalf("all=%d err=%v", len(list), err)
	}
	// 按等级
	if list, _ := d.Vulns().Search(VulnQuery{Severity: "critical"}); len(list) != 1 || list[0].CVE != "CVE-2021-44228" {
		t.Fatalf("sev=%v", list)
	}
	// 按 CVE
	if list, _ := d.Vulns().Search(VulnQuery{CVE: "CVE-2021-45047"}); len(list) != 1 {
		t.Fatalf("cve=%d", len(list))
	}
	// 按 IP + 状态
	if list, _ := d.Vulns().Search(VulnQuery{AssetIP: "10.0.0.2", Status: "fixed"}); len(list) != 1 {
		t.Fatalf("ip+status=%d", len(list))
	}
	// 按标题关键字
	if list, _ := d.Vulns().Search(VulnQuery{Title: "rapid"}); len(list) != 1 {
		t.Fatalf("title=%d", len(list))
	}
	// 分页
	page1, total, err := d.Vulns().SearchPage(VulnQuery{}, 1, 3)
	if err != nil || len(page1) != 3 || total != 4 {
		t.Fatalf("page1=%d total=%d err=%v", len(page1), total, err)
	}
	page2, total, _ := d.Vulns().SearchPage(VulnQuery{}, 2, 3)
	if total != 4 || len(page2) != 1 {
		t.Fatalf("page2=%d total=%d", len(page2), total)
	}
	// 越界页
	empty, total, _ := d.Vulns().SearchPage(VulnQuery{}, 99, 10)
	if total != 4 || len(empty) != 0 {
		t.Fatalf("oob=%d total=%d", len(empty), total)
	}
	// MarkFixed
	fixed, err := d.Vulns().MarkFixed(page2[0].ID)
	if err != nil || fixed.Status != "fixed" || fixed.FixedAt == nil {
		t.Fatalf("markfixed: %v %+v", err, fixed)
	}
	// 总数保持
	if n, _ := d.Vulns().Count(); n != 4 {
		t.Fatalf("count=%d", n)
	}
}

// TestWhitelist 白名单表: 类型校验 / CIDR / 过期 / 启停
func TestWhitelist(t *testing.T) {
	d := openTestDB(t)
	wl := &WhitelistEntry{Type: WLTypeIP, Match: "192.168.1.99", Reason: "测试机", Enabled: true}
	if err := d.Whitelists().Create(wl); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(wl.ID) < 3 || !strings.HasPrefix(wl.ID, "wl") {
		t.Fatalf("id=%s", wl.ID)
	}
	// 非法类型
	if err := d.Whitelists().Create(&WhitelistEntry{Type: "xxx", Match: "1"}); err == nil {
		t.Fatal("非法类型应失败")
	}
	// 非法 CIDR
	if err := d.Whitelists().Create(&WhitelistEntry{Type: WLTypeCIDR, Match: "10.0.0"}); err == nil {
		t.Fatal("非法 CIDR 应失败")
	}
	// 合法 CIDR
	cidr := &WhitelistEntry{Type: WLTypeCIDR, Match: "10.0.0.0/8", Enabled: true}
	if err := d.Whitelists().Create(cidr); err != nil {
		t.Fatalf("cidr: %v", err)
	}
	// 过期
	exp := &WhitelistEntry{Type: WLTypePort, Match: "8080", ExpiresAt: time.Now().Add(-time.Hour)}
	if err := d.Whitelists().Create(exp); err != nil {
		t.Fatal(err)
	}
	if list, _ := d.Whitelists().EnabledOnly(); len(list) != 2 {
		t.Fatalf("enabled=%d", len(list))
	}
	// 启停
	upd, err := d.Whitelists().SetEnabled(wl.ID, false)
	if err != nil || upd.Enabled {
		t.Fatalf("setenabled: %v %+v", err, upd)
	}
	if list, _ := d.Whitelists().EnabledOnly(); len(list) != 1 {
		t.Fatalf("enabled after off=%d", len(list))
	}
}

// TestScanTask 扫描任务: 创建 / 状态流转 / 查询
func TestScanTask(t *testing.T) {
	d := openTestDB(t)
	st := &ScanTask{Type: "host", Target: "10.0.0.5", CreatedBy: "admin"}
	if err := d.ScanTasks().Create(st); err != nil {
		t.Fatalf("create: %v", err)
	}
	if st.Status != TaskPending || st.ID == "" {
		t.Fatalf("task=%+v", st)
	}
	// 状态流转
	running, err := d.ScanTasks().UpdateStatus(st.ID, TaskRunning, "")
	if err != nil || running.StartedAt == nil {
		t.Fatalf("running: %v %+v", err, running)
	}
	done, err := d.ScanTasks().UpdateStatus(st.ID, TaskSuccess, "发现 3 个漏洞")
	if err != nil || done.FinishedAt == nil || done.Result != "发现 3 个漏洞" {
		t.Fatalf("done: %v %+v", err, done)
	}
	if list, _ := d.ScanTasks().ByStatus(TaskSuccess); len(list) != 1 {
		t.Fatalf("bystatus=%d", len(list))
	}
	// 非法任务
	if err := d.ScanTasks().Create(&ScanTask{Type: "", Target: "x"}); err == nil {
		t.Fatal("空类型应失败")
	}
}

// TestUserSession 用户 / 会话表
func TestUserSession(t *testing.T) {
	d := openTestDB(t)
	u := NewUser("alice", "hash-123")
	u.Role = RoleAdmin
	if err := d.Users().Create(u); err != nil {
		t.Fatalf("user: %v", err)
	}
	if err := d.Users().Create(&User{Username: "a"}); err == nil {
		t.Fatal("短用户名应失败")
	}
	if list, _ := d.Users().EnabledOnly(); len(list) != 1 {
		t.Fatalf("users=%d", len(list))
	}

	sn := &Session{ID: "token-abc", UserID: "alice", ExpiresAt: time.Now().Add(time.Hour)}
	if err := d.Sessions().Create(sn); err != nil {
		t.Fatalf("session: %v", err)
	}
	if list, _ := d.Sessions().Active(); len(list) != 1 {
		t.Fatalf("active=%d", len(list))
	}
	// 吊销
	if err := d.Sessions().Revoke("token-abc"); err != nil {
		t.Fatal(err)
	}
	if list, _ := d.Sessions().Active(); len(list) != 0 {
		t.Fatalf("active after revoke=%d", len(list))
	}
	// 过期清理(已吊销 + 已过期 均清理)
	old := &Session{ID: "token-old", UserID: "alice", ExpiresAt: time.Now().Add(-time.Hour)}
	_ = d.Sessions().Create(old)
	if n := d.Sessions().ExpireNow(); n != 2 {
		t.Fatalf("expire=%d", n)
	}
}

// TestConfigItem 授权配置表: 按键读写
func TestConfigItem(t *testing.T) {
	d := openTestDB(t)
	item, err := d.Configs().SetKey("license.key", "abcd-1234", "授权密钥")
	if err != nil || item.Key != "license.key" {
		t.Fatalf("setkey: %v %+v", err, item)
	}
	// 覆盖
	if _, err := d.Configs().SetKey("license.key", "new-key", "授权密钥"); err != nil {
		t.Fatal(err)
	}
	got, err := d.Configs().GetKey("license.key")
	if err != nil || got.Value != "new-key" {
		t.Fatalf("getkey: %v %+v", err, got)
	}
	if n, _ := d.Configs().Count(); n != 1 {
		t.Fatalf("count=%d", n)
	}
	// 空键
	if err := d.Configs().Create(&ConfigItem{Key: ""}); err == nil {
		t.Fatal("空键应失败")
	}
}

// TestRuleCPEProbe 规则库 / CPE 库 / 探针管理表
func TestRuleCPEProbe(t *testing.T) {
	d := openTestDB(t)
	// 规则
	r := NewRule("YUGSIGHT-0001", RuleTypeBuiltin, "测试规则")
	r.Severity = "HIGH"
	if err := d.Rules().Create(r); err != nil {
		t.Fatalf("rule: %v", err)
	}
	if r.Severity != "high" {
		t.Fatalf("severity 归一化=%s", r.Severity)
	}
	if list, _ := d.Rules().EnabledOnly(); len(list) != 1 {
		t.Fatalf("rules=%d", len(list))
	}
	// CPE
	c := &CPE{ID: "cpe:2.3:a:apache:http_server:2.4.49:*", Part: "a", Vendor: "apache", Product: "http_server", Version: "2.4.49"}
	if err := d.CPEs().Create(c); err != nil {
		t.Fatalf("cpe: %v", err)
	}
	if list, _ := d.CPEs().FindByProduct("HTTP_Server"); len(list) != 1 {
		t.Fatalf("cpe find=%d", len(list))
	}
	// 探针
	pb := &Probe{ID: "node-01", Name: "机房A", Capabilities: "portscan,web"}
	if err := d.Probes().Create(pb); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if pb.Status != ProbeOffline {
		t.Fatalf("probe status=%s", pb.Status)
	}
	if _, err := d.Probes().MarkSeen("node-01"); err != nil {
		t.Fatal(err)
	}
	if list, _ := d.Probes().Online(); len(list) != 1 || list[0].LastSeenAt.IsZero() {
		t.Fatalf("online=%d", len(list))
	}
	if _, err := d.Probes().SetStatus("node-01", ProbeDisabled); err != nil {
		t.Fatal(err)
	}
	if list, _ := d.Probes().Online(); len(list) != 0 {
		t.Fatalf("online after disable=%d", len(list))
	}
}

// TestAuditLog 审计日志: 追加 / 倒序 / 上限裁剪
func TestAuditLog(t *testing.T) {
	d := openTestDB(t)
	for i := 0; i < 5; i++ {
		if err := d.Audits().Append(AuditLog{UserID: "alice", Action: "asset.create", Target: "10.0.0.1"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	recent, err := d.Audits().Recent(3)
	if err != nil || len(recent) != 3 {
		t.Fatalf("recent: %v %d", err, len(recent))
	}
	// 倒序: 最后一条在前
	if recent[0].ID == recent[2].ID {
		t.Fatal("recent 应去重倒序")
	}
	// 上限裁剪: 直接灌满
	for i := 0; i < maxAuditEntries; i++ {
		_ = d.Audits().Append(AuditLog{Action: "test"})
	}
	if n, _ := d.Audits().Count(); n > maxAuditEntries {
		t.Fatalf("audit count=%d 超过上限", n)
	}
	// 空 action 校验
	if err := d.Audits().Append(AuditLog{Action: ""}); err == nil {
		t.Fatal("空 action 应失败")
	}
}

// TestAuditQueryAndPrune 审计: 筛选/分页/按天裁剪(2026-09-20 保存天数功能)
func TestAuditQueryAndPrune(t *testing.T) {
	d := openTestDB(t)
	base := time.Date(2026, 9, 3, 12, 0, 0, 0, time.Local)
	// 3 天 x 不同用户/动作的数据(base 前 2 天 / 前 1 天 / 当天)
	for i := -2; i <= 0; i++ {
		_ = d.Audits().Append(AuditLog{UserID: "alice", Action: "scan.start", Target: "10.0.0.1", Detail: "type=ip", CreatedAt: base.AddDate(0, 0, i)})
		_ = d.Audits().Append(AuditLog{UserID: "bob", Action: "login.success", Target: "", Detail: "IP 192.168.1.2", CreatedAt: base.AddDate(0, 0, i).Add(time.Minute)})
	}

	// 用户过滤
	l, total, err := d.Audits().Query(AuditFilter{User: "alice", Limit: 100})
	if err != nil || total != 3 || len(l) != 3 {
		t.Fatalf("user filter: %v total=%d len=%d", err, total, len(l))
	}
	// 动作包含过滤
	_, total, _ = d.Audits().Query(AuditFilter{Action: "scan"})
	if total != 3 {
		t.Fatalf("action filter: total=%d, 期望 3", total)
	}
	// 关键字(详情, 大小写不敏感)
	_, total, _ = d.Audits().Query(AuditFilter{Keyword: "ip 192.168"})
	if total != 3 {
		t.Fatalf("keyword filter: total=%d, 期望 3", total)
	}
	// 日期范围: 前 1 天 12:00 起 24 小时(边界含两端: 09-02 12:00/12:01 + 09-03 12:00)
	from := base.AddDate(0, 0, -1)
	to := base.AddDate(0, 0, -1).Add(24 * time.Hour)
	_, total, _ = d.Audits().Query(AuditFilter{From: from, To: to})
	if total != 3 {
		t.Fatalf("date filter: total=%d, 期望 3", total)
	}
	// 分页: size=2 共 6 条 -> 第一页 2 条且倒序, 第二页 2 条
	p1, total, _ := d.Audits().Query(AuditFilter{Limit: 2, Offset: 0})
	if total != 6 || len(p1) != 2 {
		t.Fatalf("page1: total=%d len=%d", total, len(p1))
	}
	if !p1[1].CreatedAt.Before(p1[0].CreatedAt) {
		t.Fatal("分页结果应按时间倒序")
	}
	p2, _, _ := d.Audits().Query(AuditFilter{Limit: 2, Offset: 2})
	if len(p2) != 2 || p2[0].ID == p1[0].ID {
		t.Fatal("第二页不应与第一页重叠")
	}
	// 越界 offset 返回空(不 panic 不报错)
	p3, _, _ := d.Audits().Query(AuditFilter{Limit: 2, Offset: 99})
	if len(p3) != 0 {
		t.Fatalf("越界 offset 应为空, got %d", len(p3))
	}

	// 按天裁剪: 截断到 base-1d(第 2 天起点) -> 删掉第 1 天的 2 条
	if n := d.Audits().PruneOlderThan(base.AddDate(0, 0, -1)); n != 2 {
		t.Fatalf("prune: n=%d, 期望 2", n)
	}
	if n, _ := d.Audits().Count(); n != 4 {
		t.Fatalf("prune 后 count=%d, 期望 4", n)
	}
	// 零值 cutoff 不删
	if n := d.Audits().PruneOlderThan(time.Time{}); n != 0 {
		t.Fatalf("零值 cutoff 不应删除, n=%d", n)
	}
}

// TestPersistence 重启后数据持久化 + 坏行降级
func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(Config{Type: TypeSQLite, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Assets().Create(NewAsset("10.1.1.1"))
	_ = d.Vulns().Create(NewVuln("10.1.1.1", "测试漏洞", "high"))
	_ = d.Close()

	// 重新打开, 数据应在
	d2, err := Open(Config{Type: TypeSQLite, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if n, _ := d2.Assets().Count(); n != 1 {
		t.Fatalf("persistence assets=%d", n)
	}
	if n, _ := d2.Vulns().Count(); n != 1 {
		t.Fatalf("persistence vulns=%d", n)
	}
	// 坏行降级: 手工写入坏行后重开
	if err := writeFileAppend(dir+"/vulns.jsonl", "not-a-json\n"); err != nil {
		t.Fatal(err)
	}
	d3, err := Open(Config{Type: TypeSQLite, Dir: dir})
	if err != nil {
		t.Fatalf("reopen with bad line: %v", err)
	}
	defer d3.Close()
	if n, _ := d3.Vulns().Count(); n != 1 {
		t.Fatalf("bad line 后 vulns=%d", n)
	}
}

// writeFileAppend 追加一行到文件(测试用)。
func writeFileAppend(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}
