// api_v2.go Yugsight 第二阶段核心 REST API(任务 4.1, /api/v2/ 前缀)。
//
// - 统一响应格式: server.Resp{code,message,data} + 错误码(旧 /api/* 接口保持原格式不受影响)
// - 数据访问: 全部经 db 包统一 DAO 接口, 不直接操作存储/SQL, 业务不感知底层数据库
// - 认证: 复用既有 requireAuth 登录校验(基础用户会话管理: 登录/登出/会话过期, 见 auth.go)
// - 降级: 数据库初始化失败时 v2 接口返回 503, 服务不崩溃; 健康检查接口免登录
// - 审计: 写操作自动落审计日志(db 审计日志表)
//
// 跨平台备注: 中心管理端支持 Windows / Linux 编译运行; Linux 环境下不建议本地
// 执行抓包 / SYN 扫描任务, 此类任务经扫描任务表的 probeNode 字段下发远端探针执行。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/models"
	"yugsight/internal/server"
)

// ===== 数据库懒加载 =====

var (
	v2dbOnce sync.Once
	v2db     *db.Database
	v2dbErr  error
)

// v2DBProvider 经 registerV2Routes 注入的 db provider(默认 nil = 用真实懒加载库)。
//
// 存在的意义: 生产代码中存在不经 HTTP 层直接落库的路径(如探针上线/任务结果回调),
// 它们调用 v2DB() 而非 v2GetDB(); 测试注入库时必须让这类路径也走注入库,
// 否则测试数据会落到真实 ./data 目录, 既污染现场又让断言失败。
//
// 注意: 本字段绝不可是 v2DB 自身 —— 否则 v2DB -> provider -> v2DB 无限自递归,
// 1GB 栈耗尽后 fatal error: stack overflow(原生级崩溃, recover 拦不住、
// 日志也写不进去, 现场表现为"进程静默消失")。selfProvider 即为此设的兜底。
var (
	v2DBProviderMu sync.RWMutex
	v2DBProvider   func() *db.Database
)

// isSelfProvider 判断 p 是否就是 v2DB 自身(按函数入口地址比对)。
//
// 为什么需要: 生产路径 registerV2Routes(srv, v2DB) 与历史赋值 v2GetDB = v2DB
// 都会让 provider 指向 v2DB; 只判断非 nil 会直接踩进无限递归。
func isSelfProvider(p func() *db.Database) bool {
	if p == nil {
		return false
	}
	self := reflect.ValueOf(v2DB).Pointer()
	return reflect.ValueOf(p).Pointer() == self
}

// v2DB 懒加载数据库(读程序目录 config.json 的 database 段; 失败降级不崩溃)。
func v2DB() *db.Database {
	v2DBProviderMu.RLock()
	injected := v2DBProvider
	v2DBProviderMu.RUnlock()
	// 注入的 provider 若非自身才走注入; 是自身则视为"未注入"继续走下方懒加载,
	// 避免自递归栈溢出(见 v2DBProvider 注释)。
	if injected != nil && !isSelfProvider(injected) {
		return injected()
	}
	v2dbOnce.Do(func() {
		db.SetLogger(logLine)
		// settings.json 的 database 节优先, 回退 config.json 的 database 段
		db.SetConfigReader(func() ([]byte, bool) { return section(secDatabase, "") })
		cfg, err := db.LoadConfig()
		if err != nil {
			logLine("数据库配置读取失败, 使用默认: " + err.Error())
			cfg = db.DefaultConfig()
		}
		v2db, v2dbErr = db.Open(cfg)
		if v2dbErr != nil {
			logLine("数据库初始化失败, /api/v2 降级运行: " + v2dbErr.Error())
		} else {
			// 弱口令字典首次启动初始化(幂等 best-effort; 失败不影响 v2 其它能力):
			// 数据库懒加载成功的这一刻就是"首次启动"的准确时机。
			ensureWeakPassDict(v2db)
		}
	})
	return v2db
}

// buildV2Handler 构建 /api/v2/ 组处理器(独立中间件链: 全局 recover -> CORS -> 请求日志 -> 路由),
// main.go 以 mux.Handle("/api/v2/", buildV2Handler()) 挂载, 与既有接口共存互不影响。
func buildV2Handler() http.Handler {
	srv := server.New(
		server.WithLogger(logLine),
		server.WithMiddleware(server.CORS("*"), server.Logging(logLine)),
	)
	registerV2Routes(srv, v2DB)
	return srv.Handler()
}

// v2GetDB 当前生效的数据库访问入口(默认懒加载 v2DB; 测试可经 registerV2Routes 注入)。
var v2GetDB = v2DB

// registerV2Routes 注册 v2 全部路由(测试可注入自定义 db provider)。
//
// getDB 为 nil 或就是 v2DB 自身时, 保持默认懒加载(生产路径即此情形);
// 传自定义 provider 时才记录到 v2DBProvider, 使不经过 HTTP 层的落库路径
// (探针回调等)也使用同一个库。
//
// 关键: 绝不把 v2DB 自身记成 provider —— 那会让 v2DB() 无限自递归。
func registerV2Routes(srv *server.Server, getDB func() *db.Database) {
	if getDB != nil && !isSelfProvider(getDB) {
		v2GetDB = getDB
		v2DBProviderMu.Lock()
		v2DBProvider = getDB
		v2DBProviderMu.Unlock()
	}
	// 健康检查(免登录: 供探活/负载检查)
	srv.Get("/api/v2/health", func(w http.ResponseWriter, r *http.Request) {
		server.OK(w, map[string]any{"name": appName, "version": appVersion, "time": time.Now().Format(time.RFC3339)})
	})

	// 拓扑链路真实数据(2026-09-29 阶段 B; 只读聚合, 详见 topology_links_api.go)
	registerTopologyLinksRoutes(srv)
	registerTopoViewRoutes(srv)

	// 写操作统一挂 RBAC 中间件(免登录模式下两者均直通, 规则 6):
	//   adminOrOperator = admin + operator(操作员) —— 业务写操作(资产/漏洞/白名单/
	//     任务/探针/引擎/报告)都是"操作员按设计拥有"的能力;
	//   adminOnly = 仅 admin —— 授权与模型页专属(用户账号/会话吊销/审计配置与清理),
	//     账号体系是提权红线, 操作员同样不能碰。
	// 读路由(各 GET)保持 requireAuth, auditor 只读角色正常使用。
	// ===== 资产管理: 增删改查 + 标签管理 =====
	srv.Get("/api/v2/assets", requireAuth(hV2AssetList))
	srv.Post("/api/v2/assets", requireAuth(adminOrOperator(hV2AssetUpsert)))
	srv.Get("/api/v2/assets/{id}", requireAuth(hV2AssetGet))
	srv.Put("/api/v2/assets/{id}", requireAuth(adminOrOperator(hV2AssetUpdate)))
	srv.Delete("/api/v2/assets/{id}", requireAuth(adminOrOperator(hV2AssetDelete)))
	srv.Delete("/api/v2/assets/dead", requireAuth(adminOrOperator(hV2AssetCleanDead)))
	// 批量删除选中(前端"删除选中"按钮): 精确路径优先于 {id} 模式, 无冲突
	srv.Post("/api/v2/assets/batch-delete", requireAuth(adminOrOperator(hV2AssetBatchDelete)))
	srv.Post("/api/v2/assets/{id}/tags", requireAuth(adminOrOperator(hV2AssetTagsAdd)))
	srv.Delete("/api/v2/assets/{id}/tags", requireAuth(adminOrOperator(hV2AssetTagsRemove)))
	// 代理 ARP 幽灵资产: 预览(只读) + 清理(破坏性, 需 operator 以上; 前端先预览确认再删, 见 arp_ghost.go)
	srv.Get("/api/v2/assets/arp-ghosts", requireAuth(hV2ArpGhostPreview))
	srv.Post("/api/v2/assets/arp-ghosts/cleanup", requireAuth(adminOrOperator(hV2ArpGhostCleanup)))

	// ===== 漏洞查询: 分页 / 多维筛选 / 详情 / 删除 / 清空 =====
	srv.Get("/api/v2/vulns", requireAuth(hV2VulnList))
	// 精确路径优先于 {id} 模式, 无冲突(与 raw/batch-delete 同口径)
	srv.Get("/api/v2/vulns/options", requireAuth(hV2VulnOptions))
	srv.Post("/api/v2/vulns", requireAuth(adminOrOperator(hV2VulnUpsert)))
	srv.Get("/api/v2/vulns/{id}", requireAuth(hV2VulnGet))
	srv.Put("/api/v2/vulns/{id}", requireAuth(adminOrOperator(hV2VulnUpdate)))
	srv.Delete("/api/v2/vulns/{id}", requireAuth(adminOrOperator(hV2VulnDelete)))
	// 集合级 DELETE = 清空全部漏洞记录(前端"清空全部漏洞"按钮; 破坏性动作,
	// 前端二次确认 + 后端记审计, 只清漏洞表不动资产表)
	srv.Delete("/api/v2/vulns", requireAuth(adminOrOperator(hV2VulnClearAll)))

	// ===== 白名单管理: 添加 / 删除 / 列表 / 启停 =====
	//
	// Deprecated: 这是一套与扫描管线脱节的"双轨另一轨"。扫描管线实际生效的是
	// scanctl 本地白名单(scanctl_api.go 的 /api/vuln/whitelist*, 存 exe 同目录
	// scanctl/whitelist.jsonl), 命中即过滤 finding; 本组接口只写 db 白名单表,
	// 不参与过滤。前端扫描控制页已全部走 /api/vuln/*, 无调用方。
	// 保留理由: 已有数据与契约测试依赖它(删除会破坏外部集成); 待 db 与 scanctl
	// 白名单合并为一轨后再整体下线。
	srv.Get("/api/v2/whitelist", requireAuth(hV2WhitelistList))
	srv.Post("/api/v2/whitelist", requireAuth(adminOrOperator(hV2WhitelistAdd)))
	srv.Put("/api/v2/whitelist/{id}", requireAuth(adminOrOperator(hV2WhitelistUpdate)))
	srv.Delete("/api/v2/whitelist/{id}", requireAuth(adminOrOperator(hV2WhitelistDelete)))

	// ===== 扫描任务: 创建 / 状态查询 / 列表 =====
	srv.Post("/api/v2/scans", requireAuth(adminOrOperator(hV2ScanCreate)))
	srv.Get("/api/v2/scans", requireAuth(hV2ScanList))
	srv.Get("/api/v2/scans/{id}", requireAuth(hV2ScanGet))
	srv.Post("/api/v2/scans/{id}/status", requireAuth(adminOrOperator(hV2ScanStatus)))
	srv.Delete("/api/v2/scans/{id}", requireAuth(adminOrOperator(hV2ScanDelete)))
	// 集合级 DELETE = 清空全部扫描任务历史记录(首页"清空历史记录"按钮;
	// 破坏性动作: 前端二次确认 + 后端记审计。只清任务表, 不动资产/漏洞)
	srv.Delete("/api/v2/scans", requireAuth(adminOrOperator(hV2ScanClearAll)))
	// 批量删除选中(前端"扫描历史"列表勾选; 与 assets/raw 批量删除同口径)
	srv.Post("/api/v2/scans/batch-delete", requireAuth(adminOrOperator(hV2ScanBatchDelete)))
	// 取消运行中的扫描(2026-09-27: 扫描历史页"取消"按钮; 本地/探针/调度三路径统一入口,
	// 实现见 scan_history.go hV2ScanCancel)
	srv.Post("/api/v2/scans/{id}/cancel", requireAuth(adminOrOperator(hV2ScanCancel)))

	// ===== 用户会话管理(基于既有登录会话; 属授权与模型页能力, 保持 adminOnly) =====
	srv.Get("/api/v2/sessions", requireAuth(hV2SessionsList))
	srv.Delete("/api/v2/sessions/{id}", requireAuth(adminOnly(hV2SessionRevoke)))

	// ===== 审计日志(配置与清理是"授权与模型"能力, 保持 adminOnly) =====
	srv.Get("/api/v2/audit", requireAuth(hV2AuditList))
	srv.Get("/api/v2/audit/config", requireAuth(hV2AuditConfigGet))
	srv.Post("/api/v2/audit/config", requireAuth(adminOnly(hV2AuditConfigSet)))
	// 清理: 不带参数 = 清空全部; ?days=N 只清 N 天前。清理动作本身会留一条审计记录。
	srv.Delete("/api/v2/audit", requireAuth(adminOnly(hV2AuditClear)))
	srv.Delete("/api/v2/audit/{id}", requireAuth(adminOnly(hV2AuditDeleteOne)))

	// 恢复出厂(授权与模型页"服务管理"区; adminOnly 破坏性红线, 清空全部运行期数据)。
	// cleanEnv=true 时额外清 bin/agents/logs, 用于打 dist 分发包前。
	srv.Post("/api/v2/factory-reset", requireAuth(adminOnly(hV2FactoryReset)))

	// ===== 品牌自定义(授权与模型页"品牌自定义"面板; 2026-09-28) =====
	// 读 requireAuth(登录角色可见), 写 adminOnly(与同页用户/审计配置同口径)。
	RegisterBrandRoutes(srv)

	// ===== 数据库状态 =====
	srv.Get("/api/v2/db/status", requireAuth(hV2DBStatus))

	// ===== 探针管理(任务 6.3 分布式扫描框架) =====
	// 与其它 v2 路由同一装配点: 独立 registerProbeRoutes 便于单测单独挂载,
	// probe.json 未启用时接口返回"未启用"状态, 不影响单机流程。
	registerProbeRoutes(srv)

	// ===== 任务调度(任务 7.1 队列调度 + 策略模板 + 限速) =====
	// scheduler.json 未启用时接口仍可访问(便于前端引导用户开启), 但 /api/scan
	// 不会被接管 —— 保持即时执行, 零行为变化(项目规则 5)。
	registerSchedulerRoutes(srv)

	// ===== 报告引擎(任务 7.2 报告生成 + 资产拓扑 + 历史对比) =====
	// report.json 未启用时除 /status 外统一返回"未启用"提示, 不影响经典页
	// /api/report 即时报告链路(项目规则 1/5)。
	registerReportRoutes(srv)

	// ===== 安全运维大屏(任务 7.3 大屏数据聚合) =====
	// 只读聚合视图: 不接管扫描/不下发任务/不写库, 因此无需启用开关,
	// 未登录仍受 requireAuth 保护。二期预留的 Prometheus 文本端点
	// (/api/v2/screen/metrics)由 screen.json 的 metrics 开关控制, 默认关闭。
	registerBigScreenRoutes(srv)

	// ===== 阶段 4: 中心端运行状态(首页仪表盘 Tab1"中心端运行状态"面板) =====
	// 只读聚合视图(与大屏同一决策: 不改执行链路, 无需启用开关); 逐项降级,
	// 任一子项失败不影响整体。
	registerCenterStatusRoutes(srv)

	// ===== SNMP 网络监控(任务 10a 周期采集 + 监控 API) =====
	// enabled 默认 true 但空目标 = 零网络活动; 写操作(目标增删/配置)挂 adminOnly。
	registerMonitorRoutes(srv)

	// ===== 节点监控采集底座(阶段 1: WinRM/SSH/主机SNMP/ICMP/NetFlow/NETCONF/RESTCONF) =====
	// 默认全关(规则 5): 未开启时引擎不跑循环、不监听端口、零外连;
	// SNMP 网络设备监控继续走 monitor 包, 本组是节点监控页的扩展采集协议。
	registerNodeRoutes(srv)

	// ===== 扫描作业(命名任务编排: 深度扫描→弱口令→渗透→完成) =====
	// 作业会真实发起扫描流量, 故写操作(创建/取消/删除)挂 adminOrOperator;
	// 报告中心据此"按作业名生成报告 / 按作业名分类原始报告"。
	registerJobRoutes(srv)

	// ===== 弱口令字典可视化(内置 349 + 自定义; 读 requireAuth, 写 adminOnly) =====
	registerWeakPassDictRoutes(srv)

	// ===== 配置热重载与功能开关(二期 15) =====
	// 改 settings.json 后不必重启: 文件监听自动生效, 这里提供手动触发入口。
	srv.Post("/api/v2/config/reload", requireAuth(adminOrOperator(hConfigReload)))
	// 功能开关: 页面上的开关读写(默认全开, 保存即生效)。
	registerFeatureSwitchRoutes(srv)
}

// ===== 通用辅助 =====

// v2NeedDB 取数据库; 不可用时返回统一 503 响应。
func v2NeedDB(w http.ResponseWriter) *db.Database {
	d := v2GetDB()
	if d == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "数据库不可用(初始化失败, 详见日志)")
		return nil
	}
	return d
}

// decodeJSON 解析请求体; 失败统一 400。
// 兼容"被二次 JSON.stringify 的 body"(历史前端 bug: 已序列化的字符串被再序列化一次,
// 服务端收到 JSON 字符串字面量 "{\"a\":1}"): 首解码失败且原始字节以引号开头时,
// 先解出内层字符串再解一次。让新旧前端(含未强刷的缓存旧页)都能正常保存。
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	raw, rerr := io.ReadAll(r.Body)
	if rerr != nil {
		server.FailBadRequest(w, "请求体读取失败: "+rerr.Error())
		return false
	}
	uerr := json.Unmarshal(raw, v)
	if uerr == nil {
		return true
	}
	// 兜底: body 是 JSON 字符串字面量(外层被引号包一层), 解开内层 JSON 再解一次
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		var inner string
		if json.Unmarshal(raw, &inner) == nil && inner != "" &&
			json.Unmarshal([]byte(inner), v) == nil {
			return true
		}
	}
	server.FailBadRequest(w, "请求格式错误: "+uerr.Error())
	return false
}

// parsePage 解析分页参数(page 从 1 起, size 默认 20 上限 200)。
func parsePage(q url.Values) (int, int) {
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(q.Get("size"))
	if size < 1 {
		size = 20
	}
	if size > 200 {
		size = 200
	}
	return page, size
}

// paginate 内存分页。
func paginate[T any](all []T, page, size int) []T {
	start := (page - 1) * size
	if start >= len(all) {
		return []T{}
	}
	end := start + size
	if end > len(all) {
		end = len(all)
	}
	return all[start:end]
}

// clientIP 取客户端 IP(支持 X-Forwarded-For)。
func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// currentUser 当前登录用户名(单用户制, 取账户库唯一用户; 免登录模式为 local)。
func currentUser() string {
	if authDisabled {
		return "local"
	}
	authMu.Lock()
	defer authMu.Unlock()
	if authStore != nil {
		for u := range authStore.Users {
			return u
		}
	}
	return ""
}

// logAudit 写审计日志(失败不影响主流程)。
//
// r 可以为 nil: 非 HTTP 触发的事件(系统启动、调度器派发的扫描)没有请求上下文,
// 此时来源 IP 留空, 用户仍按 currentUser() 口径记录。
func logAudit(d *db.Database, r *http.Request, action, target, detail string) {
	if d == nil {
		return
	}
	ip := ""
	if r != nil {
		ip = clientIP(r)
	}
	rec := db.AuditLog{
		UserID:   currentUser(),
		Action:   action,
		Target:   target,
		Detail:   detail,
		ClientIP: ip,
	}
	if err := d.Audits().Append(rec); err != nil {
		logLine("审计日志写入失败: " + err.Error())
		return
	}
	// 同时写入运行日志(二期 15): 库里的审计记录要进页面才看得到, 而运维排障时
	// 手上第一份材料是 yugsight.log —— 两条路都留, 谁都不依赖另一个可用。
	logLine(fmt.Sprintf("[审计] %s %s %s %s", rec.UserID, action, target, detail))
}

// ===== 资产管理 =====

type assetIn struct {
	IP        string   `json:"ip"`
	MAC       string   `json:"mac"`
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	Service   string   `json:"service"`
	Version   string   `json:"version"`
	Banner    string   `json:"banner"`
	ProbeNode string   `json:"probeNode"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
}

// hV2AssetList GET /api/v2/assets 支持 ?ip= &tag= &page= &size=
func hV2AssetList(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	q := r.URL.Query()
	page, size := parsePage(q)
	list, err := d.Assets().List()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	if ip := q.Get("ip"); ip != "" {
		list, _ = d.Assets().FindByIP(ip)
	}
	if tag := q.Get("tag"); tag != "" {
		list, _ = d.Assets().FindByTag(tag)
	}
	// 只看存活筛选(前端"只看存活"开关, 默认开): alive=1 只留 Alive=true,
	// alive=0 只留 Alive=false。在 ip/tag 基础上对当前 list 追加过滤(基于
	// 已有结果而非重查全表, 保证多条件 AND)。
	if av := q.Get("alive"); av != "" {
		onlyAlive := av != "0"
		filtered := make([]*db.Asset, 0, len(list))
		for _, a := range list {
			if a.Alive == onlyAlive {
				filtered = append(filtered, a)
			}
		}
		list = filtered
	}
	// 主机口径筛选: host=1 只留 IP 字段是合法 IP 的条目。资产表混有 SCA 工件
	// (Trivy 镜像/文件扫描按工件标识入账, 非 IP), 仪表盘"资产总数(主机维度)"
	// 用这个口径, 与资产页"共 N 台主机"对齐; 列表页默认不带, 工件仍可见(带标签)。
	if q.Get("host") == "1" {
		filtered := make([]*db.Asset, 0, len(list))
		for _, a := range list {
			if net.ParseIP(a.IP) != nil {
				filtered = append(filtered, a)
			}
		}
		list = filtered
	}
	server.OK(w, map[string]any{
		"list":  paginate(list, page, size),
		"total": len(list), "page": page, "size": size,
	})
}

// hV2AssetUpsert POST /api/v2/assets 按 IP 幂等写入(存在则更新)
func hV2AssetUpsert(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var in assetIn
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.IP == "" {
		server.FailBadRequest(w, "资产 IP 不能为空")
		return
	}
	a := db.NewAsset(in.IP)
	a.MAC, a.Hostname, a.OS = in.MAC, in.Hostname, in.OS
	a.Service, a.Version, a.Banner = in.Service, in.Version, in.Banner
	a.ProbeNode, a.Ports = in.ProbeNode, in.Ports
	a.AddTags(in.Tags...)
	created, err := d.Assets().Upsert(a)
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	logAudit(d, r, "asset.upsert", a.IP, fmt.Sprintf("created=%v", created))
	server.OK(w, map[string]any{"asset": a, "created": created})
}

// hV2AssetGet GET /api/v2/assets/{id}
func hV2AssetGet(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	a, err := d.Assets().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "资产不存在")
		return
	}
	server.OK(w, a)
}

// hV2AssetUpdate PUT /api/v2/assets/{id} 整条更新(IP 不可变, 保持原发现时间)
func hV2AssetUpdate(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	a, err := d.Assets().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "资产不存在")
		return
	}
	var in assetIn
	if !decodeJSON(w, r, &in) {
		return
	}
	foundAt := a.FoundAt
	a.MAC, a.Hostname, a.OS = in.MAC, in.Hostname, in.OS
	a.Service, a.Version, a.Banner = in.Service, in.Version, in.Banner
	a.ProbeNode, a.Ports = in.ProbeNode, in.Ports
	if in.Tags != nil {
		a.Tags = in.Tags
	}
	a.FoundAt = foundAt
	if err := d.Assets().Update(a); err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	logAudit(d, r, "asset.update", a.IP, "")
	server.OK(w, a)
}

// hV2AssetDelete DELETE /api/v2/assets/{id}
func hV2AssetDelete(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	a, err := d.Assets().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "资产不存在")
		return
	}
	if ok, err := d.Assets().Delete(a.ID); err != nil || !ok {
		server.FailInternal(w, "删除失败")
		return
	}
	logAudit(d, r, "asset.delete", a.IP, "")
	server.OK(w, map[string]any{"deleted": true})
}

// hV2AssetBatchDelete POST /api/v2/assets/batch-delete {ids} 批量删除选中资产。
//
// 与 hV2AssetDelete 同权限(adminOrOperator); 上限 500(与 penta 批量删除同口径)。
// 逐条删、单条失败不阻断其余(与 penta batch 同范式); 审计一条汇总留痕。
func hV2AssetBatchDelete(w http.ResponseWriter, r *http.Request) {
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
	// 按 id 去重(前端选中态理论上无重复, 防御重复提交)
	seen := make(map[string]bool, len(in.IDs))
	n := 0
	for _, id := range in.IDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if ok, err := d.Assets().Delete(id); err == nil && ok {
			n++
		}
	}
	logAudit(d, r, "asset.batch_delete", "", fmt.Sprintf("批量删除 %d/%d 条", n, len(seen)))
	server.OK(w, map[string]any{"deleted": n})
}

// hV2AssetCleanDead DELETE /api/v2/assets/dead 批量删除所有未存活(Alive=false)资产。
//
// 语义: 清理"从未存活过"的探测噪声。存活过的资产 Alive 永不翻案
// (upsertProbeAsset 只 true 覆盖), 故 Alive=false 恰好全是没响应过的 IP,
// 清理不会误删"曾上线后来下线"的主机(它们 Alive=true)。
func hV2AssetCleanDead(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	n, err := d.Assets().DeleteDead()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	logAudit(d, r, "asset.clean_dead", "", fmt.Sprintf("deleted=%d", n))
	server.OK(w, map[string]any{"deleted": n})
}

// hV2AssetTagsAdd POST /api/v2/assets/{id}/tags {tags: [...]}
func hV2AssetTagsAdd(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var req struct {
		Tags []string `json:"tags"`
	}
	if !decodeJSON(w, r, &req) || len(req.Tags) == 0 {
		server.FailBadRequest(w, "tags 不能为空")
		return
	}
	a, err := d.Assets().AddTag(r.PathValue("id"), req.Tags...)
	if err != nil {
		server.FailNotFound(w, "资产不存在")
		return
	}
	logAudit(d, r, "asset.tags.add", a.IP, strings.Join(req.Tags, ","))
	server.OK(w, a)
}

// hV2AssetTagsRemove DELETE /api/v2/assets/{id}/tags {tags: [...]}
func hV2AssetTagsRemove(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var req struct {
		Tags []string `json:"tags"`
	}
	if !decodeJSON(w, r, &req) || len(req.Tags) == 0 {
		server.FailBadRequest(w, "tags 不能为空")
		return
	}
	a, err := d.Assets().RemoveTag(r.PathValue("id"), req.Tags...)
	if err != nil {
		server.FailNotFound(w, "资产不存在")
		return
	}
	logAudit(d, r, "asset.tags.remove", a.IP, strings.Join(req.Tags, ","))
	server.OK(w, a)
}

// ===== 漏洞查询 =====

// hV2VulnList GET /api/v2/vulns 分页 + 多维筛选
// ?severity=&cve=&ip=&title=&source=&status=&page=&size=
func hV2VulnList(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	q := r.URL.Query()
	page, size := parsePage(q)
	// 空参数 = 不过滤(注意: 归一化函数对空值有默认值, 须先判空再归一化)
	vq := db.VulnQuery{}
	if s := strings.TrimSpace(q.Get("severity")); s != "" {
		vq.Severity = models.NormalizeSeverity(s)
	}
	if c := strings.TrimSpace(q.Get("cve")); c != "" {
		vq.CVE = models.NormalizeCVE(c)
	}
	if ip := strings.TrimSpace(q.Get("ip")); ip != "" {
		vq.AssetIP = models.NormIP(ip)
	}
	if s := strings.TrimSpace(q.Get("title")); s != "" {
		vq.Title = s
	}
	if s := strings.TrimSpace(q.Get("source")); s != "" {
		vq.Source = s
	}
	if s := strings.TrimSpace(q.Get("status")); s != "" {
		vq.Status = s
	}
	list, total, err := d.Vulns().SearchPage(vq, page, size)
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	server.OK(w, map[string]any{
		"list":  list,
		"total": total, "page": page, "size": size,
	})
}

// hV2VulnOptions GET /api/v2/vulns/options —— 漏洞列表筛选选项。
// 2026-10-02 用户口径: 筛选选项基于当前数据里实际存在的值 —— 等级只返回漏洞
// 库中存在的等级; 状态按用户两态口径(开放=非 fixed)只返回有数据的态。
// 列表是分页接口, 选项须从全量库聚合(不能只看当前页)。
func hV2VulnOptions(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	sevSet := map[string]bool{}
	openCount, fixedCount := 0, 0
	if dao := d.Vulns(); dao != nil {
		if list, err := dao.Search(db.VulnQuery{}); err == nil {
			for _, v := range list {
				if v == nil {
					continue
				}
				sevSet[models.NormalizeSeverity(v.Severity)] = true
				if models.IsFixedStatus(v.Status) {
					fixedCount++
				} else {
					openCount++
				}
			}
		}
	}
	severities := make([]string, 0)
	for _, s := range []string{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
		if sevSet[s] {
			severities = append(severities, s)
		}
	}
	statuses := make([]map[string]any, 0)
	if openCount > 0 {
		statuses = append(statuses, map[string]any{"id": models.VulnStatusOpen, "count": openCount})
	}
	if fixedCount > 0 {
		statuses = append(statuses, map[string]any{"id": models.VulnStatusFixed, "count": fixedCount})
	}
	server.OK(w, map[string]any{"severities": severities, "statuses": statuses})
}

// hV2VulnUpsert POST /api/v2/vulns 漏洞结果写入(扫描结果回传, 按稳定 ID 幂等)
func hV2VulnUpsert(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var in struct {
		models.Vuln
		ScanTaskID string `json:"scanTaskId"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	v := &db.Vuln{Vuln: in.Vuln, ScanTaskID: in.ScanTaskID}
	if err := v.Validate(); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	created, err := d.Vulns().Upsert(v)
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	logAudit(d, r, "vuln.upsert", v.AssetIP, v.Title)
	server.OK(w, map[string]any{"vuln": v, "created": created})
}

// hV2VulnGet GET /api/v2/vulns/{id}
func hV2VulnGet(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	v, err := d.Vulns().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "漏洞不存在")
		return
	}
	server.OK(w, v)
}

// hV2VulnUpdate PUT /api/v2/vulns/{id} 更新状态/误报标记等(漏洞键字段不可变)
func hV2VulnUpdate(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	v, err := d.Vulns().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "漏洞不存在")
		return
	}
	var in struct {
		Status        string `json:"status"`
		FalsePositive bool   `json:"falsePositive"`
		FPNote        string `json:"fpNote"`
		Confidence    *int   `json:"confidence"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Status != "" {
		// 只接受两态口径内的四个取值(历史 new/duplicate 允许原样回写),
		// 其余一律 400 —— 脏状态值会绕过 db 层"开放=非 fixed"的分界判断。
		switch in.Status {
		case models.VulnStatusNew, models.VulnStatusDuplicate,
			models.VulnStatusOpen, models.VulnStatusFixed:
		default:
			server.FailBadRequest(w, "非法状态: "+in.Status)
			return
		}
		v.Status = in.Status
		// 手动流转必须同步 FixedAt: 大屏"修复趋势"与详情"修复时间"都按
		// FixedAt 统计(见 db.VulnDAO.FixedSince), 只改状态不改时间会让
		// 手动修复的漏洞在趋势图里凭空消失。
		switch in.Status {
		case models.VulnStatusFixed:
			now := time.Now()
			v.FixedAt = &now
		default:
			v.FixedAt = nil
		}
	}
	v.FalsePositive = in.FalsePositive
	if in.FPNote != "" {
		v.FPNote = in.FPNote
	}
	if in.Confidence != nil {
		v.Confidence = *in.Confidence
	}
	if err := d.Vulns().Update(v); err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	logAudit(d, r, "vuln.update", v.AssetIP, v.Title)
	server.OK(w, v)
}

// hV2VulnDelete DELETE /api/v2/vulns/{id}
func hV2VulnDelete(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	v, err := d.Vulns().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "漏洞不存在")
		return
	}
	if ok, err := d.Vulns().Delete(v.ID); err != nil || !ok {
		server.FailInternal(w, "删除失败")
		return
	}
	logAudit(d, r, "vuln.delete", v.AssetIP, v.Title)
	server.OK(w, map[string]any{"deleted": true})
}

// hV2VulnClearAll DELETE /api/v2/vulns 清空全部漏洞记录。
//
// 破坏性操作(前端二次确认后才调): 记审计 vuln.clear 留痕并返回删除条数。
// 只清漏洞表, 资产表保留 —— 资产是"发现过的资产"台账, 清掉不可逆且与本次意图无关。
func hV2VulnClearAll(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	n, err := d.Vulns().DeleteAll()
	if err != nil {
		server.FailInternal(w, "清空失败: "+err.Error())
		return
	}
	logAudit(d, r, "vuln.clear", "", "清空全部漏洞 "+strconv.Itoa(n)+" 条")
	server.OK(w, map[string]any{"deleted": n})
}

// ===== 白名单管理 =====
//
// Deprecated: 整节为双轨遗留(详见 registerV2Routes 里 /api/v2/whitelist* 的注释)。
// 扫描管线生效的是 scanctl 白名单(/api/vuln/whitelist*), 本组接口只读写 db 表。
// 行为保持不变: 既有数据与契约测试依赖它, 下线需等两轨合并。

// hV2WhitelistList GET /api/v2/whitelist
func hV2WhitelistList(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	list, err := d.Whitelists().List()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	server.OK(w, map[string]any{"list": list, "total": len(list)})
}

// hV2WhitelistAdd POST /api/v2/whitelist
func hV2WhitelistAdd(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var in struct {
		Type      string    `json:"type"`
		Match     string    `json:"match"`
		Reason    string    `json:"reason"`
		Enabled   *bool     `json:"enabled"` // 缺省 = 启用
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	e := &db.WhitelistEntry{
		Type: in.Type, Match: in.Match, Reason: in.Reason,
		Enabled: true, ExpiresAt: in.ExpiresAt,
	}
	if in.Enabled != nil {
		e.Enabled = *in.Enabled
	}
	if err := d.Whitelists().Create(e); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	logAudit(d, r, "whitelist.add", e.Match, in.Type)
	server.OK(w, e)
}

// hV2WhitelistUpdate PUT /api/v2/whitelist/{id} 启停
func hV2WhitelistUpdate(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	e, err := d.Whitelists().SetEnabled(r.PathValue("id"), in.Enabled)
	if err != nil {
		server.FailNotFound(w, "白名单条目不存在")
		return
	}
	logAudit(d, r, "whitelist.update", e.Match, fmt.Sprintf("enabled=%v", in.Enabled))
	server.OK(w, e)
}

// hV2WhitelistDelete DELETE /api/v2/whitelist/{id}
func hV2WhitelistDelete(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	e, err := d.Whitelists().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "白名单条目不存在")
		return
	}
	if ok, err := d.Whitelists().Delete(e.ID); err != nil || !ok {
		server.FailInternal(w, "删除失败")
		return
	}
	logAudit(d, r, "whitelist.delete", e.Match, e.Type)
	server.OK(w, map[string]any{"deleted": true})
}

// ===== 扫描任务 =====

// hV2ScanCreate POST /api/v2/scans 创建任务(基础创建: 记录落库, 执行由扫描管线/远端探针接管)
func hV2ScanCreate(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var in struct {
		Type      string          `json:"type"` // ip|port|web|host
		Target    string          `json:"target"`
		Params    json.RawMessage `json:"params"`
		ProbeNode string          `json:"probeNode"` // 远端探针 ID(空 = 本地)
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	t := &db.ScanTask{
		Type: in.Type, Target: in.Target, Params: in.Params,
		ProbeNode: in.ProbeNode, CreatedBy: currentUser(),
	}
	if err := d.ScanTasks().Create(t); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	logAudit(d, r, "scan.create", t.Target, t.Type)
	server.OK(w, t)
}

// scanListItem 扫描历史列表项 = 任务记录 + 探针实时进度(2026-09-27: 用户口径
// "扫描历史里能看到扫描进度")。探针任务的进度在 probe_tasks 表(随探针进度消息
// 更新), 本地扫描的进度在 SSE 流里(不落表, 本字段为空属正常)。
type scanListItem struct {
	*db.ScanTask
	ProbeProgress string `json:"probeProgress,omitempty"`
}

// hV2ScanList GET /api/v2/scans 列表 ?status=&page=&size=
func hV2ScanList(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	q := r.URL.Query()
	page, size := parsePage(q)
	list, err := d.ScanTasks().List()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	if s := q.Get("status"); s != "" {
		list, _ = d.ScanTasks().ByStatus(s)
	}
	// 文件引擎 List 是插入序(最旧在前) —— 扫描历史页按"最近的在前"展示,
	// 统一倒序(createdAt 缺失的排在最前, 稳定排序)
	sort.SliceStable(list, func(i, j int) bool { return list[j].CreatedAt.Before(list[i].CreatedAt) })
	// 进度只对"运行中的探针任务"实时取(进度只在运行中变化, 且运行中的任务很少,
	// 避免每次列表都逐条 join 探针任务表)。
	pageItems := paginate(list, page, size)
	items := make([]scanListItem, 0, len(pageItems))
	for _, t := range pageItems {
		item := scanListItem{ScanTask: t}
		if t.Status == db.TaskRunning && t.ProbeNode != "" && d.ProbeTasks() != nil {
			if pt, perr := d.ProbeTasks().Get(t.ID); perr == nil && pt != nil {
				item.ProbeProgress = pt.Progress
			}
		}
		items = append(items, item)
	}
	// 2026-10-02 用户口径: 筛选选项基于当前数据里实际存在的 —— 回带扫描任务
	// 全量里真实存在的状态(无数据的状态不进选项, 后期有了再出现)。CountByStatus
	// 是单遍计数(不拷贝实体), 全量口径不受 status 过滤影响。
	statuses := make([]map[string]any, 0)
	if counts, err := d.ScanTasks().CountByStatus(); err == nil {
		for _, st := range []string{db.TaskRunning, db.TaskSuccess, db.TaskFailed, db.TaskCancelled, db.TaskPending} {
			if counts[st] > 0 {
				statuses = append(statuses, map[string]any{"id": st, "count": counts[st]})
			}
		}
	}
	server.OK(w, map[string]any{
		"list":     items,
		"total":    len(list), "page": page, "size": size,
		"statuses": statuses,
	})
}

// hV2ScanGet GET /api/v2/scans/{id} 状态查询
func hV2ScanGet(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	t, err := d.ScanTasks().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "任务不存在")
		return
	}
	server.OK(w, t)
}

// hV2ScanStatus POST /api/v2/scans/{id}/status {status, result}
func hV2ScanStatus(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	var in struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if !decodeJSON(w, r, &in) || in.Status == "" {
		server.FailBadRequest(w, "status 不能为空")
		return
	}
	t, err := d.ScanTasks().UpdateStatus(r.PathValue("id"), in.Status, in.Result)
	if err != nil {
		server.FailNotFound(w, "任务不存在")
		return
	}
	logAudit(d, r, "scan.status", t.ID, in.Status)
	server.OK(w, t)
}

// hV2ScanDelete DELETE /api/v2/scans/{id}
func hV2ScanDelete(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	t, err := d.ScanTasks().Get(r.PathValue("id"))
	if err != nil {
		server.FailNotFound(w, "任务不存在")
		return
	}
	if ok, err := d.ScanTasks().Delete(t.ID); err != nil || !ok {
		server.FailInternal(w, "删除失败")
		return
	}
	logAudit(d, r, "scan.delete", t.ID, t.Type)
	server.OK(w, map[string]any{"deleted": true})
}

// hV2ScanClearAll DELETE /api/v2/scans 清空全部扫描任务历史记录。
//
// 首页仪表盘把"当前任务(调度器)"与"累计历史(v2 任务表)"分开显示后, 用户自然会问
// "累计这些能不能清掉" —— 历史任务记录一旦堆积就只剩统计价值, 留着反而让人误以为
// 有一堆任务卡着。清空只影响任务表, 资产/漏洞/探针任务明细都不动。
func hV2ScanClearAll(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	n, err := d.ScanTasks().DeleteAll()
	if err != nil {
		server.FailInternal(w, "清空失败: "+err.Error())
		return
	}
	logAudit(d, r, "scan.clear", "", "清空全部扫描任务 "+strconv.Itoa(n)+" 条")
	server.OK(w, map[string]any{"deleted": n})
}

// ===== 用户会话管理 =====

// hV2SessionsList GET /api/v2/sessions 当前生效会话(既有登录会话, token 脱敏)
func hV2SessionsList(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	authMu.Lock()
	list := make([]map[string]any, 0, len(sessions))
	for tok, rec := range sessions {
		list = append(list, map[string]any{
			"token":     maskToken(tok),
			"user":      rec.user, // RBAC: 会话管理界面要能看出"谁的会话"
			"role":      rec.role,
			"expiresAt": rec.exp,
			"valid":     now.Before(rec.exp),
		})
	}
	authMu.Unlock()
	server.OK(w, map[string]any{"list": list, "total": len(list)})
}

// hV2SessionRevoke DELETE /api/v2/sessions/{id} 吊销会话(支持完整 token 或前缀)
func hV2SessionRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		server.FailBadRequest(w, "会话 ID 不能为空")
		return
	}
	authMu.Lock()
	removed := 0
	for tok := range sessions {
		if tok == id || strings.HasPrefix(tok, id) {
			delete(sessions, tok)
			removed++
		}
	}
	authMu.Unlock()
	if removed == 0 {
		server.FailNotFound(w, "会话不存在")
		return
	}
	logAudit(v2GetDB(), r, "session.revoke", maskToken(id), "")
	server.OK(w, map[string]any{"removed": removed})
}

// maskToken token 脱敏(仅保留前 8 位)。
func maskToken(tok string) string {
	if len(tok) <= 8 {
		return tok
	}
	return tok[:8] + "..."
}

// ===== 审计日志 =====

// hV2AuditList GET /api/v2/audit?limit=
// hV2AuditList GET /api/v2/audit 审计日志: 筛选 + 分页
// ?user= 精确用户 / ?action= 动作包含 / ?keyword= 关键字(用户/动作/对象/详情)
// ?from=2006-01-02&to=2006-01-02 日期范围 / ?page=&size=(默认 50)
func hV2AuditList(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
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
			f.To = t.Add(24*time.Hour - time.Second) // 含当天
		}
	}
	page, size := parsePage(q)
	f.Limit, f.Offset = size, (page-1)*size
	list, total, err := d.Audits().Query(f)
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	server.OK(w, map[string]any{"list": list, "total": total, "page": page, "size": size})
}

// ===== 数据库状态 =====

// hV2DBStatus GET /api/v2/db/status 驱动类型 / 数据目录 / 各表记录数
func hV2DBStatus(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	server.OK(w, map[string]any{
		"type":  d.Type(),
		"dir":   d.Dir(),
		"stats": d.Stats(),
	})
}
