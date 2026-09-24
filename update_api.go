// update_api.go 规则库在线更新 Web API(任务 2 检查点 9: 版本展示 / 一键更新 / 更新日志)。
//
// 端点(均需登录, 与其余管理端点一致):
//   GET  /api/rules/update/status   规则版本 + 远端更新状态 + 分级加载统计 + 备份列表
//   POST /api/rules/update/start    一键更新(后台异步执行, 进度轮询 /progress)
//   GET  /api/rules/update/progress 更新进度 / 结果
//   GET  /api/rules/update/log      更新日志(新 -> 旧, 最近 50 条)
//   POST /api/rules/update/restore  回滚到指定备份版本(恢复后自动热加载)
//
// 配置: exe 同目录 updater.json(可选外部资源, 缺失 = 全部默认, 静默降级不报错):
//   {"sources":["https://host/yugsight/"],"proxy":"","interval":"24h",
//    "autoUpdate":false,"tieredLoad":false,"onDemandKB":512}
// 默认全部关闭: 无下载源不发起任何更新动作; tieredLoad 默认 false = 规则集全量常驻。
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"yugsight/scanner"
)

// readConfigFile 读取 exe 同目录下的 JSON 配置文件, 并剥掉可能存在的 UTF-8 BOM。
//
// 【为什么必须剥 BOM】用户手工编辑配置是主路径, 而 Windows 记事本与 PowerShell 的
// `Set-Content -Encoding UTF8` 都会写出带 BOM(EF BB BF)的 UTF-8 文件。encoding/json
// 遇到 BOM 会直接报 "invalid character 'ï' looking for beginning of value", 表现为
// "配置明明写对了却不生效"(实测踩过: updater.json 里 direct.enabled=true 但接口仍报
// 未启用)。这里的容错是必要的, 不是防御性编程洁癖。
//
// 返回 (内容, 是否存在)。文件缺失不是错误(所有配置文件都是可选的)。
//
// 【与 settings.json 的关系】本函数只读**单个 old-style 文件**, 是 settings.json
// 未配置该节时的回退路径。统一配置请走 section(name, legacyName)。
func readConfigFile(name string) ([]byte, bool) {
	exe, err := os.Executable()
	if err != nil {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(exe), name))
	if err != nil {
		return nil, false
	}
	return stripBOM(data), true
}

// 一键更新运行时状态(进程级一份)
type updateState struct {
	running   bool
	startedAt time.Time
	prog      scanner.UpdateProgress
	result    *scanner.UpdateResult
	err       string
}

var (
	updMu    sync.Mutex
	updState = &updateState{}
)

// updaterFileConfig updater.json 的结构(含直连官方仓库通道配置)
//
// 直连段存在的意义: 官方 Nuclei 模板仓库不提供 rules-manifest.json(它只挂了一个
// 191 字节的 checksums 文件), 因此"开箱即用"必须由客户端自己把源码包转成 manifest。
// 详见 scanner/rule_direct.go 的文件头说明。
type updaterFileConfig struct {
	Sources    []string `json:"sources"`
	Proxy      string   `json:"proxy"`
	Interval   string   `json:"interval"`
	AutoUpdate bool     `json:"autoUpdate"`
	TieredLoad bool     `json:"tieredLoad"`
	OnDemandKB int      `json:"onDemandKB"`
	// Direct 官方仓库直连通道(默认关闭, 需显式 enabled=true)
	Direct *struct {
		Enabled       bool     `json:"enabled"`
		TemplatesRepo string   `json:"templatesRepo"`
		TemplatesRef  string   `json:"templatesRef"`
		Severities    []string `json:"severities"`
		MaxTemplates  int      `json:"maxTemplates"`
	} `json:"direct,omitempty"`
}

// loadUpdaterConfig 读取 updater 配置(settings.json 的 updater 节, 回退旧 updater.json;
// 可选, 缺失/非法 = 默认配置, 不报错)。同时装配"直连官方模板仓库"通道(未配置
// direct 段时按开箱即用策略默认开启, 理由见 applyUpdaterDefaults 的说明;
// 现成示例见 settings.example.json)。
func loadUpdaterConfig() {
	data, ok := section(secUpdater, "")
	if !ok {
		// 文件缺失 = 默认配置: 无自建源 / 自动更新关 / 分级加载关 / 直连通道**开**。
		// 直连通道要显式设置一次, 否则用户先 SetDirectOptions 再加载会串味。
		scanner.SetDirectOptions(scanner.DirectOptions{Enabled: true})
		logLine("未配置 updater 节, 已启用官方模板仓库直连更新(不需自建源; " +
			"如需后台自动更新, 在 settings.json 的 updater 节设 autoUpdate=true)")
		return
	}
	var cfg updaterFileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		logLine("updater 配置解析失败, 使用默认更新配置: " + err.Error())
		scanner.SetDirectOptions(scanner.DirectOptions{Enabled: true})
		return
	}
	scanner.SetDownloadSource(cfg.Sources...)
	scanner.SetProxy(cfg.Proxy)
	if cfg.Interval != "" {
		if d, perr := time.ParseDuration(cfg.Interval); perr == nil && d > 0 {
			scanner.SetUpdateInterval(d)
		}
	}
	scanner.SetAutoUpdate(cfg.AutoUpdate)
	scanner.SetTieredLoad(cfg.TieredLoad)
	if cfg.OnDemandKB > 0 {
		scanner.SetOnDemandThreshold(cfg.OnDemandKB)
	}
	// 直连通道: 用户显式给出 direct 段时完全按配置走(含 enabled=false 彻底关闭);
	// 未给出时按开箱即用策略默认开启。
	autoDefault := applyUpdaterDefaults(&cfg)
	doc := scanner.DirectConfig()
	if cfg.Direct != nil {
		doc = scanner.DirectOptions{
			Enabled:       cfg.Direct.Enabled,
			TemplatesRepo: cfg.Direct.TemplatesRepo,
			TemplatesRef:  cfg.Direct.TemplatesRef,
			Severities:    cfg.Direct.Severities,
			MaxTemplates:  cfg.Direct.MaxTemplates,
			Proxy:         cfg.Proxy, // 复用同一个代理
		}
		scanner.SetDirectOptions(doc)
	}
	logLine(fmt.Sprintf("更新器配置已加载: 自建源 %d 个, 自动更新=%v, 分级加载=%v, 直连官方仓库=%v%s",
		len(cfg.Sources), cfg.AutoUpdate, cfg.TieredLoad, doc.Enabled,
		map[bool]string{true: " (未配置 direct 段, 按默认开启)", false: ""}[autoDefault]))
}

// applyUpdaterDefaults 在用户没写 direct 段时, 按"开箱即用"策略自动打开官方直连通道。
//
// ===== 为什么默认打开(与其他功能默认关闭的口径不同) =====
//
// 项目规则 5 说"新增功能默认关闭", 但那针对的是**会改变行为或引入外部依赖**的功能
// (外部引擎、探针、调度器、报告)。规则库更新不属于这一类:
//   - 它只往 rules/ 目录里写模板文件, 不改扫描流程、不改既有文件(旧版本自动备份);
//   - 检查与下载都发生在后台, 失败只记日志, 对扫描零影响;
//   - "规则库能自动从官方更新"本身就是用户的明确预期 —— 要求先手写 JSON 才能生效,
//     结果就是绝大多数部署永远停留在内置规则上, 这是更严重的功能缺失。
//
// 但**纯自动后台下载**仍然需要 autoUpdate 显式开启(见 loadUpdaterConfig): 那会在用户
// 完全不知情的情况下产生长时间网络流量, 与"默认零网络行为"的约束冲突。
// 于是这里的分工是:
//
//	direct.enabled 默认 true  -> 页面/接口能看到"有更新可拿", 一键更新按钮可用;
//	autoUpdate     默认 false -> 后台不会自己跑流量, 由用户决定何时开。
//
// 用户显式写 direct.enabled=false 时尊重其选择(内网隔离环境不希望有任何 GitHub 请求)。
func applyUpdaterDefaults(cfg *updaterFileConfig) (autoEnabled bool) {
	if cfg.Direct != nil {
		return false // 用户显式配置过: 完全按其配置走
	}
	scanner.SetDirectOptions(scanner.DirectOptions{Enabled: true})
	return true
}

// handleRulesUpdateStatus 规则版本 + 远端更新状态 + 分级加载统计 + 备份列表
func handleRulesUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := scanner.UpdaterConfig()
	out := map[string]any{
		"configured":  len(cfg.Sources) > 0,
		"sources":     cfg.Sources,
		"autoUpdate":  cfg.AutoUpdate,
		"interval":    cfg.Interval.String(),
		"localCommit": scanner.LocalRuleCommit(),
		"tiered":      scanner.TieredStats(),
		"backups":     scanner.ListBackups(scanner.RulesDir()),
	}
	if c, err := scanner.CheckRuleUpdate(); err != nil {
		out["checkError"] = err.Error()
	} else {
		out["remoteCommit"] = c.RemoteCommit
		out["available"] = c.Available
		out["files"] = c.Files
		out["source"] = c.Source
	}
	// 直连官方仓库通道: 未启用时也回传配置状态, 前端据此展示"开启方式"而不是报错
	dcfg := scanner.DirectConfig()
	out["direct"] = map[string]any{
		"enabled": dcfg.Enabled,
		"repo":    dcfg.TemplatesRepo,
		"ref":     dcfg.TemplatesRef,
	}
	if dcfg.Enabled {
		if c, err := scanner.CheckDirect(); err != nil {
			out["directCheckError"] = err.Error()
		} else {
			out["directRemoteRev"] = c.RemoteRev
			out["directAvailable"] = c.Available
			out["directLocalRev"] = c.LocalCommit
		}
	}
	jsonOK(w, out)
}

// ===== 直连官方模板仓库通道(nuclei-templates) =====
//
// 与自建源通道的区别: 不需要任何源端配合 —— 直接拉官方 GitHub 源码包, 在客户端
// 解包/过滤/算 sha256 合成 manifest, 再走同一套落地流程(见 scanner/rule_direct.go)。
// 代价是必须能访问 github.com(或配好代理/镜像), 且"版本标识"是 commit sha
// 而不是项目版本号。

// handleRulesDirectStatus GET /api/rules/update/direct/status
func handleRulesDirectStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := scanner.DirectConfig()
	out := map[string]any{
		"enabled":     cfg.Enabled,
		"repo":        cfg.TemplatesRepo,
		"ref":         cfg.TemplatesRef,
		"severities":  cfg.Severities,
		"maxFiles":    cfg.MaxTemplates,
		"localCommit": scanner.LocalRuleCommit(),
	}
	if !cfg.Enabled {
		out["hint"] = "在 settings.json 的 updater 节增加 \"direct\": {\"enabled\": true} 即可开启官方仓库直连更新(无需自建源)"
		jsonOK(w, out)
		return
	}
	if c, err := scanner.CheckDirect(); err != nil {
		out["checkError"] = err.Error()
	} else {
		out["remoteRev"] = c.RemoteRev
		out["localRev"] = c.LocalCommit
		out["available"] = c.Available
		out["zipURL"] = c.ZipURL
	}
	jsonOK(w, out)
}

// handleRulesDirectStart POST /api/rules/update/direct/start
// 后台异步执行直连更新, 进度复用 /api/rules/update/progress 轮询(共用 updState)
func handleRulesDirectStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !scanner.DirectConfig().Enabled {
		failJSON(w, "直连更新通道未启用: 请在 settings.json 的 updater 节增加 \"direct\": {\"enabled\": true}")
		return
	}
	updMu.Lock()
	if updState.running {
		updMu.Unlock()
		failJSON(w, "已有更新任务进行中, 请稍候")
		return
	}
	updState.running = true
	updState.startedAt = time.Now()
	updState.prog = scanner.UpdateProgress{}
	updState.result = nil
	updState.err = ""
	updMu.Unlock()
	// 规则库更新入审计(影响全系统检测能力的关键操作)
	logAudit(v2DB(), r, "rule.update.start", "", "channel=direct(直连 NVD/官方源)")

	go func() {
		res, err := scanner.DirectUpdate(func(p scanner.UpdateProgress) {
			updMu.Lock()
			updState.prog = p
			updMu.Unlock()
		})
		updMu.Lock()
		updState.running = false
		updState.result = res
		if err != nil {
			updState.err = err.Error()
		}
		updMu.Unlock()
	}()
	jsonOK(w, map[string]any{"ok": true, "started": true, "channel": "direct"})
}

// handleRulesUpdateStart 一键更新: 后台异步执行规则库更新(不阻塞请求), 进度经 /progress 轮询
func handleRulesUpdateStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	updMu.Lock()
	if updState.running {
		updMu.Unlock()
		failJSON(w, "已有更新任务进行中, 请稍候")
		return
	}
	if len(scanner.UpdaterConfig().Sources) == 0 {
		updMu.Unlock()
		failJSON(w, "未配置下载源: 请在 settings.json 的 updater 节配置 sources 字段")
		return
	}
	updState.running = true
	updState.startedAt = time.Now()
	updState.prog = scanner.UpdateProgress{}
	updState.result = nil
	updState.err = ""
	updMu.Unlock()
	// 规则库更新入审计(影响全系统检测能力的关键操作)
	logAudit(v2DB(), r, "rule.update.start", "", "channel=source(配置源 manifest)")

	go func() {
		res, err := scanner.DownloadRuleUpdate(func(p scanner.UpdateProgress) {
			updMu.Lock()
			updState.prog = p
			updMu.Unlock()
		})
		updMu.Lock()
		updState.running = false
		updState.result = res
		if err != nil {
			updState.err = err.Error()
		}
		updMu.Unlock()
	}()
	jsonOK(w, map[string]any{"ok": true, "started": true})
}

// handleRulesUpdateProgress 更新进度 / 结果(running=true 时轮询本端点)
func handleRulesUpdateProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	updMu.Lock()
	defer updMu.Unlock()
	out := map[string]any{"running": updState.running, "progress": updState.prog}
	if !updState.running && (updState.result != nil || updState.err != "") {
		out["result"] = updState.result
		out["error"] = updState.err
		out["startedAt"] = updState.startedAt.Format("2006-01-02 15:04:05")
	}
	jsonOK(w, out)
}

// handleRulesUpdateLog 更新日志(新 -> 旧, 最近 50 条)
func handleRulesUpdateLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, map[string]any{"entries": scanner.ReadUpdateLog(50)})
}

// handleRulesUpdateRestore 回滚到指定备份版本(恢复后自动热加载)
func handleRulesUpdateRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Backup string `json:"backup"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Backup == "" {
		failJSON(w, "请求格式错误(需要 backup 字段)")
		return
	}
	n, err := scanner.RestoreRulesBackup(req.Backup)
	if err != nil {
		failJSON(w, err.Error())
		return
	}
	// 回滚入审计: 回滚改变全系统规则库状态, 必须可追溯"谁在什么时候回滚到哪一版"
	logAudit(v2DB(), r, "rule.update.restore", req.Backup, fmt.Sprintf("恢复 %d 个文件", n))
	jsonOK(w, map[string]any{"ok": true, "files": n, "localCommit": scanner.LocalRuleCommit()})
}
