// engine_download_api.go 引擎一键下载/安装的装配层(任务: 引擎与规则库自动获取)。
//
// 本文件是 engmgr 包与 main 包的唯一连接点(与 report_api / scheduler_api / probe_agent_download
// 同角色), 职责只有三件:
//   1. 单例持有 engmgr.Manager(懒加载), 并把引擎目录、日志接到既有约定上;
//   2. 把 envdetect 的探测结果(路径/版本)回填进 Manager 的 Info 快照, 让前端一次拿到
//      "能不能装 / 装没装 / 装的是哪个版本";
//   3. 暴露 4 个 requireAuth 端点(状态/开始/进度/卸载)。
//
// 配置: exe 同目录 engine.json 的 downloads 段(与既有 engine.json 共用同一个文件,
// 不再新增配置文件 —— 用户手工编辑的文件越少越不容易配错):
//
//	{
//	  "enabled": true,
//	  "downloads": {
//	    "allowDownload": false,      // 总开关: 不显式打开则只能看状态, 不能下载
//	    "engines": ["trivy","nuclei"],// 一键安装默认装哪些(空 = 目录里所有默认勾选项)
//	    "proxy": "http://127.0.0.1:7890",
//	    "githubMirror": "",           // 可选: 把 github.com 换成镜像前缀(国内网络常用)
//	    "clearCacheAfterInstall": false
//	  }
//	}
//
// 默认全部关闭: allowDownload=false 时 /start 直接返回明确错误(不静默不发请求),
// 符合项目规则 5(新增功能默认关闭)。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"yugsight/internal/engmgr"
	"yugsight/internal/envdetect"
)

// engineDownloadConfig 下载相关配置(engine.json 的 downloads 段)
type engineDownloadConfig struct {
	// AllowDownload 总开关(默认 false): 关闭时只能查询状态, 不能下载
	AllowDownload bool `json:"allowDownload"`
	// Engines 一键安装默认包含的引擎(空 = 使用目录内各引擎的默认勾选状态)
	Engines []string `json:"engines,omitempty"`
	// Proxy 下载代理(http://host:port)
	Proxy string `json:"proxy,omitempty"`
	// GitHubMirror GitHub 下载镜像前缀。
	//
	// 国内网络直连 github.com 经常失败(实测 234MB 的 ZAP 基本下不完), 所以留一个
	// 可配置的镜像前缀。为空时保持官方地址不变 —— 不预设第三方镜像, 避免把供应链
	// 风险默认引入(镜像内容不可控, 装进 bin/ 的会是能执行的二进制)。
	//
	// 【支持写多个候选】用逗号/分号/空白分隔(如 "https://a/, https://b/")。
	// 写多个时程序会在下载前**实测**每个候选的速度, 自动选最快的那个 —— 镜像站
	// 存活率变化很快, 让用户自己去测速并不现实。
	GitHubMirror string `json:"githubMirror,omitempty"`
	// MirrorProbe 是否在下载前探测镜像可用性(默认 true)。
	//
	// 开启后的行为: 先对候选镜像发轻量测速请求(每个上限 mirrorProbeMs), 选出可用
	// 且最快的; **若配了镜像却一个都不可用, 直接停止安装并说明原因**, 而不是默默
	// 退回直连 —— 直连在国内大概率也失败, 用户还会以为是镜像没生效。
	// 配了单个镜像时默认不探测(省一次往返), 设 true 可强制探测。
	//
	// 用指针是为了区分"没写这个字段"(默认 true)与"显式写了 false"(关掉探测)——
	// bool 零值会把两者混为一谈, 用户写 false 想关却关不掉(或反之默认被关掉)。
	MirrorProbe *bool `json:"mirrorProbe,omitempty"`
	// MirrorProbeMS 单个候选镜像的探测时长上限(毫秒, 默认 4000)
	MirrorProbeMS int64 `json:"mirrorProbeMs,omitempty"`
	// ClearCacheAfterInstall 安装成功后清理下载缓存(默认 false: 留着便于失败重试)
	ClearCacheAfterInstall bool `json:"clearCacheAfterInstall,omitempty"`
	// AutoInstall 启动后检测到引擎缺失时自动下载安装(默认 false)。
	//
	// 与 AllowDownload 的分工: AllowDownload 决定"允许不允许下载这件事"(安全边界,
	// 关闭时一键安装按钮也不可用); AutoInstall 决定"要不要在没人点按钮时自己去装"。
	// 默认关闭是因为它会带来**没人看着的长任务 + 几百 MB 流量**(ZAP 233MB), 需要
	// 显式同意(项目规则 5)。开了之后 AllowDownload 不需要重复设置 —— 自动安装本身
	// 就蕴含"允许下载", 要求用户同时写两个开关纯属为难人。
	AutoInstall bool `json:"autoInstall,omitempty"`
	// AutoInstallEngines 自动安装的引擎子集(空 = 用 engines 字段; 再空 = 目录内
	// 所有"当前平台可下载且默认勾选"的引擎, 即 ZAP 这类 DefaultOff 的不会被自动装)。
	AutoInstallEngines []string `json:"autoInstallEngines,omitempty"`
}

var (
	engDlOnce sync.Once
	engDlMgr  *engmgr.Manager
	engDlCfg  engineDownloadConfig
	// engDlLog 日志出口。默认直连 logLine(与控制台/文件双写一致), 测试可替换以捕获输出。
	//
	// 【为什么不直接调 logLine】logLine 直接写 os.Stdout 与文件句柄, 测试里没法捕获
	// (会把断言过程刷到控制台, 且拿不到"产生了哪些行"这个关键事实)。而"进度日志是否
	// 节流"恰恰只能靠"数行数"来断言, 所以留一个可替换的口子。
	//
	// 命名刻意不叫 engLog: 那个名字已被 engine_api.go 的另一个变量占用(是 []string,
	// 编译期直接 redeclared 冲突), 加 Dl 前缀与本文件其余 engDl* 命名保持一套。
	engDlLog = func(s string) { logLine(s) }
)

// engDlLogf 走可注入的日志出口(拼好格式再交给出口)
func engDlLogf(s string) { engDlLog(s) }

// splitMirrorList 数一下配置里写了几个镜像候选(仅用于启动日志提示)
func splitMirrorList(raw string) []string {
	var out []string
	cur := ""
	for _, r := range raw {
		if r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// instanceEngineDownload 返回引擎下载管理器(懒加载单例)
func instanceEngineDownload() *engmgr.Manager {
	engDlOnce.Do(func() {
		engDlCfg = loadEngineDownloadConfig()
		// 引擎目录与 engine/envdetect 的约定一致: exe 同目录 bin/
		engDlMgr = engmgr.New(engineBinDir())
		engDlMgr.SetLogger(func(s string) { logLine("引擎下载: " + s) })
		if engDlCfg.Proxy != "" {
			engmgr.SetProxy(engDlCfg.Proxy)
		}
		if engDlCfg.GitHubMirror != "" {
			// 支持逗号分隔的多个候选, 由 engmgr 在下载前探测并选最快的一个
			engmgr.SetGitHubMirror(engDlCfg.GitHubMirror)
		}
		// 镜像探测: 配了镜像就"先检测再下载"。用户明确要求过 —— 不能等下载
		// 超时 60s 才发现镜像已死; 也要求"全都不行就停下来告知", 而不是默默直连。
		engmgr.SetMirrorProbe(mirrorProbeOn(engDlCfg), engDlCfg.MirrorProbeMS)
		if mirrorProbeOn(engDlCfg) && engDlCfg.GitHubMirror != "" {
			n := len(splitMirrorList(engDlCfg.GitHubMirror))
			logLine(fmt.Sprintf("引擎下载: 已启用镜像预探测(%d 个候选, 单个上限 %dms)", n, engDlCfg.MirrorProbeMS))
		}
		if !engDlCfg.AllowDownload {
			// AutoInstall 蕴含"允许下载"(见配置注释): 只开了自动补装而没开 allowDownload 时,
			// 若仍按"未启用"处理, 用户会看到"自动装好了"但页面按钮全是灰的, 自相矛盾。
			if engDlCfg.AutoInstall {
				logLine("引擎下载: 已启用(由 downloads.autoInstall 隐含开启), 目录 " + engineBinDir())
			} else {
				logLine("引擎下载: 未启用(engine.downloads.allowDownload=true 可开启一键安装)")
			}
		} else {
			logLine(fmt.Sprintf("引擎下载: 已启用, 目录 %s, 代理=%v", engineBinDir(), engDlCfg.Proxy != ""))
		}
		})
	return engDlMgr
}

// downloadsAllowed 下载是否被允许。
//
// 抽成纯函数(而非只留 engineDownloadsEnabled)是为了可测: sync.Once 单例一旦初始化
// 就没法重置, 想验证判定规则只能靠纯函数, 否则测试得去顶掉 Once 污染同包其它用例。
func downloadsAllowed(cfg engineDownloadConfig) bool {
	return cfg.AllowDownload || cfg.AutoInstall
}

// engineDownloadsEnabled 下载总开关是否打开(自动补装蕴含允许下载, 见配置注释)
func engineDownloadsEnabled() bool {
	instanceEngineDownload()
	return downloadsAllowed(engDlCfg)
}

// loadEngineDownloadConfig 读 exe 同目录 engine.json 的 downloads 段。
//
// 复用同一个配置文件而不是新开 engine_download.json: 引擎相关配置集中一处,
// 用户可以少记一个文件名; 解析失败时保持默认(全关), 不报错不崩溃。
func loadEngineDownloadConfig() engineDownloadConfig {
	// 用 readConfigFile 而不是直接 ReadFile: 它会剥掉 Windows 记事本/PowerShell
	// 写出的 UTF-8 BOM —— 带 BOM 时 json.Unmarshal 会直接失败, 表现为"配置写对了
	// 却不生效"(实测踩过)。同 updater.json 的处理口径。
	var cfg engineDownloadConfig
	data, ok := section(secEngine, "")
	if !ok {
		return cfg
	}
	var wrapper struct {
		Downloads *engineDownloadConfig `json:"downloads"`
	}
	if json.Unmarshal(data, &wrapper) != nil {
		logLine("engine 配置解析失败(下载配置使用默认值: 全部关闭)")
		return defaultEngineDownloadConfig()
	}
	if wrapper.Downloads == nil {
		return defaultEngineDownloadConfig()
	}
	cfg = *wrapper.Downloads
	// MirrorProbe 未显式配置时默认开启: "配了镜像先测一下再用"是更安全的行为,
	// 而"写多个镜像让程序挑最快的"必须靠它才有意义。
	if cfg.MirrorProbe == nil {
		t := true
		cfg.MirrorProbe = &t
	}
	if cfg.MirrorProbeMS <= 0 {
		cfg.MirrorProbeMS = 4000
	}
	return cfg
}

// defaultEngineDownloadConfig 配置缺失/损坏时的兜底(除探测开关外全部关闭)
func defaultEngineDownloadConfig() engineDownloadConfig {
	t := true
	return engineDownloadConfig{MirrorProbe: &t, MirrorProbeMS: 4000}
}

// mirrorProbeOn 读探测开关(指针解引用 + 默认值兜底)
func mirrorProbeOn(cfg engineDownloadConfig) bool {
	return cfg.MirrorProbe == nil || *cfg.MirrorProbe
}

// ===== API =====

// handleEngineDownloadStatus GET /api/engine/downloads
//
// 返回: 开关状态 + 逐引擎可下载性(平台支持/是否需要 7z/是否已装/已装版本)
// + 已缓存包体占用。前端据此渲染"一键安装"按钮与禁用理由。
func handleEngineDownloadStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := instanceEngineDownload()
	infos := m.Info()

	// 把 envdetect 的探测结果合并进来: Manager 只扫 bin/ 是否"有文件",
	// 而"能不能跑、版本多少"由 envdetect 负责(它有 --version 探测与降级判定)。
	det := envdetect.Get()
	installed := map[string]envdetect.EngineStatus{}
	for _, e := range det.Engines {
		installed[e.Name] = e
	}
	for i := range infos {
		// 引擎名映射: engmgr 的 nmap/trivy/zap <-> envdetect 的 nmapcore/trivycore/zapcore
		key := ""
		switch string(infos[i].Engine) {
		case "nmap":
			key = envdetect.EngineNmap
		case "trivy":
			key = envdetect.EngineTrivy
		case "zap":
			key = envdetect.EngineZap
		case "nuclei":
			key = envdetect.EngineNuclei
		}
		if es, ok := installed[key]; ok && es.Found {
			infos[i].Installed = true
			infos[i].InstalledPath = es.Path
			infos[i].InstalledVersion = es.Version
		}
	}
	cacheBytes, cacheFiles := m.BlobCacheSize()
	prog, running, results, lastErr := m.Progress()

	jsonOK(w, map[string]any{
		"configured":   engineDownloadsEnabled(),
		"binDir":       m.BinDir(),
		"proxy":        maskProxy(engDlCfg.Proxy),
		"mirror":       engDlCfg.GitHubMirror != "",
		// 镜像候选与"当前实际在用哪个": 配了多个候选时用户需要看到程序挑了哪一个,
		// 否则他无法判断"自动选最快"到底有没有在工作。
		"mirrorCandidates": engmgr.MirrorCandidates(),
		"mirrorInUse":      engmgr.CurrentMirror(),
		"mirrorProbe":      mirrorProbeOn(engDlCfg),
		"mirrorProbeMs":    engDlCfg.MirrorProbeMS,
		"engines":      infos,
		"cacheBytes":   cacheBytes,
		"cacheFiles":   cacheFiles,
		"running":      running,
		"progress":     prog,
		"results":      results,
		"lastError":    lastErr,
		"extractTools": engmgr.ExtractToolNames(),
		// 自动补装状态: 前端据此显示"缺的会被自动装好"与"当前会补哪几个平台包",
		// 让用户不必翻配置文件就能确认自动化是否在工作。
		"autoInstall": map[string]any{
			"enabled":  engDlCfg.AutoInstall,
			"pending":  engineAutoInstallTargets(engDlCfg, m),
			"explicit": len(engDlCfg.AutoInstallEngines) > 0,
		},
	})
}

// handleEngineDownloadStart POST /api/engine/downloads/start
//
// 请求体: {"engines":["trivy","nuclei"]}(可省略 = 使用配置里的默认集合)。
// 后台异步执行, 前端轮询 /progress。
func handleEngineDownloadStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := instanceEngineDownload()
	if !engineDownloadsEnabled() {
		failJSON(w, "引擎下载未启用: 请在 settings.json 的 engine.downloads 中设置 allowDownload=true")
		return
	}
	if _, running, _, _ := m.Progress(); running {
		failJSON(w, "已有引擎下载任务进行中, 请等待完成")
		return
	}
	var req struct {
		Engines []string `json:"engines"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // 体为空是合法用法(用默认集合)
	}
	var targets []engmgr.Engine
	for _, s := range req.Engines {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		targets = append(targets, engmgr.Engine(s))
	}
	if len(targets) == 0 {
		for _, s := range engDlCfg.Engines {
			targets = append(targets, engmgr.Engine(strings.ToLower(strings.TrimSpace(s))))
		}
	}

	go func() {
		res, err := m.Install(targets, nil)
		if err != nil {
			logLine("引擎下载: 任务结束(有失败项): " + err.Error())
		} else {
			ok := 0
			for _, it := range res {
				if it.OK {
					ok++
				}
			}
			logLine(fmt.Sprintf("引擎下载: 任务完成, 成功 %d/%d", ok, len(res)))
		}
		// 装完立刻重新探测一次, 前端下次轮询就能看到新版本(不必手动点"重新检测")
		envdetect.Refresh()
		if engDlCfg.ClearCacheAfterInstall {
			if cerr := m.ClearBlobCache(); cerr != nil {
				logLine("引擎下载: 缓存清理失败: " + cerr.Error())
			}
		}
	}()
	jsonOK(w, map[string]any{"ok": true, "started": true, "engines": targets})
}

// handleEngineDownloadProgress GET /api/engine/downloads/progress
func handleEngineDownloadProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := instanceEngineDownload()
	prog, running, results, lastErr := m.Progress()
	out := map[string]any{
		"running":  running,
		"progress": prog,
		"results":  results,
	}
	if !running {
		out["error"] = lastErr
	}
	// 镜像探测结论: 前端可展示"已自动选用 xxx(比直连快 N 倍)", 让用户看得见
	// "先检测再下载"确实发生了, 而不是黑箱。
	if cs := engmgr.MirrorProbeSnapshot(); len(cs) > 0 {
		out["mirrorProbe"] = cs
		if cur := engmgr.CurrentMirror(); cur != "" {
			out["mirrorInUse"] = cur
		}
	}
	jsonOK(w, out)
}

// handleEngineDownloadUninstall POST /api/engine/downloads/uninstall
//
// 请求体: {"engine":"trivy"}。删除 bin/ 下对应引擎的可执行文件(不递归删目录,
// 避免误删用户放在 bin/ 里的其它资源)。
func handleEngineDownloadUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := instanceEngineDownload()
	if !engineDownloadsEnabled() {
		failJSON(w, "引擎下载未启用: 需在 settings.json 的 engine.downloads 中设置 allowDownload=true")
		return
	}
	var req struct {
		Engine string `json:"engine"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Engine) == "" {
		failJSON(w, "请求格式错误(需要 engine 字段)")
		return
	}
	n, err := m.Uninstall(engmgr.Engine(strings.ToLower(strings.TrimSpace(req.Engine))))
	if err != nil {
		failJSON(w, err.Error())
		return
	}
	envdetect.Refresh()
	jsonOK(w, map[string]any{"ok": true, "removed": n})
}

// handleEngineDownloadCacheClear POST /api/engine/downloads/cache/clear
// 清理已下载包体缓存(失败重试后回收磁盘空间; 不能删正在被解包的包, 故仅在空闲时允许)
func handleEngineDownloadCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := instanceEngineDownload()
	if _, running, _, _ := m.Progress(); running {
		failJSON(w, "有下载任务进行中, 暂不可清理缓存")
		return
	}
	if err := m.ClearBlobCache(); err != nil {
		failJSON(w, "清理失败: "+err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

// ===== 启动后自动补装 =====

// startEngineAutoInstall 启动后异步检测引擎缺失并自动补装(默认关闭, 见 AutoInstall 字段)。
//
// ===== 为什么异步 + 只装"该装的" =====
//
// 用户诉求是"检测到没有就自动下载进来, 尽量自动化"。要守住四条边界, 否则自动化会变成惊吓:
//  1. **异步**: ZAP 包 233MB, 同步等会卡住启动(Web 页面都打不开), 用户以为程序没反应;
//  2. **只装缺失的**: 已装的不重下(几百 MB 流量不该白花);
//  3. **跳过 DefaultOff 的**: ZAP 这类默认不勾选的引擎不自动装(它体积最大且只对 Web
//     扫描有用, 无差别自动下载会吃掉整个带宽), 想装就显式列进 autoInstallEngines;
//  4. **失败不阻塞**: 任何一步失败只记日志 —— 引擎缺失本来就有内置引擎兜底路径。
//
// 与 AllowDownload 的关系: AutoInstall=true 时视为同时允许下载(见结构体注释), 不让用户
// 为同一个意图写两个开关。
func startEngineAutoInstall() {
	instanceEngineDownload() // 确保配置已加载
	if !engDlCfg.AutoInstall {
		return // 默认关闭: 零网络行为(项目规则 5)
	}
	m := instanceEngineDownload()
	if _, running, _, _ := m.Progress(); running {
		return // 已有任务在跑(用户刚点了一键安装), 不叠加
	}
	names := engineAutoInstallTargets(engDlCfg, m)
	if len(names) == 0 {
		logLine("引擎自动补装: 未发现缺失的可自动安装引擎, 跳过")
		return
	}
	logLine(fmt.Sprintf("引擎自动补装: 后台开始安装 %d 个缺失引擎(%s); 大包下载可能耗时较久",
		len(names), strings.Join(names, ", ")))
	go func() {
		// 顶层 recover: 后台 goroutine 里逃出的 panic 会带走整个进程(且 recover 只在
		// 本层生效), 自动补装纯属锦上添花, 绝不能因此影响主服务(规则 4)。
		defer func() {
			if rec := recover(); rec != nil {
				logLine(fmt.Sprintf("引擎自动补装: 后台任务异常已恢复: %v", rec))
			}
		}()
		// 【为什么必须传进度回调】第一版传了 nil, 结果从"开始安装"到下载完成这几分钟里
		// 控制台一片安静(里程碑日志只在 extracting/done 打)——用户看不到任何动静, 以为
		// 卡死了或者"根本没在装", 于是关掉窗口, 下载被中断且无任何痕迹(实测踩过)。
		// 下载几十到几百 MB 是分钟级长任务, 必须有可见的推进过程。
		res, err := m.Install(toEngines(names), autoInstallProgress())
		if err != nil {
			// Install 的 err 是"有失败项"的汇总; 逐项结果在 res 里, 逐条记清楚便于排错
			for _, it := range res {
				if !it.OK {
					logLine(fmt.Sprintf("引擎自动补装[%s] 失败: %s", it.Engine, it.Error))
				}
			}
			logLine("引擎自动补装: 任务结束(存在失败项): " + err.Error())
		} else {
			ok := 0
			for _, it := range res {
				if it.OK {
					ok++
				}
			}
			logLine(fmt.Sprintf("引擎自动补装: 完成, 成功 %d/%d", ok, len(res)))
		}
		// 装完刷新探测, 状态卡片立刻反映新引擎(不必等用户手动点"重新检测")
		envdetect.Refresh()
		if engDlCfg.ClearCacheAfterInstall {
			if cerr := m.ClearBlobCache(); cerr != nil {
				logLine("引擎自动补装: 缓存清理失败: " + cerr.Error())
			}
		}
	}()
}

// autoInstallProgress 自动补装的进度回调: 把下载推进过程打到控制台。
//
// ===== 为什么需要"节流到每 10% 一条" =====
//
// 进度回调是**每个数据块触发一次**的(几十 KB 一次), 一个 100MB 的包会产生上千次回调。
// 直接全打会把 yugsight.log 冲爆(日志文件几秒内涨到几十 MB), 真问题被淹没; 而
// 一次不打又会让用户在下载的几分钟里完全看不到动静(这正是第一版的问题)。
//
// 折中: 只在"百分比跨过 10 的整数倍"或"阶段变化"时打一条, 长任务里既能看到推进,
// 日志量也可控(单包最多 10 条 + 阶段切换)。
//
// 用闭包持有状态而不读 Manager.Progress(): 回调本身就是权威事件源, 再回查一次
// 快照反而可能读到下一个引擎的进度(一批任务逐个安装, 快照会被覆盖)。
func autoInstallProgress() engmgr.ProgressFunc {
	lastPct := -1
	lastStage := ""
	return func(p engmgr.Progress) {
		// 阶段切换(queued->checking->downloading->extracting->installing->done/failed)
		// 必须打: 这些是用户能理解的里程碑, 与百分比无关
		if p.Status != lastStage {
			lastStage = p.Status
			// 阶段切换时重置百分比记忆, 否则下一个阶段从 50% 起步却因"没跨过 10 的倍数"
			// 而沉默(各阶段的 Percent 是各自独立的计数)
			lastPct = -1
			if p.Phase != "" {
				engDlLogf(fmt.Sprintf("引擎自动补装[%s] %s: %s", p.Engine, p.Status, p.Phase))
			}
		}
		// 下载阶段才有字节进度
		if p.Status != engmgr.StDownloading || p.Percent < 0 {
			return
		}
		if p.Percent/10 != lastPct/10 || lastPct < 0 {
			lastPct = p.Percent
			line := fmt.Sprintf("引擎自动补装[%s] 下载中 %d%%", p.Engine, p.Percent)
			if p.TotalB > 0 {
				line += fmt.Sprintf(" (%s/%s", humanMB(p.Bytes), humanMB(p.TotalB))
			} else {
				line += fmt.Sprintf(" (%s", humanMB(p.Bytes))
			}
			if p.Speed > 0 {
				line += fmt.Sprintf(", %s/s", humanMB(p.Speed))
			}
			engDlLogf(line + ")")
		}
	}
}

// humanMB 字节数转人类可读的 MB/GB 字符串(日志里看大包体积更直观)。
// 用 1000 进制而非 1024: 与下载器/浏览器显示的口径一致, 避免用户对不上数。
func humanMB(n int64) string {
	if n < 0 {
		return "?"
	}
	const (
		kb = 1000
		mb = 1000 * kb
		gb = 1000 * mb
	)
	switch {
	case n >= gb:
		return fmt.Sprintf("%.2fGB", float64(n)/float64(gb))
	case n >= mb:
		return fmt.Sprintf("%.1fMB", float64(n)/float64(mb))
	case n >= kb:
		return fmt.Sprintf("%.0fKB", float64(n)/float64(kb))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// engineAutoInstallTargets 计算"应当自动补装"的引擎名列表。
//
// 优先级: autoInstallEngines > engines > 目录内全部合规项。
// 为什么中间还看 engines: 该字段是用户既有配置里"我关心哪些引擎"的表达(一键安装默认
// 集合), 自动补装沿同一意图走最符合预期, 不必逼用户再抄一遍。
func engineAutoInstallTargets(cfg engineDownloadConfig, m *engmgr.Manager) []string {
	want := cfg.AutoInstallEngines
	if len(want) == 0 {
		want = cfg.Engines
	}
	// 平台可下载性 + 是否已装: 直接复用 Manager.Info(), 避免在这里重写一遍平台判定
	// (重写就会和 engmgr 的规则漂移, 出现"界面说能装、自动装却失败"的怪现象)。
	infos := m.Info()
	var out []string
	for _, info := range infos {
		name := string(info.Engine)
		if len(want) > 0 {
			if !containsFold(want, name) {
				continue
			}
		} else if info.DefaultOff != "" {
			continue // 未点名时跳过"默认不勾选"的引擎(如 ZAP: 233MB)
		}
		if !info.Supported {
			continue // 当前平台/架构没有官方包(装了也跑不起来)
		}
		if info.Installed {
			continue // 已装不重下
		}
		out = append(out, name)
	}
	return out
}

// toEngines 字符串切片转 engmgr.Engine 切片(顺带归一化大小写与空白)
func toEngines(names []string) []engmgr.Engine {
	out := make([]engmgr.Engine, 0, len(names))
	for _, n := range names {
		out = append(out, engmgr.Engine(strings.ToLower(strings.TrimSpace(n))))
	}
	return out
}

// containsFold 大小写不敏感地判断列表是否包含某值(引擎名用户可能写成 Nmap/ZAP)
func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}

// maskProxy 代理地址脱敏(可能含用户名密码, 不回显明文)
func maskProxy(p string) string {
	if p == "" {
		return ""
	}
	if i := strings.Index(p, "@"); i >= 0 {
		return "***" + p[i:]
	}
	return p
}

// ensureGitHubMirrorNote 供前端提示: 未配置镜像且非国内网络时给出建议
func ensureGitHubMirrorNote() string {
	if engDlCfg.GitHubMirror != "" {
		return ""
	}
	return "直连 GitHub 失败时可配置 engine.json 的 downloads.githubMirror 或 downloads.proxy"
}

// errEngineDownloadsDisabled 统一错误(供测试断言)
var errEngineDownloadsDisabled = errors.New("engine downloads disabled")

// engineDownloadConfigPath 配置来源路径(红线: 唯一配置文件 settings.json)。
//
// engineCfgPath 已随 engine.json 一并删除(配置收敛整改), 这里改为直接指向
// settings.json; 保留为变量以便测试改指临时目录。
var engineDownloadConfigPath = settingsFilePath

var _ = time.Second // 保留 time import(进度时间戳相关扩展)
