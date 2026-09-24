package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"yugsight/engine"
	"yugsight/envdetect"
	"yugsight/pathrel"
	"yugsight/scanctl"
	"yugsight/scanner"
	"yugsight/sse"
)

//go:embed web/*
var uiFS embed.FS

const (
	appName = "Yugsight"
	// displayCnName 控制台日志/提示里展示的产品名(项目命名口径: Yugsight / 御视)。
	// appName 保持纯英文: 它是机器可读身份(API 的 name 字段、日志文件名 yugsight.log、
	// 注册表 Software\Yugsight), 混入中文会让脚本与前端按英文名匹配的逻辑全部失效。
	displayCnName = "御视 (Yugsight)"
)

// appVersion 当前构建的版本号(形如 1.0.0, 展示在 UI / 报告 / 探针上报里)。
//
// 【为什么是 var 而不是 const】构建脚本通过
// `-ldflags "-X main.appVersion=<ver>"` 注入, 而 ldflags 只能改写**变量**。
// 写成 const 的话链接期会报 "cannot set with -X"。
//
// 【默认值的作用】直接用 `go build`(不经过 scripts/build.ps1)时拿到的就是这个
// 兜底值, 保证任何构建方式都能编译出可运行程序, 只是版本号不随构建自增。
//
// 自增规则见 version.go: 末位 +1, 到 9 则进位(1.0.0.9 -> 1.0.1.0), 由构建脚本落盘。
var appVersion = "1.0.0"

var (
	// logOut 日志文件写入器(带轮转)。nil 表示日志只走控制台 —— 文件打开失败时
	// 降级不报错, 不能因为"日志写不了"就让扫描器起不来(项目规则 4)。
	// 具体轮转规则见 logrotate.go: 超过上限归档为 logs/yugsight-N.log 后重开新文件。
	logOut *logWriter
	logMu  sync.Mutex // 串行化控制台输出, 防止多 goroutine 并发写导致行交错
	// logFilePath 当前日志的完整路径(供 UI/日志提示展示真实位置, 避免各处拼字符串)
	logFilePath string
)

func initLog() {
	exe, err := os.Executable()
	if err != nil {
		exe = "."
	}
	dir := filepath.Dir(exe)
	logOut = newLogWriterFromConfig(dir, "yugsight.log")
	// 用 logPaths 反算真实路径而不是各处在文案里手拼: keepAtRoot 开关会改变
	// 当前日志的位置, 手拼的文案会与实际不符(用户按提示找不到文件)
	logFilePath, _ = logPaths(dir, "yugsight.log", loadLogConfig())
	// 启动日志说明轮转参数: 用户看到日志"忽然变少/多了 logs 目录"时,
	// 日志本身就是答案, 不用去翻源码或文档
	if c := loadLogConfig(); c.MaxMB > 0 {
		logLine(fmt.Sprintf("日志轮转已启用: %s 超过 %dMB 后归档为 %s/yugsight-N.log (保留最近 %d 份)",
			logFilePath, c.MaxMB, c.Dir, c.MaxFiles))
	} else {
		logLine(fmt.Sprintf("日志轮转未启用(maxMB=0), %s 将持续追加", logFilePath))
	}
}

// logDisplayPath 返回给用户看的日志路径。
//
// 优先用 initLog 记下的真实路径; 若 initLog 尚未执行(例如 main 早期 panic,
// 提权/单实例检查阶段就失败), 退化为"exe 同目录 logs/yugsight.log"这一默认口径 ——
// 崩在最早期时提示必须仍然指向一个能让人找到线索的地方, 不能返回空串。
func logDisplayPath() string {
	if logFilePath != "" {
		return logFilePath
	}
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(logRotateDefaultDir, "yugsight.log")
	}
	p, _ := logPaths(filepath.Dir(exe), "yugsight.log", loadLogConfig())
	return p
}

// closeLog 进程退出前调用, 让最后几条日志落盘并释放文件句柄
func closeLog() {
	if logOut != nil {
		logOut.Close()
	}
}

func logLine(s string) {
	if len([]rune(s)) > 1000 {
		s = string([]rune(s)[:1000]) + "..."
	}
	// 日志展示口径: exe 目录树内的绝对路径一律相对化(用户要求"只要日志出现路径就用相对")。
	// 兜底钩子放在日志入口 —— 各模块(db/engmgr/scanner/envdetect...)无论走 logLine 还是
	// 注入的 logger, 最终都从这里出, 一处覆盖全部; 目录外路径原样保留。
	s = pathrel.InMessage(s)
	line := time.Now().Format("2006-01-02 15:04:05  ") + s + "\n"
	// 文件写入自带锁(轮转需要), 控制台的锁单独持有: 合并成一把会让每行日志的
	// 控制台输出也压在文件锁上, 长时间持锁时终端明显卡顿
	if logOut != nil {
		_, _ = logOut.Write([]byte(line))
	}
	logMu.Lock()
	if os.Stdout != nil {
		fmt.Fprint(os.Stdout, line)
	}
	// 顶栏重绘必须与输出同锁: "移光标->写行->移回"与并发的日志输出交错会把日志写进
	// 顶栏行中间(撕裂)。函数内部对"未启用/无 URL"是一次原子读, 日志洪峰下零开销。
	consolePinAfterLog()
	logMu.Unlock()
}

var uiPort int

// uiMode 主页 UI 风格: vue=Vue3 新前端(默认) | old=经典单文件页;
// 经典页始终可在 /classic/ 子路径访问; -ui 参数可切换主页
var uiMode = "vue"

// nucleiOn / nucleiDirPath: Nuclei 外部模板扫描的全局开关与模板目录。
// 全局开关(-nuclei)与前端任务开关(enableNuclei)同时为真才执行;
// 与内置规则(vuln_builtin.json)是两套独立规则, 互不影响。
var nucleiOn bool
var nucleiDirPath string

func main() {
	// 顶层兜底: 捕获启动阶段(消息循环之前)的 panic。windowsgui 无控制台, 崩溃原因只会
	// 写进日志; 这里再弹个框, 用户双击闪退时也能看到原因, 不用去翻日志
	defer func() {
		if r := recover(); r != nil {
			logLine(fmt.Sprintf("程序异常退出(panic): %v\n%s", r, debug.Stack()))
			showMessage(appName+" 启动异常", "程序启动时发生异常, 已记录到日志:\n"+fmt.Sprint(r)+"\n\n详见 "+logDisplayPath())
		}
	}()
	port := flag.Int("port", 8420, "Web UI 起始监听端口, 被占用时自动顺延")
	noAdmin := flag.Bool("no-admin", false, "不请求管理员权限(ICMP 将不可用)")
	elevated := flag.Bool("elevated", false, "(内部)已执行过提权, 不再重复提权")
	noAuth := flag.Bool("no-auth", false, "测试模式: 跳过注册/登录(也可在 exe 同目录放 test_mode.txt 文件, 生产构建请勿使用)")
	noBrowser := flag.Bool("no-browser", false, "不自动打开浏览器")
	// -lan 保留兼容: 绑定 0.0.0.0 现已是默认行为, 带不带都一样(旧快捷方式/脚本不用改)。
	_ = flag.Bool("lan", false, "(保留兼容)已默认绑定 0.0.0.0 全部网卡, 无需再带")
	bindLocal := flag.Bool("bind-local", false, "只绑定本机局域网 IP(默认绑 0.0.0.0, 全部网卡)")
	nuclei := flag.Bool("nuclei", false, "启用 Nuclei 模板扫描(现已默认启用, 此参数保留兼容, 无需再带)")
	noNuclei := flag.Bool("no-nuclei", false, "关闭 Nuclei 模板扫描(默认开启; 内置模板已打包进 exe, 外部模板放 exe 同目录 templates/)")
	nucleiDir := flag.String("nuclei-dir", "", "Nuclei 模板目录(缺省用 exe 同目录 templates/)")
	ai := flag.Bool("ai", false, "全局启用 AI 后置分析(扫描批量风险汇总), 配置读 exe 同目录 ai.json, 默认关闭")
	probeFlag := flag.String("probe", "", "启用分布式探针中心端: center=只作中心端, both=中心端+本地探针端(同机联调); 探针端请用独立的 yugsight-agent 程序")
	showVer := flag.Bool("version", false, "显示版本号后退出")
	pcapMode := flag.String("pcap", "", "(内部)抓包 worker 模式: devices|capture, 请勿手动使用")
	pcapDev := flag.String("pcap-dev", "", "(内部)抓包设备路径, 请勿手动使用")
	pcapFilter := flag.String("pcap-filter", "", "(内部)BPF 过滤表达式, 请勿手动使用")
	flag.StringVar(&uiMode, "ui", "vue", "主页 UI 风格: vue=Vue3 新前端(默认) | old=经典单文件页; 经典页始终可在 /classic/ 子路径访问")
	flag.Parse()
	if *showVer {
		fmt.Println(appName + " v" + appVersion + " (MIT License)")
		return
	}
	// 抓包 worker 子进程: 最前面分发, 不做单实例检查(不与父进程抢互斥量)/不提权/不绑端口
	// 目的: wpcap.dll 驱动调用(枚举/抓包)与主进程隔离, 驱动崩溃只死子进程
	if *pcapMode != "" {
		runPcapWorker(*pcapMode, *pcapDev, *pcapFilter)
		return
	}

	initLog()
	// 默认自动提权到管理员(ICMP ping 等探测需要), -no-admin 或已提权(-elevated)跳过。
	// 必须先提权再做单实例检查: 否则 UAC re-exec 时, 新(管理员)进程会读到原进程
	// 尚未释放的互斥量, 误判"已在运行"而退出; 原进程随后也退出 => 双击后无进程存活(闪退)
	if !*noAdmin && !*elevated {
		ensureAdmin()
	}
	// 单实例检查(防双击多次/重复启动): 放在提权之后, 由最终进程持有实例
	ensureSingleInstance()
	if *noAuth || testModeEnabled() {
		authDisabled = true
		if testModeEnabled() {
			logLine("检测到 test_mode.txt, 测试模式: 跳过注册/登录/设备绑定")
		}
	}
	loadAuth()
	// settings.json 的 auth 节: enabled=false 整体关闭登录鉴权; 全新安装自动创建
	// 初始账号(默认 admin/admin123, 明文回写 auth 节供查看), 详见 auth_init.go
	applyAuthSwitch()
	initDefaultAccount()

	// 加载漏洞库: 内置规则 + exe 同目录 vuln/ 下所有 *.json
	if n, errs := scanner.LoadVulnLibrary(); n > 0 || len(errs) > 0 {
		logLine(fmt.Sprintf("漏洞库已加载: %d 条规则(内置 + vuln/ 目录)", n))
		for _, e := range errs {
			logLine("漏洞库警告: " + e)
		}
	}

	// Nuclei 外部模板(与内置规则两套独立): 默认启用, 无需再带 -nuclei 参数(-no-nuclei 关闭);
	// 启用后启动即预加载模板缓存 —— 一次读盘解析, 之后所有扫描任务复用, 不重复读 yaml
	nucleiOn = !*noNuclei
	if *nuclei {
		logLine("检测到 -nuclei 参数: Nuclei 模板扫描现已默认启用, 以后启动无需再带该参数")
	}
	if nucleiOn {
		dir := *nucleiDir
		if dir == "" {
			if exe, err := os.Executable(); err == nil {
				dir = filepath.Join(filepath.Dir(exe), "templates")
			} else {
				dir = "templates"
			}
		}
		nucleiDirPath = dir
		tpls, errs := scanner.LoadTemplateCache(dir)
		if len(tpls) > 0 || len(errs) > 0 {
			logLine(fmt.Sprintf("Nuclei 外部模板缓存: %d 个模板 (目录 %s)", len(tpls), dir))
			for _, e := range errs {
				logLine("Nuclei 模板警告: " + e)
			}
		}
		logLine(fmt.Sprintf("Nuclei 内置模板: %d 个 (打包进 exe, 外部模板同 ID 可覆盖)",
			scanner.BuiltinTemplateCount()))
	}

	// 规则库在线更新(任务 2): 配置读 exe 同目录 updater.json(可选, 默认全部关闭:
	// 无下载源不更新 / 自动更新关 / 分级加载关); 后台自动更新循环仅当 autoUpdate 开启时运行
	loadUpdaterConfig()
	scanner.StartUpdater()

	// AI 后置分析(可选插件, 只解读不判定): exe 同目录 ai.json + -ai 全局开关;
	// 默认关闭, 关闭时不发起任何 LLM 调用。扫描结束批量汇总见 handleScan 尾部。
	initAI(*ai)

	// 任务 4.2: 环境检测(本地引擎 ./bin/ + Npcap 驱动): 异步检测不阻塞启动,
	// 引擎缺失自动标记降级(切换内置引擎); 状态经 /api/env 上报前端引擎面板
	envdetect.SetLogger(logLine)
	envdetect.Init()

	// 统一配置中心: 读 settings.json 并把已配置的节打到日志。
	//
	// 【为什么在启动最早期调】后续所有模块(engine/probe/scheduler/report/capture...)
	// 都会经 section() 读配置, 这里先加载一次, 保证日志里"配置加载情况"出现在各模块
	// 的状态行之前 —— 用户排查"为什么我的配置没生效"时, 第一眼就能看到程序到底读到
	// 了哪些节。
	loadSettings()
	// scanner 包的白名单持久化注入: 存进 settings.json 的 whitelist 节, 由装配层
	// 负责合并写(保留其它节与注释)。scanner 包本身不感知 settings.json 的存在。
	scanner.SetWhitelistHook(scanner.WhitelistHook{
		Load: func() ([]byte, bool) { return sectionBytes(secWhitelist) },
		Save: func(data []byte) error {
			var v any
			if err := json.Unmarshal(data, &v); err != nil {
				return err
			}
			return writeSection(secWhitelist, v)
		},
	})

	// 抓包配置预加载: 把抓包配置读进来并把开关(环路检测/全量采集)打到启动日志。
	//
	// 【为什么必须在启动时主动调一次】instanceCaptureConfig 是懒加载的, 若只在
	// 捕获接口里触发, 用户改完配置重启后日志里什么都看不到, 会以为配置
	// 没生效而反复排查。启动即加载让配置状态在日志里可见(与 engine/probe 的
	// "启动时打印是否启用"口径一致)。
	instanceCaptureConfig()

	// 引擎自动补装(可选, 默认关闭): engine.json 的 downloads.autoInstall=true 时,
	// 启动后后台把"缺失且当前平台可下载"的引擎自动装进 ./bin/。异步执行不阻塞启动;
	// 关闭时不发任何请求(项目规则 5)。
	//
	// 无需先判断开关再调用: startEngineAutoInstall 内部第一件事就是查配置并 return,
	// 在这里再读一遍配置反而有"两处判定口径不一致"的风险(一处读字符串比较、一处读
	// 结构体字段, 迟早会漂)。
	startEngineAutoInstall()

	// 任务 6.1: 外部引擎 CLI 执行器(./bin/ nmapcore/trivycore/zapcore):
	// 统一执行封装(stdout/stderr 双捕获 + 超时控制 + 进程树递归终止), 供扫描管线
	// 编排调用; 执行器本身不启动进程, 无任务时空转零开销
	engine.SetLogger(logLine)

	// 任务 6.2: 引擎输出解析 + 自动降级编排(engine/parsers)。
	// 装配顺序: 外部执行器(6.1) + 内置引擎兜底 Runner -> 解析(nmap XML/JSON,
	// trivy JSON, zap JSON) -> 归一化(标准 Asset/Vuln)。
	// 默认关闭(engine.json enabled=false): 仅初始化不发起任何外部进程调用,
	// 引擎缺失/执行失败/解析失败时自动降级内置引擎, 不中断任务。
	instanceOrchestrator()

	// 任务 6.3: 分布式扫描探针框架(中心端管理服务 + 探针端 SDK)。
	// 装配顺序: 日志注入 -> 探针端(后续任务) -> 中心端监听。
	// 配置读 exe 同目录 probe.json(可选): 默认 center.enabled/client.enabled 均 false,
	// 即不监听端口也不发起外连, 行为与单机版完全一致; 监听失败只记日志降级。
	probeOverrideRole = *probeFlag
	instanceProbe()

	// 任务 7.1: 扫描任务队列调度(排队 + 全局/单节点并发 + 策略模板 + 网段限速 +
	// 探针路由与重分配)。配置读 exe 同目录 scheduler.json(可选):
	// 默认 enabled=false —— 不接管 /api/scan, 保持原有即时执行, 零行为变化。
	// 须在 instanceProbe 之后: 调度器要同步探针节点视图才能做负载路由。
	instanceScheduler()

	// 任务 10a: SNMP 网络监控(周期采集交换机/服务器指标)。
	// 默认启用但空目标 = 零网络活动, 用户从监控页加目标后才开始采集;
	// 只读 GET/GETBULK, 对目标设备零影响。
	instanceMonitor()

	// 阶段 1: 节点监控采集底座(WinRM/SSH/主机SNMP/ICMP/NetFlow/NETCONF/RESTCONF)
	// 默认全关(规则 5): 未开启时不跑循环、不监听端口、零外连。
	instanceCollect()

	// 阶段 3: AI 全链路分析模块装配(配置读取器/结构化记忆数据源/RAG 索引)。
	// 本身不产生任何 LLM 调用 —— 全局 enabled 仍由 initAI 控制, 关闭时零外连。
	InitAI()

	// 二期 15: 配置热重载 —— 改 settings.json 后 5 秒内自动生效(另有 SIGUSR1
	// 与 POST /api/v2/config/reload 两个触发口)。放在各单例装配之后: 重载要
	// 把新配置推给已存在的实例, 先建后重才有对象可推。
	StartSettingsWatcher()
	RegisterReloadSignal()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveUI)
	mux.HandleFunc("/classic", serveUI)   // 经典单文件页固定入口
	mux.HandleFunc("/classic/", serveUI)
	mux.HandleFunc("/api/auth/status", handleAuthStatus)
	mux.HandleFunc("/api/register", handleRegister)
	mux.HandleFunc("/api/login", handleLogin)

	// 2FA(动态验证码)登录前接口(算法与前端同源, 全本地计算)。
	// 旧设置页 3 条 requireAuth 路由(status/seed/toggle)前端零调用, 已删除
	// (2026-09-21 收尾: 不留死接口) —— 码值与启停全部落到登录页, 与
	// /api/login、/api/auth/status 同口径不走 requireAuth(单管理员内网工具)。
	mux.HandleFunc("/api/auth/2fa/code", handle2FACode)
	mux.HandleFunc("/api/auth/2fa/enable", handle2FAEnable)
	mux.HandleFunc("/api/auth/2fa/disable", handle2FADisable)
	mux.HandleFunc("/api/whoami", handleWhoami)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/quit", handleQuit) // 免登录: 登录页底部与授权管理页"服务管理"卡各有一个停止入口
	// 用户管理(RBAC): 除 /me 外全部 adminOnly —— 账号体系是"提权红线",
	// operator/auditor 都不能碰: 否则可自建 admin 账号自我提权。
	// 前端授权管理页(/license)对非 admin 隐藏 + 路由守卫, 这里是不依赖前端的兜底。
	mux.HandleFunc("/api/v2/users", requireAuth(adminOnly(handleUsersCollection)))
	mux.HandleFunc("/api/v2/users/me", requireAuth(handleUsersMe))
	// {name} 同路径承载 PUT(更新)与 DELETE(删除), 按方法分发
	mux.HandleFunc("/api/v2/users/{name}", requireAuth(adminOnly(handleUsersManage)))
	mux.HandleFunc("/api/scan", requireAuth(adminOrOperator(handleScan))) // 触发扫描=写操作
	mux.HandleFunc("/api/nuclei/reload", requireAuth(adminOrOperator(handleNucleiReload)))
	mux.HandleFunc("/api/rules/update/status", requireAuth(handleRulesUpdateStatus))
	mux.HandleFunc("/api/rules/update/start", requireAuth(adminOrOperator(handleRulesUpdateStart)))
	mux.HandleFunc("/api/rules/update/progress", requireAuth(handleRulesUpdateProgress))
	mux.HandleFunc("/api/rules/update/log", requireAuth(handleRulesUpdateLog))
	mux.HandleFunc("/api/rules/update/restore", requireAuth(adminOrOperator(handleRulesUpdateRestore)))
	mux.HandleFunc("/api/vuln/rules", requireAuth(handleVulnRules))
	mux.HandleFunc("/api/vuln/builtin", requireAuth(handleVulnBuiltin))
	mux.HandleFunc("/api/vuln/import", requireAuth(adminOrOperator(handleVulnImport)))
	// 规则"待验证 -> 已验证": 导入规则默认已验证(导入即生效); 仅显式声明 status=pending
	// 的暂存规则需靶机测试通过后由用户确认, 标记后立即生效。属写操作, adminOnly。
	mux.HandleFunc("/api/vuln/rules/verify", requireAuth(adminOrOperator(handleVulnRulesVerify)))
	mux.HandleFunc("/api/vuln/control/status", requireAuth(handleCtlStatus))
	// NVD 漏洞规则一键同步(后台拉取, 前端轮询进度)
	mux.HandleFunc("/api/vuln/rules/sync", requireAuth(adminOrOperator(handleRulesSyncStart)))
	mux.HandleFunc("/api/vuln/rules/sync/progress", requireAuth(handleRulesSyncProgress))
	// 弱口令 / 空口令检测(weakpass 包): 默认关闭, 白名单 + 限速 + 审计, 不支持的协议明确报错。
	// start/stop 是主动攻击动作, 只读角色一律禁止(adminOnly)。
	mux.HandleFunc("/api/authcheck/status", requireAuth(handleAuthCheckStatus))
	mux.HandleFunc("/api/authcheck/start", requireAuth(adminOrOperator(handleAuthCheckStart)))
	mux.HandleFunc("/api/authcheck/stop", requireAuth(adminOrOperator(handleAuthCheckStop)))
	mux.HandleFunc("/api/vuln/whitelist", requireAuth(handleWhitelistList))
	mux.HandleFunc("/api/vuln/whitelist/add", requireAuth(adminOrOperator(handleWhitelistAdd)))
	mux.HandleFunc("/api/vuln/whitelist/remove", requireAuth(adminOrOperator(handleWhitelistRemove)))
	mux.HandleFunc("/api/vuln/fps", requireAuth(handleFPSList))
	mux.HandleFunc("/api/vuln/fps/mark", requireAuth(adminOrOperator(handleFPSMark)))
	mux.HandleFunc("/api/vuln/fps/remove", requireAuth(adminOrOperator(handleFPSRemove)))
	// 阶段 5 渗透工作台: 全部 adminOnly(与扫描模块物理隔离的攻击性能力,
	// operator/auditor 无入口无权限); 执行需逐次 ack 授权确认,
	// penta.* 审计落独立表 penta_audit(与通用审计分离; 仅管理员可清空,
	// 清空动作本身写 penta.audit.clear 痕迹)
	mux.HandleFunc("/api/v2/penta/status", requireAuth(adminOnly(hPentaStatus)))
	mux.HandleFunc("/api/v2/penta/tasks", requireAuth(adminOnly(hPentaTasks)))
	mux.HandleFunc("/api/v2/penta/tasks/import", requireAuth(adminOnly(hPentaImport)))
	mux.HandleFunc("/api/v2/penta/tasks/batch", requireAuth(adminOnly(hPentaBatch)))
	mux.HandleFunc("/api/v2/penta/tasks/export", requireAuth(adminOnly(hPentaExport)))
	mux.HandleFunc("/api/v2/penta/tasks/{id}", requireAuth(adminOnly(hPentaTaskManage)))
	mux.HandleFunc("/api/v2/penta/tasks/{id}/run", requireAuth(adminOnly(hPentaRun)))
	mux.HandleFunc("/api/v2/penta/tasks/{id}/result", requireAuth(adminOnly(hPentaResult)))
	mux.HandleFunc("/api/v2/penta/templates", requireAuth(adminOnly(hPentaTemplates)))
	mux.HandleFunc("/api/v2/penta/templates/import", requireAuth(adminOnly(hPentaTplImport)))
	mux.HandleFunc("/api/v2/penta/tasks/{id}/feedback", requireAuth(adminOnly(hPentaFeedback)))
	mux.HandleFunc("/api/v2/penta/audit", requireAuth(adminOnly(hPentaAuditList))) // 渗透审计(独立表)
	mux.HandleFunc("DELETE /api/v2/penta/audit", requireAuth(adminOnly(hPentaAuditClear))) // 清空(admin 专用, 留痕)
	mux.HandleFunc("/api/info", requireAuth(handleInfo))
	mux.HandleFunc("/api/report", requireAuth(handleReport))
	mux.HandleFunc("/api/capture/devices", requireAuth(handleCaptureDevices))
	mux.HandleFunc("/api/capture/install", requireAuth(adminOrOperator(handleCaptureInstall))) // 装 Npcap 驱动=写操作
	mux.HandleFunc("/api/capture/start", requireAuth(handleCaptureStart))
	mux.HandleFunc("/api/capture/stop", requireAuth(handleCaptureStop))
	mux.HandleFunc("/api/capture/state", requireAuth(handleCaptureState))
	mux.HandleFunc("/api/capture/analysis", requireAuth(handleCaptureAnalysis))
	// 报文列表(全量采集 + 页面过滤): 抓包默认只做粗筛, 细过滤在展示层做
	mux.HandleFunc("/api/capture/packets", requireAuth(handleCapturePackets))
	mux.HandleFunc("/api/capture/export", requireAuth(handleCaptureExport)) // PCAP 导出
	// 阶段 3: AI 全链路分析模块(配置/模板/RAG 文档库/结构化记忆库/分析触发)
	RegisterAIRoutes(mux)
	// 任务 4.2: SSE 实时事件流(多客户端广播) + 环境检测(本地引擎/Npcap 驱动)
	mux.HandleFunc("/api/events", requireAuth(sse.Default().Handler()))
	mux.HandleFunc("/api/env", requireAuth(handleEnvStatus))
	mux.HandleFunc("/api/env/refresh", requireAuth(handleEnvRefresh))
	mux.HandleFunc("/api/env/install", requireAuth(adminOrOperator(handleEnvInstall))) // 装系统驱动=写操作
	// 任务 6.2: 引擎编排状态与降级统计(执行/解析失败自动降级为内置引擎)
	mux.HandleFunc("/api/engine/status", requireAuth(handleEngineStatus))
	mux.HandleFunc("/api/engine/refresh", requireAuth(handleEngineRefresh))
	// 引擎一键下载/安装(外部引擎 nmap/trivy/zap/nuclei 官方包自动获取):
	// 配置读 engine.json 的 downloads 段, 默认 allowDownload=false 只能查状态。
	mux.HandleFunc("/api/engine/downloads", requireAuth(handleEngineDownloadStatus))
	mux.HandleFunc("/api/engine/downloads/start", requireAuth(adminOrOperator(handleEngineDownloadStart)))
	mux.HandleFunc("/api/engine/downloads/progress", requireAuth(handleEngineDownloadProgress))
	mux.HandleFunc("/api/engine/downloads/uninstall", requireAuth(adminOrOperator(handleEngineDownloadUninstall)))
	mux.HandleFunc("/api/engine/downloads/cache/clear", requireAuth(adminOrOperator(handleEngineDownloadCacheClear)))
	// 规则库直连官方仓库更新通道(无需自建源; 配置读 updater.json 的 direct 段)
	mux.HandleFunc("/api/rules/update/direct/status", requireAuth(handleRulesDirectStatus))
	mux.HandleFunc("/api/rules/update/direct/start", requireAuth(adminOrOperator(handleRulesDirectStart)))
	// 任务 4.1: /api/v2/ REST API 组(统一响应格式 + 统一 DAO 数据访问层;
	// 独立中间件链: 全局异常捕获/CORS/请求日志; 数据存 exe 同目录 data/, 配置 config.json)
	mux.Handle("/api/v2/", buildV2Handler())
	// 任务 4.3: Vue3 前端(构建产物经 go:embed 嵌入, 单文件离线可加载), /app/ 子路径
	mux.HandleFunc("/app", handleVueApp)
	mux.HandleFunc("/app/", handleVueApp)
	// 任务 10d: 3D 地球 IP 流向 + globe 静态资源(走根 mux, 不在 /api/v2/ 子树下)
	registerDashboardRoutes(mux)

	localIP := scanner.LocalIP()
	// 默认绑定 0.0.0.0(全部网卡): 监听范围不再取决于启动瞬间探测到的那个 IP。
	// 【为什么不绑单个 IP】实测机器 DHCP 换租 / VPN 插拔导致地址变化后, 进程还活着、端口
	// 也还"在听", 但当初绑定的地址已不属于本机 → 浏览器与 curl 一律超时, 只能重启进程,
	// 表现为"网页突然全部打不开", 且日志停在最后一次请求上, 极易误判成服务卡死。
	// 0.0.0.0 覆盖所有网卡(含回环), 地址怎么变都连得上; localIP 仍只用于"告诉用户
	// 打开哪个地址"(控制台标题栏 / 自动打开的页面)。要收窄暴露面时用 -bind-local 回到旧行为。
	bindHost := "0.0.0.0"
	if *bindLocal {
		bindHost = localIP
	}
	tlsCfg := loadTLSConfig()
	scheme := "http"
	addr, p, err := "", 0, error(nil)
	if tlsCfg.Enabled {
		addr, p, err = startTLSServer(safeHandler(mux), *port, bindHost, tlsCfg)
		if err != nil {
			// 配置了 TLS 但证书缺失/损坏/不配对: 降级 HTTP 继续跑(规则 3),
			// 明文凭据风险记日志提醒修证书, 而不是让服务直接起不来。
			logLine("TLS 启动失败, 降级为 HTTP(凭据为明文传输): " + err.Error())
			addr, p, err = startServer(safeHandler(mux), *port, bindHost)
		} else {
			scheme = "https"
			logLine("TLS 已启用: 证书 " + tlsCfg.Cert + " (自签证书浏览器会提示不受信任, 点继续即可)")
			// HTTP 强制跳转(功能审计 1b): 旧书签/文档里的 http:// 地址访问时
			// 301 到 https 主服务, 而不是让浏览器报"连接错误"。
			if raddr, _, rerr := startHTTPRedirectServer(p, *port, bindHost); rerr == nil {
				logLine(fmt.Sprintf("HTTP %s 已启用 301 强制跳转至 HTTPS %s", raddr, addr))
			} else {
				logLine("HTTP 跳转服务启动失败(不影响 HTTPS 直接访问): " + rerr.Error())
			}
		}
	}
	if err == nil && addr == "" {
		addr, p, err = startServer(safeHandler(mux), *port, bindHost)
	}
	if err != nil {
		logLine("启动失败: " + err.Error())
		showMessage(appName+" v"+appVersion+" 启动失败", err.Error()+"\n\n详见 "+logDisplayPath())
		return
	}
	uiPort = p
	uiURL := scheme + "://" + localIP + ":" + strconv.Itoa(p)
	logLine(fmt.Sprintf("%s v%s 已启动, 本机地址: %s, UI 地址: %s (绑定 %s)", displayCnName, appVersion, localIP, uiURL, addr))
	// 系统启动事件入审计(用户诉求: "启动等等"也要在审计日志里) + 启动审计日志
	// 保存天数裁剪循环(启动清一次老数据, 之后每小时一次)。
	logAudit(v2DB(), nil, "system.startup", displayCnName, fmt.Sprintf("version=%s port=%d bind=%s", appVersion, p, addr))
	startAuditRetentionLoop()
	// 地址常显: 上面这行会在后续日志里被顶出可视区, 关掉网页后就找不回来了。
	// 把地址写进控制台标题栏(常驻不滚屏)并在 quitCh 建好后启动 O 键快捷打开。
	// 必须在 startServer 成功之后调: 端口顺延后的真实端口此刻才确定。
	SetUIURL(uiURL)
	setConsoleIcon() // 任务栏显示 yugsight 图标(conhost 默认是终端图标)
	if !*noBrowser {
		openBrowser(uiURL)
	}
	// 控制台窗口只显示日志, 启动即最小化: 双击部署的用户习惯"等页面弹出就关黑窗口",
	// 若关窗即停服务, 页面会莫名空白(实测高频发生)。关窗=服务留后台;
	// 停服务走网页"停止服务"(免登录, 入口在登录页底部链接与授权管理页"服务管理"卡片 ——
	// 2026-09-21 从顶栏移入该页降低误触)或恢复窗口后 Ctrl+C。
	logLine("提示: 关闭此窗口不停止服务(后台继续); 停止服务用网页\"停止服务\"或恢复窗口后 Ctrl+C")
	minimizeConsoleWindow()
	quitCh := make(chan struct{}, 1)
	installConsoleQuitHandler(quitCh)
	// 控制台常显提示(标题栏地址 + O 键打开页面)。放在 installConsoleQuitHandler 之后:
	// 键盘监听 goroutine 需要一个能感知退出的通道, 否则退出时它会一直阻塞在 stdin 读上。
	startConsoleHint(quitCh)
	<-quitCh
	logLine("控制台已关闭, " + displayCnName + " 已停止")
	engine.Default().CancelAll() // 主进程退出前终止运行中的外部引擎子进程树, 防残留占端口
	stopCaptureProc()            // 主进程退出前结束抓包子进程, 避免孤儿进程继续占着 wpcap.dll
	stopProbe()                  // 主进程退出前关闭探针中心端监听与探针端连接(未启用时为空操作)
	stopScheduler()              // 主进程退出前停止调度循环(未启用时为空操作)
	stopMonitor()                // 主进程退出前停止 SNMP 监控采集循环(未启用时为空操作)
	stopCollect()                // 主进程退出前停止节点采集引擎(未启用时为空操作)
	StopSettingsWatcher()        // 退出前停止配置文件监听
}

// safeHandler 兜底捕获任意接口处理器的 panic, 避免单个接口异常导致整个进程退出
func safeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				logLine(fmt.Sprintf("接口处理 panic(%s %s): %v", r.Method, r.URL.Path, p))
				http.Error(w, "内部错误: "+fmt.Sprint(p), http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

// handleInfo 返回本机真实 IP / 全部 IP / 主机名 / 当前端口, 供 UI 填充默认值
func handleInfo(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	ip := scanner.LocalIP()
	list := []string{ip}
	for _, x := range scanner.LocalIPs() {
		if x != ip {
			list = append(list, x)
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":                 appName,
		"version":              appVersion,
		"localIP":              ip,
		"ipList":               list,
		"hostname":             hostname,
		"port":                 uiPort,
		"vulnRules":            scanner.VulnRuleCount(),        // 内置规则(vuln_builtin.json)
		"cpeProducts":          scanner.CPEProductCount(),      // 主机漏洞 CPE 库产品数(内置 + cpe/ 外部热更新)
		"cpeCves":              scanner.CPEVulnCount(),         // 主机漏洞 CPE 库 CVE 条数
		"nucleiEnabled":        nucleiOn,                       // Nuclei 模板扫描全局开关
		"nucleiTemplates":      scanner.TemplateCount(),        // 外部模板缓存数量(exe 同目录 templates/)
		"nucleiTemplatesBuilt": scanner.BuiltinTemplateCount(), // 内置模板数量(打包进 exe)
		"aiEnabled":            aiAn.Enabled(),                 // AI 后置分析总开关
		"engineEnabled":        engineEnabled(),                // 任务 6.2: 外部引擎解析/降级编排开关
		"engineStatus":         engineSnapshot(),               // 引擎编排统计(来源/降级次数)
		"probeEnabled":         probeEnabled(),                 // 任务 6.3: 探针框架是否启用(中心端或探针端)
		"probeRole":            probeRole(),                    // center / probe / center+probe / ""
		"probeOnline":          probeOnlineCount(),             // 中心端在线探针数(未启用为 0)
	})
}

// ===== 漏扫报告 =====

type reportFinding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	// Fix 内置修复建议(可空): 报告要能直接回答"怎么处理"
	Fix string `json:"fix,omitempty"`
	// Source 规则来源: "nuclei" = 外部 Nuclei 模板; 空 = 内置规则(vuln_builtin.json)
	Source string `json:"source,omitempty"`
}

type reportScanIn struct {
	Type      string          `json:"type"`
	Target    string          `json:"target"`
	TypeName  string          `json:"typeName"`
	StartTime string          `json:"startTime"`
	Duration  string          `json:"duration"`
	Summary   string          `json:"summary"`
	RowHead   []string        `json:"rowHead"`
	Rows      [][]string      `json:"rows"`
	Findings  []reportFinding `json:"findings"`
}

// loadReportTemplate 优先使用 exe 同目录 report_template.html(用户自定义), 否则用内置模板。
// 每次请求重新读取, 修改模板无需重启程序
func loadReportTemplate() (*template.Template, error) {
	if exe, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "report_template.html")); err == nil {
			return template.New("report").Funcs(tplFuncs).Parse(string(data))
		}
	}
	data, err := uiFS.ReadFile("web/report.html")
	if err != nil {
		return nil, err
	}
	return template.New("report").Funcs(tplFuncs).Parse(string(data))
}

var tplFuncs = template.FuncMap{
	"add": func(a, b int) int { return a + b },
}

// handleReport 渲染漏扫报告(HTML 文件下载)
func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Title    string         `json:"title"`
		Operator string         `json:"operator"`
		Scans    []reportScanIn `json:"scans"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		failJSON(w, "请求格式错误: "+err.Error())
		return
	}
	if len(req.Scans) == 0 {
		failJSON(w, "没有扫描数据")
		return
	}
	if req.Title == "" {
		req.Title = "Yugsight 漏洞扫描报告"
	}

	sev := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
	total := 0
	for _, s := range req.Scans {
		for _, f := range s.Findings {
			sev[f.Severity]++
			total++
		}
	}
	level := "无"
	if sev["high"] > 0 {
		level = "高"
	} else if sev["medium"] > 0 {
		level = "中"
	} else if sev["low"] > 0 {
		level = "低"
	}

	// 转为 map 结构, 模板中使用小写字段名更友好
	scansOut := make([]map[string]any, 0, len(req.Scans))
	for _, s := range req.Scans {
		findingsOut := make([]map[string]any, 0, len(s.Findings))
		for _, f := range s.Findings {
			// 键名首字母大写: 与 report.html 模板中的 .Severity/.Title/.Fix 对应。
			// 曾用小写键 + 模板大写访问, 模板取不到值 → 报告里"安全发现"表格一直空着。
			findingsOut = append(findingsOut, map[string]any{
				"Severity": f.Severity,
				"Title":    f.Title,
				"Detail":   f.Detail,
				"Fix":      f.Fix,
				"Source":   f.Source,
			})
		}
		scansOut = append(scansOut, map[string]any{
			"type":      s.Type,
			"target":    s.Target,
			"typeName":  s.TypeName,
			"startTime": s.StartTime,
			"duration":  s.Duration,
			"summary":   s.Summary,
			"rowHead":   s.RowHead,
			"rows":      s.Rows,
			"findings":  findingsOut,
		})
	}

	data := map[string]any{
		"Title":         req.Title,
		"Operator":      req.Operator,
		"Tool":          appName + " v" + appVersion,
		"Time":          time.Now().Format("2006-01-02 15:04:05"),
		"Scans":         scansOut,
		"TotalFindings": total,
		"High":          sev["high"],
		"Medium":        sev["medium"],
		"Low":           sev["low"],
		"Info":          sev["info"],
		"RiskLevel":     level,
	}

	tmpl, err := loadReportTemplate()
	if err != nil {
		failJSON(w, "报告模板加载失败: "+err.Error())
		return
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		failJSON(w, "报告渲染失败: "+err.Error())
		return
	}

	fname := "yugsight_report_" + time.Now().Format("20060102_150405") + ".html"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	w.Write(buf.Bytes())
}

// handleQuit 从 Web 界面停止整个服务(POST /api/quit, 免登录;
// 入口是登录页底部链接与授权管理页"服务管理"卡片)
func handleQuit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	logLine("用户从 Web 界面退出, " + displayCnName + " 已停止")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write([]byte(`{"ok":true}`))
	time.Sleep(200 * time.Millisecond) // 等响应发出
	engine.Default().CancelAll()       // 退出前终止运行中的外部引擎子进程树
	stopCaptureProc()                  // 退出前结束抓包子进程
	stopProbe()                        // 退出前关闭探针中心端/探针端连接
	stopScheduler()                    // 退出前停止调度循环(运行中任务置暂停以支持续扫)
	stopMonitor()                      // 退出前停止 SNMP 监控采集循环
	stopCollect()                      // 退出前停止节点采集引擎
		StopSettingsWatcher()              // 退出前停止配置文件监听
	os.Exit(0)
}

func failJSON(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// startServer 依次尝试 startPort 起的 20 个端口, 避免端口冲突导致静默退出
func startServer(mux http.Handler, startPort int, host string) (string, int, error) {
	for i := 0; i < 20; i++ {
		p := startPort + i
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		go func() {
			if err := http.Serve(ln, mux); err != nil {
				logLine("HTTP 服务异常: " + err.Error())
			}
		}()
		return addr, p, nil
	}
	return "", 0, fmt.Errorf("端口 %d-%d 均被占用, 请关闭占用程序后重试", startPort, startPort+19)
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	// 支持 "/" (主页) 与 "/classic/" (经典页固定入口)
	path := r.URL.Path
	isClassic := false
	if path == "/classic" || path == "/classic/" {
		isClassic = true
	} else if path != "/" {
		http.NotFound(w, r)
		return
	}
	// /classic/ 固定出经典页; "/" 按 uiMode 决定
	useVue := !isClassic && uiMode == "vue"
	if useVue {
		data, err := vueFS.ReadFile("frontend/dist/index.html")
		if err != nil {
			// dist 未构建时降级到经典页, 不报错
			logLine("Vue3 前端资源缺失, 主页降级为经典页: " + err.Error())
			data, err = uiFS.ReadFile("web/index.html")
			if err != nil {
				http.Error(w, "UI not found", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(data)
		return
	}
	data, err := uiFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "UI not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// testModeEnabled 检查 exe 同目录是否存在 test_mode.txt, 存在则跳过注册/登录/设备绑定(测试期免验证)
func testModeEnabled() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(filepath.Dir(exe), "test_mode.txt"))
	return err == nil
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// explorer.exe 是最可靠的 Windows 打开 URL 方式(系统级, 不依赖浏览器关联)。
		// rundll32 url.dll 在某些配置下静默失败(无报错), explorer 不会。
		cmd = exec.Command("explorer.exe", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	if err := cmd.Start(); err != nil {
		logLine("打开浏览器失败: " + err.Error())
	}
}

func joinInts(list []int) string {
	parts := make([]string, len(list))
	for i, p := range list {
		parts[i] = fmt.Sprint(p)
	}
	return strings.Join(parts, ",")
}

// scanTarget 扫描目标的审计口径: web 记 URL, 其余记 CIDR/IP(哪个有记哪个)。
func scanTarget(req scanReq) string {
	if req.Type == "web" {
		return strings.TrimSpace(req.URL)
	}
	if c := strings.TrimSpace(req.CIDR); c != "" {
		return c
	}
	return strings.TrimSpace(req.IP)
}

type scanReq struct {
	Type        string `json:"type"` // ip | port | web | host
	IP          string `json:"ip"`
	CIDR        string `json:"cidr"`
	Ports       string `json:"ports"`
	URL         string `json:"url"`
	TimeoutMs   int    `json:"timeoutMs"`
	Concurrency int    `json:"concurrency"`
	// Nuclei 外部模板扫描(仅 host 类型有效, 需全局开关 -nuclei 同时开启):
	// enableNuclei 为任务级开关; nucleiTags/nucleiTagsExclude 为 tag 黑白名单
	// (逗号分隔, 可含 severity 名称, 如 "cisa-kev,critical,high")
	EnableNuclei      bool   `json:"enableNuclei"`
	NucleiTags        string `json:"nucleiTags"`
	NucleiTagsExclude string `json:"nucleiTagsExclude"`
	// 任务 6.3: 执行位置。ExecAt="probe" 时下发到 ProbeNode 指定探针执行(需中心端启用),
	// 空值/"local" 保持原有本地执行语义, 零行为变化。
	ExecAt    string `json:"execAt"`
	ProbeNode string `json:"probeNode"`
	// 任务 6.4: 探针端抓包骨架开关(仅 ExecAt="probe" 时有效)。
	// 默认 false —— 抓包要落盘且可能很大, 必须显式开启(项目规则 5)。
	// 探针端无 Npcap 时降级为"只记录交互摘要", 不阻断扫描。
	Capture         bool   `json:"capture"`
	CaptureDevice   string `json:"captureDevice"`
	CaptureFilter   string `json:"captureFilter"`
	CaptureMaxBytes int64  `json:"captureMaxBytes"`
	EnableArp       *bool  `json:"enableArp"`      // 探针端 ARP 探测开关(nil=默认开)
	EnableExternal  *bool  `json:"enableExternal"` // 探针端外部引擎开关(nil=默认开)
	// 探针端 SYN 半开扫描(仅 port/host 类型, 默认 false): 探针端需 Windows+管理员
	// 或 Linux root/CAP_NET_RAW, 不满足时探针自动降级全连接(项目规则 5)。
	// 用 bool 而非 *bool: 探针端默认即关闭, "不传 = 关" 已表达默认语义, 无需三态。
	EnableSynScan bool `json:"enableSynScan"`

	// 任务 c8: 漏洞库规则选择(仅 web 类型有效)。RuleMode=="selected" 时只启用
	// SelectedRules 列出的规则(空列表 = 不启用任何漏洞库规则); 其余取值(空/"all")
	// 启用全部规则, 与旧行为一致 —— 非 Web 扫描与脚本/API 直接调用零影响(向后兼容)。
	RuleMode      string   `json:"ruleMode"`
	SelectedRules []string `json:"selectedRules"`

	// 存活判定模式(仅 ip/alive 类型有效): "strict" 只认 ICMP/ARP 应答,
	// 端口开放不算存活; 空值/"loose" 为默认宽松口径(端口开放也算, 避免
	// "只开 445 的在线主机被报成不存活"导致整段网段看起来全灭)。
	AliveMode string `json:"aliveMode"`

	// 任务 7.1: 是否走任务队列调度。默认 false —— 保持 /api/scan 原有"立即执行
	// 并流式返回"的语义不变(前端与外部脚本依赖该行为); 传 true 且调度器已启用
	// (调度器默认启用, 可在 settings.json 的 scheduler 节显式关闭)时任务改为
	// 入队, 由调度器按并发/限速/节点派发。
	Queue bool `json:"queue"`

	// 外部引擎编排(默认 false): 为 true 且 engine 总开关 enabled=true 时,
	// host/port/web 交给 engine/parsers 编排器执行, 失败自动回落内置流程。
	// 默认关闭 → 零行为变化(见 scan_engine.go)。
	UseEngine bool `json:"useEngine"`
	// 调度参数(仅 queue=true 时有效): 策略模板 / 执行节点 / 优先级 / 自动重试。
	Strategy  string `json:"strategy"`
	QueueNode string `json:"queueNode"`
	Priority  int    `json:"priority"`
	AutoRetry *bool  `json:"autoRetry"`

	// Web 深度扫描(仅 web 类型有效, 默认 false): 开启后在既有单 URL 扫描之外
	// 追加"同源爬虫 + POST 表单 + SQLi 三类(union/布尔/时间盲注) + XSS 多位置"
	// 探测(scanner.WebScanDeep)。默认关闭 —— 爬取会发起数十倍于单 URL 的请求,
	// 时间盲注还要等服务端延时, 必须显式开启(项目规则 5)。
	WebDeep bool `json:"webdeep"`
}

const defaultHostPorts = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017"

// defaultAliveProbePorts 存活探测未指定端口时的默认探测集。
//
// 【为什么按目标形态分两套】"存活扫描"与"端口扫描"在端口上的诉求正相反:
//
//   - 端口扫描: 端口就是结果本身, 用户会明确指定;
//   - 存活扫描: 端口只是"判断主机在不在"的手段, 多探一个端口就多一份全网段的耗时
//     (n 个主机 × m 个端口 × 超时)。所以网段场景要克制, 单机场景可以放宽。
//
// 网段里挑的是"最可能开着且最安静"的一组: 445/139(Windows 一定开)、22/23(Telnet/
// SSH 设备)、80/443(Web/路由器/摄像头)、3389(远程桌面)、8080/8000(管理口)。
// 这些端口在真实内网里命中率最高, 且对端不做多余交互(不做 banner 抓取)。
func defaultAliveProbePorts(req scanReq, hosts []string) []int {
	// 显式给了 IP 字段(单机语义)或解析后只有一个目标 -> 用较全的常用端口集
	single := len(hosts) == 1 || strings.TrimSpace(req.IP) != ""
	if single {
		if ps, err := scanner.ParsePorts(defaultHostPorts); err == nil {
			return ps
		}
	}
	return []int{445, 139, 22, 23, 80, 443, 3389, 8080, 8000}
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req scanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
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
		// 任务 4.2: 同时广播到 SSE 事件流, 所有订阅客户端(多标签/多窗口)实时收到
		// 扫描日志(status)/资产发现(ip/port)/漏洞结果(finding)等事件
		_ = sse.Default().Publish(event, b)
	}

	// 扫描操作入审计(用户诉求: "操作"要在审计日志里; 扫描是最高频的核心操作)。
	// 三种去向(探针/排队/本地)统一在入口记, 去向写进 detail。
	logAudit(v2DB(), r, "scan.start", scanTarget(req),
		fmt.Sprintf("type=%s queue=%v execAt=%s", req.Type, req.Queue, req.ExecAt))

	// 任务 6.3: 执行位置路由 —— 指定探针执行时把任务下发给探针, 本地不再执行。
	// 判定条件严格: 仅当 execAt=probe 且 probeNode 非空才走远端;
	// 任一条件不满足(含中心端未启用)一律保持原有本地扫描流程, 零行为变化。
	if req.ExecAt == "probe" && req.ProbeNode != "" {
		dispatchToProbe(req, emit)
		return
	}

	// 任务 7.1: 调度接管 —— 调度器启用且请求未指定"立即执行"时, 任务改为入队,
	// 由调度器按并发/节点/限速条件派发(scheduler_api.go 的 schedExec 回调会
	// 再次调用本函数体执行真正的扫描)。
	//
	// 判定用 Status(入队) 而非"一律入队"的原因: 既有前端与脚本调用 /api/scan
	// 期待的是 SSE 流式结果(边扫边看), 强行改成"先入队再等"会让它们拿到空的
	// 事件流。故保留原语义为默认, 需要排队时显式传 queue=true。
	if req.Queue && schedulerEnabled() {
		enqueueScanRequest(req, emit)
		return
	}

	runScanPipeline(r.Context(), req, emit)
}

// runScanPipeline 执行一次本地扫描(HTTP 与调度器共用)。
//
// 抽出来的原因: 任务 7.1 的调度器需要在同一条扫描能力上获得"可取消 + 可回传
// 摘要"的形态, 而 handleScan 原本是"HTTP handler + SSE 直写"。把扫描主体外提
// 即可让两条路径共用一份实现, 避免"调度器里另写一套扫描逻辑"导致的长期漂移。
//
// 契约: emit 由调用方提供(HTTP 直写 SSE / 调度器转全局广播); 函数同步阻塞到
// 扫描结束; ctx 取消时扫描器内部的 emit 循环会尽快退出。
func runScanPipeline(ctx context.Context, req scanReq, emit func(string, any)) {
	// 扫描结束入审计(与 handleScan 的 scan.start 配对): 耗时 + 是否被取消。
	// 无 HTTP 上下文(调度器派发路径) r=nil, 来源 IP 留空。
	scanStartAt := time.Now()
	defer func() {
		extra := ""
		if ctx.Err() != nil {
			extra = " 已取消"
		}
		logAudit(v2DB(), nil, "scan.finish", scanTarget(req),
			fmt.Sprintf("type=%s elapsed=%s%s", req.Type, time.Since(scanStartAt).Round(time.Second), extra))
	}()

	// AI 后置分析(可选): 开启时顺带收集 finding 事件, 任务结束后做批量风险汇总。
	var aiVulnMu sync.Mutex
	var aiVulns []scanner.Vuln
	// 扫描管控(scanctl 模块): finding 事件逐条判定 ——
	// 白名单命中 -> 吞掉(不进报告与统计); 误报规则命中 -> 附加
	// falsePositive/fpNote 字段透传(前端展示标记, 导出报告时排除)。
	// 无条目时零行为, 不影响原有扫描流程。
	ctl := scanctl.Instance()
	targetIP, targetPort := "", 0
	switch req.Type {
	case "host":
		targetIP = strings.TrimSpace(req.IP)
	case "web":
		if u, uerr := url.Parse(strings.TrimSpace(req.URL)); uerr == nil {
			targetIP = u.Hostname()
			targetPort = 80
			if u.Scheme == "https" {
				targetPort = 443
			}
			if _, p, perr := net.SplitHostPort(u.Host); perr == nil {
				if n, aerr := strconv.Atoi(p); aerr == nil {
					targetPort = n
				}
			}
		}
	}
	// 落库收集器(scan_persist.go): 扫描结束后把 finding 与资产归一化写入 v2 库,
	// 单机模式下报告/大屏/资产/漏洞页才有数据来源。收尾 flush, 失败只记日志。
	sink := newScanSink(req, targetIP, targetPort)
	emitAI := func(event string, data any) {
		if event == "finding" && ctl != nil && targetIP != "" {
			title, cve, port := findingKeyInfo(data)
			if port == 0 {
				port = targetPort
			}
			if wlHit, wlEntry, fpsRule := ctl.CheckFinding(targetIP, port, cve, title); wlHit {
				logLine(fmt.Sprintf("白名单命中, 自动过滤: %s (类型 %s / %s)", title, wlEntry.Type, wlEntry.Match))
				emit("status", map[string]any{"msg": "白名单命中, 已自动过滤: " + title})
				return
			} else if fpsRule.ID != "" {
				logLine(fmt.Sprintf("误报规则命中, 自动标记: %s (备注: %s)", title, fpsRule.Note))
				data = withFPFlag(data, fpsRule.Note)
			}
		}
		emit(event, data)
		sink.observe(event, data) // 过完白名单/误报后才收集(白名单命中已在上方 return)
		if event == "finding" {
			if b, err := json.Marshal(data); err == nil {
				var v scanner.Vuln
				if json.Unmarshal(b, &v) == nil && v.Title != "" {
					aiVulnMu.Lock()
					aiVulns = append(aiVulns, v)
					aiVulnMu.Unlock()
				}
			}
		}
	}
	var hostAssets []scanner.ServiceAsset // host 扫描的服务指纹, 供 AI 批量汇总

	timeout := 1500 * time.Millisecond
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	if timeout < 300*time.Millisecond {
		timeout = 300 * time.Millisecond
	}
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	conc := req.Concurrency
	if conc <= 0 {
		conc = 200
	}
	if conc > 1000 {
		conc = 1000
	}

	fail := func(msg string) {
		emit("status", map[string]any{"msg": "错误: " + msg})
		emit("done", map[string]any{"msg": "扫描终止"})
	}

	// 引擎编排(scan_engine.go, 默认关闭): useEngine 且 engine.enabled 同时为真时
	// host/port/web 走外部引擎; 降级时返回 false, 继续走下方内置流程。
	if req.UseEngine && engineEnabled() && engineScanType(req.Type) {
		if runEngineScan(ctx, req, sink, emitAI) {
			sink.flush()
			// 报告中心二期: 原始报告自动存档(best-effort 异步, 不拖慢 SSE 收尾)
			if rr := buildRawScanReport(req, sink, scanStartAt); rr != nil {
				autoSaveRawReport(v2DB(), rr)
			}
			emit("done", map[string]any{"msg": "全部完成"})
			return
		}
	}

	switch req.Type {
	case "ip", "alive":
		// "alive" 是 "ip" 的别名(与探针下发口径一致): 两者都支持网段与单 IP,
		// 区别只在探测范围的默认值, 见下方补默认端口的判定
		hosts, err := scanner.ParseHosts(req.CIDR)
		if err != nil {
			fail(err.Error())
			return
		}
		probe, perr := scanner.ParsePorts(req.Ports)
		inferredPorts := false // 端口由"目标形态"推断而非用户显式指定
		if perr != nil {
			// 用户没填端口时, 按目标形态给一份更贴合的默认端口集:
			// 单 IP 用主机的暴露面集合(445/3389 等), 网段给截断到 /24 常见端口 —— 用
			// "存活探测"的场景通常是"找在线主机", 探测端口只用于兜底, 不宜太宽导致大网段耗时爆炸
			probe = defaultAliveProbePorts(req, hosts)
			inferredPorts = true
		}
		strict := strings.EqualFold(strings.TrimSpace(req.AliveMode), "strict")
		mode := "宽松(ICMP/ARP 应答或端口开放)"
		if strict {
			mode = "严格(仅 ICMP/ARP 应答)"
		}
		msg := fmt.Sprintf("开始探测 %d 个目标, 端口: %s, 判定: %s", len(hosts), joinInts(probe), mode)
		if inferredPorts {
			msg += "(默认端口)"
		}
		emit("status", map[string]any{"msg": msg})
		alive, excluded := scanner.ScanIPsWithDetail(ctx, hosts, probe, conc, timeout, strict, emit)
		summary := fmt.Sprintf("扫描结束: 存活 %d / %d", alive, len(hosts))
		if excluded > 0 {
			summary += fmt.Sprintf(" (另有 %d 台仅探测端口开放, 按严格判定未计入)", excluded)
		}
		emit("status", map[string]any{"msg": summary})
	case "unified":
		// 统一扫描(c7): 一次探测同时输出存活状态 + 开放端口(含服务/banner), 消除
		// "存活扫一遍、端口再扫一遍"的重复发包。判定口径由 aliveMode 决定:
		// strict(仅 ICMP/ARP) / loose(默认, ICMP/ARP 或端口开放) / none(跳过存活, 纯端口扫描)。
		hosts, err := scanner.ParseHosts(req.CIDR)
		if err != nil {
			fail(err.Error())
			return
		}
		probe, perr := scanner.ParsePorts(req.Ports)
		inferredPorts := false
		if perr != nil {
			probe = defaultAliveProbePorts(req, hosts)
			inferredPorts = true
		}
		mode := scanner.ParseAliveMode(req.AliveMode) // 空值 -> loose(与旧默认一致)
		modeName := map[scanner.AliveMode]string{
			scanner.AliveModeStrict: "严格(仅 ICMP/ARP 应答)",
			scanner.AliveModeLoose:  "宽松(ICMP/ARP 或端口开放)",
			scanner.AliveModeNone:   "跳过存活, 纯端口扫描",
		}[mode]
		msg := fmt.Sprintf("统一扫描 %d 个目标, 端口: %s, 判定: %s", len(hosts), joinInts(probe), modeName)
		if inferredPorts {
			msg += "(默认端口)"
		}
		emit("status", map[string]any{"msg": msg})
		alive, excluded, openPorts, elapsed := scanner.UnifiedScan(ctx, hosts, probe, mode, conc, timeout, emit)
		var summary string
		if mode == scanner.AliveModeNone {
			summary = fmt.Sprintf("统一扫描结束: 开放端口 %d 个, 耗时 %s", openPorts, elapsed)
		} else {
			summary = fmt.Sprintf("统一扫描结束: 存活 %d / %d, 开放端口 %d 个, 耗时 %s", alive, len(hosts), openPorts, elapsed)
			if excluded > 0 {
				summary += fmt.Sprintf(" (另有 %d 台仅端口开放, 严格判定未计入)", excluded)
			}
		}
		emit("status", map[string]any{"msg": summary})
	case "port":
		ip := strings.TrimSpace(req.IP)
		if net.ParseIP(ip) == nil {
			fail("目标 IP 无效: " + req.IP)
			return
		}
		ports, err := scanner.ParsePorts(req.Ports)
		if err != nil {
			fail(err.Error())
			return
		}
		emit("status", map[string]any{"msg": fmt.Sprintf("开始扫描 %s 的 %d 个端口", ip, len(ports))})
		results := scanner.ScanPorts(ctx, ip, ports, timeout, conc, emit)
		open := 0
		for _, r := range results {
			if r.State == "open" {
				open++
			}
		}
		sink.addPortResults(ip, results)
		emit("status", map[string]any{"msg": fmt.Sprintf("扫描结束: 开放 %d / %d 个端口", open, len(ports))})
	case "web":
		// c8: 漏洞库规则选择 —— RuleMode=="selected" 时只启用前端勾选的规则(scope=web
		// 子集, 见 /api/vuln/rules); 否则启用全部(与旧行为一致)。ruleFilter 传 nil = 全启用,
		// 空集 = 不启用任何漏洞库规则(其它基线探测不受影响)。
		var ruleFilter map[string]bool
		if req.RuleMode == "selected" {
			ruleFilter = make(map[string]bool, len(req.SelectedRules))
			for _, id := range req.SelectedRules {
				if id = strings.TrimSpace(id); id != "" {
					ruleFilter[id] = true
				}
			}
		}
		scanner.WebScan(req.URL, emitAI, ruleFilter)
		// 深度扫描(开关 webdeep, 默认关): 关闭时上面一行就是全部行为, 零变化
		if req.WebDeep {
			scanner.WebScanDeep(req.URL, emitAI, ruleFilter)
		}
		// Web 扫描不返回资产指纹, 从 URL 补一个(供 AI 批量汇总)
		if u, err := url.Parse(strings.TrimSpace(req.URL)); err == nil && u.Host != "" {
			port := 80
			if u.Scheme == "https" {
				port = 443
			}
			if _, p, err := net.SplitHostPort(u.Host); err == nil {
				if n, aerr := strconv.Atoi(p); aerr == nil {
					port = n
				}
			}
			hostAssets = append(hostAssets, scanner.ServiceAsset{IP: u.Hostname(), Port: port, Scheme: u.Scheme, Product: "web"})
			sink.addServiceAssets(hostAssets)
		}
	case "host":
		ip := strings.TrimSpace(req.IP)
		if net.ParseIP(ip) == nil {
			fail("目标 IP 无效: " + req.IP)
			return
		}
		ports, err := scanner.ParsePorts(req.Ports)
		if err != nil {
			ports, _ = scanner.ParsePorts(defaultHostPorts)
		}
		assets := scanner.HostScan(ctx, ip, ports, timeout, conc, emitAI)
		hostAssets = assets
		sink.addServiceAssets(assets)
		// Nuclei 外部模板扫描(可选插件): 全局开关 + 任务开关同时开启,
		// 复用 HostScan 输出的服务资产(产品+版本指纹), 不重复探测端口
		if nucleiOn && req.EnableNuclei && len(assets) > 0 {
			runNucleiScan(assets, req, emitAI)
		}
	default:
		fail("未知扫描类型: " + req.Type)
		return
	}
	// AI 批量风险汇总(可选, host/web 类型): 复用扫描 SSE 推送 "ai" 事件(流式),
	// 失败只提示不阻断, 结果不改动任何漏洞判定
	if aiAn.Enabled() && (req.Type == "host" || req.Type == "web") &&
		(len(hostAssets) > 0 || len(aiVulns) > 0) {
		emit("status", map[string]any{"msg": "AI 批量风险汇总中(可能需要数十秒)..."})
		if _, err := aiAn.AnalyzeScanBatchStream(toPtrs(hostAssets), toPtrs(aiVulns), emit); err != nil {
			emit("status", map[string]any{"msg": "AI 汇总失败: " + err.Error()})
		}
	}
	sink.flush() // 扫描结果落 v2 库(失败只记日志, 不影响既有 SSE 流程)
	// 报告中心二期: 原始报告自动存档(best-effort 异步, 不拖慢 SSE 收尾)
	if rr := buildRawScanReport(req, sink, scanStartAt); rr != nil {
		autoSaveRawReport(v2DB(), rr)
	}
	emit("done", map[string]any{"msg": "全部完成"})
	// 报告引擎 autoGenerate 开关打开时, 扫描结束自动归档一份报告(异步, 默认关闭)
	scanTarget := req.IP
	if req.CIDR != "" {
		scanTarget = req.CIDR
	}
	if req.URL != "" {
		scanTarget = req.URL
	}
	maybeAutoGenerateReport(req.Type, scanTarget)
}

// toPtrs 值切片转指针切片(scanner AI 接口按指针接收)
func toPtrs[T any](vs []T) []*T {
	out := make([]*T, len(vs))
	for i := range vs {
		out[i] = &vs[i]
	}
	return out
}

var cveInTextRe = regexp.MustCompile(`CVE-\d{4}-\d+`)

// findingKeyInfo 从 finding 事件提取 (标题, CVE, 端口):
// 内置规则 Finding 无 CVE 字段, 从标题里提取(如 "[YUGSIGHT-0001] ... CVE-2021-44228 ...");
// NucleiFinding 自带 CVE/Host/Port。
func findingKeyInfo(data any) (title, cve string, port int) {
	switch f := data.(type) {
	case scanner.Finding:
		return f.Title, strings.ToUpper(cveInTextRe.FindString(f.Title)), 0
	case scanner.NucleiFinding:
		return f.Title, f.CVE, f.Port
	default:
		return "", "", 0
	}
}

// withFPFlag 给 finding 事件附加误报标记字段(保留原字段, 前端展示标记用)
func withFPFlag(data any, note string) any {
	b, err := json.Marshal(data)
	if err != nil {
		return data
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return data
	}
	m["falsePositive"] = true
	m["fpNote"] = note
	return m
}

// runNucleiScan Nuclei 模板扫描(与内置规则 vuln_builtin.json 独立):
// 模板集 = 内置(exe 打包) + 外部(预加载缓存/热更新, 不重复解析 yaml)
// -> tag 黑白名单 -> 指纹过滤 -> 并发执行。
// 每条命中经 emit("finding") 实时推送(SSE, 事件格式与内置规则统一,
// 带 source: "nuclei"=外部模板 / "nuclei-builtin"=内置模板)。
func runNucleiScan(assets []scanner.ServiceAsset, req scanReq, emit func(string, any)) {
	dir := nucleiDirPath
	if dir == "" {
		if exe, err := os.Executable(); err == nil {
			dir = filepath.Join(filepath.Dir(exe), "templates")
		} else {
			dir = "templates"
		}
	}
	allTpls, loadErrs := scanner.LoadAllTemplates(dir) // 内置 + 外部(命中缓存, 不重读 yaml)
	for _, e := range loadErrs {
		emit("status", map[string]any{"msg": "nuclei 模板警告: " + e})
	}
	if len(allTpls) == 0 {
		emit("status", map[string]any{"msg": "无可用 Nuclei 模板, 跳过模板扫描"})
		return
	}
	emit("status", map[string]any{"msg": fmt.Sprintf("Nuclei 模板就绪: 共 %d 个(内置 %d, 外部 %d)",
		len(allTpls), scanner.BuiltinTemplateCount(), scanner.TemplateCount())})
	// tag 黑白名单(前端可配置, 如 "cisa-kev,critical,high"; 条件词可为 tag 或 severity)
	tpls := scanner.FilterTemplatesByTags(allTpls, splitTags(req.NucleiTags), splitTags(req.NucleiTagsExclude))
	if len(tpls) == 0 {
		emit("status", map[string]any{"msg": "Nuclei 模板经 tag 过滤后无可用项, 跳过模板扫描"})
		return
	}

	runner := scanner.NewNucleiRunner(scanner.DefaultRunnerConfig())
	total := 0
	for _, a := range assets {
		if !scanner.IsWebPort(a.Port) {
			continue // 只对 Web 端口跑 HTTP 模板, 避免向 SSH 等非 Web 服务发请求
		}
		// 内部按 a.Product/a.Version 再过滤一次模板; 命中逐条实时 emit("finding")
		total += len(runner.RunNucleiTemplates(a, tpls, emit))
	}
	emit("status", map[string]any{"msg": fmt.Sprintf("Nuclei 模板扫描完成: 命中 %d 条", total)})
}

// handleNucleiReload 手动热更新外部模板目录(模板库更新后无需重启程序):
// 强制重新读盘解析并刷新缓存, 返回内置/外部模板数量与加载警告。
func handleNucleiReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !nucleiOn {
		failJSON(w, "Nuclei 模板扫描未启用(程序以 -no-nuclei 参数启动时关闭; 默认启动即启用)")
		return
	}
	dir := nucleiDirPath
	if dir == "" {
		if exe, err := os.Executable(); err == nil {
			dir = filepath.Join(filepath.Dir(exe), "templates")
		} else {
			dir = "templates"
		}
	}
	_, errs := scanner.RefreshTemplateCache(dir)
	all, _ := scanner.LoadAllTemplates(dir)
	logLine(fmt.Sprintf("手动热更新 Nuclei 模板: 共 %d (内置 %d, 外部 %d, 警告 %d)",
		len(all), scanner.BuiltinTemplateCount(), scanner.TemplateCount(), len(errs)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"dir":      dir,
		"builtin":  scanner.BuiltinTemplateCount(),
		"external": scanner.TemplateCount(),
		"total":    len(all),
		"errors":   errs,
	})
}

// ===== 漏洞库管理(查看/导入) =====

// handleVulnRules 列出当前已加载的全部规则(内置 + 外部, 带来源与适用范围),
// 供前端"漏洞库"界面按适用范围(Web / 主机)分组展示。
// scopes 为按适用范围的计数汇总, 前端统计卡直接取用, 不再自己遍历一遍。
func handleVulnRules(w http.ResponseWriter, r *http.Request) {
	rules := scanner.AllRules()
	scopes := map[string]int{scanner.ScopeWeb: 0, scanner.ScopeHost: 0}
	sevs := scanner.RuleSeverityStats()
	sources := map[string]int{}
	for _, rule := range rules {
		scopes[rule.EffectiveScope()]++
		sources[rule.Source]++
	}
	verified, pending := scanner.RuleStatusStats()
	jsonOK(w, map[string]any{
		"count":     scanner.VulnRuleCount(),
		"dir":       scanner.VulnerableDir(),
		"scopes":    scopes,
		"severities": sevs,
		"sources":    sources,
		"status":     map[string]int{"verified": verified, "pending": pending},
		"rules":      rules,
	})
}

// handleVulnRulesVerify 把指定 ID 的规则标记为"已验证"(靶机测试通过后的确认动作),
// 标记后规则立即参与扫描。幂等: 重复标记不产生副作用。
func handleVulnRulesVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs []string `json:"ids"`
		ID  string   `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		failJSON(w, "请求格式错误: "+err.Error())
		return
	}
	if req.ID != "" {
		req.IDs = append(req.IDs, req.ID)
	}
	if len(req.IDs) == 0 {
		failJSON(w, "未指定要验证的规则 ID")
		return
	}
	added, err := scanner.MarkRulesVerified(req.IDs)
	if err != nil {
		failJSON(w, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "marked": added})
}

// handleVulnBuiltin 返回内置规则(vuln_builtin.json)原始 JSON, 让用户能直接查看自带规则
func handleVulnBuiltin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write([]byte(scanner.BuiltinRulesJSON()))
}

// handleVulnImport 接收规则 JSON, 校验后写入 vuln/ 目录并热重载(无需重启)
func handleVulnImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		JSON     string `json:"json"`
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		failJSON(w, "请求格式错误: "+err.Error())
		return
	}
	n, warns, err := scanner.ImportVulnRules(req.JSON, req.Filename)
	if err != nil {
		failJSON(w, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "imported": n, "total": scanner.VulnRuleCount(), "warnings": warns})
}

// splitTags 逗号切分 tag 条件并去空白
func splitTags(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ===== AI 后置分析(可选插件, 只解读/汇总, 不参与漏洞判定) =====

// aiAn 全局 AI 分析器(initAI 构建; 禁用时 Analyze* 立即返回错误, 不占资源)
var aiAn *scanner.AIAnalyzer

// initAI 加载 ai.json(exe 同目录, 兼容旧格式 {apiBase,apiKey,model})注入 scanner 全局配置,
// 返回最终启用状态。规则: 无文件/显式 enabled=false 时默认关闭; -ai 强制开启;
// 旧格式(无 enabled 字段)存在即视为开启(旧逻辑: 保存配置 = 有意使用)。
func initAI(force bool) bool {
	scanner.SetAILogger(aiSlogLogger()) // 模块日志并入 yugsight.log
	cfg := scanner.DefaultAIConfig()
	cfg.Enabled = false
	if data, ok := section(secAI, ""); ok {
		_ = json.Unmarshal(data, &cfg)
		var raw map[string]json.RawMessage
		if json.Unmarshal(data, &raw) == nil {
			if _, ok := raw["enabled"]; !ok {
				cfg.Enabled = true // 旧格式无 enabled 字段
			}
			if _, ok := raw["backend"]; !ok && cfg.APIBase != "" {
				if strings.Contains(cfg.APIBase, "11434") || strings.Contains(cfg.APIBase, "ollama") {
					cfg.Backend = "ollama"
				} else {
					cfg.Backend = "openai"
				}
			}
		}
	}
	if force {
		cfg.Enabled = true
	}
	// 【兜底】配置声称启用但 apiKey 为空 → 强制关闭并说明原因。
	//
	// 为什么需要这道守卫: 本模块为兼容旧 ai.json 保留了"无 enabled 字段即视为
	// 开启"的语义(旧逻辑: 保存配置 = 有意使用)。而配置统一到 settings.json 后,
	// ai 节很容易只写了 apiBase/model 而漏掉 enabled —— 此时会被判为"开启",
	// 日志打出"AI 分析已启用", 但每次调用都会因缺 key 失败。用户看到的是
	// "明明启用了却不工作", 排查方向完全错。
	//
	// ollama 是本地服务免密钥, 故不检查。openai 兼容接口必须有 key。
	if cfg.Enabled && cfg.Backend != "ollama" && strings.TrimSpace(cfg.APIKey) == "" && !force {
		logLine("AI 配置缺少 apiKey, 已自动关闭(如需本地模型请设 backend=ollama)")
		cfg.Enabled = false
	}
	scanner.SetGlobalConfig(cfg)
	aiAn = scanner.NewAIAnalyzer(cfg)
	if cfg.Enabled {
		logLine(fmt.Sprintf("AI 分析已启用: backend=%s model=%s api=%s", cfg.Backend, cfg.Model, cfg.APIBase))
	} else {
		logLine("AI 分析未启用(以 -ai 启动或在 settings.json 的 ai 节设 enabled=true 开启)")
	}
	return cfg.Enabled
}

// aiSlogLogger 把 AI 模块的 slog 日志经 logLine 写入 yugsight.log(与主日志统一)
func aiSlogLogger() *slog.Logger {
	return slog.New(&aiLineHandler{})
}

type aiLineHandler struct{}

func (h *aiLineHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *aiLineHandler) WithAttrs(_ []slog.Attr) slog.Handler         { return h }
func (h *aiLineHandler) WithGroup(_ string) slog.Handler              { return h }
func (h *aiLineHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	fmt.Fprintf(&b, "AI [%s] %s", r.Level.String(), r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
		return true
	})
	logLine(b.String())
	return nil
}
