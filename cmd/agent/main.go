// Yugsight 探针端(yugsight-agent) 独立可执行入口。
//
// 为什么独立成二进制(2026-09-16 拆分):
//
//	早期实现把探针端塞进主程序 yugsight.exe(main.go 的 -probe=agent), 这在分布式部署
//	上是错的 —— 探针要装到多台被扫描机器上, 却被迫携带完整 Web UI / Vue 前端 / 规则库 /
//	引擎编排等与"上报信息 + 收任务 + 跑扫描"无关的重量, 且会无谓地监听 Web 端口。
//	拆开后:
//	  - 产物小(不含 go:embed 前端/模板/规则库, 仅 probe + scanner + 标准库);
//	  - 零入站端口: 只对中心端发起一条出站 TCP 连接, 不监听任何端口;
//	  - 升级解耦: 中心端升级 UI/规则不影响 agent。
//
// 配置: 与中心端同目录约定 —— exe 同目录 probe.json 的 client 段(见 yugsight/probe.ProbeConfig)。
// 也支持命令行覆盖中心端地址与密钥, 便于容器/无人值守部署。
//
// 降级约定(项目规则 3/4): 配置缺失/中心端不可达一律记日志继续运行, 不 panic 不退出;
// 探针侧日志写 logs/yugsight-agent.log(与控制台并行输出), 超过上限归档为
// logs/yugsight-agent-N.log(见 logrotate.go; probe.json 的 log 节可配 keepAtRoot
// 让当前日志留在 exe 根目录以兼容存量排障脚本)。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"yugsight/pathrel"
	"yugsight/probe"
	"yugsight/probe/agentexec"
	"yugsight/scanner"
)

const (
	agentName    = "Yugsight Agent"
	agentVersion = "1.0.0"
)

// logFile 日志写入器(带轮转, 见同目录 logrotate.go)。
// nil = 文件打开失败, 此时只写控制台(不阻断启动)。
var logFile *agentLogWriter

// logLine 写一条 agent 日志(带时间戳, 与控制端格式一致便于对照)。
func logLine(s string) {
	if len([]rune(s)) > 1000 {
		s = string([]rune(s)[:1000]) + "..."
	}
	// 与控制端同口径: 日志里 exe 目录树内的绝对路径一律相对化(目录外原样保留)。
	s = pathrel.InMessage(s)
	line := time.Now().Format("2006-01-02 15:04:05  ") + s + "\n"
	if logFile != nil {
		_, _ = logFile.Write([]byte(line))
	}
	fmt.Fprint(os.Stdout, line)
}

func main() {
	// 顶层兜底: agent 通常以无窗口方式运行, 崩溃原因只能靠日志;
	// 这里保证任何启动期 panic 都被记录而不是静默退出。
	defer func() {
		if r := recover(); r != nil {
			logLine(fmt.Sprintf("探针异常退出(panic): %v\n%s", r, debug.Stack()))
		}
	}()

	center := flag.String("center", "", "中心端地址, 如 192.168.1.10:8600(覆盖 probe.json 的 client.centerAddr)")
	flag.StringVar(center, "server", "", "(同 -center) 中心端地址")
	token := flag.String("token", "", "节点密钥(覆盖 probe.json 的 client.token)")
	id := flag.String("id", "", "探针标识(留空则按主机名生成并落盘, 重启保持不变)")
	name := flag.String("name", "", "节点别名(默认 hostname)")
	cfgPath := flag.String("config", "", "配置文件路径(默认 exe 同目录 probe.json)")
	showVer := flag.Bool("version", false, "显示版本号后退出")
	uninstall := flag.Bool("uninstall", false, "卸载探针(停止进程 + 删除开机自启 + 删除安装目录)")
	flag.Parse()

	initLog()
	if *showVer {
		fmt.Println(agentName + " v" + agentVersion + " (MIT License)")
		return
	}
	// 卸载入口: 双击安装目录里的「卸载探针.exe」(按文件名判定, 见 isUninstallLaunch),
	// 或脚本显式带 -uninstall。放在单实例检查之前 —— 探针正在跑时也要能卸载。
	if *uninstall || isUninstallLaunch() {
		logLine("进入卸载流程...")
		runUninstall()
		// 成功时 runUninstall 内部已 os.Exit; 走到这里=用户取消或非 Windows 空桩,
		// 两种情况都该直接结束本次启动(不能"取消卸载"却变成"启动探针")。
		return
	}

	// ===== 单实例 + Windows 双击自安装 =====
	// 零参数 = 用户双击: 自安装到 C 盘 + 注册开机自启 + 后台启动
	// (见 install_windows.go); 安装失败(如 C 盘不可写)则降级为前台运行。
	// 带任意参数 = 命令行部署: 只做单实例检查, 其余行为与之前完全一致。
	// 非 Windows: installAndLaunch 是空桩(install_other.go), 直接走原流程。
	doubleClick := flag.NFlag() == 0 && flag.NArg() == 0
	if !acquireSingleInstance() {
		if doubleClick {
			ShowInfo(agentName, "探针已在运行中, 无需重复启动。")
		}
		logLine("探针已在运行(单实例), 本次启动退出")
		return
	}
	defer releaseSingleInstance()
	if runtime.GOOS == "windows" && doubleClick && !installAndLaunch() {
		logLine("自安装失败, 回退为前台运行")
	}

	cfg := loadConfig(*cfgPath)
	if *center != "" {
		cfg.CenterAddr = *center
	}
	if *token != "" {
		cfg.Token = *token
	}
	if *id != "" {
		cfg.ID = *id
	}
	if *name != "" {
		cfg.Name = *name
	}
	// agent 入口默认强制启用探针端: 用户显式启动 agent 即代表要用它,
	// 不必再在 probe.json 里写 enabled=true(但配置文件缺失时给清晰报错提示)。
	if cfg.CenterAddr == "" {
		// 找不到中心端地址时弹输入框让用户补填(Windows)。
		//
		// 【为什么必须弹框而不是打了日志就退出】agent 最常见的部署方式是在被扫描
		// 机器上双击运行, 此时用户看不到控制台输出(窗口一闪而过或被安全软件拦),
		// 打了日志等于什么都没发生, 表现为"程序没反应"。弹框是唯一能让用户知道
		// "还差一个地址"的手段, 且当场填完就能继续, 不用回去改配置文件重来。
		//
		// 只有在"未带 -center 参数且配置里也没有"时才弹 —— 已经配好的场景弹框
		// 反而会打扰无人值守部署(规则: 不改变既有正常流程)。
		logLine("未配置中心端地址, 等待用户在弹框中填写...")
		raw := promptCenterAddr(agentName,
			"未找到中心端地址, 请输入中心端地址后继续\n\n格式: IP:端口, 例如 192.168.1.10:8600\n如中心端设置了节点密钥, 空格后附上: 192.168.1.10:8600 密钥\n留空则退出", 300)
		addr, token := parseCenterInput(raw)
		if addr == "" {
			logLine("未配置中心端地址: 请设置 probe.json 的 client.centerAddr, 或用 -center 指定")
			logLine("示例: yugsight-agent.exe -center 192.168.1.10:8600 -token <密钥>")
			return
		}
		cfg.CenterAddr = addr
		if token != "" {
			cfg.Token = token
		}
		// 地址(和密钥)补填后写回配置文件: 下次启动(含开机自启)就不用再填。
		// 写失败只记日志不影响本次运行(可能是只读目录, 不应因此拒绝服务)。
		if err := saveCenterAddr(*cfgPath, addr, token); err != nil {
			logLine("中心端地址已用于本次运行, 但写回配置失败(下次仍需重新填写): " + err.Error())
		} else {
			logLine("中心端地址已保存到配置文件, 下次启动自动使用: " + addr)
		}
	}

	// 探针日志并入 agent 日志; 版本上报用于中心端展示
	probe.SetGlobalLogger(logLine)
	probe.SetProbeVersion(agentVersion)

	p := probe.NewProbe(cfg, agentexec.Run)
	p.SetLogger(logLine)
	// 自动更新: 中心端在注册应答里比对版本, 不一致则下发更新指令。
	//
	// 默认启用(agent 是分布式部署的, 一台台手工替换不现实), 但受两个前提约束:
	//  1. 中心端必须配置了 agents/ 目录里对应平台的包(没有则指令带 404, 更新自动放弃);
	//  2. 程序所在目录必须可写(只读安装目录下 SelfUpdateSupported 为 false, 只提示)。
	// 两个前提任一不满足都只是"不更新", 不影响探针继续工作(规则 3/4)。
	if probe.SelfUpdateSupported() {
		p.SetSelfUpdater(&probe.SelfUpdater{Logf: logLine})
	} else {
		logLine("程序所在目录不可写, 自动更新不可用(如需更新请手动替换程序文件)")
	}
	p.OnUpdated(func(res probe.UpdateResult) {
		if !res.Updated {
			return
		}
		// 更新落地后必须重启才生效 —— 用户通常不知道这一点, 不提示就会以为
		// "更新了但版本还是旧的"。弹框 + 日志双通道, 保证有人值守能看见、无人
		// 值守可事后查日志。
		logLine("请关闭本窗口并重新启动探针, 新版本才会生效")
		ShowInfo("Yugsight Agent",
			"探针已更新到 v"+res.Version+"\n\n请关闭本窗口并重新启动探针, 新版本才会生效。")
	})
	warnLoopbackCenter(cfg.CenterAddr)
	p.Start()
	logLine(fmt.Sprintf("御视探针 (%s) v%s 已启动: 探针 ID=%s, 目标中心端 %s",
		agentName, agentVersion, p.ID(), cfg.CenterAddr))
	// 打印本地扫描能力: 分布式部署出问题时(如"中心端下发的抓包任务不生效"),
	// 第一件事就是确认探针这台机器到底具备哪些能力, 因此启动即明确告知。
	logLine("本地扫描能力: " + agentexec.CapabilitySummary())
	logLine("提示: 按 Ctrl+C 可停止探针")
	// 连不上中心端时的交互守卫(Windows 弹框改地址/静默/退出; 其它平台无操作)
	startConnectGuard(p, cfg, *cfgPath)

	// 等待退出信号(Ctrl+C / SIGTERM); 不做单实例/提权/端口绑定 —— agent 只做出站连接
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	logLine("收到退出信号, 正在断开与中心端的连接...")
	p.Stop()
	logLine(agentName + " 已停止")
	// 退出前关文件: 让最后几条日志落盘(尤其是"已停止"这条)并释放句柄,
	// 否则外部工具(如日志采集)可能在句柄未释放时读到半截内容
	if logFile != nil {
		logFile.Close()
	}
}

// loadConfig 读取 probe.json 的 client 段(可选, 缺失/损坏时返回带默认值的配置)。
//
// 与主程序 probe_api.go 的配置口径一致: 同一份 probe.json 既可被中心端读取(center 段),
// 也可被 agent 读取(client 段), 两端因此可以共享一个文件或用各自的副本。
func loadConfig(path string) probe.ProbeConfig {
	cfg := probe.ProbeConfig{Enabled: true}
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			path = "probe.json"
		} else {
			path = filepath.Join(filepath.Dir(exe), "probe.json")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		logLine("未找到配置文件 " + path + " (将仅使用命令行参数)")
		return cfg
	}
	// Windows 记事本/PowerShell Set-Content -Encoding UTF8 会写入 UTF-8 BOM(EF BB BF),
	// 直接交给 json.Unmarshal 会报 invalid character —— 这类"用户手工编辑配置"的场景
	// 必须容错, 否则用户会以为程序读不到自己填的地址。这里统一剥掉 BOM。
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	// 兼容两种写法: {"client": {...}} (主程序完整配置) 或 {...} (仅 client 段)
	var wrap struct {
		Client *probe.ProbeConfig `json:"client"`
	}
	if json.Unmarshal(data, &wrap) == nil && wrap.Client != nil {
		cfg = *wrap.Client
	} else if json.Unmarshal(data, &cfg) != nil {
		logLine("配置文件解析失败, 忽略: " + path)
		return probe.ProbeConfig{Enabled: true}
	}
	cfg.Enabled = true
	return cfg
}

// parseCenterInput 解析弹框输入: "IP:端口" 或 "IP:端口 节点密钥"(密钥可选, 空格分隔)。
//
// 密钥允许一并填写的原因: 中心端一键开启会自动生成节点密钥, 没有密钥时注册
// 会被中心端拒绝, 而探针端无从得知密钥 —— 只有用户知道。一个弹框把地址和
// 密钥都拿到, 避免"先填地址、再改配置文件补密钥"两步走。
func parseCenterInput(s string) (addr, token string) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", ""
	}
	addr = fields[0]
	if len(fields) > 1 {
		token = fields[1]
	}
	return addr, token
}

// saveCenterAddr 把用户填写的中心端地址(与可选的节点密钥)写回配置文件。
//
// 【为什么用"读-改-写"而不是直接生成新配置】probe.json 是中心端与探针端共用的
// 同一个文件, 里面还有 token/日志/其它开关。若这里直接覆盖, 会把用户的其它设置
// 一并抹掉(尤其是 token, 抹掉后下次注册会被中心端拒绝, 用户完全不知道是自己填
// 地址时被清空的)。
//
// 实现上用 map[string]any 承载整个文档再只改 client.centerAddr/client.token:
// 这样未知字段(将来新增的配置项)也会被原样保留, 不会因为本文件不认识某个
// 键就把用户配置吃掉。token 为空时不写, 保留配置里已有的密钥。
func saveCenterAddr(path, addr, token string) error {
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			path = "probe.json"
		} else {
			path = filepath.Join(filepath.Dir(exe), "probe.json")
		}
	}
	doc := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
		// 解析失败时从空文档开始 —— 宁可重建也不要因为旧文件损坏而完全写不进去。
		// (损坏的原文件仍在磁盘上, 未被破坏, 用户可自行取回)
		_ = json.Unmarshal(data, &doc)
	} else if !os.IsNotExist(err) {
		return err
	}

	// 定位 client 段: 既支持 {"client":{...}} 完整配置, 也支持 {...} 仅 client 段。
	client, ok := doc["client"].(map[string]any)
	if !ok {
		// 判断是不是"扁平写法"(顶层直接是 ProbeConfig 字段):
		// 若文档里已有 centerAddr 或为空, 就按扁平写法处理, 避免把已有配置错误嵌套。
		if _, flat := doc["centerAddr"]; flat || len(doc) == 0 {
			doc["centerAddr"] = addr
			if token != "" {
				doc["token"] = token
			}
			return writeJSONAtomic(path, doc)
		}
		client = map[string]any{}
		doc["client"] = client
	}
	client["centerAddr"] = addr
	if token != "" {
		client["token"] = token
	}
	return writeJSONAtomic(path, doc)
}

// writeJSONAtomic 原子写入 JSON(先写临时文件再改名, 避免写一半崩溃留下坏配置)。
func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// initLog 打开 logs/yugsight-agent.log(与控制台并行)。
//
// 与控制端日志分离的原因: agent 与中心端可能部署在同一台机器上联调,
// 共用一个日志文件会互相覆盖时间线, 且进程退出时文件句柄争用容易读到半截内容。
//
// 轮转: 探针是**长期无人值守**部署的, 日志无限增长比中心端更容易出事(磁盘写满会
// 连带影响 agent 自身运行), 所以这里同样接轮转。日志与归档都在 logs/ 下,
// 与中心端目录相同但文件名前缀不同(yugsight-agent-*), 清理时互不影响 ——
// 归档取名靠 archiveSeqRe 精确匹配本文件名, 不会把对方的卷删掉。
func initLog() {
	exe, err := os.Executable()
	if err != nil {
		exe = "."
	}
	logFile = newAgentLogWriter(filepath.Dir(exe), "yugsight-agent.log")
}

// 编译期断言: agentexec 的执行函数必须满足 probe.ExecFunc 签名。
// 放在这里是为了让"探针端执行器与协议层解耦"这条约束在编译期就被固定住。
var _ probe.ExecFunc = agentexec.Run

// scanner 直接引用: 保证 agent 二进制链接的正是主程序同一套扫描实现(而非另起炉灶)。
var _ = scanner.ScanPorts

// 引用 slog 以对齐项目"错误统一走结构化日志"的约定(agent 侧经 logLine 落文件)。
var _ = slog.LevelInfo
