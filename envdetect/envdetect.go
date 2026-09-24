// Package envdetect 本地环境检测(任务 4.2):
//
//   - 启动时遍历 exe 同目录的 ./bin/ 目录, 识别本地引擎 nmapcore / trivycore / zapcore 并读取版本;
//   - Windows 下读取注册表检测 Npcap 驱动安装状态(未安装时前端展示"安装网络驱动"按钮,
//     点击执行项目根目录的 npcap-setup.exe, 见 env_api.go);
//   - 引擎缺失/不可用时自动标记降级(Fallback/Degraded): 扫描切换回内置引擎, 前端据此置灰。
//
// 纯标准库零第三方依赖; 检测异步执行不阻塞启动; 目录缺失/注册表不可读等一律降级不崩溃。
package envdetect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"yugsight/pathrel"
)

// 本地引擎名(bin/ 目录二进制命名约定: 前缀名 + 可选版本后缀, 如 nmapcore.exe / nmap-7.94.exe)
const (
	EngineNmap  = "nmapcore"
	EngineTrivy = "trivycore"
	EngineZap   = "zapcore"
	// EngineNuclei 官方 nuclei 引擎(可选外部引擎: 内置引擎只能跑 HTTP 模板,
	// 装官方引擎后可使用 network/dns/ssl 等更多协议; 由引擎下载模块按 nucleicore.exe 装入)
	EngineNuclei = "nucleicore"
)

// EngineStatus 单个本地引擎检测结果
type EngineStatus struct {
	Name    string `json:"name"`
	Found   bool   `json:"found"`
	State   string `json:"state"` // ok | missing | detecting | error
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
	// Fallback: 引擎缺失或不可用 -> 自动降级为内置引擎
	Fallback bool `json:"fallback"`
}

// NpcapStatus Npcap 抓包驱动检测结果(仅 Windows 适用)
type NpcapStatus struct {
	Supported bool   `json:"supported"`
	Installed bool   `json:"installed"`
	// Source: registry-service(驱动服务) / registry-uninstall(卸载注册项) / file(DLL 文件) / -
	Source string `json:"source,omitempty"`
	// Version 注册表 Uninstall 键的 DisplayVersion(可能为空)
	Version string `json:"version,omitempty"`
	// Installer exe 同目录(项目根目录)找到的安装器路径: npcap-setup.exe 或 npcap-*.exe
	Installer string `json:"installer,omitempty"`
}

// Status 环境检测总结果
type Status struct {
	BinDir    string         `json:"binDir"`
	OS        string         `json:"os"`
	Detecting bool           `json:"detecting"`
	Engines   []EngineStatus `json:"engines"`
	Npcap     NpcapStatus    `json:"npcap"`
	// Java JRE/JDK 运行时(仅 ZAP 依赖; 其它引擎是原生二进制, 不需要)
	Java JavaStatus `json:"java"`
	// Degraded 因缺失/异常而降级的引擎名列表(前端置灰/降级提示依据)
	Degraded  []string `json:"degraded,omitempty"`
	CheckedAt string   `json:"checkedAt"`
}

// JavaStatus Java 运行时检测结果。
//
// 【为什么单列一项而不是塞进引擎表】ZAP 的"引擎文件在不在"和"能不能跑"是两件事:
// 官方跨平台免安装包**不含 Java**, 本机只有 Java 8 时 ZAP 文件齐全但一执行就抛
// UnsupportedClassVersionError(class file version 61.0 = 需要 Java 17)。
// 如果只报"ZAP 就绪", 用户会以为一切正常, 直到真正扫描时才失败且看不明原因。
type JavaStatus struct {
	Supported  bool   `json:"supported"`          // 本机是否需要 Java(固定 true, 保留字段便于前端统一渲染)
	Found      bool   `json:"found"`              // PATH 里能否执行 java
	Version    string `json:"version,omitempty"`  // 解析出的版本(如 1.8.0 / 17.0.9)
	OK         bool   `json:"ok"`                 // 是否满足 ZAP 要求(17+)
	MinVersion int    `json:"minVersion"`         // 要求的最低主版本(17)
	Note       string `json:"note,omitempty"`     // 不满足时的可读说明
	// Bundled 命中的是"ZAP 自带 JDK"(bin/zapcore/ZAP_<ver>/jre)而不是系统 Java。
	//
	// 【为什么必须让前端知道这件事】两种"满足要求"的处置方式完全不同: 自带 JDK 意味着
	// 这台机器**不需要装任何 Java**; 而系统 Java 意味着换台电脑还得再装一遍。
	// 前端据此显示"已随 ZAP 内置"而不是笼统的"Java 就绪", 用户才不会白装一个 Java。
	Bundled bool `json:"bundled,omitempty"`
	// Path 实际使用的 java 可执行文件路径(自带 JDK 时才有值, 便于排障时核对)
	Path string `json:"path,omitempty"`
}

var (
	mu     sync.RWMutex
	cached *Status
	busy   bool

	logf = func(string) {}
)

// SetLogger 注入主程序日志函数(并入 yugsight.log)
func SetLogger(f func(string)) {
	if f != nil {
		logf = f
	}
}

// Init 启动时调用: 触发一次异步检测(不阻塞 Web 服务启动)
func Init() { detectAsync() }

// Refresh 重新检测(前端手动刷新 / 装完驱动后重读注册表)
func Refresh() { detectAsync() }

// Get 当前检测快照; 检测未完成时返回"检测中"占位(不阻塞 API)
func Get() *Status {
	mu.RLock()
	defer mu.RUnlock()
	if cached != nil {
		return cached
	}
	s := &Status{
		OS:        runtime.GOOS,
		BinDir:    binDir(),
		Detecting: true,
		CheckedAt: time.Now().Format("2006-01-02 15:04:05"),
		Engines:   make([]EngineStatus, 0, len(engineSpecs)),
	}
	for _, sp := range engineSpecs {
		s.Engines = append(s.Engines, EngineStatus{Name: sp.Name, State: "detecting"})
	}
	s.Npcap = detectNpcap()
	// Java 探测很快(单次 exec), 但为与其它项口径一致, 检测中也先给占位
	s.Java = JavaStatus{Supported: true, MinVersion: javaMinMajor, Note: "检测中..."}
	return s
}

func detectAsync() {
	mu.Lock()
	if busy {
		mu.Unlock()
		return
	}
	busy = true
	mu.Unlock()

	go func() {
		st := detect()
		mu.Lock()
		cached = st
		busy = false
		mu.Unlock()
		for _, e := range st.Engines {
			switch e.State {
			case "ok":
				logf("环境检测: 引擎 " + e.Name + " 就绪 (版本 " + e.Version + ", 路径 " + e.Path + ")")
			case "error":
				logf("环境检测: 引擎 " + e.Name + " 异常 (" + e.Error + "), 自动降级为内置引擎")
			default:
				logf("环境检测: 引擎 " + e.Name + " 未检测到, 自动降级为内置引擎")
			}
		}
		if st.Npcap.Supported {
			if st.Npcap.Installed {
				v := st.Npcap.Version
				if v == "" {
					v = "未知"
				}
				logf("环境检测: Npcap 驱动已安装 (来源 " + st.Npcap.Source + ", 版本 " + v + ")")
			} else {
				logf("环境检测: Npcap 驱动未安装, 抓包功能不可用(前端可触发安装)")
			}
		}
		// Java 只在"已装 ZAP 但不满足版本"时才值得占用一行日志: 没装 ZAP 的用户
		// 大多也没有 Java, 每次都报"未检测到 Java"会造成噪音, 让人误以为系统缺东西。
		if !st.Java.OK && zapInstalled(st) {
			logf("环境检测: 已安装 ZAP 但 " + st.Java.Note)
		}
	}()
}

// zapInstalled 判断 bin/ 下是否已装 ZAP(用于决定 Java 缺失是否值得告警)。
func zapInstalled(st *Status) bool {
	for _, e := range st.Engines {
		if e.Name == EngineZap && e.Found {
			return true
		}
	}
	return false
}

// detect 执行一次完整检测(bin/ 引擎 + Npcap 驱动)
func detect() *Status {
	dir := binDir()
	st := &Status{
		BinDir:    dir,
		OS:        runtime.GOOS,
		CheckedAt: time.Now().Format("2006-01-02 15:04:05"),
		Engines:   make([]EngineStatus, 0, len(engineSpecs)),
	}
	st.Npcap = detectNpcap()
	st.Java = detectJava()

	// bin/ 目录缺失属正常情况(外部资源可选), 全部引擎记为缺失
	entries, _ := os.ReadDir(dir)
	for _, sp := range engineSpecs {
		es := EngineStatus{Name: sp.Name, State: "missing"}
		// bin/ 优先; 找不到回退系统 PATH(覆盖第三方自装引擎: apt/brew 装到 PATH,
		// 未放进 exe 同目录 bin/)。这与执行器 findBin 的口径一致, 检测到的就能用。
		p := findBinaryPath(dir, entries, sp)
		if p == "" {
			if lpp, ok := lookupOnPath(sp.Prefix); ok {
				p = lpp
			}
		}
		if p != "" {
			es.Found = true
			es.Path = shortPath(p) // exe 树内转相对短路径; PATH 里的保留绝对路径便于定位
			// JVM 类引擎(ZAP)先走零启动的 jar 名提取: 冷启动约 16s 会拖慢探测,
			// 按默认 5s 还会被杀掉误判降级, 而版本号直接可读, 无需启动 JVM。
			var ver, raw string
			var err error
			if sp.FastVersion != nil {
				ver = sp.FastVersion(p)
			}
			if ver == "" {
				timeout := sp.VerTimeout
				if timeout <= 0 {
					timeout = defaultVerTimeout
				}
				ver, raw, err = probeVersion(p, sp.VerArgs, timeout)
			}
			if err != nil {
				es.State = "error"
				es.Error = err.Error()
				es.Fallback = true
			} else {
				es.State = "ok"
				if ver != "" {
					es.Version = ver
				} else if raw != "" {
					es.Version = "unknown" // 可运行但输出里没解析出版本号
				}
			}
		} else {
			es.Fallback = true // 引擎缺失 -> 自动降级
			es.Error = "bin/ 目录无此引擎, 且系统 PATH 中未找到 " + sp.Prefix // 未安装原因, 前端展示
		}
		if es.Fallback {
			st.Degraded = append(st.Degraded, es.Name)
		}
		st.Engines = append(st.Engines, es)
	}
	return st
}

// lookupOnPath 用 exec.LookPath 在系统 PATH 里查引擎命令(第三方自装引擎)。
// 查不到返回 ("", false); 任何异常都按"未找到"处理, 不 panic(引擎为可选外部资源)。
func lookupOnPath(cmd string) (string, bool) {
	if cmd == "" {
		return "", false
	}
	if p, err := exec.LookPath(cmd); err == nil {
		return p, true
	}
	return "", false
}

// findBinaryPath 返回引擎二进制的完整路径(顶层找不到时回退到套装子目录)。
//
// 【为什么需要子目录回退】nmap 是"多文件套装": engmgr 把整个 zip(含 DLL 与
// nmap-services 等数据文件)解到 bin/nmapcore/ 下, 入口在子目录里。只扫顶层会让
// "已装好的 nmap"被判为 missing, 前端反复提示"未检测到引擎, 已降级"。
func findBinaryPath(dir string, entries []os.DirEntry, sp engineSpec) string {
	if name := findBinary(entries, sp); name != "" {
		return filepath.Join(dir, name)
	}
	return findBinaryInSubdir(dir, sp)
}

// findBinaryInSubdir 在 bin/<prefix>* 子目录中递归查找引擎入口。
// 子目录名以引擎前缀开头才算数, 避免误扫其它引擎的套装目录。
func findBinaryInSubdir(dir string, sp engineSpec) string {
	subs, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	isWin := runtime.GOOS == "windows"
	prefix := strings.ToLower(sp.Prefix)
	for _, e := range subs {
		if !e.IsDir() || !strings.HasPrefix(strings.ToLower(e.Name()), prefix) {
			continue
		}
		var exeHit, batHit string
		_ = filepath.Walk(filepath.Join(dir, e.Name()), func(p string, info os.FileInfo, werr error) error {
			if werr != nil || info == nil || info.IsDir() {
				return nil
			}
			n := strings.ToLower(info.Name())
			if isWin {
				if !strings.HasPrefix(n, prefix) {
					return nil
				}
				// .bat 与 .exe 都要认: ZAP 官方跨平台包里没有 zap.exe, 入口是 zap.bat
				// (脚本内拼 java 命令行跑 zap.jar)。只认 .exe 会让装好的 ZAP 被判 missing。
				// 优先级 .exe > .bat(更直接的启动方式)。
				switch {
				case strings.HasSuffix(n, ".exe") && exeHit == "":
					exeHit = p
				case strings.HasSuffix(n, ".bat") && batHit == "":
					batHit = p
				}
			} else if !strings.Contains(n, ".") && strings.HasPrefix(n, prefix) && exeHit == "" {
				exeHit = p
			}
			return nil
		})
		if exeHit != "" {
			return exeHit
		}
		if batHit != "" {
			return batHit
		}
	}
	return ""
}

// defaultVerTimeout 引擎版本探测默认超时。原生二进制引擎(nmap/trivy/nuclei)
// 秒级返回, 5s 足够; JVM 类引擎(ZAP)冷启动远超此值, 用各自 VerTimeout 覆盖。
const defaultVerTimeout = 5 * time.Second

// engineSpec 引擎识别规则: bin/ 下按前缀匹配可执行文件
type engineSpec struct {
	Name    string
	Prefix  string
	VerArgs [][]string // 依次尝试的版本参数, 首个能解析出版本号的胜出
	// VerTimeout 版本探测超时(0 = defaultVerTimeout)。ZAP 这类 JVM 引擎冷启动
	// 约 16s, 远超默认 5s: 按 5s 跑 `zap.bat -cmd -version` 会在版本返回前被杀,
	// Windows 下被 Kill 的子进程退出码为 1, 日志报 "exit status 1" 并被误判降级。
	VerTimeout time.Duration
	// FastVersion 可选: 不启动进程、直接从同目录文件快速提取版本号(如 ZAP 的版本
	// 号写在 zap-<ver>.jar 文件名里, 无需启动 16s 的 JVM 去问它)。命中则跳过命令
	// 探测; 命令探测仍作兜底, 供 jar 命名非规范的极端情况。
	FastVersion func(path string) string
}

var engineSpecs = []engineSpec{
	{Name: EngineNmap, Prefix: "nmap", VerArgs: [][]string{{"--version"}, {"-version"}, {"version"}}},
	{Name: EngineTrivy, Prefix: "trivy", VerArgs: [][]string{{"version"}, {"--version"}, {"-version"}}},
	// ZAP 是 Java Swing GUI 程序: 版本探测必须带 -cmd, 否则每次启动服务时探测 ZAP
	// 版本都会弹出 ZAP 窗口(然后被 5s 超时杀掉), 表现为"一打开 exe 就跳出 ZAP GUI"。
	// 另外 ZAP 只认单横线 -version(双横线 --version 会打印帮助并不返回版本号),
	// 故把 -version 放在首位。实测(2026-09, ZAP 2.17.0): `zap.bat -cmd -version`
	// 无窗口、立即返回 "2.17.0"。
	{Name: EngineZap, Prefix: "zap",
		VerArgs:     [][]string{{"-cmd", "-version"}, {"-cmd", "--version"}, {"-cmd", "version"}},
		VerTimeout:  30 * time.Second, // JVM 冷启动约 16s, 给足余量
		FastVersion: zapVersionFromJar, // 版本号写在 zap-<ver>.jar 文件名里, 零启动提取
	},
	// 注意探测顺序: nuclei 的前缀匹配必须放在最后。
	// "nucleicore.exe" 以 "nmap/trivy/zap" 任何一个为前缀都不成立, 但反过来
	// trivycore/nmapcore 也都不以 "nuclei" 开头, 所以顺序本身不会误命中; 放在末尾
	// 只是为了保持"主扫描引擎在前、可选外部引擎在后"的展示顺序。
	{Name: EngineNuclei, Prefix: "nuclei", VerArgs: [][]string{{"-version"}, {"--version"}, {"-version"}}},
}

// binDirFn 定位引擎目录的实现。默认取 exe 同目录 bin/, 测试可替换。
//
// 【为什么留这个可替换点】binDir 读的是 os.Executable() —— 在测试进程里那是 go 的
// 临时构建目录, 指向它就只能去测真实磁盘布局, 无法用构造数据覆盖"自带 JDK 半成品
// 目录""zapcore 根布局"这些必须验到的边界。留一个函数变量比到处加 if testing 干净。
var binDirFn = func() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(".", "bin")
	}
	return filepath.Join(filepath.Dir(exe), "bin")
}

// binDir 返回 exe 同目录的 bin/ 路径(本地引擎约定放置处)
func binDir() string { return binDirFn() }

// shortPath 把 exe 目录树内的绝对路径转成 ".\bin\xxx.exe" 形式的相对短路径(仅展示用)。
//
// 【为什么存相对路径】引擎/安装器/自带 JDK 都约定放 exe 同目录树下, 绝对路径只是把
// 安装目录重复一遍: 换台机器或换个目录部署, 日志与页面上的路径全变, 没法对照;
// 前端窄表格里 E:\path\to\yugsight\bin\nucleicore.exe 还会折行。相对路径跨机器
// 一致且一眼能看出"就在 exe 旁边"。真需要绝对定位时, Status.BinDir(始终为绝对
// 路径)就是锚点, 两者拼接即完整路径。
//
// 不在 exe 目录下(如系统 Java 的 PATH 路径)或计算失败时原样返回, 不做强制截短。
// 实现统一收敛在 pathrel 包(日志入口 logLine 的兜底相对化用它同一套口径)。
func shortPath(p string) string { return pathrel.Short(p) }

// findBinary 在 bin/ 条目中找引擎二进制:
// 精确匹配 <prefix>[.exe] 优先, 否则取任意以 prefix 开头的可执行文件(如 nmapcore.exe / nmap-7.94.exe)。
// 可执行判定: Windows 只认 .exe; 其它平台跳过带扩展点的文件(配置/数据文件)。
func findBinary(entries []os.DirEntry, sp engineSpec) string {
	isWin := runtime.GOOS == "windows"
	var loose string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.ToLower(e.Name())
		if isWin && !strings.HasSuffix(n, ".exe") {
			continue
		}
		if !isWin && strings.Contains(n, ".") {
			continue
		}
		if n == sp.Prefix || n == sp.Prefix+".exe" {
			return e.Name()
		}
		if strings.HasPrefix(n, sp.Prefix) && loose == "" {
			loose = e.Name()
		}
	}
	return loose
}

var verRe = regexp.MustCompile(`(\d+\.\d+(?:\.\d+){0,3})`)

// zapVersionFromJar 从 ZAP 入口(zap.bat / zap)同目录的 zap-<version>.jar 文件名
// 提取版本号, 零 JVM 启动。官方包 jar 名固定为 zap-<ver>.jar, 版本号直接可读;
// 启动一次 ZAP 的 JVM 冷启动约 16s, 远超探测超时, 故能读文件名就不启动。
// 找不到 / 无版本号返回空串, 调用方回退到命令探测。
func zapVersionFromJar(entryPath string) string {
	entries, err := os.ReadDir(filepath.Dir(entryPath))
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(strings.ToLower(n), "zap-") || !strings.HasSuffix(n, ".jar") {
			continue
		}
		if m := verRe.FindString(n); m != "" {
			return m
		}
	}
	return ""
}

// probeVersion 依次用候选参数运行 <binary> 读取版本(每项 timeout 超时):
// 返回 (版本号, 输出摘要, 错误)。可运行但无版本号时 version 为空、raw 有输出。
func probeVersion(path string, argSets [][]string, timeout time.Duration) (version, raw string, err error) {
	var lastErr error
	for _, args := range argSets {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		raw = firstLines(string(out))
		if m := verRe.FindString(raw); m != "" {
			return m, raw, nil
		}
		if raw != "" {
			return "", raw, nil
		}
	}
	if lastErr != nil {
		msg := lastErr.Error()
		if ctxErr := "exec: "; strings.HasPrefix(msg, ctxErr) {
			msg = strings.TrimPrefix(msg, ctxErr)
		}
		return "", "", fmt.Errorf("无法运行引擎: %s", strings.TrimSpace(msg))
	}
	return "", "", nil
}

// firstLines 取前 3 行非空文本并限长(版本输出摘要)
func firstLines(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if ln == "" {
			continue
		}
		out = append(out, ln)
		if len(out) >= 3 {
			break
		}
	}
	t := strings.Join(out, " | ")
	if len([]rune(t)) > 120 {
		t = string([]rune(t)[:120]) + "..."
	}
	return t
}
