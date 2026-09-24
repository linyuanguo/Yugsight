// driver.go 引擎下载/安装/卸载驱动。
//
// 设计要点(都是踩过或预判到的坑):
//
//  1. 【不污染 bin/ 的既有文件】安装时若 bin/ 已存在目标文件(可能是用户手工放的
//     nmapcore.exe, 或某个我们无权覆盖的自定义版本), 一律不覆盖 —— 而是写入
//     带后缀的隔离名, 并把 skipReason 上报给前端, 由用户自己决定是否清理。
//     自动覆盖用户的二进制是"静默破坏", 属于不可接受的行为。
//
//  2. 【先暂存再落位】下载到 <bin>/.engmgr-tmp/ 下, 解包、校验、改名全部在暂存区
//     完成, 最后一步才 rename 进 bin/。中途任何失败都只清暂存目录, bin/ 不受影响
//     (与 scanner/rule_updater.go 的 .staging 语义一致)。
//
//  3. 【进度可轮询】耗时可达数分钟(233MB 的 ZAP), 所以全程写内存状态, 由装配层
//     暴露 /progress 端点给前端轮询; 同时把进度回调出去(与规则库更新同一套交互)。
//
//  4. 【失败必带指引】自动化链路失败时(无 7z、网络不通、GitHub 被墙), 结果里必须
//     带 Homepage 官方下载页 —— 用户问过"不要人工找链接", 那失败时就更不能只丢一句
//     "失败", 必须给出可点的落地地址。
//
//  5. 【默认不触发】本模块只在用户显式点击或配置 allowDownload=true 时可下载,
//     不在启动路径上发起任何网络请求(项目规则 5: 新增功能默认关闭)。
package engmgr

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// stDownloading.. 任务状态(与 scanner.UpdateProgress 的状态词保持同一套语义, 便于前端复用)
const (
	StQueued      = "queued"
	StChecking    = "checking"    // 查询上游最新版本
	StDownloading = "downloading" // 下载包体
	StExtracting  = "extracting"  // 解包 / 抽取
	StInstalling  = "installing"  // 落位到 bin/
	StDone        = "done"
	StFailed      = "failed"
	StNoUpdate    = "uptodate" // 本地已是最新
	StSkipped     = "skipped"
)

// Info 单个引擎的可下载性信息(供前端渲染按钮/提示)
type Info struct {
	Engine      Engine `json:"engine"`
	Display     string `json:"display"`
	Homepage    string `json:"homepage"`
	Note        string `json:"note,omitempty"`
	DefaultOff  string `json:"defaultOff,omitempty"`
	Supported   bool   `json:"supported"`   // 当前平台/架构是否有官方包
	NeedExtract bool   `json:"needExtractor"` // 是否依赖系统 7z/tar(Windows SFX)
	// ExtractorReady 系统解包器是否可用(needExtractor=true 时才有意义)
	ExtractorReady bool `json:"extractorReady"`
	// Installed 目标文件是否已在 bin/ 中
	Installed bool   `json:"installed"`
	// InstalledPath/InstalledVersion 已安装时的路径与版本(来自 envdetect 探测结果, 由装配层回填)
	InstalledPath    string `json:"installedPath,omitempty"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	// LatestVersion 上游最新版本(仅在 check 时回填)
	LatestVersion string `json:"latestVersion,omitempty"`
	// AssetName 将要下载的资产文件名(便于用户核对)
	AssetName string `json:"assetName,omitempty"`
	// Unsupported 不支持的原因(平台无包 / 需要解包器但未探测到)
	Unsupported string `json:"unsupportedReason,omitempty"`
	// RuntimeMissing 运行时依赖缺失的原因(如 ZAP 需要 Java 17+ 但本机只有 Java 8)。
	//
	// 与 Unsupported 分开是因为语义不同: Unsupported 是"这个平台/环境压根无法安装",
	// 而 RuntimeMissing 是"能装, 但装了也跑不起来" —— 属于更隐蔽的坑(ZAP 实测:
	// 下载 273MB + 解包 + 落位全部成功, 用户以为装好了, 实际一执行就 class 版本报错)。
	// 前端应把这条显著展示, 让用户先去解决依赖。
	RuntimeMissing string `json:"runtimeMissing,omitempty"`
}

// Progress 任务进度(单引擎粒度: 一批任务逐个安装, 每次只有一个是"活跃"的)
type Progress struct {
	Engine   Engine `json:"engine"`
	Status   string `json:"status"`
	Phase    string `json:"phase,omitempty"` // 人类可读的当前阶段说明
	Total    int    `json:"total"`           // 本次任务总引擎数
	Done     int    `json:"done"`            // 已完成引擎数
	Bytes    int64  `json:"bytes"`           // 已下载字节
	TotalB   int64  `json:"totalBytes"`      // 包体总字节(-1 表示上游未给长度)
	Percent  int    `json:"percent"`         // 下载百分比(-1 表示未知)
	Speed    int64  `json:"speed"`           // 字节/秒
	Version  string `json:"version,omitempty"`
	Error    string `json:"error,omitempty"`
	StartedAt string `json:"startedAt,omitempty"`
}

// ItemResult 单个引擎的安装结果
type ItemResult struct {
	Engine   Engine `json:"engine"`
	Display  string `json:"display"`
	OK       bool   `json:"ok"`
	Version  string `json:"version"`
	Installed string `json:"installed,omitempty"` // 落位后的完整路径
	RenameTo  string `json:"renameTo,omitempty"`  // 若因命名冲突隔离安装, 说明改成什么名字
	Homepage  string `json:"homepage,omitempty"`  // 失败时的官方下载页(指引兜底)
	HomepageNote string `json:"homepageNote,omitempty"`
	Error    string `json:"error,omitempty"`
	Skipped  bool   `json:"skipped,omitempty"`
	SkipReason string `json:"skipReason,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`

	// ===== 以下三项仅 ZAP 会有值(它需要额外的 Java 运行时) =====

	// JDKVersion 随 ZAP 一并装入的自带 JDK 版本(如 "17.0.20+101"); 未装成为空
	JDKVersion string `json:"jdkVersion,omitempty"`
	// JDKPath 自带 JDK 的落地目录(bin/zapcore/ZAP_<ver>/jre)
	//
	// 【为什么不让用户去猜这个目录】它是排障时第一个要看的地方(确认 java 在不在),
	// 也是"把整个 zapcore 拷到别的电脑"时要一起带走的东西 —— 直接回显出来最省事。
	JDKPath string `json:"jdkPath,omitempty"`
	// JDKNote JDK 结果的说明(成功/跳过/失败原因), 前端直接展示。
	//
	// 失败时**不置 OK=false**: ZAP 本体已完整落位, 缺 Java 是运行期依赖, 用户自己
	// 装一个 Java 17 就能用。具体理由见 installOne 里的注释。
	JDKNote string `json:"jdkNote,omitempty"`
}

// ProgressFunc 进度回调(可为 nil)
type ProgressFunc func(p Progress)

// Manager 引擎下载管理器。
//
// 单例由装配层持有; 本类型自身并发安全(同一时刻只允许一个下载任务在跑)。
type Manager struct {
	mu      sync.Mutex
	info    []Info // 目录快照 + 平台能力(每次刷新时重算)
	prog    Progress
	running bool
	results []ItemResult // 上一轮结果
	lastErr string
	logf    func(string)
	// binDir 引擎安装目录。
	//
	// 存成字段而不是每次现算: 测试要把它改指临时目录, 现算会读到开发机真实 bin/。
	binDir string
	// client 下载用 HTTP 客户端(超时宽松: 大包在慢链路上需要很久)
	client *http.Client
	// tools 系统解包器探测结果(懒探测)
	tools     extractTools
	toolsOnce sync.Once
}

// New 创建管理器(不发起网络请求)。binDir 为引擎安装目录(通常 exe 同目录 bin/)。
func New(binDir string) *Manager {
	m := &Manager{
		logf:   func(string) {},
		client: &http.Client{Timeout: 30 * time.Minute},
	}
	m.binDir = binDir
	m.refreshInfo()
	return m
}

// BinDir 当前引擎安装目录
func (m *Manager) BinDir() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.binDir
}

// SetBinDir 改指引擎目录(测试用; 同时刷新 Info 快照)
func (m *Manager) SetBinDir(dir string) {
	m.mu.Lock()
	m.binDir = dir
	m.mu.Unlock()
	m.refreshInfo()
}

// SetLogger 注入日志函数(并入 yugsight.log)
func (m *Manager) SetLogger(f func(string)) {
	if f != nil {
		m.mu.Lock()
		m.logf = f
		m.mu.Unlock()
	}
}

func (m *Manager) log(s string) {
	m.mu.Lock()
	f := m.logf
	m.mu.Unlock()
	if f != nil {
		f(s)
	}
}

// extractToolsFor 懒探测系统解包器(只在真正需要时探测)
func (m *Manager) extractToolsFor() extractTools {
	m.toolsOnce.Do(func() { m.tools = DetectExtractTools() })
	return m.tools
}

// refreshInfo 重算引擎目录快照(平台能力 + 是否已安装)
func (m *Manager) refreshInfo() {
	m.mu.Lock()
	dir := m.binDir
	m.mu.Unlock()
	tools := m.extractToolsFor()
	out := make([]Info, 0, len(catalog))
	for i := range catalog {
		s := &catalog[i]
		it := Info{
			Engine:    s.Engine,
			Display:   s.Display,
			Homepage:  s.Homepage,
			Note:      s.Note,
			DefaultOff: s.DefaultOff,
		}
		p, ok := pickPattern(s, runtime.GOOS, runtime.GOARCH)
		it.Supported = ok
		if !ok {
			it.Unsupported = fmt.Sprintf("官方未发布 %s/%s 平台的发行包", runtime.GOOS, runtime.GOARCH)
		} else if p.PinnedVer != "" {
			// 固定版本: 直接把真实文件名渲染出来(如 nmap-7.92-win32.zip), 比占位符更清楚
			it.AssetName = renderAsset(p, p.PinnedVer)
			it.LatestVersion = p.PinnedVer
		} else {
			it.AssetName = p.Name // 占位符形式, 版本未知时也能看出命名规则
		}
		it.NeedExtract = s.needExtractor && p.Ext == "exe" && runtime.GOOS == "windows"
		it.ExtractorReady = tools.Available()
		if it.NeedExtract && !it.ExtractorReady {
			it.Unsupported = "需要系统提供 7z/tar 才能从官方安装器中抽取可执行文件"
			it.Supported = false
		}
		// 已安装判定: 按 envdetect 的前缀口径扫一遍 bin/
		if p, found := findInstalled(dir, s.Want); found {
			it.Installed = true
			it.InstalledPath = p
		}
		// 运行时依赖预检: ZAP 是 Java 程序, 没有 Java 17+ 就**根本无法启动**
		// (实测: Java 8 下 zap.bat 抛 UnsupportedClassVersionError, class file version 61.0)。
		// 这里提前把结论标出来, 而不是等用户下完 273MB 才发现跑不了 —— 下载成本很高,
		// 失败必须尽可能早地暴露。
		if s.Engine == EngineZap {
			if ok, ver := javaRuntimeOK(); !ok {
				it.RuntimeMissing = fmt.Sprintf(
					"未检测到 Java 17+ (当前: %s)。ZAP 是 Java 程序, 官方跨平台包不含 Java, 请先安装 JDK/JRE 17 或更高版本",
					firstNonEmpty(ver, "未安装 Java"))
				// 没装 Java 时把 Supported 置 false: 前端据此禁用"安装"按钮, 避免用户白下 273MB。
				// 已安装的 ZAP 不降级 —— 用户仍应能"重新安装/卸载"来修复环境。
				//
				// 注意: 一旦置 false, **必须**给 Unsupported 一个原因。前端与测试都以
				// "不支持则必有原因"为口径(TestInfoPlatformMarking 断言的就是这条),
				// 否则用户看到按钮变灰却不知道为何。
				if !it.Installed {
					it.Supported = false
					it.Unsupported = "本机缺少 ZAP 运行所需的 Java 17+ 运行时, 装上也无法启动"
				}
			}
		}
		out = append(out, it)
	}
	m.mu.Lock()
	m.info = out
	m.mu.Unlock()
}

// findInstalled 在 bin/ 中按引擎约定的名字找已安装的可执行文件。
func findInstalled(dir string, w wantFile) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	// 套装引擎(nmap): 入口在 bin/<BundleName>/ 子目录内(可能还嵌一层归档前缀目录),
	// 不能只扫顶层文件 —— 否则装好了也判为"未安装", 界面上反复提示重新安装。
	if w.BundleDir {
		sub := filepath.Join(dir, bundleDirName(w))
		if p, ok := findExtracted(sub, w); ok {
			return p, true
		}
		// 隔离安装的目录名带 -engmgr-<时间戳> 后缀, 一并认下
		if es, err := os.ReadDir(dir); err == nil {
			prefix := bundleDirName(w) + "-engmgr-"
			for _, e := range es {
				if !e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
					continue
				}
				if p, ok := findExtracted(filepath.Join(dir, e.Name()), w); ok {
					return p, true
				}
			}
		}
		return "", false
	}
	var loose string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.ToLower(e.Name())
		if !isExecName(n) {
			continue
		}
		if w.InstallName != "" && n == strings.ToLower(w.InstallName) {
			return filepath.Join(dir, e.Name()), true
		}
		if loose == "" && entryMatches(n, w) {
			loose = filepath.Join(dir, e.Name())
		}
	}
	if loose != "" {
		return loose, true
	}
	return "", false
}

// bundleDirName 套装引擎在 bin/ 下的目录名(空 BundleName 时由 InstallName 去扩展名推得)
func bundleDirName(w wantFile) string {
	if w.BundleName != "" {
		return w.BundleName
	}
	return strings.TrimSuffix(w.InstallName, filepath.Ext(w.InstallName))
}

// Info 返回引擎目录快照(前端渲染用)
func (m *Manager) Info() []Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Info, len(m.info))
	copy(out, m.info)
	return out
}

// Progress 当前/上一次任务进度快照
func (m *Manager) Progress() (Progress, bool, []ItemResult, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]ItemResult, len(m.results))
	copy(res, m.results)
	return m.prog, m.running, res, m.lastErr
}

// Refresh 重扫既有信息(前端"重新检测"时调用)
func (m *Manager) Refresh() { m.refreshInfo() }

// Uninstall 删除 bin/ 下该引擎的可执行文件(仅删本模块约定的 InstalledName/前缀匹配项)。
// 返回删除的文件数。不递归删目录(避免误删用户放在 bin/ 里的其它资源)。
func (m *Manager) Uninstall(e Engine) (int, error) {
	s, err := FindEngine(e)
	if err != nil {
		return 0, err
	}
	dir := m.BinDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("引擎目录不可读: %w", err)
	}
	n := 0
	// 套装引擎(nmap): 整个 bin/<BundleName>/ 目录都属于本引擎, 连目录一起删。
	// 这里**必须是本引擎专属目录**才递归删 —— 目录名由本模块约定写死, 不会命中
	// 用户自己的目录, 因此不违反"不递归删目录"的一般原则。
	if s.Want.BundleDir {
		base := bundleDirName(s.Want)
		for _, en := range entries {
			if !en.IsDir() {
				continue
			}
			name := en.Name()
			if name != base && !strings.HasPrefix(name, base+"-engmgr-") {
				continue
			}
			p := filepath.Join(dir, name)
			if err := os.RemoveAll(p); err != nil {
				return n, fmt.Errorf("删除套装目录 %s 失败: %w", p, err)
			}
			n++
			m.log("引擎卸载: 已删除 " + p)
		}
		m.refreshInfo()
		return n, nil
	}
	for _, en := range entries {
		if en.IsDir() {
			continue
		}
		name := en.Name()
		low := strings.ToLower(name)
		if !isExecName(low) {
			continue
		}
		if !entryMatches(low, s.Want) && low != strings.ToLower(s.Want.InstallName) {
			continue
		}
		p := filepath.Join(dir, name)
		if err := os.Remove(p); err != nil {
			return n, fmt.Errorf("删除 %s 失败: %w", p, err)
		}
		n++
		m.log("引擎卸载: 已删除 " + p)
	}
	m.refreshInfo()
	if n == 0 {
		return 0, nil
	}
	return n, nil
}

// ===== 下载安装主流程 =====

// Install 下载并安装指定引擎(同步阻塞; 装配层放 goroutine 里跑并轮询 Progress)。
//
// engines 为空 = 按目录顺序安装全部"当前平台可下载且默认勾选"的引擎。
func (m *Manager) Install(engines []Engine, pf ProgressFunc) ([]ItemResult, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil, errors.New("已有引擎下载任务进行中")
	}
	m.running = true
	m.results = nil
	m.lastErr = ""
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	targets := engines
	if len(targets) == 0 {
		for i := range catalog {
			if catalog[i].DefaultOff == "" {
				targets = append(targets, catalog[i].Engine)
			}
		}
	}
	dir := m.BinDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("创建引擎目录失败: %w", err)
	}

	// 0) 镜像探测: 配置了多个镜像时先比出最快的那个再开始下载。
	//
	// 【为什么放在最前面、且只做一次】镜像速度是链路属性, 一批任务内不会变;
	// 每个引擎都探一遍纯属浪费。更重要的是用户明确要求"先检测再下载, 不行就
	// 停止并告知" —— 若所有镜像都不可用且配了镜像(说明用户本意是走镜像), 此时
	// 应当停下来告诉他, 而不是默默退回直连(直连大概率也会失败, 用户还以为是
	// 镜像没生效)。
	if mirs := m.mirrorPrefixes(); len(mirs) > 0 && mirrorProbeEnabled(len(mirs)) {
		m.setProgress(Progress{Status: StChecking, Total: len(targets), Done: 0,
			Phase: fmt.Sprintf("检测 %d 个下载镜像可用性", len(mirs)),
			StartedAt: time.Now().Format("2006-01-02 15:04:05")})
		pr := m.probeMirrors(mirs, "")
		if pr.Chosen != "" {
			SetGitHubMirror(pr.Chosen)
		} else {
			// 全部镜像不可用: 这是"配置了镜像却一个能用的都没有", 属于需要用户
			// 介入的状态。按用户要求停止并告知, 不再让每个引擎各自超时重试一遍。
			msg := m.mirrorFailureMsg(pr)
			m.mu.Lock()
			m.lastErr = msg
			m.mu.Unlock()
			return nil, errors.New(msg)
		}
	}

	var results []ItemResult
	for i, e := range targets {
		m.setProgress(Progress{Engine: e, Status: StQueued, Total: len(targets), Done: i,
			StartedAt: time.Now().Format("2006-01-02 15:04:05")})
		r := m.installOne(e, len(targets), i, pf)
		results = append(results, r)
		m.mu.Lock()
		m.results = append([]ItemResult(nil), results...)
		m.mu.Unlock()
		if !r.OK && !r.Skipped {
			m.log(fmt.Sprintf("引擎安装失败: %s - %s", r.Display, r.Error))
		}
	}
	m.refreshInfo()

	m.mu.Lock()
	prog := m.prog
	prog.Done = len(targets)
	if prog.Done > 0 {
		prog.Percent = 100
	}
	m.mu.Unlock()
	// 全部失败才算整体失败(部分成功是有价值的结果, 交给前端逐项展示)
	failed := 0
	for _, r := range results {
		if !r.OK && !r.Skipped {
			failed++
		}
	}
	if failed == len(results) && len(results) > 0 {
		err := fmt.Errorf("%d 个引擎全部安装失败, 详见逐项结果", failed)
		m.mu.Lock()
		m.lastErr = err.Error()
		m.mu.Unlock()
		return results, err
	}
	return results, nil
}

// installOne 安装单个引擎(下载 -> 解包 -> 落位), 任何一步失败只返回结果不 panic。
func (m *Manager) installOne(e Engine, total, done int, pf ProgressFunc) ItemResult {
	s, err := FindEngine(e)
	if err != nil {
		return ItemResult{Engine: e, Display: string(e), Error: err.Error()}
	}
	res := ItemResult{Engine: e, Display: s.Display, Homepage: s.Homepage}

	r0, err := latestRelease(s)
	if err != nil {
		res.Error = err.Error()
		res.HomepageNote = "自动下载不可用, 请从官方下载页获取"
		return res
	}
	pat, ok := pickPattern(s, runtime.GOOS, runtime.GOARCH)
	if !ok {
		res.Error = fmt.Sprintf("官方未发布 %s/%s 平台的发行包, 请从官方下载页获取", runtime.GOOS, runtime.GOARCH)
		res.HomepageNote = "该平台无官方免安装包"
		return res
	}
	needSFX := s.needExtractor && pat.Ext == "exe" && runtime.GOOS == "windows"
	if needSFX && !m.extractToolsFor().Available() {
		res.Error = "未在系统中找到 7z/tar, 无法从官方安装器中抽取可执行文件; 可安装 7-Zip 后重试, 或从官方下载页手动安装"
		res.HomepageNote = "需要 7-Zip 才能自动抽取"
		return res
	}

	// 1) 定版本: 固定版本(PinnedVer)直接用, 否则查上游最新。
	//
	// 固定版本用于上游已停止发布该格式的情况(nmap 的 Windows zip 停在 7.92)。
	// 此时**必须跳过上游查询**: 目录页最新是 7.991, 拿它拼 "nmap-7.991-win32.zip" 会 404
	// (该文件不存在), 表现为"下载失败"而不是"该格式已停发", 反而更难排查。
	var ver, tag string
	if pat.PinnedVer != "" {
		ver = pat.PinnedVer
		tag = ver
		m.log(fmt.Sprintf("引擎下载: %s 使用固定版本 %s(该平台包已停发, 不跟随上游最新)", s.Display, ver))
	} else {
		m.setProgress(Progress{Engine: e, Status: StChecking, Total: total, Done: done,
			Phase: "查询上游最新版本", StartedAt: time.Now().Format("2006-01-02 15:04:05")})
		var err error
		tag, err = m.latestTag(r0)
		if err != nil {
			res.Error = "查询最新版本失败: " + err.Error()
			res.HomepageNote = "网络不可达时请检查代理配置, 或从官方下载页获取"
			return res
		}
		ver, err = parseVersionFromTag(r0, tag)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		if pat.Ext == "exe" && runtime.GOOS == "windows" {
			// nmap 的 setup 文件名里带版本且 URL 无 tag 段(直挂 dist/ 目录)
			ver = normalizeNmapVer(r0, tag, ver)
		}
	}
	res.Version = ver
	fileName := renderAsset(pat, ver)
	dlURL := releaseURL(r0, tag, fileName)
	if r0.Owner == "nmap" || strings.Contains(r0.DownloadBase, "nmap.org") {
		// nmap.org 的路径不是 <base><tag>/<file>, 而是 <base><file>
		dlURL = r0.DownloadBase + fileName
	}

	// 2) 下载到暂存目录
	tmpDir := filepath.Join(m.BinDir(), ".engmgr-tmp")
	// 【本次踩坑】这里原本是 "RemoveAll 失败即整体失败"。但 Windows 上删除失败最常见的
	// 原因是**上一次运行(或杀软实时扫描)仍持有文件句柄**, 与"本次能不能装"毫无关系:
	// 实测现象是启动后 1 秒内报 "清理暂存目录失败: unlinkat ... .zip: The process cannot
	// access the file because it is being used by another process", 用户看到的是"引擎
	// 自动补装失败", 而真相只是残留文件删不掉 —— 一个可自愈的噪音被升级成了功能故障。
	// 正确处理: 删不掉就换成带时间戳的新暂存目录, 本次安装照常进行; 老目录留待下次清理
	// (它本来就只是临时区, 不参与落位判定)。只有"连新目录都建不出来"才算真失败。
	if err := os.RemoveAll(tmpDir); err != nil {
		alt := tmpDir + "-" + time.Now().Format("20060102-150405")
		m.log(fmt.Sprintf("引擎下载: 暂存目录被占用(%v), 改用 %s", err, filepath.Base(alt)))
		tmpDir = alt
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		res.Error = "创建暂存目录失败: " + err.Error()
		return res
	}
	defer os.RemoveAll(tmpDir)

	pkgPath := filepath.Join(tmpDir, fileName)
	blobPath := filepath.Join(m.BinDir(), ".engmgr-blobs", fileName)
	var dlErr error
	// 已下载过的包体直接复用(重试场景避免把 233MB 再下一遍)。
	//
	// 【本次踩坑 - 必须校验完整性】原判定只有 "文件存在且 Size()>0", 于是一个**下载中断
	// 留下的残片**会被永远当成完整包复用: 解包每次都失败、每次都复用同一个坏文件, 靠重试
	// 永远修不好。实测现象: bin/.engmgr-tmp 里躺着 215KB 的 trivy_*.zip(真实包 50MB+),
	// 启动后 1 秒内就报"解包失败", 而日志里既没有下载动作也看不出哪里不对。
	// 正确做法: 复用前先校验它能否被正常打开/读取, 读不通就丢弃并重新下载。
	if blobOK(blobPath, fileName) {
		m.log("引擎下载: 复用已缓存包体 " + blobPath)
		dlErr = copyLocal(blobPath, pkgPath, func(n int64, blobSize int64, speed int64) {
			prog := Progress{Engine: e, Status: StDownloading, Total: total, Done: done,
				Bytes: n, TotalB: blobSize, Percent: pct(n, blobSize), Speed: speed,
				Phase: "复用已缓存包体", Version: ver}
			m.setProgress(prog)
			if pf != nil {
				pf(prog)
			}
		})
	} else {
		if st, serr := os.Stat(blobPath); serr == nil {
			// 损坏缓存要删掉: 留着不仅永远不被复用, 还会持续占几百 MB 磁盘
			m.log(fmt.Sprintf("引擎下载: 缓存包体不完整(%d 字节, 疑似上次下载中断), 已丢弃并重新下载", st.Size()))
			_ = os.Remove(blobPath)
		}
		dlErr = m.download(dlURL, pkgPath, e, ver, total, done, pf)
	}
	if dlErr != nil {
		res.Error = fmt.Sprintf("下载失败: %v (地址 %s)", dlErr, dlURL)
		res.HomepageNote = "自动下载失败, 可从官方下载页获取后放入 bin/"
		return res
	}
	if st, serr := os.Stat(pkgPath); serr == nil {
		res.Bytes = st.Size()
		// 缓存包体, 便于失败重试(失败不删缓存, 由用户通过清理接口回收)
		if !strings.HasPrefix(pkgPath, blobPath) {
			_ = os.MkdirAll(filepath.Dir(blobPath), 0o755)
			_ = copyFileSimple(pkgPath, blobPath)
		}
	}

	// 3) 解包/抽取
	m.setProgress(Progress{Engine: e, Status: StExtracting, Total: total, Done: done,
		Phase: "解包并抽取可执行文件", Version: ver})
	if pf != nil {
		pf(m.getProg())
	}
	exePath, err := m.extract(pkgPath, pat, tmpDir, e)
	if err != nil {
		res.Error = "解包失败: " + err.Error()
		if needSFX {
			res.HomepageNote = "从官方安装器抽取失败(需 7-Zip), 可从官方下载页手动安装"
		}
		return res
	}

	// 4) 落位到 bin/
	m.setProgress(Progress{Engine: e, Status: StInstalling, Total: total, Done: done,
		Phase: "写入引擎目录", Version: ver})
	if pf != nil {
		pf(m.getProg())
	}
	installed, renameTo, err := m.place(exePath, s)
	if err != nil {
		res.Error = "写入引擎目录失败: " + err.Error()
		return res
	}
	res.OK = true
	res.Installed = installed
	res.RenameTo = renameTo
	if s.needExtractor && pat.Ext == "exe" {
		res.SkipReason = "" // SFX 抽取模式下无附加提示
	}

	// 5) ZAP 专属: 补装它运行所需的 JDK 17 并改写启动脚本。
	//
	// 【为什么放在 ZAP 这一支而不是做成一个"通用依赖"机制】目前只有 ZAP 有
	// 运行期外部依赖(其它三个引擎是静态二进制)。做成通用机制会引入一层没有第二个
	// 使用者的抽象, 反而更难读。等真出现第二个 Java 引擎再抽不迟。
	//
	// 【为什么失败不算 ZAP 安装失败】ZAP 的 273MB 文件已经完整落位了; 缺 Java 只是
	// 运行期依赖, 用户完全可以自己装个 Java 17 就用起来。把 JDK 的下载失败上升为
	// 整体失败, 会让一次网络抖动毁掉已经成功的 273MB —— 代价完全不对等。
	// 故这里只记录到 res.JDKNote 并写日志, res.OK 保持 true。
	if e == EngineZap && installed != "" {
		jdRes, jerr := m.ensureZapJDK(installed, ver, total, done, pf)
		switch {
		case jerr != nil:
			res.JDKNote = "ZAP 自带 JDK 未装成: " + jerr.Error() +
				" (ZAP 文件已就绪, 装上 Java 17+ 后即可使用)"
			m.log("ZAP 运行时: JDK 自动安装失败(不影响 ZAP 本体): " + jerr.Error())
		case jdRes.Skipped != "":
			res.JDKNote = jdRes.Skipped
			m.log("ZAP 运行时: " + jdRes.Skipped)
		default:
			res.JDKVersion = jdRes.Version
			res.JDKPath = jdRes.Path
			res.JDKNote = "已随 ZAP 装入自带 JDK " + jdRes.Version + ", 与系统 Java 隔离"
		}
		// 启动脚本改写放在 JDK 之后(且无论 JDK 成功与否都要做):
		// JDK 装好了 —— 脚本让 ZAP 用上它; JDK 没装成 —— 脚本会回落到 PATH 里的
		// java, 并提示"若启动失败请安装 Java 17+"。两种情况的脚本内容是同一份,
		// 因为它本来就是"有自带 JRE 就用, 没有就回落"的动态判定。
		if _, lerr := ensureZapLauncher(installed, m.log); lerr != nil {
			m.log("ZAP 启动脚本: 改写失败(不影响 ZAP 文件): " + lerr.Error())
		}
	}

	m.log(fmt.Sprintf("引擎安装完成: %s v%s -> %s", s.Display, ver, installed))
	return res
}

// normalizeNmapVer nmap 的 setup 文件名与 tag 都形如 nmap-7.991-setup.exe:
// tag 里带的是完整文件名片段, 需要把版本号单独取出来用于 {ver} 渲染。
func normalizeNmapVer(r release, tag, ver string) string {
	if strings.Contains(r.DownloadBase, "nmap.org") && strings.HasSuffix(ver, "-setup") {
		return strings.TrimSuffix(ver, "-setup")
	}
	if strings.Contains(r.DownloadBase, "nmap.org") && strings.HasSuffix(ver, "-win32") {
		return strings.TrimSuffix(ver, "-win32")
	}
	return ver
}

// extract 按包体扩展名选择解包方式。
func (m *Manager) extract(pkgPath string, pat assetPattern, workDir string, e Engine) (string, error) {
	s, err := FindEngine(e)
	if err != nil {
		return "", err
	}
	low := strings.ToLower(pkgPath)
	switch {
	case strings.HasSuffix(low, ".zip"):
		// 多文件套装(nmap)必须整包解出, 不能只抽主程序: 主程序依赖同目录的
		// DLL 与数据文件, 单抽会得到"能执行但启动即 0xC0000135"的残废引擎。
		if s.Want.BundleDir {
			sub := filepath.Join(workDir, "bundle")
			if err := os.MkdirAll(sub, 0o755); err != nil {
				return "", err
			}
			return extractBundleZip(pkgPath, sub, s.Want)
		}
		return extractFromZip(pkgPath, workDir, s.Want)
	case strings.HasSuffix(low, ".tar.gz") || strings.HasSuffix(low, ".tgz"):
		return extractFromTarGz(pkgPath, workDir, s.Want)
	case strings.HasSuffix(low, ".gz"):
		return extractFromGz(pkgPath, workDir, s.Want)
	case strings.HasSuffix(low, ".exe"):
		sub := filepath.Join(workDir, "sfx")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return "", err
		}
		return extractFromSFX(pkgPath, sub, s.Want, m.extractToolsFor())
	case strings.HasSuffix(low, ".dmg"):
		return "", errors.New("macOS 官方仅提供 dmg 镜像, 请手动安装后把可执行文件放入 bin/")
	default:
		return "", fmt.Errorf("不支持的包格式: %s", filepath.Base(pkgPath))
	}
}

// place 把解包出的可执行文件放进 bin/, 返回 (最终路径, 隔离重命名后的名字, error)。
//
// 命名冲突处理见文件头注释第 1 点: 冲突时隔离安装, 不覆盖用户文件。
func (m *Manager) place(src string, s *engineSpecEntry) (string, string, error) {
	if s.Want.BundleDir {
		return m.placeBundle(src, s)
	}
	dir := m.BinDir()
	target := filepath.Join(dir, s.Want.InstallName)
	if _, err := os.Stat(target); err == nil {
		// 已存在: 生成隔离名 <name>-engmgr-<时间戳><ext>, 不覆盖
		ext := filepath.Ext(s.Want.InstallName)
		base := strings.TrimSuffix(s.Want.InstallName, ext)
		alt := fmt.Sprintf("%s-engmgr-%s%s", base, time.Now().Format("20060102-150405"), ext)
		target = filepath.Join(dir, alt)
		m.log("引擎安装: 目标名已存在, 隔离安装为 " + filepath.Base(target))
		// 同一次安装允许覆盖自己刚隔离出来的文件(重试场景)
		_ = os.Remove(target)
		if err := copyFileSimple(src, target); err != nil {
			return "", "", err
		}
		return target, filepath.Base(target), nil
	}
	// 不存在: 直接 rename(同盘原子, 避免大文件二次拷贝)
	_ = os.Chmod(src, executablePerm)
	if err := os.Rename(src, target); err != nil {
		// rename 可能因跨设备失败, 回退到拷贝
		if cerr := copyFileSimple(src, target); cerr != nil {
			return "", "", fmt.Errorf("rename 与 copy 均失败: %v / %v", err, cerr)
		}
	}
	return target, "", nil
}

// placeBundle 整包落位(多文件套装): 把解包目录整体搬到 bin/<BundleName>/,
// 返回入口程序路径。
//
// 【为什么用目录整体 rename 而不是逐个文件拷贝】套装里有几十个文件、总共几十 MB,
// 逐个拷贝既慢又要处理"半途失败留下半个目录"的脏状态。整个目录 rename 是**同盘原子
// 操作**: 要么全到位, 要么原样不动 —— 与单文件路径下 place 的语义一致。
//
// 【冲突处理】目标目录已存在时同样不覆盖用户文件(见文件头注释第 1 点), 改为带时间戳
// 的隔离目录名。这里必须先 RemoveAll 隔离名(可能来自上一次失败重试), 否则 rename
// 在 Windows 上会因"目标已存在"直接失败。
//
// src 是解包出的 bundle 根目录, 其内部保留归档原始结构(可能有一层 nmap-7.92/ 前缀),
// 这对 nmap 无害: nmap.exe 用相对自身目录查找资源文件, 前缀层不影响。
func (m *Manager) placeBundle(src string, s *engineSpecEntry) (string, string, error) {
	// 防御: src 必须是"解包根目录"。若拿到的是文件(上游 extract 语义被改错时会这样),
	// 直接报错而不是把它 rename 成一个同名文件 —— 后者会静默丢掉全部依赖文件,
	// 且错误信息会误导成"目录内找不到入口", 极难定位(实测踩过)。
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		return "", "", fmt.Errorf("套装落位需要目录, 实际得到 %s(非目录)", src)
	}
	dir := m.BinDir()
	name := s.Want.BundleName
	if name == "" {
		ext := filepath.Ext(s.Want.InstallName)
		name = strings.TrimSuffix(s.Want.InstallName, ext)
	}
	// 目标路径若被上次失败留下的**同名文件**占着, rename 到目录会失败; 先清掉。
	// (正常情况不该出现 —— 但 0xC0000135 那次故障恰好留下了 bin/nmapcore 这个文件)
	if st, err := os.Lstat(filepath.Join(dir, name)); err == nil && !st.IsDir() {
		m.log("引擎安装: 清理同名残留文件 " + name)
		_ = os.Remove(filepath.Join(dir, name))
	}
	target := filepath.Join(dir, name)
	renameTo := ""
	if _, err := os.Stat(target); err == nil {
		alt := fmt.Sprintf("%s-engmgr-%s", name, time.Now().Format("20060102-150405"))
		target = filepath.Join(dir, alt)
		renameTo = alt
		m.log("引擎安装: 套装目录已存在, 隔离安装为 " + alt)
	}
	_ = os.RemoveAll(target) // 同一次安装允许覆盖自己刚隔离出来的目录(重试场景)
	if err := os.Rename(src, target); err != nil {
		// rename 可能因跨设备失败, 回退到递归拷贝
		if cerr := copyDirRecursive(src, target); cerr != nil {
			return "", "", fmt.Errorf("套装目录 rename 与 copy 均失败: %v / %v", err, cerr)
		}
	}
	// 入口程序 = 目录内匹配到的那个可执行文件(extractBundleZip 已校验存在)
	entry, ok := findExtracted(target, s.Want)
	if !ok {
		return "", "", fmt.Errorf("套装目录 %s 内未找到入口可执行文件 %s", filepath.Base(target), s.Want.WantName)
	}
	_ = os.Chmod(entry, executablePerm)
	return entry, renameTo, nil
}

// copyDirRecursive 递归拷贝目录(placeBundle 的跨设备回退路径)。
// 保留归档内的相对结构; 可执行文件的 x 位由调用方在落位后统一补。
func copyDirRecursive(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode().Perm()|0o644)
	})
}

// setProgress 写进度并回调
func (m *Manager) setProgress(p Progress) {
	m.mu.Lock()
	// 保留累计字段: 单次调用只更新自己关心的字段
	if p.StartedAt == "" {
		p.StartedAt = m.prog.StartedAt
	}
	m.prog = p
	m.mu.Unlock()
}

func (m *Manager) getProg() Progress {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prog
}

// pct 计算百分比; total<=0 时返回 -1(未知)
func pct(n, total int64) int {
	if total <= 0 {
		return -1
	}
	if n >= total {
		return 100
	}
	if n <= 0 {
		return 0
	}
	return int(n * 100 / total)
}

// download 流式下载并上报进度(带速度滑动窗口)。
func (m *Manager) download(rawURL, dest string, e Engine, ver string, total, done int, pf ProgressFunc) error {
	req, err := http.NewRequest(http.MethodGet, applyMirror(rawURL), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Yugsight-EngMgr/1.0")
	// 总时长不限(0): 慢速链路(实测 nmap.org ~188KB/s)下 50MB 包要十几分钟,
	// 设总上限会在快下完时把请求砍断, 表现为 "unexpected EOF" 或 "下载不完整"。
	// 卡死风险由 Transport 的 TLSHandshakeTimeout/DialTimeout 与下面的停顿看门狗覆盖。
	resp, err := m.newClient(0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	size := resp.ContentLength
	var got int64
	lastT := time.Now()
	var lastN int64
	var speed int64
	buf := make([]byte, 128<<10)

	// 停顿看门狗: 不限总时长的代价是"链路悄悄死掉就永远等下去", 表现为界面
	// 一直显示"下载中 xx%"却再也不涨。这里用一个独立计时器兜底 —— 只要
	// 连续 60s 没有任何新字节就判定链路已死, 关闭 Body 让阻塞中的 Read 立即
	// 返回错误(Go 的 http 会在 Body.Close 时中断读取), 避免线程永久挂住。
	const stallLimit = 60 * time.Second
	stall := time.AfterFunc(stallLimit, func() { _ = resp.Body.Close() })
	defer stall.Stop()
	kick := func() { stall.Reset(stallLimit) }

	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			kick() // 有字节到达 = 链路仍活着, 重置看门狗
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			got += int64(n)
			// 每累计 1MB 或间隔 >0.3s 上报一次, 避免高频回调打爆前端轮询
			if now := time.Now(); now.Sub(lastT) > 300*time.Millisecond {
				dt := now.Sub(lastT).Seconds()
				if dt > 0 {
					speed = int64(float64(got-lastN) / dt)
				}
				lastT, lastN = now, got
				prog := Progress{Engine: e, Status: StDownloading, Total: total, Done: done,
					Bytes: got, TotalB: size, Percent: pct(got, size), Speed: speed,
					Phase: "下载中", Version: ver}
				m.setProgress(prog)
				if pf != nil {
					pf(prog)
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			// 看门狗已触发 = 不是对端断开, 而是长时间零字节。原始错误通常是
			// "http: read on closed response body" 这类没有指向性的文本, 换成
			// 能指导用户行动的说法(换镜像/配代理/稍后重试)。
			if !stall.Stop() {
				return fmt.Errorf("下载停滞超 %s 无数据, 已中断(已下 %d 字节); 可换 githubMirror 或配置 proxy 后重试", stallLimit, got)
			}
			return rerr
		}
	}
	// 长度校验: 上游给了 Content-Length 就必须一致, 否则视为半截文件
	if size > 0 && got != size {
		return fmt.Errorf("下载不完整(期望 %d 字节, 实得 %d 字节)", size, got)
	}
	prog := Progress{Engine: e, Status: StDownloading, Total: total, Done: done,
		Bytes: got, TotalB: size, Percent: 100, Speed: speed, Phase: "下载完成", Version: ver}
	m.setProgress(prog)
	if pf != nil {
		pf(prog)
	}
	return nil
}

// copyLocal 复用已缓存包体(上报进度以便前端看到"仍在进行")
func copyLocal(src, dst string, report func(n, total, speed int64)) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 1<<20)
	var got int64
	lastT := time.Now()
	var lastN int64
	var speed int64
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			got += int64(n)
			if now := time.Now(); now.Sub(lastT) > 300*time.Millisecond {
				if dt := now.Sub(lastT).Seconds(); dt > 0 {
					speed = int64(float64(got-lastN) / dt)
				}
				lastT, lastN = now, got
				if report != nil {
					report(got, st.Size(), speed)
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if report != nil {
		report(got, st.Size(), speed)
	}
	return out.Close()
}

// copyFileSimple 整文件拷贝(小文件/回退路径)
func copyFileSimple(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, in, executablePerm)
}

// BlobCacheSize 返回已缓存包体占用的字节数与文件数(前端展示/清理提示)
func (m *Manager) BlobCacheSize() (int64, int) {
	dir := filepath.Join(m.BinDir(), ".engmgr-blobs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	var total int64
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if st, err := e.Info(); err == nil {
			total += st.Size()
			n++
		}
	}
	return total, n
}

// ClearBlobCache 清理下载缓存(失败重试后回收空间)
func (m *Manager) ClearBlobCache() error {
	dir := filepath.Join(m.BinDir(), ".engmgr-blobs")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	m.log("引擎下载: 已清理包体缓存")
	return nil
}

// ===== 下载通道配置(代理 / GitHub 镜像) =====

var (
	dlCfgMu        sync.RWMutex
	dlProxy        string
	dlGitHubMirror string
	// dlMirrorRaw 保存配置里的**原始**值(可能含多个候选, 逗号分隔)。
	// GitHubMirror 只用其中一个生效前缀, 探测需要知道全部候选, 故单独留一份。
	dlMirrorRaw string
)

// SetProxy 设置引擎下载代理(空 = 直连或系统代理)。
//
// 与规则库更新器共用同一个代理配置来源(engine.json 的 downloads.proxy), 但各自
// 持有副本: 规则库更新器支持"运行中改配置", 引擎下载是一次性长任务, 中途改代理
// 只会让请求行为不可预测 —— 这里只在任务开始时读取一次。
func SetProxy(proxy string) {
	dlCfgMu.Lock()
	dlProxy = strings.TrimSpace(proxy)
	dlCfgMu.Unlock()
}

// SetGitHubMirror 设置 GitHub 下载镜像前缀(如 "https://ghproxy.example.com/")。
//
// 为什么做成"前缀拼接"而不是"预设若干镜像": 镜像站可用性变化很快, 硬编码的列表
// 三个月后大概率一半是死的; 而且镜像内容不可控(下载的是要装进 bin/ 执行的二进制),
// 默认引入第三方镜像等于默认引入供应链风险 —— 所以留配置项, 但不预置具体镜像。
//
// 拼接规则: mirror + 原始完整 URL(主流加速服务的通用形式)。
func SetGitHubMirror(mirror string) {
	raw := strings.TrimSpace(mirror)
	// 支持配多个候选(逗号/分号/空白分隔): "https://a/, https://b/"。
	// 生效值先用第一个, 真正的选择权交给 download 前的镜像探测(见 Install)。
	// 这样用户既可以直接写死一个, 也可以写一串让程序自动挑最快的。
	mirror = raw
	if list := splitMirrors(raw); len(list) > 0 {
		mirror = list[0]
	}
	if mirror != "" && !strings.HasSuffix(mirror, "/") {
		mirror += "/"
	}
	dlCfgMu.Lock()
	dlGitHubMirror = mirror
	dlMirrorRaw = raw
	dlCfgMu.Unlock()
}

// mirrorPrefixes 返回配置里声明的全部镜像候选(已规范化)。
// 探测失败时会调用 SetGitHubMirror(选中的单个)覆盖生效值, 但候选集要保留原样,
// 否则第二次安装就只剩一个候选、无法再比速度。
func (m *Manager) mirrorPrefixes() []string {
	dlCfgMu.RLock()
	raw := dlMirrorRaw
	cur := dlGitHubMirror
	dlCfgMu.RUnlock()
	if list := splitMirrors(raw); len(list) > 0 {
		return list
	}
	if cur != "" {
		return []string{cur}
	}
	return nil
}

// mirrorFailureMsg 组装"所有镜像都不可用"的用户可读说明。
//
// 光说"失败"没用 —— 用户需要知道的是: 哪几个镜像试过了、各自怎么失败的、
// 接下来能做什么(换镜像/配代理/直连)。失败信息的作用是指导下一步动作。
func (m *Manager) mirrorFailureMsg(pr *probeResult) string {
	var b strings.Builder
	b.WriteString("所有下载镜像均不可用, 已停止安装。")
	if pr != nil && len(pr.Candidates) > 0 {
		b.WriteString(" 探测结果: ")
		for i, c := range pr.Candidates {
			if i > 0 {
				b.WriteString("; ")
			}
			if c.OK {
				b.WriteString(fmt.Sprintf("%s 可用(%dKB/s)", c.Prefix, c.Speed/1024))
			} else {
				b.WriteString(fmt.Sprintf("%s %s", c.Prefix, c.Error))
			}
		}
	}
	b.WriteString(" 可在 exe 同目录 engine.json 的 downloads.githubMirror 里换一个镜像")
	b.WriteString("(可写多个, 逗号分隔, 程序会自动选最快的), 或配置 downloads.proxy 走代理。")
	return b.String()
}

// applyMirror 按配置把 GitHub 地址改写成镜像地址(非 GitHub 地址原样返回)
func applyMirror(raw string) string {
	dlCfgMu.RLock()
	m := dlGitHubMirror
	dlCfgMu.RUnlock()
	if m == "" || !isGitHubURL(raw) {
		return raw
	}
	return m + raw
}

// CurrentMirror 返回当前生效的镜像前缀(空 = 直连)。供状态接口展示"实际在用哪个"。
func CurrentMirror() string {
	dlCfgMu.RLock()
	defer dlCfgMu.RUnlock()
	return dlGitHubMirror
}

// MirrorCandidates 返回配置声明的全部候选(供状态接口展示"配了几个、将探测")
func MirrorCandidates() []string {
	dlCfgMu.RLock()
	raw := dlMirrorRaw
	dlCfgMu.RUnlock()
	return splitMirrors(raw)
}

// newClient 构造下载用 HTTP 客户端(按当前代理配置)。
//
// 【为什么必须 Clone 默认 Transport, 而不是 `&http.Transport{Proxy: ...}`】
// 直接字面量构造会把**所有未显式赋值的字段清零**, 包括 Go 为 DefaultTransport
// 设定的关键默认值:
//
//	TLSHandshakeTimeout   0(永不超时)   —— 握手挂起时整个下载永久卡死
//	ExpectContinueTimeout 0            —— 大文件上传/长连接协商异常
//	IdleConnTimeout       0(不回收)     —— 连接泄漏
//	MaxIdleConnsPerHost   0            —— 不复用连接, 每次重新 TLS 握手
//	DialContext           nil          —— 走裸 net.Dial, 无 keep-alive/无双栈优选
//
// 实测症状(2026-09-17, nmap.org): 手工 Transport 下 37MB 的 nmap 安装包反复在
// 4~5MB 处 `unexpected EOF`; 同样的网络用浏览器/脚本能稳定跑到 ~188KB/s 下完。
// 换成 Clone() 后保留标准库的连接复用与超时策略, 长链路才稳。
//
// Client.Timeout 传 0 表示不限制**总时长**(仅由各阶段超时约束): 大包(50MB+)在
// 慢速链路上需要十几分钟, 给总时长设上限等于给慢用户判死刑。原先传 30min 也会
// 在差网络下把未下完的请求直接砍断。
func (m *Manager) newClient(timeout time.Duration) *http.Client {
	dlCfgMu.RLock()
	proxy := dlProxy
	dlCfgMu.RUnlock()
	// Clone 标准 Transport: 继承全部默认值(超时/连接池/keep-alive), 再按需覆盖
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		tr = &http.Transport{}
	}
	tr = tr.Clone()
	// 代理留空 = 回落到环境变量 HTTP_PROXY / HTTPS_PROXY(推荐):
	// 用户改环境变量后无需改配置文件; 代理关闭(环境变量清空)即自动直连。
	// 不直接用 http.ProxyFromEnvironment: 它把首次结果缓存在 sync.Once 里且无公开
	// 失效接口, 导致改了环境变量"看起来没生效"; envProxyFunc 每次实时读取。
	tr.Proxy = envProxyFunc(m.log)
	if proxy != "" {
		// 缺 scheme 时补 http://, 否则 url.Parse 会把 127.0.0.1 当协议, 代理静默失效
		if !strings.Contains(proxy, "://") {
			proxy = "http://" + proxy
		}
		if u, err := url.Parse(proxy); err == nil && u.Host != "" {
			tr.Proxy = http.ProxyURL(u)
		} else {
			m.log("引擎下载: 代理地址非法, 已忽略: " + proxy)
		}
	}
	// 放大空闲连接池: 一次安装会顺序下多个引擎, 复用连接省掉重复 TLS 握手
	if tr.MaxIdleConnsPerHost < 4 {
		tr.MaxIdleConnsPerHost = 4
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// ExtractToolNames 系统可用的解包工具名(供前端提示"需要 7-Zip")
func ExtractToolNames() []string { return DetectExtractTools().Names() }

// ===== 上游版本查询 =====

// latestTag 查询上游最新 tag。
//
// GitHub 走 Releases API(tag_name 字段); nmap 这种没有 GitHub Release 的源走
// 目录页正则抓取(URL 与正则都在 catalog 里显式声明, 不在这里硬编码)。
//
// 【GitHub API 限流的两级回退 —— 这是一次真实故障的修复】
// api.github.com 对匿名请求限 60 次/小时/IP 且按 IP 共享, 配额一空就恒返 403。
// 实测用户环境: X-RateLimit-Remaining=0, 走代理也一样(限的是 IP 不是网络路径),
// 表现为"查询最新版本失败: HTTP 403" —— 而这个失败**完全不该阻断安装**, 因为
// 真正的下载地址在 github.com 上, 不受 API 限流。故:
//
//	第 1 级: API 正常 -> 直接取 tag_name(最准确, 能拿到 prerelease 排除等语义);
//	第 2 级: API 失败(403/超时/无 tag_name) -> 用 LatestPageURL 走 releases/latest
//	        页面, 读 **302 重定向后的最终 URL**, 末段即 tag。零配额、零鉴权。
//
// 两级都失败才报错, 且错误信息里带上"两条路都试过了 + 各自原因", 便于用户判断
// 是网络问题还是上游改版。
func (m *Manager) latestTag(r release) (string, error) {
	isAPI := strings.Contains(r.LatestURL, "api.github.com")

	if isAPI {
		body, err := m.fetchText(r.LatestURL)
		if err == nil {
			if tag := jsonField(body, "tag_name"); tag != "" {
				return tag, nil
			}
			err = errors.New("响应缺少 tag_name 字段")
		}
		// API 通道失败 -> 回退到非 API 的 releases/latest 页面
		if r.LatestPageURL == "" {
			return "", fmt.Errorf("GitHub API 查询失败(%v), 且未配置回退地址", err)
		}
		m.log("引擎下载: GitHub API 不可用(" + shortErr(err) + "), 改用 releases/latest 网页通道")
		tag, perr := m.latestTagFromRedirect(r.LatestPageURL)
		if perr != nil {
			return "", fmt.Errorf("GitHub API 与网页通道均失败(API: %v; 网页: %v)", err, perr)
		}
		return tag, nil
	}

	body, err := m.fetchText(r.LatestURL)
	if err != nil {
		return "", err
	}
	// 目录页(nmap.org/dist/): 用 catalog 声明的正则扫出全部版本号, 取最大者。
	// 目录页里同时存在旧版本(7.92 的 win32.zip 等), 所以不能取"第一个匹配" ——
	// 列表是按时间倒序但混着 beta/旧包, 取最大值最稳。
	ms := r.TagRe.FindAllStringSubmatch(string(body), -1)
	if len(ms) == 0 {
		return "", fmt.Errorf("未在 %s 找到版本信息", r.LatestURL)
	}
	best := ""
	for _, mm := range ms {
		if len(mm) < 2 || mm[1] == "" {
			continue
		}
		if versionAtLeast(mm[1], best) {
			best = mm[1]
		}
	}
	if best == "" {
		return "", fmt.Errorf("未在 %s 解析出版本号", r.LatestURL)
	}
	// 返回完整匹配串(nmap-7.991): parseVersionFromTag 会从中再取一次版本号,
	// 调用方拿它拼文件名时还需要 "nmap-<ver>-setup.exe" 这种形态。
	return "nmap-" + best, nil
}

// latestTagFromRedirect 用 GitHub 的 releases/latest **网页**拿最新 tag:
// 该地址会 302 到 /releases/tag/<tag>, 取最终 URL 的末段即可。
//
// 【为什么能绕开限流】api.github.com 与 github.com 是两套独立的服务与配额:
// 前者匿名 60 次/小时/IP, 后者不限量。而引擎包的下载本来就依赖 github.com 可达
// (DownloadBase 就指向它), 所以"能下载 => 就能用这条路查版本", 二者可用性一致。
//
// 【为什么不用 atom feed(releases.atom)】实测该 feed 里混着 nightly 版本
// (如 w2026-09-15 这类每周构建), 取"第一条"会拿到 nightly 而不是稳定版;
// 而 releases/latest 在 GitHub 语义上就是"最新一个**非 prerelease**发布", 与 API
// 的 latest 完全等价, 不需要自己再排除 nightly。
func (m *Manager) latestTagFromRedirect(pageURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, applyMirror(pageURL), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Yugsight-EngMgr/1.0")
	req.Header.Set("Accept", "text/html")
	// 关键: 手动接管重定向 —— 我们要的正是 Location 里的 tag, 若让 http.Client
	// 自动跟完, 最终响应体是整个 release 页面(几百 KB), 还得再去 HTML 里正则捞 tag,
	// 既慢又脆(页面结构一改就废)。这里只取第一跳的 Location, 不读 body。
	var target string
	cli := m.newClient(20 * time.Second)
	cli.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		// 只认第一跳; via 长度 >1 说明已在跟第二跳, 直接终止
		if len(via) >= 1 {
			target = r.URL.String()
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := cli.Do(req)
	if err != nil {
		return "", shortErrToErr(err)
	}
	defer resp.Body.Close()
	// 两种情况都要处理: 未跟重定向(3xx, 手动留下) 或 已跟到最终页(200)
	if target == "" {
		if resp.Request != nil && resp.Request.URL != nil {
			target = resp.Request.URL.String()
		}
	}
	if target == "" {
		return "", fmt.Errorf("HTTP %d(未取得重定向地址)", resp.StatusCode)
	}
	return parseTagFromReleaseURL(target)
}

// parseTagFromReleaseURL 从 GitHub release 页面地址里取 tag(纯函数, 便于单测)。
// 形如 .../releases/tag/v2.17.0 -> v2.17.0; 不含该段或 tag 为空则报错(不猜)。
func parseTagFromReleaseURL(u string) (string, error) {
	const seg = "/releases/tag/"
	i := strings.LastIndex(u, seg)
	if i < 0 {
		return "", fmt.Errorf("地址不含 %s: %s", seg, u)
	}
	tag := strings.Trim(u[i+len(seg):], "/")
	if tag == "" {
		return "", errors.New("地址里 tag 为空")
	}
	// 带查询串/锚点时截断(如 /releases/tag/v2.17.0?expanded=true)
	if j := strings.IndexAny(tag, "?#"); j >= 0 {
		tag = tag[:j]
	}
	if tag == "" {
		return "", errors.New("地址里 tag 为空")
	}
	return tag, nil
}

// shortErrToErr 把 shortErr 的字符串包成 error(保留统一的错误压缩口径)
func shortErrToErr(err error) error {
	return errors.New(shortErr(err))
}

// fetchText 拉取一个文本/JSON 资源(限制大小, 20s 超时)
func (m *Manager) fetchText(raw string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, applyMirror(raw), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Yugsight-EngMgr/1.0")
	req.Header.Set("Accept", "application/vnd.github+json, text/html")
	resp, err := m.newClient(20 * time.Second).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// jsonField 从 JSON 文本里取出顶层字符串字段。
//
// 为什么不用 encoding/json: 只为取 1 个字段而定义 struct 会让 catalog 与
// 解析逻辑分家(上游加字段就要改两处); 这里用"键 -> 引号内字符串"的最小解析,
// 失败时返回空串由调用方给出明确错误。
func jsonField(body, key string) string {
	k := `"` + key + `"`
	i := strings.Index(body, k)
	if i < 0 {
		return ""
	}
	rest := body[i+len(k):]
	j := strings.Index(rest, ":")
	if j < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[j+1:])
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	if e := strings.Index(rest, `"`); e >= 0 {
		return rest[:e]
	}
	return ""
}

// isGitHubURL 判断是否"可被镜像加速的 GitHub 下载域名"。
//
// 【刻意排除 api.github.com】曾试过把 API 域名也纳入镜像改写, 想着"受限网络里 API
// 与下载一起被拦"; 实测(2026-09)主流加速服务 ghfast.top 对 API 路径返回 403 ——
// 它们只代理 release/源码下载, 不代理 REST API。所以纳入 API 会直接把"能用的直连
// 查询"改成"被镜像拒绝", 反而更糟。API 限速(60 次/小时)只能靠代理或等配额恢复,
// 不由镜像解决; 报错信息里已给出明确提示。
func isGitHubURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Host)
	// codeload 是源码包下载域(codeload.github.com), 属于可加速范围
	return strings.HasSuffix(h, "github.com") || strings.HasSuffix(h, "githubusercontent.com")
}
