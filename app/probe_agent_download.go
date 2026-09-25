// probe_agent_download.go 探针 agent 分发: 中心端向用户提供各平台 agent 安装包下载。
//
// 为什么单独成文件(项目规则 1: 新增功能优先独立文件):
//
//	探针端 yugsight-agent 是独立二进制(见 cmd/agent), 要装到多台被扫描机器上,
//	但此前只能靠用户手工拷贝文件 + 手写 probe.json, 部署门槛高。本文件在既有
//	探针 API 组(token 管理、在线状态)之外补上"分发"这一环, probe_api.go 只加
//	一条路由注册, 既有接口与扫描流程零改动。
//
// 设计要点:
//
//  1. 二进制不打包进主程序: 单个 agent 约 6-7MB, 四平台全嵌入会让中心端 exe
//     凭空膨胀 25MB 以上, 且升级 agent 就得重新编译中心端。改为运行时从
//     exe 同目录 agents/ 目录读取(与 bin/ 外部引擎、templates/ 模板同一约定)。
//  2. 目录缺失/文件不存在一律降级: 接口返回"未分发"而不是 500/panic(规则 3/4),
//     前端据此展示部署指引, 不会误以为功能坏了。
//  3. 文件名兼容主程序与独立程序两种命名: 显式约定 yugsight-agent_{os}_{arch}[.exe],
//     同时前缀匹配 yugsight_agent_/agent_ 等常见手改写法(与 rule_updater 的
//     命名容忍风格一致), 降低"我明明放了文件却提示缺失"的困惑。
//  4. 防目录穿越: os/arch 只允许白名单取值, 文件名由白名单拼出后仍校验 base,
//     确保不越出 agents/ 目录(接口虽走 requireAuth, 但白名单是更强的不变式)。
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"yugsight/internal/agentpkg"
	"yugsight/internal/probe"
	"yugsight/internal/scanner"
	"yugsight/internal/server"
)

// ===== 平台矩阵 =====

// agentPlatforms 支持分发的平台矩阵。
//
// 只列 go build 能交叉编译出的常用组合(见各任务的交叉编译验证口径):
// linux/amd64+arm64(服务器)、windows/amd64+arm64(办公终端)、darwin/amd64+arm64(macOS)。
// 未列入的组合(如 freebsd)由用户自行本地编译, 不在此枚举 —— 白名单越短越安全。
var agentPlatforms = []struct {
	OS      string
	Arch    string
	Label   string // 平台展示名
	Install string // 部署与启动命令(前端直接展示给用户)
}{
	// Windows 走"双击自安装": 装到 C:\YugsightAgent + 注册开机自启 + 弹框填中心端地址,
	// 不需要命令行(见 cmd/agent/install_windows.go)。
	{"windows", "amd64", "Windows x64", "双击运行: 自动安装到 C:\\YugsightAgent 并注册开机自启, 按弹窗填写中心端地址"},
	{"windows", "arm64", "Windows ARM64", "双击运行: 自动安装到 C:\\YugsightAgent 并注册开机自启, 按弹窗填写中心端地址"},
	{"linux", "amd64", "Linux x64", "./yugsight-agent -center <中心端IP>:8600 -token <节点密钥>"},
	{"linux", "arm64", "Linux ARM64", "./yugsight-agent -center <中心端IP>:8600 -token <节点密钥>"},
	{"darwin", "amd64", "macOS Intel", "./yugsight-agent -center <中心端IP>:8600 -token <节点密钥>"},
	{"darwin", "arm64", "macOS Apple Silicon", "./yugsight-agent -center <中心端IP>:8600 -token <节点密钥>"},
}

// agentNamePrefixes 文件名可接受的前缀(按优先级)。
//
// 主约定是 yugsight-agent, 其余为常见手写变体: 用户手动 `go build -o` 时很容易
// 写成 yugsight_agent_linux_amd64 / agent_linux_amd64, 前缀匹配可避免"放了文件
// 却提示未分发"的错判。带 - 的优先(标准命名), 顺序即优先级。
var agentNamePrefixes = []string{"yugsight-agent", "yugsight_agent", "yugsightagent", "agent"}

// agentDownloadDir agent 安装包目录(exe 同目录 agents/)。
//
// 声明为变量(非函数)以便测试改指临时目录 —— 与 reportCfgPath、rulesExternalDir
// 同一手法, 否则用例一跑就会去读开发机真实目录, 断言随环境漂移。
var agentDownloadDir = func() string {
	exe, err := os.Executable()
	if err != nil {
		return "agents"
	}
	return filepath.Join(filepath.Dir(exe), "agents")
}

// ===== 平台解析与文件定位 =====

// agentPlatform 按 os/arch 取平台定义; 不在矩阵内返回 false。
func agentPlatform(osName, arch string) (string, string, string, string, bool) {
	o := strings.ToLower(strings.TrimSpace(osName))
	a := strings.ToLower(strings.TrimSpace(arch))
	for _, p := range agentPlatforms {
		if p.OS == o && p.Arch == a {
			return p.OS, p.Arch, p.Label, p.Install, true
		}
	}
	return "", "", "", "", false
}

// findAgentBinary 在 agents/ 目录中定位指定平台的 agent 二进制。
//
// 返回 (路径, 文件名, 是否存在)。顺序:
//  1. 显式约定名 yugsight-agent_{os}_{arch}[.exe](精确命中优先);
//  2. 逐个前缀做**词边界**匹配(如 yugsight-agent_linux_amd64 命中 yugsight-agent)。
//
// 为什么要求词边界而不是裸 strings.HasPrefix: 前缀 yugsight-agent 会命中
// "yugsight-agent-linux-amd64-v2"(可接受)也会命中 "yugsight-agents"(不该命中),
// 词边界(下个字符是 _ . - 或结尾)把这类误判挡掉, 同时保留版本后缀的容忍度。
// 扩展名容忍 .exe / .bin(用户在 Linux 上手动改名很常见)。
func findAgentBinary(osName, arch string) (string, string, bool) {
	dir := agentDownloadDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", false // 目录不存在 = 未分发(正常降级, 不记错误日志刷屏)
	}
	platToken := osName + "_" + arch // yugsight-agent_linux_amd64

	// 第一轮: 精确约定名
	for _, prefix := range agentNamePrefixes {
		want := []string{
			prefix + "_" + platToken,
			prefix + "-" + osName + "-" + arch,
		}
		for _, base := range want {
			for _, ext := range []string{"", ".exe", ".bin"} {
				if p, name, ok := agentFileIn(dir, entries, base+ext); ok {
					return p, name, true
				}
			}
		}
	}
	// 第二轮: 前缀 + 词边界(容忍 -v1.0.0 之类后缀)
	for _, prefix := range agentNamePrefixes {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := strings.ToLower(e.Name())
			if !strings.HasPrefix(n, prefix) {
				continue
			}
			rest := n[len(prefix):]
			if rest != "" && !strings.HasPrefix(rest, "_") && !strings.HasPrefix(rest, "-") && !strings.HasPrefix(rest, ".") {
				continue // 词边界不符(如 yugsight-agents), 跳过
			}
			// 必须同时含本平台 os 与 arch, 否则会误取到别的平台包
			if !strings.Contains(n, osName) || !strings.Contains(n, arch) {
				continue
			}
			return filepath.Join(dir, e.Name()), e.Name(), true
		}
	}
	return "", "", false
}

// agentFileIn 在目录条目中查找指定文件名(大小写不敏感)。
//
// 为什么大小写不敏感: Windows 文件系统本身不区分大小写, 但 Linux 区分;
// 中心端可能部署在任一平台, 用户从 Windows 拷来的包名大小写常不一致。
func agentFileIn(dir string, entries []os.DirEntry, want string) (string, string, bool) {
	w := strings.ToLower(want)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.ToLower(e.Name()) != w {
			continue
		}
		p := filepath.Join(dir, e.Name())
		// 防目录穿越: 拼出的路径必须仍在 agents/ 内(文件名来自目录枚举, 属双保险)
		if filepath.Dir(p) != filepath.Clean(dir) {
			continue
		}
		return p, e.Name(), true
	}
	return "", "", false
}

// listAgentPackages 列出 agents/ 目录中当前可下载的 agent 包。
//
// 用于 /api/v2/probe/agent/list: 前端据此渲染"哪些平台可下载", 避免用户
// 逐个点击才发现包没上传。文件名无法判定平台时仍列出(标注 platform 为空),
// 宁多列不漏 —— 漏列会让人以为文件没被识别。
func listAgentPackages() []map[string]any {
	out := []map[string]any{}
	installed := map[string]map[string]any{}
	for _, p := range agentPlatforms {
		if path, name, ok := findAgentBinary(p.OS, p.Arch); ok {
			size := int64(0)
			if fi, err := os.Stat(path); err == nil {
				size = fi.Size()
			}
			item := map[string]any{
				"os": p.OS, "arch": p.Arch, "label": p.Label, "file": name,
				"size": size, "install": p.Install,
			}
			out = append(out, item)
			installed[p.OS+"/"+p.Arch] = item
		}
	}
	// 补充: 目录里存在但不匹配任何平台矩阵的文件(用户自编译的其他平台包)
	// 只提示存在, 不猜平台 —— 猜错会给出错误的下载链接。
	dir := agentDownloadDir()
	entries, err := os.ReadDir(dir)
	if err == nil {
		known := map[string]bool{}
		for _, it := range out {
			known[fmt.Sprint(it["file"])] = true
		}
		for _, e := range entries {
			if e.IsDir() || known[e.Name()] {
				continue
			}
			if !looksLikeAgent(e.Name()) {
				continue
			}
			fi, ferr := e.Info()
			size := int64(0)
			if ferr == nil {
				size = fi.Size()
			}
			out = append(out, map[string]any{
				"os": "", "arch": "", "label": "自定义/未识别平台",
				"file": e.Name(), "size": size,
				"install": "yugsight-agent -center <中心端IP>:8600 -token <节点密钥>",
			})
		}
	}
	return out
}

// looksLikeAgent 文件名是否像 agent 包(用于"未识别平台"补充列表的过滤)。
func looksLikeAgent(name string) bool {
	n := strings.ToLower(name)
	if strings.HasSuffix(n, ".json") || strings.HasSuffix(n, ".txt") || strings.HasSuffix(n, ".log") {
		return false // 同目录常见的手写配置文件/说明, 不该出现在下载列表里
	}
	for _, prefix := range agentNamePrefixes {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// agentDownloadHint 未分发 agent 包时的引导文案(含当前查找目录与编译命令)。
//
// 文案里给出 go build 命令而不是只报"文件不存在": 用户拿到的一是"放哪",
// 二是"怎么产出", 后者在跨平台分发场景(中心端是 Linux 但要给 Windows 探针装)
// 恰恰是最容易卡住的地方。
//
// 有可用工具链/源码目录时, 额外提示可以走 /agent/build 就地补包(否则用户只能读到
// 一堆命令却不知道该在哪台机器上敲)。
func agentDownloadHint() string {
	hint := fmt.Sprintf("未在 %s 找到 yugsight-agent 安装包。请先编译并放入该目录: "+
		"go build -trimpath -ldflags \"-s -w\" -o agents/yugsight-agent_windows_amd64.exe ./cmd/agent "+
		"(命名约定 yugsight-agent_{os}_{arch}[.exe], 支持 windows/linux/darwin × amd64/arm64)",
		agentDownloadDir())
	if agentpkg.Supported() {
		if _, _, ok := agentpkg.Toolchain(); ok {
			if _, ok2 := agentpkg.FindRepoDir(); ok2 {
				hint += "。本机已具备 Go 工具链与源码目录, 也可直接调用 POST /api/v2/probe/agent/build 就地补包"
			}
		}
	}
	return hint
}

// ===== 就地补包(中心端自己编译探针) =====
//
// 背景: 探针包按约定要由开发机脚本产出后放进 agents/, 但中心端常常是一台没有
// 项目脚本的服务器 —— 页面提示"未分发"就成了死结。这里给中心端两条自救路径,
// 都不联网: 先把 GOCACHE 里已有的构建产物拷出来(零成本), 不行再调 go build。
// 全部失败时回传明确原因 + 可复制的命令, 不改变 agents/ 目录里的既有文件。

var agentBuildMu sync.Mutex

// agentOutputName 就地构建/取回的产物文件名(必须落在 agentNamePrefixes 的约定内,
// 否则分发接口自己都识别不到)。
func agentOutputName(osName, arch string) string {
	name := fmt.Sprintf("yugsight-agent_%s_%s", osName, arch)
	if osName == "windows" {
		name += ".exe"
	}
	return name
}

// buildAgentForPlatform 就地补出指定平台的探针包。
//
// 只支持"当前平台"(交叉编译可以做到, 但会让用户在服务器上下载一整套工具链,
// 且产物无法当场验证; 其它平台交给构建脚本, 指引里写清楚)。
func buildAgentForPlatform(osName, arch string) agentpkg.CmdResult {
	agentBuildMu.Lock()
	defer agentBuildMu.Unlock()

	hostOS, hostArch := agentpkg.HostPlatform()
	if osName != hostOS || arch != hostArch {
		return agentpkg.CmdResult{
			OK: false,
			Error: fmt.Sprintf("只能在中心端本机补出 %s/%s 的探针包; %s/%s 请用构建脚本产出"+
				"(powershell -File scripts/build-agents.ps1)后放入 agents/ 目录",
				hostOS, hostArch, osName, arch),
		}
	}
	if !agentpkg.Supported() {
		return agentpkg.CmdResult{OK: false, Error: agentpkg.SupportNote()}
	}
	dir := agentDownloadDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return agentpkg.CmdResult{OK: false, Error: "创建 agents/ 目录失败: " + err.Error()}
	}
	out := filepath.Join(dir, agentOutputName(osName, arch))

	// 路径 1: GOCACHE 里已有现成产物(用户之前跑过 go build ./cmd/agent) —— 零成本,
	// 秒级完成且不需要重新编译整个 scanner 包, 所以优先于真编译。
	if hit, err := agentpkg.CopyGoCacheAgent(out); err == nil && hit.OK {
		logLine("探针分发: 已从本机构建缓存取出 " + filepath.Base(out))
		return agentpkg.CmdResult{
			OK:      true,
			Command: hit.Command,
			Output:  "命中 Go 构建缓存: " + hit.Path,
			Seconds: 0,
		}
	} else if hit.Error != "" {
		logLine("探针分发: 构建缓存不可用(" + hit.Error + "), 转为就地编译")
	}
	// 路径 2: 真编译
	res := agentpkg.BuildAgent(agentpkg.BuildRequest{OutPath: out})
	if res.OK {
		logLine("探针分发: 已在中心端就地构建 " + filepath.Base(out))
	} else {
		logLine("探针分发: 就地构建失败: " + res.Error)
	}
	return res
}

// hAgentBuild POST /api/v2/probe/agent/build 在中心端本机补出当前平台的探针包。
//
// 请求体: {"os":"linux","arch":"amd64"}(可省略 = 本机平台)。
// 同步执行(编译最长几分钟), 前端需给出等待提示 —— 做成异步任务会让"补包"这个小
// 高频动作多出一套轮询逻辑, 不划算。
func hAgentBuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		server.FailBadRequest(w, "请用 POST")
		return
	}
	var req struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // 空体 = 用本机平台
	}
	hostOS, hostArch := agentpkg.HostPlatform()
	osName := strings.ToLower(strings.TrimSpace(req.OS))
	arch := strings.ToLower(strings.TrimSpace(req.Arch))
	if osName == "" {
		osName = hostOS
	}
	if arch == "" {
		arch = hostArch
	}
	if _, _, _, _, ok := agentPlatform(osName, arch); !ok {
		server.FailBadRequest(w, fmt.Sprintf("不支持的平台组合 %s/%s, 可用: %s",
			osName, arch, agentPlatformSummary()))
		return
	}
	res := buildAgentForPlatform(osName, arch)
	if !res.OK {
		// 补包失败不是服务端故障: 环境不具备工具链/源码是很正常的状态,
		// 用 400 + 明确原因, 前端直接展示"怎么解决"。
		server.FailBadRequest(w, res.Error)
		return
	}
	server.OK(w, map[string]any{
		"ok":      true,
		"os":      osName,
		"arch":    arch,
		"file":    agentOutputName(osName, arch),
		"dir":     agentDownloadDir(),
		"command": res.Command,
		"output":  res.Output,
		"seconds": res.Seconds,
		"note":    "已放入 agents/ 目录, 现在可以直接下载分发",
	})
}

// ===== HTTP API =====

// hAgentList GET /api/v2/probe/agent/list 列出可下载的 agent 包与部署说明。
func hAgentList(w http.ResponseWriter, r *http.Request) {
	pkgs := listAgentPackages()
	hostOS, hostArch := agentpkg.HostPlatform()
	// hint 只在"一个包都没有"时给出编译指引。
	//
	// 【为什么要判空】早期版本无条件回带 hint, 结果是"已经分发了包、页面也列出来了,
	// 底下却挂着一行'未找到 yugsight-agent 安装包'"(实测在冒烟里复现) —— 用户会以为
	// 分发没生效, 转头去重新编译, 属于自己给自己找麻烦。有包时不提示缺包才是自洽的。
	hint := ""
	if len(pkgs) == 0 {
		hint = agentDownloadHint()
	}
	// (前端只判空字符串即可, 无需额外约定 null/空串的差异)
	server.OK(w, map[string]any{
		"list":     pkgs,
		"total":    len(pkgs),
		"dir":      agentDownloadDir(),
		"hint":     hint,
		"protocol": agentProtocolVersion(),
		// 中心端实际监听地址: 前端据此生成可直接复制的探针启动命令,
		// 避免用户去翻 probe.json 再手打地址(地址写错是探针部署最常见的问题)。
		"centerAddr": agentAdvertiseAddr(),
		// 就地补包能力: 前端据此决定是否显示"在中心端补出本平台包"按钮,
		// 以及按钮下方提示为什么不可用(有原因可看的禁用比灰按钮友好)。
		"build": agentBuildCapability(hostOS, hostArch),
	})
}

// agentBuildCapability 汇总"中心端能否就地补包"给前端。
//
// 三个字段分开报而不是只给一个 bool: 用户最需要知道的是"差什么"(没 Go / 没源码),
// 只给 false 会让他在页面和服务器之间反复试。
func agentBuildCapability(hostOS, hostArch string) map[string]any {
	out := map[string]any{
		"supported": agentpkg.Supported(),
		"hostOS":    hostOS,
		"hostArch":  hostArch,
		"note":      agentpkg.SupportNote(),
	}
	if !agentpkg.Supported() {
		return out
	}
	_, ver, toolOK := agentpkg.Toolchain()
	out["toolchain"] = toolOK
	out["toolVersion"] = ver
	repo, repoOK := agentpkg.FindRepoDir()
	out["repoDir"] = repo
	out["repoFound"] = repoOK
	// 能否立刻补包 = 工具链 + 源码目录都在
	out["canBuild"] = toolOK && repoOK
	switch {
	case !toolOK && !repoOK:
		out["ready"] = "本机缺少 Go 工具链与源码目录, 请在开发机用 scripts/build-agents.ps1 产出后放入 agents/"
	case !toolOK:
		out["ready"] = "本机未找到 Go 工具链(需 Go 1.25+ 且在 PATH 中), 已找到源码目录 " + repo
	case !repoOK:
		out["ready"] = "未找到源码目录(可用环境变量 YUGSIGHT_REPO 指定源码根目录)"
	default:
		out["ready"] = "可在中心端直接补出 " + hostOS + "/" + hostArch + " 的探针包(其余平台用构建脚本)"
	}
	return out
}

// hAgentDownload GET /api/v2/probe/agent/download?os=&arch= 下载指定平台 agent 包。
//
// 走 requireAuth 会话鉴权(与其它 v2 接口一致); 故意**不用** URL 传 token ——
// 密钥会进浏览器历史/代理日志/Referer, 属敏感信息泄漏面。
func hAgentDownload(w http.ResponseWriter, r *http.Request) {
	osName := r.URL.Query().Get("os")
	arch := r.URL.Query().Get("arch")
	if strings.TrimSpace(osName) == "" || strings.TrimSpace(arch) == "" {
		server.FailBadRequest(w, "请指定 os 与 arch 参数(如 ?os=windows&arch=amd64)")
		return
	}
	o, a, _, _, ok := agentPlatform(osName, arch)
	if !ok {
		server.FailBadRequest(w, fmt.Sprintf("不支持的平台组合 %s/%s, 可用: %s",
			osName, arch, agentPlatformSummary()))
		return
	}
	path, name, found := findAgentBinary(o, a)
	if !found {
		// 404 而非 500: 未上传包是"尚未分发"这一正常状态, 不是服务端故障
		server.FailNotFound(w, agentDownloadHint())
		return
	}
	f, err := os.Open(path)
	if err != nil {
		server.FailInternal(w, "agent 包读取失败: "+err.Error())
		return
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		server.FailInternal(w, "agent 包状态读取失败: "+err.Error())
		return
	}
	// 下载文件名统一为标准名(用户存下来的就是能直接跑的名字), 与磁盘上的实际
	// 文件名无关 —— 磁盘上可能是 yugsight-agent.exe(本地构建), 分发时应带平台标识。
	dlName := fmt.Sprintf("yugsight-agent_%s_%s", o, a)
	if strings.HasSuffix(strings.ToLower(name), ".exe") || o == "windows" {
		dlName += ".exe"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+dlName+"\"")
	w.Header().Set("Cache-Control", "no-store")
	// ServeContent 支持 Range/If-Modified-Since, 且比 io.Copy 多了断点续传能力
	// (agent 包 6MB+, 弱网环境下续传有价值)
	http.ServeContent(w, r, dlName, fi.ModTime(), f)
}

// hAgentGuide GET /api/v2/probe/agent/guide 探针部署指引(纯文本, 便于运维直接复制)。
//
// 单独一个接口而不是塞进 /list: 运维常需要把指引贴到工单/邮件里, 纯文本
// text/plain 比在浏览器里翻 JSON 友好得多。
func hAgentGuide(w http.ResponseWriter, r *http.Request) {
	addr := agentAdvertiseAddr()
	if addr == "" {
		addr = "<中心端IP>:8600"
	}
	token := probeCfg.Center.Token
	if token == "" {
		token = "<节点密钥, 见 probe.json 的 center.token>"
	}
	var b strings.Builder
	b.WriteString(appName + " 探针(agent)部署指引\n")
	b.WriteString(strings.Repeat("=", 48) + "\n\n")
	b.WriteString("1) 在中心端本机(或用户浏览器所在机器)下载对应平台的 agent:\n")
	b.WriteString("   " + appName + " Web -> 探针管理 -> 下载探针\n")
	b.WriteString("   或直接访问: /api/v2/probe/agent/download?os=<windows|linux|darwin>&arch=<amd64|arm64>\n\n")
	b.WriteString("2) Windows: 把下载的 yugsight-agent.exe 拷到目标机器, 双击运行即可 ——\n")
	b.WriteString("   自动安装到 C:\\YugsightAgent、注册开机自启动, 按弹窗提示填写中心端地址\n")
	b.WriteString("   (连不上中心端时会再次弹窗: 可选 5/30/自定义分钟后再提醒, 或退出探针)。\n\n")
	b.WriteString("3) Linux / macOS: 命令行启动(拷贝后在该目录执行):\n")
	b.WriteString("   yugsight-agent -center " + addr + " -token " + token + "\n")
	repoDir := agentDownloadDir()
	b.WriteString("   当前 agent 包查找目录: " + repoDir + "\n\n")
	b.WriteString("   也可用 probe.json(与 agent 同目录), client 段示例:\n")
	b.WriteString("   {\"client\":{\"enabled\":true,\"centerAddr\":\"" + addr + "\",\"token\":\"" + token + "\"}}\n\n")
	b.WriteString("4) 探针只向中心端发起一条出站 TCP 连接, 不监听任何端口;\n")
	b.WriteString("   请确认被扫描机器到中心端 " + addr + " 的网络可达(防火墙放行出站)。\n\n")
	b.WriteString("5) 回到 Web 探针管理页, 节点应在数秒内上线(在线/离线每 5s 自动刷新)。\n\n")
	b.WriteString("常见问题:\n")
	b.WriteString("- 提示\"未配置中心端地址\": probe.json 未找到或地址为空, 用 -center 显式指定。\n")
	b.WriteString("- 提示\"密钥错误\": 中心端 probe.json 的 center.token 与 -token 必须一致。\n")
	b.WriteString("- Windows 记事本保存的 JSON 带 BOM 也能识别(已做容错), 但建议直接用命令行参数。\n")
	b.WriteString("- Windows 卸载: 双击 C:\\YugsightAgent 目录下的「卸载探针.exe」即可\n")
	b.WriteString("  (自动停止探针 + 删除开机自启 + 删除安装目录); 或手工: 结束 yugsight-agent\n")
	b.WriteString("  进程、删除 C:\\YugsightAgent 目录、删除注册表项\n")
	b.WriteString("  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\YugsightAgent。\n")
	b.WriteString("- 探针日志: 与 agent 同目录的 yugsight-agent.log(Windows 安装后在 C:\\YugsightAgent 下)。\n")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

// ===== 辅助 =====

// agentPlatformSummary 平台矩阵摘要(错误提示用): "windows/amd64, windows/arm64, ..."。
func agentPlatformSummary() string {
	parts := make([]string, 0, len(agentPlatforms))
	for _, p := range agentPlatforms {
		parts = append(parts, p.OS+"/"+p.Arch)
	}
	return strings.Join(parts, ", ")
}

// agentProtocolVersion 当前协议版本(agent 与中心端必须一致, 前端下载页需展示)。
func agentProtocolVersion() int { return probe.ProtocolVersion }

// agentAdvertiseAddr 中心端对外可连的地址(生成探针启动命令用)。
//
// 由 probe.json 的 center.listen 推导 —— 但监听 :8600 这种"绑全部网卡"的写法
// 无法推导出用户该填哪个 IP, 此时返回本机局域网 IP。全部推导失败返回空串,
// 由调用方退化为占位符, 不返回错误(指引文案不该因拿不到 IP 而整体失败)。
//
// 注: ServerConfig 无 advertise 字段(有意不加, 避免为一个展示用途的地址
// 扩协议配置); 用户在 NAT/多网卡环境需要显式指定时, 可在指引里自行替换占位符。
func agentAdvertiseAddr() string {
	listen := strings.TrimSpace(probeCfg.Center.Listen)
	if listen == "" {
		// 保持"空配置返回空串"的既有契约: 本函数有多个消费方, 其中前端展示
		// 需要能拿到空值以退化为占位符(见 TestAgentAdvertiseAddr 第 4 条)。
		//
		// 【注意】需要"一定能拿到可连地址"的场景(如自动更新下发)不能直接用本
		// 函数, 应走 agentAdvertiseAddrOrDefault —— 否则会在 listen 未配置时
		// 静默拿不到地址(表现为更新永远不生效, 且日志上看不出原因)。
		return ""
	}
	host, port, err := splitHostPortLoose(listen)
	if err != nil {
		return ""
	}
	if port == "" {
		port = "8600"
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		// 绑全部网卡: 局域网 IP 才是探针真正该连的地址
		if ip := localAdvertiseIP(); ip != "" {
			return ip + ":" + port
		}
		return ""
	case "127.0.0.1", "localhost":
		// 仅本机监听: 探针只能部署在同机(同机联调场景), 如实返回
		return host + ":" + port
	}
	return host + ":" + port
}

// agentAdvertiseAddrOrDefault 与 agentAdvertiseAddr 相同, 但**保证返回可连地址**。
//
// 【为什么需要这个变体】probe.NewCenter 在 Listen 为空时按默认 ":8600" 启动监听
// (见 server.go 的 Start)。因此"listen 为空"只代表"用了默认端口", 不代表"没有
// 监听"。agentAdvertiseAddr 为兼容前端占位符展示而返回空串, 但自动更新下发必须
// 拿到真实地址 —— 否则会出现"探针明明连上了中心端, 更新却永远下不来"的静默失效。
// 两个语义分开成两个函数, 让各自的调用方拿到符合自身需要的口径。
func agentAdvertiseAddrOrDefault() string {
	if got := agentAdvertiseAddr(); got != "" {
		return got
	}
	// tryListen 用指定的默认监听串再推导一次(不改全局配置, 避免副作用)
	listen := strings.TrimSpace(probeCfg.Center.Listen)
	if listen != "" {
		return "" // 配了却推导不出, 说明地址本身有问题, 不猜
	}
	host, port, err := splitHostPortLoose(":8600")
	if err != nil {
		return ""
	}
	if port == "" {
		port = "8600"
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		if ip := localAdvertiseIP(); ip != "" {
			return ip + ":" + port
		}
		return ""
	}
	return host + ":" + port
}

// splitHostPortLoose 宽松解析监听地址: ":8600" / "0.0.0.0:8600" / "[::]:8600"。
//
// 不用 net.SplitHostPort 的原因: 它对 ":8600"(无主机部分)会报 missing port
// in address, 而这恰恰是最常见的监听写法。这里手动切最后一个冒号即可。
func splitHostPortLoose(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("空地址")
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "", nil // 只有主机没端口(如 "0.0.0.0"), 端口由调用方兜底
	}
	host := strings.Trim(s[:i], "[]")
	port := s[i+1:]
	if port == "" {
		return host, "", nil
	}
	return host, port, nil
}

// localAdvertiseIP 本机对外 IP(取首个非回环 IPv4)。
//
// 复用 scanner.LocalIP() 的探测口径(它已处理多网卡/虚拟网卡优先级),
// 不可用时退化为空串 —— 这里不做网络探测重试, 指引文案不值得阻塞请求。
func localAdvertiseIP() string {
	ip := strings.TrimSpace(scanner.LocalIP())
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return ""
	}
	return ip
}

// sortedAgentPlatforms 平台矩阵按 os/arch 排序的副本(供测试稳定断言,
// 也避免调用方误改全局切片)。
func sortedAgentPlatforms() []string {
	parts := make([]string, 0, len(agentPlatforms))
	for _, p := range agentPlatforms {
		parts = append(parts, p.OS+"/"+p.Arch)
	}
	sort.Strings(parts)
	return parts
}
