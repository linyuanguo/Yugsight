// catalog.go 引擎下载目录: 官方发布源 + 包命名规则 + 目标文件匹配规则。
//
// 这里所有 URL 与文件命名规则都在 2026-09 逐个实测过(见每条的 VerifiedAt 注释),
// 改动前请重新核对官方 Releases 页 —— 上游改名(如 ZAP 的版本号用下划线、Trivy 的
// 操作系统大小写混用)是本模块最容易踩的坑。
//
// 命名规则的三个已知"坑"(实测确认, 不要凭直觉写):
//   1. Trivy: 版本号不含 v, 操作系统名大小写混用 —— Linux / macOS / windows(全小写);
//      架构写作 64bit / ARM64 而非 amd64; 且 Windows 只有 zip, 其它平台是 tar.gz。
//   2. ZAP:   Linux 包用点号版本(ZAP_2.17.0_Linux.tar.gz), 而 Windows 包用下划线
//      版本(ZAP_2_17_0_windows.exe), 两者不能共用模板。
//   3. nmap:  7.93 起不再发布 Windows 免安装 zip(最后是 2021 年的 7.92-win32.zip),
//      新版只有 -setup.exe(NSIS, 非 7z SFX, 无法自动解包)。故固定下载 7.92 zip,
//      且**必须整包落位**(见 wantFile.BundleDir): 该 zip 内 nmap.exe 依赖同目录的
//      DLL(nsock32/openssl 等)与数据文件(nmap-services/nmap-payloads), 只抽主程序
//      会让进程启动即报 STATUS_DLL_NOT_FOUND(0xC0000135)。
package engmgr

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Engine 引擎标识(与 envdetect.EngineNmap/Trivy/Zap 的语义一一对应, 但本包不 import
// envdetect: 装配层负责把两边对上, 保持 engmgr 可独立单测)
type Engine string

const (
	EngineNmap  Engine = "nmap"
	EngineTrivy Engine = "trivy"
	EngineZap   Engine = "zap"
	EngineNuclei Engine = "nuclei"
)

// wantFile 解包后在归档里找什么文件。
type wantFile struct {
	// WantName 精确文件名(小写比较), 如 "trivy.exe" / "nuclei.exe"
	WantName string
	// WantPrefix 归档内可能出现的具体文件名(精确比对, 允许带扩展点)。
	// 例: zap.sh —— Linux 的 ZAP 是启动脚本, 用前缀匹配会被"类 Unix 不带点"的
	// 可执行判定否决, 必须在这里精确列出。
	WantPrefix []string
	// Prefix 引擎名前缀, 必须与 envdetect.findBinary / engine.findBin 的口径一致,
	// 否则装完检测不到。前缀匹配要求词边界(避免漏成它的兄弟程序)。
	Prefix []string
	// ExecPerm 解包后的权限(Windows 忽略, 类 Unix 需 0755)
	ExecPerm os.FileMode
	// InstallName 装入 bin/ 时使用的固定文件名。
	//
	// 为什么要改固定名: envdetect 与 engine.findBin 都按"前缀 + 词边界"匹配,
	// 而这批二进制里有几个恰好是词边界反例 —— trivycore.exe(nuclei 的旧名)
	// 前缀 trivy 后接 'c' 不是词边界, zaproxy.exe 前缀 zap 后接 'r' 同样不是。
	// 统一改名为 <引擎>core.exe 后, 前缀匹配 100% 命中, 不再依赖运气。
	InstallName string

	// BundleDir 该引擎是否为"多文件套装", 必须整包落位到 bin/<引擎>core/ 子目录。
	//
	// 【为什么需要这个开关】默认策略是"在归档里找到唯一目标可执行文件 -> 抽出来放
	// bin/"。这对 trivy/nuclei 这类**单文件静态二进制**完全正确(它们零外部依赖),
	// 但对 nmap 是致命的: nmap-7.92-win32.zip 里 nmap.exe 依赖同目录的一批 DLL
	// (nsock32、libssl/libcrypto、zlib 等) 和数据文件(nmap-services、nmap-payloads、
	// nmap-mac-prefixes、nse_main.lua 与 scripts/)。只抽 nmap.exe 的结果是**文件存在、
	// PE 头正确、但一执行就 0xC0000135(STATUS_DLL_NOT_FOUND)**, 表现为"装好了却跑不了",
	// 且从文件大小/时间戳上完全看不出问题 —— 实测踩坑。
	//
	// 置 true 后: 整个归档解到 bin/<引擎>core/, 主程序放该目录内同名文件,
	// 并通过 <引擎>core.exe 前缀匹配仍然被 envdetect 找到(BundleExe 指定入口名)。
	BundleDir bool
	// BundleName 整包落位时的子目录名(空 = strings.TrimSuffix(InstallName, ext))。
	// 例: nmap 的 InstallName 是 nmapcore.exe, 子目录即 bin/nmapcore/。
	BundleName string
}

// release 一次引擎发布的上游信息
type release struct {
	// Owner/Repo GitHub 仓库(用于查最新 tag 与拼下载地址); 非 GitHub 源留空
	Owner, Repo string
	// LatestURL 最新版本查询入口(GitHub Releases API 或自建索引)
	LatestURL string
	// LatestPageURL 版本查询的**非 API 回退入口**(通常是 GitHub 的 releases/latest 页面)。
	//
	// 【为什么必须有这个回退 —— 这是一次真实故障】
	// GitHub 的 API(api.github.com)对匿名请求限 60 次/小时/IP, 且是**按 IP 共享**的:
	// 用户所在网络只要有人(或本机反复重试)用掉了配额, 后续所有请求一律 403, 且
	// 响应体是 {"message":"API rate limit exceeded..."}, 没有 tag_name 字段 ——
	// 原实现的报错因此是"上游返回内容缺少 tag_name(GitHub 可能限流)"，用户看到的是
	// "查询最新版本失败: HTTP 403", 完全不知道该怎么办。
	//
	// 而下载地址走的是 github.com(网页), **不受 API 限流影响**。实测(2026-09):
	//   GET https://github.com/<owner>/<repo>/releases/latest
	//   -> 302 Location: /<owner>/<repo>/releases/tag/v2.17.0
	// 最终 URL 的最后一段就是 tag。这条路零配额、零鉴权, 因此作为 API 失败后的
	// 兜底通道 —— 只要 github.com 能打开(下载本来就依赖它), 版本查询就能成功。
	//
	// 留空表示该源没有可用回退(如 nmap.org 目录页, 那条路本身就不走 API)。
	LatestPageURL string
	// DownloadBase 资产下载前缀
	DownloadBase string
	// TagRe 从 tag 里提取版本号的正则(第 1 组必须是纯版本号, 不含 v 前缀)
	TagRe *regexp.Regexp
	// VerifiedAt 该源最后一次实测日期(便于后续复核)
	VerifiedAt string
}

// assetPattern 某个平台/架构下的资产文件名模板。
//
// {ver} = 版本号(不含 v); {verU} = 版本号把点换成下划线(ZAP 的 Windows 包需要);
// {os}/{arch} 按各厂商的大小写原样写入模板, 不做归一化 —— 因为上游就是这么大小写混用的。
//
// PinnedVer 非空表示"这个包的版本由本字段写死, 不跟随上游最新版本"。
// 用于上游已停止发布该格式的情况(见 nmap): 最新版拿不到可用包体, 只能固定用最后一个
// 还能自动解包的版本。此时不会去查上游最新 tag, 避免出现"显示 7.991 却去下 7.92"的错位。
type assetPattern struct {
	OS, Arch string
	Ext      string // zip / tar.gz / exe / gz
	Name     string // 文件名模板
	PinnedVer string
}

// engineSpecEntry 一个引擎在本模块里的全部下载知识。
type engineSpecEntry struct {
	Engine   Engine
	Display  string
	Releases []release
	Patterns []assetPattern
	Want     wantFile
	// Homepage 官方下载页(自动下载不可用时的兜底指引目标)
	Homepage string

	// needExtractor 是否依赖系统解包器(7z SFX), true 时前端需提示"需要 7-Zip"
	needExtractor bool
	// DefaultOff 默认不勾选的理由(前端展示); 空 = 默认勾选
	DefaultOff string
	// Note 附加说明(如 ZAP 需要 Java 运行时), 前端展示
	Note string
}

var verOnlyRe = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

// catalog 引擎目录(顺序即前端展示顺序)
var catalog = []engineSpecEntry{
	// ===== Trivy: 优先级最高 =====
	// 免安装、单文件、零依赖静态 Go 二进制、多平台齐全, 自动下载解包最干净, 收益最大。
	{
		Engine:  EngineTrivy,
		Display: "Trivy (漏洞/配置/密钥扫描)",
		Homepage: "https://github.com/aquasecurity/trivy/releases",
		Releases: []release{{
			Owner: "aquasecurity", Repo: "trivy",
			LatestURL:     "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
			LatestPageURL: "https://github.com/aquasecurity/trivy/releases/latest",
			DownloadBase:  "https://github.com/aquasecurity/trivy/releases/download/",
			TagRe:         regexp.MustCompile(`^v?(\d+(?:\.\d+){1,3})$`),
			VerifiedAt:    "2026-09 (v0.74.0)",
		}},
		Patterns: []assetPattern{
			// 注意大小写: Linux 首字母大写且架构写 64bit; windows 全小写; macOS 驼峰
			{OS: "linux", Arch: "amd64", Ext: "tar.gz", Name: "trivy_{ver}_Linux-64bit.tar.gz"},
			{OS: "linux", Arch: "arm64", Ext: "tar.gz", Name: "trivy_{ver}_Linux-ARM64.tar.gz"},
			{OS: "windows", Arch: "amd64", Ext: "zip", Name: "trivy_{ver}_windows-64bit.zip"},
			{OS: "darwin", Arch: "amd64", Ext: "tar.gz", Name: "trivy_{ver}_macOS-64bit.tar.gz"},
			{OS: "darwin", Arch: "arm64", Ext: "tar.gz", Name: "trivy_{ver}_macOS-ARM64.tar.gz"},
		},
		Want: wantFile{
			WantName:    "trivy.exe",
			WantPrefix:  []string{"trivy"},
			Prefix:      []string{"trivy"},
			ExecPerm:    executablePerm,
			InstallName: "trivycore.exe",
		},
	},

	// ===== Nuclei 官方引擎 =====
	// 本项目已有内置引擎(HTTP-only)。装官方 nuclei 的价值在于协议覆盖:
	// network / dns / ssl / websocket 等模板内置引擎跑不了, 且官方引擎拼写完全一致。
	{
		Engine:  EngineNuclei,
		Display: "Nuclei (官方引擎, 扩展协议覆盖)",
		Homepage: "https://github.com/projectdiscovery/nuclei/releases",
		Releases: []release{{
			Owner: "projectdiscovery", Repo: "nuclei",
			LatestURL:     "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest",
			LatestPageURL: "https://github.com/projectdiscovery/nuclei/releases/latest",
			DownloadBase:  "https://github.com/projectdiscovery/nuclei/releases/download/",
			TagRe:         regexp.MustCompile(`^v?(\d+(?:\.\d+){1,3})$`),
			VerifiedAt:    "2026-09 (v3.11.1)",
		}},
		Patterns: []assetPattern{
			{OS: "linux", Arch: "amd64", Ext: "zip", Name: "nuclei_{ver}_linux_amd64.zip"},
			{OS: "linux", Arch: "arm64", Ext: "zip", Name: "nuclei_{ver}_linux_arm64.zip"},
			{OS: "windows", Arch: "amd64", Ext: "zip", Name: "nuclei_{ver}_windows_amd64.zip"},
			{OS: "darwin", Arch: "amd64", Ext: "zip", Name: "nuclei_{ver}_macOS_amd64.zip"},
			{OS: "darwin", Arch: "arm64", Ext: "zip", Name: "nuclei_{ver}_macOS_arm64.zip"},
		},
		Want: wantFile{
			WantName:    "nuclei.exe",
			WantPrefix:  []string{"nuclei"},
			Prefix:      []string{"nuclei"},
			ExecPerm:    executablePerm,
			InstallName: "nucleicore.exe", // 是后缀引擎, 不是主扫描引擎, 故不与 nmap/trivy/zap 同列
		},
		Note: "内置引擎已能跑 HTTP 模板; 安装官方引擎后可使用 network/dns/ssl 等更多协议模板",
	},

	// ===== ZAP =====
	// 默认不勾选: 273MB + 依赖 Java 17 运行时。保留能力但默认关, 由用户显式选择。
	//
	// 【为什么用 Crossplatform.zip 而不是 windows.exe(这是一次真实故障的修复)】
	// 原实现抓的是 ZAP_<verU>_windows.exe, 并按"7z SFX 自解压"去抽取 —— 该假设**完全不成立**:
	// 实测该文件(256MB)是 **install4j 安装器**(头部含 install4j/i4j/jre.tar 标识 272 次,
	// 且 7z magic 37 7A BC AF 27 1C 不存在), 属于需要**运行安装向导**才能落地的封装,
	// 没有任何纯解包通道。用户现象是: 244MB 下载成功、进度走到 100%, 最后报
	// "解包失败: 未在文件中找到 7z 归档签名" —— 白下 244MB。
	//
	// 正确做法: 官方同时发布了 **ZAP_<ver>_Crossplatform.zip**(273MB), 它是**纯 zip**
	// (实测头部即 PK + 顶层目录 ZAP_2.17.0/), 解压即用、无需安装器、无需 7-Zip。
	// 代价是它**不含 Java**(官方仅 macOS 的 dmg 内含 Java 17), 故 Note 里明确要求
	// 用户自备 Java 17+, 并在能力检测时给出可读的失败原因。
	//
	// 与 nmap 同构: ZAP 也是"多文件套装"(zap.jar + lib/ + 启动脚本 + 配置),
	// 因此复用 BundleDir 整包落位 —— 只抽单个 zap.sh 同样跑不起来。
	{
		Engine:  EngineZap,
		Display: "OWASP ZAP (Web 应用动态扫描)",
		Homepage: "https://github.com/zaproxy/zaproxy/releases",
		Releases: []release{{
			Owner: "zaproxy", Repo: "zaproxy",
			LatestURL:     "https://api.github.com/repos/zaproxy/zaproxy/releases/latest",
			LatestPageURL: "https://github.com/zaproxy/zaproxy/releases/latest",
			DownloadBase:  "https://github.com/zaproxy/zaproxy/releases/download/",
			TagRe:         regexp.MustCompile(`^v?(\d+(?:\.\d+){1,3})$`),
			VerifiedAt:    "2026-09 (v2.17.0)",
		}},
		Patterns: []assetPattern{
			// 三个桌面平台统一用 Crossplatform.zip: 一个包体覆盖 Windows/Linux/macOS,
			// 且都是纯 zip(避免各平台各自的安装器封装)。
			// 注意 macOS 官方还有 ZAP_<ver>.dmg —— dmg 是磁盘镜像, 本模块不支持(见 extract 的 dmg 分支),
			// 故 macOS 也走 Crossplatform.zip。
			{OS: "windows", Arch: "amd64", Ext: "zip", Name: "ZAP_{ver}_Crossplatform.zip"},
			{OS: "linux", Arch: "amd64", Ext: "zip", Name: "ZAP_{ver}_Crossplatform.zip"},
			{OS: "linux", Arch: "arm64", Ext: "zip", Name: "ZAP_{ver}_Crossplatform.zip"},
			{OS: "darwin", Arch: "amd64", Ext: "zip", Name: "ZAP_{ver}_Crossplatform.zip"},
			{OS: "darwin", Arch: "arm64", Ext: "zip", Name: "ZAP_{ver}_Crossplatform.zip"},
		},
		Want: wantFile{
			// 归档内是 ZAP_<ver>/ 目录: zap.bat(Win) / zap.sh(Unix) 启动脚本 + zap.jar + lib/。
			// 只抽启动脚本没用 —— 它要靠同目录的 jar 与 lib 才能跑, 故整包落位(BundleDir)。
			// WantName/WantPrefix 只用于"在包内认出入口脚本", 精确列名避免命中 zap-*.jar 等兄弟文件。
			WantName: "zap.bat",
			// 注意: 这两个名字必须**精确**匹配, 不能靠前缀 —— 包内还有 zap.jar / zap-*.jar
			// 以及 zaproxy 相关文件, 前缀匹配会命中错的东西。
			WantPrefix:  []string{"zap.bat", "zap.sh"},
			Prefix:      []string{"zap"},
			ExecPerm:    executablePerm,
			InstallName: "zapcore" + exeSuffix,
			BundleDir:   true,
			BundleName:  "zapcore",
		},
		DefaultOff: "包体积 273MB 且依赖 Java 17 运行时",
		Note: "官方跨平台免安装包(Windows/Linux/macOS 通用), 解压即用无需 7-Zip; " +
			"运行需自行安装 Java 17+ (Windows 版不自带 Java), 未装 Java 时 ZAP 无法启动",
		// Crossplatform.zip 是纯 zip, 不依赖系统 7-Zip
		needExtractor: false,
	},

	// ===== nmap =====
	// Windows 自动安装固定用 7.92 免安装 zip。
	//
	// 【为什么要固定旧版, 而不是跟最新版】实测(2026-09)确认: 官方 7.93 起 Windows 只发
	// nmap-<ver>-setup.exe, 该包是 **NSIS 安装器**(实测 7.991: PE 节表含 NSIS 标志性的
	// 空 .ndata 节、内嵌 "Nullsoft" 串, 而 7z magic 37 7A BC AF 27 1C 完全不存在)。
	// 原先按"7z SFX"实现的抽取通道因此必然失败(报"未找到 7z 归档签名"), 且装 7-Zip 也无用
	// —— 格式就不是 7z。而带 nmap.exe 的免安装 zip 最后一个版本是 7.92(2021-08), 之后再无。
	//
	// 取舍: 7.92 与 7.991 在"端口/服务/主机探测"这个主用途上没有实质差别, 而自动安装
	// 新版需要实现 NSIS 解析 + LZMA 解码(数千行, 且新版 NSIS 连 7-Zip 都不保证能解),
	// 成本与风险都远高于收益。故固定 7.92 保证"点一下就能装好"。
	//
	// 【Npcap 必须另外装】此 zip 只含 nmap.exe, **不含 Npcap 驱动**。缺驱动时只有 TCP
	// connect 扫描(-sT)可用, SYN 扫描(-sS)等需要原始套接字的模式会失败。界面上必须说清,
	// 否则用户会以为 nmap 装坏了。
	{
		Engine:  EngineNmap,
		Display: "Nmap (端口/服务/主机探测)",
		Homepage: "https://nmap.org/download",
		Releases: []release{{
			// nmap 的版本索引不在 GitHub Releases(仓库无 release), 用官方目录页 + 固定命名
			LatestURL:    "https://nmap.org/dist/",
			DownloadBase: "https://nmap.org/dist/",
			TagRe:        regexp.MustCompile(`nmap-(\d+(?:\.\d+){1,3})`),
			VerifiedAt:   "2026-09 (目录页最新 7.991; 自动安装固定 7.92-win32.zip)",
		}},
		Patterns: []assetPattern{
			// 固定 7.92 免安装 zip: 纯 zip, 无需 7z/tar, 解包通道已实测可用。
			// 不跟最新版本(理由见上方注释: 7.93+ 只有 NSIS 安装器)。
			{OS: "windows", Arch: "amd64", Ext: "zip", Name: "nmap-{ver}-win32.zip", PinnedVer: "7.92"},
		},
		Want: wantFile{
			WantName:    "nmap.exe",
			WantPrefix:  []string{"nmap"},
			Prefix:      []string{"nmap"},
			ExecPerm:    executablePerm,
			InstallName: "nmapcore.exe",
			// 整包落位: nmap.exe 运行时需要同目录的 DLL 与数据文件, 单抽主程序必崩
			// (0xC0000135)。详见 wantFile.BundleDir 注释。
			BundleDir:  true,
			BundleName: "nmapcore",
		},
		Note: "自动安装的是 7.92 免安装版(官方 7.93 起 Windows 只发安装器, 无法可靠自动解包)。" +
			"注意: 该包不含 Npcap 驱动, 只有 -sT(TCP connect)扫描可用; 需要 -sS(SYN)等原始套接字模式请另装 Npcap",
		// 7.92 是纯 zip, 不再依赖系统 7z/tar
		needExtractor: false,
	},
}

// exeSuffix 当前平台可执行文件后缀(用于拼 InstallName)
var exeSuffix = func() string {
	if isWindows {
		return ".exe"
	}
	return ""
}()

// Catalog 返回引擎目录副本(前端展示用; 不暴露内部切片以免被改写)
func Catalog() []engineSpecEntry {
	out := make([]engineSpecEntry, len(catalog))
	copy(out, catalog)
	return out
}

// FindEngine 按标识查引擎(未知标识返回错误, 不 panic)
func FindEngine(e Engine) (*engineSpecEntry, error) {
	for i := range catalog {
		if catalog[i].Engine == e {
			return &catalog[i], nil
		}
	}
	return nil, fmt.Errorf("未知引擎: %s", e)
}

// latestRelease 返回引擎的首选上游(多源时取第一个; 本模块暂不使用多源引擎下载
// —— 引擎包来自厂商官方, 不存在镜像会更安全, 与规则库多源策略刻意不同)
func latestRelease(s *engineSpecEntry) (release, error) {
	if len(s.Releases) == 0 {
		return release{}, fmt.Errorf("%s 未配置上游发布源", s.Display)
	}
	return s.Releases[0], nil
}

// pickPattern 选出当前平台的资产命名模板。
// 返回的 bool 表示"官方是否提供该平台/架构的包"。
func pickPattern(s *engineSpecEntry, goos, goarch string) (assetPattern, bool) {
	for _, p := range s.Patterns {
		if p.OS == goos && p.Arch == goarch {
			return p, true
		}
	}
	return assetPattern{}, false
}

// renderAsset 把 {ver}/{verU} 占位符替换为真实文件名。
func renderAsset(p assetPattern, ver string) string {
	verU := strings.ReplaceAll(ver, ".", "_")
	n := strings.ReplaceAll(p.Name, "{verU}", verU)
	n = strings.ReplaceAll(n, "{ver}", ver)
	return n
}

// releaseURL 按 tag 拼下载地址: <DownloadBase><tag>/<fileName>
//
// 注意 GitHub 的 URL 里 tag 带 v 前缀(github.com/.../download/v3.11.1/xxx.zip),
// 而文件名里不带 v —— 这两处不能混用(实测确认)。
func releaseURL(r release, tag, fileName string) string {
	return r.DownloadBase + tag + "/" + fileName
}

// parseVersionFromTag 从 tag 中提取纯版本号。失败返回错误(不猜)。
func parseVersionFromTag(r release, tag string) (string, error) {
	if m := r.TagRe.FindStringSubmatch(tag); len(m) > 1 {
		return m[1], nil
	}
	// 正则没吃到时退化为"直接找版本号"(nmap 这类 tag 就是文件名的场景)
	if m := verOnlyRe.FindString(tag); m != "" {
		return m, nil
	}
	return "", fmt.Errorf("无法从 tag %q 解析版本号", tag)
}

// versionAtLeast 比较 a >= b(仅用于"本地版本是否已是最新"的展示性判断;
// 3 段版本号点分比较, 缺位补 0)。
func versionAtLeast(a, b string) bool {
	pa, pb := splitVer(a), splitVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return true
}

func splitVer(v string) [3]int {
	var out [3]int
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	for i, seg := range strings.Split(v, ".") {
		if i >= 3 {
			break
		}
		// 去掉 beta/rc 之类的后缀, 非数字部分视作 0
		num := seg
		for j := 0; j < len(num); j++ {
			if num[j] < '0' || num[j] > '9' {
				num = num[:j]
				break
			}
		}
		if num == "" {
			continue
		}
		n, err := strconv.Atoi(num)
		if err != nil {
			continue
		}
		out[i] = n
	}
	return out
}

// errNotSupported 平台/架构无官方包
var errNotSupported = errors.New("该平台无官方发行包")
