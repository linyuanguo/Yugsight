// jdk.go ZAP 专用 JDK 17 的自动下载与解压(装配进 ZAP 安装流程)。
//
// 【为什么必须做这件事 —— 一次真实故障】
// ZAP 官方跨平台包(Crossplatform.zip, 273MB)**不含 Java**, 运行要求 Java 17+。
// 用户机器上是 Java 8, 于是: 下载 273MB 成功 → 解包成功 → 落位成功 → 但 zap.bat
// 抛 UnsupportedClassVersionError(class file version 61.0)。表现是"界面上安装成功,
// 一使用就起不来", 且错误信息是 JVM 的 class 版本号, 大多数人看不出该装什么。
//
// 【为什么不是"提示用户自己装"】
// 实测过这条路: 需要用户自己找到 Adoptium、选对平台/架构、下载 190MB、解压、配置 PATH。
// 而落地到具体机器的形态通常是"把 dist 目录拷到内网另一台电脑"上, 那台机器未必能上网,
// 也未必有权限改 PATH。所以做成"跟着 ZAP 一起下来、跟着 ZAP 目录一起走"。
//
// 【为什么不装进系统 PATH】
// 这是一个真实的取舍: 用户机器上已有 Java 8(可能还有其它依赖 Java 8 的业务系统),
// 动 PATH 会**破坏既有环境**。故 JDK 解压到 bin/zapcore/ZAP_<ver>/jre/,
// 由我们生成的 zap.bat 用绝对路径直接调用, 与系统 Java 完全隔离。
//
// 纯标准库; 下载/解压失败一律返回错误但**不影响 ZAP 本身装好**(降级路径见 installOne)。
package engmgr

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// jdkVendorImageType 从 Adoptium 取哪种产物。
//
// 用 jdk 而非 jre: Adoptium 自 17 起**不再单独发布 jre 镜像**(jre 需要 jlink 手工裁剪),
// API 传 image_type=jre 会返回空数组, 表现为"接口调通但拿不到包"。jdk 多一些编译工具
// (约 40MB), 但可用性优先 —— 多占这点空间远好过"下载不到"。
const (
	jdkVendor    = "eclipse" // Eclipse Temurin(Adoptium 官方发行版)
	jdkImageType = "jdk"
	jdkFeature   = 17 // ZAP 2.17 的 class file version 61.0 对应 Java 17
)

// jdkDirName 解压后的目录名(固定名, 不带版本号)。
//
// 【为什么固定而不带版本】它是我们生成的 zap.bat 里写死的相对路径。带上版本号后
// (jre-17.0.20/) 每次升级 JDK 都要重写所有启动脚本, 一旦漏改就是"JDK 在但 ZAP 找不到"。
// 版本号记录在同目录的 version.txt 里, 供状态页展示与升级比较。
const jdkDirName = "jre"

// jdkVersionFile jdk/ 目录内的版本标记(内容为 semver, 如 "17.0.20+101")。
const jdkVersionFile = "version.txt"

// jdkAPITemplate Adoptium v3 API: 查"指定 feature 版本的最新发行"。
//
// 【为什么用 assets/latest 而不是 assets/feature_releases】前者返回结构更简单
// (直接一个数组, 每项含 binary.package.link), 且语义就是"最新可用", 不需要我们
// 自己按时间排序挑第一个。实测(2026-09)返回 jdk-17.0.20.1+1, 包名
// OpenJDK17U-jdk_x64_windows_hotspot_17.0.20.1_1.zip, 190MB。
const jdkAPITemplate = "https://api.adoptium.net/v3/assets/latest/%d/hotspot" +
	"?architecture=%s&image_type=%s&os=%s&vendor=%s"

// jdkPackage 一个 JDK 发行包(只保留我们需要的字段)
type jdkPackage struct {
	ReleaseName string `json:"release_name"`
	Version     struct {
		Semver string `json:"semver"`
		Major  int    `json:"major"`
	} `json:"version"`
	Binary struct {
		Package struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
			Link string `json:"link"`
		} `json:"package"`
	} `json:"binary"`
}

// jdkResult JDK 自动安装的结果(供日志/前端展示, 不作为失败判定依据)。
type jdkResult struct {
	// Skipped 跳过原因(非 Windows 的 ZAP 包已含 Java 或走系统 java 等)
	Skipped string
	// Version/Path 装好后的版本与 jre 目录绝对路径
	Version string
	Path    string
	// Bytes 下载字节数(走缓存复用时为缓存大小)
	Bytes int64
}

// adoptiumArch 把 Go 的 GOARCH 映射成 Adoptium 的架构名。
//
// 【为什么必须显式映射而不是直接用 runtime.GOARCH】Adoptium 用的是 "x64" 而不是
// "amd64", 直接传 GOARCH 会 400(Invalid architecture)。arm64 两边恰好同名, 但不能
// 因为"碰巧对了一个"就不写映射 —— 后续加平台时会踩坑。
// 不认识的架构返回空串, 由调用方跳过(不猜: 猜错会下到错误架构的 JDK, 报的却是
// "无法启动"这种看不出根因的错)。
func adoptiumArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		return ""
	}
}

// adoptiumOS 把 Go 的 GOOS 映射成 Adoptium 的操作系统名。
func adoptiumOS(goos string) string {
	switch goos {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "mac"
	default:
		return ""
	}
}

// jdkInstalledVersion 读 bin/zapcore/ZAP_<ver>/jre/version.txt, 返回已装 JDK 版本。
// 目录不存在或标记缺失时返回空串(不报错: "没装"是正常状态)。
func jdkInstalledVersion(zapDir string) string {
	b, err := os.ReadFile(filepath.Join(zapDir, jdkDirName, jdkVersionFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// jdkJavaBin 返回 zapDir/jre 下的 java 可执行文件路径(可能不存在)。
//
// JDK 归档的解压结构有两种历史形态, 都要认:
//
//	旧: <root>/jdk-17.0.20+1/bin/java.exe            (直接一层)
//	新: <root>/jdk-17.0.20+1/bin/java.exe            (同上)
//	macOS: <root>/jdk-17.0.20+1/Contents/Home/bin/java
//
// 用"递归找第一个 bin/java[.exe]"来兼容, 不硬编码路径 —— 上游改一次目录结构,
// 硬编码就会变成"JDK 装好了但 ZAP 说找不到 Java"。
func jdkJavaBin(zapDir string) string {
	root := filepath.Join(zapDir, jdkDirName)
	if _, err := os.Stat(root); err != nil {
		return ""
	}
	name := "java"
	if isWindows {
		name = "java.exe"
	}
	var hit string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || hit != "" {
			return nil
		}
		if strings.EqualFold(info.Name(), name) && strings.EqualFold(filepath.Base(filepath.Dir(p)), "bin") {
			hit = p
		}
		return nil
	})
	return hit
}

// ensureZapJDK 为已落位的 ZAP 目录补齐 JDK 17(下载 → 解压 → 写版本标记)。
//
// zapEntry 是 ZAP 入口脚本路径(bin/zapcore/ZAP_<ver>/zap.bat)。
// 返回 jdkResult 与 error: error 非 nil 表示"JDK 没装成", 但**调用方不应因此把
// ZAP 判为安装失败** —— ZAP 文件本身是完好的, 缺 Java 只是运行期依赖(用户仍可自己
// 装 Java 17 后用起来)。这条边界必须守住, 否则一次网络抖动会让 273MB 的成果作废。
func (m *Manager) ensureZapJDK(zapEntry string, ver string, total, done int, pf ProgressFunc) (jdkResult, error) {
	zapDir := filepath.Dir(zapEntry)
	if zapDir == "" || zapDir == "." {
		return jdkResult{}, errors.New("无法确定 ZAP 目录, 跳过 JDK 安装")
	}

	// 已装则跳过: 重装 ZAP(或修环境)时不该把 190MB 再下一遍
	if v := jdkInstalledVersion(zapDir); v != "" {
		if b := jdkJavaBin(zapDir); b != "" {
			m.log("ZAP 运行时: 已存在自带 JDK " + v + ", 跳过下载")
			return jdkResult{Version: v, Path: filepath.Join(zapDir, jdkDirName)}, nil
		}
		// 标记在但 java 不在 = 上次解压被中断留下的半成品, 清掉重来
		m.log("ZAP 运行时: 已有 JDK 标记但缺少 java 可执行文件, 重新安装")
		_ = os.RemoveAll(filepath.Join(zapDir, jdkDirName))
	}

	arch := adoptiumArch(runtime.GOARCH)
	osName := adoptiumOS(runtime.GOOS)
	if arch == "" || osName == "" {
		return jdkResult{}, fmt.Errorf("Adoptium 无 %s/%s 的 JDK 发行包", runtime.GOOS, runtime.GOARCH)
	}
	if osName == "mac" {
		// macOS 的 ZAP 官方 dmg **自带 Java 17**(见 catalog.go 的说明), 且我们下载的是
		// Crossplatform.zip(不含 Java)。macOS 上额外下 JDK 收益存疑, 且 .tar.gz 结构
		// 与 Windows 的 zip 不同(为它多写一条解包通道不划算), 故明确跳过而不是静默失败。
		return jdkResult{Skipped: "macOS 平台的 ZAP 官方包自带 Java, 无需额外下载 JDK"}, nil
	}

	apiURL := fmt.Sprintf(jdkAPITemplate, jdkFeature, arch, jdkImageType, osName, jdkVendor)
	m.setProgress(Progress{Engine: EngineZap, Status: StChecking, Total: total, Done: done,
		Phase: "查询 ZAP 运行所需的 JDK 17 最新版本", Version: ver})
	if pf != nil {
		pf(m.getProg())
	}
	pkg, err := m.fetchJDKPackage(apiURL)
	if err != nil {
		return jdkResult{}, err
	}
	m.log(fmt.Sprintf("ZAP 运行时: 将下载 %s (%s, %s)",
		pkg.ReleaseName, pkg.Binary.Package.Name, humanSize(pkg.Binary.Package.Size)))

	// 下载到 <bin>/.engmgr-tmp/jdk/<包名>; 复用 .engmgr-blobs 缓存避免重试再下 190MB
	tmpDir := filepath.Join(m.BinDir(), ".engmgr-tmp", "jdk")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return jdkResult{}, fmt.Errorf("创建 JDK 暂存目录失败: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	fileName := pkg.Binary.Package.Name
	if fileName == "" {
		fileName = "temurin-jdk17.zip"
	}
	pkgPath := filepath.Join(tmpDir, fileName)
	blobPath := filepath.Join(m.BinDir(), ".engmgr-blobs", fileName)

	// 并发上报进度时用独立的 Engine 标签会让前端以为"又开了一个引擎", 故沿用 EngineZap,
	// 只把 Phase 换掉 —— 用户看到的是"当前包"进度条继续走, 语义正确(是同一个 ZAP 任务)。
	report := func(n, totalB, speed int64) {
		p := Progress{Engine: EngineZap, Status: StDownloading, Total: total, Done: done,
			Bytes: n, TotalB: totalB, Percent: pct(n, totalB), Speed: speed,
			Phase: "下载 ZAP 运行所需的 JDK 17", Version: ver}
		m.setProgress(p)
		if pf != nil {
			pf(p)
		}
	}
	if blobOK(blobPath, fileName) {
		m.log("ZAP 运行时: 复用已缓存 JDK 包体 " + blobPath)
		err = copyLocal(blobPath, pkgPath, report)
	} else {
		if st, serr := os.Stat(blobPath); serr == nil {
			m.log(fmt.Sprintf("ZAP 运行时: JDK 缓存包体不完整(%d 字节), 已丢弃并重新下载", st.Size()))
			_ = os.Remove(blobPath)
		}
		err = m.download(pkg.Binary.Package.Link, pkgPath, EngineZap, ver, total, done, pf)
	}
	if err != nil {
		return jdkResult{}, fmt.Errorf("JDK 下载失败: %w", err)
	}
	var gotBytes int64
	if st, serr := os.Stat(pkgPath); serr == nil {
		gotBytes = st.Size()
		_ = os.MkdirAll(filepath.Dir(blobPath), 0o755)
		_ = copyFileSimple(pkgPath, blobPath)
	}

	// 解压: 先把 jre 解到临时位置, 成功后再整体改名进 ZAP 目录。
	//
	// 【为什么不在原地解】解压 190MB 约几千个文件, 中途失败(磁盘满/被杀)会留下一个
	// **半截的 jre 目录** —— 而 jdkJavaBin 可能恰好能找到 java.exe, 于是被判为"装好了",
	// 之后 ZAP 一启动就报类缺失, 且现象与"没装 Java"完全不同, 极难排查。
	// 先解到临时目录再原子改名, 失败时 ZAP 目录完全不受影响。
	m.setProgress(Progress{Engine: EngineZap, Status: StExtracting, Total: total, Done: done,
		Phase: "解压 JDK 17 到 ZAP 目录", Version: ver})
	if pf != nil {
		pf(m.getProg())
	}
	staging := filepath.Join(tmpDir, "stage")
	_ = os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return jdkResult{}, fmt.Errorf("创建 JDK 解压目录失败: %w", err)
	}
	if err := extractJDKArchive(pkgPath, staging); err != nil {
		return jdkResult{}, err
	}
	// 【必须先"拍平"再加锁落位 —— 这是第一次实测暴露的真实缺陷】
	// Adoptium 的 zip 内部多一层版本目录: 解出来是
	//
	//	jre/jdk-17.0.20.1+1/bin/java.exe      <- 实际结构
	//
	// 而 ZAP 的启动脚本只认 jre/bin/java.exe。不拍平的话脚本里的
	// `if exist "%~dp0jre\bin\java.exe"` 永远不成立, 结果是: JDK 下好了、装好了、
	// 状态页也显示"已装入 JDK 17", 但 ZAP 启动时**依然用系统那个 Java 8** ——
	// 一切看起来都对, 错误却一模一样, 是最难查的一类问题(本次实测踩到)。
	//
	// 拍平到"唯一的版本目录"而不是拍平到任意一层: 直接把里面所有东西搬到 jre/ 根,
	// 会在归档只有一层且没有 bin/ 时把目录结构搞乱; 只认"根下恰好一个目录且其中有
	// bin/java"这一种形态最稳, 其余情况保持原样交给 jdkJavaBin 递归兜底。
	if moved, err := flattenSingleRoot(staging); err != nil {
		return jdkResult{}, err
	} else if moved {
		m.log("ZAP 运行时: 已拍平 JDK 目录结构(去掉归档自带的版本层目录)")
	}

	target := filepath.Join(zapDir, jdkDirName)
	_ = os.RemoveAll(target)
	if err := os.Rename(staging, target); err != nil {
		if cerr := copyDirRecursive(staging, target); cerr != nil {
			return jdkResult{}, fmt.Errorf("JDK 落位失败: %v / %v", err, cerr)
		}
	}
	if err := os.WriteFile(filepath.Join(target, jdkVersionFile),
		[]byte(pkg.Version.Semver+"\n"), 0o644); err != nil {
		// 版本标记写不进去只是"下次会重下一遍", 不影响本次可用性, 记日志继续
		m.log("ZAP 运行时: 写入 JDK 版本标记失败: " + err.Error())
	}
	// 落位后必须复核 java 在不在, 且优先要求"直接在 jre/bin/ 下"——
	// 因为启动脚本只认这一条路径。递归找到但在深层目录时给出明确日志(脚本会回落
	// 到系统 Java), 让用户能从日志看出"JDK 装了但脚本没用上", 而不是对着 mojibake
	// 般的报错猜。
	javaPath := jdkJavaBin(zapDir)
	if javaPath == "" {
		// 解压成功但找不到 java: 直接报错而不是留个假象。这里必须删掉目录, 否则
		// 下次靠 jdkInstalledVersion 判"已装"却又找不到 java, 会一直重装却不成功。
		_ = os.RemoveAll(target)
		return jdkResult{}, errors.New("JDK 已解压但未找到 bin/java, 归档结构与预期不符")
	}
	if !fileExists(filepath.Join(target, "bin", javaExeName())) {
		m.log("ZAP 运行时: 警告 - java 不在 " + filepath.Join(jdkDirName, "bin") +
			" 下(实际 " + javaPath + "), ZAP 启动脚本可能回落使用系统 Java")
	}
	m.log(fmt.Sprintf("ZAP 运行时: JDK %s 已装入 %s", pkg.Version.Semver, target))
	return jdkResult{Version: pkg.Version.Semver, Path: target, Bytes: gotBytes}, nil
}

// javaExeName 当前平台的 java 可执行文件名。
func javaExeName() string {
	if isWindows {
		return "java.exe"
	}
	return "java"
}

// fileExists 文件存在且不是目录(生产代码用; 与测试里的同名辅助不冲突的前提是
// 测试那份已删除 —— 同包内不允许重名)。
func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// flattenSingleRoot 若 dir 下"只有一个目录且其它都是普通文件(如 release/README)",
// 就把那个唯一目录的内容上移到 dir 根, 使其变成 <dir>/bin/java 布局。
//
// 返回是否真的搬动了。搬不动(有多个目录/没有子目录)时保持原样, 不算错误 ——
// 归档结构变化是上游的自由, 我们只处理能确定意图的这一种。
//
// 【为什么必须是"唯一的目录"】有些 JDK 归档根下同时有 bin/、lib/、conf/、jmods/
// 等多个目录, 那种情况本身就是正确布局(直接就是 jre 根), 再去挑一个搬反而会搬错。
func flattenSingleRoot(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	var onlyDir string
	dirCount := 0
	for _, e := range entries {
		if e.IsDir() {
			dirCount++
			onlyDir = e.Name()
		}
	}
	if dirCount != 1 || onlyDir == "" {
		return false, nil
	}
	// 唯一目录里必须有 bin/java 才认定为"版本层", 且必须在它自己的根下 ——
	// 否则(如只有 lib/ 一个目录)说明这不是版本层, 搬上去会把结构搞坏。
	if !fileExists(filepath.Join(dir, onlyDir, "bin", javaExeName())) {
		return false, nil
	}
	src := filepath.Join(dir, onlyDir)
	subs, err := os.ReadDir(src)
	if err != nil {
		return false, err
	}
	for _, s := range subs {
		if err := os.Rename(filepath.Join(src, s.Name()), filepath.Join(dir, s.Name())); err != nil {
			return false, fmt.Errorf("拍平 JDK 目录结构失败(%s): %w", s.Name(), err)
		}
	}
	_ = os.Remove(src)
	return true, nil
}

// fetchJDKPackage 查 Adoptium 取最新 JDK 17 包信息。
func (m *Manager) fetchJDKPackage(apiURL string) (*jdkPackage, error) {
	req, err := http.NewRequest(http.MethodGet, applyMirror(apiURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Yugsight-EngMgr/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := m.newClient(30 * time.Second).Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询 JDK 版本失败(网络不可达, 可配置 downloads.proxy 后重试): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询 JDK 版本失败: HTTP %d(Adoptium API 可能暂时不可用)", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("读取 JDK 版本信息失败: %w", err)
	}
	var list []jdkPackage
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("解析 JDK 版本信息失败: %w", err)
	}
	if len(list) == 0 {
		return nil, errors.New("Adoptium 未返回可用的 JDK 17 发行版(该平台可能已停止发布)")
	}
	// 取第一个: API 的 assets/latest 语义就是"最新可用", 已按发布时间倒序。
	// 不自己排序 —— 多平台返回多份二进制时按大小/时间排序都可能选错。
	for i := range list {
		if list[i].Binary.Package.Link != "" {
			return &list[i], nil
		}
	}
	return nil, errors.New("Adoptium 返回的 JDK 发行版缺少下载地址")
}

// extractJDKArchive 解压 JDK 归档到 dir。
//
// 目前只支持 zip(Windows 上 ZAP 的自动安装仅 Windows 走完整流程; 非 Windows 平台
// 的 JDK 是 tar.gz, 由 extractJDKTarGz 处理)。这两个格式不共用 extractBundleZip:
// 后者的 maxBundleBytes(1GB) 是给引擎套装用的, JDK 解出约 300MB 尚可, 但它的
// entryMatches 逻辑会顺手把 bin/java.exe 标记成可执行权限 —— 语义上没问题, 但为了
// 不误伤引擎安装的既有行为, 这里独立实现, 互不影响。
func extractJDKArchive(archivePath, dir string) error {
	low := strings.ToLower(archivePath)
	switch {
	case strings.HasSuffix(low, ".zip"):
		return extractJDKZip(archivePath, dir)
	case strings.HasSuffix(low, ".tar.gz"), strings.HasSuffix(low, ".tgz"):
		return extractJDKTarGz(archivePath, dir)
	default:
		return fmt.Errorf("不支持的 JDK 归档格式: %s", filepath.Base(archivePath))
	}
}

// extractJDKZip 全量解压 JDK zip 并保留内部目录结构。
//
// 与 extractBundleZip 的三点差异(都是有意的):
//  1. 只要有 java 就算成功 —— entryMatches 是给"引擎入口"设计的, JDK 的入口在
//     解压后才确定(可能有 Contents/Home 这类中间层), 拿它判成功会误报失败;
//  2. 上限放大到 maxJDKBytes: JDK 解出约 300MB, 且它比 1GB 的通用上限更贴近实际,
//     能更早挡住异常的巨包;
//  3. 不设置可执行权限位: Windows 忽略, 而 Linux/macOS 走 tar.gz 分支, 天然带权限位。
//     在 zip 分支里猜哪些文件该 +x 只会猜错。
func extractJDKZip(zipPath, dir string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("打开 JDK zip 失败: %w", err)
	}
	defer zr.Close()

	var total int64
	foundJava := false
	for _, f := range zr.File {
		safe := archiveSafe(f.Name)
		if safe == "" {
			continue
		}
		dst := filepath.Join(dir, filepath.FromSlash(safe))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			continue
		}
		total += int64(f.UncompressedSize64)
		if total > maxJDKBytes {
			return fmt.Errorf("JDK 解出内容超过上限 %d 字节, 已中止", int64(maxJDKBytes))
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("读取 JDK 条目 %s 失败: %w", f.Name, err)
		}
		// 目录要能被进: zip 里可能没有独立的目录条目, writeCapped 内部 MkdirAll 兜住
		werr := writeCapped(dst, rc, 0o755)
		rc.Close()
		if werr != nil {
			return fmt.Errorf("解压 JDK 条目 %s 失败: %w", f.Name, werr)
		}
		if strings.EqualFold(filepath.Base(safe), "java.exe") || strings.EqualFold(filepath.Base(safe), "java") {
			foundJava = true
		}
	}
	if !foundJava {
		return errors.New("JDK 归档内未找到 java 可执行文件, 包结构可能已变更")
	}
	return nil
}

// extractJDKTarGz 全量解压 JDK tar.gz(Linux 平台的 Adoptium 发行格式)。
//
// 保留权限位是必须的: tar 里的 bin/java 带 0755, 若统一按 0644 写盘, 解出来的 java
// 根本执行不了, 现象是"JDK 装好了但 ZAP 启动报权限拒绝"。
// 与 zip 分支同理, 只要有 java 就算成功。
func extractJDKTarGz(tgzPath, dir string) error {
	f, err := os.Open(tgzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("JDK 包不是合法 gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var total int64
	foundJava := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 JDK tar 失败: %w", err)
		}
		safe := archiveSafe(h.Name)
		if safe == "" {
			continue
		}
		dst := filepath.Join(dir, filepath.FromSlash(safe))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			continue
		case tar.TypeSymlink:
			// JDK 的 tar 里有符号链接(如 lib/*.so 的版本链)。必须保留 —— 解成普通
			// 文件会让 JVM 找不到库; 完全跳过则 java 直接起不来。
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			_ = os.Remove(dst)
			if err := os.Symlink(h.Linkname, dst); err != nil {
				// 创建失败(如文件系统不支持)不算致命: 继续解压, 后续有 java 检查兜底
				continue
			}
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			continue // 其它类型(设备/管道)不应出现在 JDK 包里, 跳过
		}
		total += h.Size
		if total > maxJDKBytes {
			return fmt.Errorf("JDK 解出内容超过上限 %d 字节, 已中止", int64(maxJDKBytes))
		}
		perm := os.FileMode(h.Mode).Perm()
		if perm == 0 {
			perm = 0o644
		}
		if err := writeCapped(dst, tr, perm); err != nil {
			return fmt.Errorf("解压 JDK 条目 %s 失败: %w", h.Name, err)
		}
		if filepath.Base(safe) == "java" {
			foundJava = true
		}
	}
	if !foundJava {
		return errors.New("JDK 归档内未找到 java 可执行文件, 包结构可能已变更")
	}
	return nil
}

// maxJDKBytes JDK 解出总量的上限(1.5GB)。
// Java 17 的 JDK 解出约 300MB(含 jmods 与调试符号), 留足余量; 不设更高是因为
// 再高就挡不住"下到了错误的巨型包"这种情况。
const maxJDKBytes = 3 << 29

// humanSize 字节数转人类可读体积(日志里看大包体积更直观)。
//
// 用 1000 进制而非 1024: 与下载器/浏览器/Adoptium 页面显示的口径一致
// (Adoptium 写 190MB 就真的是 190000000 字节), 避免用户对不上数。
//
// 本包内独立实现而不复用 main 包的 humanMB: 那个在 main 包里, engmgr 不能反向依赖
// (会形成包循环), 而 engmgr 又必须能独立单测 —— 所以只能各自持有一份。
func humanSize(n int64) string {
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

// ===== ZAP 启动脚本(让 ZAP 用自带的 jre) =====
//
// 【为什么必须自己生成启动脚本 —— 这是本次改动最关键的一环】
// 官方 zap.bat 的内容只有一行有效命令:
//
//	java %jvmopts% -jar zap-2.17.0.jar %*
//
// 它**只从 PATH 找 java**, 完全不看同目录有没有 jre/。也就是说"把 JDK 解压到
// ZAP 旁边"这件事本身**不能**让 ZAP 跑起来 —— 系统里那个 Java 8 依然会被优先命中,
// 依旧抛 UnsupportedClassVersionError。官方 zap.sh 稍好(在 macOS 分支找了
// ../PlugIns/jre*, Linux 分支尊重 JAVA_HOME), 但 Linux 不带 JAVA_HOME 时同样退化
// 为 PATH 查找。所以: 下载 JDK 与"让 ZAP 真的用上它"是两件必须一起做的事。
//
// 【为什么不改 PATH / 环境变量】见本文件头部说明: 会破坏用户已有的 Java 8 环境。
//
// 【落地形态】原 zap.bat 保留为 zap-orig.bat(不删用户可见的官方文件), 我们写的
// zap.bat 优先用同目录 jre/ 的 java, 找不到才回落到 PATH —— 这样"用户自己装了
// Java 17"和"我们下好了 JDK"两条路都能工作, 且后者优先(它就是为这台机器准备的)。

// zapLauncherName 启动脚本名(与官方一致: Windows 用 .bat, 类 Unix 用 .sh)
func zapLauncherName() string {
	if isWindows {
		return "zap.bat"
	}
	return "zap.sh"
}

// ensureZapLauncher 把 ZAP 入口脚本改写成"优先使用同目录 jre/"。
//
// zapEntry 为官方入口脚本路径。返回是否改写过(改写过才需要在日志里说明)。
//
// 幂等: 已经是我们生成的脚本(含标记行)时直接返回, 避免重装 ZAP 时把备份覆盖掉
// —— 备份一旦被自己的脚本覆盖, 就再也回不到官方原版了。
func ensureZapLauncher(zapEntry string, logf func(string)) (bool, error) {
	if zapEntry == "" {
		return false, errors.New("ZAP 入口脚本路径为空")
	}
	if _, err := os.Stat(zapEntry); err != nil {
		return false, fmt.Errorf("ZAP 入口脚本不存在: %w", err)
	}
	orig, err := os.ReadFile(zapEntry)
	if err != nil {
		return false, err
	}
	if strings.Contains(string(orig), zapLauncherMarker) {
		return false, nil // 已是我们的脚本, 幂等返回
	}
	// 备份官方原版: 用户可能想手工对比/回退, 覆盖掉就永久丢失了
	backup := zapEntry + ".orig"
	if _, err := os.Stat(backup); err != nil {
		if werr := os.WriteFile(backup, orig, 0o755); werr != nil {
			logf("ZAP 启动脚本: 备份官方原版失败(继续改写): " + werr.Error())
		}
	}
	script := zapLauncherScript(zapEntry)
	if err := os.WriteFile(zapEntry, []byte(script), 0o755); err != nil {
		return false, fmt.Errorf("写入 ZAP 启动脚本失败: %w", err)
	}
	logf("ZAP 启动脚本: 已改写为优先使用同目录 jre/ (官方原版备份为 " + filepath.Base(backup) + ")")
	return true, nil
}

// zapLauncherMarker 标记行: 用于幂等判定与"这个脚本是我们生成的"识别。
// 放在脚本内不会影响执行, 但 grep 一下就知道来源。
const zapLauncherMarker = "#YUGSIGHT-JRE-LAUNCHER"

// zapLauncherScript 生成启动脚本内容。
//
// 【Windows 分支的关键细节】%~dp0 是"脚本所在目录"(带尾部反斜杠), 这是批处理里
// 唯一可靠的自身定位方式(cd 出来的 %CD% 在用户从别处调用时是错的)。用
// if exist 判断而不检查版本 —— 版本判断会把脚本复杂度抬高一个量级, 而"jre 是我们
// 自己下的 JDK 17"这个前提由 ensureZapJDK 保证。
// zapLauncherScript 生成启动脚本内容。
//
// 【为什么脚本里全部用英文注释 —— 这是第一次实测暴露的真实缺陷】
// 第一版写了中文注释, 结果生成的 zap.bat 在 cmd 里显示为一堆乱码:
//
//	rem 浼樺厛浣跨敤 ZAP 鑷甫 JRE...
//
// 原因是 .bat 不是 UTF-8 文件: cmd.exe 按**系统 ANSI 代码页**读取它(中文 Windows
// 是 GBK/936), 而 Go 的 os.WriteFile 写出的是 UTF-8 字节。两者不一致时, 注释乱码
// 只是难看, 但**若乱码落在命令或字符串里就会改变行为**(GBK 解码出来的字节可能包含
// 引号、重定向符), 属于随时会炸的隐患。
//
// 取舍: 我们无法可靠得知目标机器的代码页(同一份二进制要能在任意区域的 Windows 上跑),
// 把脚本写成纯 ASCII 就绕开了整个问题 —— 脚本里本就没有必须中文的地方。
// 面向用户的提示文案一律走 echo 的英文 + 界面上用中文说明, 各司其职。
func zapLauncherScript(zapEntry string) string {
	base := filepath.Base(zapEntry)
	jar := zapJarName(filepath.Dir(zapEntry))
	if isWindows {
		return "@echo off\r\n" +
			"rem " + zapLauncherMarker + "\r\n" +
			"rem Prefer the JRE bundled next to this script (installed by Yugsight into jre/)\r\n" +
			"rem so that an outdated system Java is never picked up by accident.\r\n" +
			"rem The original vendor script is kept as " + base + ".orig\r\n" +
			"setlocal\r\n" +
			"set \"ZAPJRE=%~dp0jre\"\r\n" +
			"if exist \"%ZAPJRE%\\bin\\java.exe\" (\r\n" +
			"  set \"PATH=%ZAPJRE%\\bin;%PATH%\"\r\n" +
			") else (\r\n" +
			"  rem Fall back to PATH when no bundled JRE is present (user-installed Java 17).\r\n" +
			"  echo [Yugsight] No bundled JRE found, falling back to system Java. 1>&2\r\n" +
			"  echo [Yugsight] If ZAP fails to start, install Java 17 or newer. 1>&2\r\n" +
			")\r\n" +
			"if exist \"%USERPROFILE%\\ZAP\\.ZAP_JVM.properties\" (\r\n" +
			"  set /p jvmopts=< \"%USERPROFILE%\\ZAP\\.ZAP_JVM.properties\"\r\n" +
			") else (\r\n" +
			"  set jvmopts=-Xmx512m\r\n" +
			")\r\n" +
			"java %jvmopts% -jar \"%~dp0" + jar + "\" %*\r\n" +
			"exit /b %ERRORLEVEL%\r\n"
	}
	// 类 Unix: 把 jre/bin 放到 PATH 最前; JAVA_HOME 也一起指过去, 因为部分 JVM 参数
	// (如 -Xdock:icon 的查找)会读它。UTF-8 是类 Unix 的通用约定, 这里用中文也无妨,
	// 但为与 Windows 分支保持一致(便于日后统一维护)仍用英文。
	return "#!/usr/bin/env bash\n" +
		"# " + zapLauncherMarker + "\n" +
		"# Prefer the JRE bundled next to this script (installed by Yugsight into jre/)\n" +
		"# so that an outdated system Java is never picked up by accident.\n" +
		"# The original vendor script is kept as " + base + ".orig\n" +
		"BASEDIR=\"$(cd \"$(dirname \"$0\")\" && pwd -P)\"\n" +
		"if [ -x \"$BASEDIR/jre/bin/java\" ]; then\n" +
		"  export JAVA_HOME=\"$BASEDIR/jre\"\n" +
		"  export PATH=\"$JAVA_HOME/bin:$PATH\"\n" +
		"else\n" +
		"  echo \"[Yugsight] No bundled JRE found, falling back to system Java.\" 1>&2\n" +
		"  echo \"[Yugsight] If ZAP fails to start, install Java 17 or newer.\" 1>&2\n" +
		"fi\n" +
		"exec java -Xmx512m -jar \"$BASEDIR/" + jar + "\" \"$@\"\n"
}

// zapJarName ZAP 主 jar 文件名。
//
// 【为什么不写死 "zap-2.17.0.jar"】官方脚本里是写死的, 但那样 ZAP 一升级版本号,
// 脚本就指向不存在的 jar, 报 "Unable to access jarfile" —— 这个错误与我们要解决的
// Java 版本问题混在一起, 排查方向会被带偏。所以按目录里实际存在的 zap-<ver>.jar 决定。
//
// 探测失败时退回官方脚本同款形态 "zap-<entryVer>.jar"(entryBase 形如 zap.bat 时
// 拿不到版本号, 此时最后的兜底是 "zap.jar", 至少批处理的报错会指向真实文件名)。
func zapJarName(zapDir string) string {
	if n := zapJarInDir(zapDir); n != "" {
		return n
	}
	return "zap.jar"
}

// zapJarInDir 在 ZAP 目录里找主 jar(zap-<ver>.jar)。找不到返回空串。
func zapJarInDir(zapDir string) string {
	entries, err := os.ReadDir(zapDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.ToLower(e.Name())
		if strings.HasPrefix(n, "zap-") && strings.HasSuffix(n, ".jar") {
			return e.Name()
		}
	}
	return ""
}
