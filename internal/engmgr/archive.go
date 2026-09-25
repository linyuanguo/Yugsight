// archive.go 归档解包: zip / tar.gz / gzip, 以及 Windows SFX 安装器(7z 自解压)的静默解包。
//
// 为什么全部手写: 本项目零第三方依赖约束(见项目规则), 标准库的 archive/zip 与
// archive/tar 足够覆盖 GitHub Releases 的两类包体(zip / tar.gz)。
//
// 安全要点(解包前必须过安全校验, 见 archiveSafe):
//   - zip 条目名与目录名要做"目录穿越"检查: 远端包里的 ../../ 或绝对路径必须拒绝,
//     否则一个恶意(或被劫持的)包可以覆盖程序外的任意文件;
//   - 逐个条目判断是否为我们想要的二进制, 命中即返回, 不解包整个包
//     (ZAP 包 233MB, 全量解包既慢又占空间, 且我们只要一个可执行文件);
//   - 单文件写盘上限 maxExtractBytes, 防止 zip 炸弹(声明 1KB 实际解出几十 GB)。
package engmgr

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxExtractBytes 单个文件解包上限(512MB): 最大的引擎(ZAP)解包后约 300MB, 留足余量。
const maxExtractBytes = 512 << 20

// archiveSafe 校验归档条目名安全, 返回规范化后的相对路径。
// 拦截: 绝对路径、盘符路径、含 .. 的路径、空名。"" 表示不安全。
func archiveSafe(name string) string {
	// zip 规范要求用 / 分隔; 但恶意包可能塞 \ (Windows 上是真实分隔符)
	n := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if n == "" {
		return ""
	}
	if strings.HasPrefix(n, "/") {
		return "" // 绝对路径
	}
	if len(n) >= 2 && n[1] == ':' {
		return "" // C:/ 之类盘符
	}
	clean := filepath.ToSlash(filepath.Clean(n))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	return clean
}

// entryMatches 判断解包出的文件名是否为我们要找的引擎可执行文件。
//
// 匹配规则刻意"严进":
//   - 必须等于 w.WantName(如 trivy.exe / nuclei.exe / nmap.exe);
//   - 或在 w.WantPrefix 里出现的完整文件名(如 zap.sh —— Linux 的 ZAP 是个启动脚本,
//     名字带扩展点); 这一层刻意不做"看起来像可执行文件"的判定, 因为脚本在类 Unix
//     上就是合法的可执行入口;
//   - 或用 w.Prefix 前缀匹配且后一个字符是词边界(_ . - 或结尾)。用前缀匹配时必须
//     同时"看起来是可执行文件"(Windows 必须 .exe, 类 Unix 不带点), 否则 trivy.yaml
//     这类同前缀的配置会被当成引擎。
//
// 为什么 Prefix 与 WantPrefix 要分开: Prefix 是"引擎识别口径", 必须与
// envdetect.findBinary / engine.findBin 一致(否则装完检测不到); WantPrefix 是
// "归档里可能出现的具体文件名", 允许带点。混成一个字段会让 Linux 的 zap.sh 因为
// isExecName 否决而永远匹配不到。
func entryMatches(base string, w wantFile) bool {
	b := strings.ToLower(filepath.Base(base))
	if w.WantName != "" && b == strings.ToLower(w.WantName) {
		return true
	}
	for _, full := range w.WantPrefix {
		if b == strings.ToLower(full) {
			return true
		}
	}
	prefixes := w.Prefix
	if len(prefixes) == 0 {
		prefixes = w.WantPrefix // 未配 Prefix 时退回 WantPrefix 做前缀匹配
	}
	for _, p := range prefixes {
		p = strings.ToLower(p)
		if !strings.HasPrefix(b, p) {
			continue
		}
		rest := b[len(p):]
		// 词边界: 前缀即全名, 或后接分隔符
		if rest == "" || rest[0] == '.' || rest[0] == '_' || rest[0] == '-' {
			if isExecName(b) {
				return true
			}
		}
	}
	return false
}

// isExecName 可执行文件名判定: Windows 只认 .exe; 其它平台排除带扩展名的文件
// (与 envdetect.findBinary / engine.findBin 的口径保持一致)。
func isExecName(lower string) bool {
	if isWindows {
		return strings.HasSuffix(lower, ".exe")
	}
	return !strings.Contains(lower, ".")
}

// ===== zip =====

// blobOK 校验下载缓存中的包体是否"完整可用"。
//
// 【为什么必须有这个校验】缓存复用的前提是"这个文件是完整的包"; 但下载可能中断
// (网络断、程序被杀、磁盘满), 留下一个**长度非 0 的残片**。仅凭"存在且 Size()>0"
// 复用残片, 会造成一个**永久自锁**: 每次重试都复用同一个坏文件 → 每次解包都失败 →
// 用户无论点多少次"重新安装"都不可能成功, 且日志里看不到任何网络动作, 极难定位
// (实测: 215KB 的 trivy zip 残片导致每次启动都报"解包失败")。
//
// 校验口径按扩展名选择, 只做"结构是否完整"的检查(不比对哈希 —— 上游不提供稳定
// 的校验值, 而结构检查已足够识别截断):
//   - zip: 能打开并读到中央目录(zip.OpenReader 会校验 EOCD 记录, 截断包在此失败)
//   - tar.gz / .gz: 能建立 gzip 流并成功读出内容(截断的 gzip 在读取时报 unexpected EOF)
//   - 其它(如 Windows SFX .exe): 只能查大小下限 —— 无结构可验, 交给解包阶段报错
func blobOK(path, fileName string) bool {
	st, err := os.Stat(path)
	if err != nil || st.Size() <= 0 {
		return false
	}
	low := strings.ToLower(fileName)
	switch {
	case strings.HasSuffix(low, ".zip"):
		zr, err := zip.OpenReader(path)
		if err != nil {
			return false
		}
		_ = zr.Close()
		return true
	case strings.HasSuffix(low, ".tar.gz"), strings.HasSuffix(low, ".tgz"), strings.HasSuffix(low, ".gz"):
		f, err := os.Open(path)
		if err != nil {
			return false
		}
		defer func() { _ = f.Close() }()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return false
		}
		defer func() { _ = gz.Close() }()
		// 读一小段即可暴露"截断": 截断包的 gzip 尾校验或数据流会在此报错。
		// 不读全部: 233MB 的包全读一遍太浪费(装包时马上还要再解一遍)。
		n, rerr := io.CopyN(io.Discard, gz, 64<<10)
		if rerr != nil && n == 0 {
			return false
		}
		if rerr != nil && rerr != io.EOF && n < 64<<10 {
			// 期望能读满 64KB: 读不满说明包体在中途就结束了
			return false
		}
		return true
	default:
		// SFX 安装器等无结构可验, 只挡"明显不可能"的尺寸(实测有效包都在 10MB 以上,
		// 用 1MB 作为"绝不可能是完整包"的下限, 宁可多下一次也不复用垃圾)
		return st.Size() > 1<<20
	}
}

// extractFromZip 在 zip 包中查找目标可执行文件并解包到 dir, 返回解包后的完整路径。
// 未命中返回 errNotFound(调用方据此回退到"解包首个可执行文件"等策略)。
func extractFromZip(zipPath, dir string, w wantFile) (string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("打开 zip 失败: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		safe := archiveSafe(f.Name)
		if safe == "" {
			continue // 不安全条目直接跳过(不是报错: 包内可能夹带无关的怪路径)
		}
		if !entryMatches(safe, w) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("读取 zip 条目 %s 失败: %w", f.Name, err)
		}
		dst := filepath.Join(dir, filepath.Base(safe))
		werr := writeCapped(dst, rc, w.ExecPerm)
		rc.Close()
		if werr != nil {
			return "", fmt.Errorf("解包 %s 失败: %w", f.Name, werr)
		}
		return dst, nil
	}
	return "", errNotFound
}

// extractBundleZip 把整个 zip 解包到 dir(保留内部目录结构)。
//
// 【返回什么 —— 这里踩过一次坑】返回的是**解包根目录本身**(即入参 dir), 不是入口文件路径。
// 曾经返回入口文件路径, 结果 placeBundle 拿它去 os.Rename -> 把单个 nmap.exe 改名成了
// bin/nmapcore(一个 2.6MB 的**文件**), 几百个依赖文件全丢在暂存目录被清掉, 表现为
// "套装目录 nmapcore 内未找到入口可执行文件" —— 文件明明在, 但它是文件不是目录。
// 入口由调用方(placeBundle)在落位后自行查找, 语义更清晰。
//
// 【与 extractFromZip 的区别】extractFromZip 是"在包里找一个文件, 命中即停, 只写那一个";
// 本函数用于 BundleDir=true 的多文件套装(nmap), 必须**全量落盘** —— 主程序依赖同目录的
// DLL 与数据文件, 少一个都跑不起来(见 wantFile.BundleDir 的踩坑说明)。
//
// 安全与体积: 每个条目都过 archiveSafe(目录穿越/盘符/..) 与 writeCapped(单文件上限),
// 且整体解出字节数受 maxBundleBytes 约束 —— 全量解包放大了 zip 炸弹的面积, 不能只靠
// 单文件上限。
func extractBundleZip(zipPath, dir string, w wantFile) (string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("打开 zip 失败: %w", err)
	}
	defer zr.Close()

	var mainPath string
	var total int64
	for _, f := range zr.File {
		safe := archiveSafe(f.Name)
		if safe == "" {
			continue // 不安全条目跳过(不报错: 包内可能夹带无关怪路径)
		}
		dst := filepath.Join(dir, filepath.FromSlash(safe))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return "", err
			}
			continue
		}
		// 解压前的声明大小也计入总量, 避免"很多个刚好不超限的小文件"绕过限制
		total += int64(f.UncompressedSize64)
		if total > maxBundleBytes {
			return "", fmt.Errorf("整包解出内容超过上限 %d 字节, 已中止", int64(maxBundleBytes))
		}
		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("读取 zip 条目 %s 失败: %w", f.Name, err)
		}
		perm := os.FileMode(0o644)
		if entryMatches(safe, w) {
			perm = w.ExecPerm // 可执行文件带 x 位(Windows 忽略, 类 Unix 必需)
		}
		werr := writeCapped(dst, rc, perm)
		rc.Close()
		if werr != nil {
			return "", fmt.Errorf("解包 %s 失败: %w", f.Name, werr)
		}
		if mainPath == "" && entryMatches(safe, w) {
			mainPath = dst
		}
	}
	// 入口必须存在, 否则说明这个包根本不是我们预期的套装结构(提前失败好过装个空目录)
	if mainPath == "" {
		return "", errNotFound
	}
	// 返回解包根目录(dir 本身), 由调用方落位后再定位入口 —— 见函数头注释
	return dir, nil
}

// maxBundleBytes 整包落位的解出总量上限(1GB)。
// nmap 7.92 解出约 60MB, 留足余量; 取 1GB 是为了将来复用给更大的套装而不必改这里。
const maxBundleBytes = 1 << 30

// ===== tar.gz =====

// extractFromTarGz 在 tar.gz 包中查找目标可执行文件并解包(Trivy/ZAP 的 Linux 包是 tar.gz)。
func extractFromTarGz(tgzPath, dir string, w wantFile) (string, error) {
	f, err := os.Open(tgzPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("不是合法 gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("读取 tar 失败: %w", err)
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		safe := archiveSafe(h.Name)
		if safe == "" || !entryMatches(safe, w) {
			continue
		}
		dst := filepath.Join(dir, filepath.Base(safe))
		if err := writeCapped(dst, tr, w.ExecPerm); err != nil {
			return "", fmt.Errorf("解包 %s 失败: %w", h.Name, err)
		}
		return dst, nil
	}
	return "", errNotFound
}

// ===== gzip 单文件(裸 gzip: 内容就是可执行文件本身) =====

// extractFromGz 解包裸 gzip 文件(如某些平台只提供 <name>.gz)。目标名由归档名推断。
func extractFromGz(gzPath, dir string, w wantFile) (string, error) {
	f, err := os.Open(gzPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("不是合法 gzip: %w", err)
	}
	defer gz.Close()
	name := strings.TrimSuffix(filepath.Base(gzPath), ".gz")
	dst := filepath.Join(dir, name)
	if err := writeCapped(dst, gz, w.ExecPerm); err != nil {
		return "", err
	}
	return dst, nil
}

// ===== 7z SFX(自解压安装器) =====

// extractFromSFX 从 Windows 自解压安装器(7-Zip SFX, 如 nmap 的 -setup.exe)中抽取目标文件。
//
// 原理: 7z SFX 的结构是"存根程序 + 完整的 7z 归档", 归档起点用 magic 扫描定位
// (7z 签名 37 7A BC AF 27 1C, 后接 2 字节版本号)。找到起点后用 exec 调系统的
// 7z/tar 从该起点解包。
//
// 为什么不自己解 7z: 7z 的 LZMA/LZMA2 解码器是数千行代码, 引入会大幅膨胀二进制并
// 带来安全维护面。改用"仅当系统自带解包器时可用"的降级策略 —— 拿不到就明确报错并
// 给出官方下载页, 不静默失败(见 driver 层的 Finalize 语义)。
//
// 调用方保证: tools 非空(由 DetectExtractTools 探测), 且仅 Windows 调用。
func extractFromSFX(exePath, dir string, w wantFile, tools extractTools) (string, error) {
	start, err := sfxArchiveOffset(exePath)
	if err != nil {
		return "", err
	}
	if len(tools.Commands) == 0 {
		return "", errors.New("系统未提供 7z/tar 解包器, 无法从自解压安装器中抽取文件")
	}
	var lastErr error
	for _, c := range tools.Commands {
		args := c.Args(exePath, dir, start)
		out, err := runTool(c.Path, args, tools.Timeout)
		if err != nil {
			lastErr = fmt.Errorf("%s 解包失败: %v (%s)", filepath.Base(c.Path), err, firstLine(out))
			continue
		}
		// 解包器输出目录布局不可控(可能带子目录), 递归找一个匹配的目标文件
		if p, ok := findExtracted(dir, w); ok {
			return p, nil
		}
		lastErr = fmt.Errorf("%s 解包成功但未找到目标可执行文件", filepath.Base(c.Path))
	}
	if lastErr == nil {
		lastErr = errors.New("自解压包解包失败")
	}
	return "", lastErr
}

// sfxArchiveOffset 扫描 7z SFX 的可执行文件, 返回内嵌 7z 归档的起始偏移。
// 找不到返回错误(说明它不是 7z SFX, 或格式不认识 —— 不猜, 直接失败)。
func sfxArchiveOffset(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	// 7z magic: 37 7A BC AF 27 1C + 2 字节主/次版本
	magic := []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}
	const chunk = 1 << 20
	buf := make([]byte, chunk+len(magic))
	var off int64
	carry := 0
	for {
		n, rerr := f.ReadAt(buf[carry:], off)
		total := carry + n
		if total <= 0 {
			break
		}
		if i := indexBytes(buf[:total], magic); i >= 0 {
			// 版本号字节需要存在才算有效签名
			if i+len(magic)+2 <= total {
				return off + int64(i), nil
			}
		}
		// 保留 magic 长度-1 的重叠, 防止签名跨块边界被漏掉
		keep := len(magic) - 1
		if total < keep {
			keep = total
		}
		copy(buf[:keep], buf[total-keep:total])
		carry = keep
		off += int64(total - keep)
		if rerr != nil {
			break
		}
		if off > maxSFXScan {
			break // 已扫描 512MB 仍未找到, 放弃(避免在大文件上无限循环)
		}
	}
	return 0, errors.New("未在文件中找到 7z 归档签名(可能不是 7z 自解压安装器)")
}

// maxSFXScan 自解压包签名扫描上限(nmap setup 约 30MB, 留足余量)
const maxSFXScan = 512 << 20

// indexBytes 等价 bytes.Index(手写以避免额外 import 混淆; 语义一致)
func indexBytes(hay, needle []byte) int {
	if len(needle) == 0 || len(hay) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// findExtracted 在解包目录(含子目录)中递归查找目标可执行文件。
func findExtracted(dir string, w wantFile) (string, bool) {
	var found string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || found != "" {
			return nil
		}
		if entryMatches(p, w) {
			found = p
		}
		return nil
	})
	return found, found != ""
}

// ===== 通用 =====

// errNotFound 归档中没有找到目标可执行文件
var errNotFound = errors.New("归档中未找到目标可执行文件")

// writeCapped 把 r 写入 path, 超过 maxExtractBytes 直接报错(防 zip 炸弹)。
func writeCapped(path string, r io.Reader, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	// 多读 1 字节用于判定"是否超限"
	n, cerr := io.Copy(f, io.LimitReader(r, maxExtractBytes+1))
	if n > maxExtractBytes {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("解包内容超过上限 %d 字节", int64(maxExtractBytes))
	}
	if cerr != nil {
		f.Close()
		os.Remove(path)
		return cerr
	}
	return f.Close()
}
