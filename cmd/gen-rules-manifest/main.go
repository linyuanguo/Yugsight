// gen-rules-manifest 源端清单生成工具(自建源通道用)。
//
// ===== 它解决什么问题 =====
//
// 客户端(scanner/rule_updater.go)的在线更新协议要求源端提供 rules-manifest.json:
//
//	{"commit":"<sha>","files":[{"path":"http/xxx.yaml","size":123,"sha256":"<hex>"}]}
//
// 而官方 nuclei-templates 仓库**不提供这种格式**(它的 Release 只挂了一个 191 字节的
// checksums 文件)。所以要么客户端自己算(已实现: scanner/rule_direct.go 的直连通道),
// 要么由源端预先算好(本工具)。两者产出的 manifest 完全同构, 客户端两条通道可交替使用。
//
// 自建源相比直连通道的价值: 内网环境无法访问 github.com 时, 由一台能出网的机器跑本工具
// 生成产物, 再放到内网静态服务器(nginx/OSS/S3 均可) —— 客户端只需配 updater.json 的
// sources 指向它, 全程不碰外网。
//
// ===== 用法 =====
//
//	# 从一个已经解包好的官方模板目录生成(最常用)
//	go run ./cmd/gen-rules-manifest -src ./nuclei-templates -out ./dist
//
//	# 直接从官方仓库 zipball 拉取并生成(需要能访问 github.com)
//	go run ./cmd/gen-rules-manifest -repo projectdiscovery/nuclei-templates -ref v9.9.0 -out ./dist
//
//	# 生成的产物(放到静态服务器根目录即可):
//	#   dist/rules-manifest.json
//	#   dist/rules/http/**/*.yaml
//
// ===== 过滤口径 =====
//
// 与客户端直连通道(scanner/rule_direct.go 的 extractTemplates)保持一致: 只收 http/
// 目录下的 YAML、跳过 _ 前缀的共享片段、按严重级过滤、排除内置引擎跑不了的协议类型。
// 口径必须一致, 否则"自建源更新完规则数变少"这类问题很难排查。
//
// 依赖: 仅标准库(archive/zip + crypto/sha256 + encoding/json)。
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 默认值(与客户端默认口径对齐)
const (
	defaultRepo       = "projectdiscovery/nuclei-templates"
	defaultSeverities = "critical,high,medium"
	maxTemplateBytes  = 4 << 20   // 单模板 4MB 上限
	maxZipBytes       = 256 << 20 // 源码包 256MB 上限
)

// manifestFile 单个文件的清单条目(字段名与客户端 RemoteFile 完全一致)
type manifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// manifest 清单根对象(字段名与客户端 RemoteManifest 完全一致)
type manifest struct {
	Commit string         `json:"commit"`
	Name   string         `json:"name"`
	Files  []manifestFile `json:"files"`
}

func main() {
	var (
		src     = flag.String("src", "", "已解包的官方模板目录(含 http/ 子目录); 与 -repo 二选一")
		repo    = flag.String("repo", defaultRepo, "官方仓库 owner/name(-src 为空时用它拉 zipball)")
		ref     = flag.String("ref", "", "分支/tag/commit(-repo 模式可选; 空 = 默认分支最新)")
		commit  = flag.String("commit", "", "写入清单的版本标识(默认自动取: -src 模式取目录名或时间戳)")
		out     = flag.String("out", "./dist", "产物输出目录(生成 rules-manifest.json 与 rules/ 子树)")
		sevs    = flag.String("severities", defaultSeverities, "只保留这些严重级(逗号分隔; 空 = 全部)")
		maxN    = flag.Int("max", 0, "模板数量上限(0 = 不限制)")
		proxy   = flag.String("proxy", "", "下载代理 http://host:port(-repo 模式用)")
		quiet   = flag.Bool("q", false, "只输出摘要")
		verbose = flag.Bool("v", false, "输出被跳过的文件与原因")
	)
	flag.Parse()

	if *src == "" && *repo == "" {
		fatalf("必须提供 -src(本地目录)或 -repo(官方仓库)")
	}

	severities := splitCSV(*sevs)
	tmpDir := ""

	staging := *src
	if staging == "" {
		// -repo 模式: 拉 zipball 到临时目录并解包
		dir, err := os.MkdirTemp("", "gen-rules-*")
		if err != nil {
			fatalf("创建临时目录失败: %v", err)
		}
		defer os.RemoveAll(dir)
		tmpDir = dir
		rev := *ref
		if rev == "" {
			if rev, err = latestCommit(*repo, *proxy); err != nil {
				fatalf("查询最新提交失败: %v", err)
			}
		}
		if *commit == "" {
			*commit = rev
		}
		zipPath := filepath.Join(dir, "templates.zip")
		url := fmt.Sprintf("https://codeload.github.com/%s/zip/%s", *repo, rev)
		if !*quiet {
			logf("下载 %s", url)
		}
		if err := downloadFile(zipPath, url, *proxy); err != nil {
			fatalf("下载源码包失败: %v", err)
		}
		unpacked := filepath.Join(dir, "src")
		if err := unzipTo(zipPath, unpacked); err != nil {
			fatalf("解包失败: %v", err)
		}
		// zipball 顶层是 <repo>-<sha>/, 往下找一层含 http/ 的目录
		root, err := findHTTPRoot(unpacked)
		if err != nil {
			fatalf("%v", err)
		}
		staging = root
	}
	_ = tmpDir

	if *commit == "" {
		// 本地目录模式: 没有天然的版本标识。用目录名 + 时间戳, 保证"每次生成都算一次
		// 新版本"——否则客户端会认为"无更新"而拒绝应用(它会比对 commit 字符串)。
		*commit = fmt.Sprintf("local-%s-%d", filepath.Base(absOr(staging)), time.Now().Unix())
	}

	entries, skipped, err := collectTemplates(staging, severities, *maxN, *verbose)
	if err != nil {
		fatalf("%v", err)
	}
	if len(entries) == 0 {
		fatalf("未找到符合条件的目标模板(检查 -src 是否指向含 http/ 的目录, 以及 -severities)")
	}

	// 写出产物: dist/rules-manifest.json + dist/rules/http/**/*.yaml
	rulesRoot := filepath.Join(*out, "rules")
	m := manifest{Commit: *commit, Name: "rules"}
	for _, e := range entries {
		rel := "http/" + e.rel
		dst := filepath.Join(rulesRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			fatalf("创建目录失败: %v", err)
		}
		if err := os.WriteFile(dst, e.data, 0o644); err != nil {
			fatalf("写出模板失败: %v", err)
		}
		sum := sha256.Sum256(e.data)
		m.Files = append(m.Files, manifestFile{Path: rel, Size: int64(len(e.data)), SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })

	blob, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fatalf("序列化清单失败: %v", err)
	}
	// 清单路径必须在 rules/ 的**同级**(客户端按 base+rules-manifest.json 取)
	mp := filepath.Join(*out, "rules-manifest.json")
	if err := os.WriteFile(mp, blob, 0o644); err != nil {
		fatalf("写出清单失败: %v", err)
	}

	var total int64
	for _, f := range m.Files {
		total += f.Size
	}
	fmt.Printf("生成完成: %d 个模板(跳过 %d), 共 %.1f MB\n", len(m.Files), skipped, float64(total)/1048576)
	fmt.Printf("  版本标识: %s\n", m.Commit)
	fmt.Printf("  清单文件: %s\n", mp)
	fmt.Printf("  模板目录: %s\n", rulesRoot)
	fmt.Println()
	fmt.Println("部署方式: 把上面两个产物放到静态服务器根目录, 客户端 updater.json 配")
	fmt.Printf("  {\"sources\": [\"https://<你的域名>/<路径>/\"]}\n")
}

// ===== 模板收集 =====

// stagedTemplate 收集到的单个模板(rel 相对 http/)
type stagedTemplate struct {
	rel  string
	data []byte
}

// collectTemplates 遍历 <root>/http/ 收集可用模板。
// 过滤口径与客户端直连通道完全一致(见文件头说明)。
func collectTemplates(root string, severities []string, maxN int, verbose bool) ([]stagedTemplate, int, error) {
	httpDir := filepath.Join(root, "http")
	st, err := os.Stat(httpDir)
	if err != nil || !st.IsDir() {
		return nil, 0, fmt.Errorf("%s 下没有 http/ 目录(确认 -src 指向的是模板仓库根目录)", root)
	}
	sevs := map[string]bool{}
	for _, s := range severities {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			sevs[s] = true
		}
	}
	var out []stagedTemplate
	skipped := 0
	skip := func(rel, why string) {
		skipped++
		if verbose {
			logf("跳过 %s: %s", rel, why)
		}
	}
	err = filepath.Walk(httpDir, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return nil
		}
		relOS, rerr := filepath.Rel(httpDir, p)
		if rerr != nil {
			return nil
		}
		rel := filepath.ToSlash(relOS)
		low := strings.ToLower(rel)
		if !strings.HasSuffix(low, ".yaml") && !strings.HasSuffix(low, ".yml") {
			return nil // 非模板文件(README/JSON 等)静默跳过, 不计入 skipped
		}
		// 官方以 _ 开头的文件是共享片段/示例, 不是可执行模板
		if strings.HasPrefix(filepath.Base(rel), "_") {
			skip(rel, "_ 前缀共享片段")
			return nil
		}
		if maxN > 0 && len(out) >= maxN {
			skip(rel, "已达数量上限")
			return nil
		}
		if info.Size() > maxTemplateBytes {
			skip(rel, fmt.Sprintf("超过单模板上限(%d 字节)", info.Size()))
			return nil
		}
		data, derr := os.ReadFile(p)
		if derr != nil || len(data) == 0 {
			skip(rel, "读取失败或空文件")
			return nil
		}
		if len(sevs) > 0 && !severityAllowed(data, sevs) {
			skip(rel, "严重级不在保留列表内")
			return nil
		}
		if !isExecutableHTTPTemplate(data) {
			skip(rel, "内置引擎不支持的模板类型(非 HTTP)")
			return nil
		}
		out = append(out, stagedTemplate{rel: rel, data: data})
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("遍历模板目录失败: %w", err)
	}
	return out, skipped, nil
}

// ===== 过滤(与 scanner/rule_direct.go 同口径, 独立实现避免工具依赖主程序包) =====

// severityAllowed 只保留指定严重级(匹配 severity:/tags: 行; 空集合 = 全收)
func severityAllowed(data []byte, sevs map[string]bool) bool {
	if len(sevs) == 0 {
		return true
	}
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	for _, line := range strings.Split(strings.ToLower(string(head)), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "severity:") && !strings.HasPrefix(line, "tags:") {
			continue
		}
		for sv := range sevs {
			if strings.Contains(line, sv) {
				return true
			}
		}
	}
	return false
}

// isExecutableHTTPTemplate 只保留内置引擎能执行的 HTTP 模板
// (顶层必须有 request:/requests:, 且不含 network/dns/ssl/headless/javascript 等块)
func isExecutableHTTPTemplate(data []byte) bool {
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	s := string(head)
	for _, bad := range []string{
		"headless:", "javascript:", "network:", "code:", "websocket:", "ssl:", "dns:", "whois:", "file:",
	} {
		if hasTopLevelKey(s, bad) {
			return false
		}
	}
	if hasTopLevelKey(s, "flow:") { // workflow: 只声明依赖, 不执行
		return false
	}
	return hasTopLevelKey(s, "request:") || hasTopLevelKey(s, "requests:")
}

// hasTopLevelKey 是否存在"行首无缩进"的指定键(键名需带冒号)
func hasTopLevelKey(s, key string) bool {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" || ln[0] == ' ' || ln[0] == '\t' || ln[0] == '#' {
			continue
		}
		if strings.HasPrefix(ln, key) {
			return true
		}
	}
	return false
}

// ===== 网络与解包 =====

// latestCommit 查仓库默认分支最新 commit sha(GitHub API 匿名限速 60 次/小时)
func latestCommit(repo, proxy string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits?per_page=1", repo)
	body, err := fetch(url, proxy)
	if err != nil {
		return "", err
	}
	s := string(body)
	k := `"sha"`
	i := strings.Index(s, k)
	if i < 0 {
		return "", fmt.Errorf("未在 %s 的响应中找到 sha 字段", url)
	}
	rest := strings.TrimSpace(s[i+len(k)+1:])
	rest = strings.TrimPrefix(rest, ":")
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, `"`) {
		return "", fmt.Errorf("sha 字段格式异常")
	}
	rest = rest[1:]
	if e := strings.Index(rest, `"`); e >= 0 {
		return rest[:e], nil
	}
	return "", fmt.Errorf("sha 字段未闭合")
}

// fetch 拉取文本响应(限制 4MB)
func fetch(raw, proxy string) ([]byte, error) {
	resp, err := client(proxy, 20*time.Second).Get(raw)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("HTTP 403: 可能触到 GitHub 匿名接口限速(60 次/小时), 稍后重试或改用 -src 本地目录模式")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// downloadFile 流式下载到本地文件
func downloadFile(dest, raw, proxy string) error {
	resp, err := client(proxy, 30*time.Minute).Get(raw)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	if resp.ContentLength > maxZipBytes {
		return fmt.Errorf("源码包过大(%d 字节)", resp.ContentLength)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxZipBytes+1))
	if err != nil {
		return err
	}
	if n > maxZipBytes {
		return fmt.Errorf("源码包超过上限 %d 字节", maxZipBytes)
	}
	return nil
}

// unzipTo 解包 zip 到目标目录
func unzipTo(zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		// 目录穿越防护: 归档内容不可信, 拒绝绝对路径与上行穿越
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			continue
		}
		p := filepath.Join(dest, filepath.FromSlash(name))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		w, err := os.Create(p)
		if err != nil {
			rc.Close()
			return err
		}
		_, cerr := io.Copy(w, io.LimitReader(rc, maxZipBytes))
		rc.Close()
		w.Close()
		if cerr != nil {
			return cerr
		}
	}
	return nil
}

// findHTTPRoot 在解包目录里定位"含 http/ 子目录"的那一层(处理 zipball 的顶层包装目录)
func findHTTPRoot(dir string) (string, error) {
	if st, err := os.Stat(filepath.Join(dir, "http")); err == nil && st.IsDir() {
		return dir, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		if st, err := os.Stat(filepath.Join(sub, "http")); err == nil && st.IsDir() {
			return sub, nil
		}
	}
	return "", fmt.Errorf("%s 下未找到含 http/ 子目录的模板根(下载的包结构可能已变)", dir)
}

// ===== 小工具 =====

func client(proxy string, timeout time.Duration) *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if proxy = strings.TrimSpace(proxy); proxy != "" {
		if !strings.Contains(proxy, "://") {
			proxy = "http://" + proxy
		}
		if u, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		} else {
			logf("代理地址非法, 已忽略: %s", proxy)
		}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func absOr(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func logf(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "错误: "+format+"\n", a...)
	os.Exit(1)
}
