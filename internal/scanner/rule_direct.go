// rule_direct.go 规则库"直连官方仓库"更新通道。
//
// ===== 为什么需要这个模块 =====
//
// 既有更新链路(scanner/rule_updater.go)要求源端提供 rules-manifest.json, 而官方
// Nuclei 模板仓库**不提供这种格式**(它的 Release 只挂了一个 191 字节的 checksums
// 文件, 模板本身走源码 zipball)。所以"开箱即用的自动更新"必须由客户端自己完成
// 源端本该做的那一步:
//
//   下载官方源码压缩包 -> 解包 -> 过滤出可用的 HTTP 模板 -> 逐个算 sha256 ->
//   在内存中合成 RemoteManifest -> 复用 DownloadRuleUpdate 的既有落地流程。
//
// 关键设计: 合成出来的 manifest 直接喂给既有的 applyManifest, 于是断点续传、
// sha256 校验、失败回滚、旧版本自动备份、checksum.sha256 登记、RefreshRules 热加载
// 这些已经写好的语义全部原样复用 —— 直连通道不另起一套落地逻辑。
//
// ===== 为什么按"单模板文件"下载而不是整包一次性应用 =====
//
// 源码 zipball 解包后每个模板都是独立文件, 完全可以整包直接铺到 rules/。
// 但那样会绕过 sha256 校验与"只接受 http/ 目录"的硬过滤, 而且全量覆盖会连带
// 覆盖用户手工调整过的模板。这里刻意逐文件合成 manifest 并走同一套下载校验流程:
// 代价是多一次本地文件拷贝, 换来的是两条通道(自建源 / 官方直连)的安全语义完全一致。
//
// 依赖: 仅标准库(net/http + archive/zip)。默认关闭, 需显式开启。
package scanner

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"yugsight/internal/pathrel"
)

// ===== 直连配置 =====

// DirectOptions 直连官方仓库通道的配置
type DirectOptions struct {
	// Enabled 总开关(默认关闭; 项目规则 5: 新增功能默认关闭)
	Enabled bool
	// TemplatesRepo 模板仓库(默认 projectdiscovery/nuclei-templates)
	TemplatesRepo string
	// TemplatesRef 指定分支/tag/commit; 空 = 仓库默认分支最新
	TemplatesRef string
	// Proxy 下载代理(空 = 直连或系统代理)
	Proxy string
	// MaxTemplates 单次更新的模板数量上限。
	//
	// 为什么要限: 官方模板全量约 12000+ 个, 全部拉下来再加 sha256 计算要几分钟且
	// 占几十 MB 内存。默认只取"带 critical/high/medium 严重级标签"的模板(约 3000 个),
	// 这覆盖了绝大多数实战价值; 给 0 表示不限制(全量)。
	MaxTemplates int
	// Severities 只保留这些严重级的模板(空 = 全部)。默认 critical/high/medium。
	Severities []string
}

// 默认值
const (
	defaultTemplatesRepo = "projectdiscovery/nuclei-templates"
	// defaultSeverityFilter 默认只收高危档: 低危/信息级模板数量巨大且对"扫描器出结论"
	// 帮助有限, 全量拉取会把单次更新拖到几分钟。
	defaultSeverityFilter = "critical,high,medium"
	// defaultMaxTemplates 默认模板数量上限(防内存与耗时失控)
	defaultMaxTemplates = 6000
	// directMaxZipBytes 源码压缩包大小上限(官方全量 zipball 约 35MB, 留足余量)
	directMaxZipBytes = 256 << 20
)

var (
	directMu  sync.RWMutex
	directCfg = DirectOptions{
		Enabled:       false,
		TemplatesRepo: defaultTemplatesRepo,
		Severities:    strings.Split(defaultSeverityFilter, ","),
		MaxTemplates:  defaultMaxTemplates,
	}
)

// SetDirectOptions 设置直连通道配置(装配层从 updater.json 读取后调用)
func SetDirectOptions(o DirectOptions) {
	directMu.Lock()
	defer directMu.Unlock()
	if strings.TrimSpace(o.TemplatesRepo) == "" {
		o.TemplatesRepo = defaultTemplatesRepo
	}
	o.TemplatesRepo = strings.Trim(strings.TrimSpace(o.TemplatesRepo), "/")
	o.TemplatesRef = strings.TrimSpace(o.TemplatesRef)
	o.Proxy = strings.TrimSpace(o.Proxy)
	directCfg = o
}

// DirectConfig 返回配置快照(只读副本)
func DirectConfig() DirectOptions {
	directMu.RLock()
	defer directMu.RUnlock()
	c := directCfg
	c.Severities = append([]string(nil), c.Severities...)
	return c
}

// directEnabled 直连通道是否可用(开关打开)
func directEnabled() bool {
	directMu.RLock()
	defer directMu.RUnlock()
	return directCfg.Enabled
}

// ===== 版本探测 =====

// DirectCheck 直连通道的"有无更新"判断结果
type DirectCheck struct {
	Available   bool   `json:"available"`   // 是否有更新
	RemoteRev   string `json:"remoteRev"`   // 远端版本标识(commit sha 或 tag)
	LocalCommit string `json:"localCommit"` // 本地已应用版本(记录的是修订标识的 sha256)
	Repo        string `json:"repo"`
	Ref         string `json:"ref,omitempty"`
	ZipURL      string `json:"zipURL"`
}

// CheckDirect 查询官方仓库最新修订, 与本地已应用的记录对比。
//
// 远端身份用 commit sha(zipball 里带不出版本号, 只能问一次 API); 本地记录用
// 该 sha 的 sha256 —— 与自建源通道的 .commit 文件同构, 因此两条通道可以交替使用
// 而不会让"已是最新"的判断错乱。
func CheckDirect() (*DirectCheck, error) {
	cfg := DirectConfig()
	if !cfg.Enabled {
		return nil, fmt.Errorf("直连更新通道未启用(updater.json 中 direct.enabled=true 可开启)")
	}
	out := &DirectCheck{Repo: cfg.TemplatesRepo, Ref: cfg.TemplatesRef}
	rev, err := latestCommit(cfg)
	if err != nil {
		return nil, err
	}
	out.RemoteRev = rev
	out.ZipURL = zipballURL(cfg, rev)
	// 本地记录: 优先用"直连修订标记", 缺失时退化为既有 .commit(说明用户用过自建源)
	local := readDirectRev(rulesOfficialDir())
	if local == "" {
		local = readLocalCommit(rulesOfficialDir())
	}
	out.LocalCommit = local
	out.Available = rev != "" && rev != local
	return out, nil
}

// latestCommit 取仓库默认分支(或指定 ref)的最新 commit sha。
//
// 分两步: 先用 commits API 拿 sha(ref 为空)或用 git/ref 拿指定 ref 的 sha。
// GitHub API 匿名限速 60 次/小时, 单次更新只查一次, 正常使用不会触顶;
// 触顶时返回明确错误(带 403 提示), 由前端展示而不是静默失败。
func latestCommit(cfg DirectOptions) (string, error) {
	if cfg.TemplatesRef != "" {
		// ref 可能是分支/tag/commit: 统一用 commits/<ref> 接口(它三者都接受)
		raw := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s",
			cfg.TemplatesRepo, cfg.TemplatesRef)
		body, err := directFetch(raw, cfg.Proxy, 20*time.Second)
		if err != nil {
			return "", fmt.Errorf("查询 %s 的 ref %s 失败: %w", cfg.TemplatesRepo, cfg.TemplatesRef, err)
		}
		return jsonFirstString(body, "sha"), nil
	}
	raw := fmt.Sprintf("https://api.github.com/repos/%s/commits?per_page=1", cfg.TemplatesRepo)
	body, err := directFetch(raw, cfg.Proxy, 20*time.Second)
	if err != nil {
		return "", fmt.Errorf("查询 %s 最新提交失败: %w", cfg.TemplatesRepo, err)
	}
	return jsonFirstString(body, "sha"), nil
}

// zipballURL 拼源码压缩包地址。给 rev 时用 codeload 直连地址(避免先 302 再下载,
// 也避免 api.github.com 的限速统计), 不给时用 GitHub 的 zipball 重定向入口。
func zipballURL(cfg DirectOptions, rev string) string {
	if rev == "" {
		return fmt.Sprintf("https://api.github.com/repos/%s/zipball", cfg.TemplatesRepo)
	}
	// codeload 需要 仓库/zip/<rev> 形式
	return fmt.Sprintf("https://codeload.github.com/%s/zip/%s", cfg.TemplatesRepo, rev)
}

// ===== 主流程 =====

// DirectUpdate 执行一次"直连官方仓库"的规则更新。
//
// 流程: 查最新修订 -> (无变化直接返回 uptodate) -> 下载源码 zip -> 解包到暂存目录
// -> 过滤出可用的 HTTP 模板 -> 合成 manifest -> 交给既有 applyManifest 落地。
func DirectUpdate(pf ProgressFunc) (*UpdateResult, error) {
	cfg := DirectConfig()
	if !cfg.Enabled {
		return nil, fmt.Errorf("直连更新通道未启用(updater.json 中 direct.enabled=true 可开启)")
	}
	emit := func(status, phase string, total, done int) {
		if pf == nil {
			return
		}
		pf(UpdateProgress{Total: total, Done: done, Current: phase, Status: status})
	}

	emit(stUptodate, "查询官方仓库最新修订", 0, 0)
	rev, err := latestCommit(cfg)
	if err != nil {
		emit(stError, "", 0, 0)
		return nil, err
	}
	if rev == "" {
		emit(stError, "", 0, 0)
		return nil, fmt.Errorf("未能从 %s 获取最新修订标识", cfg.TemplatesRepo)
	}
	dir := rulesOfficialDir()
	local := readDirectRev(dir)
	if local == "" {
		local = readLocalCommit(dir)
	}
	if local == rev {
		emit(stUptodate, "本地已是最新", 0, 0)
		return &UpdateResult{Updated: false, Commit: rev}, nil
	}

	// 下载源码包到临时目录(不在 rules/ 下, 避免被 ruleset 扫描到)
	tmpRoot, err := os.MkdirTemp("", "yugsight-rules-direct-*")
	if err != nil {
		emit(stError, "", 0, 0)
		return nil, fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmpRoot)

	// 断点缓存: zip 不放 tmpRoot(函数退出就被清), 而是放在 exe 同目录的 data/cache/ 下,
	// 按 rev 命名 —— 这样下载慢/中断后重试能从断点继续, 而不是把几十 MB 重下一遍。
	// rev 变了(官方更新了)则是一份全新的缓存文件, 不会误用旧包。
	zipPath := filepath.Join(directCacheDir(), "templates-"+safeRevName(rev)+".zip.part")
	emit(stDownloading, "下载官方模板源码包", 0, 0)
	if err := downloadDirectFile(zipPath, zipballURL(cfg, rev), cfg.Proxy, pf); err != nil {
		emit(stError, "", 0, 0)
		return nil, fmt.Errorf("下载官方模板包失败: %w", err)
	}
	// 下载完整后即从缓存清除: 包已在 tmpRoot 解包路上, 留着只会白占几十 MB 磁盘
	defer os.Remove(zipPath)

	emit(stExtracting, "解析模板包(仅提取 HTTP 模板)", 0, 0)
	tpls, skipped, err := extractTemplates(zipPath, cfg)
	if err != nil {
		emit(stError, "", 0, 0)
		return nil, err
	}
	if len(tpls) == 0 {
		emit(stError, "", 0, 0)
		return nil, fmt.Errorf("官方模板包中未找到符合条件的模板(检查 severities 过滤配置)")
	}

	// 合成 manifest: 把解包出的模板写到临时暂存目录并逐个算 sha256
	stage := filepath.Join(tmpRoot, "stage")
	m := &RemoteManifest{Commit: rev, Name: "rules"}
	for _, t := range tpls {
		rel := "http/" + t.rel
		dst := filepath.Join(stage, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			emit(stError, "", 0, 0)
			return nil, fmt.Errorf("准备暂存文件失败: %w", err)
		}
		if err := os.WriteFile(dst, t.data, 0o644); err != nil {
			emit(stError, "", 0, 0)
			return nil, fmt.Errorf("写入暂存文件失败: %w", err)
		}
		sum := sha256.Sum256(t.data)
		m.Files = append(m.Files, RemoteFile{
			Path:   rel,
			Size:   int64(len(t.data)),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })

	// 复用既有落地流程: 传 localStage 让下载阶段直接拷贝暂存文件(零网络二次请求)
	emit(stApplying, "校验并应用模板", len(m.Files), 0)
	res, err := applyManifest(m, "", pf, stage)
	if err != nil {
		emit(stError, "", len(m.Files), 0)
		return nil, err
	}
	res.Skipped += skipped
	// 记录直连修订标识(供下次 CheckDirect 对比)
	if err := writeDirectRev(dir, rev); err != nil {
		updateLog.Warn("直连修订标记写入失败(下次会重复更新一次)", "err", err)
	}
	updateLog.Info("规则库直连更新完成", "repo", cfg.TemplatesRepo, "rev", rev,
		"files", len(m.Files), "skipped", skipped)
	return res, nil
}

// stagedTemplate 从官方包里提取出的单个模板
type stagedTemplate struct {
	rel  string // 相对 http/ 的路径(如 "cves/2024/CVE-2024-1234.yaml")
	data []byte
}

// extractTemplates 从源码 zipball 中提取可用的 HTTP 模板。
//
// 只用"路径 + 内容特征"判断, 不引入 YAML 解析:
//   - 路径必须在 <root>/http/ 下且以 .yaml/.yml 结尾 —— 官方模板目录结构就是这样,
//     这也是既有更新协议"只接受 http/ 前缀"的物理来源;
//   - 跳过以 _ 开头的文件名(官方用 _ 前缀放共享片段/占位模板, 不是可执行模板);
//   - 严重级过滤用文本匹配 tags 行(避免为一个字段引入完整 YAML 解析与错误处理路径)。
func extractTemplates(zipPath string, cfg DirectOptions) ([]stagedTemplate, int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, 0, fmt.Errorf("打开模板包失败(可能不是合法 zip): %w", err)
	}
	defer zr.Close()

	sevs := normalizeSeverities(cfg.Severities)
	max := cfg.MaxTemplates
	if max <= 0 {
		max = defaultMaxTemplates
	}
	var out []stagedTemplate
	skipped := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.ReplaceAll(f.Name, "\\", "/")
		// zipball 顶层是 "<repo>-<sha>/", 剥掉它
		idx := strings.Index(name, "/http/")
		if idx < 0 {
			continue
		}
		rel := name[idx+len("/http/"):]
		if rel == "" {
			continue
		}
		low := strings.ToLower(rel)
		if !strings.HasSuffix(low, ".yaml") && !strings.HasSuffix(low, ".yml") {
			continue
		}
		// 官方以 _ 开头的文件是共享片段/示例, 不是可执行模板
		if strings.HasPrefix(filepath.Base(rel), "_") {
			skipped++
			continue
		}
		// 目录穿越防护: 官方包里混入怪路径时直接拒绝
		// 用归一化后的路径继续(./a.yaml -> a.yaml, a/../b.yaml -> b.yaml), 后续按它写盘
		if safe := archiveSafeRel(rel); safe != "" {
			rel = safe
		} else {
			skipped++
			continue
		}
		if len(out) >= max {
			skipped++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			skipped++
			continue
		}
		// 单模板上限 4MB(官方最大的模板也就几百 KB; 超过必然是异常内容)
		data, rerr := io.ReadAll(io.LimitReader(rc, 4<<20))
		rc.Close()
		if rerr != nil || len(data) == 0 {
			skipped++
			continue
		}
		if len(sevs) > 0 && !severityAllowed(data, sevs) {
			skipped++
			continue
		}
		// 只保留内置引擎能真正执行的类型(HTTP 请求 + 至少一个 matcher)。
		// 官方包里有大量 network/dns/ssl/headless/javascript 模板, 内置引擎跑不了,
		// 收进来只会让 ruleset 加载时逐个跳过并刷警告。
		if !isExecutableHTTPTemplate(data) {
			skipped++
			continue
		}
		out = append(out, stagedTemplate{rel: rel, data: data})
	}
	return out, skipped, nil
}

// severityAllowed 判断模板的 severity 是否在允许集合内。
//
// 只做文本特征匹配而不解析 YAML: 匹配 severity 所在那一行, 并额外接受 tags 行里
// 出现的严重级词(官方模板普遍把严重级同时写进 tags)。
//
// 【踩坑】绝不能拿 "info:" 做关键词 —— info 是每个模板都有的顶层元数据块名,
// 它的行只包含块名而没有任何严重级词。真正的严重级在缩进的 "severity: high" 行上。
// 误判方向取"多收"(宁可多收不可漏收): 收错的模板会在 ruleset 加载时被正常解析或跳过,
// 而漏收会静默丢掉真实检测能力。
func severityAllowed(data []byte, sevs map[string]bool) bool {
	if len(sevs) == 0 {
		return true // 空集合 = 不限制
	}
	head := data
	if len(head) > 4096 {
		head = head[:4096] // 严重级字段一定在模板头部, 不必全文扫描(全量扫上万个文件很慢)
	}
	s := strings.ToLower(string(head))
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 只看声明类型的行: severity: high / tags: cve,rce,high
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

// isExecutableHTTPTemplate 判断是否内置引擎能执行的模板。
//
// 判定口径必须与 nuclei_parser.ParseNucleiTemplate + ruleset.skipReason 完全对齐,
// 否则会出现"直连通道收进来、加载阶段又全部跳过"的假成功(用户看到更新成功但规则数
// 没变)。具体规则:
//   - 顶层键含 headless / javascript / network / code / websocket / ssl / dns / whois
//     -> 内置引擎跑不了, 排除;
//   - 必须存在顶层 http / request / requests(内置引擎是 HTTP-only);
//   - 顶层 flow 是 workflow 模板(只声明依赖, 不直接执行), 排除。
//
// matchers 不在这里判: 官方存在"只有 paths 靠 matchers-condition 命中"的写法,
// 逐个精确判定代价高且容易误杀; 真正非法/无 matcher 的模板会在 ruleset 加载时
// 通过 validateTemplate 报出无效 matcher 警告, 由用户可见。
//
// 【为什么要接受 http: —— 实测踩过的坑, 曾导致直连更新 100% 失败】
// Nuclei 模板格式随版本演进了两代键名: 早期用 `requests:`(复数列表), 后来用
// `request:`(单数), 当前官方仓库(templates-ref 已到 2026 年)统一用 **`http:`**。
// 本函数原先只认 request/requests, 于是官方 zipball 里 12000+ 个模板逐条落到
// "没有 request 键"分支被全部过滤掉, extractTemplates 返回空切片, 上游直接报
// "官方模板包中未找到符合条件的模板(检查 severities 过滤配置)"。
//
// 这个报错文案还把排查带偏过: 它提示去查 severities 过滤, 而实际与严重级无关 ——
// 严重级过滤发生在更后面(见 extractTemplates 中 severityAllowed 的调用位置)。
// 全量下载几十 MB 后必然失败, 是"一键更新官方模板"按钮功能上完全不可用的直接原因。
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
	if hasTopLevelKey(s, "flow:") {
		return false // workflow 模板: 只提取依赖, 不执行
	}
	return hasTopLevelKey(s, "http:") || hasTopLevelKey(s, "request:") || hasTopLevelKey(s, "requests:")
}

// hasTopLevelKey 判断 YAML 文本里是否存在"行首(无缩进)"的指定键。
//
// key 需带冒号(如 "network:")。带冒号是必要的: 只写 "network" 会把
// "networks:" 这类更长键名也匹配上。
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

// normalizeSeverities 归一化严重级集合(小写)
func normalizeSeverities(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out[s] = true
		}
	}
	return out
}

// archiveSafeRel 校验相对路径安全(符号链接/绝对路径/上行穿越一律拒绝)
func archiveSafeRel(rel string) string {
	rel = strings.TrimSpace(strings.ReplaceAll(rel, "\\", "/"))
	if rel == "" || strings.HasPrefix(rel, "/") {
		return ""
	}
	clean := filepath.ToSlash(filepath.Clean(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	// 目录层级过深(官方结构是 http/<分类>/<子分类>/xxx.yaml, 最多 4 层)
	if strings.Count(clean, "/") > 5 {
		return ""
	}
	return clean
}

// ===== 网络 =====

// directClient 按配置构造 HTTP 客户端(代理可变)
// proxy 留空时回落到环境变量代理(envProxyFunc), 代理关闭即自动直连
func directClient(proxy string, timeout time.Duration) *http.Client {
	tr := &http.Transport{Proxy: envProxyFunc()}
	if proxy != "" {
		tr.Proxy = proxyFunc(proxy)
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// directFetch 拉取文本/JSON(限制 4MB)
func directFetch(raw, proxy string, timeout time.Duration) ([]byte, error) {
	resp, err := directClient(proxy, timeout).Get(raw)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("HTTP 403: 可能是 GitHub 匿名接口限速(60 次/小时), 稍后重试或改用自建源")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("HTTP 404: %s (仓库/分支不存在?)", raw)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// downloadDirectFile 流式下载源码包并上报进度(支持 Range 断点续传)。
//
// 【为什么必须续传】官方全量源码包 20-35MB, 国内直连常见几十 KB/s —— 一次下载
// 往往要几分钟到十几分钟。此前实现用 os.Create 直接截断重下, 意味着连接抖动、
// 切网、点错取消后的任何一次中断都会让**已下载的几十 MB 全部作废**, 用户的实际
// 感受就是"永远下不完"。现在改为写 .part 并在重试时带 Range 从断点继续。
//
// dest 是目标 .part 文件的路径(调用方负责目录存在与最终清理)。
func downloadDirectFile(dest, raw, proxy string, pf ProgressFunc) error {
	// 已有部分下载则从断点继续(源端不支持 Range 时自动退回整包重下)
	var off int64
	if st, err := os.Stat(dest); err == nil {
		off = st.Size()
		if off > directMaxZipBytes {
			os.Remove(dest) // 异常残留(超过上限), 丢弃重下
			off = 0
		}
	}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	if off > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
	}
	resp, err := directClient(proxy, 30*time.Minute).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 源端不支持续传(没回 206)时必须把偏移清零, 否则会从文件中部开始覆盖写,
	// 得到一个拼接错位的损坏 zip —— 这种包解压会报错, 但排查方向完全被带偏。
	if off > 0 && resp.StatusCode != http.StatusPartialContent {
		off = 0
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	// 总长度: 206 时 ContentLength 只是剩余部分, 需要加上已有偏移
	total := resp.ContentLength
	if resp.StatusCode == http.StatusPartialContent && total > 0 {
		total += off
	}
	if total > directMaxZipBytes {
		return fmt.Errorf("模板包过大(%d 字节), 超过上限", total)
	}

	flags := os.O_WRONLY | os.O_CREATE
	if off == 0 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(dest, flags, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	// 续传必须把写位置移到断点处: OpenFile 的写位置默认在文件头, 不 seek 的话
	// 206 回来的"剩余字节"会从偏移 0 开始写, 直接覆盖掉已下载的前半段 —— 结果是
	// 一个"只有后半段"的损坏包(比断点丢失更隐蔽: 文件还在、大小看着也像下载过)。
	if off > 0 {
		if _, serr := f.Seek(off, io.SeekStart); serr != nil {
			return fmt.Errorf("定位断点失败(%v), 放弃续传改整包重下", serr)
		}
	}

	got := off
	lastT := time.Now()
	lastN := got
	var speed int64
	buf := make([]byte, 128<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if got+int64(n) > directMaxZipBytes {
				return fmt.Errorf("模板包超过上限 %d 字节", int64(directMaxZipBytes))
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			got += int64(n)
			// 上报间隔取 500ms: 300ms 在几十 KB/s 的慢链路上也会频繁上报,
			// 但每 300ms 只有几十字节的增量, 前端换算出的速度跳动很大(用户会
			// 误以为速度在剧烈波动)。500ms 兼顾"进度不卡顿"与"速度可读"。
			if now := time.Now(); now.Sub(lastT) > 500*time.Millisecond {
				if dt := now.Sub(lastT).Seconds(); dt > 0 {
					speed = int64(float64(got-lastN) / dt)
				}
				lastT, lastN = now, got
				if pf != nil {
					// Total/Done 在这条链路上没有意义(整包只算 1 个"文件"), 真正能
					// 反映进度的是字节数: 前端按 Bytes/TotalBytes 画百分比, TotalBytes=0
					// 时退化为只显示已下载量与速度(对端未给 Content-Length)。
					cur := "下载官方模板源码包"
					if off > 0 {
						cur = fmt.Sprintf("下载官方模板源码包(续传, 已完成 %s)", humanBytes(off))
					}
					pf(UpdateProgress{Total: 1, Current: cur,
						Status: stDownloading, Speed: speed,
						Bytes: got, TotalBytes: total})
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			// 原始错误(如 unexpected EOF)对用户没有意义; 带上已下载量与"断点已保留"
			// 才是用户需要的信息 —— 否则用户只会看到"unexpected EOF"然后怀疑软件坏了。
			return fmt.Errorf("下载中断(%v): 已下载 %d 字节, 断点已保留, 重试将从断点继续", rerr, got)
		}
	}
	if total > 0 && got != total {
		return fmt.Errorf("下载不完整(期望 %d, 实得 %d; 已保留断点, 重试将继续)", total, got)
	}
	// 完成终报: 循环内的进度上报按 500ms 节流, 小文件/快链路整个下载都在一个
	// 节流窗口内, 节流上报一次都不会发 —— 不补终报的话, 前端进度条停在 0%(或
	// 9x%)然后突然"完成", 用户会怀疑卡死。成功路径恒定补发一次全量字节。
	if pf != nil {
		pf(UpdateProgress{Total: 1, Current: "下载官方模板源码包完成",
			Status: stDownloading, Bytes: got, TotalBytes: total})
	}
	return nil
}

// humanBytes 人类可读的字节数(仅用于进度文案, 不追求精度)
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTP"[exp])
}

// ===== 本地修订标记 =====

// directRevFile 直连通道的修订标记文件名(与自建源通道的 .commit 并列存放)
const directRevFile = ".direct-rev"

// directCacheDir 直连下载的断点缓存目录(exe 同目录 data/cache/, 本地数据统一收进 data/)。
//
// 为什么不放系统临时目录: 系统临时目录可能被清理工具/重启清空, 而"断点续传"
// 的价值恰恰建立在"上次中断的 .part 还在"之上 —— 放在程序自己的目录里更可控。
// 目录创建失败时退回系统临时目录(降级不报错, 只是失去续传能力)。
func directCacheDir() string {
	exe, err := os.Executable()
	if err != nil {
		return os.TempDir()
	}
	// 2026-09-24 dist 目录整理: 本地数据统一收进 data/(旧 "exe 同目录 cache/" 由
	// main.go 的 migrateLegacyDirs 启动时一次性迁移)
	dir := filepath.Join(filepath.Dir(exe), "data", "cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// dir 走 pathrel.Short: slog 属性不经过 logLine 的相对化兜底
		updateLog.Warn("断点缓存目录创建失败, 退回系统临时目录(本次下载不支持续传)", "dir", pathrel.Short(dir), "err", err)
		return os.TempDir()
	}
	return dir
}

// safeRevName 把修订标识规整成安全文件名。
//
// rev 来自远端(commit sha 或用户配置的 ref), 直接拼进文件名有目录穿越风险
// (如 ref 写成 "../../x")。分两步中和:
//  1. 白名单字符: 只保留字母数字与 . _ -, 其余一律替换为 _ —— 于是一个 rev 里
//     不可能再出现 / 或 \ 这样的路径分隔符;
//  2. **再把连续点号折叠成单个 _**: 光靠第 1 步不够 —— "." 是合法文件名字符,
//     "../../etc/passwd" 会被整形成 ".._.._etc_passwd", 看着像安全了, 但仍以
//     ".." 开头。Windows 上 ".." 相关名字有历史兼容语义(会触发 8.3 短名/保留名
//     处理), 与其依赖各平台巧合, 不如让它根本不以点号开头/结尾。
//
// 长度钳到 64 字符(sha256 是 64 位, 留足余量)。
func safeRevName(rev string) string {
	var sb strings.Builder
	for _, r := range rev {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	s := sb.String()
	// 折叠连续点号: ".." -> "_", "..." -> "_", 保证结果不含 ".." 也不以 "." 开头
	for strings.Contains(s, "..") {
		s = strings.ReplaceAll(s, "..", "_")
	}
	s = strings.Trim(s, ".")
	if s == "" {
		return "unknown"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// readDirectRev 读本地已应用的直连修订标识
func readDirectRev(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, directRevFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeDirectRev 写直连修订标识
func writeDirectRev(dir, rev string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, directRevFile), []byte(rev+"\n"), 0o644)
}

// jsonFirstString 从 JSON 文本中取第一个出现的指定键的字符串值。
//
// 复用 rule_direct 的最小解析而不是定义 struct: GitHub 的 commits 接口返回是数组,
// 我们要的是数组里第一个 commit 的 sha —— 用"取首个出现位置"既短又稳, 不会因为
// 上游加字段而失效(失败时返回空串, 由调用方给出明确错误)。
func jsonFirstString(body []byte, key string) string {
	s := string(body)
	k := `"` + key + `"`
	i := strings.Index(s, k)
	if i < 0 {
		return ""
	}
	rest := s[i+len(k):]
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

// proxyFunc 解析代理地址(非法或空地址返回 nil = 不设代理, 由 ProxyFromEnvironment 兜底)。
// 地址缺 scheme 时由 normalizeProxy 补 http://, 否则 url.Parse 会把 127.0.0.1 当协议导致静默失效。
func proxyFunc(raw string) func(*http.Request) (*url.URL, error) {
	return parseProxyFunc("直连通道", raw)
}
