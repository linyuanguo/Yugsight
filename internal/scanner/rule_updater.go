//go:build !windows || windows

// rule_updater.go 统一在线更新模块(规则库 + CPE 库, 合并实现)。
//
// 能力:
//   - 统一配置: 多下载源(按序切换)、HTTP 代理、更新周期、自动更新开关(默认关闭)
//   - 规则库更新: 只下载 http/ 目录模板, 增量对比 commit 哈希(无变化零下载),
//     断点续传(.part + Range), 并发 3, 下载后 sha256 校验, 失败回滚(暂存目录整体清除)
//   - CPE 库更新: 精简/完整版均由源端 manifest 指定, 下载 gzip 压缩文件,
//     校验通过后解压(内存)写入 cpe/ 目录生效
//   - 全部校验通过后自动调用 RefreshRules / RefreshCPE 热加载, 无需重启
//   - 进度回调: 总文件数 / 已下载 / 当前文件 / 速度 / 状态
//   - 后台异步执行(StartUpdater), 不阻塞启动
//
// 源端约定(base URL 形如 https://host/yugsight/):
//   - rules-manifest.json  {"commit":"<sha>","files":[{"path":"http/xxx.yaml","size":123,"sha256":"<hex>"}]}
//   - cpe-manifest.json    {"commit":"<sha>","files":[{"path":"cpe/xxx.json.gz","size":123,"sha256":"<hex>"}]}
//     其中 sha256 为下载文件(压缩态)的哈希; 本地 commit 记录于 rules/.commit / cpe/.commit
//
// 降级: 未配置下载源 / 全部源失败 / 校验失败 均只记日志并返回错误,
// 不动现有规则文件, 不影响正常扫描。
//
// 依赖: 仅 Go 标准库(net/http + compress/gzip)。
package scanner

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	_ "unsafe" // go:linkname 需要

	"yugsight/internal/pathrel"
)

// updateLog 组件日志
var updateLog = slog.Default().With("component", "updater")

// envProxyFunc 读取环境变量构造代理函数。
//
// 【为什么不用 http.ProxyFromEnvironment】标准库把首次解析结果缓存在 sync.Once 里
// (Go 1.25 net/http/transport.go 的 envProxyOnce), 该缓存**无公开失效接口**:
//   - 测试中改了 HTTP_PROXY 必须清缓存才能生效, 而 linkname 已无法访问其私有变量
//     (Go 1.23+ 收紧 pull linkname, 报 "invalid reference to net/http.envProxyOnce")
//   - 用户改了环境变量也想即时生效时, 缓存会让新值"看起来没作用"
//
// 故自行解析环境变量: 语义与标准库一致(大小写皆认、无 scheme 补 http://、
// 支持 NO_PROXY 排除), 且每次调用实时读取, 无缓存陷阱。
//
// 注意: HTTP_PROXY 在 CGI 场景可能被同名请求头污染, 标准库对此有防护(拒绝含
// 注入字符的值); 本程序是本地工具, 不做 CGI 场景, 但仍对值做基本校验。
func envProxyFunc() func(*http.Request) (*url.URL, error) {
	raw := firstEnv("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
	noProxy := firstEnv("NO_PROXY", "no_proxy")
	return func(req *http.Request) (*url.URL, error) {
		// 环境变量为空 = 不使用代理(直连)
		if strings.TrimSpace(raw) == "" {
			return nil, nil
		}
		host := req.URL.Hostname()
		// NO_PROXY 命中则直连(简化匹配: 后缀比对 + "*" 通配 + localhost)
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil, nil
		}
		if matchNoProxy(host, noProxy) {
			return nil, nil
		}
		u, err := url.Parse(normalizeProxy(raw))
		if err != nil || u.Host == "" {
			updateLog.Warn("环境变量代理地址非法, 已回退直连", "proxy", raw, "err", err)
			return nil, nil
		}
		return u, nil
	}
}

// firstEnv 返回首个非空环境变量的值
func firstEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// matchNoProxy 判断 host 是否命中 NO_PROXY 列表(逗号分隔)。
// 支持: 精确匹配、".example.com"/"example.com" 后缀匹配、"*" 全放行、
// 以及 CIDR 网段(192.168.0.0/16)。CIDR 与通配写法(192.168.*)都很常见, 内网场景
// 必须让它们生效 —— 否则内网请求被送进代理, 轻则变慢重则连不通。
func matchNoProxy(host, noProxy string) bool {
	noProxy = strings.TrimSpace(noProxy)
	if noProxy == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	ip := net.ParseIP(host)
	for _, item := range strings.Split(noProxy, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if item == "*" {
			return true
		}
		// CIDR 网段: 192.168.0.0/16
		if strings.Contains(item, "/") {
			if _, cidr, err := net.ParseCIDR(item); err == nil && ip != nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		item = strings.TrimPrefix(item, ".")
		// 通配写法: 192.168.* -> 按前缀段匹配
		if strings.HasSuffix(item, ".*") {
			if strings.HasPrefix(host, strings.TrimSuffix(item, "*")) {
				return true
			}
			continue
		}
		if host == item || strings.HasSuffix(host, "."+item) {
			return true
		}
	}
	return false
}

// ===== 统一配置 =====

// UpdaterOptions 在线更新配置
type UpdaterOptions struct {
	Sources    []string      // 多下载源(base URL, 按优先级排列, 失败自动切换下一个)
	Proxy      string        // 下载代理 http://host:port(空 = 直连或系统代理)
	Interval   time.Duration // 自动更新检查周期(0 = 不自动)
	AutoUpdate bool          // 自动更新开关(默认关闭, 需显式 SetAutoUpdate(true))
}

var (
	upMu  sync.RWMutex
	upCfg = UpdaterOptions{Interval: 24 * time.Hour, AutoUpdate: false}
)

// 测试钩子: 替换真实网络(沙箱环回被拦截, 测试用内存实现); nil = 走真实 net/http
var (
	upFetchFn    func(raw string, timeout time.Duration) ([]byte, error)
	upDownloadFn func(u, dest string, f RemoteFile, meter *speedMeter) error
)

// SetDownloadSource 设置下载源列表(按优先级排列, 前面的源失败自动切换下一个)
func SetDownloadSource(sources ...string) {
	upMu.Lock()
	defer upMu.Unlock()
	s := make([]string, 0, len(sources))
	for _, x := range sources {
		if x = strings.TrimSpace(x); x != "" {
			s = append(s, strings.TrimSuffix(x, "/")+"/")
		}
	}
	upCfg.Sources = s
}

// SetProxy 设置下载代理(传空串恢复直连/系统代理)
func SetProxy(proxy string) {
	upMu.Lock()
	defer upMu.Unlock()
	upCfg.Proxy = strings.TrimSpace(proxy)
}

// SetUpdateInterval 设置自动更新检查周期(0 = 禁用自动更新)
func SetUpdateInterval(d time.Duration) {
	upMu.Lock()
	defer upMu.Unlock()
	if d < 0 {
		d = 0
	}
	upCfg.Interval = d
}

// SetAutoUpdate 设置自动更新开关(默认关闭; 开启后由 StartUpdater 的后台循环执行)
func SetAutoUpdate(on bool) {
	upMu.Lock()
	defer upMu.Unlock()
	upCfg.AutoUpdate = on
}

// UpdaterConfig 返回当前配置快照(只读副本)
func UpdaterConfig() UpdaterOptions {
	upMu.RLock()
	defer upMu.RUnlock()
	c := upCfg
	c.Sources = append([]string(nil), c.Sources...)
	return c
}

// newHTTPClient 按当前配置构造 HTTP 客户端(代理可变, 故每次重建)
//
// 【代理来源优先级】
//  1. 配置文件 updater.proxy 非空 —— 显式指定, 强行使用(代理关闭时会硬失败, 不推荐)
//  2. 配置留空 —— 回落到系统环境变量 HTTP_PROXY / HTTPS_PROXY / NO_PROXY
//
// 推荐留空: 环境变量在进程启动时读取, 代理关了自动回退直连, 无需改配置重启。
// 注意程序**不读** Windows「Internet 选项」里的系统代理设置, 只认环境变量。
func newHTTPClient(timeout time.Duration) *http.Client {
	upMu.RLock()
	proxy := upCfg.Proxy
	upMu.RUnlock()
	tr := &http.Transport{Proxy: envProxyFunc()}
	if proxy != "" {
		tr.Proxy = parseProxyFunc("更新器", proxy)
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// normalizeProxy 规范化代理地址。
//
// 【为什么必须补 scheme】Go 的 ProxyFromEnvironment / url.Parse 遇到 `127.0.0.1:7890`
// 这种无 scheme 写法时, 会把 `127.0.0.1` 当作**协议**、`:7890` 当作**主机**,
// 结果是代理静默失效(不报错, 只是连不上)。用户手抄配置极易漏掉 http://。
func normalizeProxy(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		return "http://" + raw
	}
	return raw
}

// parseProxyFunc 解析代理地址为 Proxy 函数(非法或空地址返回 nil = 不设代理)
func parseProxyFunc(who, raw string) func(*http.Request) (*url.URL, error) {
	norm := normalizeProxy(raw)
	if norm == "" {
		return nil
	}
	u, err := url.Parse(norm)
	if err != nil || u.Host == "" {
		updateLog.Warn(who+": 代理地址非法, 已忽略", "proxy", raw, "err", err)
		return nil
	}
	return http.ProxyURL(u)
}

// resetProxyEnvCache 兼容旧调用点: envProxyFunc 每次实时读环境变量, 已无缓存需清。
// 保留空实现是为了不破坏既有测试与新测试的调用(语义已变, 见 envProxyFunc 注释)。
func resetProxyEnvCache() {}

// fetchURL 下载一个 URL 的内容(限时, 限 32MB)
func fetchURL(raw string, timeout time.Duration) ([]byte, error) {
	if upFetchFn != nil {
		return upFetchFn(raw, timeout)
	}
	resp, err := newHTTPClient(timeout).Get(raw)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

// ===== 进度与结果 =====

// 进度状态
const (
	stDownloading = "downloading" // 下载中
	stExtracting  = "extracting"  // 解包/提取(仅直连官方仓库通道使用, 见 rule_direct.go)
	stVerifying   = "verifying"   // 校验中
	stApplying    = "applying"    // 应用(暂存 -> 正式目录)
	stDone        = "done"        // 完成(含热加载)
	stUptodate    = "uptodate"    // 无更新
	stError       = "error"       // 失败(已回滚/未动正式文件)
)

// UpdateProgress 更新进度
type UpdateProgress struct {
	Total   int    `json:"total"`   // 总文件数
	Done    int    `json:"done"`    // 已下载文件数
	Current string `json:"current"` // 当前文件(相对路径)
	Speed   int64  `json:"speed"`   // 下载速度(字节/秒, 滑动窗口)
	Status  string `json:"status"`  // 状态(见 st* 常量)

	// ===== 字节级进度(仅"单包下载"阶段有意义: 直连通道的整包 zip) =====
	//
	// 为什么需要: 直连通道下载的是**一个**源码 zip, 逐文件计数始终是 0/1, 前端拿不到
	// 任何细粒度反馈 —— 而这个包可能有几十 MB, 在慢链路上要几分钟。用户看到进度条
	// 长时间不动会以为卡死。这里补字节字段让前端能显示真实百分比与速度。
	//
	// TotalBytes 为 0 表示"长度未知"(对端未给 Content-Length); 此时前端应退化为
	// 只显示已下载字节数 + 速度, 不要显示百分比。
	Bytes      int64 `json:"bytes,omitempty"`      // 已下载字节
	TotalBytes int64 `json:"totalBytes,omitempty"` // 总字节(0 = 未知)
}

// ProgressFunc 进度回调(可为 nil)
type ProgressFunc func(p UpdateProgress)

// UpdateResult 更新结果
type UpdateResult struct {
	Updated bool     `json:"updated"` // 是否实际发生更新
	Commit  string `json:"commit"`  // 应用后的 commit 哈希
	Files   int      `json:"files"`   // 下载并应用的文件数
	Skipped int      `json:"skipped"` // 跳过的文件数(如规则包中非 http/ 目录)
	Errors  []string `json:"errors"`
}

// speedMeter 下载速度滑动窗口统计
type speedMeter struct {
	mu    sync.Mutex
	bytes int64
	last  int64
	lastT time.Time
}

// add 计入 n 字节, 返回当前速度(字节/秒)
func (m *speedMeter) add(n int) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytes += int64(n)
	now := time.Now()
	dt := now.Sub(m.lastT).Seconds()
	var sp int64
	if dt > 0.2 {
		sp = int64(float64(m.bytes-m.last) / dt)
		m.last, m.lastT = m.bytes, now
	}
	return sp
}

// ===== 清单与增量对比 =====

// RemoteFile 远端清单中的单个文件
type RemoteFile struct {
	Path   string `json:"path"`   // 相对路径(规则包: http/xxx.yaml; CPE: cpe/xxx.json[.gz])
	Size   int64  `json:"size"`   // 文件大小(字节; CPE 为 gzip 压缩后大小)
	SHA256 string `json:"sha256"` // 文件 sha256(小写 hex; CPE 为压缩态哈希)
}

// RemoteManifest 远端包清单(源端生成, 发布时更新 commit)
type RemoteManifest struct {
	Commit string       `json:"commit"` // commit 哈希(增量对比基准)
	Name   string       `json:"name"`   // "rules" / "cpe"
	Files  []RemoteFile `json:"files"`
}

// UpdateCheck 更新检查结果
type UpdateCheck struct {
	Available    bool   `json:"available"`    // 是否有更新
	LocalCommit  string `json:"localCommit"`  // 本地已应用 commit
	RemoteCommit string `json:"remoteCommit"` // 远端最新 commit
	Files        int    `json:"files"`        // 待更新文件数
	Source       string `json:"source"`       // 命中的下载源
}

// readLocalCommit 读取本地已应用的 commit(文件缺失返回空串)
func readLocalCommit(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, ".commit"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeCommit 写入本地已应用的 commit(写失败只记日志, 不中断)
func writeCommit(dir, commit string) {
	// dir 走 pathrel.Short: slog 属性不经过 logLine 的相对化兜底
	short := pathrel.Short(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		updateLog.Warn("commit 目录创建失败", "dir", short, "err", err)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, ".commit"), []byte(commit+"\n"), 0o644); err != nil {
		updateLog.Warn("commit 写入失败", "dir", short, "err", err)
	}
}

// fetchManifest 依次尝试各下载源拉取清单(多源切换), 返回清单与命中源
func fetchManifest(name string) (*RemoteManifest, string, error) {
	upMu.RLock()
	sources := upCfg.Sources
	upMu.RUnlock()
	if len(sources) == 0 {
		return nil, "", errors.New("未配置下载源(SetDownloadSource)")
	}
	var lastErr error
	for _, src := range sources {
		data, err := fetchURL(src+name, 10*time.Second)
		if err != nil {
			lastErr = err
			updateLog.Warn("下载源拉取清单失败, 切换下一个源", "source", src, "err", err)
			continue
		}
		var m RemoteManifest
		if err := json.Unmarshal(data, &m); err != nil {
			lastErr = err
			updateLog.Warn("清单解析失败, 切换下一个源", "source", src, "err", err)
			continue
		}
		if m.Commit == "" {
			lastErr = errors.New("清单缺少 commit 字段")
			continue
		}
		return &m, src, nil
	}
	return nil, "", fmt.Errorf("所有下载源均失败: %w", lastErr)
}

// CheckRuleUpdate 检查规则包更新(增量对比 commit 哈希; 多源失败自动切换)。
// 未配置下载源或全部源不可达时返回错误(不影响任何现有文件)。
func CheckRuleUpdate() (*UpdateCheck, error) {
	m, src, err := fetchManifest("rules-manifest.json")
	if err != nil {
		return nil, err
	}
	local := readLocalCommit(rulesOfficialDir())
	return &UpdateCheck{
		Available:    m.Commit != local && len(m.Files) > 0,
		LocalCommit:  local,
		RemoteCommit: m.Commit,
		Files:        len(m.Files),
		Source:       src,
	}, nil
}

// CheckCPEUpdate 检查 CPE 库更新(增量对比 commit 哈希; 多源失败自动切换)
func CheckCPEUpdate() (*UpdateCheck, error) {
	m, src, err := fetchManifest("cpe-manifest.json")
	if err != nil {
		return nil, err
	}
	local := readLocalCommit(cpeDir())
	return &UpdateCheck{
		Available:    m.Commit != local && len(m.Files) > 0,
		LocalCommit:  local,
		RemoteCommit: m.Commit,
		Files:        len(m.Files),
		Source:       src,
	}, nil
}

// ===== 下载引擎(断点续传 + 并发 3) =====

const (
	downloadWorkers = 3      // 并发下载数
	chunkSize       = 32 << 10
)

// downloadOne 下载单个文件到 dest 的 .part 暂存(支持 Range 断点续传), 完成后核对大小
func downloadOne(client *http.Client, u, dest string, f RemoteFile, meter *speedMeter) error {
	if upDownloadFn != nil {
		if err := upDownloadFn(u, dest, f, meter); err != nil {
			return err
		}
		// 钩子实现不负责大小核对, 统一在这里校验
		return checkPartSize(dest+".part", f.Size, f.Path)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	part := dest + ".part"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	var off int64
	if st, serr := os.Stat(part); serr == nil {
		off = st.Size()
		if off >= f.Size {
			return nil // 上次已下完, 等校验阶段确认
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if off > 0 && resp.StatusCode != http.StatusPartialContent {
		off = 0 // 源端不支持续传, 从头开始
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, u)
	}
	flags := os.O_WRONLY | os.O_CREATE
	if off == 0 {
		flags |= os.O_TRUNC
	}
	fw, err := os.OpenFile(part, flags, 0o644)
	if err != nil {
		return err
	}
	buf := make([]byte, chunkSize)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := fw.Write(buf[:n]); werr != nil {
				fw.Close()
				return werr
			}
			meter.add(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			fw.Close()
			return rerr
		}
	}
	if cerr := fw.Close(); cerr != nil {
		return cerr
	}
	return checkPartSize(part, f.Size, f.Path)
}

// checkPartSize 核对 .part 下载后的字节数, 不符则清除并返回错误
func checkPartSize(part string, want int64, label string) error {
	st, err := os.Stat(part)
	if err != nil || st.Size() != want {
		os.Remove(part)
		return fmt.Errorf("%s: 下载大小不符(期望 %d 字节)", label, want)
	}
	return nil
}

// downloadAll 以 3 并发下载全部文件到 staging 目录; 进度经 pf 回调。
//
// localStage 非空时表示"包体已在本地"(直连官方仓库通道: 源码 zip 已被解包到本地
// 暂存目录), 此时逐文件做本地拷贝而不是再发一次 HTTP —— 否则会把已经拿到的模板
// 重新拉一遍, 既慢又白耗流量。语义上仍是"把 staging 填满待校验的文件"。
func downloadAll(client *http.Client, base, staging string, files []RemoteFile, pf ProgressFunc, meter *speedMeter) error {
	localStage := ""
	if s := localStageOf(client); s != "" {
		localStage = s
	}
	jobs := make(chan RemoteFile)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	done := 0
	report := func(cur, status string) {
		if pf == nil {
			return
		}
		mu.Lock()
		p := UpdateProgress{Total: len(files), Done: done, Current: cur, Speed: meter.add(0), Status: status}
		mu.Unlock()
		pf(p)
	}
	for w := 0; w < downloadWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				var err error
				if localStage != "" {
					err = copyStagedFile(localStage, staging, f)
				} else {
					err = downloadOne(client, base+f.Path, filepath.Join(staging, f.Path), f, meter)
				}
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				}
				done++
				mu.Unlock()
				report(f.Path, stDownloading)
			}
		}()
	}
	for _, f := range files {
		jobs <- f
	}
	close(jobs)
	wg.Wait()
	return firstErr
}

// verifyFiles 对 staging 中的全部文件做 sha256 完整性校验(暂存文件带 .part 后缀)
func verifyFiles(staging string, files []RemoteFile) error {
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(staging, f.Path) + ".part")
		if err != nil {
			return fmt.Errorf("%s: 读取暂存文件失败 %v", f.Path, err)
		}
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), f.SHA256) {
			return fmt.Errorf("%s: sha256 校验失败(可能已被篡改)", f.Path)
		}
	}
	return nil
}

// copyStagedFile 把本地暂存目录中的文件拷进"下载暂存区"(仍带 .part 后缀),
// 使后续的校验/应用阶段完全无感知 —— 两条通道走同一套落地代码。
func copyStagedFile(srcStage, staging string, f RemoteFile) error {
	src := filepath.Join(srcStage, filepath.FromSlash(f.Path))
	dst := filepath.Join(staging, filepath.FromSlash(f.Path)) + ".part"
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("%s: 读取本地暂存文件失败 %v", f.Path, err)
	}
	return os.WriteFile(dst, data, 0o644)
}

// localStageTransport 承载"本地暂存目录"的传输层。
//
// 为什么走 Transport 载体: 既有 downloadAll 的签名是
// downloadAll(client, base, staging, ...), 直连通道没有第二个下载源可传(base 用不上),
// 在这里改签名会牵动 CPE 通道; 把"本地暂存目录"挂在 Transport 上传递, 可以让签名字面
// 不变、两条通道共用同一份实现(改动最小, 见项目规则 1)。
//
// RoundTrip 刻意返回错误: 一旦代码真的拿它发请求, 说明本地拷贝分支没生效,
// 此时必须显式失败而不是静默走网络(避免"以为在本地拷贝, 实际又把包拉了一遍")。
type localStageTransport struct {
	localStage string
}

func (t *localStageTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("本地暂存模式不应发起网络请求(内部错误)")
}

// localStageOf 从客户端里取出本地暂存目录(不是本地模式则返回空串)
func localStageOf(c *http.Client) string {
	if c == nil {
		return ""
	}
	if lt, ok := c.Transport.(*localStageTransport); ok {
		return lt.localStage
	}
	return ""
}

// newLocalStageClient 构造"本地暂存模式"的客户端(不用于网络请求)
func newLocalStageClient(stage string) *http.Client {
	return &http.Client{Transport: &localStageTransport{localStage: stage}}
}

// ===== 暂存 -> 正式目录(原子替换 + 回滚) =====

// copyFile 拷贝文件(小文件场景, 规则包/CPE 包均远小于内存上限)
func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o644)
}

// applyFile 把暂存文件原子替换到正式位置: 先写到 target.new 再 rename,
// 任一步失败删除 .new, 旧文件保持不动(回滚语义)
func applyFile(stagingFile, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp := target + ".new"
	if err := copyFile(stagingFile, tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// removeStaging 清除整个暂存目录(失败回滚: 旧规则文件未被触碰)
func removeStaging(dir string) {
	if err := os.RemoveAll(dir); err != nil {
		updateLog.Warn("暂存目录清理失败", "dir", dir, "err", err)
	}
}

// updateChecksumFile 把本次更新的文件登记进 rules/checksum.sha256(供 ruleset 下次加载校验)
func updateChecksumFile(dir string, files []RemoteFile) {
	m := loadRuleChecksums(dir)
	for _, f := range files {
		m[f.Path] = strings.ToLower(f.SHA256)
	}
	var sb strings.Builder
	for k, v := range m {
		fmt.Fprintf(&sb, "%s  %s\n", v, k)
	}
	p := filepath.Join(dir, "checksum.sha256")
	if err := os.MkdirAll(dir, 0o755); err == nil {
		if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
			updateLog.Warn("checksum.sha256 更新失败", "err", err)
		}
	}
}

// ===== 规则库更新 =====

// DownloadRuleUpdate 下载并应用规则包更新。
//
// 流程: 拉清单(多源切换) -> 过滤仅 http/ 目录模板 -> 并发 3 断点续传到暂存目录
// -> sha256 全量校验(失败回滚: 清除暂存, 不动正式文件) -> 原子替换到 rules/
// -> 登记 checksum.sha256 + commit -> RefreshRules 热加载(无需重启)。
func DownloadRuleUpdate(pf ProgressFunc) (*UpdateResult, error) {
	m, src, err := fetchManifest("rules-manifest.json")
	if err != nil {
		if pf != nil {
			pf(UpdateProgress{Status: stError})
		}
		return nil, err
	}
	return applyManifest(m, src, pf, "")
}

// applyManifest 把一份清单落地到 rules/ 目录(自建源通道与直连通道共用的唯一实现)。
//
//   - m      远端清单(commit + 逐文件 size/sha256)
//   - src    文件下载源(base URL); 与 localStage 二选一
//   - localStage 非空表示包体已在本地(直连官方仓库通道), 直接本地拷贝不走网络
//
// 流程: 过滤仅 http/ 目录模板 -> 并发 3 断点续传到暂存目录 -> sha256 全量校验
// (失败回滚: 清除暂存, 不动正式文件) -> 原子替换到 rules/ -> 登记 checksum.sha256
// + commit -> RefreshRules 热加载(无需重启)。
//
// 抽成独立函数的动机: 直连通道需要绕过"自建源多源切换", 但下载/校验/回滚/备份/
// 热加载这些语义必须与自建源通道完全一致。复制一份实现是安全隐患(两边会各自漂移),
// 所以这里只做"清单从哪来"的解耦, 落地语义只有一份。
func applyManifest(m *RemoteManifest, src string, pf ProgressFunc, localStage string) (*UpdateResult, error) {
	res := &UpdateResult{}
	t0 := time.Now()
	emit := func(status string) {
		if pf == nil {
			return
		}
		pf(UpdateProgress{Total: res.Files, Done: res.Files, Status: status})
	}
	if m == nil {
		emit(stError)
		return nil, errors.New("清单为空")
	}
	dir := rulesOfficialDir()
	oldCommit := readLocalCommit(dir) // 版本记录: 更新前本地 commit(失败日志/备份命名用)
	logFail := func(stage string, err error) {
		logUpdateEntry(UpdateLogEntry{Time: time.Now(), Kind: "rules", FromCommit: oldCommit,
			Files: res.Files, Status: "rollback", Error: stage + ": " + err.Error(),
			DurationMS: time.Since(t0).Milliseconds()})
	}

	// 只下载 http/ 目录模板(硬过滤, 源端误发其他目录也拦截)
	var files []RemoteFile
	for _, f := range m.Files {
		p := filepath.ToSlash(strings.TrimSpace(f.Path))
		if !strings.HasPrefix(p, "http/") {
			res.Skipped++
			updateLog.Info("规则包文件不在 http/ 目录, 跳过", "path", p)
			continue
		}
		files = append(files, RemoteFile{Path: p, Size: f.Size, SHA256: strings.ToLower(f.SHA256)})
	}
	res.Files = len(files) // 进度口径: 总文件数 = 实际下载文件数(skipped 只在结果中体现)
	if len(files) == 0 {
		emit(stUptodate)
		res.Updated = false
		return res, nil
	}

	staging := filepath.Join(dir, ".staging")
	emit(stDownloading)
	client := newHTTPClient(10 * time.Minute)
	if localStage != "" {
		client = newLocalStageClient(localStage) // 本地已有包体: 走拷贝而不是 HTTP
	}
	meter := &speedMeter{lastT: time.Now()}
	if err := downloadAll(client, src, staging, files, pf, meter); err != nil {
		removeStaging(staging) // 回滚: 清除暂存, 正式文件未动
		updateLog.Error("规则包下载失败, 已回滚(暂存清除)", "err", err)
		logFail("下载失败", err)
		emit(stError)
		return nil, fmt.Errorf("规则包下载失败: %w", err)
	}

	emit(stVerifying)
	if err := verifyFiles(staging, files); err != nil {
		removeStaging(staging) // 回滚
		updateLog.Error("规则包校验失败, 已回滚(暂存清除, 旧规则保留)", "err", err)
		logFail("sha256 校验失败", err)
		emit(stError)
		return nil, fmt.Errorf("规则包校验失败: %w", err)
	}

	emit(stApplying)
	// 旧版本自动备份: 覆盖正式文件前保留上一可用版本(保留最近 3 版)
	if oldCommit != "" {
		backupOldVersion(dir, "rules", oldCommit)
	}
	for _, f := range files {
		if err := applyFile(filepath.Join(staging, f.Path)+".part", filepath.Join(dir, f.Path)); err != nil {
			removeStaging(staging) // 回滚
			updateLog.Error("规则包应用失败, 已回滚", "file", f.Path, "err", err)
			logFail("应用失败", err)
			emit(stError)
			return nil, fmt.Errorf("规则包应用失败: %w", err)
		}
	}
	updateChecksumFile(dir, files)
	writeCommit(dir, m.Commit)
	removeStaging(staging)

	// 热加载: 全部校验通过后自动生效, 无需重启
	RefreshRules()
	updateLog.Info("规则包更新完成并热加载", "source", src, "commit", m.Commit, "files", len(files))
	logUpdateEntry(UpdateLogEntry{Time: time.Now(), Kind: "rules", FromCommit: oldCommit,
		ToCommit: m.Commit, Files: len(files), Status: "success",
		DurationMS: time.Since(t0).Milliseconds()})
	res.Updated = true
	res.Commit = m.Commit
	emit(stDone)
	return res, nil
}

// ===== CPE 库更新(精简/完整版, gzip) =====

// DownloadCPEUpdate 下载并应用 CPE 库更新(gzip 压缩传输, 内存解压, 校验后生效)。
//
// 流程: 拉清单 -> 并发下载到暂存目录 -> sha256 校验(压缩态) -> 逐个 gzip 解压
// (内存, 不生成临时文件) + JSON 合法性校验 -> 写入 cpe/ 目录 -> commit
// -> RefreshCPE 热加载。任一步失败清除暂存回滚, 不动现有 CPE 库。
func DownloadCPEUpdate(pf ProgressFunc) (*UpdateResult, error) {
	res := &UpdateResult{}
	t0 := time.Now()
	emit := func(status string) {
		if pf == nil {
			return
		}
		pf(UpdateProgress{Total: res.Files, Done: res.Files, Status: status})
	}
	m, src, err := fetchManifest("cpe-manifest.json")
	if err != nil {
		emit(stError)
		return nil, err
	}
	dir := cpeDir()
	oldCommit := readLocalCommit(dir) // 版本记录: 更新前本地 commit
	logFail := func(stage string, err error) {
		logUpdateEntry(UpdateLogEntry{Time: time.Now(), Kind: "cpe", FromCommit: oldCommit,
			Files: res.Files, Status: "rollback", Error: stage + ": " + err.Error(),
			DurationMS: time.Since(t0).Milliseconds()})
	}

	var files []RemoteFile
	for _, f := range m.Files {
		p := filepath.ToSlash(strings.TrimSpace(f.Path))
		if p == "" {
			res.Skipped++
			continue
		}
		files = append(files, RemoteFile{Path: p, Size: f.Size, SHA256: strings.ToLower(f.SHA256)})
	}
	res.Files = len(files) // 进度口径: 总文件数 = 实际下载文件数(skipped 只在结果中体现)
	if len(files) == 0 {
		emit(stUptodate)
		res.Updated = false
		return res, nil
	}

	staging := filepath.Join(dir, ".staging")
	emit(stDownloading)
	client := newHTTPClient(10 * time.Minute)
	meter := &speedMeter{lastT: time.Now()}
	if err := downloadAll(client, src, staging, files, pf, meter); err != nil {
		removeStaging(staging)
		updateLog.Error("CPE 库下载失败, 已回滚", "err", err)
		logFail("下载失败", err)
		emit(stError)
		return nil, fmt.Errorf("CPE 库下载失败: %w", err)
	}

	emit(stVerifying)
	if err := verifyFiles(staging, files); err != nil {
		removeStaging(staging)
		updateLog.Error("CPE 库校验失败, 已回滚", "err", err)
		logFail("sha256 校验失败", err)
		emit(stError)
		return nil, fmt.Errorf("CPE 库校验失败: %w", err)
	}

	emit(stApplying)
	// 旧版本自动备份: 覆盖正式文件前保留上一可用版本(保留最近 3 版)
	if oldCommit != "" {
		backupOldVersion(dir, "cpe", oldCommit)
	}
	// 解压(内存) + JSON 校验 + 写入正式目录; 全部成功才落盘 commit 并热加载
	for _, f := range files {
		if err := applyCPEFile(dir, staging, f, logFail); err != nil {
			removeStaging(staging) // 回滚: 旧 CPE 库保留
			emit(stError)
			return nil, err
		}
	}
	writeCommit(dir, m.Commit)
	removeStaging(staging)

	// 热加载: 校验通过即生效
	RefreshCPE()
	updateLog.Info("CPE 库更新完成并热加载", "source", src, "commit", m.Commit, "files", len(files))
	logUpdateEntry(UpdateLogEntry{Time: time.Now(), Kind: "cpe", FromCommit: oldCommit,
		ToCommit: m.Commit, Files: len(files), Status: "success",
		DurationMS: time.Since(t0).Milliseconds()})
	res.Updated = true
	res.Commit = m.Commit
	emit(stDone)
	return res, nil
}

// applyCPEFile 解压(内存) + JSON 校验 + 写入单个 CPE 文件; 失败经 logFail 记更新日志
func applyCPEFile(dir, staging string, f RemoteFile, logFail func(string, error)) error {
	target := filepath.Join(dir, strings.TrimSuffix(f.Path, ".gz"))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		logFail("CPE 目录创建失败", err)
		return fmt.Errorf("CPE 目录创建失败: %w", err)
	}
	gz, err := os.ReadFile(filepath.Join(staging, f.Path) + ".part")
	if err != nil {
		logFail("读取暂存失败", err)
		return fmt.Errorf("%s: 读取暂存失败 %v", f.Path, err)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		updateLog.Error("CPE 文件不是合法 gzip, 已回滚", "file", f.Path, "err", err)
		logFail("不是合法 gzip", err)
		return fmt.Errorf("%s: 不是合法 gzip: %w", f.Path, err)
	}
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		logFail("gzip 解压失败", err)
		return fmt.Errorf("%s: gzip 解压失败 %v", f.Path, err)
	}
	var probe cpeFile // 结构校验: 保证是合法 CPE 字典 JSON
	if err := json.Unmarshal(data, &probe); err != nil {
		updateLog.Error("CPE 文件 JSON 非法, 已回滚", "file", f.Path, "err", err)
		logFail("JSON 非法", err)
		return fmt.Errorf("%s: JSON 非法: %w", f.Path, err)
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		logFail("写入失败", err)
		return fmt.Errorf("%s: 写入失败 %v", f.Path, err)
	}
	return nil
}

// ===== 后台自动更新(异步, 不阻塞启动) =====

var upStartOnce sync.Once

// StartUpdater 启动后台更新循环(协程, 立即返回, 不阻塞启动)。
// 仅当 AutoUpdate 开关开启且周期 > 0 时执行检查与更新;
// 每次循环重新读取开关, 运行中 SetAutoUpdate(false) 即停止。
// 调用方(main.go 启动流程)只需调用一次。
func StartUpdater() {
	upStartOnce.Do(func() {
		go func() {
			for {
				upMu.RLock()
				on, iv := upCfg.AutoUpdate, upCfg.Interval
				upMu.RUnlock()
				if on && iv > 0 {
					runAutoUpdate()
					time.Sleep(iv)
				} else {
					time.Sleep(5 * time.Minute) // 关闭时低频复查开关
				}
			}
		}()
		updateLog.Info("后台更新任务已启动(异步)", "autoUpdate", upCfg.AutoUpdate, "interval", upCfg.Interval)
	})
}

// runAutoUpdate 执行一轮自动更新(规则包 + CPE 库 + 直连官方仓库), 失败只记日志不 panic
//
// 【直连通道为什么必须在这里也要跑】
// 自建源(sources)要求源端提供 rules-manifest.json, 而官方 nuclei-templates 仓库
// 不提供这种格式 —— 也就是说"只想用官方模板、懒得自建源"的用户在早期版本里即使
// 打开了 autoUpdate 也永远拿不到更新(CheckRuleUpdate 直接报"未配置下载源")。
// 这与"能自动从官方更新"的预期不符, 所以把直连通道接进同一轮自动更新:
// 两条通道各自独立检查, 谁有新版本就更新谁。
//
// 顺序刻意"直连在前": 直连通道是内置默认源(无需任何配置), 先跑它能保证
// "开了 autoUpdate 就一定有效果"; 自建源放后面, 有配置时再覆盖(自建源通常
// 是内网镜像, 更适合作为企业环境的正式通道)。
func runAutoUpdate() {
	runAutoDirectUpdate()
	if c, err := CheckRuleUpdate(); err != nil {
		updateLog.Warn("自动更新: 规则包检查失败", "err", err)
	} else if c.Available {
		if _, err := DownloadRuleUpdate(nil); err != nil {
			updateLog.Error("自动更新: 规则包更新失败", "err", err)
		}
	}
	if c, err := CheckCPEUpdate(); err != nil {
		updateLog.Warn("自动更新: CPE 库检查失败", "err", err)
	} else if c.Available {
		if _, err := DownloadCPEUpdate(nil); err != nil {
			updateLog.Error("自动更新: CPE 库更新失败", "err", err)
		}
	}
}

// runAutoDirectUpdate 自动更新里的"直连官方仓库"分支。
//
// 与自建源分支的关键差异: 直连通道从 api.github.com 查提交号, 匿名限速 60 次/小时。
// 自动更新周期通常 24h, 单次只查一次不会触顶; 但若用户把周期调到很短(或手动频繁
// 触发), 触顶会一直报 403 —— 这时记日志提示即可, 不要退出循环(下个周期自然恢复)。
func runAutoDirectUpdate() {
	if !directEnabled() {
		return // 未开启直连通道: 零网络行为
	}
	c, err := CheckDirect()
	if err != nil {
		updateLog.Warn("自动更新: 直连官方仓库检查失败", "err", err,
			"hint", "GitHub API 匿名限速 60 次/小时, 可配置 updater.json 的 proxy 或稍后重试")
		return
	}
	if !c.Available {
		updateLog.Info("自动更新: 官方模板已是最新", "rev", c.LocalCommit)
		return
	}
	updateLog.Info("自动更新: 发现官方模板新版本", "remote", c.RemoteRev, "local", c.LocalCommit)
	if _, err := DirectUpdate(nil); err != nil {
		updateLog.Error("自动更新: 直连官方仓库更新失败", "err", err)
	}
}
