// rules_sync.go 漏洞规则一键同步: 从 NVD API 2.1 拉取 CVE 数据, 过滤到可指纹产品,
// 输出到 exe 同目录 vuln/cpe/ 热更新目录(2026-09-24 dist 目录整理: 规则库统一收进
// vuln/; 与 scripts/nvd_sync.go 逻辑一致, 但以内置 API 形式
// 供前端"一键同步"按钮调用, 无需用户手动跑脚本)。
//
// 设计:
//   - 默认关闭(规则 5): 仅在用户显式点击"一键同步"时才发起网络请求, 不自动执行
//   - 后台 goroutine 执行, 不阻塞 HTTP handler
//   - 进度通过 atomic 变量 + progress 端点轮询
//   - 网络不可达(NVD 403/超时)时明确报错, 不静默失败
//   - 输出格式与 cpe_builtin.json 一致(cpeFile), 放入 cpe/ 后程序热加载即生效
//
// ===== 增量同步(2026-09-24, 用户反馈"重开服务后又从头开始同步") =====
//
// 旧行为只有全量: 每次点同步都从第 1 页拉全部 ~40 万条 CVE(20-40 分钟), 同步
// 中途重启服务则进度全丢(结果只在收尾时持久化), 用户只能再点一次从头再来。
// 现在: 有上次完成记录时默认增量 —— 只拉"上次同步之后 NVD 修改过的 CVE"
// (lastModStartDate), 并**合并**进已有 nvd-*.json(按 CVE 号 upsert: 新覆盖旧、
// 未变化的保留)。NVD 该过滤只返回"修改过"的条目, 直接覆盖会丢掉全部未变化的
// CVE, 所以合并是必须的。用户显式勾选"全量重同步"或上次同步被中断(无完成记录)
// 时回退全量; 增量模式下输出目录里没有任何已有文件(被手工删过)也自动回退全量。
//
// ===== NVD API 2.1 迁移(2026-09-24, 用户反馈"一键同步 403"的根因) =====
//
// 旧 2.0 端点 https://services.nist.gov/api/cve/cves 已于 2025-07 退役, 现在
// 直接回 403 —— 这就是"拉取第 1 页失败: HTTP 403"的来源, 重试多少次都没用。
// 2.1 端点为 https://services.nvd.nist.gov/rest/json/cves/2.0, 与 2.0 的差异:
//   - 分页: page+pageSize → startIndex(0 基偏移)+resultsPerPage(上限 2000),
//     响应没有 totalPages, 用 totalResults 自算页数
//   - 响应体: items[] → vulnerabilities[].cve; CVE 编号在 cve.id(旧版是顶层 cveId)
//   - 限流(官方口径): 匿名 5 次/30 秒, 带 API Key 50 次/30 秒, 超限回 429 +
//     Retry-After。旧代码注释"无 Key 5 req/s"是错的 —— 按 5 req/s 发(250ms 间隔)
//     会立刻被 429。这里用滑动窗口节流 + 429 按 Retry-After 退避双保险。
//   - 可选 API Key(nist.gov 免费申请): 页面填写后存 settings.json 的 nvd 节,
//     同步速度 10 倍(全量 40 万条: 匿名约 20 分钟, 带 Key 约 3-5 分钟)。
//
// ===== 全量分批续传(2026-09-25, 用户反馈"同步中途关服务, 重开能不能续上") =====
//
// 增量只解决了"第二次同步慢", 解决不了"首次全量跑到一半服务停了" —— 旧全量是
// 一条连续分页链: 只在全部页拉完之后才落盘, 中途停进程 = 前面几十页白跑, 重开
// 从第 1 页再来(且没有完成记录, 连增量都用不上)。现在全量切成若干批, **每批跑
// 完立即落盘**并持久化进度, 下次点同步(含服务重启后)从断点继续。
//
// ===== 为什么按"页"分批而不是按"日期"分批(2026-09-25 实测推翻原设计) =====
//
// 最初按 lastMod 日期窗口切批(90 天一批, 靠 lastModStartDate/EndDate 过滤)。
// 实测跑废了: 用户网络对**任何带日期参数的 NVD 请求都返回 404**(换 Z 后缀、
// 换无时区、换 pubStartDate 全是 404), 只有不带日期参数才 200 —— 结果是 109
// 批每批都拉到 0 条, 白跑半小时, 库里一条没多:
//
//   不带参数                              -> 200, totalResults=397416
//   &lastModStartDate=...T00:00:00.000Z   -> 404
//   &lastModStartDate=...T00:00:00.000+00:00 -> 404
//   &pubStartDate=...                     -> 404
//
// 所以分批维度必须换成**不依赖日期**的东西: startIndex 分页偏移。当前口径:
//   - 每批 nvdBatchPages 页(默认 10 页 = 2 万条 CVE), 全库约 199 页 → 约 20 批;
//   - 请求只带 resultsPerPage/startIndex/apiKey, 不带任何日期参数;
//   - 每批跑完 → 写盘 vuln/cpe/nvd-*.json + 写 settings.json 的 nvd.resume
//     {nextPage, next}; 中断后从 nextPage 继续, 已完成批次不重跑;
//   - 粒度是"批": 中断最多丢当前批(10 页), 前面的批已落盘。
// 副作用: 该网络下 NVD 只剩"拉全量"一条路, 真·增量(lastMod 过滤)不可用 ——
// 重复同步靠 upsert 幂等合并不产生重复条目, 只是时间成本不变。

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ===== 产品映射(与 scripts/nvd_sync.go 的 nvdKeyMap 一致) =====

var rulesSyncKeyMap = map[string]string{
	"apache:http_server":     "apache",
	"apache:httpd":           "apache",
	"nginx:nginx":            "nginx",
	"microsoft:iis":          "iis",
	"microsoft:web_server":   "iis",
	"apache:tomcat":          "tomcat",
	"eclipse:jetty":          "jetty",
	"jetty:jetty":            "jetty",
	"jenkins:jenkins":        "jenkins",
	"openssh:openssh":        "openssh",
	"redis:redis":            "redis",
	"oracle:mysql":           "mysql",
	"mariadb:mariadb_server": "mariadb",
	"postgresql:postgresql":  "postgresql",
	"mongodb:mongodb":        "mongodb",
	"elastic:elasticsearch":  "elasticsearch",
	"exim:exim":              "exim",
	"php:php":                "php",
	"memcached:memcached":    "memcached",
	"ntp:ntp":                "ntp",
	"samba:samba":            "samba",
	"docker:docker":          "docker",
	"haproxy:haproxy":        "haproxy",
}

// ===== 同步状态 =====

var (
	rulesSyncRunning atomic.Bool
	rulesSyncMu      sync.Mutex // 防止并发启动
	rulesSyncState   struct {
		Running     bool           `json:"running"`
		TotalPages  int            `json:"totalPages"`
		CurrentPage int            `json:"currentPage"`
		TotalCVEs   int            `json:"totalCves"`
		KeptCVEs    int            `json:"keptCves"`
		Products    int            `json:"products"`
		StartedAt   time.Time      `json:"startedAt"`
		FinishedAt  time.Time      `json:"finishedAt"`
		Error       string         `json:"error,omitempty"`
		Files       []string       `json:"files,omitempty"`
		Source      string         `json:"source,omitempty"`
		MinCVSS     float64        `json:"minCvss,omitempty"`
		// APIKeyConfigured 本次同步是否带 NVD API Key(前端据此提示限速档位)。
		// 只回 true/false, 不回显 Key 本身。
		APIKeyConfigured bool `json:"apiKeyConfigured,omitempty"`
		// Mode 同步模式: full=全量 / incremental=增量(只拉上次同步后修改的 CVE)。
		// 空值=无完成记录时的首次全量(与 full 行为相同, 仅展示口径不同)。
		Mode  string `json:"mode,omitempty"`
		Since string `json:"since,omitempty"`
		// 全量分批进度(2026-09-25): 第几批 / 共几批 / 当前批的页范围。
		// 前端据此显示"第 3/20 批(第 21-30 页)", 让用户知道 20 分钟不是卡死。
		BatchIndex    int `json:"batchIndex,omitempty"`
		BatchTotal    int `json:"batchTotal,omitempty"`
		BatchFromPage int `json:"batchFromPage,omitempty"`
		BatchToPage   int `json:"batchToPage,omitempty"`
		// Resumable 存在未完成的分批计划(下次点同步可从断点继续)。
		// 只在未运行时回带: 运行中进度本身就是实时的, 不需要这个提示。
		Resumable bool `json:"resumable,omitempty"`
	}
)

// ===== API 路由注册 =====

func registerRulesSyncRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/vuln/rules/sync", requireAuth(handleRulesSyncStart))
	mux.HandleFunc("GET /api/vuln/rules/sync/progress", requireAuth(handleRulesSyncProgress))
}

// ===== 启动同步 =====

func handleRulesSyncStart(w http.ResponseWriter, r *http.Request) {
	if rulesSyncRunning.Load() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "同步任务已在进行中, 请稍候"})
		return
	}

	// 解析可选参数
	var req struct {
		MinCVSS float64 `json:"minCvss"`
		Since   string  `json:"since"`
		APIKey  string  `json:"apiKey"`
		Full    bool    `json:"full"` // 显式全量重同步(默认=有完成记录时增量)
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.MinCVSS < 0 {
		req.MinCVSS = 0
	}
	// API Key: 请求体显式给了就保存并采用(用户填一次, 下次留空即用已存的);
	// 没给则回退 settings.json 的 nvd 节; 都没有 = 匿名档(5 次/30 秒)。
	key := nvdAPIKey(strings.TrimSpace(req.APIKey))

	// 增量默认: 有上次完成记录且用户没显式指定 full/since 时, 只拉上次同步之后
	// 修改过的 CVE(见文件头"增量同步"节)。中断过的同步没有完成记录 → 自然回退全量。
	var syncSince string
	syncSince, mode := decideSyncMode(req.Since, req.Full)
	req.Since = syncSince

	// 分批计划: 全量走"按 lastMod 日期分批", 每批落盘一次, 中断可续(文件头
	// "全量分批续传"节)。三种走向:
	//   1) 有未完成的 resume 且本次没显式指定起点/全量重来 → 从断点续;
	//   2) 无 resume 且判定为全量 → 新建计划从头分批;
	//   3) 显式增量(since 非空) → 仍走单区间 syncNVD(增量本来就快, 无需分批)。
	// resume 的 MinCVSS 与本次不一致时不能续: 过滤条件变了, 前面批的数据口径不同。
	var batch *nvdResume
	if req.Since == "" {
		if pending := loadNVDResume(); pending != nil && !req.Full && pending.MinCVSS == req.MinCVSS {
			batch = pending
			mode = "resume"
			logLine(fmt.Sprintf("检测到上次未完成的同步, 从第 %d/%d 批继续(第 %d 页起)",
				pending.Next+1, pending.Total, pending.NextPage))
		} else {
			batch = newNVDResume(req.MinCVSS)
			mode = "full-batch"
		}
	}

	rulesSyncMu.Lock()
	rulesSyncState.Running = true
	rulesSyncState.StartedAt = time.Now()
	rulesSyncState.FinishedAt = time.Time{}
	rulesSyncState.Error = ""
	rulesSyncState.CurrentPage = 0
	rulesSyncState.TotalPages = 0
	rulesSyncState.TotalCVEs = 0
	rulesSyncState.KeptCVEs = 0
	rulesSyncState.Products = 0
	rulesSyncState.Files = nil
	rulesSyncState.Source = "nvd"
	rulesSyncState.MinCVSS = req.MinCVSS
	rulesSyncState.APIKeyConfigured = key != ""
	rulesSyncState.Mode = mode
	rulesSyncState.Since = req.Since
	rulesSyncState.Resumable = false
	rulesSyncState.BatchIndex = 0
	rulesSyncState.BatchTotal = 0
	rulesSyncState.BatchFromPage = 0
	rulesSyncState.BatchToPage = 0
	if batch != nil {
		rulesSyncState.BatchIndex = batch.Next
		rulesSyncState.BatchTotal = batch.Total
	}
	rulesSyncMu.Unlock()

	rulesSyncRunning.Store(true)
	go func() {
		defer rulesSyncRunning.Store(false)
		// 收尾顺序(LIFO): 先落 FinishedAt, 再持久化结果, 最后清运行标志
		defer persistNVDLastSync()
		defer func() {
			rulesSyncMu.Lock()
			rulesSyncState.Running = false
			rulesSyncState.FinishedAt = time.Now()
			rulesSyncMu.Unlock()
		}()
		if batch != nil {
			syncNVDBatched(req.MinCVSS, key, batch)
			return
		}
		syncNVD(req.MinCVSS, req.Since, key)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"started": true,
		"message": "NVD 同步已启动, 请轮询 /api/vuln/rules/sync/progress 查看进度",
	})
}

func handleRulesSyncProgress(w http.ResponseWriter, _ *http.Request) {
	restoreNVDLastSync()
	rulesSyncMu.Lock()
	state := rulesSyncState
	rulesSyncMu.Unlock()
	// 未运行时回带"可续传"标记: 上次同步被中断(停服务/强杀)后, 用户刷新页面
	// 应能看到"可从第 N 批继续", 否则只能看到"从未同步"或一份过期统计。
	if !state.Running {
		if r := loadNVDResume(); r != nil {
			state.Resumable = true
			state.BatchIndex = r.Next
			state.BatchTotal = r.Total
			state.KeptCVEs = r.KeptCVEs
			state.TotalCVEs = r.TotalCVEs
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(state)
}

// ===== 最近一次同步结果持久化 =====
//
// 规则文件本身在 cpe/ 目录是持久的(重启照常热加载), 但"上次同步时间/统计"
// 原先只存在进程内存(rulesSyncState) —— 服务一重启页面就显示"从未同步",
// 用户会以为要重新点一键同步(同步要 20-40 分钟)。所以把收尾结果存到
// settings.json 的 nvd 节, 进程重启后首次读进度时恢复展示状态。

// nvdLastSync 持久化到 settings.json nvd.lastSync 的最近一次同步结果。
type nvdLastSync struct {
	FinishedAt time.Time  `json:"finishedAt"`
	Products   int        `json:"products"`
	KeptCVEs   int        `json:"keptCves"`
	TotalCVEs  int        `json:"totalCves"`
	Files      []string   `json:"files,omitempty"`
	Source     string     `json:"source,omitempty"`
	Error      string     `json:"error,omitempty"`
	Mode       string     `json:"mode,omitempty"` // full / incremental(增量依赖 finishedAt 作起点)
}

// persistNVDLastSync 把当前终态写到 settings.json 的 nvd 节。
// 必须"读-合并-写"而不是整节替换: writeSection 是整节覆盖, 同一 nvd 节里
// 还存着用户填的 apiKey, 直接替换会把 Key 抹掉。
func persistNVDLastSync() {
	rulesSyncMu.Lock()
	st := rulesSyncState
	rulesSyncMu.Unlock()

	kv := nvdSectionKV()
	kv["lastSync"] = nvdLastSync{
		FinishedAt: st.FinishedAt,
		Products:   st.Products,
		KeptCVEs:   st.KeptCVEs,
		TotalCVEs:  st.TotalCVEs,
		Files:      st.Files,
		Source:     st.Source,
		Error:      st.Error,
		Mode:       st.Mode,
	}
	if err := writeNVDSectionKV(kv); err != nil {
		logLine("NVD 同步结果持久化失败(不影响规则文件本身): " + err.Error())
	}
}

// loadNVDLastSync 从 settings.json 读回最近一次同步结果。
// 直接读盘而非走 settings 缓存: 恢复时机(首个进度请求)可能早于缓存填充,
// 且读盘拿到的就是"当前真实内容", 与 writeSection 的口径一致。
func loadNVDLastSync() *nvdLastSync {
	data, err := os.ReadFile(settingsFilePath())
	if err != nil {
		return nil
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(stripBOM(data), &top) != nil {
		return nil
	}
	raw, ok := top[secNVD]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var kv struct {
		LastSync *nvdLastSync `json:"lastSync"`
	}
	if json.Unmarshal(raw, &kv) != nil {
		return nil
	}
	return kv.LastSync
}

// 指针而非值: 值拷贝会触发 go vet noCopy 告警, 且测试需整体替换来重置单例。
var nvdRestoreOnce = &sync.Once{}

// restoreNVDLastSync 进程重启后恢复展示状态。只在"没有进行中的同步且内存
// 里没有完成记录"时生效 —— 正在跑的新同步自然覆盖旧结果, 无需特殊处理。
// 用 Once 保证恢复只发生一次, 之后的进度请求直接读内存。
func restoreNVDLastSync() {
	nvdRestoreOnce.Do(func() {
		rulesSyncMu.Lock()
		need := !rulesSyncState.Running && rulesSyncState.FinishedAt.IsZero()
		rulesSyncMu.Unlock()
		if !need {
			return
		}
		last := loadNVDLastSync()
		if last == nil || last.FinishedAt.IsZero() {
			return
		}
		rulesSyncMu.Lock()
		rulesSyncState.FinishedAt = last.FinishedAt
		rulesSyncState.Products = last.Products
		rulesSyncState.KeptCVEs = last.KeptCVEs
		rulesSyncState.TotalCVEs = last.TotalCVEs
		rulesSyncState.Files = last.Files
		rulesSyncState.Source = last.Source
		rulesSyncState.Error = last.Error
		rulesSyncState.Mode = last.Mode
		rulesSyncMu.Unlock()
		logLine(fmt.Sprintf("已恢复上次 NVD 同步结果: %s (产品 %d / CVE %d)",
			last.FinishedAt.Format("2006-01-02 15:04"), last.Products, last.KeptCVEs))
	})
}

// decideSyncMode 决定本次同步模式, 返回 (since, mode)。
// 独立成纯函数便于单测: 增量决策只依赖"用户显式参数 + 上次完成记录"两个输入。
func decideSyncMode(explicitSince string, full bool) (string, string) {
	if explicitSince != "" {
		return explicitSince, "incremental"
	}
	if full {
		return "", "full"
	}
	last := loadNVDLastSync()
	if last == nil {
		return "", "full"
	}
	// 上次失败的原因是"环境拦截带日期参数的请求"(fetchNVDPage 对空正文 404 的
	// 专用文案) → 不再尝试增量。否则每次点同步都要先白试一次注定失败的增量,
	// 表现为"第一次点报错、第二次点才开始干活"。
	if last.Error != "" && strings.Contains(last.Error, "HTTP 404") &&
		strings.Contains(last.Error, "响应体为空") {
		logLine("上次同步失败源于环境拦截带日期参数的查询, 本次直接走全量分批(不再尝试增量)")
		return "", "full"
	}
	// 只有"成功完成"的记录才能当增量基线: 失败的那次拉到的数据是 0 条,
	// 它的 finishedAt 只是"失败时刻"——若拿它当起点, 默认增量会永远失败。
	if !last.FinishedAt.IsZero() && last.Error == "" {
		return last.FinishedAt.UTC().Format("2006-01-02"), "incremental"
	}
	return "", "full"
}

// ===== 核心同步逻辑 =====

// nvdPageSize 单页条数(2.1 上限 2000, 取满减少总页数)。
const nvdPageSize = 2000

// nvdBaseURL NVD API 2.1 列表端点(旧 2.0 的 services.nist.gov/api/cve 已退役,
// 必回 403)。用变量而非常量: 测试把它指到本地假服务做端到端验证(离线)。
var nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// syncNVD 单区间同步: 从 NVD 2.1 API 分页拉取 CVE, 过滤到可指纹产品, 写入
// vuln/cpe/ 目录。在后台 goroutine 中执行, 进度通过 rulesSyncState 更新。
// apiKey 非空时随请求带上(限速档 50 次/30 秒), 为空走匿名档(5 次/30 秒)。
//
// since 为空 = 全量(不带日期参数); 非空 = 只拉该日期之后修改过的 CVE。
// 全量的"分批续传"走 syncNVDBatched(见文件头), 两者共用 syncNVDRange。
func syncNVD(minCVSS float64, since, apiKey string) {
	client := &http.Client{
		Timeout:   120 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}
	// 滑动窗口节流: 每次发请求前先占一个窗口名额, 满了就等到最早一次出窗。
	// 不靠它只靠 429 退避的话, 会连续撞墙浪费 30 秒档(全量 200 页下差距巨大)。
	rate := newNVDRate(apiKey != "")

	// 2026-09-24 dist 目录整理: 规则库统一收进 vuln/(旧 "exe 同目录 cpe/" 由
	// main.go 的 migrateLegacyDirs 启动时一次性迁移)
	outDir := filepath.Join(exeDir(), "vuln", "cpe")

	var prods map[string]*nvdProductSync
	prods = map[string]*nvdProductSync{}
	// 增量模式(since 非空): 先读回已有 nvd-*.json, 新结果合并进旧数据。
	// NVD 的 lastModStartDate 只返回"修改过"的 CVE, 直接覆盖会丢掉全部未变化的;
	// 输出目录里没有任何已有文件(首次同步被手工清理过)则回退全量。
	if since != "" {
		if existing := loadExistingNVDSync(outDir); existing != nil {
			prods = existing
		} else {
			logLine("NVD 增量同步未找到已有文件(可能已被清理), 回退全量同步")
		}
	}

	q := url.Values{}
	q.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
	if since != "" {
		q.Set("lastModStartDate", since+"T00:00:00.000+00:00")
	}
	if apiKey != "" {
		q.Set("apiKey", apiKey)
	}
	scope := "全量"
	if since != "" {
		scope = "增量自 " + since
	}
	// kept(命中数)不单独用: 落盘后以库内实际条数 totalCves 为准, 增量合并下
	// 两者本就不相等(旧 CVE 也在库里, 但不是本次命中)。
	total, _, _, err := syncNVDPageSpan(client, rate, prods, minCVSS, q, scope, 1, 0, 0, 0)
	if err != nil {
		return // 状态与日志已在 syncNVDPageSpan 内填充
	}

	files, totalCves, werr := writeNVDProductFiles(prods, outDir)
	if werr != nil {
		rulesSyncMu.Lock()
		rulesSyncState.Error = werr.Error()
		rulesSyncMu.Unlock()
		return
	}
	rulesSyncMu.Lock()
	rulesSyncState.Products = len(files)
	rulesSyncState.KeptCVEs = totalCves
	rulesSyncState.Files = files
	rulesSyncMu.Unlock()

	mode := "全量"
	if since != "" {
		mode = fmt.Sprintf("增量(自 %s)", since)
	}
	logLine(fmt.Sprintf("NVD 同步完成(%s): %d 个产品文件, 库内共 %d 条 CVE(本次拉取 %d) → %s",
		mode, len(files), totalCves, total, outDir))
}

// syncNVDPageSpan 拉取 [fromPage, toPage] 区间的页, 命中结果合并进 prods。
//
// q 由调用方构造(决定是否带日期过滤 —— 本环境带日期参数会被拦, 分批传的是不带
// 日期的 q); toPage<=0 表示一直拉到最后一页(按响应的 totalResults 自算)。
// baseTotal/baseKept 是已完成批次的累计数, 只用于进度展示。
//
// 返回 (本段拉取条数, 本段命中条数, 是否已到全库最后一页, 错误)。
func syncNVDPageSpan(client *http.Client, rate *nvdRate, prods map[string]*nvdProductSync,
	minCVSS float64, q url.Values, scope string, fromPage, toPage int, baseTotal, baseKept int) (int, int, bool, error) {
	total := 0
	kept := 0

	page := fromPage
	if page < 1 {
		page = 1
	}

	for {
		// 2.1 分页是 0 基偏移(旧 2.0 是 1 基页码)
		q.Set("startIndex", strconv.Itoa((page-1)*nvdPageSize))
		body, err := fetchNVDPage(client, nvdBaseURL+"?"+q.Encode())
		if err != nil {
			// NVD 对"日期区间内无任何结果"回 404(不是 200 空列表), 且正文带
			// "Result set from start date to end date is empty"。这恰恰是正常
			// 结局——这段时间内 NVD 没改过任何 CVE——不能当失败, 否则"安静的
			// 一天"之后点同步必报错, 完成记录也存不进去。
			// 【只认带说明正文的 404】: 空正文的 404 是网络拦截(2026-09-25 实测
			// 本环境对一切带日期参数的请求都回空正文 404, 见文件头), 当成功会把
			// 基线推到"今天", 白丢这段时间的更新。
			if strings.Contains(err.Error(), "HTTP 404") &&
				strings.Contains(err.Error(), "Result set") {
				logLine(fmt.Sprintf("NVD 同步(%s): 该区间无修改的 CVE, 跳过(0 条)", scope))
				return total, kept, true, nil
			}
			rulesSyncMu.Lock()
			rulesSyncState.Error = fmt.Sprintf("拉取第 %d 页失败: %v", page, err)
			rulesSyncState.Running = false
			rulesSyncMu.Unlock()
			slog.Error("NVD 同步失败", "page", page, "scope", scope, "error", err)
			return total, kept, false, err
		}

		var pg nvdPageSync
		if err := json.Unmarshal(body, &pg); err != nil {
			rulesSyncMu.Lock()
			rulesSyncState.Error = fmt.Sprintf("解析第 %d 页失败: %v", page, err)
			rulesSyncMu.Unlock()
			return total, kept, false, err
		}

		total += len(pg.Vulnerabilities)
		for _, it := range pg.Vulnerabilities {
			if processNVDItemSync(it, prods, minCVSS) {
				kept++
			}
		}

		// 2.1 没有 totalPages 字段, 用 totalResults 自算(向上取整)。
		totalPages := (pg.TotalResults + nvdPageSize - 1) / nvdPageSize

		rulesSyncMu.Lock()
		rulesSyncState.CurrentPage = page
		rulesSyncState.TotalPages = totalPages
		rulesSyncState.TotalCVEs = baseTotal + total
		rulesSyncState.KeptCVEs = baseKept + kept
		rulesSyncMu.Unlock()

		logLine(fmt.Sprintf("NVD 同步(%s): 第 %d/%d 页 (累计 %d 条 CVE, 命中 %d)",
			scope, page, totalPages, baseTotal+total, baseKept+kept))

		// 结束条件有两个: 到全库末页(受 NVD 总量变化影响, 只能在拿到响应后判)
		// 或到本批末页(分批续传的分界)。取或。
		if page >= totalPages || (toPage > 0 && page >= toPage) {
			return total, kept, page >= totalPages, nil
		}
		page++
		// 占下一个限速名额(窗口未满时立即通过, 满了阻塞到出窗)
		rate.wait()
	}
}

// writeNVDProductFiles 把内存里的产品/CVE 集合写到 vuln/cpe/nvd-<产品>.json。
//
// 单区间同步与分批同步共用: 分批每跑完一批就调一次, 才能做到"已完成的批稳稳
// 落盘, 中断只丢当前批"。返回 (写出的文件清单, 库内总 CVE 数, 错误)。
func writeNVDProductFiles(prods map[string]*nvdProductSync, outDir string) ([]string, int, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, 0, fmt.Errorf("创建输出目录 %s 失败: %v", outDir, err)
	}

	names := make([]string, 0, len(prods))
	for k := range prods {
		names = append(names, k)
	}
	sort.Strings(names)

	totalCves := 0
	var files []string
	for _, k := range names {
		p := prods[k]
		if len(p.CVEs) == 0 {
			continue
		}
		totalCves += len(p.CVEs)
		vendor := ""
		if idx := strings.Index(k, ":"); idx > 0 {
			vendor = k[:idx]
		}
		doc := map[string]any{
			"version":  "nvd-sync " + time.Now().Format("2006-01-02"),
			"products": []map[string]any{{
				"cpe":     "cpe:2.3:a:" + k,
				"vendor":  vendor,
				"product": p.Key,
				"cves":    p.CVEs,
			}},
		}
		fn := filepath.Join(outDir, "nvd-"+p.Key+".json")
		data, _ := json.MarshalIndent(doc, "", "  ")
		if err := os.WriteFile(fn, data, 0o644); err != nil {
			slog.Error("写 CPE 文件失败", "file", fn, "error", err)
			continue
		}
		files = append(files, filepath.Base(fn))
	}
	return files, totalCves, nil
}

// ===== 全量分批续传 =====
//
// 见文件头"为什么按页分批而不是按日期分批"。一句话: 全量切成一个个 **页块**
// (每批 nvdBatchPages 页), 每批落盘 + 记进度, 中断后从下一批继续。

// nvdBatchPages 单批页数。10 页 × 2000 条 = 2 万条/批, 全库约 199 页 → 约 20 批。
// 取值权衡: 太小则每批都要重写全部产品文件(写盘是整文件覆盖, 有成本) ; 太大则
// 中断时要重跑的多。10 页这一档: 中断最多丢 2 万条的进度, 写盘约 20 次。
const nvdBatchPages = 10

// nvdResume 未完成的全量分批计划(持久化到 settings.json 的 nvd.resume)。
// Next 是"下一个待跑批次"的下标(0 基), NextPage 是该批的首页页码(1 基)。
//
// Kind 是格式标识: 2026-09-25 之前按日期分窗(Kind 为空)的版本留下的 resume
// 必须被丢弃 —— 日期分批已被实测证伪(见文件头), 继续沿用它只会又空跑一遍。
type nvdResume struct {
	Kind       string    `json:"kind"` // 恒为 "page"
	Mode       string    `json:"mode"`
	MinCVSS    float64   `json:"minCvss"`
	TotalPages int       `json:"totalPages"` // 全库页数(拿到首个响应后才准确)
	BatchPages int       `json:"batchPages"`
	Total      int       `json:"total"` // 批数(TotalPages 已知时为准确值)
	Next       int       `json:"next"`
	NextPage   int       `json:"nextPage"`
	StartedAt  time.Time `json:"startedAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	TotalCVEs  int       `json:"totalCves"`
	KeptCVEs   int       `json:"keptCves"`
}

// batchPageRange 第 i 批(0 基)的页区间(1 基页码, 闭区间)。
func batchPageRange(i, batchPages int) (from, to int) {
	if batchPages <= 0 {
		batchPages = nvdBatchPages
	}
	return i*batchPages + 1, (i + 1) * batchPages
}

// newNVDResume 新建一份分批计划。首份计划在拿到首个响应前不知道总页数,
// Total 先按"一批"估算, 第一批跑完拿到 totalResults 后回填(见 syncNVDBatched)。
func newNVDResume(minCVSS float64) *nvdResume {
	return &nvdResume{
		Kind:       "page",
		Mode:       "full-batch",
		MinCVSS:    minCVSS,
		BatchPages: nvdBatchPages,
		Total:      1,
		Next:       0,
		NextPage:   1,
		StartedAt:  time.Now(),
	}
}

// loadNVDResume 读回未完成的分批计划; 没有 / 已跑完(Next>=Total) / 格式不符 → nil。
func loadNVDResume() *nvdResume {
	raw, ok := section(secNVD, "")
	if !ok {
		return nil
	}
	var kv struct {
		Resume *nvdResume `json:"resume"`
	}
	if json.Unmarshal(raw, &kv) != nil || kv.Resume == nil {
		return nil
	}
	r := kv.Resume
	// 旧格式(按日期分窗)一律丢弃, 不能续
	if r.Kind != "page" {
		return nil
	}
	if r.Total <= 0 || r.Next < 0 || r.Next >= r.Total {
		return nil
	}
	if r.BatchPages <= 0 {
		r.BatchPages = nvdBatchPages
	}
	if r.NextPage <= 0 {
		r.NextPage = batchFrom(r.Next, r.BatchPages)
	}
	return r
}

// batchFrom 第 i 批首页页码(loadNVDResume 兜底用, 避免写成两个地方)。
func batchFrom(i, batchPages int) int {
	from, _ := batchPageRange(i, batchPages)
	return from
}

// saveNVDResume 持久化分批进度。失败只记日志: 最坏结果是下次从本批重跑,
// 不会丢已有数据(每批的产出文件已落盘)。
func saveNVDResume(r *nvdResume) {
	r.UpdatedAt = time.Now()
	kv := nvdSectionKV()
	kv["resume"] = r
	if err := writeNVDSectionKV(kv); err != nil {
		logLine("NVD 续传进度保存失败(下次将从本批重跑): " + err.Error())
	}
}

func clearNVDResume() {
	kv := nvdSectionKV()
	if _, ok := kv["resume"]; !ok {
		return
	}
	delete(kv, "resume")
	if err := writeNVDSectionKV(kv); err != nil {
		logLine("NVD 续传进度清理失败: " + err.Error())
	}
}

// nvdSectionKV 读回 nvd 节的全部键值(合并写的前提: 同节还存着 apiKey/lastSync)。
func nvdSectionKV() map[string]any {
	kv := map[string]any{}
	if raw, ok := section(secNVD, ""); ok {
		_ = json.Unmarshal(raw, &kv)
	}
	return kv
}

// writeNVDSectionKV 合并写 nvd 节。
// 必须"读-合并-写": writeSection 是整节覆盖, 直接传一个只含 resume 的 map
// 会把同节的 apiKey / lastSync 抹掉(2026-09-25 修 nvdAPIKey 的同类问题)。
func writeNVDSectionKV(kv map[string]any) error {
	if err := writeSection(secNVD, kv); err != nil {
		return err
	}
	resetSettingsCache()
	return nil
}

// syncNVDBatched 分批全量同步: 逐批拉取 → 每批落盘 → 每批记进度。
// 中断(停服务/进程被杀/网络失败)后重开, handleRulesSyncStart 会带同一份
// resume 进来, 从 Next 批继续; 全部跑完清 resume, 之后走增量。
func syncNVDBatched(minCVSS float64, apiKey string, r *nvdResume) {
	client := &http.Client{
		Timeout:   120 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}
	rate := newNVDRate(apiKey != "")
	outDir := filepath.Join(exeDir(), "vuln", "cpe")

	// 先读回已有文件: 前面批次已经落盘的结果必须保留, 否则本批写盘会把
	// 前几批的成果冲掉(写盘是整文件覆盖)。首次同步目录为空 → 从空集开始。
	prods := map[string]*nvdProductSync{}
	if existing := loadExistingNVDSync(outDir); existing != nil {
		prods = existing
	}

	// 分批请求的查询串: 刻意**不带任何日期参数** —— 本环境对带日期参数的 NVD 请求
	// 一律 404(实测见文件头), 带上去就是每批拉 0 条。
	q := url.Values{}
	q.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
	if apiKey != "" {
		q.Set("apiKey", apiKey)
	}

	batches := 0
	for i := r.Next; ; i++ {
		from, to := batchPageRange(i, r.BatchPages)
		rulesSyncMu.Lock()
		rulesSyncState.BatchIndex = i
		rulesSyncState.BatchTotal = r.Total
		rulesSyncState.BatchFromPage = from
		rulesSyncState.BatchToPage = to
		rulesSyncMu.Unlock()

		total, _, reachedEnd, err := syncNVDPageSpan(client, rate, prods, minCVSS, q,
			fmt.Sprintf("第 %d-%d 页", from, to), from, to, r.TotalCVEs, r.KeptCVEs)
		if err != nil {
			// 本批失败: 保 Next=i(下次从本批重跑), 前面的批已落盘不丢。
			// 页面能把 etcd…(此处是 NVD)的临时故障表现为"失败", 但已同步的部分保留。
			r.Next = i
			r.NextPage = from
			saveNVDResume(r)
			return
		}

		files, totalCves, werr := writeNVDProductFiles(prods, outDir)
		if werr != nil {
			rulesSyncMu.Lock()
			rulesSyncState.Error = werr.Error()
			rulesSyncMu.Unlock()
			r.Next = i
			r.NextPage = from
			saveNVDResume(r)
			return
		}

		rulesSyncMu.Lock()
		rulesSyncState.Products = len(files)
		rulesSyncState.KeptCVEs = totalCves
		rulesSyncState.Files = files
		// 拿到首个响应后才知道全库页数, 回填批数(只影响展示的分母与实际循环出口)
		if total > 0 || reachedEnd {
			if tp := rulesSyncState.TotalPages; tp > 0 && r.TotalPages != tp {
				r.TotalPages = tp
				r.Total = (tp + r.BatchPages - 1) / r.BatchPages
				rulesSyncState.BatchTotal = r.Total
			}
		}
		rulesSyncMu.Unlock()

		batches++
		r.Next = i + 1
		r.NextPage = to + 1
		r.TotalCVEs += total
		r.KeptCVEs = totalCves
		saveNVDResume(r)
		logLine(fmt.Sprintf("NVD 分批同步: 第 %d/%d 批完成(第 %d-%d 页), 已落盘 %d 个产品文件 / 库内 %d 条 CVE",
			i+1, r.Total, from, to, len(files), totalCves))

		if reachedEnd {
			break
		}
	}

	// 全部批次完成: 清续传标记(收尾的 persistNVDLastSync 由调用方 defer)
	clearNVDResume()
	rulesSyncMu.Lock()
	rulesSyncState.BatchIndex = r.Total
	rulesSyncState.BatchFromPage = 0
	rulesSyncState.BatchToPage = 0
	rulesSyncMu.Unlock()
	logLine(fmt.Sprintf("NVD 分批同步全部完成: 共 %d 批 / %d 页, %d 个产品文件 / 库内 %d 条 CVE → %s",
		batches, r.TotalPages, rulesSyncState.Products, rulesSyncState.KeptCVEs, outDir))
}

// ===== NVD 2.1 数据结构 =====
//
// 与 2.0 的形态差异: 2.0 是 items[](CVE 编号在项级 cveId), 2.1 是
// vulnerabilities[](每项再包一层 cve, 编号在 cve.id)。逐层拆开而不是
// 压平, 是为了让 JSON 标签与官方响应一一可对, 排查字段错位时不用猜。

// nvdPageSync 2.1 列表端点顶层响应(平铺, 注意没有 totalPages —— 用
// totalResults 自算页数, 见 syncNVD)。
type nvdPageSync struct {
	ResultsPerPage  int           `json:"resultsPerPage"`
	StartIndex      int           `json:"startIndex"`
	TotalResults    int           `json:"totalResults"`
	Vulnerabilities []nvdVulnSync `json:"vulnerabilities"`
}

// nvdVulnSync 2.1 的每个条目: 真正的 CVE 对象在 cve 字段里。
type nvdVulnSync struct {
	CVE nvdCveSync `json:"cve"`
}

// nvdCveSync 2.1 的 CVE 内层对象(descriptions/metrics/configurations 的
// 内部结构与 2.0 一致, 复用同一套解析路径)。
type nvdCveSync struct {
	ID           string `json:"id"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []struct {
			CvssData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CvssMetricV30 []struct {
			CvssData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
		} `json:"cvssMetricV30"`
		CvssMetricV2 []struct {
			CvssData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CpeMatch []struct {
				Criteria              string `json:"criteria"`
				Vulnerable            bool   `json:"vulnerable"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdProductSync struct {
	Key  string
	CVEs []map[string]any
}

// processNVDItemSync 处理单条 CVE, 返回是否命中可指纹产品。
func processNVDItemSync(it nvdVulnSync, prods map[string]*nvdProductSync, minCVSS float64) bool {
	cvss := 0.0
	if m := it.CVE.Metrics.CvssMetricV31; len(m) > 0 {
		cvss = m[0].CvssData.BaseScore
	} else if m := it.CVE.Metrics.CvssMetricV30; len(m) > 0 {
		cvss = m[0].CvssData.BaseScore
	} else if m := it.CVE.Metrics.CvssMetricV2; len(m) > 0 {
		cvss = m[0].CvssData.BaseScore
	}
	if cvss < minCVSS {
		return false
	}

	title := ""
	for _, d := range it.CVE.Descriptions {
		if d.Lang == "en" {
			title = strings.TrimSpace(d.Value)
			break
		}
	}
	if title == "" && len(it.CVE.Descriptions) > 0 {
		title = strings.TrimSpace(it.CVE.Descriptions[0].Value)
	}

	type acc struct {
		groups   []string
		allVer   bool
	}
	byProd := map[string]*acc{}
	for _, cfg := range it.CVE.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CpeMatch {
				if !m.Vulnerable {
					continue
				}
				vp, ok := vendorProductSync(m.Criteria)
				if !ok {
					continue
				}
				key, ok := rulesSyncKeyMap[vp]
				if !ok {
					continue
				}
				group, expressible := constraintsFromMatchSync(
					m.VersionStartIncluding, m.VersionStartExcluding,
					m.VersionEndIncluding, m.VersionEndExcluding,
				)
				if !expressible {
					continue
				}
				a := byProd[key]
				if a == nil {
					a = &acc{}
					byProd[key] = a
				}
				if group == "" {
					a.allVer = true
					continue
				}
				a.groups = appendUniqueSync(a.groups, group)
			}
		}
	}
	if len(byProd) == 0 {
		return false
	}

	for key, a := range byProd {
		p := prods[key]
		if p == nil {
			p = &nvdProductSync{Key: key}
			prods[key] = p
		}
		entry := map[string]any{
			"cve":   it.CVE.ID,
			"title": title,
			"cvss":  cvss,
		}
		if !a.allVer {
			entry["constraints"] = a.groups
		}
		upsertNVDVuln(p, entry)
	}
	return true
}

// upsertNVDVuln 按 CVE 号 upsert 条目: 同号已有则替换(NVD 对同一 CVE 会更新版本
// 约束/评分, 必须用新数据), 否则追加。全量模式 prods 为空, 等价于原 append 行为;
// 增量模式靠它保证"新覆盖旧、未变化的保留"。
func upsertNVDVuln(p *nvdProductSync, entry map[string]any) {
	for i, e := range p.CVEs {
		if e["cve"] == entry["cve"] {
			p.CVEs[i] = entry
			return
		}
	}
	p.CVEs = append(p.CVEs, entry)
}

// loadExistingNVDSync 读回输出目录里已有的 nvd-*.json(增量合并用)。
// 目录不存在或没有任何有效 nvd 文件时返回 nil(调用方据此回退全量)。
func loadExistingNVDSync(outDir string) map[string]*nvdProductSync {
	files, err := os.ReadDir(outDir)
	if err != nil {
		return nil
	}
	prods := map[string]*nvdProductSync{}
	for _, f := range files {
		name := f.Name()
		if f.IsDir() || !strings.HasPrefix(name, "nvd-") || !strings.HasSuffix(name, ".json") {
			continue // 只认本模块产出的 nvd-<产品>.json, 不碰用户自放的其它规则
		}
		data, rerr := os.ReadFile(filepath.Join(outDir, name))
		if rerr != nil {
			continue
		}
		var doc struct {
			Products []struct {
				Product string           `json:"product"`
				CVEs    []map[string]any `json:"cves"`
			} `json:"products"`
		}
		if json.Unmarshal(data, &doc) != nil {
			continue // 坏文件跳过(与 CPE 引擎"只记告警不中断"的口径一致)
		}
		for _, p := range doc.Products {
			if strings.TrimSpace(p.Product) == "" {
				continue
			}
			prods[p.Product] = &nvdProductSync{Key: p.Product, CVEs: p.CVEs}
		}
	}
	if len(prods) == 0 {
		return nil
	}
	return prods
}

func vendorProductSync(criteria string) (string, bool) {
	if !strings.HasPrefix(criteria, "cpe:2.3:a:") {
		return "", false
	}
	rest := criteria[len("cpe:2.3:a:"):]
	parts := strings.Split(rest, ":")
	if len(parts) < 2 {
		return "", false
	}
	v, p := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if v == "" || p == "" || v == "*" || p == "*" {
		return "", false
	}
	return strings.ToLower(v) + ":" + strings.ToLower(p), true
}

func constraintsFromMatchSync(startInc, startExc, endInc, endExc string) (string, bool) {
	var clauses []string
	add := func(op, v string) {
		if v == "" {
			return
		}
		if !isNumericVerSync(v) {
			clauses = append(clauses, "\x00BAD")
			return
		}
		clauses = append(clauses, op+" "+v)
	}
	add(">=", startInc)
	add(">", startExc)
	add("<=", endInc)
	add("<", endExc)
	for _, c := range clauses {
		if c == "\x00BAD" {
			return "", false
		}
	}
	if len(clauses) == 0 {
		return "", true
	}
	return strings.Join(clauses, ", "), true
}

func isNumericVerSync(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	hasDigit := false
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '.':
		default:
			return false
		}
	}
	return hasDigit
}

func appendUniqueSync(list []string, items ...string) []string {
	for _, it := range items {
		exist := false
		for _, x := range list {
			if x == it {
				exist = true
				break
			}
		}
		if !exist {
			list = append(list, it)
		}
	}
	return list
}

// nvdRate NVD 2.1 的滑动窗口节流器。
//
// 官方限流是"每 30 秒窗口 N 次"(匿名 5 / 带 Key 50), 不是"每秒 N 次" ——
// 旧实现按 250ms 间隔发请求, 在前 30 秒内就会发出上百次, 除 403 外还会
// 持续 429。这里发请求前先占名额, 窗口占满时阻塞到最早一次请求滑出窗口,
// 让整条同步链路的发送节奏天然贴合限制。
type nvdRate struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	stamps []time.Time
}

func newNVDRate(withKey bool) *nvdRate {
	limit := 5
	if withKey {
		limit = 50
	}
	return &nvdRate{limit: limit, window: 30 * time.Second}
}

// wait 阻塞直到可以发起一次请求(并占用该次的名额)。
// 每次醒来都重新评估: 窗口内还剩几次没用, 没有就睡到最早一次出窗。
func (t *nvdRate) wait() {
	for {
		t.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-t.window)
		i := 0
		for i < len(t.stamps) && t.stamps[i].Before(cutoff) {
			i++
		}
		t.stamps = t.stamps[i:]
		if len(t.stamps) < t.limit {
			t.stamps = append(t.stamps, now)
			t.mu.Unlock()
			return
		}
		wake := t.stamps[0].Add(t.window).Sub(now)
		t.mu.Unlock()
		// +150ms 余量: 窗口边界上的整秒并发容易再次撞 429
		time.Sleep(wake + 150*time.Millisecond)
	}
}

// fetchNVDPage 拉取单页(含重试)。策略:
//   - 200 成功; 429 按 Retry-After 退避重试(节流器之外的第二道保险);
//   - 403/404 是端点级错误(如旧 2.0 地址已退役), 重试无意义, 立即失败;
//   - 网络错 / 5xx 短退避重试。
func fetchNVDPage(client *http.Client, url string) ([]byte, error) {
	var lastErr error
	const maxAttempts = 8
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Yugsight-NVD-Sync/1.0 (internal vulnerability rule sync)")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			time.Sleep(2 * time.Second)
			continue
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return body, nil
		case http.StatusTooManyRequests:
			// 429: 限流。Retry-After 给的是"距离下个窗口余量"的秒数,
			// 没给就按整个 30 秒档等(等短了就是白撞)。
			d := 30 * time.Second
			if ra := strings.TrimSpace(resp.Header.Get("Retry-After")); ra != "" {
				if secs, perr := strconv.Atoi(ra); perr == nil && secs > 0 {
					d = time.Duration(secs) * time.Second
				}
			}
			if d > 60*time.Second {
				d = 60 * time.Second
			}
			lastErr = fmt.Errorf("HTTP 429 触发 NVD 限流, %s 后重试", d)
			time.Sleep(d + 150*time.Millisecond)
			continue
		case http.StatusForbidden, http.StatusNotFound:
			// 带响应体片段: NVD 的 404 正文通常是 "Result set from start date to
			// end date is empty"(区间无结果的正常语义), 拿到正文才能区分"查询为空"
			// 和"被中间代理拦了", 不然光一个 404 没法排查。
			snippet := strings.TrimSpace(string(body))
			switch {
			case snippet != "":
				if len(snippet) > 300 {
					snippet = snippet[:300]
				}
				return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet)
			case resp.StatusCode == http.StatusNotFound:
				// 2026-09-24 实测: 本机(沙箱)网络对带日期参数的 NVD 查询回
				// 空响应体 404(真 NVD 的空结果 404 必带说明正文)。空正文 =
				// 大概率被中间代理/拦截器拦了, 直接说破, 免得用户对着
				// 干巴巴的 "HTTP 404" 猜半天。
				return nil, fmt.Errorf("HTTP 404(响应体为空 —— 真 NVD 的 404 应带说明正文, 大概率是网络环境拦截了带日期参数的查询; 可改用全量同步, 全量不带日期参数)")
			default:
				return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		default:
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			time.Sleep(2 * time.Second)
			continue
		}
	}
	return nil, lastErr
}

// ===== NVD API Key 存取 =====

// nvdAPIKey 取本次同步用的 API Key: 显式传入优先, 否则回退 settings.json 的 nvd 节。
// 显式传了非空值时顺手持久化(用户只该填一次, 下次留空即用已存的)。
func nvdAPIKey(given string) string {
	if given != "" {
		// 合并写: 2026-09-25 之前这里直接 writeSection(整节覆盖), 会把同节的
		// lastSync(上次同步完成记录)与 resume(续传进度)一起抹掉 —— 表现为
		// "填完 Key 后下次同步变成全量重跑 / 续传进度消失"。
		kv := nvdSectionKV()
		kv["apiKey"] = given
		if err := writeNVDSectionKV(kv); err != nil {
			logLine("NVD API Key 保存失败(仅本次生效): " + err.Error())
		}
		return given
	}
	if raw, ok := section(secNVD, ""); ok {
		var kv struct {
			APIKey string `json:"apiKey"`
		}
		if json.Unmarshal(raw, &kv) == nil {
			return strings.TrimSpace(kv.APIKey)
		}
	}
	return ""
}
