// rules_sync.go 漏洞规则一键同步: 从 NVD API 拉取 CVE 数据, 过滤到可指纹产品,
// 输出到 exe 同目录 cpe/ 热更新目录(与 scripts/nvd_sync.go 逻辑一致, 但以内置 API 形式
// 供前端"一键同步"按钮调用, 无需用户手动跑脚本)。
//
// 设计:
//   - 默认关闭(规则 5): 仅在用户显式点击"一键同步"时才发起网络请求, 不自动执行
//   - 后台 goroutine 执行, 不阻塞 HTTP handler
//   - 进度通过 atomic 变量 + progress 端点轮询
//   - 网络不可达(NVD 403/超时)时明确报错, 不静默失败
//   - 输出格式与 cpe_builtin.json 一致(cpeFile), 放入 cpe/ 后程序热加载即生效

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
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.MinCVSS < 0 {
		req.MinCVSS = 0
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
	rulesSyncMu.Unlock()

	rulesSyncRunning.Store(true)
	go func() {
		defer rulesSyncRunning.Store(false)
		defer func() {
			rulesSyncMu.Lock()
			rulesSyncState.Running = false
			rulesSyncState.FinishedAt = time.Now()
			rulesSyncMu.Unlock()
		}()
		syncNVD(req.MinCVSS, req.Since)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"started": true,
		"message": "NVD 同步已启动, 请轮询 /api/vuln/rules/sync/progress 查看进度",
	})
}

func handleRulesSyncProgress(w http.ResponseWriter, _ *http.Request) {
	rulesSyncMu.Lock()
	state := rulesSyncState
	rulesSyncMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(state)
}

// ===== 核心同步逻辑 =====

// syncNVD 从 NVD 2.0 API 分页拉取 CVE, 过滤到可指纹产品, 写入 cpe/ 目录。
// 在后台 goroutine 中执行, 进度通过 rulesSyncState 更新。
func syncNVD(minCVSS float64, since string) {
	client := &http.Client{
		Timeout:   120 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}

	outDir := filepath.Join(exeDir(), "cpe")

	var prods map[string]*nvdProductSync
	prods = map[string]*nvdProductSync{}
	total := 0
	kept := 0

	page := 1
	q := url.Values{}
	q.Set("pageSize", "2000")
	if since != "" {
		q.Set("lastModStartDate", since+"T00:00:00.000+00:00")
	}

	for {
		q.Set("page", strconv.Itoa(page))
		fullURL := "https://services.nist.gov/api/cve/cves?" + q.Encode()
		body, err := fetchNVDPage(client, fullURL)
		if err != nil {
			rulesSyncMu.Lock()
			rulesSyncState.Error = fmt.Sprintf("拉取第 %d 页失败: %v", page, err)
			rulesSyncState.Running = false
			rulesSyncMu.Unlock()
			slog.Error("NVD 同步失败", "page", page, "error", err)
			return
		}

		var pg struct {
			TotalResults int           `json:"totalResults"`
			TotalPages   int           `json:"totalPages"`
			Items        []cveItemSync `json:"items"`
		}
		if err := json.Unmarshal(body, &pg); err != nil {
			rulesSyncMu.Lock()
			rulesSyncState.Error = fmt.Sprintf("解析第 %d 页失败: %v", page, err)
			rulesSyncMu.Unlock()
			return
		}

		total += len(pg.Items)
		for _, it := range pg.Items {
			if processNVDItemSync(it, prods, minCVSS) {
				kept++
			}
		}

		rulesSyncMu.Lock()
		rulesSyncState.CurrentPage = page
		rulesSyncState.TotalPages = pg.TotalPages
		rulesSyncState.TotalCVEs = total
		rulesSyncState.KeptCVEs = kept
		rulesSyncMu.Unlock()

		logLine(fmt.Sprintf("NVD 同步: 第 %d/%d 页 (累计 %d 条 CVE, 命中 %d)", page, pg.TotalPages, total, kept))

		if page >= pg.TotalPages {
			break
		}
		page++
		// 限速: 无 API Key 为 5 req/s
		time.Sleep(250 * time.Millisecond)
	}

	// 输出到 cpe/ 目录
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		rulesSyncMu.Lock()
		rulesSyncState.Error = fmt.Sprintf("创建输出目录 %s 失败: %v", outDir, err)
		rulesSyncMu.Unlock()
		return
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

	rulesSyncMu.Lock()
	rulesSyncState.Products = len(files)
	rulesSyncState.KeptCVEs = totalCves
	rulesSyncState.Files = files
	rulesSyncMu.Unlock()

	logLine(fmt.Sprintf("NVD 同步完成: %d 个产品文件, %d 条 CVE → %s", len(files), totalCves, outDir))
}

// ===== NVD 数据结构(与 scripts/nvd_sync.go 一致) =====

type cveItemSync struct {
	CveID string `json:"cveId"`
	Cve   struct {
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
	} `json:"cve"`
}

type nvdProductSync struct {
	Key  string
	CVEs []map[string]any
}

// processNVDItemSync 处理单条 CVE, 返回是否命中可指纹产品。
func processNVDItemSync(it cveItemSync, prods map[string]*nvdProductSync, minCVSS float64) bool {
	cvss := 0.0
	if m := it.Cve.Metrics.CvssMetricV31; len(m) > 0 {
		cvss = m[0].CvssData.BaseScore
	} else if m := it.Cve.Metrics.CvssMetricV30; len(m) > 0 {
		cvss = m[0].CvssData.BaseScore
	} else if m := it.Cve.Metrics.CvssMetricV2; len(m) > 0 {
		cvss = m[0].CvssData.BaseScore
	}
	if cvss < minCVSS {
		return false
	}

	title := ""
	for _, d := range it.Cve.Descriptions {
		if d.Lang == "en" {
			title = strings.TrimSpace(d.Value)
			break
		}
	}
	if title == "" && len(it.Cve.Descriptions) > 0 {
		title = strings.TrimSpace(it.Cve.Descriptions[0].Value)
	}

	type acc struct {
		groups   []string
		allVer   bool
	}
	byProd := map[string]*acc{}
	for _, cfg := range it.Cve.Configurations {
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
			"cve":   it.CveID,
			"title": title,
			"cvss":  cvss,
		}
		if !a.allVer {
			entry["constraints"] = a.groups
		}
		p.CVEs = append(p.CVEs, entry)
	}
	return true
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

func fetchNVDPage(client *http.Client, url string) ([]byte, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
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
		if resp.StatusCode == http.StatusOK {
			return body, nil
		}
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		time.Sleep(3 * time.Second)
	}
	return nil, lastErr
}
