//go:build ignore

// nvd_sync.go NVD 全量 CVE 同步工具: 把 NVD 数据库过滤成 Yugsight CPE 引擎可消费
// 的产品字典(版本 -> CVE), 输出到 exe 同目录 cpe/ 热更新目录。
//
// 用法(任意目录, 输出位置用 --out 指定, 默认 dist/cpe/):
//
//	go run scripts/nvd_sync.go --out e:/project/Yugsight/dist/cpe
//	go run scripts/nvd_sync.go --out ./cpe --min-cvss 4.0 --since 2015-01-01
//	go run scripts/nvd_sync.go --limit 1        # 只拉第一页(冒烟测试)
//
// 设计说明:
//   - NVD 2.0 API 分页全量拉取(每页 2000 条), 限速 5 req/s(无 API Key 的限额);
//     代理走环境变量 HTTP(S)_PROXY(Go 默认行为), 国内网络需先配代理。
//   - 只保留"网络可指纹"的产品(vendor:product 映射表): 版本匹配的前提是能从
//     banner/主动探测拿到版本号, 拿不到版本的产品(JDK/Spring/Log4j 等)进字典
//     也不会被命中, 白白撑大体积, 故在同步时过滤。
//   - 只收 application 类 CPE(part=a); 操作系统 CVE(part=o, 如 Windows)在 v1
//     不纳入 —— IIS 版本 -> Windows 版本的 EOL 判定已由内置规则覆盖, OS 级
//     CVE 的版本指纹可靠性不足(见 docs/vuln-rules-roadmap.md 的边界说明)。
//   - 版本约束转换: NVD 的 versionStartIncluding/Excluding + versionEndIncluding/
//     Excluding 四边界 -> 我们的 ">= a, < b" 子句(AND); 任一边界非数字
//     (alpha1/*/空值异常)时该 match 跳过(宁缺毋滥, 避免误报)。
//   - 输出格式与 scanner/cpe_builtin.json 完全一致(cpeFile), 放入 cpe/ 目录后
//     程序热加载即生效(同 CPE 外部覆盖内置), 无需重启、无需重新编译。

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// nvdKeyMap NVD CPE 的 vendor:product -> 本项目 CPE 字典产品键。
//
// 产品键必须与 scanner 的 productKey() 输出对齐(服务名归一化结果):
// 字典里的 product 字段 = 这里映射到的 key。新增可指纹产品时, 两边同时加。
var nvdKeyMap = map[string]string{
	"apache:http_server":        "apache",
	"apache:httpd":              "apache", // 旧版 CPE 命名
	"nginx:nginx":               "nginx",
	"microsoft:iis":             "iis",
	"microsoft:web_server":      "iis", // 旧版 CPE 命名
	"apache:tomcat":             "tomcat",
	"eclipse:jetty":             "jetty",
	"jetty:jetty":               "jetty",
	"jenkins:jenkins":           "jenkins",
	"openssh:openssh":           "openssh",
	"redis:redis":               "redis",
	"oracle:mysql":              "mysql",
	"mariadb:mariadb_server":    "mariadb",
	"postgresql:postgresql":     "postgresql",
	"mongodb:mongodb":           "mongodb",
	"elastic:elasticsearch":     "elasticsearch",
	"exim:exim":                 "exim",
	"php:php":                   "php",
	"memcached:memcached":       "memcached",
	"ntp:ntp":                   "ntp",
	"samba:samba":               "samba",
	"docker:docker":             "docker",
	"haproxy:haproxy":           "haproxy",
}

// ===== NVD API 数据结构(只取需要的字段) =====

type cveItem struct {
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

type cvePage struct {
	TotalResults int       `json:"totalResults"`
	TotalPages   int       `json:"totalPages"`
	Items        []cveItem `json:"items"`
}

// ===== 版本约束转换 =====

// isNumericVer 版本号是否可安全参与比较(纯数字与点; 拒绝 alpha1/*/带后缀的杂项)。
//
// NVD 的版本值质量参差: "alpha1"、"*"、"20140101" 之类的都出现过。我们引擎的
// 版本比较是语义化数字比较, 混进非数字会产生错误命中(误报), 因此这类 match 直接
// 丢弃 —— 宁可少报一条, 不能错报一条(错报会让用户不信任整个工具)。
func isNumericVer(v string) bool {
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

// versionBounds NVD cpeMatch 的四个版本边界
type versionBounds struct {
	VersionStartIncluding string
	VersionStartExcluding string
	VersionEndIncluding   string
	VersionEndExcluding   string
}

// constraintsFromMatch 把一个 NVD cpeMatch 的边界转成**一个**约束组字符串
// (组内子句以 ", " 连接 = AND)。无法安全表达时返回 ("", false)。
//
// 【格式关键: 必须合并成一个字符串】CPE 引擎的约束语义(cpe.go)是
// "每个 Constraints 元素 = 一个 AND 组, 多个元素 = OR"。若把 ">= a" 与 "< b"
// 拆成两个元素, 引擎按 OR 解释 = 全版本命中(误报)。一个 cpeMatch 的四个边界
// 是 AND 关系, 必须合并成 ">= a, < b" 这样一条。
//
// 返回空串(且 ok=true)表示该 match 无版本边界 = 该产品全部版本受影响。
func constraintsFromMatch(m versionBounds) (string, bool) {
	var clauses []string
	add := func(op, v string) {
		if v == "" {
			return
		}
		if !isNumericVer(v) {
			// 标记: 该 match 不可表达 —— 用特殊值传递
			clauses = append(clauses, "\x00BAD")
			return
		}
		clauses = append(clauses, op+" "+v)
	}
	add(">=", m.VersionStartIncluding)
	add(">", m.VersionStartExcluding)
	add("<=", m.VersionEndIncluding)
	add("<", m.VersionEndExcluding)
	for _, c := range clauses {
		if c == "\x00BAD" {
			return "", false
		}
	}
	if len(clauses) == 0 {
		// 无边界 = 该产品全部版本受影响(常见于老 CVE), 空串表达
		return "", true
	}
	return strings.Join(clauses, ", "), true
}

// vendorProduct 从 cpe23Uri 提取 "vendor:product"(仅 application 类)
func vendorProduct(criteria string) (string, bool) {
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

// ===== 同步主体 =====

func main() {
	outDir := flag.String("out", "dist/cpe", "输出目录(程序 exe 同目录的 cpe/)")
	minCVSS := flag.Float64("min-cvss", 0, "最低 CVSS 基础分(0=不过滤)")
	since := flag.String("since", "", "只同步该日期之后发布的 CVE(如 2015-01-01, 空=全量)")
	limit := flag.Int("limit", 0, "只拉取前 N 页(冒烟测试用, 0=全量)")
	base := flag.String("base", "https://services.nist.gov/api/cve/cves", "NVD API 基础 URL(可指向镜像/自建源, 便于离线环境)")
	flag.Parse()

	client := &http.Client{
		Timeout: 120 * time.Second,
		// 默认即尊重 HTTP(S)_PROXY 环境变量(Go 内置), 国内网络先配代理
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}

	var prods map[string]*nvdProduct
	prods = map[string]*nvdProduct{}
	total := 0
	kept := 0

	page := 1
	q := url.Values{}
	q.Set("pageSize", "2000")
	if *since != "" {
		// NVD 2.0 API: lastModStartDate 过滤"该日期之后新发布/修订"的 CVE
		q.Set("lastModStartDate", *since+"T00:00:00.000+00:00")
	}
	for {
		if *limit > 0 && page > *limit {
			break
		}
		q.Set("page", strconv.Itoa(page))
		fullURL := *base + "?" + q.Encode()
		body, err := fetchPage(client, fullURL)
		if err != nil {
			log.Fatalf("拉取第 %d 页失败: %v\n(提示: 国内网络通常需先设置 HTTPS_PROXY 环境变量, 见 docs/vuln-rules-roadmap.md)", page, err)
		}
		var pg cvePage
		if err := json.Unmarshal(body, &pg); err != nil {
			log.Fatalf("解析第 %d 页失败: %v", page, err)
		}
		total += len(pg.Items)
		for _, it := range pg.Items {
			if !processItem(it, prods, *minCVSS) {
				continue
			}
			kept++
		}
		fmt.Printf("  第 %d/%d 页 (%d 条 CVE, 累计 %d, 命中可指纹产品 %d)\n",
			page, pg.TotalPages, len(pg.Items), total, kept)
		if page >= pg.TotalPages {
			break
		}
		page++
		// 限速: 无 API Key 为 5 req/s, 留点余量
		time.Sleep(250 * time.Millisecond)
	}

	// 输出: 每个产品一个 JSON(与 cpe_builtin.json 同格式), 放入 cpe/ 热更新目录
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}
	names := make([]string, 0, len(prods))
	for k := range prods {
		names = append(names, k)
	}
	sort.Strings(names)
	totalCves := 0
	for _, k := range names {
		p := prods[k]
		if len(p.CVEs) == 0 {
			continue
		}
		totalCves += len(p.CVEs)
		vendor := strings.Split(keyCpe[k], ":")[3] // cpe:2.3:a:<vendor>:<product>
		doc := map[string]any{
			"version":  "nvd-sync " + time.Now().Format("2006-01-02"),
			"products": []map[string]any{{
				"cpe":     keyCpe[k],
				"vendor":  vendor,
				"product": p.Key,
				"cves":    p.CVEs,
			}},
		}
		fn := filepath.Join(*outDir, "nvd-"+p.Key+".json")
		data, _ := json.MarshalIndent(doc, "", "  ")
		if err := os.WriteFile(fn, data, 0o644); err != nil {
			log.Fatalf("写 %s 失败: %v", fn, err)
		}
		fmt.Printf("  写出 %-28s %4d 条 CVE\n", fn, len(p.CVEs))
	}
	fmt.Printf("\n完成: 共 %d 条 CVE, 其中 %d 条来自可指纹产品, 输出 %d 个产品文件 / %d 条 CVE 到 %s\n",
		total, kept, len(names), totalCves, *outDir)
	fmt.Println("下一步: 把上述文件放入程序 exe 同目录的 cpe/ 目录(本工具默认已输出到 dist/cpe), 重启程序或等待规则更新即热生效。")
}

// nvdProduct 聚合同一产品键的 CVE
type nvdProduct struct {
	Key  string
	CVEs []map[string]any
}

// keyCpe 产品键 -> 代表性 cpe:2.3:a:vendor:product 串(取 nvdKeyMap 第一个
// 映射到该键的 vendor:product)。仅作字典条目元数据(引擎匹配只依赖 product 键),
// 但保持规范格式便于人工核对与外部工具消费。
var keyCpe = func() map[string]string {
	keys := make([]string, 0, len(nvdKeyMap))
	for vp := range nvdKeyMap {
		keys = append(keys, vp)
	}
	sort.Strings(keys) // 确定性: map 迭代顺序随机, 排序后每键取字典序第一个 vendor:product
	m := map[string]string{}
	for _, vp := range keys {
		key := nvdKeyMap[vp]
		if _, ok := m[key]; !ok {
			m[key] = "cpe:2.3:a:" + vp
		}
	}
	return m
}()

func processItem(it cveItem, prods map[string]*nvdProduct, minCVSS float64) bool {
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
	// 标题: 优先英文描述
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

	// 按产品聚合约束(同一 CVE 可能有多个 configuration 节点/多个 match)。
	// 语义: 同一产品的不同 match 是 OR 关系(一个版本只会落在一个区间),
	// 每个 match 是一个 AND 组 -> 一个约束字符串; 空组(无边界)= 全版本受影响,
	// 与任何 OR 项并存时直接退化为"全版本"(constraints 置空)。
	type acc struct {
		groups   []string
		allVer   bool
	}
	byProd := map[string]*acc{}
	for _, cfg := range it.Cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CpeMatch {
				if !m.Vulnerable {
					continue // excluded 节点表达"不受影响", 不参与
				}
				vp, ok := vendorProduct(m.Criteria)
				if !ok {
					continue
				}
				key, ok := nvdKeyMap[vp]
				if !ok {
					continue
				}
				bounds := versionBounds{
					VersionStartIncluding: m.VersionStartIncluding,
					VersionStartExcluding: m.VersionStartExcluding,
					VersionEndIncluding:   m.VersionEndIncluding,
					VersionEndExcluding:   m.VersionEndExcluding,
				}
				group, expressible := constraintsFromMatch(bounds)
				if !expressible {
					continue
				}
				a := byProd[key]
				if a == nil {
					a = &acc{}
					byProd[key] = a
				}
				if group == "" {
					a.allVer = true // 无边界 match: 该产品全版本受影响
					continue
				}
				a.groups = appendUnique(a.groups, group)
			}
		}
	}
	if len(byProd) == 0 {
		return false
	}

	for key, a := range byProd {
		p := prods[key]
		if p == nil {
			p = &nvdProduct{Key: key}
			prods[key] = p
		}
		// allVer 时不写 constraints 字段(引擎: 缺省 = 全部版本受影响)
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

func appendUnique(list []string, items ...string) []string {
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

// fetchPage 拉取单页(带重试: NVD 偶发 5xx; 必须带 User-Agent, 否则 NVD 返回 403)
func fetchPage(client *http.Client, url string) ([]byte, error) {
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
