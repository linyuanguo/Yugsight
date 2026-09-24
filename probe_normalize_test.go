// probe_normalize_test.go 任务 6.4: 探针结果 → 中心端归一化入库链路的测试。
//
// 覆盖重点:
//  1. 报告提取的三条兼容路径(Report 结构体 / map / Raw JSON 字符串)
//  2. 归一化后落库: 资产与漏洞进 v2 表, 重复上报不重复增长
//  3. 空报告/非法输入不产生副作用(不写盘不 panic)
//  4. onProbeResultIngest 的 recover 兜底

package main

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"yugsight/db"
	"yugsight/models"
	"yugsight/normalizer"
	"yugsight/probe"
)

// setupProbeIngestDB 初始化一个临时 v2 数据库并注入 provider(测试后恢复)。
//
// 注入 v2DBProvider(而非 v2GetDB): 探针结果落库走的是 v2DB() ——
// 它不经 HTTP 层, 只认 v2DBProvider(见 api_v2.go 注释)。
//
// 恢复时必须置回原值: provider 若残留会导致其它用例的数据写进这个临时库。
func setupProbeIngestDB(t *testing.T) *db.Database {
	t.Helper()
	prevDisabled := authDisabled
	authDisabled = true
	v2DBProviderMu.Lock()
	prevProvider := v2DBProvider
	v2DBProviderMu.Unlock()
	t.Cleanup(func() {
		authDisabled = prevDisabled
		v2DBProviderMu.Lock()
		v2DBProvider = prevProvider
		v2DBProviderMu.Unlock()
	})

	d, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	// 排空自动存档的异步 goroutine(后注册先执行, 在 Close/TempDir 清理前完成写入),
	// 否则迟到的写入会让 TempDir RemoveAll 因目录非空失败(Windows 实测)。
	t.Cleanup(func() { waitRawSaves() })
	v2DBProviderMu.Lock()
	v2DBProvider = func() *db.Database { return d }
	v2DBProviderMu.Unlock()
	return d
}

// sampleProbeReport 构造一份探针报告(1 资产 2 漏洞: 1 有 CVE 1 无)。
func sampleProbeReport() normalizer.ProbeReport {
	return normalizer.ProbeReport{
		NodeID: "probe-placeholder",
		ScanID: "scan-1",
		Time:   time.Now(),
		Assets: []normalizer.ProbeAsset{{
			IP: "10.0.0.5", Hostname: "web01", OS: "Linux / Unix",
			Ports: []int{80, 443}, Service: "80/http,443/https",
			Banner: "nginx/1.18.0", Tags: []string{"存活", "web"},
		}},
		Vulns: []normalizer.ProbeVuln{
			{
				IP: "10.0.0.5", Port: 80, Protocol: "http", CVE: "CVE-2021-1234",
				Title: "Nginx 越界读取", Severity: "high", Description: "测试漏洞",
				Evidence: "证据A", Request: "GET / HTTP/1.1", Response: "HTTP/1.1 200 OK",
				Confidence: 100, FoundAt: time.Now(),
			},
			{
				IP: "10.0.0.5", Port: 23, Protocol: "tcp",
				Title: "Telnet 服务开放", Severity: "high", Description: "明文传输",
				Confidence: 40, FoundAt: time.Now(),
			},
		},
	}
}

// TestExtractProbeReport 报告提取的三条兼容路径都必须能取到数据。
func TestExtractProbeReport(t *testing.T) {
	rep := sampleProbeReport()

	// 路径 1: Report 为 normalizer.ProbeReport(同进程直传)
	got, ok := extractProbeReport(&probe.TaskResult{Report: rep})
	if !ok || len(got.Vulns) != 2 {
		t.Fatalf("结构体路径提取失败: ok=%v vulns=%d", ok, len(got.Vulns))
	}

	// 路径 2: Report 为 map(跨进程 JSON 编解码后的形态)
	b, _ := json.Marshal(rep)
	var asMap map[string]any
	_ = json.Unmarshal(b, &asMap)
	got, ok = extractProbeReport(&probe.TaskResult{Report: asMap})
	if !ok || len(got.Assets) != 1 || got.Assets[0].IP != "10.0.0.5" {
		t.Fatalf("map 路径提取失败: ok=%v assets=%+v", ok, got.Assets)
	}

	// 路径 3: 只在 Raw 里放 JSON(旧探针兜底)
	got, ok = extractProbeReport(&probe.TaskResult{Raw: string(b)})
	if !ok || len(got.Vulns) != 2 {
		t.Fatalf("Raw 路径提取失败: ok=%v vulns=%d", ok, len(got.Vulns))
	}

	// 空数据不应被认作有效报告
	if _, ok := extractProbeReport(&probe.TaskResult{}); ok {
		t.Fatal("空结果不应提取出报告")
	}
	if _, ok := extractProbeReport(nil); ok {
		t.Fatal("nil 结果不应提取出报告")
	}
}

// TestIngestProbeResultPersists 归一化入库: 资产与漏洞都应写入 v2 表,
// 且漏洞带来源标记与证据(供前端详情展示)。
func TestIngestProbeResultPersists(t *testing.T) {
	d := setupProbeIngestDB(t)

	stat := ingestProbeResult("probe-A", &probe.TaskResult{
		TaskID: "task-1", Status: probe.TaskDone, Report: sampleProbeReport(),
	})
	if stat == nil {
		t.Fatal("归一化应返回统计")
	}
	if stat.Assets != 1 {
		t.Fatalf("应入库 1 个资产, 实际 %d", stat.Assets)
	}
	if stat.Vulns != 2 {
		t.Fatalf("应入库 2 条漏洞, 实际 %d", stat.Vulns)
	}

	// 资产落库校验(含探针归属与标签合并)
	assets, err := d.Assets().FindByIP("10.0.0.5")
	if err != nil || len(assets) != 1 {
		t.Fatalf("资产应落库: err=%v n=%d", err, len(assets))
	}
	if assets[0].ProbeNode != "probe-A" {
		t.Fatalf("资产应归属探针 probe-A, 实际 %q", assets[0].ProbeNode)
	}
	// 端口 = 资产自带 [80,443] ∪ 漏洞端口 [23]: 归一化新建资产时必须带上自带的端口,
	// 否则"只在单批次里首现"的资产会丢掉全部端口(资产页看不到端口)。
	if len(assets[0].Ports) != 3 {
		t.Fatalf("资产端口应为 80/443/23 三份, 实际: %v", assets[0].Ports)
	}

	// 漏洞落库校验
	vulns, err := d.Vulns().Search(db.VulnQuery{AssetIP: "10.0.0.5"})
	if err != nil {
		t.Fatalf("漏洞查询失败: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("应有 2 条漏洞, 实际 %d", len(vulns))
	}
	var withCVE *db.Vuln
	for _, v := range vulns {
		if v.Source != normalizer.SourceProbe {
			t.Fatalf("漏洞来源应标记为 probe, 实际 %q", v.Source)
		}
		if v.CVE == "CVE-2021-1234" {
			withCVE = v
		}
	}
	if withCVE == nil {
		t.Fatal("带 CVE 的漏洞应落库")
	}
	if withCVE.Request == "" || withCVE.Response == "" {
		t.Fatal("漏洞应保留原始请求/响应证据")
	}
	if withCVE.Confidence != 100 {
		t.Fatalf("置信度应保留(100 = POC 验证), 实际 %d", withCVE.Confidence)
	}
}

// TestIngestProbeResultDedup 重复上报同一漏洞不应导致记录增长
// (同资产+同 CVE 归一化为同一条, 状态标记为重复)。
func TestIngestProbeResultDedup(t *testing.T) {
	d := setupProbeIngestDB(t)

	for i := 0; i < 3; i++ {
		stat := ingestProbeResult("probe-A", &probe.TaskResult{
			TaskID: "task-1", Status: probe.TaskDone, Report: sampleProbeReport(),
		})
		if stat == nil {
			t.Fatal("归一化应返回统计")
		}
	}

	vulns, err := d.Vulns().Search(db.VulnQuery{AssetIP: "10.0.0.5"})
	if err != nil {
		t.Fatalf("漏洞查询失败: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("重复上报不应增长记录(应仍为 2 条), 实际 %d", len(vulns))
	}
	// 资产同样不应重复(按 IP 幂等)
	assets, _ := d.Assets().FindByIP("10.0.0.5")
	if len(assets) != 1 {
		t.Fatalf("资产不应重复, 实际 %d", len(assets))
	}
}

// TestIngestProbeEmptyReport 空报告不应产生任何写入(避免无意义写盘)。
func TestIngestProbeEmptyReport(t *testing.T) {
	d := setupProbeIngestDB(t)

	stat := ingestProbeResult("probe-A", &probe.TaskResult{TaskID: "t", Status: probe.TaskDone})
	if stat == nil || stat.Assets != 0 || stat.Vulns != 0 {
		t.Fatalf("空报告应返回零统计, 实际 %+v", stat)
	}
	assets, _ := d.Assets().List()
	if len(assets) != 0 {
		t.Fatalf("空报告不应写入资产, 实际 %d", len(assets))
	}
}

// TestIngestProbeNoDB 数据库不可用时归一化必须静默跳过(不 panic 不阻断)。
//
// 说明: 这里直接用一个临时库然后关闭它 —— 关闭后的 DAO 会返回错误,
// 覆盖 persistProbeFindings 的"落库失败只记日志"分支(比传 nil 更接近真实故障)。
func TestIngestProbeNoDB(t *testing.T) {
	d := setupProbeIngestDB(t)
	_ = d.Close() // 关闭后再落库: 应走到错误分支而不是 panic

	stat := onProbeIngestNoPanic(t, func() *probeIngestStat {
		return ingestProbeResult("probe-A", &probe.TaskResult{
			TaskID: "t", Status: probe.TaskDone, Report: sampleProbeReport(),
		})
	})
	if stat == nil {
		t.Fatal("数据库不可用时应返回统计而不是 nil")
	}
	// 归一化统计仍然正确(只是没落库)
	if stat.Vulns != 2 {
		t.Fatalf("数据库不可用时归一化仍应产出统计, 实际 %d", stat.Vulns)
	}
	if stat.PersistFail == 0 {
		t.Fatal("落库失败应被计数(PersistFail > 0)")
	}
}

// onProbeIngestNoPanic 执行 fn 并把 panic 转成测试失败(明确断言"不 panic")。
func onProbeIngestNoPanic(t *testing.T, fn func() *probeIngestStat) (out *probeIngestStat) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("归一化不应 panic: %v", r)
		}
	}()
	return fn()
}

// TestOnProbeResultIngestRecover 归一化入口必须 recover 兜底:
// 传入异常数据不能让 panic 逃出并带走探针连接 goroutine。
func TestOnProbeResultIngestRecover(t *testing.T) {
	setupProbeIngestDB(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 不应 panic 逃出
		onProbeResultIngest("probe-A", &probe.TaskResult{
			TaskID: "t", Status: probe.TaskDone, Report: sampleProbeReport(),
		})
		onProbeResultIngest("probe-A", nil)
		// Report 为无法序列化的类型: 走 recover 路径
		onProbeResultIngest("probe-A", &probe.TaskResult{
			TaskID: "t", Report: make(chan int),
		})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("归一化入口超时(可能死锁)")
	}
}

// TestIngestProbeResultConcurrent 并发上报不同探针的结果不应产生竞态或丢数据。
func TestIngestProbeResultConcurrent(t *testing.T) {
	d := setupProbeIngestDB(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			rep := sampleProbeReport()
			// 每个探针扫不同主机, 避免互相覆盖
			ip := "10.0.0." + string(rune('1'+n))
			for j := range rep.Assets {
				rep.Assets[j].IP = ip
			}
			for j := range rep.Vulns {
				rep.Vulns[j].IP = ip
			}
			ingestProbeResult("probe-"+string(rune('A'+n)), &probe.TaskResult{
				TaskID: "task", Status: probe.TaskDone, Report: rep,
			})
		}(i)
	}
	wg.Wait()

	assets, err := d.Assets().List()
	if err != nil {
		t.Fatalf("资产列表失败: %v", err)
	}
	if len(assets) != 8 {
		t.Fatalf("8 个探针的资产都应落库, 实际 %d", len(assets))
	}
}

// TestProbeTaskArgs 下发参数组装: 空值不下发, 抓包开关透传。
func TestProbeTaskArgs(t *testing.T) {
	// 全部为空: 返回空串(探针端走默认配置, 能力全开)
	if s := probeTaskArgs(scanReq{Type: "port"}, ""); s != "" {
		t.Fatalf("无有效参数应返回空串, 实际 %q", s)
	}

	// 端口 + 超时 + 并发
	s := probeTaskArgs(scanReq{Type: "port", TimeoutMs: 2000, Concurrency: 64}, "80,443")
	var args map[string]any
	if err := json.Unmarshal([]byte(s), &args); err != nil {
		t.Fatalf("参数应为合法 JSON: %v (%q)", err, s)
	}
	if args["ports"] != "80,443" {
		t.Fatalf("端口应下发: %v", args["ports"])
	}
	if args["timeoutMs"] != float64(2000) || args["concurrency"] != float64(64) {
		t.Fatalf("超时/并发应下发: %v", args)
	}
	// 未开启抓包时不应出现 capture 字段(默认关)
	if _, ok := args["capture"]; ok {
		t.Fatal("未开启抓包不应下发 capture")
	}

	// 抓包开关 + 上限
	s = probeTaskArgs(scanReq{
		Type: "port", Capture: true, CaptureFilter: "host 10.0.0.5", CaptureMaxBytes: 1 << 20,
	}, "80")
	if err := json.Unmarshal([]byte(s), &args); err != nil {
		t.Fatalf("参数应为合法 JSON: %v", err)
	}
	if args["capture"] != true {
		t.Fatalf("capture 应为 true: %v", args["capture"])
	}
	if args["captureFilter"] != "host 10.0.0.5" {
		t.Fatalf("过滤条件应下发: %v", args["captureFilter"])
	}
	if args["captureMaxBytes"] != float64(1<<20) {
		t.Fatalf("大小上限应下发: %v", args["captureMaxBytes"])
	}
}

// TestProbeTargetAliveType alive 类型目标映射(任务 6.4 新增类型)。
func TestProbeTargetAliveType(t *testing.T) {
	target, ports := probeTarget(scanReq{Type: "alive", CIDR: "192.168.1.0/24"})
	if target != "192.168.1.0/24" {
		t.Fatalf("alive 应使用 CIDR, 实际 %q", target)
	}
	if ports != "" {
		t.Fatalf("alive 不应带端口, 实际 %q", ports)
	}
	// 端口字段仍应透传给 port/host
	if _, ports := probeTarget(scanReq{Type: "host", IP: "10.0.0.1", Ports: "80,443"}); ports != "80,443" {
		t.Fatalf("host 应透传端口, 实际 %q", ports)
	}
}

// TestProbeResultRawRoundTrip 报告经 Raw 字段往返后仍可被中心端解析。
//
// 这是跨进程通信的真实路径: 探针把报告序列化进 Raw(JSON 串)回传,
// 中心端必须能从 Raw 里还原出完整报告(含证据字段)。
func TestProbeResultRawRoundTrip(t *testing.T) {
	rep := sampleProbeReport()
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("报告序列化失败: %v", err)
	}
	// 模拟跨进程: Python/Go 的 json 解码会把对象变成 map, 但 Raw 是字符串原样保留
	got, ok := extractProbeReport(&probe.TaskResult{Raw: string(b)})
	if !ok {
		t.Fatal("Raw 往返后应能提取报告")
	}
	if len(got.Assets) != 1 || got.Assets[0].Hostname != "web01" {
		t.Fatalf("资产字段往返丢失: %+v", got.Assets)
	}
	if len(got.Vulns) != 2 {
		t.Fatalf("漏洞数量往返不一致: %d", len(got.Vulns))
	}
	for _, v := range got.Vulns {
		if strings.HasPrefix(v.CVE, "CVE-2021") {
			if v.Request == "" || v.Response == "" {
				t.Fatal("证据字段(请求/响应)往返丢失")
			}
			if v.Confidence != 100 {
				t.Fatalf("置信度往返丢失: %d", v.Confidence)
			}
		}
	}
}

// TestProbeVulnStatusFromNormalize 归一化产出的漏洞状态应为 new(首次发现)。
func TestProbeVulnStatusFromNormalize(t *testing.T) {
	batch := normalizer.FromProbeReport(sampleProbeReport())
	if batch == nil {
		t.Fatal("报告应能转成原始批次")
	}
	res := normalizer.NormalizeWithOptions(normalizer.Options{ScanID: "s1"}, batch)
	if res == nil || len(res.Vulns) == 0 {
		t.Fatal("归一化应产出漏洞")
	}
	for _, v := range res.Vulns {
		if v.Status != models.VulnStatusNew {
			t.Fatalf("首次归一化应标记为 new, 实际 %q", v.Status)
		}
	}
}
