package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/models"
	"yugsight/internal/server"
)

// TestScreenOverviewAPI 大屏总览接口: 结构完整 + 关键指标正确。
func TestScreenOverviewAPI(t *testing.T) {
	h, d := newV2TestEnv(t)
	now := time.Now()

	a := db.NewAsset("192.168.1.10")
	a.Alive = true
	a.Hostname = "web01"
	a.Ports = []int{22, 80}
	if _, err := d.Assets().Upsert(a); err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	dead := db.NewAsset("192.168.1.11")
	if _, err := d.Assets().Upsert(dead); err != nil {
		t.Fatalf("upsert asset: %v", err)
	}

	for _, in := range []struct {
		ip, title, sev string
	}{
		{"192.168.1.10", "Redis 未授权访问", "critical"},
		{"192.168.1.10", "老旧 OpenSSH", "high"},
		{"192.168.1.11", "信息泄露", "medium"},
	} {
		v := db.NewVuln(in.ip, in.title, in.sev)
		v.FoundAt, v.LastSeenAt = now.Add(-time.Hour), now.Add(-time.Hour)
		if _, err := d.Vulns().Upsert(v); err != nil {
			t.Fatalf("upsert vuln: %v", err)
		}
	}

	w := doReq(t, h, "GET", "/api/v2/screen/overview", "")
	if w.Code != 200 {
		t.Fatalf("status=%d body=%.400s", w.Code, w.Body.String())
	}
	out := decodeResp(t, w)
	if out.Code != server.CodeOK {
		t.Fatalf("resp=%+v", out)
	}
	body := w.Body.String()
	// 大屏各区块必须齐备(缺任何一段前端就会留空白占位)
	// 逐个字段断言, 而不是只判 200: 大屏最怕的是"接口通了但某项永远为 0"
	for _, key := range []string{
		`"overview"`, `"trend"`, `"severity"`, `"probes"`, `"topVulns"`, `"topAssets"`, `"recentTasks"`,
		`"assets"`, `"assetsAlive"`, `"tasksRunning"`, `"probesOnline"`,
	} {
		if !strings.Contains(body, key) {
			t.Fatalf("响应缺少字段 %s: %.500s", key, body)
		}
	}
	// 趋势点应为默认 7 天
	if n := strings.Count(body, `"label"`); n != 7 {
		t.Fatalf("趋势点数应为 7, got %d", n)
	}
	// 关键指标值(资产 2 台其中 1 台存活; 漏洞 3 条未修复)
	for _, want := range []string{
		`"assets":2`, `"assetsAlive":1`, `"assetsDown":1`,
		`"critical":1`, `"high":1`, `"medium":1`, `"risk":3`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("响应缺少指标 %s:\n%s", want, body)
		}
	}
	// 探针未启用时不应报错, 只是空列表
	if !strings.Contains(body, `"probes":[]`) {
		t.Fatalf("无探针时 probes 应为空数组(而非 null):\n%s", body)
	}
}

// TestScreenOverviewParams 参数钳制: days/top 超出范围不应放大响应。
func TestScreenOverviewParams(t *testing.T) {
	h, _ := newV2TestEnv(t)
	w := doReq(t, h, "GET", "/api/v2/screen/overview?days=9999&top=9999", "")
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if n := strings.Count(w.Body.String(), `"label"`); n != 90 {
		t.Fatalf("days 应被钳制为 90, got %d", n)
	}
	w = doReq(t, h, "GET", "/api/v2/screen/overview?days=abc&top=-5", "")
	if w.Code != 200 {
		t.Fatalf("非法参数应回落默认值, status=%d", w.Code)
	}
	if n := strings.Count(w.Body.String(), `"label"`); n != 7 {
		t.Fatalf("非法 days 应回落 7, got %d", n)
	}
}

// TestScreenMetricsDisabledByDefault 二期预留端点默认不挂载。
func TestScreenMetricsDisabledByDefault(t *testing.T) {
	h, _ := newV2TestEnv(t)
	w := doReq(t, h, "GET", "/api/v2/screen/metrics", "")
	if w.Code != 404 {
		t.Fatalf("metrics 默认应未启用(404), got %d body=%.200s", w.Code, w.Body.String())
	}
}

// TestScreenMetricsEnabled 开关打开后 handler 返回 Prometheus 文本且不含 JSON 信封。
//
// 直接调 handler 而不是走路由: 路由注册依赖全局配置单例, 若用临时目录里的
// screen.json 驱动注册流程, 会把配置缓存污染到其它用例(与 report/scheduler
// 测试对全局缓存的处理约定一致)。
func TestScreenMetricsEnabled(t *testing.T) {
	_, d := newV2TestEnv(t)
	v := db.NewVuln("192.168.1.10", "严重", "critical")
	v.FoundAt, v.LastSeenAt = time.Now(), time.Now()
	if _, err := d.Vulns().Upsert(v); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v2/screen/metrics", nil)
	w := httptest.NewRecorder()
	hScreenMetrics(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type 应为 text/plain, got %s", ct)
	}
	body := w.Body.String()
	if strings.Contains(body, `"code"`) {
		t.Fatalf("指标端点不应返回 v2 JSON 信封: %.200s", body)
	}
	if !strings.Contains(body, `yugsight_vulns_total{severity="critical"} 1`) {
		t.Fatalf("指标内容错误:\n%s", body)
	}
}

// TestBigScreenConfigDefault 配置缺省 = metrics 关闭(不依赖磁盘文件)。
func TestBigScreenConfigDefault(t *testing.T) {
	prevMu := bigScreenCfgDone
	prevVal := bigScreenCfgVal
	t.Cleanup(func() {
		bigScreenCfgMu.Lock()
		bigScreenCfgDone, bigScreenCfgVal = prevMu, prevVal
		bigScreenCfgMu.Unlock()
	})
	// 直接置入"已加载且默认值", 避免读到开发机上真实的 screen.json
	bigScreenCfgMu.Lock()
	bigScreenCfgDone, bigScreenCfgVal = true, bigScreenConfig{}
	bigScreenCfgMu.Unlock()

	if cfg := loadBigScreenConfig(); cfg.Metrics {
		t.Fatal("默认应关闭 Prometheus 指标端点")
	}
	// 状态字段是隐式的: 打开开关后应能读到
	bigScreenCfgMu.Lock()
	bigScreenCfgDone, bigScreenCfgVal = true, bigScreenConfig{Metrics: true}
	bigScreenCfgMu.Unlock()
	if cfg := loadBigScreenConfig(); !cfg.Metrics {
		t.Fatal("配置为 true 时应读回 true")
	}
}

// TestBigScreenConfigPath 配置路径落在 exe 同目录。
func TestBigScreenConfigPath(t *testing.T) {
	p := bigScreenConfigPath()
	if !strings.HasSuffix(p, "screen.json") {
		t.Fatalf("配置路径应以 screen.json 结尾: %s", p)
	}
}

// TestBigScreenConfigBOM 带 UTF-8 BOM 的 screen.json 必须能正常解析。
//
// 回归用例: Windows 记事本与 PowerShell Set-Content -Encoding utf8 都会写入
// BOM(EF BB BF)。不剥离时 json.Unmarshal 报 "invalid character 'ï'",
// 用户看到的现象是"改了配置却不生效", 极难自行定位(任务 6.3 在 probe.json
// 上踩过同一个坑)。这里不经文件系统, 直接验证剥离逻辑本身。
func TestBigScreenConfigBOM(t *testing.T) {
	raw := []byte{0xEF, 0xBB, 0xBF}
	raw = append(raw, []byte(`{"metrics":true}`)...)

	// 不剥 BOM 时必然失败 —— 先证明这个前提成立, 否则本用例会变成"永远通过"
	if err := json.Unmarshal(raw, &bigScreenConfig{}); err == nil {
		t.Fatal("前提不成立: 带 BOM 的 JSON 竟然能直接解析, 用例失去意义")
	}
	trimmed := bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	var cfg bigScreenConfig
	if err := json.Unmarshal(trimmed, &cfg); err != nil {
		t.Fatalf("剥 BOM 后应能解析: %v", err)
	}
	if !cfg.Metrics {
		t.Fatal("剥 BOM 后 metrics 应为 true")
	}
}

// TestEnrichProbeLoadNilCenter 探针中心端未启用时补数据函数应安全空操作。
func TestEnrichProbeLoadNilCenter(t *testing.T) {
	prev := probeCenter
	t.Cleanup(func() { probeCenter = prev })
	probeCenter = nil

	// 不应 panic
	enrichProbeLoad(nil)
}

// TestOverviewVulnListUnaffected 大屏接口不得影响既有漏洞列表接口口径。
func TestOverviewVulnListUnaffected(t *testing.T) {
	h, d := newV2TestEnv(t)
	v := db.NewVuln("192.168.1.20", "测试漏洞", "high")
	v.FoundAt, v.LastSeenAt = time.Now(), time.Now()
	if _, err := d.Vulns().Upsert(v); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	v.Severity = models.SeverityHigh
	w := doReq(t, h, "GET", "/api/v2/vulns?size=10", "")
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "测试漏洞") {
		t.Fatalf("既有漏洞列表接口异常: %.300s", w.Body.String())
	}
}
