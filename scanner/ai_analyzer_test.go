package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// sampleVuln 构造含多种敏感信息的样例漏洞数据(用于脱敏测试)
func sampleVuln() (*Vuln, *ServiceAsset) {
	v := &Vuln{
		ID:       "V-001",
		Severity: "high",
		Title:    "任意文件读取",
		Detail:   "通过 /login 接口可读取服务器文件",
		Source:   "nuclei",
		CVE:      "CVE-2021-44228",
		Path:     "/login",
		Request: "GET /login?token=abc123&password=admin123 HTTP/1.1\n" +
			"Host: 10.0.0.5\n" +
			"Authorization: Bearer sk-supersecret123\n" +
			"Cookie: session=xyz; user=root\n\n",
		Response: "HTTP/1.1 200 OK\n" +
			"Set-Cookie: JSESSIONID=abc; Path=/\n" +
			"Content-Type: application/json\n\n" +
			`{"access_token":"eyJhbGciOiJIUzI1NiJ9abc.def.ghi","auth":"Bearer abcdef123456","msg":"ok"}`,
	}
	a := &ServiceAsset{IP: "10.0.0.5", Port: 443, Scheme: "https", Product: "tomcat", Version: "9.0.50"}
	return v, a
}

// fakeLLM 纯内存 HTTP RoundTripper, mock OpenAI 兼容 LLM 响应(零真实网络)。
// 捕获每次请求的 user 消息, 用于断言"敏感信息未泄露给 LLM"。
type fakeLLM struct {
	mu       sync.Mutex
	hits     int
	gotUser  string
	gotBody  []byte
	status   int
	sse      string // 流式 SSE 响应体
	jsonBody string // 非流式 JSON 响应体
	useJSON  bool
	// 并发峰值统计(限流测试用)
	cur, peak int
	delay     time.Duration
}

func (f *fakeLLM) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.hits++
	f.cur++
	if f.cur > f.peak {
		f.peak = f.cur
	}
	f.mu.Unlock()

	body, _ := io.ReadAll(req.Body)
	var p struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(body, &p)
	f.mu.Lock()
	f.gotBody = body
	if len(p.Messages) > 0 {
		f.gotUser = p.Messages[len(p.Messages)-1].Content
	}
	f.mu.Unlock()

	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	f.cur--
	f.mu.Unlock()

	var respBody io.Reader
	ct := "text/event-stream"
	if f.useJSON {
		ct = "application/json"
		respBody = strings.NewReader(f.jsonBody)
	} else {
		respBody = strings.NewReader(f.sse)
	}
	return &http.Response{
		StatusCode: f.status,
		Status:     fmt.Sprintf("%d OK", f.status),
		Header:     http.Header{"Content-Type": []string{ct}},
		Body:       io.NopCloser(respBody),
		Request:    req,
	}, nil
}

// sseFor 构造单块 SSE 流式响应, content 为模型最终输出的 JSON 文本
func sseFor(content string) string {
	delta, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"delta": map[string]any{"content": content}}},
	})
	return fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", delta)
}

// TestDesensitizeRaw 脱敏: 敏感头/Bearer/JWT/密码类参数被擦除, 非敏感字段保留
func TestDesensitizeRaw(t *testing.T) {
	v, _ := sampleVuln()
	req := DesensitizeRaw(v.Request, 4096)
	resp := DesensitizeRaw(v.Response, 4096)

	for _, s := range []string{
		"sk-supersecret123", // Authorization 整行脱敏
		"admin123",          // password=***
		"abc123",            // token=***
		"session=xyz",       // Cookie 整行脱敏
		"JSESSIONID=abc",    // Set-Cookie 整行脱敏
		"eyJhbGciOiJIUzI1NiJ9", // JWT
		"abcdef123456",      // Bearer
	} {
		if strings.Contains(req, s) || strings.Contains(resp, s) {
			t.Errorf("脱敏后仍含敏感串 %q", s)
		}
	}
	if !strings.Contains(req, "Authorization: ***REDACTED***") {
		t.Errorf("Authorization 头应被脱敏: %q", req)
	}
	if !strings.Contains(req, "Cookie: ***REDACTED***") {
		t.Errorf("Cookie 头应被脱敏: %q", req)
	}
	if !strings.Contains(resp, "Set-Cookie: ***REDACTED***") {
		t.Errorf("Set-Cookie 头应被脱敏: %q", resp)
	}
	if !strings.Contains(resp, "***JWT***") {
		t.Errorf("JWT 应被脱敏: %q", resp)
	}
	if !strings.Contains(resp, "Bearer ***") {
		t.Errorf("Bearer 应被脱敏: %q", resp)
	}
	if !strings.Contains(req, "password=***") {
		t.Errorf("password 参数应被脱敏: %q", req)
	}
	// 非敏感字段应保留
	if !strings.Contains(req, "Host: 10.0.0.5") {
		t.Errorf("Host 头应保留: %q", req)
	}
	if !strings.Contains(req, "GET /login") {
		t.Errorf("请求行应保留: %q", req)
	}
}

// TestDesensitizeRawTruncate 超长证据截断到 maxBytes
func TestDesensitizeRawTruncate(t *testing.T) {
	long := strings.Repeat("a", 5000) + "\n" + strings.Repeat("b", 5000)
	if got := DesensitizeRaw(long, 2048); len(got) > 2048+64 || !strings.Contains(got, "[truncated]") {
		t.Errorf("超长证据应截断并带标记, got len=%d", len(got))
	}
	if got := DesensitizeRaw(strings.Repeat("x", 30000), 0); len(got) > defaultAIMaxEvidence+64 {
		t.Errorf("默认上限应为 %d, got %d", defaultAIMaxEvidence, len(got))
	}
}

// TestExtractJSON 从围栏/纯文本/异常输出中截取 JSON
func TestExtractJSON(t *testing.T) {
	for name, in := range map[string]string{
		"fenced": "```json\n{\"a\":1}\n```",
		"plain":  `pre {"a":1} post`,
		"nested": `{"a":1,"b":{"c":2}}`,
	} {
		got := extractJSON(in)
		if !strings.HasPrefix(got, "{") || !strings.HasSuffix(got, "}") {
			t.Errorf("%s: 应截取到完整 JSON, got %q", name, got)
		}
	}
	if got := extractJSON("no json here"); strings.Contains(got, "{") {
		t.Errorf("无 JSON 不应截取到对象, got %q", got)
	}
}

// TestParseAIResult 正常解析 + 数值钳制 + 异常降级(不 panic)
func TestParseAIResult(t *testing.T) {
	res := parseAIResult("finding", `{"riskSummary":"s","falsePositive":150,"needReview":true}`, "m", 0)
	if res.FalsePositive != 100 {
		t.Errorf("falsePositive 应钳制到 100, got %d", res.FalsePositive)
	}
	res2 := parseAIResult("finding", "抱歉我无法分析", "m", 0)
	if !res2.NeedReview || res2.RiskSummary != "抱歉我无法分析" {
		t.Errorf("非结构化输出应降级为原文并强制人工复核, got %+v", res2)
	}
}

// TestDisabledNoLLM 关闭态: 立即返回错误, 不发起任何 LLM 调用(不占资源)
func TestDisabledNoLLM(t *testing.T) {
	fl := &fakeLLM{}
	a := NewAIAnalyzer(AIModelConfig{Enabled: false, Backend: "openai", Model: "x", TimeoutSec: 5, MaxEvidence: 4096})
	a.SetTransport(fl)
	if _, err := a.AnalyzeSingleVuln(&Vuln{Title: "t"}, &ServiceAsset{IP: "1.1.1.1", Port: 80, Scheme: "http"}); err == nil {
		t.Fatal("禁用态应返回错误")
	}
	if _, err := a.AnalyzeScanBatch(nil, nil); err == nil {
		t.Fatal("禁用态批量应返回错误")
	}
	fl.mu.Lock()
	h := fl.hits
	fl.mu.Unlock()
	if h != 0 {
		t.Errorf("禁用态不应发起 LLM 调用, hits=%d", h)
	}
}

// TestAnalyzeSingleVulnE2E 端到端: 流式解析 + 脱敏断言(LLM 侧收不到敏感串) + 结果缓存
func TestAnalyzeSingleVulnE2E(t *testing.T) {
	const resultJSON = `{"riskSummary":"ok","falsePositive":30,"needReview":true,"reviewAdvice":"check","rootCause":"x"}`
	fl := &fakeLLM{status: 200, sse: sseFor(resultJSON)}
	a := NewAIAnalyzer(AIModelConfig{Enabled: true, Backend: "openai", Model: "m", TimeoutSec: 5, Desensitize: true, MaxEvidence: 4096})
	a.SetTransport(fl)
	v, as := sampleVuln()

	res, err := a.AnalyzeSingleVuln(v, as)
	if err != nil {
		t.Fatalf("AnalyzeSingleVuln 失败: %v", err)
	}
	if res.FalsePositive != 30 || !res.NeedReview {
		t.Errorf("结果解析异常: %+v", res)
	}
	if res.FromCache {
		t.Errorf("首次调用不应命中缓存")
	}

	// 脱敏断言: LLM 侧收到的 user 内容不得含任何敏感串
	for _, s := range []string{"sk-supersecret123", "admin123", "abc123", "session=xyz", "JSESSIONID=abc", "eyJhbGciOiJIUzI1NiJ9", "abcdef123456"} {
		if strings.Contains(fl.gotUser, s) {
			t.Errorf("敏感信息泄露到 LLM: %q", s)
		}
	}
	if !strings.Contains(fl.gotUser, "***REDACTED***") || !strings.Contains(fl.gotUser, "Bearer ***") {
		t.Errorf("user 内容应含脱敏标记: %q", fl.gotUser)
	}

	// 缓存: 第二次相同证据应命中缓存, 不再调用 LLM
	fl.mu.Lock()
	h1 := fl.hits
	fl.mu.Unlock()
	if h1 != 1 {
		t.Fatalf("首次应调用一次 LLM, hits=%d", h1)
	}
	res2, err := a.AnalyzeSingleVuln(v, as)
	if err != nil {
		t.Fatalf("第二次调用失败: %v", err)
	}
	if !res2.FromCache {
		t.Errorf("相同证据第二次应命中缓存")
	}
	fl.mu.Lock()
	h2 := fl.hits
	fl.mu.Unlock()
	if h2 != 1 {
		t.Errorf("命中缓存后不应再调用 LLM, hits=%d", h2)
	}
}

// TestAnalyzeScanBatchE2E 批量汇总: 流式 + 高危资产/横向渗透字段 + 不携带原始报文
func TestAnalyzeScanBatchE2E(t *testing.T) {
	const resultJSON = `{"riskSummary":"整体高危","falsePositive":20,"needReview":true,"reviewAdvice":"复核高危","highRiskAssets":["10.0.0.5","10.0.0.9"],"lateralRisk":"同网段开放 445, 存在横向移动风险"}`
	fl := &fakeLLM{status: 200, sse: sseFor(resultJSON)}
	a := NewAIAnalyzer(AIModelConfig{Enabled: true, Backend: "openai", Model: "m", TimeoutSec: 5, MaxEvidence: 4096})
	a.SetTransport(fl)
	assets := []*ServiceAsset{{IP: "10.0.0.5", Port: 443, Scheme: "https", Product: "tomcat", Version: "9.0.50"}}
	vulns := []*Vuln{{ID: "V-001", Severity: "high", Title: "任意文件读取", Source: "nuclei"}}

	res, err := a.AnalyzeScanBatch(assets, vulns)
	if err != nil {
		t.Fatalf("AnalyzeScanBatch 失败: %v", err)
	}
	if len(res.HighRiskAssets) != 2 || res.LateralRisk == "" {
		t.Errorf("批量字段解析异常: %+v", res)
	}
	// 批量模式只发送摘要, 不含原始请求/凭据(降低 token 与泄露面)
	if strings.Contains(fl.gotUser, "sk-") || strings.Contains(fl.gotUser, "Authorization") {
		t.Errorf("批量模式不应携带原始请求/凭据: %q", fl.gotUser)
	}
}

// TestAnalyzeRemediationE2E 修复建议: 非流式(整段 JSON)兜底分支可解析
func TestAnalyzeRemediationE2E(t *testing.T) {
	const resultJSON = `{"riskSummary":"文件上传漏洞","falsePositive":10,"needReview":false,"remediation":"Windows: 限制扩展名; Linux: chattr +i; 中间件: 配置白名单"}`
	inner, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]any{"content": resultJSON}}},
	})
	fl := &fakeLLM{status: 200, useJSON: true, jsonBody: string(inner)}
	a := NewAIAnalyzer(AIModelConfig{Enabled: true, Backend: "openai", Model: "m", TimeoutSec: 5, MaxEvidence: 4096})
	a.SetTransport(fl)
	v, as := sampleVuln()
	res, err := a.AnalyzeRemediation(v, as)
	if err != nil {
		t.Fatalf("AnalyzeRemediation 失败: %v", err)
	}
	if res.Remediation == "" {
		t.Errorf("remediation 应非空")
	}
}

// TestRateLimit 全局并发限流: MaxConcurrency=2 时, 10 个并发请求的 LLM 在途峰值 <= 2
func TestRateLimit(t *testing.T) {
	fl := &fakeLLM{status: 200, sse: sseFor(`{"riskSummary":"x","falsePositive":1}`), delay: 15 * time.Millisecond}
	SetMaxAIConcurrency(2)
	defer SetMaxAIConcurrency(defaultAIMaxConc) // 恢复默认, 避免影响其他测试
	a := NewAIAnalyzer(AIModelConfig{Enabled: true, Backend: "openai", Model: "m", TimeoutSec: 5, MaxEvidence: 4096, MaxConcurrency: 2})
	a.SetTransport(fl)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v := &Vuln{ID: fmt.Sprintf("V-%d", i), Title: fmt.Sprintf("t%d", i)}
			if _, err := a.AnalyzeSingleVuln(v, &ServiceAsset{IP: "10.0.0.1", Port: 80, Scheme: "http"}); err != nil {
				t.Errorf("并发分析失败: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if fl.peak > 2 {
		t.Errorf("LLM 在途峰值 %d 超过限流上限 2", fl.peak)
	}
	if fl.hits != 10 {
		t.Errorf("应完成全部 10 次调用, hits=%d", fl.hits)
	}
}

// TestStreamChatReasoningContentJSON 思考型模型(llama.cpp + Qwen3 等)只回
// reasoning_content、content 为空: 不回退的话页面只会看到"AI 接口无返回内容",
// 与"配置错误"无法区分 —— 这是真实线上踩过的坑(2026-09-23 服务端换模型后)。
func TestStreamChatReasoningContentJSON(t *testing.T) {
	fl := &fakeLLM{status: 200, useJSON: true, jsonBody: `{"choices":[{"message":{"role":"assistant","content":"","reasoning_content":"思考内容: 网络正常"}}]}`}
	a := NewAIAnalyzer(AIModelConfig{Enabled: true, Backend: "openai", Model: "m", TimeoutSec: 5})
	a.SetTransport(fl)
	out, err := a.StreamChat(context.Background(), "s", "u", nil)
	if err != nil {
		t.Fatalf("应回退 reasoning_content 而不是报错: %v", err)
	}
	if out != "思考内容: 网络正常" {
		t.Errorf("content 为空时应返回 reasoning_content, 得到 %q", out)
	}
}

// TestStreamChatSSEReasoningFallback SSE 流式路径同样回退: 只有 reasoning 增量、
// 无正式回答时, 结束时用思考内容兜底; 有正式回答时思考内容不得混入正文。
func TestStreamChatSSEReasoningFallback(t *testing.T) {
	// 场景 1: 全程只有 reasoning_content(思考吃光 token 预算)
	r1, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"delta": map[string]any{"reasoning_content": "思考A"}}},
	})
	r2, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"delta": map[string]any{"reasoning_content": "思考B"}}},
	})
	fl := &fakeLLM{status: 200, sse: "data: " + string(r1) + "\n\ndata: " + string(r2) + "\n\ndata: [DONE]\n\n"}
	a := NewAIAnalyzer(AIModelConfig{Enabled: true, Backend: "openai", Model: "m", TimeoutSec: 5})
	a.SetTransport(fl)
	out, err := a.StreamChat(context.Background(), "s", "u", nil)
	if err != nil {
		t.Fatalf("纯 reasoning 流应回退成功: %v", err)
	}
	if out != "思考A思考B" {
		t.Errorf("纯 reasoning 流应返回思考内容, 得到 %q", out)
	}

	// 场景 2: reasoning 之后有正式回答 —— 正文只含正式回答, 思考不混入
	c1, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"delta": map[string]any{"reasoning_content": "思考过程"}}},
	})
	c2, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"delta": map[string]any{"content": "正式结论"}}},
	})
	fl2 := &fakeLLM{status: 200, sse: "data: " + string(c1) + "\n\ndata: " + string(c2) + "\n\ndata: [DONE]\n\n"}
	a2 := NewAIAnalyzer(AIModelConfig{Enabled: true, Backend: "openai", Model: "m", TimeoutSec: 5})
	a2.SetTransport(fl2)
	out2, err := a2.StreamChat(context.Background(), "s", "u", nil)
	if err != nil {
		t.Fatalf("reasoning+content 流失败: %v", err)
	}
	if out2 != "正式结论" {
		t.Errorf("有正式回答时不得混入思考内容, 得到 %q", out2)
	}
}
