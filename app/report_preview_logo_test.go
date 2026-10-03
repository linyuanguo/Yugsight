package main

// 2026-09-25 两项用户需求的接口契约守卫:
//  ① 报告存档页内预览(GET /report/{id}/preview): HTML 应 200 + text/html,
//     供前端 iframe 渲染;
//  ② 模板封面 logo(POST/GET/DELETE /report/word/templates/visual/logo):
//     上传落盘 → 读取回显 → 删除后 404, 三段闭环。

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 1x1 透明 PNG(base64)—— 最小合法图片, 用于 logo 上传校验。
const testLogoB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC"

// TestReportPreviewByID 报告存档页内预览契约: HTML 报告回 200 + text/html。
func TestReportPreviewByID(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)

	// 先归档一份报告
	w := doReq(t, h, "POST", "/api/v2/report/generate",
		`{"format":"html","title":"预览契约","archive":true}`)
	if w.Code != 200 {
		t.Fatalf("generate status=%d body=%s", w.Code, w.Body.String())
	}
	// 报告 id 在 data.report.id(统一响应有 data 外层)
	var gen struct {
		Data struct {
			Report struct {
				ID string `json:"id"`
			} `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &gen); err != nil || gen.Data.Report.ID == "" {
		t.Fatalf("解析报告 id 失败: %v body=%s", err, w.Body.String())
	}
	rid := gen.Data.Report.ID

	// 预览: 200 + text/html + 内容含标题
	wp := doReq(t, h, "GET", "/api/v2/report/"+rid+"/preview", "")
	if wp.Code != 200 {
		t.Fatalf("preview status=%d", wp.Code)
	}
	if ct := wp.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("preview Content-Type 应为 text/html, 实际 %q", ct)
	}
	if !strings.Contains(wp.Body.String(), "预览契约") {
		t.Error("预览内容缺少报告标题")
	}

	// 不存在的 id -> 404
	wx := doReq(t, h, "GET", "/api/v2/report/no-such-id/preview", "")
	if wx.Code != 404 {
		t.Fatalf("预览不存在 id 应 404, 实际 %d", wx.Code)
	}
}

// TestReportPreviewWordAsHTML Word 存档页内预览契约(2026-09-25 用户要求"Word 也要
// 能页内打开, 不要只给下载"): 预览端点把存档的 .docx 解析回块序列再渲染成
// text/html 供 iframe 查看; 且渲染结果不再带"版权信息"悬浮按钮(用户要求移除,
// 章节本身在报告末尾, 不需要额外入口)。
func TestReportPreviewWordAsHTML(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)

	w := doReq(t, h, "POST", "/api/v2/report/generate",
		`{"format":"word","title":"Word预览契约","archive":true}`)
	if w.Code != 200 {
		t.Fatalf("generate status=%d body=%s", w.Code, w.Body.String())
	}
	var gen struct {
		Data struct {
			Report struct {
				ID string `json:"id"`
			} `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &gen); err != nil || gen.Data.Report.ID == "" {
		t.Fatalf("解析报告 id 失败: %v body=%s", err, w.Body.String())
	}
	rid := gen.Data.Report.ID

	wp := doReq(t, h, "GET", "/api/v2/report/"+rid+"/preview", "")
	if wp.Code != 200 {
		t.Fatalf("preview status=%d", wp.Code)
	}
	if ct := wp.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Word 预览 Content-Type 应为 text/html(块序列转 HTML), 实际 %q", ct)
	}
	body := wp.Body.String()
	if !strings.Contains(body, "Word预览契约") {
		t.Error("Word 预览内容缺少报告标题")
	}
	if strings.Contains(body, "doc-nav") {
		t.Error("Word 预览不应再带\"版权信息\"悬浮按钮(doc-nav)")
	}
}

// TestWordLogoUploadRoundTrip logo 上传→读取→删除闭环, 且落盘位置在 outp/logos/。
func TestWordLogoUploadRoundTrip(t *testing.T) {
	// wordTplDir 改指临时目录(同 reportConfigPath 手法), 避免污染开发机真实 outp/。
	// 注意: t.TempDir() 每次调用都建新目录, 必须捕获一次 —— 否则上传与校验各拿
	// 到不同目录, 文件"上传成功却校验找不到"。
	prev := wordTplDir
	dir := t.TempDir()
	wordTplDir = func() string { return dir }
	t.Cleanup(func() { wordTplDir = prev })

	h, _ := newReportTestEnv(t, true)

	name := "logo-test"
	// 1) 上传
	w1 := doReq(t, h, "POST", "/api/v2/report/word/templates/visual/logo",
		`{"name":"`+name+`","data":"`+testLogoB64+`"}`)
	if w1.Code != 200 {
		t.Fatalf("logo 上传 status=%d body=%s", w1.Code, w1.Body.String())
	}
	// 落盘: outp/logos/<name>.png
	lo := filepath.Join(wordTplDir(), "logos", name+".png")
	if _, err := os.Stat(lo); err != nil {
		t.Fatalf("logo 未落盘 %s: %v", lo, err)
	}

	// 2) 读取回显: 200 + image/png + 字节一致
	w2 := doReq(t, h, "GET", "/api/v2/report/word/templates/visual/logo?name="+name, "")
	if w2.Code != 200 {
		t.Fatalf("logo 读取 status=%d", w2.Code)
	}
	if ct := w2.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("logo Content-Type=%q, 期望 image/png", ct)
	}
	if got, _ := base64.StdEncoding.DecodeString(testLogoB64); string(w2.Body.Bytes()) != string(got) {
		t.Error("logo 读取字节与上传不一致")
	}

	// 3) 删除后 404
	w3 := doReq(t, h, "DELETE", "/api/v2/report/word/templates/visual/logo?name="+name, "")
	if w3.Code != 200 {
		t.Fatalf("logo 删除 status=%d", w3.Code)
	}
	w4 := doReq(t, h, "GET", "/api/v2/report/word/templates/visual/logo?name="+name, "")
	if w4.Code != 404 {
		t.Fatalf("删除后读取应 404, 实际 %d", w4.Code)
	}
}
