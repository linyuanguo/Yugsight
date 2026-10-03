package main

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"yugsight/internal/report"
)

// TestReportDownloadFilenameUTF8 守报告下载文件名的契约(2026-09-25 用户反馈
// "下载名带问号"): 中文标题裸塞 filename="..." 会被浏览器按 Latin-1 解码,
// 每个中文字变 "?"。必须带 RFC 5987 filename*=UTF-8''<百分号编码>, 且 ASCII
// 回退 filename 不得含非 ASCII 字符。
func TestReportDownloadFilenameUTF8(t *testing.T) {
	h, d := newReportTestEnv(t, true)

	arch := &report.Archive{
		Title:     "客户A 安全扫描报告",
		Operator:  "测试",
		CreatedAt: time.Now(),
		Format:    report.FormatWord,
		Status:    report.StatusReady,
		ContentB64: base64.StdEncoding.EncodeToString([]byte("fake-docx")),
	}
	arch.Validate()
	if _, err := d.Reports().Upsert(arch); err != nil {
		t.Fatalf("存档: %v", err)
	}

	w := doReq(t, h, "GET", "/api/v2/report/"+arch.ID+"/download", "")
	if w.Code != 200 {
		t.Fatalf("下载应 200, 实际 %d", w.Code)
	}
	cd := w.Header().Get("Content-Disposition")
	t.Logf("Content-Disposition: %s", cd)

	// 1) 必须带 filename*(RFC 5987)
	i := strings.Index(cd, "filename*=UTF-8''")
	if i < 0 {
		t.Fatalf("缺 filename*=UTF-8'' 参数: %s", cd)
	}
	star := strings.SplitN(cd[i+len("filename*=UTF-8''"):], ";", 2)[0]
	// 2) filename* 值不得含裸中文(必须全百分号编码)
	for _, r := range star {
		if r >= 0x80 {
			t.Fatalf("filename* 含未编码的非 ASCII 字符: %s", star)
		}
	}
	// 3) 解码后应还原完整中文标题
	decoded, err := url.PathUnescape(star)
	if err != nil {
		t.Fatalf("filename* 不是合法百分号编码: %s", star)
	}
	if !strings.Contains(decoded, "客户A 安全扫描报告") {
		t.Fatalf("filename* 解码后应含中文标题: %q", decoded)
	}
	if !strings.HasSuffix(decoded, ".docx") {
		t.Fatalf("文件名应以 .docx 结尾: %q", decoded)
	}

	// 4) ASCII 回退 filename 不得含非 ASCII
	ascii := ""
	for _, seg := range strings.Split(cd, ";") {
		seg = strings.TrimSpace(seg)
		if strings.HasPrefix(seg, "filename=") {
			ascii = strings.Trim(seg[len("filename="):], `"`)
		}
	}
	for _, r := range ascii {
		if r >= 0x80 {
			t.Fatalf("ASCII 回退 filename 含非 ASCII: %q", ascii)
		}
	}
	if ascii == "" {
		t.Fatal("缺 ASCII 回退 filename(老客户端兼容)")
	}
}
