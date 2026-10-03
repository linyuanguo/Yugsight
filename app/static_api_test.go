package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestHandleStatic 静态下载契约: rootCA.crt 从 data/cert/ 直接读(无 static 副本);
// 其余直接子文件(证书工具)从 static/ 取; 目录穿越(../)、子路径、空名一律 404 ——
// 登录页未登录也能下载, 但不能借道读 data/cert/ 之外的凭据(server.pem/server-key.pem
// 即使物理存在于 data/cert/, 也必须 404: 通道只对 rootCA.crt 一个公钥文件精确放行)。
func TestHandleStatic(t *testing.T) {
	base := filepath.Join(exeDir(), "static")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	// 任意普通文件(模拟 YugsightCertTool.exe)放 static/
	if err := os.WriteFile(filepath.Join(base, "tool.bin"), []byte("TOOL"), 0o600); err != nil {
		t.Fatal(err)
	}
	// rootCA.crt 只放 data/cert/(模拟自动签发落盘), static/ 里不放
	certDir := filepath.Join(exeDir(), "data", "cert")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(certDir) })
	if err := os.WriteFile(filepath.Join(certDir, "rootCA.crt"), []byte("CERT"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "server-key.pem"), []byte("PRIV"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 正常取文件: rootCA.crt 走 data/cert/, 普通文件走 static/
	for _, p := range []string{"/static/rootCA.crt", "/static/tool.bin"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		handleStatic(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("取文件 %s 应 200, 实际 %d", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
			t.Errorf("Content-Type 应为 octet-stream, 实际 %q", ct)
		}
	}

	// 凭据绝不泄露: data/cert/server-key.pem 物理存在但通道不提供 → 404
	req := httptest.NewRequest(http.MethodGet, "/static/server-key.pem", nil)
	rec := httptest.NewRecorder()
	handleStatic(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("server-key.pem 应 404(凭据不公开), 实际 %d", rec.Code)
	}

	// 穿越 / 子路径 / 空名: 一律 404
	for _, p := range []string{"/static/../secret", "/static/sub/x", "/static/"} {
		req2 := httptest.NewRequest(http.MethodGet, p, nil)
		rec2 := httptest.NewRecorder()
		handleStatic(rec2, req2)
		if rec2.Code != http.StatusNotFound {
			t.Errorf("路径 %s 应 404, 实际 %d", p, rec2.Code)
		}
	}
}
