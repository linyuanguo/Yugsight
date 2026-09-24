package main

// TLS 配置契约测试(任务: HTTPS 支持)。
//
// 守的契约: tlsReady 是 main.go 决定"起 TLS 还是降级 HTTP"的唯一闸门 ——
// 判错方向两种后果都很重: 该启用时漏启用 = 凭据明文传输无提示;
// 证书缺失时误判可用 = 服务直接起不来(失去"能用但明文"的兜底, 规则 3)。
// 握手用例走真实自签证书 + TLS 客户端, 回环被沙箱拦截时跳过(真机联调覆盖)。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestTLSReady(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		cfg  tlsConfig
		want bool
	}{
		{"默认零值不启用", tlsConfig{}, false},
		{"启用但缺路径", tlsConfig{Enabled: true}, false},
		{"启用但只给 cert", tlsConfig{Enabled: true, Cert: cert}, false},
		{"启用但文件不存在", tlsConfig{Enabled: true, Cert: filepath.Join(dir, "nope.pem"), Key: key}, false},
		{"启用且文件都在", tlsConfig{Enabled: true, Cert: cert, Key: key}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := c.cfg.tlsReady()
			if got != c.want {
				t.Fatalf("tlsReady = %v (reason=%q), 期望 %v", got, reason, c.want)
			}
		})
	}
}

// writeSelfSignedCert 现场生成自签证书(ECDSA P-256, 含 127.0.0.1 SAN)。
func writeSelfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "yugsight-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// loopbackAllowed 回环 TCP 是否可用(沙箱拦截时跳过握手用例)。
func loopbackAllowed() bool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestStartTLSServerHandshake 端到端: 自签证书起 TLS 服务, 客户端
// InsecureSkipVerify 握手拿到 200。守"证书配对正确才起服务"的链路;
// 回环被沙箱拦截时跳过, 由真机联调覆盖。
func TestStartTLSServerHandshake(t *testing.T) {
	if !loopbackAllowed() {
		t.Skip("沙箱拦截回环连接, TLS 握手由真机联调覆盖")
	}
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	// 取一个空闲端口作起始(startTLSServer 会从其起顺延 20 个)。
	// 注意 SplitHostPort 返回 (host, port) —— 取反了会得到 "127.0.0.1"
	// 转 0, 服务落到 0 号端口随机监听, 握手 URL 直接失效。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	basePort, _ := strconv.Atoi(portStr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls-ok"))
	})
	addr, port, err := startTLSServer(mux, basePort, "127.0.0.1", tlsConfig{Enabled: true, Cert: certPath, Key: keyPath})
	if err != nil {
		t.Fatalf("startTLSServer 失败: %v", err)
	}
	t.Logf("TLS 服务监听 %s", addr)

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   3 * time.Second,
	}
	resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatalf("TLS 握手失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TLS 端点应 200, 实际 %d", resp.StatusCode)
	}
}

// TestHTTPSRedirectHandler HTTP→HTTPS 强制跳转的契约(离线, 不依赖回环):
// 301 状态码 + Location 保留访问主机/路径/查询, 只换 scheme 与端口。
// 漏掉路径(只跳根)会让用户从 /app/ 跳回首页, 属于高频可见 bug。
func TestHTTPSRedirectHandler(t *testing.T) {
	h := httpsRedirectHandler(8420)
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"根路径", "http://192.168.1.143:8421/", "https://192.168.1.143:8420/"},
		{"子路径带查询", "http://192.168.1.143:8421/app/index.html?from=old", "https://192.168.1.143:8420/app/index.html?from=old"},
		{"无端口主机", "http://192.168.1.143/console", "https://192.168.1.143:8420/console"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, c.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusMovedPermanently {
				t.Fatalf("应 301, 实际 %d", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != c.want {
				t.Fatalf("Location = %q, 期望 %q", got, c.want)
			}
		})
	}
}
