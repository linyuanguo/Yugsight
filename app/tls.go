package main

// HTTPS 支持(任务: TLS)。
//
// 背景: 本工具传输登录凭据/2FA 动态码/探针 token, 纯 HTTP 下局域网内任何设备
// 都能抓到明文。TLS 是"凭据不进明文"的底线, 内网自签证书即可, 不需要 CA。
//
// 配置(settings.json 的 tls 节, 默认关闭, 规则 5):
//
//	{
//	  "tls": { "enabled": true, "cert": "cert.pem", "key": "key.pem" }
//	}
//
// cert/key 支持绝对路径或 exe 同目录相对路径。enabled=true 但证书文件缺失/
// 加载失败时**降级为 HTTP 并记日志**(规则 3: 外部资源缺失降级不报错) —— 否则
// 用户配了 TLS 却忘了放证书, 服务直接起不来, 反而丢掉了"能用但明文"的兜底。

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/internal/scanner"
)

// tlsConfig 统一配置中心 settings.json 的 tls 节(默认关闭, 规则 5)。
//
// 字段口径:
//
//	{
//	  "tls": { "enabled": true, "cert_file": "data/cert/server.pem", "key_file": "data/cert/server-key.pem" }
//	}
//
// cert_file/key_file 是任务约定的主字段; cert/key 是早期实现留下的旧字段名,
// 两者并存做向后兼容(cert_file 优先)。均未填时走下方默认路径 —— 并自动签发
// (见 ensureTLSAssets), 用户无需手工 openssl。
type tlsConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// 旧字段名兼容(早期实现用 cert/key, 现有配置与测试均用它们, 不能删)
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// loadTLSConfig 读 tls 节; 缺失/解析失败返回零值(= 不启用)。
func loadTLSConfig() tlsConfig {
	var c tlsConfig
	if data, ok := section(secTLS, "tls.json"); ok && len(data) > 0 {
		_ = json.Unmarshal(data, &c)
	}
	return c
}

// tlsSelfSignedActive 运行中的 HTTPS 是否使用**自动签发的自签证书**(main 启动时设置)。
// 登录页据此显示"安装根证书"引导: 自签证书用户需要装根证书消除浏览器警告; 用户自带
// 的(可能来自正规 CA 的)证书不需要该引导。
var tlsSelfSignedActive bool

// 默认证书/私钥路径(exe 同目录, 相对路径按 exe 目录解析, 见 resolveCertPath)。
// 2026-09-29 用户要求: cert/ 归入 data/ —— 证书与运行时数据同处 data 目录,
// 默认路径随之改为 data/cert/。启用 TLS 但未显式指定 cert_file/key_file 时用这套;
// 缺失时由 ensureTLSAssets 自动签发根 CA + 服务端证书到此处, 让用户"开开关就能用 HTTPS"。
const (
	defaultCertFile = "data/cert/server.pem"
	defaultKeyFile  = "data/cert/server-key.pem"
)

// effectiveCert / effectiveKey 解析实际生效的证书/私钥路径:
// 优先任务口径的 cert_file/key_file, 回退旧字段 cert/key, 最后回退默认路径。
func (c tlsConfig) effectiveCert() string {
	switch {
	case c.CertFile != "":
		return c.CertFile
	case c.Cert != "":
		return c.Cert
	default:
		return defaultCertFile
	}
}
func (c tlsConfig) effectiveKey() string {
	switch {
	case c.KeyFile != "":
		return c.KeyFile
	case c.Key != "":
		return c.Key
	default:
		return defaultKeyFile
	}
}

// userSpecified 用户是否显式给出了证书路径(区分"我要用自己的证书"与"用默认自动签发")。
func (c tlsConfig) userSpecified() bool {
	return c.CertFile != "" || c.KeyFile != "" || c.Cert != "" || c.Key != ""
}

// tlsReady 证书可用: enabled 且生效路径下两文件都能读。返回 (可启用, 原因)。
//
// 【调用顺序】main 在调 tlsReady 之前先经 ensureTLSAssets 补齐缺失证书, 故走到这里
// 时默认路径的证书要么已生成、要么用户显式指定的路径存在, 缺失即真缺失(降级 HTTP)。
func (c tlsConfig) tlsReady() (bool, string) {
	if !c.Enabled {
		return false, "未启用"
	}
	for _, p := range []string{c.effectiveCert(), c.effectiveKey()} {
		if _, err := os.Stat(resolveCertPath(p)); err != nil {
			return false, "证书文件不可读: " + p
		}
	}
	return true, ""
}

func resolveCertPath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return p
	}
	return filepath.Join(filepath.Dir(exe), p)
}

// startTLSServer 与 startServer 同端口顺延策略, 差别只在监听器带 TLS。
// 证书加载失败由调用方先经 tlsReady 拦截, 这里仍做兜底(加载失败返回错误,
// 调用方降级 HTTP)。
// httpsRedirectTarget 计算 301 跳转目标: 保留用户实际访问的主机(可能是 IP、
// 也可能是绑定域名), 只把 scheme 换成 https、端口换成 HTTPS 主服务端口。
//
// 用 r.Host 而不是本地 IP 拼: 服务可能绑局域网 IP 而用户经另一网卡/别名访问,
// 按访问者视角跳转才能"点一下还停在同一台机器上"。
func httpsRedirectTarget(r *http.Request, httpsPort int) string {
	hostPart := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		hostPart = h
	}
	return "https://" + net.JoinHostPort(hostPart, strconv.Itoa(httpsPort)) + r.URL.RequestURI()
}

// httpsRedirectHandler HTTP→HTTPS 强制跳转处理器(功能审计 1b)。
func httpsRedirectHandler(httpsPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpsRedirectTarget(r, httpsPort), http.StatusMovedPermanently)
	})
}

// startHTTPRedirectServer 起一个纯跳转的 HTTP 监听: 从 startPort 起顺延找空端口
// (HTTPS 主服务已占用起始端口, 通常落在 startPort+1)。
//
// 为什么单独一个监听而不是"同端口协议探测": TLS 握手失败的 HTTP 请求在浏览器里
// 表现为"连接错误"而非"跳转", 用户只会困惑; 给 HTTP 一个明确的端口并 301,
// 行为可预期, 日志也能把两个端口都告诉用户。
func startHTTPRedirectServer(httpsPort, startPort int, host string) (string, int, error) {
	for i := 0; i < 20; i++ {
		p := startPort + i
		if p == httpsPort {
			continue // 与 HTTPS 主服务同端口不可能成立, 防御性跳过
		}
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		go func() {
			if err := http.Serve(ln, httpsRedirectHandler(httpsPort)); err != nil {
				logLine("HTTP 跳转服务异常: " + err.Error())
			}
		}()
		return addr, p, nil
	}
	return "", 0, nil
}

func startTLSServer(mux http.Handler, startPort int, host string, cfg tlsConfig) (string, int, error) {
	certPath := resolveCertPath(cfg.effectiveCert())
	keyPath := resolveCertPath(cfg.effectiveKey())

	var tlsCfg *tls.Config
	if cfg.userSpecified() {
		// 用户自带证书: 静态加载(原逻辑, 不做动态签发 —— 用户证书固定不变)。
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return "", 0, err
		}
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	} else {
		// 默认自签: 固定根 CA + 按访问 IP/域名即时签发 + 白名单准入(换 IP 热加载)。
		if err := ensureCertAssets(certPath, keyPath); err != nil {
			return "", 0, err
		}
		if err := loadCertAssets(certPath, keyPath); err != nil {
			return "", 0, err
		}
		// 关键: 不能同时设 Certificates —— Go 只在"无静态证书 或 客户端发 SNI"时才调用
		// GetCertificate(crypto/tls common.go getCertificate), 静态兜底证书会挡住
		// "浏览器 IP 访问(无 SNI)"这条分支, 导致永远回 localhost 证书(SAN 无 IP)。
		// SNI 为空时 getCertForHello 签发覆盖全部本机 IP 的证书, 本身就是兜底, 无需静态证书。
		tlsCfg = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: getCertForHello,
		}
	}
	for i := 0; i < 20; i++ {
		p := startPort + i
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		ln, err := tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			continue
		}
		go func() {
			// 2026-09-29: 默认 ErrorLog 会把每个未信任自签证书的客户端握手拒绝打到控制台
			// 刷屏(用户实机: WSL 探针多端口探测, 一分钟刷几十行)。换成过滤过的 logger,
			// 只静音"客户端拒绝我方自签证书"这一种良性错误, 其余握手错误照常记录。
			srv := &http.Server{Handler: mux, ErrorLog: log.New(handshakeLogFilter{}, "", 0)}
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				logLine("HTTPS 服务异常: " + err.Error())
			}
		}()
		return addr, p, nil
	}
	return "", 0, nil // 端口全占用: 调用方改走 startServer 继续顺延
}

// handshakeLogFilter 过滤 TLS 握手错误日志。内网客户端未信任自签根证书时, 每次 HTTPS
// 探测/访问都会触发一条 "remote error: tls: unknown certificate"(或 bad certificate)——
// 这是客户端拒绝我方自签证书, 属预期现象, 既无告警价值又刷屏。只静音这一类;
// 畸形握手、协议异常等真正值得看的错误原样记录。
type handshakeLogFilter struct{}

func (handshakeLogFilter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("unknown certificate")) || bytes.Contains(p, []byte("bad certificate")) {
		return len(p), nil
	}
	logLine(strings.TrimSpace(string(p)))
	return len(p), nil
}

// hstsHandler 为 HTTPS 请求添加 HSTS 响应头(Strict-Transport-Security: max-age=31536000)。
//
// 【为什么只在 r.TLS != nil 时设置】HSTS 头浏览器只在安全连接(HTTPS)下处理, 纯 HTTP
// 响应带它无效; 且"未配置证书回退纯 HTTP"时下发 HSTS 会让浏览器把该域记成"必须 HTTPS",
// 之后用户再访问 http:// 直接被拦, 反而打不开。故仅在经 TLS 握手的请求上设置。
// max-age=31536000(1 年): 浏览器记住该域后续一律走 HTTPS, 防协议降级攻击。
func hstsHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

// ensureTLSAssets 启动 TLS 前确保证书就绪。返回 (是否可用, 说明)。
//
// 两条路径:
//  1. 用户显式指定了证书(cert_file/key_file 或 cert/key 非空) → 不自动生成, 尊重用户
//     自己的证书; 缺失时返回不可用(调用方降级 HTTP), 不覆盖、不签发到用户路径。
//  2. 未指定(走默认路径) → 缺失时自动签发 根CA + 服务端证书 到 data/cert/ 默认路径,
//     并把根证书留存在 data/cert/rootCA.crt(登录页"手动导入"与证书工具经
//     /static/rootCA.crt 直接读 data/cert/ 目录下载 —— 不再复制 static 副本,
//     见 static_api.go, 2026-09-29)。
//
// 自动签发是内网自签场景的兜底: 用户"开开关"即有可用 HTTPS, 无需手工 openssl,
// 也天然产出可下载的根证书(否则登录页的根证书入口无文件可给)。
func ensureTLSAssets(c tlsConfig) (bool, string) {
	if !c.Enabled {
		return false, "未启用"
	}
	certPath := resolveCertPath(c.effectiveCert())
	keyPath := resolveCertPath(c.effectiveKey())
	if c.userSpecified() {
		for _, p := range []string{certPath, keyPath} {
			if !fileExists(p) {
				return false, "指定的证书文件不存在: " + p
			}
		}
		return true, "用户指定证书"
	}
	// 默认路径: 固定根 CA(证书+私钥) + 服务器私钥; 齐全则复用, 缺失则签发。
	// 服务器证书之后按访问 IP 动态签发(GetCertificate), 换 IP 无需重签/重启。
	if err := ensureCertAssets(certPath, keyPath); err != nil {
		return false, "自动签发证书失败: " + err.Error()
	}
	// 根证书 data/cert/rootCA.crt 已随签发落盘; /static/rootCA.crt 由 handleStatic
	// 直接读 data/cert/ 提供下载(不再复制到 static/, 见 static_api.go)。
	return true, "自签证书就绪(固定根 CA, 按访问 IP 动态签发, 换 IP 无需重启)"
}

// fileExists 文件存在性判断(目录也算存在, 调用方按需再判类型)。
func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// certIsSelfSigned 判定指定路径的证书是否属"自签 / 本工具私有 CA"。
//
// 2026-09-29 修复: 此前判定靠 ensureTLSAssets 返回文案是否含"自签"两字 —— 但证书
// 已存在时(首次启动之后的每次重启)文案是"已有证书", 标志恒 false, 导致证书未受
// 信任时登录页"安装根证书"引导不再出现(实机复现)。正确口径是解析证书本身:
//   - issuer == subject → 自签叶子证书;
//   - issuer CN == "Yugsight Root CA" → 由本工具自动生成的私有 CA 签发的服务端
//     证书(generateCertPair 的产物)。
//
// 用户自带的正规 CA 证书两者都不命中 → false(不引导安装, 保持原语义)。
func certIsSelfSigned(certPath string) bool {
	data, err := os.ReadFile(resolveCertPath(certPath))
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if cert.Issuer.CommonName == "Yugsight Root CA" {
		return true
	}
	return cert.Subject.CommonName != "" && cert.Issuer.CommonName == cert.Subject.CommonName
}

// generateCertPair 签发一对自签证书: 根 CA(自签) + 服务端证书(由根 CA 签发)。
//
// 关键在 SAN(主题替代名): 服务端证书的浏览器校验按 SAN 而非 CN 匹配主机, 所以必须
// 把本机所有局域网 IP + 127.0.0.1 + localhost 都写进 SAN, 用户从哪个 IP 访问都能对上。
// 用 ECDSA P-256(比 RSA 小且快, 内网自签足够)。根 CA 有效期 10 年, 服务端约 2.5 年。
//
// 副作用: 在 data/cert/ 目录下写 rootCA.crt / rootCA.key / 服务端证书与私钥
// (2026-09-29 起 cert/ 归入 data/)。
func generateCertPair(certPath, keyPath string) error {
	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// 1) 根 CA
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Yugsight Root CA", Organization: []string{"Yugsight"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		return err
	}
	// CreateCertificate 的父证书参数要 *x509.Certificate, 把刚生成的根 CA DER 解析回对象
	caCert, err := x509.ParseCertificate(caDer)
	if err != nil {
		return err
	}
	// 2) 服务端证书(由根 CA 签发, SAN 覆盖本机全部 IP + localhost)
	srvPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	dnsNames, ipAddrs := certSANs()
	srvTmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Yugsight", Organization: []string{"Yugsight"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 5, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}
	srvDer, err := x509.CreateCertificate(rand.Reader, &srvTmpl, caCert, &srvPriv.PublicKey, caPriv)
	if err != nil {
		return err
	}
	// 3) 落盘: 服务端证书/私钥(生效路径) + 根证书(data/cert/ 目录, 供下载)
	srvKeyDER, err := x509.MarshalECPrivateKey(srvPriv)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDer})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer})
	if err := os.WriteFile(filepath.Join(dir, "rootCA.crt"), caPEM, 0o644); err != nil {
		return err
	}
	// 根 CA 私钥: 固定根 CA 的关键(2026-09-29 换 IP 热加载需求)—— 之后按访问 IP
	// 重签服务器证书都复用这把根 CA 密钥, 客户端只需装一次根 CA 即永久有效。
	caKeyDER, err := x509.MarshalECPrivateKey(caPriv)
	if err != nil {
		return err
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})
	if err := os.WriteFile(filepath.Join(dir, "rootCA.key"), caKeyPEM, 0o600); err != nil {
		return err
	}
	return nil
}

// certSANs 收集服务端证书 SAN 用: DNS=localhost+主机名, IP=127.0.0.1+全部局域网 IP。
// 局域网 IP 取 scanner.LocalIPs()(中心端实际绑 0.0.0.0, 用户可能从任一网卡 IP 访问)。
func certSANs() (dns []string, ips []net.IP) {
	dns = []string{"localhost"}
	if h, err := os.Hostname(); err == nil && h != "" && h != "localhost" {
		dns = append(dns, h)
	}
	ips = []net.IP{net.ParseIP("127.0.0.1")}
	for _, s := range scanner.LocalIPs() {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return
}

// ===== 运行时动态证书: 固定根 CA + 按访问 IP/域名即时签发(2026-09-29 换 IP 热加载) =====
//
// 背景: 中心端经常换 IP, 旧方案证书 SAN 写死"生成那一刻"的 IP, 换 IP 后浏览器报
// "名称无效", 且想重签就得删 data/cert(又换根 CA, 客户端要重装根证书)。现改为:
//   - 根 CA 固定: 首次生成后存 rootCA.crt + rootCA.key, 永不重新生成 → 客户端用
//     certtool 装一次根 CA, 之后换 IP 永远不用再装;
//   - 服务器证书即时签发: tls.Config.GetCertificate 回调按客户端实际访问的 IP/域名
//     (SNI)当场签发并缓存 —— 换 IP 零操作, 无需重启/重建;
//   - 访问白名单(https 节, 见 https_api.go): 空 = 不限制; 非空 = 只放行列表内 IP/CIDR,
//     白名单外的来源在 TLS 握手阶段即被拒(不发证书)。
// 白名单与 IP 变化都实时读 settings.json(loadHttpsConfig 每次实时读 section),
// 保存白名单 / 换 IP 都立即生效, 无需重启。

var (
	// 固定的根 CA(证书 + 私钥), 启动时加载, 之后所有服务器证书都由它签发。
	rootCACert *x509.Certificate
	rootCAPriv *ecdsa.PrivateKey
	// 固定的服务器私钥: 所有按 IP/域名即时签发的证书共用这一把私钥(同一把私钥签不同
	// SAN 的证书), 客户端验证时"公钥匹配 + SAN 匹配 + 根 CA 信任"都成立。
	serverPriv *ecdsa.PrivateKey
	// 按 host(IP 或域名)缓存已签发的证书, 避免每次握手重复签发。
	certCache sync.Map // string(host) -> *tls.Certificate
	// certAssetsMu 保护"加载/生成证书资产"的并发(启动时或首个握手触发)。
	certAssetsMu sync.Mutex
)

// ensureCertAssets 确保"固定根 CA(证书+私钥) + 服务器私钥"就绪, 返回错误。
// 三者齐全 → 直接复用(根 CA 永不重新生成); 任一缺失(首次, 或旧版本未存 rootCA.key)
// → 完整重新签发(会产出新根 CA, 需客户端重装一次 —— 仅旧版本升级的一次性代价)。
func ensureCertAssets(certPath, keyPath string) error {
	dir := filepath.Dir(certPath)
	rootCrt := filepath.Join(dir, "rootCA.crt")
	rootKey := filepath.Join(dir, "rootCA.key")
	if fileExists(rootCrt) && fileExists(rootKey) && fileExists(keyPath) {
		return nil // 资产齐全, 复用(根 CA 固定)
	}
	return generateCertPair(certPath, keyPath)
}

// loadCertAssets 加载固定根 CA + 服务器私钥到全局变量(幂等, 已加载则跳过)。
// GetCertificate 回调依赖这两个全局, 故 startTLSServer 启动时先调本函数。
func loadCertAssets(certPath, keyPath string) error {
	certAssetsMu.Lock()
	defer certAssetsMu.Unlock()
	if rootCACert != nil && rootCAPriv != nil && serverPriv != nil {
		return nil // 已加载
	}
	dir := filepath.Dir(certPath)
	caCrtPEM, err := os.ReadFile(filepath.Join(dir, "rootCA.crt"))
	if err != nil {
		return fmt.Errorf("读根 CA 证书失败: %w", err)
	}
	caCrtBlock, _ := pem.Decode(caCrtPEM)
	if caCrtBlock == nil {
		return errors.New("根 CA 证书解析失败")
	}
	rootCACert, err = x509.ParseCertificate(caCrtBlock.Bytes)
	if err != nil {
		return fmt.Errorf("根 CA 证书无效: %w", err)
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(dir, "rootCA.key"))
	if err != nil {
		return fmt.Errorf("读根 CA 私钥失败: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return errors.New("根 CA 私钥解析失败")
	}
	rootCAPriv, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("根 CA 私钥无效: %w", err)
	}
	srvKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("读服务器私钥失败: %w", err)
	}
	srvKeyBlock, _ := pem.Decode(srvKeyPEM)
	if srvKeyBlock == nil {
		return errors.New("服务器私钥解析失败")
	}
	serverPriv, err = x509.ParseECPrivateKey(srvKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("服务器私钥无效: %w", err)
	}
	return nil
}

// issueCertForHost 用固定根 CA + 固定服务器私钥, 即时签发一张覆盖 host(IP 或域名)
// 的服务器证书。host 为 IP 时写进 SAN 的 IPAddresses, 为域名时写进 DNSNames;
// localhost/127.0.0.1 始终包含(本地访问兜底)。
func issueCertForHost(host string) (*tls.Certificate, error) {
	dns := []string{"localhost"}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip, net.ParseIP("127.0.0.1"))
	} else {
		dns = append(dns, host)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Yugsight", Organization: []string{"Yugsight"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 5, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, rootCACert, &serverPriv.PublicKey, rootCAPriv)
	if err != nil {
		return nil, fmt.Errorf("签发 %s 证书失败: %w", host, err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: serverPriv}, nil
}

// localIPKey 返回本机所有局域网 IP 的排序拼接串(做缓存 key)。
// 换 IP 后本机 IP 集合变化 → key 变化 → 触发重新签发(换 IP 热加载的感知点)。
func localIPKey() string {
	var parts []string
	for _, s := range scanner.LocalIPs() {
		if ip := net.ParseIP(s); ip != nil {
			parts = append(parts, ip.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// issueCertForAllLocal 签发覆盖"localhost + 主机名 + 127.0.0.1 + 全部本机 IP"的服务器证书。
// 浏览器用 IP 访问时 SNI 为空, 服务器无法得知具体访问哪个 IP, 故签一张覆盖所有本机 IP 的
// 证书, 保证从任一本机 IP 访问都能匹配(SAN 含全部 IP)。换 IP 后由 localIPKey 变化触发重签。
func issueCertForAllLocal() (*tls.Certificate, error) {
	dns, ips := certSANs()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Yugsight", Organization: []string{"Yugsight"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 5, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, rootCACert, &serverPriv.PublicKey, rootCAPriv)
	if err != nil {
		return nil, fmt.Errorf("签发本机全 IP 证书失败: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: serverPriv}, nil
}

// getCertForHello 是 tls.Config.GetCertificate 回调: 按客户端实际访问的 host
// (SNI, IP 访问时为 IP 字符串)即时签发并返回对应证书。
//
// 返回 (nil, err) 会中断 TLS 握手 → 客户端表现为"连接失败", 即"拒绝访问"。
// 白名单(https 节)在此生效: 白名单启用且来源 IP 不在列表 → 直接拒绝(不发证书)。
func getCertForHello(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// 白名单检查(基于客户端来源 IP, 即 RemoteAddr): 限制哪些来源可访问中心端。
	// 不依赖 SNI —— 浏览器用 IP 访问时 SNI 为空, 只有 RemoteAddr 能确定来源。
	if hi.Conn != nil {
		if ra := hi.Conn.RemoteAddr(); ra != nil {
			if hp, _, err := net.SplitHostPort(ra.String()); err == nil {
				if ip := net.ParseIP(hp); ip != nil {
					if !loadHttpsConfig().allowed(ip.String()) {
						logLine("HTTPS 白名单拒绝: 来源 " + ip.String() + " 不在白名单内")
						return nil, errors.New("访问来源 IP 未在白名单内")
					}
				}
			}
		}
	}

	// 确定 host(SNI)。浏览器用 IP 访问时不发 SNI(SNI 只对域名有意义) → host 为空。
	host := hi.ServerName
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if host == "" {
		// IP 访问(SNI 空): 签发一张覆盖"本机所有 IP + 127.0.0.1 + localhost + 主机名"的证书,
		// 这样无论用户从哪个本机 IP 访问都匹配。用"本机 IP 集合"做缓存 key —— 换 IP 后集合
		// 变化 → key 变化 → 自动重新签发(含新 IP), 实现换 IP 热加载。
		cacheKey := "local:" + localIPKey()
		if v, ok := certCache.Load(cacheKey); ok {
			return v.(*tls.Certificate), nil
		}
		cert, err := issueCertForAllLocal()
		if err != nil {
			return nil, err
		}
		certCache.Store(cacheKey, cert)
		return cert, nil
	}

	// SNI 是域名或 IP: 按 SNI 签发对应证书。
	if v, ok := certCache.Load(host); ok {
		return v.(*tls.Certificate), nil
	}
	cert, err := issueCertForHost(host)
	if err != nil {
		return nil, err
	}
	certCache.Store(host, cert)
	return cert, nil
}
