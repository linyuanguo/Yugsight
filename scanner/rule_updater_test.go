package scanner

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ===== 测试辅助 =====
//
// 说明: 沙箱环境拦截环回 TCP, 无法用 httptest 起真实 HTTP 服务器。
// 这里通过包级测试钩子(upFetchFn / upDownloadFn)把网络层替换为内存实现,
// 下载器其余逻辑(并发 3、暂存、断点续传偏移、sha256 校验、回滚、原子替换、
// 热加载、进度回调)全部走真实代码路径。

// gzBytes 压缩字节串(gzip)
func gzBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// mustJSON 序列化测试数据
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeNet 内存网络: 全 URL -> 内容 映射, 下载支持断点续传(已有 .part 时只补余量并计数)
type fakeNet struct {
	files     map[string][]byte
	rangeReqs int32
}

// fetch 模拟清单/文件 GET
func (fn *fakeNet) fetch(raw string, _ time.Duration) ([]byte, error) {
	b, ok := fn.files[raw]
	if !ok {
		return nil, fmt.Errorf("404: %s", raw)
	}
	return b, nil
}

// download 模拟下载到 dest.part(按 chunk 写入并上报速度)
func (fn *fakeNet) download(u, dest string, f RemoteFile, meter *speedMeter) error {
	data, ok := fn.files[u]
	if !ok {
		return fmt.Errorf("404: %s", u)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	part := dest + ".part"
	var off int64
	if st, err := os.Stat(part); err == nil {
		off = st.Size() // 模拟 Range 续传: 只补余量
		atomic.AddInt32(&fn.rangeReqs, 1)
	}
	fw, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	buf := data[off:]
	for len(buf) > 0 {
		n := len(buf)
		if n > chunkSize {
			n = chunkSize
		}
		if _, werr := fw.Write(buf[:n]); werr != nil {
			fw.Close()
			return werr
		}
		meter.add(n)
		buf = buf[n:]
	}
	return fw.Close()
}

// withFakeNet 安装内存网络钩子, 测试结束恢复
func withFakeNet(t *testing.T, fn *fakeNet) {
	t.Helper()
	oldF, oldD := upFetchFn, upDownloadFn
	upFetchFn, upDownloadFn = fn.fetch, fn.download
	t.Cleanup(func() {
		upFetchFn, upDownloadFn = oldF, oldD
	})
}

// withUpdater 设置下载源(测试前保存, 结束后恢复), 并清空代理
func withUpdater(t *testing.T, sources ...string) {
	t.Helper()
	old := UpdaterConfig()
	SetDownloadSource(sources...)
	SetProxy("")
	t.Cleanup(func() {
		SetDownloadSource(old.Sources...)
		SetProxy(old.Proxy)
	})
}

// withDirs 为 rules/ 与 cpe/ 目录设置临时目录, 结束后恢复并重置缓存
func withDirs(t *testing.T) (rulesDir, cpeDir string) {
	t.Helper()
	rulesDir, cpeDir = t.TempDir(), t.TempDir()
	oldR, oldC := rulesExternalDir, cpeExternalDir
	rulesExternalDir, cpeExternalDir = rulesDir, cpeDir
	t.Cleanup(func() {
		rulesExternalDir, cpeExternalDir = oldR, oldC
		rulesMu.Lock()
		extLoaded = false
		rulesMu.Unlock()
		LoadCPEDictionary()
	})
	return rulesDir, cpeDir
}

// ===== 配置 =====

// TestUpdaterConfig 统一配置: 多源归一化 / 代理 / 周期 / 自动更新开关(默认关)
func TestUpdaterConfig(t *testing.T) {
	old := UpdaterConfig()
	t.Cleanup(func() {
		SetDownloadSource(old.Sources...)
		SetProxy(old.Proxy)
		SetUpdateInterval(old.Interval)
		SetAutoUpdate(old.AutoUpdate)
	})

	SetDownloadSource("https://a.example/rules", " https://b.example/rules/ ", "")
	SetProxy("http://127.0.0.1:7890")
	SetUpdateInterval(time.Hour)
	SetAutoUpdate(true)

	c := UpdaterConfig()
	if len(c.Sources) != 2 || c.Sources[0] != "https://a.example/rules/" || c.Sources[1] != "https://b.example/rules/" {
		t.Errorf("多源归一化错误: %v", c.Sources)
	}
	if c.Proxy != "http://127.0.0.1:7890" || c.Interval != time.Hour || !c.AutoUpdate {
		t.Errorf("配置错误: %+v", c)
	}
}

// TestSetProxyTransport 代理配置真正作用于 HTTP 客户端传输层
func TestSetProxyTransport(t *testing.T) {
	old := UpdaterConfig()
	t.Cleanup(func() {
		SetProxy(old.Proxy)
	})
	SetProxy("http://127.0.0.1:7890")
	c := newHTTPClient(5 * time.Second)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport 应为 *http.Transport")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/x", nil)
	pu, err := tr.Proxy(req)
	if err != nil || pu.String() != "http://127.0.0.1:7890" {
		t.Errorf("代理未生效: %v %v", pu, err)
	}
	// 空代理 = 系统代理(ProxyFromEnvironment)
	SetProxy("")
	c2 := newHTTPClient(5 * time.Second)
	tr2, _ := c2.Transport.(*http.Transport)
	if tr2 == nil || tr2.Proxy == nil {
		t.Error("清空代理后应回落到系统代理")
	}
}

// TestUpdateNoSource 未配置下载源: 全部接口返回错误, 不 panic 不动文件
func TestUpdateNoSource(t *testing.T) {
	withUpdater(t)
	if _, err := CheckRuleUpdate(); err == nil {
		t.Error("无下载源应返回错误")
	}
	if _, err := CheckCPEUpdate(); err == nil {
		t.Error("无下载源应返回错误")
	}
	if _, err := DownloadRuleUpdate(nil); err == nil {
		t.Error("无下载源应返回错误")
	}
	if _, err := DownloadCPEUpdate(nil); err == nil {
		t.Error("无下载源应返回错误")
	}
}

// ===== 规则库更新 =====

// TestRuleUpdateCheckAndDownload 增量检查 + 下载 + 只收 http/ + 进度 + 热加载
func TestRuleUpdateCheckAndDownload(t *testing.T) {
	rulesDir, _ := withDirs(t)
	tpl := []byte("id: upd-1\ninfo:\n  name: u\n  severity: high\n  tags: nginx\nrequest:\n  method: GET\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n")
	other := []byte("id: skip-me\ninfo:\n  name: s\n  severity: low\nheadless:\n  steps: []\n")
	base := "https://cdn.example/rules/"
	fn := &fakeNet{files: map[string][]byte{
		base + "rules-manifest.json": mustJSON(t, RemoteManifest{
			Commit: "c2", Name: "rules",
			Files: []RemoteFile{
				{Path: "http/upd-1.yaml", Size: int64(len(tpl)), SHA256: sha256Hex(tpl)},
				{Path: "network/skip-me.yaml", Size: int64(len(other)), SHA256: sha256Hex(other)},
			},
		}),
		base + "http/upd-1.yaml":      tpl,
		base + "network/skip-me.yaml": other,
	}}
	withFakeNet(t, fn)
	withUpdater(t, base)

	// 增量检查: 无本地 commit -> 有更新
	c, err := CheckRuleUpdate()
	if err != nil || !c.Available || c.RemoteCommit != "c2" || c.Files != 2 || c.Source != base {
		t.Fatalf("更新检查错误: %+v %v", c, err)
	}

	var last UpdateProgress
	nProg := 0
	res, err := DownloadRuleUpdate(func(p UpdateProgress) {
		last = p
		nProg++
	})
	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}
	if !res.Updated || res.Commit != "c2" || res.Files != 1 || res.Skipped != 1 {
		t.Errorf("结果错误(应只下载 http/ 1 条, 跳过 1 条): %+v", res)
	}
	if nProg == 0 || last.Status != "done" || last.Total != 1 || last.Done != 1 {
		t.Errorf("进度回调错误: %+v (n=%d)", last, nProg)
	}

	// 热加载: RefreshRules 已生效
	r, ok := GetRuleByID("upd-1")
	if !ok || r.Info == nil || r.Info.Severity != "high" {
		t.Errorf("热加载后应查到 upd-1: ok=%v r=%+v", ok, r)
	}
	// 非 http 目录文件不应落盘
	if _, err := os.Stat(filepath.Join(rulesDir, "network/skip-me.yaml")); !os.IsNotExist(err) {
		t.Error("非 http/ 目录文件不应下载")
	}
	// checksum 登记 + 更新后无增量
	ck, _ := os.ReadFile(filepath.Join(rulesDir, "checksum.sha256"))
	if !strings.Contains(string(ck), "http/upd-1.yaml") {
		t.Errorf("checksum.sha256 应登记新文件: %s", ck)
	}
	c2, err := CheckRuleUpdate()
	if err != nil || c2.Available {
		t.Errorf("更新后应无增量: %+v %v", c2, err)
	}
}

// TestRuleUpdateRollback 校验失败: 回滚(暂存清除, 正式目录无残留, 旧规则不受影响)
func TestRuleUpdateRollback(t *testing.T) {
	rulesDir, _ := withDirs(t)
	good := []byte("id: rb-1\ninfo:\n  name: r\n  severity: high\nrequest:\n  method: GET\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n")
	base := "https://cdn.example/rules/"
	fn := &fakeNet{files: map[string][]byte{
		base + "rules-manifest.json": mustJSON(t, RemoteManifest{
			Commit: "c9", Name: "rules",
			Files: []RemoteFile{{Path: "http/rb-1.yaml", Size: int64(len(good)), SHA256: strings.Repeat("0", 64)}}, // 错误哈希
		}),
		base + "http/rb-1.yaml": good,
	}}
	withFakeNet(t, fn)
	withUpdater(t, base)

	if _, err := DownloadRuleUpdate(nil); err == nil {
		t.Fatal("校验和不符应返回错误")
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "http/rb-1.yaml")); !os.IsNotExist(err) {
		t.Error("回滚后正式文件不应存在")
	}
	if _, err := os.Stat(filepath.Join(rulesDir, ".staging")); !os.IsNotExist(err) {
		t.Error("回滚后暂存目录应清除")
	}
	if _, ok := GetRuleByID("rb-1"); ok {
		t.Error("回滚后不应出现新规则")
	}
}

// TestRuleUpdateResume 断点续传: 已有 .part 时只补余量, 最终内容完整
func TestRuleUpdateResume(t *testing.T) {
	rulesDir, _ := withDirs(t)
	content := bytes.Repeat([]byte("x"), 200*1024) // 200KB, 跨多个 32KB chunk
	base := "https://cdn.example/rules/"
	fn := &fakeNet{files: map[string][]byte{
		base + "rules-manifest.json": mustJSON(t, RemoteManifest{
			Commit: "cr", Name: "rules",
			Files: []RemoteFile{{Path: "http/big.yaml", Size: int64(len(content)), SHA256: sha256Hex(content)}},
		}),
		base + "http/big.yaml": content,
	}}
	withFakeNet(t, fn)
	withUpdater(t, base)

	// 模拟上次中断留下的部分下载
	partDir := filepath.Join(rulesDir, ".staging/http")
	if err := os.MkdirAll(partDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partDir, "big.yaml.part"), content[:100*1024], 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := DownloadRuleUpdate(nil)
	if err != nil {
		t.Fatalf("断点续传失败: %v", err)
	}
	if !res.Updated {
		t.Error("应完成更新")
	}
	if atomic.LoadInt32(&fn.rangeReqs) == 0 {
		t.Error("应发生续传(只补余量)")
	}
	data, _ := os.ReadFile(filepath.Join(rulesDir, "http/big.yaml"))
	if len(data) != len(content) || !bytes.Equal(data, content) {
		t.Error("续传后文件内容不完整")
	}
}

// ===== CPE 库更新(gzip) =====

// TestCPEUpdateDownload 增量检查 + gzip 下载 + 解压写入 + 热加载
func TestCPEUpdateDownload(t *testing.T) {
	_, cpeDir := withDirs(t)
	full := []byte(`{"version":"9.9","products":[{"cpe":"cpe:2.3:a:z:z","vendor":"z","product":"zprod","cves":[{"cve":"CVE-2097-1","title":"t","cvss":9.1,"constraints":["< 3.0"]}]}]}`)
	fullGz := gzBytes(t, full)
	base := "https://cdn.example/cpe/"
	fn := &fakeNet{files: map[string][]byte{
		base + "cpe-manifest.json": mustJSON(t, RemoteManifest{
			Commit: "cc2", Name: "cpe",
			Files: []RemoteFile{{Path: "cpe_full.json.gz", Size: int64(len(fullGz)), SHA256: sha256Hex(fullGz)}},
		}),
		base + "cpe_full.json.gz": fullGz,
	}}
	withFakeNet(t, fn)
	withUpdater(t, base)

	c, err := CheckCPEUpdate()
	if err != nil || !c.Available || c.RemoteCommit != "cc2" {
		t.Fatalf("CPE 更新检查错误: %+v %v", c, err)
	}
	res, err := DownloadCPEUpdate(nil)
	if err != nil || !res.Updated || res.Files != 1 {
		t.Fatalf("CPE 更新失败: %+v %v", res, err)
	}

	// 解压后写入正式目录(无 .gz 残留)
	data, err := os.ReadFile(filepath.Join(cpeDir, "cpe_full.json"))
	if err != nil || !bytes.Equal(data, full) {
		t.Errorf("cpe_full.json 应为解压后内容: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cpeDir, "cpe_full.json.gz")); !os.IsNotExist(err) {
		t.Error("压缩态文件不应保留在 cpe/ 目录")
	}
	// 热加载: RefreshCPE 后新产品可匹配
	ms := MatchCPEEngine("zprod", "1.0")
	if len(ms) != 1 || len(ms[0].CVEs) != 1 || ms[0].CVEs[0].ID != "CVE-2097-1" {
		t.Errorf("新增 CPE 产品应可匹配: %+v", ms)
	}
	// 更新后无增量
	if c2, err := CheckCPEUpdate(); err == nil && c2.Available {
		t.Error("更新后应无增量")
	}
}

// TestCPEUpdateBadGzip 非 gzip 文件: 校验通过但解压失败 -> 回滚, 不动现有库
func TestCPEUpdateBadGzip(t *testing.T) {
	_, cpeDir := withDirs(t)
	notGz := []byte("this is not gzip data")
	base := "https://cdn.example/cpe/"
	fn := &fakeNet{files: map[string][]byte{
		base + "cpe-manifest.json": mustJSON(t, RemoteManifest{
			Commit: "cb", Name: "cpe",
			Files: []RemoteFile{{Path: "cpe_bad.json.gz", Size: int64(len(notGz)), SHA256: sha256Hex(notGz)}},
		}),
		base + "cpe_bad.json.gz": notGz,
	}}
	withFakeNet(t, fn)
	withUpdater(t, base)

	if _, err := DownloadCPEUpdate(nil); err == nil {
		t.Fatal("非法 gzip 应返回错误")
	}
	if _, err := os.Stat(filepath.Join(cpeDir, "cpe_bad.json")); !os.IsNotExist(err) {
		t.Error("回滚后不应写入正式文件")
	}
	if _, err := os.Stat(filepath.Join(cpeDir, ".staging")); !os.IsNotExist(err) {
		t.Error("回滚后暂存目录应清除")
	}
}

// ===== 体积优化(gzip 嵌入) =====

// TestBuiltinGZRules 内置核心规则包: gzip 嵌入内存解压 + 体积统计
func TestBuiltinGZRules(t *testing.T) {
	rules, errs := LoadBuiltinRules()
	if len(rules) != 5 {
		t.Fatalf("内置 gzip 规则包应加载 5 条, got %d errs=%v", len(rules), errs)
	}
	for _, r := range rules {
		if !r.Builtin || r.SHA256 == "" {
			t.Errorf("内置规则字段不完整: %s", r.ID)
		}
	}
	st := BuiltinRulesSize()
	if st.Files != 5 || st.GzipBytes <= 0 || st.RawBytes <= st.GzipBytes {
		t.Errorf("体积统计错误: %+v", st)
	}
	if !st.InMemory {
		t.Error("应为内存解压(无临时文件)")
	}
	if st.CompressionPct <= 0 || st.CompressionPct >= 1 {
		t.Errorf("压缩率应落在 (0,1): %+v", st)
	}
}

// TestBuiltinGZCPE 内置精简 CPE 库: gzip 嵌入 + 匹配逻辑不受影响 + 体积统计
func TestBuiltinGZCPE(t *testing.T) {
	old := cpeExternalDir
	cpeExternalDir = t.TempDir()
	t.Cleanup(func() {
		cpeExternalDir = old
		LoadCPEDictionary()
	})

	n, errs := RefreshCPE()
	if n == 0 {
		t.Fatalf("gzip CPE 内置库应加载成功: %v", errs)
	}
	st := CPEBuiltinSize()
	if st.GzipBytes <= 0 || st.RawBytes <= st.GzipBytes || st.Products == 0 || !st.InMemory {
		t.Errorf("CPE 体积统计错误: %+v", st)
	}
	// 匹配逻辑与原始嵌入一致(内容同源)
	if got := MatchCPE("nginx", "1.17.2"); len(got) != 1 || len(got[0].CVEs) != 4 {
		t.Errorf("gzip 内置库不应改变匹配结果: %+v", got)
	}
	if got := MatchCPEEngine("Apache httpd", "2.4.49"); len(got) != 1 || len(got[0].CVEs) != 9 {
		t.Errorf("gzip 内置库不应改变匹配结果: %+v", got)
	}
}

// ===== 多源切换 =====

// TestMultiSourceFailover 第一个源不可用 -> 自动切换第二个源
func TestMultiSourceFailover(t *testing.T) {
	withDirs(t)
	tpl := []byte("id: ms-1\ninfo:\n  name: m\n  severity: low\nrequest:\n  method: GET\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n")
	// 源 A 只有清单但无文件(会 404); 源 B 完整
	fn := &fakeNet{files: map[string][]byte{
		"https://a.example/rules/rules-manifest.json": mustJSON(t, RemoteManifest{
			Commit: "cm", Name: "rules",
			Files: []RemoteFile{{Path: "http/ms-1.yaml", Size: int64(len(tpl)), SHA256: sha256Hex(tpl)}},
		}),
		"https://b.example/rules/cpe-manifest.json": mustJSON(t, RemoteManifest{Commit: "cm", Name: "cpe", Files: nil}),
	}}
	withFakeNet(t, fn)
	// 规则包: 源 A 清单可拉, 但文件 404 -> 下载失败; 这里验证检查阶段"清单可拉即命中源"
	withUpdater(t, "https://a.example/rules/", "https://b.example/rules/")
	c, err := CheckRuleUpdate()
	if err != nil || !c.Available || c.Source != "https://a.example/rules/" {
		t.Errorf("应命中源 A 的清单: %+v %v", c, err)
	}
	// CPE: 源 A 无清单 -> 切换源 B
	c2, err := CheckCPEUpdate()
	if err != nil || c2.Source != "https://b.example/rules/" {
		t.Errorf("源 A 无 CPE 清单应切换到源 B: %+v %v", c2, err)
	}
}
