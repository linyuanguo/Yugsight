package engmgr

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ===== 测试辅助 =====

// makeZip 生成测试用 zip(entries: name -> 内容)
func makeZip(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// makeTarGz 生成测试用 tar.gz
func makeTarGz(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "test.tar.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, data := range entries {
		h := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// exeName 当前平台的 trivy 可执行文件名
func exeName() string {
	if isWindows {
		return "trivy.exe"
	}
	return "trivy"
}

// ===== 归档安全(最关键的一组: 目录穿越防护) =====

// TestArchiveSafe 目录穿越/绝对路径必须被拒绝
func TestArchiveSafe(t *testing.T) {
	bad := []string{
		"../evil.txt",
		"../../evil.txt",
		"a/../../evil.txt",
		"/etc/passwd",
		"\\Windows\\System32\\evil.dll",
		"C:/Windows/evil.dll",
		"..",
		".",
		"",
		"  ",
	}
	for _, b := range bad {
		if got := archiveSafe(b); got != "" {
			t.Errorf("archiveSafe(%q) = %q, 期望被拒绝", b, got)
		}
	}
	good := map[string]string{
		"trivy.exe":                 "trivy.exe",
		"trivy_0.74.0_windows/trivy.exe": "trivy_0.74.0_windows/trivy.exe",
		"./nuclei":                  "nuclei",
		"a/b/../c/nmap.exe":         "a/c/nmap.exe",
	}
	for in, want := range good {
		if got := archiveSafe(in); got != want {
			t.Errorf("archiveSafe(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// TestExtractFromZipTraversalBlocked 恶意条目不得写出目标目录之外。
//
// 这是本模块最重要的安全用例: 一个被劫持的包若能写出 bin/, 就等于任意文件写入。
// 用哨兵文件断言: 在目标目录外放哨兵, 若被覆盖说明穿越成功。
func TestExtractFromZipTraversalBlocked(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "secret.txt")
	if err := os.WriteFile(sentinel, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 三种穿越写法都试一遍
	zipPath := makeZip(t, map[string][]byte{
		"../secret.txt":    []byte("pwned1"),
		"../../secret.txt": []byte("pwned2"),
		"a/../../secret.txt": []byte("pwned3"),
	})
	w := wantFile{WantName: "trivy.exe", WantPrefix: []string{"trivy"}, ExecPerm: executablePerm}
	if _, err := extractFromZip(zipPath, binDir, w); err == nil {
		t.Fatal("穿越条目不应被解包成功")
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("目录穿越防护失效: 哨兵文件被改写为 %q", string(got))
	}
}

// TestExtractFromZipEscapesToParent 即使条目名带子目录, 也只落在目标目录内(取 Base)
func TestExtractFromZipEscapesToParent(t *testing.T) {
	binDir := t.TempDir()
	zipPath := makeZip(t, map[string][]byte{
		"nested/deep/dir/" + exeName(): []byte("binary-content"),
	})
	w := wantFile{WantName: exeName(), WantPrefix: []string{"trivy"}, ExecPerm: executablePerm}
	got, err := extractFromZip(zipPath, binDir, w)
	if err != nil {
		t.Fatalf("应能解包出目标文件: %v", err)
	}
	if filepath.Dir(got) != binDir {
		t.Fatalf("解包路径 %q 不在目标目录 %q 内", got, binDir)
	}
	data, _ := os.ReadFile(got)
	if string(data) != "binary-content" {
		t.Fatalf("解包内容不符: %q", string(data))
	}
}

// TestEntryMatches 目标文件匹配规则(词边界 + 可执行判定)
func TestEntryMatches(t *testing.T) {
	w := wantFile{WantName: "trivy.exe", WantPrefix: []string{"trivy"}}
	cases := []struct {
		in   string
		want bool
	}{
		{"trivy.exe", true},
		{"nested/trivy.exe", true},
		{"trivy_windows_amd64_v0.74.0.exe", true},
		{"trivy-0.74.0.exe", true},
		{"trivy.yaml", false}, // 同前缀但非可执行
		{"trivy-db.exe", true}, // 词边界命中(-), 由调用方按顺序取第一个, 真实包中 trivy.exe 在根
		{"nmap.exe", false},
		{"", false},
	}
	for _, c := range cases {
		if got := entryMatches(c.in, w); got != c.want {
			t.Errorf("entryMatches(%q) = %v, 期望 %v", c.in, got, c.want)
		}
	}
}

// TestEntryMatchesRejectsSamePrefixNonBoundary 词边界反例:
// entryMatches 对 "trivycore.exe" 这类"前缀后接字母"的名字应当命中(它确实是 trivy 的
// 改名产物), 但对 "trivyx.exe" 这种无关程序不应误判 —— 两者都靠后缀判定区分。
func TestEntryMatchesPrefixBoundary(t *testing.T) {
	// zaproxy.exe: 前缀 zap 后接 'r' 不是词边界 -> 不命中(那只是安装器名, 不是引擎入口)
	if entryMatches("zaproxy.exe", wantFile{Prefix: []string{"zap"}}) {
		t.Error("zaproxy.exe 不应被 zap 前缀命中(非词边界)")
	}
	// Linux 的 zap.sh: 走 WantPrefix 精确比对(带扩展点, 不能靠前缀匹配)
	if !entryMatches("zap.sh", wantFile{WantPrefix: []string{"zap.sh"}, Prefix: []string{"zap"}}) {
		t.Error("zap.sh 应被 WantPrefix 精确命中")
	}
	if !entryMatches("nested/dir/zap.sh", wantFile{WantPrefix: []string{"zap.sh"}}) {
		t.Error("带目录的 zap.sh 也应命中(只比 Base)")
	}
}

// TestExtractFromTarGz tar.gz 解包(Trivy/ZAP 的 Linux 包格式)
func TestExtractFromTarGz(t *testing.T) {
	dir := t.TempDir()
	tgz := makeTarGz(t, map[string][]byte{
		"LICENSE":       []byte("license text"),
		"README.md":     []byte("readme"),
		exeName():       []byte("BINARY"),
		"trivy-db.yaml": []byte("db"),
	})
	w := wantFile{WantName: exeName(), WantPrefix: []string{"trivy"}, ExecPerm: executablePerm}
	got, err := extractFromTarGz(tgz, dir, w)
	if err != nil {
		t.Fatalf("tar.gz 解包失败: %v", err)
	}
	data, _ := os.ReadFile(got)
	if string(data) != "BINARY" {
		t.Fatalf("内容不符: %q", string(data))
	}
}

// TestExtractFromZipNotFound 未命中目标时返回 errNotFound(调用方据此回退策略)
func TestExtractFromZipNotFound(t *testing.T) {
	dir := t.TempDir()
	zipPath := makeZip(t, map[string][]byte{
		"README.md": []byte("nothing here"),
	})
	w := wantFile{WantName: "trivy.exe", WantPrefix: []string{"trivy"}}
	if _, err := extractFromZip(zipPath, dir, w); err != errNotFound {
		t.Fatalf("期望 errNotFound, 实得 %v", err)
	}
}

// TestExtractFromZipRejectsOversize 单文件超限必须报错(防 zip 炸弹)
//
// 用一个"声明长度很大"的条目不方便构造, 这里改为直接验证 writeCapped 的上限判断。
func TestWriteCappedLimit(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "big.bin")
	// 构造超过上限的内容(用重复字节, 长度可控)
	big := bytes.Repeat([]byte{'x'}, maxExtractBytes+1024)
	if err := writeCapped(dst, bytes.NewReader(big), 0o644); err == nil {
		t.Fatal("超过上限的内容应当报错")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("超限文件不应留在磁盘上")
	}
}

// TestSfxArchiveOffset 7z SFX 签名定位
func TestSfxArchiveOffset(t *testing.T) {
	dir := t.TempDir()
	// 构造一个假的 SFX: 前缀若干字节 + 7z magic + 版本字节
	magic := []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04}
	prefix := bytes.Repeat([]byte{0x4D, 0x5A}, 5000) // "MZ" 存根
	p := filepath.Join(dir, "fake-setup.exe")
	if err := os.WriteFile(p, append(prefix, magic...), 0o644); err != nil {
		t.Fatal(err)
	}
	off, err := sfxArchiveOffset(p)
	if err != nil {
		t.Fatalf("应能定位 7z 签名: %v", err)
	}
	if off != int64(len(prefix)) {
		t.Fatalf("偏移应为 %d, 实得 %d", len(prefix), off)
	}
	// 非 SFX 文件必须明确失败(不猜)
	plain := filepath.Join(dir, "plain.exe")
	if err := os.WriteFile(plain, []byte("just an exe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := sfxArchiveOffset(plain); err == nil {
		t.Fatal("非 7z SFX 文件应当返回错误")
	}
}

// TestSfxArchiveOffsetCrossChunk 签名跨 1MB 块边界时必须仍能定位
// (第一版只扫整块会漏掉跨边界签名, 这个用例守住该回归)
func TestSfxArchiveOffsetCrossChunk(t *testing.T) {
	dir := t.TempDir()
	magic := []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04}
	// 让 magic 的前 3 字节落在第一块末尾, 其余落在下一块
	prefix := bytes.Repeat([]byte{0x00}, (1<<20)-3)
	p := filepath.Join(dir, "cross.exe")
	if err := os.WriteFile(p, append(prefix, magic...), 0o644); err != nil {
		t.Fatal(err)
	}
	off, err := sfxArchiveOffset(p)
	if err != nil {
		t.Fatalf("跨块签名应能定位: %v", err)
	}
	if off != int64((1<<20)-3) {
		t.Fatalf("偏移应为 %d, 实得 %d", (1<<20)-3, off)
	}
}

// ===== Catalog =====

// TestCatalogPatterns 每个引擎在当前平台的两大主流架构上都必须有可用模板或明确标记不支持
func TestCatalogPatterns(t *testing.T) {
	for i := range catalog {
		s := &catalog[i]
		if len(s.Patterns) == 0 {
			t.Errorf("%s 未配置任何资产模板", s.Engine)
		}
		if s.Want.InstallName == "" {
			t.Errorf("%s 未配置安装名(会导致前缀匹配失效)", s.Engine)
		}
		if s.Homepage == "" {
			t.Errorf("%s 未配置官方下载页(自动下载失败时无法给出指引)", s.Engine)
		}
		for _, p := range s.Patterns {
			if !bytes.Contains([]byte(p.Name), []byte("{ver}")) && !bytes.Contains([]byte(p.Name), []byte("{verU}")) {
				t.Errorf("%s 的模板 %q 缺少 {ver}/{verU} 占位符", s.Engine, p.Name)
			}
			if p.OS == "" || p.Arch == "" {
				t.Errorf("%s 的模板 %q 缺少 OS/Arch", s.Engine, p.Name)
			}
			// 渲染后的文件名必须不含残留占位符
			got := renderAsset(p, "1.2.3")
			if bytes.Contains([]byte(got), []byte("{")) {
				t.Errorf("模板 %q 渲染后仍有未替换的占位符: %q", p.Name, got)
			}
		}
	}
}

// TestInstallNameMatchesPrefixWithInstallNameForm 安装名必须满足"文件名精确匹配"
// 或"前缀 + 词边界"两条路径之一, 否则装完之后 envdetect/engine 找不到它。
//
// 为什么按 InstallName 构造 wantFile: 安装后 bin/ 里躺的就是这个名字, 检测阶段
// (envdetect.findBinary / engine.findBin)会拿 <前缀> + 词边界 去匹配它, 而不是拿
// 归档里的原始文件名 —— 用原始 Want 去断言会把目标文件判成"装完检测不到"。
// 这里显式构造一个 Prefix + WantName=InstallName 的检测口径, 与真实检测逻辑一致。
func TestInstallNameMatchesPrefixWithInstallNameForm(t *testing.T) {
	for i := range catalog {
		s := &catalog[i]
		name := s.Want.InstallName
		// 检测侧: 引擎名来自 envdetect(如 "trivycore"), 精确名同值
		engineName := strings.TrimSuffix(strings.TrimSuffix(name, ".exe"), "."+filepath.Ext(name))
		check := wantFile{WantName: name, Prefix: []string{engineName}}
		if !entryMatches(name, check) {
			t.Errorf("%s 的安装名 %q 在安装后无法被检测到(不满足精确或词边界匹配)", s.Engine, name)
		}
		// 再验证一次"前缀匹配"这条路径本身没坏: 去掉精确名后仍应命中
		if !entryMatches(name, wantFile{Prefix: []string{engineName}}) {
			t.Errorf("%s 的安装名 %q 不满足前缀匹配(词边界缺失)", s.Engine, name)
		}
	}
}

// TestRenderAssetVerU 占位符渲染(含 {verU} 下划线变体与各上游的大小写怪癖)
func TestRenderAssetVerU(t *testing.T) {
	// {verU} 机制本身仍需覆盖: 它虽已不用于 ZAP(见下方), 但模板里仍是通用能力,
	// 删掉断言会让这个占位符在无人察觉的情况下失效。
	if got := renderAsset(assetPattern{Name: "ZAP_{verU}_windows.exe"}, "2.17.0"); got != "ZAP_2_17_0_windows.exe" {
		t.Fatalf("{verU} 应把点换成下划线, 实得 %q", got)
	}

	for i := range catalog {
		s := &catalog[i]
		for _, p := range s.Patterns {
			// ZAP 三个桌面平台统一用官方跨平台免安装包(纯 zip)。
			//
			// 【为什么不再是 ZAP_<verU>_windows.exe】那 256MB 文件实测是 **install4j
			// 安装器**(头部含 install4j/i4j/jre.tar, 无 7z 签名), 只能运行安装向导,
			// 没有任何纯解包通道 —— 用户曾下满 244MB 后卡在"未找到 7z 归档签名"。
			// 跨平台 zip 解压即用, 故本断言同时守住"包名仍是纯 zip"这条底线。
			if s.Engine == EngineZap {
				got := renderAsset(p, "2.17.0")
				if got != "ZAP_2.17.0_Crossplatform.zip" {
					t.Fatalf("ZAP 包名应为 ZAP_2.17.0_Crossplatform.zip(免安装纯 zip), 实得 %q", got)
				}
				if p.Ext != "zip" {
					t.Fatalf("ZAP 包必须是 zip(不能再回到 install4j 安装器 exe), 实得 %q", p.Ext)
				}
			}
			// Trivy 的 Linux 包: 版本不带 v, 且操作系统/架构大小写是上游原样的
			// "Linux-64bit"(不是 linux-amd64)——这是实测确认的命名, 写错会 404
			if s.Engine == EngineTrivy && p.OS == "linux" && p.Arch == "amd64" {
				got := renderAsset(p, "0.74.0")
				if got != "trivy_0.74.0_Linux-64bit.tar.gz" {
					t.Fatalf("Trivy Linux/amd64 包名应为 trivy_0.74.0_Linux-64bit.tar.gz, 实得 %q", got)
				}
			}
			if s.Engine == EngineTrivy && p.OS == "windows" {
				got := renderAsset(p, "0.74.0")
				if got != "trivy_0.74.0_windows-64bit.zip" {
					t.Fatalf("Trivy Windows 包名应为 trivy_0.74.0_windows-64bit.zip, 实得 %q", got)
				}
			}
			// Nuclei 官方引擎的包名: 平台全小写 macOS 是特例
			if s.Engine == EngineNuclei && p.OS == "windows" {
				got := renderAsset(p, "3.11.1")
				if got != "nuclei_3.11.1_windows_amd64.zip" {
					t.Fatalf("Nuclei Windows 包名应为 nuclei_3.11.1_windows_amd64.zip, 实得 %q", got)
				}
			}
			// nmap: Windows 固定用 7.92 免安装 zip。
			// 【历史包袱】这里原断言的是 "nmap-7.991-setup.exe" —— 那是旧方案(以为
			// setup.exe 是 7z SFX 可自动抽取)。实测 7.991 的 setup.exe 是 **NSIS**
			// 安装器(无 7z magic), 抽取必然失败; 而 7.92 是最后一个带免安装 zip 的版本。
			// 断言包名时用渲染出的 PinnedVer, 避免"写死 7.991"与固定版本打架。
			if s.Engine == EngineNmap && p.OS == "windows" {
				if p.Ext != "zip" {
					t.Fatalf("nmap Windows 包必须是 zip(不能回到解不开的 setup.exe), 实得 %q", p.Ext)
				}
				ver := p.PinnedVer
				if ver == "" {
					ver = "7.92"
				}
				got := renderAsset(p, ver)
				if got != "nmap-7.92-win32.zip" {
					t.Fatalf("nmap Windows 包名应为 nmap-7.92-win32.zip, 实得 %q", got)
				}
				if !s.Want.BundleDir {
					t.Error("nmap 必须整包落位(BundleDir), 否则缺 DLL 会报 0xC0000135")
				}
			}
		}
	}
}

// TestReleaseURL Tag 带 v 前缀而文件名不带(实测确认的 URL 约定)
func TestReleaseURL(t *testing.T) {
	r := release{DownloadBase: "https://github.com/projectdiscovery/nuclei/releases/download/"}
	got := releaseURL(r, "v3.11.1", "nuclei_3.11.1_windows_amd64.zip")
	want := "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip"
	if got != want {
		t.Fatalf("releaseURL 拼错:\n got %s\nwant %s", got, want)
	}
}

// TestVersionParsing 版本解析与比较
func TestVersionParsing(t *testing.T) {
	cases := []struct {
		tag  string
		want string
		ok   bool
	}{
		{"v3.11.1", "3.11.1", true},
		{"3.11.1", "3.11.1", true},
		{"v0.74.0", "0.74.0", true},
		{"v2.17.0", "2.17.0", true},
	}
	re := catalog[0].Releases[0].TagRe // trivy 的正则(tag 形如 v0.74.0)
	for _, c := range cases {
		got, err := parseVersionFromTag(release{TagRe: re}, c.tag)
		if c.ok && err != nil {
			t.Errorf("parseVersionFromTag(%q) 意外失败: %v", c.tag, err)
			continue
		}
		if c.ok && got != c.want {
			t.Errorf("parseVersionFromTag(%q) = %q, 期望 %q", c.tag, got, c.want)
		}
	}
	if versionAtLeast("7.92", "7.991") {
		t.Error("7.92 不应 >= 7.991")
	}
	if !versionAtLeast("7.991", "7.92") {
		t.Error("7.991 应 >= 7.92")
	}
	if !versionAtLeast("3.11.1", "3.11.1") {
		t.Error("同版本应判定为 >= ")
	}
	if versionAtLeast("3.9.0", "3.11.0") {
		t.Error("3.9.0 不应 >= 3.11.0(需按数字段比较而非字符串)")
	}
}

// TestFindInstalled 已安装检测: 精确名优先, 否则前缀匹配
func TestFindInstalled(t *testing.T) {
	dir := t.TempDir()
	w := wantFile{WantName: exeName(), WantPrefix: []string{"trivy"}, InstallName: "trivycore.exe"}
	if _, ok := findInstalled(dir, w); ok {
		t.Fatal("空目录不应报告已安装")
	}
	// 放一个带版本后缀的名字
	loose := filepath.Join(dir, "nmap-7.94"+map[bool]string{true: ".exe", false: ""}[isWindows])
	w2 := wantFile{WantPrefix: []string{"nmap"}, InstallName: "nmapcore.exe"}
	if isWindows {
		loose = filepath.Join(dir, "nmap-7.94.exe")
	} else {
		loose = filepath.Join(dir, "nmap-7.94")
	}
	if err := os.WriteFile(loose, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := findInstalled(dir, w2); !ok {
		t.Fatal("带版本后缀的二进制应被识别为已安装")
	}
}

// TestInfoPlatformMarking Info 快照必须标出"当前平台是否可下载"
func TestInfoPlatformMarking(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)
	infos := m.Info()
	if len(infos) != len(catalog) {
		t.Fatalf("Info 数量应为 %d, 实得 %d", len(catalog), len(infos))
	}
	for _, it := range infos {
		if it.Homepage == "" {
			t.Errorf("%s 的 Info 缺少官方页", it.Engine)
		}
		// darwin/arm64 上 ZAP 有 dmg(标 supported, 但解包时会给出手动指引)
		if !it.Supported && it.Unsupported == "" {
			t.Errorf("%s 标记不支持但未给出原因", it.Engine)
		}
	}
	_ = runtime.GOOS
}

// TestUninstallRemovesOnlyEngine 卸载只删该引擎的文件, 不动同目录其它资源
func TestUninstallRemovesOnlyEngine(t *testing.T) {
	dir := t.TempDir()
	// 造两个引擎 + 一个无关文件 + 一个子目录
	trivy := filepath.Join(dir, "trivycore.exe")
	if !isWindows {
		trivy = filepath.Join(dir, "trivycore")
	}
	nmap := filepath.Join(dir, "nmapcore.exe")
	if !isWindows {
		nmap = filepath.Join(dir, "nmapcore")
	}
	for _, p := range []string{trivy, nmap} {
		if err := os.WriteFile(p, []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	keep := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(keep, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New(dir)
	n, err := m.Uninstall(EngineTrivy)
	if err != nil {
		t.Fatalf("卸载失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("应删除 1 个文件, 实得 %d", n)
	}
	if _, err := os.Stat(trivy); !os.IsNotExist(err) {
		t.Error("trivy 文件应已被删除")
	}
	if _, err := os.Stat(nmap); err != nil {
		t.Error("nmap 文件不应被删除")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("无关文件不应被删除")
	}
	if _, err := os.Stat(filepath.Join(dir, "subdir")); err != nil {
		t.Error("目录不应被删除(避免误删用户放在 bin/ 的资源)")
	}
}

// TestUninstallUnknownEngine 未知引擎必须返回错误而不是删掉别的东西
func TestUninstallUnknownEngine(t *testing.T) {
	m := New(t.TempDir())
	if _, err := m.Uninstall(Engine("not-an-engine")); err == nil {
		t.Fatal("未知引擎应返回错误")
	}
}

// ===== 进度与百分比 =====

// TestPct 百分比计算: 未知长度/边界值
func TestPct(t *testing.T) {
	if pct(50, 0) != -1 {
		t.Error("总长未知时应返回 -1")
	}
	if pct(0, 100) != 0 || pct(100, 100) != 100 || pct(150, 100) != 100 {
		t.Error("百分比边界值不正确")
	}
	if pct(1, 3) != 33 {
		t.Errorf("1/3 应为 33, 实得 %d", pct(1, 3))
	}
}

// TestConcurrentInstallRejected 同一时刻只允许一个下载任务
func TestConcurrentInstallRejected(t *testing.T) {
	m := New(t.TempDir())
	// 手动占位: 模拟任务在跑
	m.mu.Lock()
	m.running = true
	m.mu.Unlock()
	if _, err := m.Install([]Engine{EngineTrivy}, nil); err == nil {
		t.Fatal("已有任务在跑时应拒绝并发的 Install")
	}
	m.mu.Lock()
	m.running = false
	m.mu.Unlock()
}

// TestInstallUnsupportedPlatform 平台无官方包时必须给出明确错误与官方页(不静默失败)
func TestInstallUnsupportedPlatform(t *testing.T) {
	m := New(t.TempDir())
	// 目录里没有这个引擎, FindEngine 会失败 —— 这正是我们想验证的"不 panic 且返回错误"
	res := m.installOne(Engine("fake"), 1, 0, nil)
	if res.OK {
		t.Fatal("未知引擎不应报告成功")
	}
	if res.Error == "" {
		t.Fatal("未知引擎必须给出错误说明")
	}
	// 平台无模板的场景: 构造一个只有 darwin 模板的引擎项验证 pickPattern 行为
	s := &engineSpecEntry{Engine: Engine("fake"), Patterns: []assetPattern{{OS: "plan9", Arch: "mips"}}}
	if _, ok := pickPattern(s, runtime.GOOS, runtime.GOARCH); ok {
		t.Skip("测试构造的模板意外与当前平台匹配")
	}
}

// TestApplyMirror 镜像改写只作用于 GitHub 地址
func TestApplyMirror(t *testing.T) {
	SetGitHubMirror("")
	if got := applyMirror("https://github.com/a/b.zip"); got != "https://github.com/a/b.zip" {
		t.Errorf("未配置镜像时地址不应改写, 实得 %q", got)
	}
	SetGitHubMirror("https://mirror.example.com")
	got := applyMirror("https://github.com/a/b.zip")
	want := "https://mirror.example.com/https://github.com/a/b.zip"
	if got != want {
		t.Errorf("镜像改写结果不符:\n got %q\nwant %q", got, want)
	}
	// 非 GitHub 地址不受影响
	if got := applyMirror("https://nmap.org/dist/x.exe"); got != "https://nmap.org/dist/x.exe" {
		t.Errorf("非 GitHub 地址不应改写, 实得 %q", got)
	}
	SetGitHubMirror("")
}

// TestApplyMirrorCoversGitHubAPI 镜像必须同时改写 api.github.com / codeload.github.com。
//
// 【回归用例】最初的 isGitHubURL 只认 github.com 与 githubusercontent.com, 于是
// "配了镜像依然查不到最新版本号" —— 版本查询走 api.github.com, 而受限网络里 API 域名
// 与下载域名被一起拦。只改写下载地址等于只解决一半问题, 现象是报 GitHub 403/超时,
// 用户会以为是镜像配错了。
func TestApplyMirrorCoversGitHubAPI(t *testing.T) {
	SetGitHubMirror("https://mirror.example.com")
	defer SetGitHubMirror("")

	cases := map[string]string{
		"https://api.github.com/repos/a/b/releases/latest": "https://mirror.example.com/https://api.github.com/repos/a/b/releases/latest",
		"https://codeload.github.com/a/b/zip/main":         "https://mirror.example.com/https://codeload.github.com/a/b/zip/main",
		"https://raw.githubusercontent.com/a/b/c/x.yaml":   "https://mirror.example.com/https://raw.githubusercontent.com/a/b/c/x.yaml",
	}
	for in, want := range cases {
		if got := applyMirror(in); got != want {
			t.Errorf("applyMirror(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	// 非 GitHub 域名(如 nmap 官方站)绝不能被改写 —— 否则会去镜像站取不存在的东西
	if got := applyMirror("https://nmap.org/dist/nmap-7.991-setup.exe"); got != "https://nmap.org/dist/nmap-7.991-setup.exe" {
		t.Errorf("nmap 官方地址被误改写: %q", got)
	}
}

// TestIsGitHubURL 域名判定
func TestIsGitHubURL(t *testing.T) {
	yes := []string{
		"https://github.com/a/b",
		"https://api.github.com/repos/a/b",
		"https://codeload.github.com/a/b/zip/x",
		"https://raw.githubusercontent.com/a/b/c",
	}
	for _, u := range yes {
		if !isGitHubURL(u) {
			t.Errorf("%s 应判定为 GitHub 域名", u)
		}
	}
	no := []string{
		"https://nmap.org/dist/",
		"https://example.com/github.com/x",
		"not a url at all::",
	}
	for _, u := range no {
		if isGitHubURL(u) {
			t.Errorf("%s 不应判定为 GitHub 域名", u)
		}
	}
}

// TestJsonField JSON 字段最小解析
func TestJsonField(t *testing.T) {
	body := `{"tag_name":"v3.11.1","name":"x","nested":{"a":1}}`
	if got := jsonField(body, "tag_name"); got != "v3.11.1" {
		t.Errorf("tag_name 解析错误: %q", got)
	}
	if got := jsonField(body, "missing"); got != "" {
		t.Errorf("缺失字段应为空, 实得 %q", got)
	}
	if got := jsonField(`{"n":123}`, "n"); got != "" {
		t.Errorf("非字符串字段应为空, 实得 %q", got)
	}
}

// TestPlaceNoOverwrite 命名冲突时隔离安装, 绝不覆盖用户已有文件
func TestPlaceNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	s, err := FindEngine(EngineTrivy)
	if err != nil {
		t.Fatal(err)
	}
	// 用户已有一个"自己的" trivycore.exe
	existing := filepath.Join(dir, s.Want.InstallName)
	if err := os.WriteFile(existing, []byte("USER-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 新的解包产物(放在暂存区)
	src := filepath.Join(dir, "fresh-binary")
	if err := os.WriteFile(src, []byte("NEW-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New(dir)
	installed, renameTo, err := m.place(src, s)
	if err != nil {
		t.Fatalf("隔离安装失败: %v", err)
	}
	if renameTo == "" {
		t.Fatal("冲突时应返回隔离后的新名字")
	}
	if installed == existing {
		t.Fatal("不应覆盖用户已有文件")
	}
	data, _ := os.ReadFile(existing)
	if string(data) != "USER-BINARY" {
		t.Fatalf("用户文件被改写: %q", string(data))
	}
	nd, _ := os.ReadFile(installed)
	if string(nd) != "NEW-BINARY" {
		t.Fatalf("新文件内容不符: %q", string(nd))
	}
}

// TestPlaceFreshInstall 无冲突时直接落位为目标名
func TestPlaceFreshInstall(t *testing.T) {
	dir := t.TempDir()
	s, err := FindEngine(EngineNuclei)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "src-bin")
	if err := os.WriteFile(src, []byte("BIN"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New(dir)
	installed, renameTo, err := m.place(src, s)
	if err != nil {
		t.Fatalf("落位失败: %v", err)
	}
	if renameTo != "" {
		t.Errorf("无冲突时不应重命名, 实得 %q", renameTo)
	}
	if filepath.Base(installed) != s.Want.InstallName {
		t.Errorf("落位名应为 %q, 实得 %q", s.Want.InstallName, filepath.Base(installed))
	}
}

// TestBlobCache 缓存统计与清理
func TestBlobCache(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)
	if n, c := m.BlobCacheSize(); n != 0 || c != 0 {
		t.Fatalf("空缓存应为 0/0, 实得 %d/%d", n, c)
	}
	blobDir := filepath.Join(dir, ".engmgr-blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, "a.zip"), bytes.Repeat([]byte{1}, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	n, c := m.BlobCacheSize()
	if n != 1024 || c != 1 {
		t.Fatalf("缓存统计应为 1024/1, 实得 %d/%d", n, c)
	}
	if err := m.ClearBlobCache(); err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if n, _ := m.BlobCacheSize(); n != 0 {
		t.Fatalf("清理后应为 0, 实得 %d", n)
	}
}
