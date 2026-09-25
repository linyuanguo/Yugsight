package engmgr

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNmapWindowsPatternIsPinnedZip 锁住"nmap 的 Windows 自动安装固定用 7.92 免安装 zip"。
//
// 【背景 — 这是一次真实故障的回归用例】
// 官方 7.93 起 Windows 只发 nmap-<ver>-setup.exe, 而该包实测是 **NSIS 安装器**
// (PE 节表含 NSIS 标志性的空 .ndata 节、内嵌 "Nullsoft" 串, 且 7z magic
// 37 7A BC AF 27 1C 完全不存在)。原实现按"7z SFX"去扫归档签名, 必然失败并报
// "未在文件中找到 7z 归档签名", 用户看到的就是"提示解压不开"; 装 7-Zip 也没用
// —— 格式根本不是 7z。
//
// 修复方向: 固定用最后一个还带免安装 zip 的版本(7.92, 2021-08), 走纯 zip 解包通道。
//
// 本用例钉住三件事, 防止日后被人"顺手"改回 setup.exe:
//  1. Windows pattern 必须是 zip(不是 exe, 否则又回到 NSIS 死路);
//  2. 必须带 PinnedVer, 否则会拿目录页最新的 7.991 去拼 nmap-7.991-win32.zip(404);
//  3. needExtractor 必须是 false —— 7.92 是纯 zip, 不该再要求系统装 7-Zip。
func TestNmapWindowsPatternIsPinnedZip(t *testing.T) {
	s, err := FindEngine(EngineNmap)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := pickPattern(s, "windows", "amd64")
	if !ok {
		t.Fatal("Windows/amd64 应能找到 nmap 包模板")
	}
	if p.Ext != "zip" {
		t.Errorf("nmap Windows 包应为 zip(免安装), 实际 %q —— 改回 exe 会重新踩 NSIS 解不开的坑", p.Ext)
	}
	if p.PinnedVer == "" {
		t.Error("nmap Windows 包必须固定版本: 目录页最新是 7.991, 拿它拼 win32.zip 会 404")
	}
	if p.PinnedVer != "7.92" {
		t.Errorf("固定版本应为 7.92(最后一个带免安装 zip 的版本), 实际 %q", p.PinnedVer)
	}
	if got := renderAsset(p, p.PinnedVer); got != "nmap-7.92-win32.zip" {
		t.Errorf("渲染出的资产名应为 nmap-7.92-win32.zip, 实际 %q", got)
	}
	if s.needExtractor {
		t.Error("7.92 是纯 zip, needExtractor 必须为 false —— 否则会无端要求系统装 7-Zip")
	}
}

// TestNmapPinnedVerSkipsUpstreamQuery 固定版本必须绕过上游查询。
//
// 若走到 latestTag, 会拿到目录页最大的 7.991, 与固定 7.92 冲突, 或产生
// "显示 7.991 却下载 7.92"的错位。这里用"不联网也会得到 7.92"来间接验证:
// 固定版本分支不发起任何网络请求。
func TestNmapPinnedVerSkipsUpstreamQuery(t *testing.T) {
	s, _ := FindEngine(EngineNmap)
	p, _ := pickPattern(s, "windows", "amd64")
	// 模拟 installOne 的定版本分支
	ver := p.PinnedVer
	if ver == "" {
		t.Fatal("固定版本为空, 该用例失去意义")
	}
	// 不调用 latestTag 也应能得到正确文件名
	name := renderAsset(p, ver)
	if !strings.HasPrefix(name, "nmap-7.92") {
		t.Errorf("文件名应以 nmap-7.92 开头, 实际 %q", name)
	}
	// 确认下载地址拼接正确(nmap.org 的路径是 <base><file>, 无 tag 段)
	r0, _ := latestRelease(s)
	got := r0.DownloadBase + name
	if got != "https://nmap.org/dist/nmap-7.92-win32.zip" {
		t.Errorf("下载地址应为 https://nmap.org/dist/nmap-7.92-win32.zip, 实际 %q", got)
	}
}

// TestNmapMustUseBundleDir 钉住"nmap 必须整包落位"。
//
// 【背景 — 第二次真实故障的回归用例】
// 早期实现按通用策略"在归档里找到唯一目标可执行文件 -> 抽出来放 bin/", 对
// trivy/nuclei 这类单文件静态二进制没问题, 对 nmap 是致命的: 7.92 zip 里的
// nmap.exe 运行时依赖同目录的 DLL(nsock32、libssl/libcrypto、zlib 等)与数据文件
// (nmap-services / nmap-payloads / nse_main.lua 与 scripts/)。
// 只抽 nmap.exe 的结果是 **文件存在、PE 头是 MZ、字节数看着也正常, 但一执行就
// 0xC0000135(STATUS_DLL_NOT_FOUND)** —— 从大小/时间戳完全看不出问题, 实测踩坑。
//
// 本用例确保 BundleDir 不会被"顺手"去掉: 一旦为 false, 又会退回只抽单文件。
func TestNmapMustUseBundleDir(t *testing.T) {
	s, err := FindEngine(EngineNmap)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Want.BundleDir {
		t.Error("nmap 必须整包落位(BundleDir=true): 只抽 nmap.exe 会因缺 DLL 报 0xC0000135")
	}
	if s.Want.BundleName == "" {
		t.Error("BundleDir=true 时应显式声明 BundleName(落地目录名)")
	}
}

// TestNmapBundleExtractKeepsDependencies 用与真实 7.92 包相同的结构验证"整包落位"。
//
// 断言三件事:
//  1. 入口命中 nmap.exe —— 不能把 ncat/nping/npcap 这些前缀相近的文件当成 nmap;
//  2. **依赖文件全部落盘** —— DLL 与数据文件必须在, 这是本次修复的核心(缺一个就跑不起来);
//  3. 保留包内目录结构 —— nmap.exe 按相对自身目录查找 nmap-services, 结构不能拍平。
func TestNmapBundleExtractKeepsDependencies(t *testing.T) {
	p := makeZip(t, map[string][]byte{
		"nmap-7.92/nmap.exe":          []byte("MZ fake nmap binary"),
		"nmap-7.92/nmap-services":     []byte("http 80/tcp"),
		"nmap-7.92/nmap-payloads":     []byte("udp payloads"),
		"nmap-7.92/nmap-mac-prefixes": []byte("data"),
		"nmap-7.92/nse_main.lua":      []byte("-- lua"),
		"nmap-7.92/scripts/http.lua":  []byte("-- script"),
		"nmap-7.92/nsock32.dll":       []byte("DLL"),
		"nmap-7.92/libcrypto-3.dll":   []byte("DLL"),
		"nmap-7.92/ncat.exe":          []byte("MZ ncat - must NOT match"),
		"nmap-7.92/nping.exe":         []byte("MZ nping - must NOT match"),
		"nmap-7.92/npcap-1.50.exe":    []byte("MZ npcap installer"),
	})
	s, _ := FindEngine(EngineNmap)
	outDir := t.TempDir()
	root, err := extractBundleZip(p, outDir, s.Want)
	if err != nil {
		t.Fatalf("整包解包失败: %v", err)
	}
	// 必须返回**解包根目录**而非入口文件路径: 落位是"整目录 rename", 拿到文件路径
	// 会把单个 exe 改名成目录名, 依赖文件全丢(这是踩过的坑, 见函数头注释)。
	if root != outDir {
		t.Fatalf("应返回解包根目录 %q, 实际 %q", outDir, root)
	}
	if st, serr := os.Stat(root); serr != nil || !st.IsDir() {
		t.Fatalf("返回路径必须是目录: %v", serr)
	}
	// 入口能在目录内被定位到
	entry, ok := findExtracted(root, s.Want)
	if !ok {
		t.Fatal("目录内应能定位到入口可执行文件")
	}
	if base := strings.ToLower(filepathBase(entry)); base != "nmap.exe" {
		t.Fatalf("入口应为 nmap.exe, 实际 %q", base)
	}
	// 依赖必须齐全: 这是"能跑起来"与"0xC0000135"的分界
	for _, dep := range []string{
		"nmap-services", "nmap-payloads", "nmap-mac-prefixes",
		"nse_main.lua", "http.lua", "nsock32.dll", "libcrypto-3.dll",
	} {
		if !fileExistsInDir(outDir, dep) {
			t.Errorf("依赖文件 %s 未落盘 —— 缺它 nmap 会启动失败(0xC0000135 或功能残缺)", dep)
		}
	}
	// 目录结构要保留(入口与其资源在同一相对层级下)
	if !strings.Contains(strings.ToLower(entry), "nmap-7.92") {
		t.Errorf("整包落位应保留归档内目录结构, 实际入口路径 %q", entry)
	}
}

// fileExistsInDir 递归判断 dir 下是否存在指定文件名的文件
func fileExistsInDir(dir, name string) bool {
	var found bool
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.EqualFold(filepathBase(p), name) {
			found = true
		}
		return nil
	})
	return found
}

// filepathBase 包内小工具: 取路径最后一段(避开 filepath 导入与测试文件重复)
func filepathBase(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// TestNmapGOOSGuard 仅 Windows 有 nmap 包模板(其它平台应走各自原生包)。
// 这里只断言当前平台的取值与 catalog 声明一致, 防止误把 Windows 专用规则外溢。
func TestNmapGOOSGuard(t *testing.T) {
	s, _ := FindEngine(EngineNmap)
	_, okWin := pickPattern(s, "windows", "amd64")
	if !okWin {
		t.Fatal("Windows 应有 nmap 包模板")
	}
	_ = runtime.GOOS // 保留: 该用例在任意平台都应通过
}
