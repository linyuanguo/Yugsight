package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yugsight/internal/models"
)

// ===== config.yaml 解析 =====

func TestParsePackConfigScalars(t *testing.T) {
	cfg, warnings := ParsePackConfig("name: 客户A模板\nclient: 客户A\naccent: #ff0000\nfooter: 页脚文案\ncover: false\n")
	if len(warnings) != 0 {
		t.Fatalf("正常配置不应有告警: %v", warnings)
	}
	if cfg.Name != "客户A模板" || cfg.Client != "客户A" || cfg.Accent != "#ff0000" || cfg.Footer != "页脚文案" {
		t.Fatalf("标量解析错误: %+v", cfg)
	}
	if cfg.Cover == nil || *cfg.Cover {
		t.Fatalf("cover: false 应解析为 false, 得到 %v", cfg.Cover)
	}
}

func TestParsePackConfigSectionsAndComments(t *testing.T) {
	// 行尾注释不能吃进值, URL 里的 # 不能误判为注释
	cfg, _ := ParsePackConfig("# 顶部注释\nname: 带注释 # 这是注释\nsections:\n  - summary\n  - vulns\n  - assets\nlogo: logo.png\n")
	if cfg.Name != "带注释" {
		t.Fatalf("行尾注释未剥离: %q", cfg.Name)
	}
	if strings.Join(cfg.Sections, ",") != "summary,vulns,assets" {
		t.Fatalf("列表解析错误: %v", cfg.Sections)
	}
	if cfg.Logo != "logo.png" {
		t.Fatalf("logo 解析错误: %q", cfg.Logo)
	}
}

func TestParsePackConfigBadLinesDegrade(t *testing.T) {
	// 契约: 写错的字段忽略并告警, 绝不能让整份模板加载失败
	cfg, warnings := ParsePackConfig("没有冒号的一行\nunknown: x\nname: 正常\n")
	if cfg.Name != "正常" {
		t.Fatalf("坏行不应影响正常字段: %+v", cfg)
	}
	if len(warnings) < 2 {
		t.Fatalf("坏行与未知字段都应告警, 得到 %v", warnings)
	}
}

// ===== 模板目录加载 =====

func TestLoadPackDirDirectoryAndFlatDocx(t *testing.T) {
	root := t.TempDir()
	// 目录式模板
	dir := filepath.Join(root, "客户A")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgText := "name: 客户A报告\nclient: 客户A\naccent: #123456\nsections:\n  - vulns\n  - assets\n"
	if err := os.WriteFile(filepath.Join(dir, PackConfigFile), []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PackHTMLFile), []byte("<h1>{{.Title}}</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 旧形态: 根下扁平 .docx(内容无需合法, 列表只认文件存在)
	if err := os.WriteFile(filepath.Join(root, "legacy.docx"), []byte("PK\x03\x04fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	packs, warnings := LoadPackDir(root)
	if len(warnings) != 0 {
		t.Fatalf("正常目录不应告警: %v", warnings)
	}
	if len(packs) != 3 {
		t.Fatalf("应有 内置 + 目录式 + 扁平 三个模板, 得到 %d", len(packs))
	}
	if !packs[0].Builtin || packs[0].ID != BuiltinPackID {
		t.Fatalf("内置模板必须排在最前且 ID 为 default: %+v", packs[0])
	}
	byID := map[string]*Pack{}
	for _, p := range packs {
		byID[p.ID] = p
	}
	a := byID["客户A"]
	if a == nil || a.Kind != "dir" || !a.HasHTML || a.HasDocx {
		t.Fatalf("目录式模板识别错误: %+v", a)
	}
	if a.Name != "客户A报告" || a.Config.Client != "客户A" || a.Config.Accent != "#123456" {
		t.Fatalf("config.yaml 未生效: %+v", a.Config)
	}
	if strings.Join(a.Config.Sections, ",") != "vulns,assets" {
		t.Fatalf("章节顺序应来自 config.yaml: %v", a.Config.Sections)
	}
	legacy := byID["legacy"]
	if legacy == nil || legacy.Kind != "docx" || !legacy.HasDocx {
		t.Fatalf("旧扁平模板应被识别为 docx: %+v", legacy)
	}
}

func TestLoadPackDirMissingDegradesToBuiltin(t *testing.T) {
	// 契约: 目录不存在 = 只有内置模板(外部资源可选, 必须降级不报错)
	packs, warnings := LoadPackDir(filepath.Join(t.TempDir(), "nope"))
	if len(packs) != 1 || !packs[0].Builtin {
		t.Fatalf("目录缺失应只返回内置模板: %+v", packs)
	}
	if len(warnings) == 0 {
		t.Fatal("目录缺失应有告警(否则用户不知道模板没生效)")
	}
}

func TestValidPackIDRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"../evil", "a/b", "..", ".", "a\\b", ""} {
		if ValidPackID(bad) {
			t.Fatalf("应拒绝非法模板 ID: %q", bad)
		}
	}
	for _, ok := range []string{"客户A", "tmpl-1", "my_template"} {
		if !ValidPackID(ok) {
			t.Fatalf("应接受正常模板 ID: %q", ok)
		}
	}
}

func TestPackLogoExpandedToDataURI(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "withlogo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 1x1 PNG
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x01}
	if err := os.WriteFile(filepath.Join(dir, "logo.png"), png, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PackConfigFile), []byte("logo: logo.png\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PackHTMLFile), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	packs, _ := LoadPackDir(root)
	var p *Pack
	for _, x := range packs {
		if x.ID == "withlogo" {
			p = x
		}
	}
	if p == nil {
		t.Fatal("模板未加载")
	}
	if !strings.HasPrefix(p.LogoData, "data:image/png;base64,") {
		t.Fatalf("logo 应展开为 data URI(报告要自包含), 得到 %q", p.LogoData)
	}
}

// ===== ReportData =====

func TestBuildReportDataFromPack(t *testing.T) {
	snap := &Snapshot{
		Title:    "季度扫描",
		Operator: "张三",
		Assets:   []*models.Asset{{IP: "10.0.0.1", Ports: []int{22, 80}, Alive: true}},
		Vulns:    []*models.Vuln{{AssetIP: "10.0.0.1", Title: "Redis 未授权", Severity: "high", Port: 6379}},
		Scans:    []ScanInfo{{ID: "t1", Target: "10.0.0.0/24"}},
	}
	stats := ComputeStats(snap)
	cover := false
	pack := &Pack{ID: "p", Config: PackConfig{Client: "客户A", Accent: "#abc", Footer: "f", Cover: &cover, Sections: []string{"vulns"}}}
	d := BuildReportData(snap, stats, pack, "副标题")
	if d.Client != "客户A" || d.Accent != "#abc" || d.Footer != "f" {
		t.Fatalf("模板元信息未生效: %+v", d)
	}
	if d.Cover {
		t.Fatal("cover: false 应生效")
	}
	if len(d.Sections) != 1 || d.Sections[0] != "vulns" {
		t.Fatalf("章节顺序应来自模板: %v", d.Sections)
	}
	// 目标应包含资产 IP 与任务目标
	if len(d.Targets) != 2 {
		t.Fatalf("目标未汇总: %v", d.Targets)
	}
	if len(d.SevRows) != 5 || d.SevRows[1].Label != "高危" {
		t.Fatalf("等级行错误: %+v", d.SevRows)
	}
	_ = time.Now()
}

func TestBuildReportDataNilSnapshot(t *testing.T) {
	// 契约: 模板预览用空数据渲染, 不能 panic
	d := BuildReportData(nil, SnapshotStats{}, BuiltinPack(), "")
	if d.Title == "" || d.GeneratedAtText == "" {
		t.Fatalf("空数据也应产出可渲染结构: %+v", d)
	}
}

// ===== HTML 渲染 =====

func TestRenderPackHTMLBuiltin(t *testing.T) {
	d := BuildReportData(&Snapshot{
		Title:  "测试报告",
		Assets: []*models.Asset{{IP: "1.2.3.4"}},
		Vulns:  []*models.Vuln{{Title: "测试漏洞", Severity: "critical", AssetIP: "1.2.3.4"}},
	}, SnapshotStats{VulnTotal: 1, Critical: 1}, BuiltinPack(), "")
	out, err := RenderPackHTML(d, "")
	if err != nil {
		t.Fatalf("内置模板渲染失败: %v", err)
	}
	for _, want := range []string{"测试报告", "测试漏洞", "严重", "1.2.3.4"} {
		if !strings.Contains(out, want) {
			t.Fatalf("渲染结果缺 %q", want)
		}
	}
}

func TestRenderPackHTMLEscapesUntrustedData(t *testing.T) {
	// 契约(安全): 漏洞标题来自被扫描目标, 完全不受控 —— 注入的脚本必须被转义,
	// 否则"扫一个恶意站点"就能在报告里植入脚本, 而报告是要发给客户的文件。
	evil := "<script>alert(1)</script>"
	d := BuildReportData(&Snapshot{
		Title: "T", Vulns: []*models.Vuln{{Title: evil, Severity: "high"}},
	}, SnapshotStats{}, BuiltinPack(), "")
	out, err := RenderPackHTML(d, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("未转义: 恶意标题原样进入了报告")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("应转义输出, 实际: %s", out)
	}
}

func TestRenderPackHTMLUserTemplateAndBadSyntax(t *testing.T) {
	d := BuildReportData(&Snapshot{Title: "标题"}, SnapshotStats{}, BuiltinPack(), "")
	// 用户模板生效
	out, err := RenderPackHTML(d, `<p>{{.Title}}-{{.Stats.VulnTotal}}</p>`)
	if err != nil || out != "<p>标题-0</p>" {
		t.Fatalf("用户模板渲染错误: %q %v", out, err)
	}
	// 语法错误必须返回 error(调用方据此回落内置模板), 不能静默产出空报告
	if _, err := RenderPackHTML(d, "{{if .Title}}"); err == nil {
		t.Fatal("模板语法错误应返回 error")
	}
}

// ===== PDF 通道 =====

func TestConvertHTMLToPDFNoConverter(t *testing.T) {
	// 契约: 无转换器时返回哨兵错误(装配层据此回落打印通道), 绝不 panic
	if _, err := ConvertHTMLToPDF("<html></html>", time.Second); err == nil {
		// 本机若真装了转换器就不报错, 这不算失败
		if _, ok := FindPDFConverter(); ok {
			t.Skip("本机存在 PDF 转换器")
		}
		t.Fatal("无转换器时应返回错误")
	} else if _, ok := FindPDFConverter(); !ok && err != ErrNoPDFConverter {
		t.Fatalf("无转换器时应返回 ErrNoPDFConverter, 得到 %v", err)
	}
}
