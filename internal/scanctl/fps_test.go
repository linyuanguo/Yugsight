//go:build !windows || windows

package scanctl

import (
	"os"
	"path/filepath"
	"testing"

	"yugsight/internal/models"
)

func fpsTestEnv(t *testing.T) (*FPS, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "fps.jsonl")
	d, err := NewFileDAO[FPSRule](p, func() FPSRule { return FPSRule{} })
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFPS(d)
	if err != nil {
		t.Fatal(err)
	}
	return f, p
}

// TestFPMarkAndAutoMark 标记误报 + 后续扫描同资产同 CVE 自动标记
func TestFPMarkAndAutoMark(t *testing.T) {
	f, _ := fpsTestEnv(t)
	r, err := f.Mark("10.0.0.1", "cve-2021-44228", "", "WAF 拦截导致的误判", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if r.CVE != "CVE-2021-44228" {
		t.Fatalf("CVE 应归一化: %s", r.CVE)
	}

	// 后续扫描: 同资产 + 同 CVE -> 自动标记
	assets := []*models.Asset{{ID: "a1", IP: "10.0.0.1"}}
	vulns := []*models.Vuln{
		{AssetIP: "10.0.0.1", CVE: "CVE-2021-44228", Title: "Log4Shell"},
		{AssetIP: "10.0.0.1", CVE: "CVE-2021-44229", Title: "其他"},
		{AssetIP: "10.0.0.2", CVE: "CVE-2021-44228", Title: "同 CVE 不同资产"},
	}
	n := f.AutoMark(assets, vulns)
	if n != 1 {
		t.Fatalf("应标记 1 条, got %d", n)
	}
	if !vulns[0].FalsePositive || vulns[0].FPNote != "WAF 拦截导致的误判" {
		t.Fatalf("标记与备注错误: %+v", vulns[0])
	}
	if vulns[1].FalsePositive || vulns[2].FalsePositive {
		t.Fatal("不同 CVE / 不同资产不应被标记")
	}

	// Match 单条判定
	if hit, rr := f.Match(assets[0], vulns[0]); !hit || rr.Note == "" {
		t.Fatalf("Match 失败: %v %+v", hit, rr)
	}
}

// TestFPNoCVEFallback 无 CVE 时按 资产 + 标题 匹配
func TestFPNoCVEFallback(t *testing.T) {
	f, _ := fpsTestEnv(t)
	if _, err := f.Mark("10.0.0.5", "", "Server 版本泄露", "内部系统", ""); err != nil {
		t.Fatal(err)
	}
	v := &models.Vuln{AssetIP: "10.0.0.5", Title: "Server 版本泄露"}
	if hit, _ := f.Match(&models.Asset{IP: "10.0.0.5"}, v); !hit {
		t.Fatal("无 CVE 应按标题匹配")
	}
	v2 := &models.Vuln{AssetIP: "10.0.0.5", Title: "其他漏洞"}
	if hit, _ := f.Match(&models.Asset{IP: "10.0.0.5"}, v2); hit {
		t.Fatal("标题不同不应命中")
	}
}

// TestFPValidate 非法标记拒绝
func TestFPValidate(t *testing.T) {
	f, _ := fpsTestEnv(t)
	if _, err := f.Mark("", "CVE-2021-44228", "", "", ""); err == nil {
		t.Fatal("空 IP 应拒绝")
	}
	if _, err := f.Mark("10.0.0.1", "", "   ", "", ""); err == nil {
		t.Fatal("CVE 与标题皆空应拒绝")
	}
	if f.Count() != 0 {
		t.Fatal("非法标记不应落盘")
	}
}

// TestFPOverwriteAndRemove 重复标记覆盖 + 删除
func TestFPOverwriteAndRemove(t *testing.T) {
	f, _ := fpsTestEnv(t)
	r1, _ := f.Mark("10.0.0.1", "CVE-2021-44228", "", "备注一", "")
	if _, err := f.Mark("10.0.0.1", "CVE-2021-44228", "", "备注二(覆盖)", ""); err != nil {
		t.Fatal(err)
	}
	if f.Count() != 1 {
		t.Fatalf("重复标记应幂等, got %d", f.Count())
	}
	rule := f.List()[0]
	if rule.Note != "备注二(覆盖)" {
		t.Fatalf("备注应被覆盖: %s", rule.Note)
	}
	if r1.ID != rule.ID {
		t.Fatalf("同一键应同 ID: %s vs %s", r1.ID, rule.ID)
	}
	if ok, _ := f.Remove(r1.ID); !ok {
		t.Fatal("删除失败")
	}
	if f.Count() != 0 {
		t.Fatal("删除后应为空")
	}
}

// TestFPPersist 持久化重载
func TestFPPersist(t *testing.T) {
	f, p := fpsTestEnv(t)
	if _, err := f.Mark("10.1.1.1", "CVE-1999-0001", "", "持久化测试", "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("文件应存在: %s", err)
	}
	// 重载
	d2, _ := NewFileDAO[FPSRule](p, func() FPSRule { return FPSRule{} })
	f2, _ := NewFPS(d2)
	if f2.Count() != 1 {
		t.Fatalf("重载后规则数 = %d, want 1", f2.Count())
	}
	v := &models.Vuln{AssetIP: "10.1.1.1", CVE: "CVE-1999-0001", Title: "x"}
	if n := f2.AutoMark(nil, []*models.Vuln{v}); n != 1 || !v.FalsePositive {
		t.Fatalf("重载后自动标记失败: n=%d v=%+v", n, v)
	}
}
