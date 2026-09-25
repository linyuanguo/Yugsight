//go:build !windows || windows

package scanctl

import (
	"testing"

	"yugsight/internal/models"
)

// TestScoreBands 四级打分模型: 分值必须落在任务书规定的段内
func TestScoreBands(t *testing.T) {
	cases := []struct {
		name string
		in   ScoreInput
		want Tier
		min  int
		max  int
	}{
		{"POC 验证恒 100", ScoreInput{POCVerified: true, KeywordOnly: true}, TierVerified, 100, 100},
		{"精确版本+Banner 落 70-99", ScoreInput{ExactVersion: true, BannerMatch: true}, TierExact, 70, 99},
		{"精确版本+Banner+CVE+critical 不越级", ScoreInput{ExactVersion: true, BannerMatch: true, KnownCVE: true, Severity: "critical"}, TierExact, 89, 89},
		{"模糊版本 落 40-69", ScoreInput{FuzzyVersion: true}, TierFuzzy, 40, 69},
		{"精确版本无 Banner 落 40-69", ScoreInput{ExactVersion: true}, TierFuzzy, 40, 69},
		{"仅 Banner 落 40-69", ScoreInput{BannerMatch: true}, TierFuzzy, 40, 69},
		{"仅关键词 落 0-39", ScoreInput{KeywordOnly: true}, TierSuspicious, 0, 39},
		{"零值入参 落 0-39", ScoreInput{}, TierSuspicious, 0, 39},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, tier := Score(c.in)
			if tier != c.want {
				t.Fatalf("tier = %s, want %s", tier, c.want)
			}
			if s < c.min || s > c.max {
				t.Fatalf("score = %d, want in [%d, %d]", s, c.min, c.max)
			}
		})
	}
}

// TestTierOf 分值段反查
func TestTierOf(t *testing.T) {
	for score, want := range map[int]Tier{100: TierVerified, 99: TierExact, 70: TierExact, 69: TierFuzzy, 40: TierFuzzy, 39: TierSuspicious, 0: TierSuspicious} {
		if got := TierOf(score); got != want {
			t.Errorf("TierOf(%d) = %s, want %s", score, got, want)
		}
	}
}

// TestMapRiskLevel 风险等级自动映射(Critical/High/Medium/Low/Info)
func TestMapRiskLevel(t *testing.T) {
	cases := []struct {
		sev   string
		score int
		want  string
	}{
		{"critical", 100, models.SeverityCritical},
		{"high", 85, models.SeverityHigh},
		{"medium", 60, models.SeverityMedium},
		{"low", 40, models.SeverityLow},
		{"info", 100, models.SeverityInfo}, // info 恒 Info
		// 可疑级(<40)证据不足自动降一级
		{"critical", 39, models.SeverityHigh},
		{"high", 20, models.SeverityMedium},
		{"medium", 10, models.SeverityLow},
		{"low", 5, models.SeverityInfo},
		// 未知等级归一为 low 后再映射
		{"weird", 80, models.SeverityLow},
	}
	for _, c := range cases {
		if got := MapRiskLevel(c.sev, c.score); got != c.want {
			t.Errorf("MapRiskLevel(%s, %d) = %s, want %s", c.sev, c.score, got, c.want)
		}
	}
}

// TestScoreVuln 归一化漏洞打分启发式
func TestScoreVuln(t *testing.T) {
	asset := &models.Asset{
		ID:      "a1",
		IP:      "10.0.0.1",
		Version: "1.2.3",
		Banner:  "nginx/1.2.3",
		Tags:    []string{"prod"},
	}
	// POC 级: 成对请求+响应
	vPoc := &models.Vuln{AssetIP: "10.0.0.1", CVE: "CVE-2021-44228", Severity: "critical", Request: "GET /", Response: "200 OK"}
	r := ScoreVuln(vPoc, asset)
	if r.Score != 100 || r.Tier != TierVerified {
		t.Fatalf("POC 级应为 100/verified, got %d/%s", r.Score, r.Tier)
	}
	// 精确级: 证据坐实版本 + banner
	vExact := &models.Vuln{AssetIP: "10.0.0.1", CVE: "CVE-2021-44228", Severity: "high", Evidence: "server: nginx/1.2.3"}
	r = ScoreVuln(vExact, asset)
	if r.Tier != TierExact || r.Score < 70 || r.Score > 99 {
		t.Fatalf("精确级应在 70-99/exact, got %d/%s", r.Score, r.Tier)
	}
	// 模糊级: 有版本但证据未坐实
	vFuzzy := &models.Vuln{AssetIP: "10.0.0.1", Severity: "medium"}
	r = ScoreVuln(vFuzzy, asset)
	if r.Tier != TierFuzzy || r.Score < 40 || r.Score > 69 {
		t.Fatalf("模糊级应在 40-69/fuzzy, got %d/%s", r.Score, r.Tier)
	}
	// 可疑级: 无资产信息
	vSusp := &models.Vuln{AssetIP: "10.0.0.2", Severity: "high"}
	r = ScoreVuln(vSusp, nil)
	if r.Tier != TierSuspicious || !r.Suspicious || r.Score > 39 {
		t.Fatalf("可疑级应在 0-39/suspicious, got %d/%s", r.Score, r.Tier)
	}
	// 风险映射: 高危 + 可疑(证据不足) -> 降一级为 medium
	if r.RiskLevel != models.SeverityMedium {
		t.Errorf("high+可疑应映射为 medium, got %s", r.RiskLevel)
	}
}

// TestModel 模型描述完整性(四级)
func TestModel(t *testing.T) {
	m := Model()
	if len(m.Tiers) != 4 {
		t.Fatalf("应有 4 级, got %d", len(m.Tiers))
	}
}
