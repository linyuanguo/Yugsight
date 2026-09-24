package scanner

import "testing"

func TestConfidenceCalculation(t *testing.T) {
	// 验证型 + status 证据 + 版本 + 已知 CVE + critical = 80+10+5+5+5 = 105 -> 钳位 100/high
	s, lv := CalculateConfidence(ConfidenceInput{
		MatchType: MatchTypeVerified, Evidence: "status",
		HasVersion: true, KnownCVE: true, Severity: "critical",
	})
	if s != 100 || lv != "high" {
		t.Errorf("应为 100/high, 实际 %d/%s", s, lv)
	}
	// 版本匹配型 + 无证据 + 无版本 + info = 55/low
	s, lv = CalculateConfidence(ConfidenceInput{MatchType: MatchTypeVersion})
	if s != 55 || lv != "low" {
		t.Errorf("应为 55/low, 实际 %d/%s", s, lv)
	}
	// 零值输入 = 60/medium
	s, lv = CalculateConfidence(ConfidenceInput{})
	if s != 60 || lv != "medium" {
		t.Errorf("应为 60/medium, 实际 %d/%s", s, lv)
	}
	// 边界: 85 -> high
	s, lv = CalculateConfidence(ConfidenceInput{MatchType: MatchTypeVerified, KnownCVE: true}) // 80+5
	if s != 85 || lv != "high" {
		t.Errorf("应为 85/high, 实际 %d/%s", s, lv)
	}
	// 边界: 84 -> medium
	s, lv = CalculateConfidence(ConfidenceInput{MatchType: MatchTypeVerified, Evidence: "body"}) // 80+4
	if s != 84 || lv != "medium" {
		t.Errorf("应为 84/medium, 实际 %d/%s", s, lv)
	}
	// 边界: 60 -> medium / 59 -> low
	s, lv = CalculateConfidence(ConfidenceInput{MatchType: MatchTypeVersion, Evidence: "regex"}) // 55+5=60
	if s != 60 || lv != "medium" {
		t.Errorf("应为 60/medium, 实际 %d/%s", s, lv)
	}
	s, lv = CalculateConfidence(ConfidenceInput{MatchType: MatchTypeVersion, Evidence: "body"}) // 55+4=59
	if s != 59 || lv != "low" {
		t.Errorf("应为 59/low, 实际 %d/%s", s, lv)
	}
	// 下限: 不应低于 1
	s, _ = CalculateConfidence(ConfidenceInput{MatchType: "weird"})
	if s < 1 {
		t.Errorf("分值应钳位 >=1, 实际 %d", s)
	}
}

func TestConfidenceLevel(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, "high"}, {85, "high"}, {84, "medium"}, {60, "medium"}, {59, "low"}, {1, "low"}, {0, "low"},
	}
	for _, c := range cases {
		if got := ConfidenceLevel(c.score); got != c.want {
			t.Errorf("ConfidenceLevel(%d) = %s, 期望 %s", c.score, got, c.want)
		}
	}
}

func TestConfidenceForFinding(t *testing.T) {
	f := NewFinding("high", "x", "y", "")
	s, lv := ConfidenceForFinding(f)
	// 80(verified) + 5(regex) + 3(high) = 88/high
	if s != 88 || lv != "high" {
		t.Errorf("应为 88/high, 实际 %d/%s", s, lv)
	}
}
