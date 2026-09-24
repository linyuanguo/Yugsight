//go:build !windows || windows

// scoring.go 漏洞置信度打分引擎(0-100 四级模型) + 风险等级自动映射。
//
// 四级打分模型(任务 3.2):
//   - 100     完整 POC 成功验证(POCVerified)
//   - 70~99   精确版本匹配 + 服务 Banner 匹配(ExactVersion && BannerMatch)
//   - 40~69   模糊版本匹配, 无 POC 验证(FuzzyVersion / 仅有版本或 Banner)
//   - 0~39    仅关键词匹配, 标记为可疑(KeywordOnly / 无任何强证据)
//
// 同级内按已知 CVE(情报命中)与严重级别微调, 不越级(100 保留给 POC 验证):
// 各因子独立叠加、权重为整数, 逻辑透明可审计, 便于后续调参。
//
// 风险等级自动映射(Critical / High / Medium / Low / Info):
// 以来源严重级别为基线, 低置信度(可疑级 <40)自动降一级 ——
// "证据不足的高危"不应与"已验证的高危"同级展示。
//
// 依赖: 仅 Go 标准库 + yugsight/models(等级常量/归一)。
package scanctl

import (
	"strings"

	"yugsight/models"
)

// Tier 置信度等级(与 0-100 四段一一对应)
type Tier string

const (
	TierVerified   Tier = "verified"   // 100: 完整 POC 成功验证
	TierExact      Tier = "exact"      // 70-99: 精确版本匹配 + 服务 Banner 匹配
	TierFuzzy      Tier = "fuzzy"      // 40-69: 模糊版本匹配, 无 POC 验证
	TierSuspicious Tier = "suspicious" // 0-39: 仅关键词匹配, 标记为可疑
)

// TierName 等级中文名(供 UI 展示)
func (t Tier) Name() string {
	switch t {
	case TierVerified:
		return "POC 已验证"
	case TierExact:
		return "精确版本+Banner"
	case TierFuzzy:
		return "模糊版本匹配"
	default:
		return "仅关键词(可疑)"
	}
}

// TierOf 按分值反查等级段(100 / 70-99 / 40-69 / 0-39)
func TierOf(score int) Tier {
	switch {
	case score >= 100:
		return TierVerified
	case score >= 70:
		return TierExact
	case score >= 40:
		return TierFuzzy
	default:
		return TierSuspicious
	}
}

// ScoreInput 打分输入(各布尔因子独立, 优先级: POC > 精确 > 模糊 > 关键词)
type ScoreInput struct {
	POCVerified  bool   // 完整 POC 成功验证
	ExactVersion bool   // 精确版本匹配(版本落已知漏洞区间且证据坐实)
	BannerMatch  bool   // 服务 Banner 匹配
	FuzzyVersion bool   // 模糊版本匹配(有版本线索但未坐实)
	KeywordOnly  bool   // 仅关键词匹配(标记为可疑)
	KnownCVE     bool   // CVE 在已知漏洞情报中命中
	Severity     string // critical/high/medium/low/info
}

// Score 计算置信度(0-100)与等级段。纯函数, 零值入参返回"仅关键词"基线分。
func Score(in ScoreInput) (int, Tier) {
	switch {
	case in.POCVerified:
		// 100: 完整 POC 成功验证(唯一满分)
		return 100, TierVerified

	case in.ExactVersion && in.BannerMatch:
		// 70~99: 精确版本匹配 + 服务 Banner 匹配
		s := 70
		if in.KnownCVE {
			s += 10
		}
		switch {
		case models.SeverityRank(in.Severity) == 4: // critical
			s += 9
		case models.SeverityRank(in.Severity) == 3: // high
			s += 6
		case models.SeverityRank(in.Severity) == 2: // medium
			s += 3
		}
		if s > 99 {
			s = 99 // 不越级: 100 保留给 POC 验证
		}
		return s, TierExact

	case in.FuzzyVersion || in.ExactVersion || in.BannerMatch:
		// 40~69: 模糊版本匹配, 无 POC 验证
		// (精确版本但无 Banner / 有 Banner 但版本未坐实, 均落本段上沿)
		s := 40
		if in.ExactVersion {
			s += 20
		} else if in.BannerMatch {
			s += 15
		}
		if in.KnownCVE {
			s += 6
		}
		switch {
		case models.SeverityRank(in.Severity) == 4:
			s += 5
		case models.SeverityRank(in.Severity) == 3:
			s += 3
		}
		if s > 69 {
			s = 69 // 不越级
		}
		return s, TierFuzzy

	default:
		// 0~39: 仅关键词匹配, 标记为可疑
		s := 10
		if in.KnownCVE {
			s += 12
		}
		switch {
		case models.SeverityRank(in.Severity) == 4:
			s += 8
		case models.SeverityRank(in.Severity) == 3:
			s += 5
		case models.SeverityRank(in.Severity) == 2:
			s += 2
		}
		if s > 39 {
			s = 39 // 不越级
		}
		return s, TierSuspicious
	}
}

// MapRiskLevel 风险等级自动映射: 来源严重级别 + 置信度 ->
// Critical / High / Medium / Low / Info。
// 规则: info 恒为 Info; 可疑级(置信度 <40)证据不足, 自动降一级
// (critical->high, high->medium, medium->low, low->info); 其余保持基线。
func MapRiskLevel(severity string, score int) string {
	base := models.NormalizeSeverity(severity)
	if base == models.SeverityInfo {
		return models.SeverityInfo
	}
	if score < 40 {
		switch base {
		case models.SeverityCritical:
			return models.SeverityHigh
		case models.SeverityHigh:
			return models.SeverityMedium
		case models.SeverityMedium:
			return models.SeverityLow
		default:
			return models.SeverityInfo
		}
	}
	return base
}

// ScoreResult 打分结果(分值 + 等级段 + 映射后的风险等级)
type ScoreResult struct {
	Score      int    `json:"score"`      // 0-100
	Tier       Tier   `json:"tier"`       // verified/exact/fuzzy/suspicious
	TierName   string `json:"tierName"`   // 等级中文名
	RiskLevel  string `json:"riskLevel"`  // Critical/High/Medium/Low/Info(自动映射)
	Suspicious bool   `json:"suspicious"` // 是否可疑(仅关键词级)
}

// ScoreWithRisk 打分 + 风险等级映射一步到位
func ScoreWithRisk(in ScoreInput) ScoreResult {
	s, t := Score(in)
	return ScoreResult{
		Score:      s,
		Tier:       t,
		TierName:   t.Name(),
		RiskLevel:  MapRiskLevel(in.Severity, s),
		Suspicious: t == TierSuspicious,
	}
}

// DeriveInput 从归一化漏洞 + 资产启发式推导打分输入(接线辅助):
//   - POCVerified: 漏洞携带成对原始请求+响应(主动验证证据)
//   - ExactVersion: 资产版本非空, 且漏洞证据/标题/描述中坐实了该版本号
//   - BannerMatch: 资产 Banner 非空, 且同样坐实了版本号
//   - FuzzyVersion: 有版本或 Banner 线索但未坐实
//   - KeywordOnly: 以上皆无(仅靠关键词/规则命中)
//
// 注意: 这是数据可用时的启发式; 引擎侧已明确验证结论时应直接构造
// ScoreInput 调用 Score, 更精确。
func DeriveInput(v *models.Vuln, a *models.Asset) ScoreInput {
	in := ScoreInput{Severity: v.Severity}
	if v == nil {
		return in
	}
	in.POCVerified = strings.TrimSpace(v.Request) != "" && strings.TrimSpace(v.Response) != ""
	if in.POCVerified {
		return in
	}
	if a == nil {
		return in
	}
	version := strings.TrimSpace(a.Version)
	banner := strings.TrimSpace(a.Banner)
	text := v.Evidence + " " + v.Title + " " + v.Description
	verInText := version != "" && strings.Contains(text, version)
	in.ExactVersion = verInText
	in.BannerMatch = banner != "" && verInText
	if !in.ExactVersion && !in.BannerMatch {
		in.FuzzyVersion = version != "" || banner != ""
	}
	if !in.ExactVersion && !in.BannerMatch && !in.FuzzyVersion {
		in.KeywordOnly = true
	}
	return in
}

// ScoreVuln 对统一漏洞模型打分(内部 DeriveInput + ScoreWithRisk),
// 供归一化后的批量漏洞统一回填置信度与风险等级。
func ScoreVuln(v *models.Vuln, a *models.Asset) ScoreResult {
	if v == nil {
		return ScoreResult{}
	}
	return ScoreWithRisk(DeriveInput(v, a))
}

// ===== 模型描述(供 UI / API 展示) =====

// ScoringModel 四级打分模型描述(静态, 供 /api/vuln/control/status 展示)
type ScoringModel struct {
	Tiers []TierSpec `json:"tiers"`
}

// TierSpec 单级描述
type TierSpec struct {
	Tier     Tier   `json:"tier"`
	Name     string `json:"name"`
	Range    string `json:"range"`
	Remark   string `json:"remark"`
}

// Model 返回四级打分模型描述
func Model() ScoringModel {
	return ScoringModel{Tiers: []TierSpec{
		{Tier: TierVerified, Name: TierVerified.Name(), Range: "100", Remark: "完整 POC 成功验证"},
		{Tier: TierExact, Name: TierExact.Name(), Range: "70-99", Remark: "精确版本匹配 + 服务 Banner 匹配"},
		{Tier: TierFuzzy, Name: TierFuzzy.Name(), Range: "40-69", Remark: "模糊版本匹配, 无 POC 验证"},
		{Tier: TierSuspicious, Name: TierSuspicious.Name(), Range: "0-39", Remark: "仅关键词匹配, 标记为可疑"},
	}}
}
