//go:build !windows || windows

// confidence.go 漏洞置信度基础计算。
//
// 定位: "基础计算函数" —— 纯函数、无状态、无网络, 供统一漏洞模型
// (model.go) 在产出 Vulnerability 时自动计算, 也供后续归一化模块
// 对第三方引擎结果做置信度对齐。权重取整数、逻辑透明, 便于审计与
// 后续调参(各因子独立叠加, 不引入黑盒)。
//
// 计算模型(0-100, 钳位):
//   - 基础分(匹配类型):
//     verified(主动验证型, 如 PING 通/请求命中) = 80
//     version(版本匹配型, 仅版本落区间)        = 55
//     未知                                       = 60
//   - 证据类型(加分):
//     status/header +10, word/banner +8, cert +6,
//     regex/dsl +5, body +4, 无 +0
//   - 版本已确认(资产带版本号) +5
//   - CVE 已知(情报集命中: KEV/EPSS/CPE 字典) +5
//   - 严重级别: critical +5, high +3, medium +1
//
// 分级: >=85 high, >=60 medium, 其余 low
//
// 依赖: 仅 Go 标准库。
package scanner

// ConfidenceInput 置信度计算输入
type ConfidenceInput struct {
	MatchType  string // MatchTypeVerified("verified") / MatchTypeVersion("version") / ""
	Evidence   string // 证据类型: status/header/word/regex/dsl/body/banner/cert/""
	HasVersion bool   // 资产版本号已确认
	KnownCVE   bool   // CVE 号在已知漏洞情报中命中(KEV/EPSS/CPE)
	Severity   string // info/low/medium/high/critical
}

// ConfidenceLevel 按分值返回置信度等级
func ConfidenceLevel(score int) string {
	switch {
	case score >= 85:
		return "high"
	case score >= 60:
		return "medium"
	default:
		return "low"
	}
}

// CalculateConfidence 计算漏洞置信度(0-100)与等级(high/medium/low)。
// 纯函数, 入参零值也可调用(返回基础分)。
func CalculateConfidence(in ConfidenceInput) (int, string) {
	var score float64
	switch in.MatchType {
	case MatchTypeVerified:
		score = 80
	case MatchTypeVersion:
		score = 55
	default:
		score = 60
	}
	switch in.Evidence {
	case "status", "header":
		score += 10
	case "word", "banner":
		score += 8
	case "cert":
		score += 6
	case "regex", "dsl":
		score += 5
	case "body":
		score += 4
	}
	if in.HasVersion {
		score += 5
	}
	if in.KnownCVE {
		score += 5
	}
	switch SeverityRank(in.Severity) {
	case 5: // critical
		score += 5
	case 4: // high
		score += 3
	case 3: // medium
		score += 1
	}
	if score < 1 {
		score = 1
	}
	if score > 100 {
		score = 100
	}
	s := int(score + 0.5)
	return s, ConfidenceLevel(s)
}

// ConfidenceForFinding 为既有 Finding(web.go 正则规则命中)快速估算置信度:
// 正则规则命中属主动验证型(请求实际发出且响应匹配), 证据按 regex 计。
func ConfidenceForFinding(f Finding) (int, string) {
	return CalculateConfidence(ConfidenceInput{
		MatchType: MatchTypeVerified,
		Evidence:  "regex",
		Severity:  f.Severity,
	})
}
