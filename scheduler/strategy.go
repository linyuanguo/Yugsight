package scheduler

import (
	"strings"
)

// ===== 内置扫描策略模板 =====
//
// 策略 = "一组预设扫描参数"。用户既可整体套用模板, 也可在模板基础上覆盖任意
// 单字段(ParamsOverride), 无需每次手填十余个参数 —— 这是把"扫描器"变成
// "可运维工具"的关键一步: 运维人员脑子里想的是"我要做一次快速存活探测",
// 而不是"concurrency=512, timeoutMs=800, enableNuclei=false..."。
//
// 三档模板覆盖 90% 场景:
//
//	quick    快速存活探测   —— 分钟级摸清网段有哪些机器在线(不扫端口细节)
//	audit    完整资产审计   —— 端口全量 + 服务指纹 + 内核/配置风险 + 抓包留证
//	webdeep  深度 Web 漏洞  —— Web 指纹 + Nuclei POC 全量模板 + 请求响应留证

// 策略模板 ID。
const (
	StrategyQuick = "quick" // 快速存活探测
	StrategyAudit = "audit" // 完整资产审计
	StrategyWeb   = "webdeep" // 深度 Web 漏洞扫描
	StrategyCustom = "custom" // 自定义参数(不套模板, 完全用用户传入值)
)

// Strategy 一个扫描策略模板。
//
// Defaults 是"模板建议值", 不是硬约束: 用户传了同名字段就以用户值为准(见 Apply)。
type Strategy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"` // 该模板对应的扫描类型
	Description string `json:"description"`
	// Defaults 模板默认参数(用户未显式提供的字段由此填充)。
	Defaults Params `json:"defaults"`
	// Priority 建议优先级(快速探测类排前面, 避免被大审计任务压住)。
	Priority int `json:"priority"`
}

// 常用端口集(与根包 defaultHostPorts 口径一致, 此处不 import main 包故复制一份)。
const (
	// PortsAlive 存活探测的 TCP 探针端口: 覆盖面广且极短, 用于绕过禁 ICMP 的主机。
	PortsAlive = "22,80,135,139,443,445,3389"
	// PortsCommon 常用服务端口(资产审计使用)。
	PortsCommon = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995," +
		"1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017"
	// PortsWeb Web 端口(深度 Web 扫描使用)。
	PortsWeb = "80,81,88,443,8000,8008,8080,8081,8443,8888,9000,9090,9443"
)

// BuiltinStrategies 内置策略模板列表(顺序即前端展示顺序)。
//
// 参数取值的依据(不是随手填的):
//   - quick:  并发高(512)+ 超时短(600ms) + 只探 TCP 探针端口, 目标是在
//     /24 网段上几十秒出结果; 关 Nuclei/抓包(存活探测不需要漏洞验证)。
//   - audit:  并发中(256)+ 超时稍长(1200ms) + 全量常用端口 + 开 Nuclei/ARP/
//     外部引擎 + 开抓包(审计要留证据链); 限速 800pps 防止把生产网打拥塞。
	//   - webdeep: 并发低(64, Web 应用并发高容易把站点打挂)+ 超时 5s(Web 响应慢)
	//     + 只扫 Web 端口 + Nuclei 全量模板 + 抓包(漏洞要带原始请求响应)
	//     + WebDeep=true: 该策略的"深度"就体现在这里 —— 会在单 URL 扫描之外
	//       追加同源爬虫与多类型注入探测(请求量显著变大, 故只由本策略开启)。
func BuiltinStrategies() []Strategy {
	t := true
	return []Strategy{
		{
			ID:          StrategyQuick,
			Name:        "快速存活探测",
			Kind:        "ip",
			Description: "分钟级摸清网段在线主机(ICMP+TCP+ARP), 不做端口细节与漏洞验证",
			Priority:    -10, // 探测类任务优先调度, 避免被长任务饿死
			Defaults: Params{
				Ports:       PortsAlive,
				Timeout:     600,
				Concurrency: 512,
				Rate:        2000, // 存活探测包很小, 速率可放宽
				EnableArp:   &t,
				Capture:     false,
			},
		},
		{
			ID:          StrategyAudit,
			Name:        "完整资产审计",
			Kind:        "host",
			Description: "端口全量 + 服务指纹 + 系统/配置风险 + Nuclei POC + 抓包留证",
			Priority:    0,
			Defaults: Params{
				Ports:          PortsCommon,
				Timeout:        1200,
				Concurrency:    256,
				Rate:           800, // 审计覆盖端口多, 必须限速防内网拥塞
				EnableNuclei:   true,
				EnableArp:      &t,
				EnableExternal: &t,
				Capture:        true,
				CaptureMaxBytes: 32 << 20, // 单任务 PCAP 上限 32MB, 防磁盘被写满
			},
		},
		{
			ID:          StrategyWeb,
			Name:        "深度 Web 漏洞扫描",
			Kind:        "web",
			Description: "Web 指纹 + Nuclei 全量模板 POC 验证 + 原始请求响应证据留存",
			Priority:    0,
			Defaults: Params{
				Ports:       PortsWeb,
				Timeout:     5000, // Web 响应慢, 超时给足
				Concurrency: 64,   // Web 应用不耐并发, 压低避免打挂站点
				Rate:        300,
				EnableNuclei: true,
				Capture:      true,
				CaptureMaxBytes: 32 << 20,
				WebDeep:         true, // 深度策略才开爬虫式扫描(默认策略一律不开)
			},
		},
	}
}

// StrategyByID 按 ID 查内置模板(不存在返回 nil)。
func StrategyByID(id string) *Strategy {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, s := range BuiltinStrategies() {
		if s.ID == id {
			return &s
		}
	}
	return nil
}

// Apply 把模板默认值与用户覆盖值合并, 得到最终执行参数。
//
// 合并规则(关键设计):
//   - 用户显式提供的字段优先(override 覆盖 defaults), 包括"显式设为 false" ——
//     因此 Params 里凡需要"能关掉模板默认"的开关都用 *bool(EnableArp/
//     EnableExternal), 否则 false 与"未填写"无法区分, 用户永远关不掉。
//   - 模板参数按需补齐 Params.Target/IP/CIDR/URL 等目标字段(模板不定义目标)。
//   - 未指定策略/策略 ID 非法时按 custom 处理: 只用用户值, 不加任何模板默认,
//     保证"用户完全掌控"这一路径始终可用。
func Apply(strategyID string, user Params) Params {
	st := StrategyByID(strategyID)
	if st == nil {
		return user // custom 或未知 ID: 不加模板默认
	}
	out := st.Defaults
	// 目标类字段: 模板不定义, 一律以用户值为准
	out.Target, out.IP, out.CIDR, out.URL = user.Target, user.IP, user.CIDR, user.URL
	if user.Ports != "" {
		out.Ports = user.Ports
	}
	if user.Timeout > 0 {
		out.Timeout = user.Timeout
	}
	if user.Concurrency > 0 {
		out.Concurrency = user.Concurrency
	}
	if user.Rate > 0 {
		out.Rate = user.Rate
	}
	if user.EnableNuclei {
		out.EnableNuclei = true
	}
	// 模板默认关 Nuclei 时用户可开启, 反之模板默认开时用户无法用 bool 关闭 ——
	// 故这里用"用户为 true 才置 true"的保守合并; 需要显式关闭请用 custom 策略。
	if user.NucleiTags != "" {
		out.NucleiTags = user.NucleiTags
	}
	if user.NucleiTagsExclude != "" {
		out.NucleiTagsExclude = user.NucleiTagsExclude
	}
	if user.EnableArp != nil {
		out.EnableArp = user.EnableArp
	}
	if user.EnableExternal != nil {
		out.EnableExternal = user.EnableExternal
	}
	if user.EnableSynScan {
		out.EnableSynScan = true
	}
	// 抓包: 用户开则开; 用户显式关不掉模板的"开"(同上, 需要关闭请用 custom)
	if user.Capture {
		out.Capture = true
	}
	if user.CaptureDevice != "" {
		out.CaptureDevice = user.CaptureDevice
	}
	if user.CaptureFilter != "" {
		out.CaptureFilter = user.CaptureFilter
	}
	if user.CaptureMaxBytes > 0 {
		out.CaptureMaxBytes = user.CaptureMaxBytes
	}
	// WebDeep 与抓包同口径: 用户开则开; 要关掉请用 custom 策略(bool 无法表达
	// "显式关闭" vs "未填写")。
	if user.WebDeep {
		out.WebDeep = true
	}
	return out
}
