// prompt.go Prompt 模板: 三套预设 + 占位变量渲染。
//
// 渲染是**纯字符串替换**(不用正则/模板引擎): 模板由用户自由编辑,
// 引入模板引擎等于引入一套注入面(如 Go template 的函数调用),
// 而这里只需要把 {{var}} 换成数据, strings.Replace 是最小实现。
//
// 未知变量(用户自创的 {{xxx}})原样保留不替换 —— 静默抹掉会让用户
// 以为变量生效了(实际是空的), 保留原样才能一眼看出"这不是内置变量"。
package ai

import (
	"sort"
	"strings"
)

// 三套预设模板(用户可在 AI 配置页修改, 一键恢复默认)。
//
// 占位变量(内置, UI 展示):
//
//	{{raw_data}}           原始数据(脱敏后, 全部模块)
//	{{asset_info}}         资产 IP 清单
//	{{scan_result}}        扫描漏洞清单(扫描类模块; 其它模块为 无)
//	{{metric_data}}        指标/事件数据(监控类模块; 其它模块为 无)
//	{{time}}               分析时间
//	{{structured_memory}}  结构化记忆库检索结果(无数据时为 无历史记忆)

const defaultPromptCapture = `你是资深网络流量安全分析师。基于以下 Yugsight 抓包数据做专业研判:

【输出要求】
1. 结论先行: 一句话明确"是否存在异常/风险"(是/否)。
2. 若存在异常/风险, 按结构详细展开(体现专业性):
   - 威胁概述: 1-2 句概括威胁性质(端口扫描/数据外传/恶意协议/DoS 等)与整体风险等级(严重/高危/中危/低危)。
   - 逐条发现: 每个可疑流量点分条, 各含 [可疑行为 / 判断依据(五元组·协议·报文特征) / 风险等级 / 潜在影响]。
   - 攻击链关联: 多条流量指向同一攻击链(如 扫描→爆破→外传)时说明关联关系。
   - 处置建议: 具体缓解/阻断措施(封禁源 IP、收紧 ACL、排查主机等)。
3. 若未发现异常, 明确写"未发现显著异常", 并用一句话说明研判覆盖的流量范围(协议/时段)。

分析时间: {{time}}
资产信息: {{asset_info}}
抓包数据(已脱敏):
{{raw_data}}
历史参考(结构化记忆):
{{structured_memory}}`

const defaultPromptScan = `你是资深漏洞评估与安全专家。基于以下 Yugsight 扫描结果做专业研判:

【输出要求】
1. 结论先行: 一句话明确"是否存在风险"(是/否)及整体风险态势(严重/高危/中危/低危)。
2. 若存在风险, 按结构详细展开(体现专业性):
   - 风险概述: 1-2 句概括漏洞分布(等级构成、受影响资产面、可利用性)。
   - 关键漏洞: 按风险等级从高到低逐条, 各含 [漏洞 / 受影响资产 / 等级 / 风险说明(可被如何利用·影响范围) / 修复要点]。
   - 优先处置: 指出最需优先修复的 1-3 项及理由(如 可远程未授权利用、数据泄露风险)。
   - 修复建议: 版本升级/配置加固/补偿控制等具体建议。
3. 若未发现风险, 明确写"未发现显著风险", 并用一句话说明评估覆盖的资产与漏洞面。

分析时间: {{time}}
资产信息: {{asset_info}}
扫描结果(漏洞清单):
{{scan_result}}
原始数据(已脱敏):
{{raw_data}}
历史参考(结构化记忆):
{{structured_memory}}`

const defaultPromptMonitor = `你是资深运维与基础设施安全专家。基于以下 Yugsight 节点监控数据(指标/告警)做专业研判:

【输出要求】
1. 结论先行: 一句话明确"是否存在异常"(是/否)及整体健康状况(正常/存在风险/紧急)。
2. 若存在异常, 按结构详细展开(体现专业性):
   - 异常概述: 1-2 句概括异常性质(性能瓶颈/服务中断/资源耗尽/安全告警等)与严重程度。
   - 逐条异常: 每个异常指标/告警分条, 各含 [设备 / 指标或告警 / 当前值与阈值 / 根因分析 / 影响面]。
   - 关联推断: 多个异常指向同一根因(如 磁盘满→服务异常)时说明因果链。
   - 处置建议: 具体的排查/缓解/恢复措施(按优先级排序)。
3. 若未发现异常, 明确写"未发现显著异常", 并用一句话说明监控覆盖的设备与指标范围。

分析时间: {{time}}
设备指标:
{{metric_data}}
原始数据(已脱敏):
{{raw_data}}
历史告警与指标(结构化记忆):
{{structured_memory}}`

// DefaultPrompt 某模板键的预设内容(恢复默认用)。
func DefaultPrompt(key string) string {
	switch key {
	case TplCapture:
		return defaultPromptCapture
	case TplScan:
		return defaultPromptScan
	case TplMonitor:
		return defaultPromptMonitor
	}
	return ""
}

// Render 把模板里的 {{var}} 替换为 vars 中的值。
//
// 口径:
//   - 已知变量: 有值 → 替换; 无值 → 替换为 "无"(显式"无"比留空好,
//     LLM 看到"资产信息: 无"能明确知道是空数据而不是被截断);
//   - 未知变量: 原样保留(见文件头注释)。
func Render(content string, vars map[string]string) string {
	known := make(map[string]bool, len(PromptVars))
	for _, v := range PromptVars {
		known[v] = true
	}
	var b strings.Builder
	b.Grow(len(content) + 256)
	for {
		i := strings.Index(content, "{{")
		if i < 0 {
			b.WriteString(content)
			break
		}
		j := strings.Index(content[i:], "}}")
		if j < 0 {
			b.WriteString(content)
			break
		}
		end := i + j + 2
		token := strings.TrimSpace(content[i+2 : i+j])
		b.WriteString(content[:i])
		if known[token] {
			if v, ok := vars[token]; ok {
				b.WriteString(v)
			} else {
				b.WriteString("无")
			}
		} else {
			b.WriteString("{{" + token + "}}")
		}
		content = content[end:]
	}
	return b.String()
}

// SortVars 变量名排序输出(模板页展示用)。
func SortVars(vars []string) []string {
	out := make([]string, len(vars))
	copy(out, vars)
	sort.Strings(out)
	return out
}
