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

const defaultPromptCapture = `基于以下 Yugsight 实时抓包结果, 请输出:
1. 网络流量状态总体结论(流量规模、主要协议/服务分布)
2. 风险点与根因分析(可疑流量、扫描探测、异常行为等, 逐条说明判断依据)
3. 分步骤排查/处置建议(必要时附交换机/路由器命令)

分析时间: {{time}}
资产信息: {{asset_info}}
原始抓包数据(已脱敏):
{{raw_data}}
历史参考(结构化记忆):
{{structured_memory}}`

const defaultPromptScan = `基于以下 Yugsight 扫描结果, 请输出:
1. 漏洞风险总体评估(结合等级分布与资产暴露面说明评估依据)
2. 逐条漏洞的风险分析与修复建议(按风险优先级排序, 区分 Windows / Linux / 中间件)
3. 复核与验证建议(含如何确认已修复)

分析时间: {{time}}
资产信息: {{asset_info}}
扫描结果(漏洞清单):
{{scan_result}}
原始数据(已脱敏):
{{raw_data}}
历史参考(结构化记忆):
{{structured_memory}}`

const defaultPromptMonitor = `基于以下 Yugsight 节点监控数据(指标/告警事件), 请输出:
1. 设备/节点当前健康状态判定(在线状态、资源水位)
2. 异常与告警分析(原因、影响范围, 逐条说明判断依据)
3. 分步骤处置建议(含如何验证恢复)

分析时间: {{time}}
设备指标:
{{metric_data}}
原始监控数据(已脱敏):
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
