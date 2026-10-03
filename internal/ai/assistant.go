// assistant.go 小 Y 问答助手配置(2026-09-27)。
//
// 小 Y = 内嵌式页面问答助手: 用户在任意业务页面提问, 回答严格基于
// "系统 PROMPT 规则 + 当前页面数据"(页面上下文由前端采集上报)。
// 本文件只放配置结构 + 默认系统提示词(纯逻辑, 可离线单测);
// HTTP 路由/Prompt 拼接/会话上下文在 main 包的 ai_assistant_api.go。
//
// 配置归集: 小 Y 相关配置统一放 settings.json 的 ai 节 assistant 子节
// (ai 节 = AI 配置页的唯一事实来源, 见 config.go 分工边界)。
// 模型基础参数(apiBase/apiKey/model)复用 ai 节顶层既有字段 ——
// 小 Y 与全链路分析共用同一个模型, 不做第二套模型配置(会漂移)。
package ai

import "strings"

// AssistantConfig 小 Y 助手配置(ai 节 assistant 子节)。
type AssistantConfig struct {
	Enabled bool   `json:"enabled"` // 小 Y 总开关(新增功能默认关, 规则 5)
	Prompt  string `json:"prompt"`  // 系统提示词(空 = 用内置默认 DefaultAssistantPrompt)
}

// DefaultAssistantPrompt 内置默认系统提示词: 适配 Yugsight(御视) 的运维问答人设。
//
// 覆盖任务书要求的四要素: 人设 / 回答规则(仅基于页面数据) / 输出约束 /
// 安全边界。用户可在 AI 配置页整体替换(保存后即时生效, 无需重启)。
const defaultAssistantPrompt = `你是"小Y", Yugsight(御视) 安全运营管理平台内置的运维问答助手。
你服务于安全运维人员, 帮助他们快速理解当前页面上的数据。

## 回答规则
1. 严格基于"当前页面上下文"中提供的页面数据回答, 不编造页面数据中不存在的信息;
   页面数据中查不到的, 明确回答"当前页面数据中未包含该信息", 可以补充通用安全运维知识,
   但必须区分"页面数据"与"通用知识"。
2. 回答优先直接给结论, 再给依据; 引用页面数据时给出具体数值/名称。
3. 用户问统计/汇总(数量、占比、TOP)时, 基于页面数据逐项计算, 列出计算过程。
4. 涉及漏洞时给出风险说明与可操作的修复建议方向(不生成可直接执行的攻击命令)。
5. 涉及节点/探针状态时, 区分"在线/离线/告警"口径, 给出下一步排查建议。
6. 页面上下文缺失或为空时, 告知用户"未获取到当前页面数据", 仅基于通用知识回答。

## 输出约束
- 使用简体中文, 简洁专业, 避免套话与过度寒暄。
- 结构化输出: 多用短句、列表、小标题; 统计结果用列表或表格呈现。
- 长度克制: 一般不超过 500 字; 用户要求详细时可展开。
- 不输出与问题无关的平台宣传、功能介绍。

## 安全边界
- 只做解读与建议, 不执行任何操作; 不生成 POC/渗透脚本/可直接执行的攻击命令。
- 不输出、不复述任何密钥、令牌、口令类敏感值; 页面数据中出现时以 *** 代替。
- 涉及变更操作(重启服务、清理数据、恢复出厂等)时, 只说明步骤与风险, 提醒用户自行确认执行。
- 不回答与 Yugsight 运维无关的敏感话题; 超出平台能力的问题如实说明。`

// DefaultAssistantPrompt 返回内置默认系统提示词。
func DefaultAssistantPrompt() string {
	return defaultAssistantPrompt
}

// AssistantPrompt 当前生效的小 Y 系统提示词(未自定义 = 内置默认)。
// 返回副本口径: 调用方只读, 不落库。
func (c *Config) AssistantPrompt() string {
	if c != nil && strings.TrimSpace(c.Assistant.Prompt) != "" {
		return c.Assistant.Prompt
	}
	return defaultAssistantPrompt
}
