// packyaml.go config.yaml 的极简解析(只支持模板元信息需要的两种形态)。
//
// 为什么不用 yaml.v3: 见 pack.go 文件头 —— 本包刻意保持"只依赖 models + 标准库",
// 而模板元信息只有标量和一个字符串列表, 为此引入完整 YAML 实现不划算。
//
// 支持的形态:
//
//	name: 某某客户模板        # key: value(值两侧空白剥除, 支持 # 行尾注释)
//	sections:                # key: 后为空 -> 进入列表模式
//	  - summary              # - item
//	  - vulns
//
// 不支持(静默跳过并记 warning, 不报错): 嵌套 map、多行折叠、引号内的 #、锚点。
// 理由: 用户手写 config.yaml 写错时, "忽略这一行 + 告警"远好于"整份模板加载失败"。
package report

import (
	"strconv"
	"strings"
)

// ParsePackConfig 解析 config.yaml 文本, 返回配置与告警(解析永不失败)。
func ParsePackConfig(text string) (PackConfig, []string) {
	var cfg PackConfig
	var warnings []string
	// 当前处于哪个 key 的列表模式(空 = 不在列表中)
	listKey := ""
	seen := map[string]bool{}
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// 列表项: "- value" / "-value"
		if strings.HasPrefix(trimmed, "-") {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if listKey == "" {
				warnings = append(warnings, "config.yaml 第 "+strconv.Itoa(i+1)+" 行列表项不在任何字段下(已忽略)")
				continue
			}
			if listKey == "sections" && item != "" {
				cfg.Sections = append(cfg.Sections, stripComment(item))
			}
			continue
		}
		idx := strings.Index(trimmed, ":")
		if idx < 0 {
			warnings = append(warnings, "config.yaml 第 "+strconv.Itoa(i+1)+" 行不是 key: value(已忽略)")
			continue
		}
		key := strings.TrimSpace(trimmed[:idx])
		val := stripComment(strings.TrimSpace(trimmed[idx+1:]))
		listKey = ""         // 新的 key 出现 -> 结束上一个列表
		if seen[key] && val == "" {
			continue // 重复且是列表起始, 合并到同一列表(用户可能分段写)
		}
		seen[key] = true
		switch key {
		case "name":
			cfg.Name = val
		case "client":
			cfg.Client = val
		case "logo":
			cfg.Logo = val
		case "accent", "theme", "color":
			cfg.Accent = val
		case "footer":
			cfg.Footer = val
		case "cover":
			if v, ok := parseBool(val); ok {
				b := v
				cfg.Cover = &b
			} else {
				warnings = append(warnings, "config.yaml 的 cover 不是布尔值(已忽略): "+val)
			}
		case "sections":
			if val != "" {
				// 行内列表: sections: summary, vulns
				for _, s := range strings.Split(val, ",") {
					if s = strings.TrimSpace(s); s != "" {
						cfg.Sections = append(cfg.Sections, s)
					}
				}
			} else {
				listKey = "sections"
			}
		default:
			warnings = append(warnings, "config.yaml 未知字段(已忽略): "+key)
		}
	}
	return cfg, warnings
}

// stripComment 去掉行尾注释: 只有"空白 + #"才算注释起点。
//
// 为什么不能把"以 # 开头"也当注释: accent 的取值是 #4f46e5 这种颜色值, 而传入
// 的值已经过 TrimSpace, 行首信息丢失 —— 判 i==0 会把所有主题色吃掉(实测踩到)。
// YAML 的注释规则同样是"# 前需空白或位于行首", 这里按"需前置空白"实现。
func stripComment(s string) string {
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

// parseBool 识别 YAML 常用布尔写法。
func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	return false, false
}
