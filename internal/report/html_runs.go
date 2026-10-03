package report

// 模板编辑器富文本子集解析(2026-09-25 用户: 报告模板的页眉/页脚/标题/版权/
// 检测工具/免责声明/报告人/生成时间要"像 Word 一样"可编辑字体颜色/背景色/格式)。
//
// 零第三方依赖硬约束下不用 HTML 库, 手写一个只认识有限标签的迷你解析器:
//
//	允许: b/strong, i/em, u, s/strike/del, br, span[style], font[color|size|face],
//	      块级标签(结构); span/font 的 style 支持 color/background-color/
//	      font-size/font-family
//	丢弃: script/style/iframe/object/embed 等及其内容(防注入)
//	其余: 剥标签保留文本
//
// 2026-09-26 白名单扩展(用户口径"我要生效"): 新增删除线与字体族 —— 工具条上
// 有对应按钮, 白名单不收就等于"点了没反应、保存还被清洗"。font-family 是唯一
// 自由文本取值, 由 sanitizeFontFamily 收口(防闭合 style 声明注入)。
//
// 两个出口共用同一份解析:
//   - SanitizeRichHTML: 解析后再序列化回最小合法 HTML —— 存进 .visual.json 的
//     永远是白名单内的干净片段(粘贴进来的恶意内容在解析阶段就被拆掉);
//   - HTMLToRuns: 解析成 Run 序列烤进模板 docx(Word 出口走 run 属性, 不依赖 HTML)。

import (
	"fmt"
	"strconv"
	"strings"
)

// richStyle 一段文本的格式(解析期合并用)。
type richStyle struct {
	bold, italic, uline, strike bool
	color, bg, font             string
	size                        int // 半点; 0 = 继承
}

// sanitizeFontFamily 字体族值清洗(2026-09-26 白名单扩展: 工具条要能改字体)。
// 字体名是白名单里唯一的"自由文本"型取值, 必须自己收口 —— 值会被写进 style
// 属性, 若含 ; : } < > 就能闭合当前声明注入别的 CSS。
// 允许: 字母/数字/空格/逗号/引号/连字符/点/中文(宋体、微软雅黑这类中文名)。
func sanitizeFontFamily(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 64 {
		return ""
	}
	for _, c := range v {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == ' ' || c == ',' || c == '-' || c == '.' || c == '"' || c == '\'':
		case c >= 0x4E00 && c <= 0x9FFF:
		default:
			return ""
		}
	}
	return v
}

// richPart 解析产物: 一段文本(或一个换行)。
type richPart struct {
	text string
	br   bool
	st   richStyle
}

var (
	// dropTags 内容整体丢弃(安全边界: 脚本/对象类标签)。
	dropTags = map[string]bool{
		"script": true, "style": true, "iframe": true, "object": true,
		"embed": true, "link": true, "meta": true, "form": true, "input": true,
	}
	// blockTags 块级标签: 边界处产生换行(Chrome 的 contenteditable 回车默认
	// 包 <div>, 不处理的话多行文本会粘成一行)。
	blockTags = map[string]bool{
		"div": true, "p": true, "h1": true, "h2": true, "h3": true,
		"h4": true, "h5": true, "h6": true, "section": true, "article": true,
		"header": true, "footer": true, "li": true,
	}
	// namedColors 常见命名色(execCommand/旧浏览器 <font color="red"> 可能产出)。
	namedColors = map[string]string{
		"black": "000000", "white": "FFFFFF", "red": "FF0000", "green": "008000",
		"blue": "0000FF", "yellow": "FFFF00", "orange": "FFA500", "purple": "800080",
		"gray": "808080", "grey": "808080", "silver": "C0C0C0", "teal": "008080",
		"navy": "000080", "maroon": "800000", "olive": "808000", "lime": "00FF00",
		"aqua": "00FFFF", "cyan": "00FFFF", "magenta": "FF00FF",
		"transparent": "", "auto": "", "inherit": "",
	}
)

// trimFontQuotes 去掉字体名两侧引号(CSS 里含空格的字体名规范写法是带引号,
// 存进 Run 的应是裸字体名)。
func trimFontQuotes(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return strings.TrimSpace(v[1 : len(v)-1])
		}
	}
	return v
}

// parseColor 颜色值归一为"不带 # 的 RRGGBB"; 非法/空 返回 ""。
// 支持 #RGB / #RRGGBB / rgb(r,g,b) / 命名色。
func parseColor(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if c, ok := namedColors[strings.ToLower(v)]; ok {
		return c
	}
	if strings.HasPrefix(v, "#") {
		h := v[1:]
		if len(h) == 3 {
			h = fmt.Sprintf("%c%c%c%c%c%c", h[0], h[0], h[1], h[1], h[2], h[2])
		}
		if len(h) == 6 && isHexStr(h) {
			return strings.ToUpper(h)
		}
		return ""
	}
	if strings.HasPrefix(strings.ToLower(v), "rgb") {
		open := strings.IndexByte(v, '(')
		close := strings.LastIndexByte(v, ')')
		if open > 0 && close > open {
			parts := strings.Split(v[open+1:close], ",")
			if len(parts) == 3 {
				var rgb [3]int
				ok := true
				for i, p := range parts {
					n, err := strconv.Atoi(strings.TrimSpace(p))
					if err != nil || n < 0 || n > 255 {
						ok = false
						break
					}
					rgb[i] = n
				}
				if ok {
					return fmt.Sprintf("%02X%02X%02X", rgb[0], rgb[1], rgb[2])
				}
			}
		}
		return ""
	}
	return ""
}

func isHexStr(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// parseFontSize 字号归一为半点。px: 1pt=4/3px → 半点≈px*1.5; pt: *2;
// 语义档(small/large...)映射常用档; 非法返回 0(继承)。
func parseFontSize(v string) int {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return 0
	}
	if strings.HasSuffix(v, "px") {
		n, err := strconv.Atoi(strings.TrimSpace(v[:len(v)-2]))
		if err != nil || n < 6 {
			return 0
		}
		return n * 3 / 2
	}
	if strings.HasSuffix(v, "pt") {
		n, err := strconv.Atoi(strings.TrimSpace(v[:len(v)-2]))
		if err != nil || n < 4 {
			return 0
		}
		return n * 2
	}
	switch v {
	case "xx-small", "x-small":
		return 16
	case "small":
		return 18
	case "medium":
		return 24
	case "large":
		return 32
	case "x-large":
		return 40
	case "xx-large":
		return 48
	}
	return 0
}

// fontTagSize <font size="n"> 的 1-7 档 → 半点。
func fontTagSize(n int) int {
	switch n {
	case 1:
		return 16
	case 2:
		return 18
	case 3:
		return 24
	case 4:
		return 32
	case 5:
		return 44
	case 6:
		return 52
	case 7:
		return 60
	}
	return 0
}

// ---- 解析(单次调用一个局部栈, 并发安全) ----

// parseRich 把 HTML 片段解析成 part 序列(递归单遍扫描, 只认白名单标签)。
func parseRich(s string, base richStyle) []richPart {
	var parts []richPart
	var buf strings.Builder
	stack := []richStyle{} // span/font 开标签前的样式快照(闭合时回滚)

	flush := func() {
		// 不 TrimSpace 单段: 段与段之间的空格是真实内容(如 "</b> | {{time}}"
		// 里 </b> 后那个空格), 裁掉会丢字; 首尾空白由出口统一 TrimSpace。
		t := buf.String()
		if t != "" {
			parts = append(parts, richPart{text: t, st: base})
		}
		buf.Reset()
	}
	br := func() {
		flush()
		// 去重: <div>开</div>闭 一对会触发两次边界, 只记一个换行
		if len(parts) > 0 && parts[len(parts)-1].br {
			return
		}
		parts = append(parts, richPart{br: true, st: base})
	}

	i := 0
	for i < len(s) {
		c := s[i]
		if c == '&' {
			// HTML 实体: 找 ';' 判定, 非法的当普通字符
			if semi := strings.IndexByte(s[i:], ';'); semi > 0 && semi < 12 {
				dec := decodeEntity(s[i : i+semi+1])
				if dec != s[i:i+semi+1] {
					buf.WriteString(dec)
					i += semi + 1
					continue
				}
			}
			buf.WriteByte('&')
			i++
			continue
		}
		if c != '<' {
			buf.WriteByte(c)
			i++
			continue
		}
		end := strings.IndexByte(s[i:], '>')
		if end < 0 {
			// 无闭合 '>' 的残片: 当纯文本
			buf.WriteString(s[i:])
			break
		}
		tagRaw := s[i : i+end+1]
		i += end + 1
		// 标签名 = < 之后到第一个 空格/制表符/>/斜杠 之前(属性区不算名字,
		// 否则 <span style="..."> 会被当成整串标签名而失配所有 case)。
		// 先剥闭合斜杠再截名: </b> 的 '/' 在首位, 顺序反了会把名字截空。
		name := tagRaw[1:]
		isClose := strings.HasPrefix(name, "/")
		if isClose {
			name = name[1:]
		}
		if sp := strings.IndexAny(name, " \t/>"); sp >= 0 {
			name = name[:sp]
		}
		tag := strings.ToLower(name)
		if tag == "" {
			continue
		}
		// 标签名合法性: 只认字母开头
		if tag == "" || !isAlpha(tag[0]) {
			continue
		}
		// 先 flush 再改样式: buffer 里文本的格式是"写入时"的, 若等标签改了
		// base 再 flush, 快照取到的是新状态 —— <b>加粗</b> 会丢粗(实测踩坑)。
		flush()

		switch {
		case tag == "br":
			br()
		case tag == "b" || tag == "strong":
			if !isClose {
				base.bold = true
			} else {
				base.bold = false
			}
		case tag == "i" || tag == "em":
			if !isClose {
				base.italic = true
			} else {
				base.italic = false
			}
		case tag == "u":
			if !isClose {
				base.uline = true
			} else {
				base.uline = false
			}
		case tag == "s" || tag == "strike" || tag == "del":
			// 删除线(2026-09-26 白名单扩展): execCommand('strikeThrough') 产出
			// <strike>, 现代浏览器产 <s>; docx 侧写 w:strike
			if !isClose {
				base.strike = true
			} else {
				base.strike = false
			}
		case tag == "span" || tag == "font":
			if !isClose {
				stack = append(stack, base)
				applyTagStyle(tagRaw, &base)
			} else if len(stack) > 0 {
				base = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
		case blockTags[tag]:
			br()
		}
		// dropTags 内容整体丢弃(跳过到同名闭合标签)
		if dropTags[tag] && !isClose {
			i = skipBalanced(s, i, tag)
		}
		// 其它未识别标签: 剥掉, 内容继续按文本/子标签处理
	}
	flush()
	// 首尾换行不渲染(字段开头/结尾不应多一个空行)
	for len(parts) > 0 && parts[0].br {
		parts = parts[1:]
	}
	for len(parts) > 0 && parts[len(parts)-1].br {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// skipBalanced 从 pos 起跳过 <tag>...</tag>(找第一个同名闭合标签)。
func skipBalanced(s string, pos int, tag string) int {
	rest := strings.ToLower(s[pos:])
	idx := strings.Index(rest, "</"+tag)
	if idx < 0 {
		return len(s)
	}
	return pos + idx + len(tag) + 3
}

// applyTagStyle 解析 <span style="..."> / <font color= size=> 的开标签样式。
func applyTagStyle(tagRaw string, base *richStyle) {
	attrs := tagAttrs(tagRaw)
	if st, ok := attrs["style"]; ok {
		for _, kv := range strings.Split(st, ";") {
			eq := strings.IndexByte(kv, ':')
			if eq < 0 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(kv[:eq]))
			v := strings.TrimSpace(kv[eq+1:])
			switch k {
			case "color":
				if c := parseColor(v); c != "" {
					base.color = c
				}
			case "background-color", "background":
				if c := parseColor(v); c != "" {
					base.bg = c
				}
			case "font-size":
				if n := parseFontSize(v); n > 0 {
					base.size = n
				}
			case "font-family":
				// 2026-09-26 白名单扩展: 工具条的字体下拉
				// (execCommand('fontName') 产 <font face=>, 部分浏览器产 span style)
				if f := sanitizeFontFamily(trimFontQuotes(v)); f != "" {
					base.font = f
				}
			}
		}
	}
	if fc, ok := attrs["face"]; ok {
		if f := sanitizeFontFamily(trimFontQuotes(fc)); f != "" {
			base.font = f
		}
	}
	if c, ok := attrs["color"]; ok {
		if cc := parseColor(c); cc != "" {
			base.color = cc
		}
	}
	if sz, ok := attrs["size"]; ok {
		if n, err := strconv.Atoi(sz); err == nil {
			if m := fontTagSize(n); m > 0 {
				base.size = m
			}
		}
	}
}

// tagAttrs 提取 <tag k="v" ...> 的属性(只认引号/裸值属性, 简化且安全)。
func tagAttrs(tagRaw string) map[string]string {
	out := map[string]string{}
	lt := strings.IndexAny(tagRaw, " \t")
	if lt < 0 {
		return out
	}
	rest := tagRaw[lt+1:]
	if gt := strings.LastIndexByte(rest, '>'); gt > 0 {
		rest = rest[:gt]
	}
	for rest != "" {
		rest = strings.TrimSpace(rest)
		if rest == "" {
			break
		}
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		after := strings.TrimSpace(rest[eq+1:])
		if strings.HasPrefix(after, `"`) {
			end := strings.IndexByte(after[1:], '"')
			if end < 0 {
				break
			}
			out[key] = after[1 : end+1]
			rest = after[end+2:]
		} else if strings.HasPrefix(after, "'") {
			end := strings.IndexByte(after[1:], byte('\''))
			if end < 0 {
				break
			}
			out[key] = after[1 : end+1]
			rest = after[end+2:]
		} else {
			sp := strings.IndexAny(after, " \t")
			if sp < 0 {
				out[key] = after
				rest = ""
			} else {
				out[key] = after[:sp]
				rest = after[sp+1:]
			}
		}
	}
	return out
}

// decodeEntity 解码单个 HTML 实体; 非实体原样返回。
func decodeEntity(s string) string {
	if !strings.HasPrefix(s, "&") || !strings.HasSuffix(s, ";") {
		return s
	}
	name := s[1 : len(s)-1]
	switch name {
	case "nbsp":
		return "\u00A0"
	case "amp":
		return "&"
	case "lt":
		return "<"
	case "gt":
		return ">"
	case "quot":
		return "\""
	case "apos":
		return "'"
	}
	if strings.HasPrefix(name, "#x") || strings.HasPrefix(name, "#X") {
		if n, err := strconv.ParseInt(name[2:], 16, 32); err == nil && n > 0 && n < 0x110000 {
			return string(rune(n))
		}
		return s
	}
	if n, err := strconv.Atoi(name); err == nil && n > 0 && n < 0x110000 {
		return string(rune(n))
	}
	return s
}

// ---- 出口 ----

// SanitizeRichHTML 清洗富文本片段: 解析后只回写白名单五件套。
// 纯文本输入原样返回(只剥不认识的标签); 空/纯空白 返回 ""。
func SanitizeRichHTML(in string) string {
	parts := parseRich(in, richStyle{})
	var b strings.Builder
	writePartsHTML(&b, parts)
	return strings.TrimSpace(b.String())
}

// RichPlainText 富文本片段 → 纯文本(页眉/文件名/摘要等纯文本位置用)。
func RichPlainText(in string) string {
	parts := parseRich(in, richStyle{})
	var b strings.Builder
	for _, p := range parts {
		if p.br {
			b.WriteString("\n")
			continue
		}
		b.WriteString(p.text)
	}
	return strings.TrimSpace(b.String())
}

// HTMLToRuns 富文本片段 → Run 序列(模板 docx 的"烤入"路径)。
// base 给该行默认格式; 片段内标签逐项覆盖。空片段返回 nil(调用方回退占位符)。
func HTMLToRuns(in string, base Run) []Run {
	parts := parseRich(in, richStyle{
		bold: base.Bold, italic: base.Italic, uline: base.Uline,
		color: base.Color, bg: base.Bg, size: base.Size,
	})
	var runs []Run
	for _, p := range parts {
		if p.br {
			runs = append(runs, Run{Text: "\n"})
			continue
		}
		r := Run{Text: p.text}
		if p.st.bold {
			r.Bold = true
		}
		if p.st.italic {
			r.Italic = true
		}
		if p.st.uline {
			r.Uline = true
		}
		if p.st.strike {
			r.Strike = true
		}
		if p.st.color != "" {
			r.Color = p.st.color
		}
		if p.st.bg != "" {
			r.Bg = p.st.bg
		}
		if p.st.size > 0 {
			r.Size = p.st.size
		}
		if p.st.font != "" {
			r.Font = p.st.font
		}
		runs = append(runs, r)
	}
	if len(runs) == 0 {
		return nil
	}
	return runs
}

// writePartsHTML part 序列 → 最小 HTML(b/i/u/br/span + 转义文本)。
func writePartsHTML(b *strings.Builder, parts []richPart) {
	for _, p := range parts {
		if p.br {
			b.WriteString("<br>")
			continue
		}
		text := escapeHTMLMin(p.text)
		if p.st.bold {
			b.WriteString("<b>")
		}
		if p.st.italic {
			b.WriteString("<i>")
		}
		if p.st.uline {
			b.WriteString("<u>")
		}
		if p.st.strike {
			b.WriteString("<s>")
		}
		needSpan := p.st.color != "" || p.st.bg != "" || p.st.size > 0 || p.st.font != ""
		if needSpan {
			var st []string
			if p.st.color != "" {
				st = append(st, "color:#"+p.st.color)
			}
			if p.st.bg != "" {
				st = append(st, "background-color:#"+p.st.bg)
			}
			if p.st.size > 0 {
				// 半点 → px(近似回显: 24 半点=12pt≈16px)
				st = append(st, fmt.Sprintf("font-size:%dpx", p.st.size*2/3))
			}
			if p.st.font != "" {
				st = append(st, "font-family:"+p.st.font)
			}
			b.WriteString("<span style=\"" + strings.Join(st, ";") + "\">")
		}
		b.WriteString(text)
		if needSpan {
			b.WriteString("</span>")
		}
		if p.st.strike {
			b.WriteString("</s>")
		}
		if p.st.uline {
			b.WriteString("</u>")
		}
		if p.st.italic {
			b.WriteString("</i>")
		}
		if p.st.bold {
			b.WriteString("</b>")
		}
	}
}

// escapeHTMLMin 最小转义(& 优先, 防止二次解码错位)。
func escapeHTMLMin(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
