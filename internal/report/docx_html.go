// docx_html.go 块序列 → HTML: Word 模板的 HTML / PDF 输出口。
//
// 同一份"模板封面 + 数据章节"块序列, 三条出口:
//
//	WriteDocx       → .docx(Word 文档)
//	RenderWordReport → 自包含 HTML(离线可打开, 打印分页/页眉页脚与内置报告一致)
//	PrintHTML       → 自动唤起打印的 PDF 通道(纯标准库无 PDF 库, 与既有口径一致)
//
// HTML 渲染只映射块模型用到的子集(段落样式/加粗/颜色/对齐/表格), 不复制
// 内置 HTML 报告的图表代码 —— 块模型里没有图表, 保持两出口"所见即所得"一致。
package report

import (
	"fmt"
	"html"
	"path/filepath"
	"strings"
)

// WordPage HTML 页面元信息(页眉页脚/主题色)。
type WordPage struct {
	Title  string
	Header Header // 已展开占位符(调用方用 EffectiveHeader + ExpandHeaderValues 处理)
	Accent string
	// HeaderHTML/FooterHTML 页眉/页脚中段的富文本(已清洗的白名单 HTML 片段)。
	// 2026-09-25 模板编辑器: 页眉页脚可带字体颜色/底色/格式 —— 纯文本字段
	// (Header.HeaderCenter)承载不了, 走这里直接注入(本包 SanitizeRichHTML
	// 产出的片段只含 b/i/u/br/span, 无注入面)。空 = 用纯文本字段。
	HeaderHTML string
	FooterHTML string
}

// BlocksToHTML 把块序列渲染为 HTML 片段(不带文档外壳, 供预览/组装复用)。
func BlocksToHTML(blocks []Block) string {
	var b strings.Builder
	for _, blk := range blocks {
		b.WriteString(blockHTML(blk))
	}
	return b.String()
}

func blockHTML(blk Block) string {
	if blk.Kind == "tbl" {
		return tableHTML(blk)
	}
	tag := "p"
	switch blk.Style {
	case "Title":
		tag = "h1"
	case "Heading1":
		tag = "h2"
	case "Heading2":
		tag = "h3"
	case "Heading3", "Heading4":
		tag = "h4"
	case "Heading5", "Heading6":
		tag = "h5"
	}
	attr := ""
	if blk.ID != "" {
		// HTML 锚点(如 copyright 章节), 供页面内 "版权信息" 跳转
		attr = ` id="` + blk.ID + `"`
	}
	// 段落级样式: 对齐 + 章节底色(Block.Shd, 与 docx pPr/shd 同数据源)
	var st []string
	if blk.Align == "center" {
		st = append(st, "text-align:center")
	}
	if blk.Shd != "" {
		st = append(st, "background-color:#"+blk.Shd)
	}
	style := ""
	if len(st) > 0 {
		style = ` style="` + strings.Join(st, ";") + `"`
	}
	var runs strings.Builder
	for _, r := range blk.Runs {
		runs.WriteString(runHTML(r))
	}
	if runs.String() == "" {
		return "<p>&nbsp;</p>" // 空段保留版式间距(与 Word 空行对应)
	}
	return fmt.Sprintf("<%s%s%s>%s</%s>", tag, attr, style, runs.String(), tag)
}

// imageMIME 媒体文件名 -> data URI 的 MIME(未知扩展按 png, 浏览器容忍)。
func imageMIME(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	default:
		return "image/png"
	}
}

func runHTML(r Run) string {
	// 图片 run: data URI 内联(报告是"单文件自包含"的硬约束, 不能引用外部图片路径)
	if r.MediaName != "" && r.ImageB64 != "" {
		style := ""
		if r.ImageW > 0 {
			style = fmt.Sprintf(" style=\"width:%dpx\"", r.ImageW)
		}
		return fmt.Sprintf(`<img src="data:%s;base64,%s" alt="%s"%s>`,
			imageMIME(r.MediaName), r.ImageB64, html.EscapeString(r.MediaName), style)
	}
	var b strings.Builder
	text := html.EscapeString(r.Text)
	// 换行: \n → <br>(先转义再替换, 转义不影响 \n)
	text = strings.ReplaceAll(text, "\n", "<br>")
	// 字色/底色/字号/字体族合并进一个 span(模板编辑器的字符格式能力)。
	// 字体名走 html.EscapeString 后再进 style: 白名单已在解析阶段收口, 这里是
	// 渲染侧的二次保险(Block 也可能来自手动上传的 .docx, 未过 parseRich)。
	var style []string
	if r.Color != "" {
		style = append(style, "color:#"+r.Color)
	}
	if r.Bg != "" {
		style = append(style, "background-color:#"+r.Bg)
	}
	if r.Size > 0 {
		// 半点 → pt(Size=24 → 12pt); px 在高分屏/打印下换算不一致, pt 更贴近 Word
		style = append(style, fmt.Sprintf("font-size:%.1fpt", float64(r.Size)/2))
	}
	if r.Font != "" {
		style = append(style, "font-family:"+html.EscapeString(r.Font))
	}
	if r.Bold {
		b.WriteString("<strong>")
	}
	if r.Italic {
		b.WriteString("<em>")
	}
	if r.Uline {
		b.WriteString("<u>")
	}
	if r.Strike {
		b.WriteString("<s>")
	}
	if len(style) > 0 {
		b.WriteString(`<span style="` + strings.Join(style, ";") + `">`)
	}
	b.WriteString(text)
	if len(style) > 0 {
		b.WriteString("</span>")
	}
	if r.Strike {
		b.WriteString("</s>")
	}
	if r.Uline {
		b.WriteString("</u>")
	}
	if r.Italic {
		b.WriteString("</em>")
	}
	if r.Bold {
		b.WriteString("</strong>")
	}
	if r.PageBreak {
		// 打印分页(屏幕浏览时不可见, 与 Word 分页符同语义)
		b.WriteString(`<span class="page-break"></span>`)
	}
	return b.String()
}

func tableHTML(blk Block) string {
	var b strings.Builder
	// 表格底色(逐章节样式的"章节底色"覆盖到表格; 与 docx tblPr/shd 同数据源)。
	// td 背景默认透明 → 表格底色透出来; 表头 th 有 CSS 背景(#f3f4f6)会盖住,
	// 与 Word 里"表头底纹优先于表格底色"的观感一致。
	if blk.Shd != "" {
		b.WriteString(`<table style="background-color:#` + blk.Shd + `">`)
	} else {
		b.WriteString("<table>")
	}
	for i, row := range blk.Rows {
		b.WriteString("<tr>")
		for _, c := range row.Cells {
			cell := ""
			for _, r := range c.Runs {
				cell += runHTML(r)
			}
			tag := "td"
			if i == 0 {
				tag = "th" // 首行当表头(与 Word 里模板习惯一致: 第一行加粗列名)
			}
			// 单元格底纹(Cell.Shd): 此前 HTML 出口静默丢了这个字段 —— 同一份
			// 块序列两出口观感必须一致(表头 F3F4F6 在 Word 里有色, HTML 里全白)
			var cs []string
			if c.Shd != "" {
				cs = append(cs, "background-color:#"+c.Shd)
			}
			attr := ""
			if len(cs) > 0 {
				attr = ` style="` + strings.Join(cs, ";") + `"`
			}
			b.WriteString("<" + tag + attr + ">" + cell + "</" + tag + ">")
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</table>")
	return b.String()
}

// RenderWordReport 组装完整自包含 HTML 文档(打印分页 + 页眉页脚 + 正文)。
func RenderWordReport(blocks []Block, page WordPage) string {
	accent := page.Accent
	if accent == "" {
		accent = "#1f3a5f"
	}
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\">\n<title>")
	b.WriteString(html.EscapeString(page.Title))
	b.WriteString("</title>\n<style>\n")
	b.WriteString(`  @page { size: A4; margin: 18mm 14mm 16mm 14mm; }
  * { box-sizing: border-box; }
  body { font-family: "Microsoft YaHei", "Segoe UI", "PingFang SC", sans-serif;
    color: #1f2937; background: #fff; margin: 0; font-size: 13px; }
  .page { max-width: 980px; margin: 0 auto; padding: 28px 32px 60px; }
  .print-header, .print-footer { display: none; }
  @media print {
    .print-header, .print-footer { display: block; position: fixed; left: 0; right: 0;
      font-size: 10.5px; color: #6b7280; }
    .print-header { top: -10mm; border-bottom: 1px solid #e5e7eb; padding-bottom: 3mm; }
    .print-footer { bottom: -10mm; border-top: 1px solid #e5e7eb; padding-top: 3mm; }
    .print-header .l, .print-footer .l { float: left; }
    .print-header .r, .print-footer .r { float: right; }
    .print-header .c, .print-footer .c { text-align: center; }
    table, p { break-inside: avoid; }
    h2 { break-after: avoid; }
  }
  .pfh-l { display: inline-block; width: 32%; }
  .pfh-r { display: inline-block; width: 32%; text-align: right; }
  .pfh-c { display: inline-block; width: 34%; text-align: center; }
  h1 { font-size: 26px; margin: 10px 0 6px; color: #111827; }
  h2 { font-size: 16.5px; border-left: 4px; padding-left: 10px; margin: 26px 0 12px; color: #111827; }
  h3 { font-size: 14.5px; margin: 16px 0 8px; color: #374151; }
  h4 { font-size: 13.5px; margin: 14px 0 6px; color: #4b5563; }
  h5 { font-size: 13px; margin: 12px 0 5px; color: #6b7280; }
  p { margin: 6px 0; line-height: 1.75; }
  .page-break { display: none; }
  @media print { .page-break { display: block; break-after: page; page-break-after: always; } }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-bottom: 14px; }
  th { background: #f3f4f6; text-align: left; padding: 8px 10px; border: 1px solid #e5e7eb; }
  td { padding: 7px 10px; border: 1px solid #e5e7eb; word-break: break-all; vertical-align: top; }
`)
	b.WriteString(fmt.Sprintf("  h2 { border-left-color: %s; }\n", accent))
	b.WriteString("</style>\n</head>\n<body>\n")

	// 页眉页脚(打印时按页重复; 屏幕上看不到, 与内置报告同口径)
	// 页眉中段: 有富文本片段(模板自写页眉)用片段(已清洗), 否则用纯文本
	headerCenter := html.EscapeString(page.Header.HeaderCenter)
	if page.HeaderHTML != "" {
		headerCenter = page.HeaderHTML
	}
	b.WriteString("<div class=\"print-header\">")
	b.WriteString(fmt.Sprintf(`<span class="l pfh-l">%s</span><span class="c pfh-c">%s</span><span class="r pfh-r">%s</span>`,
		html.EscapeString(page.Header.HeaderLeft), headerCenter, html.EscapeString(page.Header.HeaderRight)))
	b.WriteString("</div>\n")
	b.WriteString("<div class=\"page\">\n")
	b.WriteString(BlocksToHTML(blocks))
	b.WriteString("\n</div>\n")
	// 页脚中段: 同页眉, 富文本片段优先
	footerCenter := html.EscapeString(page.Header.FooterCenter)
	if page.FooterHTML != "" {
		footerCenter = page.FooterHTML
	}
	b.WriteString("<div class=\"print-footer\">")
	b.WriteString(fmt.Sprintf(`<span class="l pfh-l">%s</span><span class="c pfh-c">%s</span><span class="r pfh-r">%s</span>`,
		html.EscapeString(page.Header.FooterLeft), footerCenter, html.EscapeString(page.Header.FooterRight)))
	b.WriteString("</div>\n</body>\n</html>\n")
	// 注: 早期版本右下角有"版权信息"悬浮跳转按钮 —— 2026-09-25 用户要求移除
	// (章节本身在报告末尾, 不需要额外入口)。#copyright 锚点保留在章节标题上,
	// 对外部深链无害。
	return b.String()
}
