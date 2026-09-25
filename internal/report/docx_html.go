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
	"strings"
)

// WordPage HTML 页面元信息(页眉页脚/主题色)。
type WordPage struct {
	Title  string
	Header Header // 已展开占位符(调用方用 EffectiveHeader + ExpandHeaderValues 处理)
	Accent string
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
	style := ""
	if blk.Align == "center" {
		style = ` style="text-align:center"`
	}
	var runs strings.Builder
	for _, r := range blk.Runs {
		runs.WriteString(runHTML(r))
	}
	if runs.String() == "" {
		return "<p>&nbsp;</p>" // 空段保留版式间距(与 Word 空行对应)
	}
	return fmt.Sprintf("<%s%s>%s</%s>", tag, style, runs.String(), tag)
}

func runHTML(r Run) string {
	var b strings.Builder
	text := html.EscapeString(r.Text)
	// 换行: \n → <br>(先转义再替换, 转义不影响 \n)
	text = strings.ReplaceAll(text, "\n", "<br>")
	if r.Bold {
		b.WriteString("<strong>")
	}
	if r.Color != "" {
		b.WriteString(fmt.Sprintf("<span style=\"color:#%s\">", r.Color))
	}
	b.WriteString(text)
	if r.Bold {
		b.WriteString("</strong>")
	}
	if r.Color != "" {
		b.WriteString("</span>")
	}
	return b.String()
}

func tableHTML(blk Block) string {
	var b strings.Builder
	b.WriteString("<table>")
	for i, row := range blk.Rows {
		b.WriteString("<tr>")
		for _, c := range row.Cells {
			cell := ""
			for _, r := range c.Runs {
				cell += runHTML(r)
			}
			if i == 0 {
				// 首行当表头(与 Word 里模板习惯一致: 第一行加粗列名)
				b.WriteString("<th>" + cell + "</th>")
			} else {
				b.WriteString("<td>" + cell + "</td>")
			}
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
		accent = "#4f46e5"
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
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-bottom: 14px; }
  th { background: #f3f4f6; text-align: left; padding: 8px 10px; border: 1px solid #e5e7eb; }
  td { padding: 7px 10px; border: 1px solid #e5e7eb; word-break: break-all; vertical-align: top; }
`)
	b.WriteString(fmt.Sprintf("  h2 { border-left-color: %s; }\n", accent))
	b.WriteString("</style>\n</head>\n<body>\n")

	// 页眉页脚(打印时按页重复; 屏幕上看不到, 与内置报告同口径)
	b.WriteString("<div class=\"print-header\">")
	b.WriteString(fmt.Sprintf(`<span class="l pfh-l">%s</span><span class="c pfh-c">%s</span><span class="r pfh-r">%s</span>`,
		html.EscapeString(page.Header.HeaderLeft), html.EscapeString(page.Header.HeaderCenter), html.EscapeString(page.Header.HeaderRight)))
	b.WriteString("</div>\n")
	b.WriteString("<div class=\"page\">\n")
	b.WriteString(BlocksToHTML(blocks))
	b.WriteString("\n</div>\n")
	b.WriteString("<div class=\"print-footer\">")
	b.WriteString(fmt.Sprintf(`<span class="l pfh-l">%s</span><span class="c pfh-c">%s</span><span class="r pfh-r">%s</span>`,
		html.EscapeString(page.Header.FooterLeft), html.EscapeString(page.Header.FooterCenter), html.EscapeString(page.Header.FooterRight)))
	b.WriteString("</div>\n")
	b.WriteString("</body>\n</html>\n")
	return b.String()
}
