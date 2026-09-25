// docx.go Word 文档(.docx)读写 —— 纯标准库实现(archive/zip + encoding/xml)。
//
// 为什么需要:
//
//	报告以"Word 模板"为单一来源(用户 2026-09-20 要求): 用户在 Word 里设计
//	封面/版式, 引擎把扫描数据填进去, 同一份内容输出 Word / HTML / PDF 三种
//	格式。标准库没有 docx 库, 但 .docx 本质是"zip 容器 + 固定结构的 XML",
//	archive/zip + encoding/xml 足够实现"读模板 + 写成品"两个方向。
//
// 能力边界(如实说明, 不做过度承诺):
//
//	- 段落: 文本 / 加粗 / 颜色 / 字号 / 对齐 / 标题样式(Heading1-6、Title);
//	- 表格: 任意行列, 单元格内多段文本;
//	- 不解析: 图片/页眉页脚域/目录域/页码域 —— 模板里放了这些元素, 读取时
//	  忽略(不报错), 生成物里不保留。要图片请自己往 Word 里插, 引擎只动文本。
//
// 文本拼接的坑(Word 特有):
//
//	Word 编辑器会把一句普通话拆成多个 <w:r>(run), 占位符 "{{title}}" 很可能
//	被拆成 "{{ti" + "tle}}" 两段。因此本包读取时按段落"先拼接全部 run 文本,
//	再做占位符替换"(见 docx_template.go), 而不是逐 run 匹配 —— 逐 run 匹配
//	在真实模板上必然漏替换。
package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ===== 块模型(Word 与 HTML 共用的中间表示) =====

// Block 文档块: 段落(p) 或 表格(tbl)。
//
// 为什么是"扁平块序列"而不是嵌套结构: docx 的 body 就是 段落/表格 的扁平
// 序列, HTML 侧也是, 中间表示与两边同构, 转换无需树操作。
type Block struct {
	// Kind "p" 段落 / "tbl" 表格
	Kind string `json:"kind"`
	// Style 段落样式: ""(普通) / "Title" / "Heading1".."Heading6"
	Style string `json:"style,omitempty"`
	// Align 对齐: ""(左) / "center" / "right"
	Align string `json:"align,omitempty"`
	// Runs 段落文本(表格块为空)
	Runs []Run `json:"runs,omitempty"`
	// Rows 表格行(段落块为空)
	Rows []Row `json:"rows,omitempty"`
}

// Run 一段带格式的文本。
type Run struct {
	// Text 文本; "\n" 表示换行(docx 侧写 <w:br/>, HTML 侧写 <br>)
	Text  string `json:"text"`
	Bold  bool   `json:"bold,omitempty"`
	Color string `json:"color,omitempty"` // 十六进制不带 #, 如 "C00000"
	// Size 字号(半点, w:sz 口径; 21 = 10.5pt 小五, 24 = 12pt 小四); 0 = 继承
	Size int `json:"size,omitempty"`
}

// Row 表格行。
type Row struct {
	Cells []Cell `json:"cells"`
}

// Cell 表格单元格。
type Cell struct {
	Runs  []Run `json:"runs"`
	Width int   `json:"width,omitempty"` // dxa(1/20 点); 0 = 自动
}

// Text 单元格纯文本。
func (c Cell) Text() string {
	var sb strings.Builder
	for _, r := range c.Runs {
		sb.WriteString(r.Text)
	}
	return sb.String()
}

// Text 返回块的纯文本(段落 = 全部 run 拼接; 表格 = 首行单元格以 " | " 连接,
// 仅供占位符定位/日志等轻量用途)。
func (b Block) Text() string {
	switch b.Kind {
	case "p":
		var sb strings.Builder
		for _, r := range b.Runs {
			sb.WriteString(r.Text)
		}
		return sb.String()
	case "tbl":
		if len(b.Rows) == 0 {
			return ""
		}
		var sb strings.Builder
		for i, c := range b.Rows[0].Cells {
			if i > 0 {
				sb.WriteString(" | ")
			}
			var t strings.Builder
			for _, r := range c.Runs {
				t.WriteString(r.Text)
			}
			sb.WriteString(t.String())
		}
		return sb.String()
	}
	return ""
}

// ===== docx 写出 =====

// DocxMeta 文档属性(core.xml, 资源管理器"详细信息"可见)。
type DocxMeta struct {
	Title  string
	Author string
}

// WriteDocx 把块序列序列化为 .docx 字节流。
func WriteDocx(blocks []Block, meta DocxMeta) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	write := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			return
		}
		_, _ = io.WriteString(w, content)
	}

	write("[Content_Types].xml", contentTypesXML)
	write("_rels/.rels", rootRelsXML)
	write("word/_rels/document.xml.rels", docRelsXML)
	write("word/styles.xml", stylesXML)
	write("docProps/core.xml", coreXML(meta))
	write("word/document.xml", documentXML(blocks))

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("docx 打包失败: %w", err)
	}
	return buf.Bytes(), nil
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`

const docRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`

// stylesXML 内置样式表: 占位符替换重写的段落依赖 Heading 样式呈现章节标题,
// 缺样式表时 Word 会把 Heading1 当普通段落(章节全变正文, 报告观感直接崩坏)。
const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:sz w:val="21"/><w:szCs w:val="21"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="240" w:after="240"/></w:pPr><w:rPr><w:b/><w:sz w:val="44"/><w:szCs w:val="44"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr><w:rPr><w:b/><w:color w:val="1F2937"/><w:sz w:val="30"/><w:szCs w:val="30"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="200" w:after="100"/></w:pPr><w:rPr><w:b/><w:color w:val="374151"/><w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="160" w:after="80"/></w:pPr><w:rPr><w:b/><w:color w:val="4B5563"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading5"><w:name w:val="heading 5"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="21"/><w:szCs w:val="21"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading6"><w:name w:val="heading 6"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="21"/><w:szCs w:val="21"/></w:rPr></w:style>
</w:styles>`

func coreXML(m DocxMeta) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">`)
	if m.Title != "" {
		b.WriteString("<dc:title>" + escXML(m.Title) + "</dc:title>")
	}
	if m.Author != "" {
		b.WriteString("<dc:creator>" + escXML(m.Author) + "</dc:creator>")
	}
	b.WriteString("</cp:coreProperties>")
	return b.String()
}

func documentXML(blocks []Block) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>`)
	for _, blk := range blocks {
		b.WriteString(blockXML(blk))
	}
	// A4 页面 + 常规页边距(1440 twips = 25.4mm 略小, 2.54cm)
	b.WriteString(`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567"/></w:sectPr>`)
	b.WriteString("</w:body></w:document>")
	return b.String()
}

func blockXML(blk Block) string {
	if blk.Kind == "tbl" {
		return tableXML(blk)
	}
	var b strings.Builder
	b.WriteString("<w:p><w:pPr>")
	if blk.Style != "" {
		b.WriteString(`<w:pStyle w:val="` + blk.Style + `"/>`)
	}
	if blk.Align == "center" {
		b.WriteString(`<w:jc w:val="center"/>`)
	} else if blk.Align == "right" {
		b.WriteString(`<w:jc w:val="right"/>`)
	}
	b.WriteString("</w:pPr>")
	for _, r := range blk.Runs {
		b.WriteString(runXML(r))
	}
	b.WriteString("</w:p>")
	return b.String()
}

func runXML(r Run) string {
	var b strings.Builder
	b.WriteString("<w:r>")
	if r.Bold || r.Color != "" || r.Size > 0 {
		b.WriteString("<w:rPr>")
		if r.Bold {
			b.WriteString("<w:b/>")
		}
		if r.Color != "" {
			b.WriteString(`<w:color w:val="` + r.Color + `"/>`)
		}
		if r.Size > 0 {
			b.WriteString(`<w:sz w:val="` + strconv.Itoa(r.Size) + `"/><w:szCs w:val="` + strconv.Itoa(r.Size) + `"/>`)
		}
		b.WriteString("</w:rPr>")
	}
	// "\n" 拆成 <w:br/>: 单条文本内混入换行(如单元格多行)
	segs := strings.Split(r.Text, "\n")
	for i, seg := range segs {
		if seg != "" {
			b.WriteString("<w:t xml:space=\"preserve\">" + escXML(seg) + "</w:t>")
		}
		if i < len(segs)-1 {
			b.WriteString("<w:br/>")
		}
	}
	b.WriteString("</w:r>")
	return b.String()
}

func tableXML(blk Block) string {
	var b strings.Builder
	b.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>`)
	for _, side := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		b.WriteString(`<w:` + side + ` w:val="single" w:sz="4" w:space="0" w:color="B0B0B0"/>`)
	}
	b.WriteString(`</w:tblBorders><w:tblLayout w:type="autofit"/></w:tblPr>`)
	for _, row := range blk.Rows {
		b.WriteString("<w:tr>")
		for _, c := range row.Cells {
			b.WriteString("<w:tc>")
			if c.Width > 0 {
				b.WriteString(`<w:tcPr><w:tcW w:w="` + strconv.Itoa(c.Width) + `" w:type="dxa"/></w:tcPr>`)
			}
			var cellB strings.Builder
			hasText := false
			for _, r := range c.Runs {
				if r.Text != "" {
					hasText = true
				}
				cellB.WriteString(runXML(r))
			}
			if !hasText {
				cellB.WriteString("<w:r><w:t xml:space=\"preserve\"> </w:t></w:r>")
			}
			b.WriteString("<w:p>" + cellB.String() + "</w:p></w:tc>")
		}
		b.WriteString("</w:tr>")
	}
	b.WriteString("</w:tbl>")
	return b.String()
}

// escXML XML 转义(& 必须最先转, 否则会二次转义其它实体的 &)。
func escXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// ===== docx 读取 =====

// ReadDocx 解析 .docx, 返回块序列(段落 + 表格)。
//
// 只关心 body 里的 w:p / w:tbl; 其余元素(sectPr/proofErr/图片等)忽略 ——
// 读取的用途是"占位符替换 + 内容重排", 不需要完整还原文档对象模型。
func ReadDocx(data []byte) ([]Block, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("不是有效的 docx(zip) 文件: %w", err)
	}
	var docData []byte
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			docData, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if docData == nil {
		return nil, fmt.Errorf("不是有效的 docx: 缺少 word/document.xml")
	}

	var doc docxDoc
	if err := xml.Unmarshal(docData, &doc); err != nil {
		return nil, fmt.Errorf("document.xml 解析失败: %w", err)
	}

	var blocks []Block
	for _, it := range doc.Body.Items {
		switch it.XMLName.Local {
		case "p":
			blocks = append(blocks, docxItemToParagraph(it))
		case "tbl":
			blocks = append(blocks, docxItemToTable(it))
		default:
			// sectPr / proofErr / bookmarkStart 等: 忽略
		}
	}
	return blocks, nil
}

// ---- document.xml 的 XML 映射(只声明需要的字段, 其余自动忽略) ----

type docxDoc struct {
	Body struct {
		Items []docxItem `xml:",any"`
	} `xml:"body"`
}

// docxItem body 层与单元格共用的"段落/表格"元素。
type docxItem struct {
	XMLName xml.Name
	PPr     *docxPPR   `xml:"pPr"`
	R       []docxRun  `xml:"r"`
	Tbl     []docxTr   `xml:"tr"`
}

type docxPPR struct {
	PStyle *docxVal `xml:"pStyle"`
	Jc     *docxVal `xml:"jc"`
}

type docxVal struct {
	Val string `xml:"val,attr"`
}

type docxRun struct {
	RPr *docxRPR         `xml:"rPr"`
	Ch  []docxRunPart    `xml:",any"`
}

// docxRunPart run 内的顺序子元素(w:t / w:br / w:tab / w:instrText...)。
// 用 ,any + chardata 保住顺序: 逐子元素拼接比"先 t 后 br"的假设更忠实。
type docxRunPart struct {
	XMLName xml.Name
	Text    string `xml:",chardata"`
}

type docxRPR struct {
	B     *docxVal `xml:"b"`
	Color *docxVal `xml:"color"`
	Sz    *docxVal `xml:"sz"`
}

type docxTr struct {
	Tc []docxTc `xml:"tc"`
}

type docxTc struct {
	P []docxItem `xml:"p"`
}

func docxItemToParagraph(it docxItem) Block {
	b := Block{Kind: "p"}
	if it.PPr != nil {
		if it.PPr.PStyle != nil {
			b.Style = normalizeDocxStyle(it.PPr.PStyle.Val)
		}
		if it.PPr.Jc != nil {
			switch it.PPr.Jc.Val {
			case "center":
				b.Align = "center"
			case "right":
				b.Align = "right"
			}
		}
	}
	for _, r := range it.R {
		b.Runs = append(b.Runs, docxRunToRun(r))
	}
	return b
}

func docxItemToTable(it docxItem) Block {
	b := Block{Kind: "tbl"}
	for _, tr := range it.Tbl {
		var row Row
		for _, tc := range tr.Tc {
			var cell Cell
			for _, p := range tc.P {
				for i, r := range docxItemToParagraph(p).Runs {
					if i > 0 && len(cell.Runs) > 0 {
						// 单元格内多段: 段间补换行, 信息不丢
						cell.Runs = append(cell.Runs, Run{Text: "\n"})
					}
					cell.Runs = append(cell.Runs, r)
				}
			}
			row.Cells = append(row.Cells, cell)
		}
		b.Rows = append(b.Rows, row)
	}
	return b
}

func docxRunToRun(r docxRun) Run {
	out := Run{}
	if r.RPr != nil {
		if r.RPr.B != nil && !isDocxFalse(r.RPr.B.Val) {
			out.Bold = true
		}
		if r.RPr.Color != nil && r.RPr.Color.Val != "" && r.RPr.Color.Val != "auto" {
			out.Color = r.RPr.Color.Val
		}
		if r.RPr.Sz != nil {
			if n, err := strconv.Atoi(r.RPr.Sz.Val); err == nil {
				out.Size = n
			}
		}
	}
	for _, p := range r.Ch {
		switch p.XMLName.Local {
		case "t":
			out.Text += p.Text
		case "br":
			out.Text += "\n"
		case "tab":
			out.Text += "\t"
		}
		// instrText / sym 等: 忽略(域代码不保留)
	}
	return out
}

// isDocxFalse Word 的属性布尔口径: <w:b/> 为真; <w:b w:val="0|false|none"/> 为假。
func isDocxFalse(val string) bool {
	return val == "0" || val == "false" || val == "none" || val == "off"
}

// normalizeDocxStyle 样式 ID 归一化: 中文版 Word 的标题样式 ID 是 "1".."6"
// (或 "标题1"), 英文版是 "heading 1"/"Heading1" —— 统一成 Heading1..6,
// 否则中文模板里的章节标题在生成物里会丢失样式。
func normalizeDocxStyle(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "title":
		return "Title"
	case "heading1", "heading 1", "1", "标题1":
		return "Heading1"
	case "heading2", "heading 2", "2", "标题2":
		return "Heading2"
	case "heading3", "heading 3", "3", "标题3":
		return "Heading3"
	case "heading4", "heading 4", "4", "标题4":
		return "Heading4"
	case "heading5", "heading 5", "5", "标题5":
		return "Heading5"
	case "heading6", "heading 6", "6", "标题6":
		return "Heading6"
	}
	return s
}
