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
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
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
	// ID HTML 锚点(docx 侧忽略; HTML 出口渲染成 <h2 id="...">, 供
	// "版权信息"这类页面内跳转入口用)
	ID string `json:"id,omitempty"`
	// Shd 块级底纹色(6 位十六进制不带 #)。2026-09-25 逐章节样式: 段落块 =
	// 全宽段落底纹(docx 写 w:pPr/shd, HTML 写 background-color), 表格块 =
	// 表格底色(docx 写 w:tblPr/shd, HTML 写 <table> 背景)。两出口同数据源,
	// "像 Word 一样的章节底色"。
	Shd string `json:"shd,omitempty"`
	// Runs 段落文本(表格块为空)
	Runs []Run `json:"runs,omitempty"`
	// Rows 表格行(段落块为空)
	Rows []Row `json:"rows,omitempty"`
}

// Run 一段带格式的文本(或一张内联图片)。
type Run struct {
	// Text 文本; "\n" 表示换行(docx 侧写 <w:br/>, HTML 侧写 <br>)
	Text   string `json:"text"`
	Bold   bool   `json:"bold,omitempty"`
	Italic bool   `json:"italic,omitempty"`
	Uline  bool   `json:"uline,omitempty"`
	// Strike 删除线(2026-09-26 白名单扩展): docx 写 w:strike, HTML 写 <s>
	Strike bool `json:"strike,omitempty"`
	// Font 字体族(如 "微软雅黑"/"宋体"; 空 = 文档默认)。docx 写 w:rFonts 的
	// ascii/hAnsi/eastAsia 三处 —— Word 对中西文各一套字体槽, 只写一个会"半截生效"
	Font  string `json:"font,omitempty"`
	Color string `json:"color,omitempty"` // 十六进制不带 #, 如 "C00000"
	// Bg 文字背景色(字符底纹, 十六进制不带 #)。2026-09-25 模板编辑器
	// "像 Word 一样" 的"底色"能力 —— docx 侧写 rPr 的 w:shd(字符底纹),
	// HTML 侧写 span 的 background-color。
	Bg string `json:"bg,omitempty"`
	// Size 字号(半点, w:sz 口径; 21 = 10.5pt 小五, 24 = 12pt 小四); 0 = 继承
	Size int `json:"size,omitempty"`
	// PageBreak 段落末尾追加分页符(w:br type=page; 封面与正文分页用)。
	// 只输出 br 不输出 w:t —— 空文本的 w:t 会被 Word 当空字符保留。
	PageBreak bool `json:"pageBreak,omitempty"`
	// MediaName 内联图片的媒体部件文件名(如 "logo.png"); 空 = 纯文本 run。
	// docx 侧写 w:drawing(关系指向 word/media/<MediaName>), HTML 侧写 data URI。
	MediaName string `json:"mediaName,omitempty"`
	// ImageB64 图片字节 base64。数据挂在 Run 上(而不是外部 map)是有意的:
	// ReadDocx 解析模板后, 图片随块序列一起存活, "保存模板 → 生成报告"的
	// WriteDocx 重打包 / HTML 渲染都不丢 —— 模板放 logo 的需求靠这个闭环
	// (2026-09-25: 用户要求报告模板能放 logo)。
	ImageB64 string `json:"imageB64,omitempty"`
	// ImageW/ImageH 显示尺寸(像素); 0 = 渲染侧按默认值。
	ImageW int `json:"imageW,omitempty"`
	ImageH int `json:"imageH,omitempty"`
}

// Row 表格行。
type Row struct {
	Cells []Cell `json:"cells"`
}

// Cell 表格单元格。
type Cell struct {
	Runs  []Run `json:"runs"`
	Width int   `json:"width,omitempty"` // dxa(1/20 点); 0 = 自动
	// Shd 单元格底纹色(十六进制不带 #, 如 "F3F4F6"; 表头行用)
	Shd string `json:"shd,omitempty"`
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
	// PageBg 页面背景色(6 位十六进制不带 #; 空 = 白) —— Word 的"页面颜色"。
	// 需要同时写 settings.xml 的 displayBackgroundShape, 否则 Word 打开仍是白纸
	// (2026-09-26 用户问"word 的背景色不能改吗": 只写 w:background 不生效)。
	PageBg string
}

// WriteDocx 把块序列序列化为 .docx 字节流(自动收集 run 里的图片写 media 部件)。
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
	writeBin := func(name string, content []byte) {
		w, err := zw.Create(name)
		if err != nil {
			return
		}
		_, _ = w.Write(content)
	}

	// 图片收集: 按媒体名去重(同名 = 同一张图), 顺序稳定(首次出现顺序),
	// rel id 从 rIdImg1 起 —— 与文档级 rId1/rId2 区分, 不冲突。
	images := map[string]*docxImage{}
	var imgOrder []string
	addImage := func(r Run) {
		if r.MediaName == "" || r.ImageB64 == "" {
			return
		}
		if _, ok := images[r.MediaName]; !ok {
			images[r.MediaName] = &docxImage{b64: r.ImageB64, w: r.ImageW, h: r.ImageH}
			imgOrder = append(imgOrder, r.MediaName)
		}
	}
	for _, blk := range blocks {
		for _, r := range blk.Runs {
			addImage(r)
		}
		for _, row := range blk.Rows {
			for _, c := range row.Cells {
				for _, r := range c.Runs {
					addImage(r)
				}
			}
		}
	}
	for i, name := range imgOrder {
		images[name].relID = fmt.Sprintf("rIdImg%d", i+1)
	}

	pageBg := meta.PageBg
	if !isHexStr(pageBg) {
		pageBg = "" // 非法色值按无背景处理(不把坏值写进 XML)
	}
	withSettings := pageBg != ""
	write("[Content_Types].xml", contentTypesXML(imgOrder, withSettings))
	write("_rels/.rels", rootRelsXML)
	write("word/_rels/document.xml.rels", docRelsXML(imgOrder, withSettings))
	write("word/styles.xml", stylesXML)
	if withSettings {
		// 只在有页面背景时才写 settings.xml —— 既有文档结构零变化
		write("word/settings.xml", settingsXML)
	}
	write("docProps/core.xml", coreXML(meta))
	write("word/document.xml", documentXML(blocks, images, pageBg))
	for _, name := range imgOrder {
		data, err := base64.StdEncoding.DecodeString(images[name].b64)
		if err != nil {
			continue // 坏图跳过(宁可没图不能打包失败)
		}
		writeBin("word/media/"+name, data)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("docx 打包失败: %w", err)
	}
	return buf.Bytes(), nil
}

// docxImage 一个媒体部件的写出信息(关系 id + 数据 + 尺寸)。
type docxImage struct {
	relID string
	b64   string
	w, h  int
}

func contentTypesXML(imgNames []string, withSettings bool) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>`)
	if withSettings {
		b.WriteString(`
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>`)
	}
	seen := map[string]bool{}
	for _, n := range imgNames {
		ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(n)), ".")
		if ext == "" || seen[ext] {
			continue
		}
		seen[ext] = true
		mime := map[string]string{"png": "image/png", "jpeg": "image/jpeg", "jpg": "image/jpeg", "gif": "image/gif"}[ext]
		if mime == "" {
			continue
		}
		b.WriteString(`<Default Extension="` + ext + `" ContentType="` + mime + `"/>`)
	}
	b.WriteString(`
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`)
	return b.String()
}

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`

func docRelsXML(imgNames []string, withSettings bool) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`)
	for i, n := range imgNames {
		b.WriteString(`<Relationship Id="rIdImg` + strconv.Itoa(i+1) +
			`" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/` +
			escXML(n) + `"/>`)
	}
	if withSettings {
		// 页面背景色需要 settings.xml 在包关系里登记(displayBackgroundShape 才生效)
		b.WriteString(`<Relationship Id="rIdSettings" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>`)
	}
	b.WriteString("</Relationships>")
	return b.String()
}

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

// settingsXML: 仅在有页面背景色时写入; displayBackgroundShape 让 <w:background>
// 的颜色在 Word 里真正铺满纸面(否则背景色不显示)。
const settingsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:displayBackgroundShape/>
</w:settings>`

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

func documentXML(blocks []Block, images map[string]*docxImage, pageBg string) string {
	var b strings.Builder
	// 图片相关命名空间(wp/a/pic/r)恒带: 无图片时是冗余但合法, 免去条件分支
	// (Word 对空命名空间不敏感, 解析器也按本地名匹配)。
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
 xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
 xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
 xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<w:body>`)
	if pageBg != "" {
		// 页面背景色(6 位 hex 不带 #): "页面颜色", 整张纸铺底
		b.WriteString(`<w:background w:color="` + pageBg + `"/>`)
	}
	for _, blk := range blocks {
		b.WriteString(blockXML(blk, images))
	}
	// A4 页面 + 常规页边距(1440 twips = 25.4mm 略小, 2.54cm)
	b.WriteString(`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567"/></w:sectPr>`)
	b.WriteString("</w:body></w:document>")
	return b.String()
}

func blockXML(blk Block, images map[string]*docxImage) string {
	if blk.Kind == "tbl" {
		return tableXML(blk, images)
	}
	var b strings.Builder
	b.WriteString("<w:p><w:pPr>")
	if blk.Style != "" {
		b.WriteString(`<w:pStyle w:val="` + blk.Style + `"/>`)
	}
	if blk.Shd != "" {
		// 段落全宽底纹(逐章节样式的"章节底色"; 与 rPr/shd 字符底纹区分)
		b.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="` + blk.Shd + `"/>`)
	}
	if blk.Align == "center" {
		b.WriteString(`<w:jc w:val="center"/>`)
	} else if blk.Align == "right" {
		b.WriteString(`<w:jc w:val="right"/>`)
	}
	b.WriteString("</w:pPr>")
	for _, r := range blk.Runs {
		b.WriteString(runXML(r, images))
	}
	b.WriteString("</w:p>")
	return b.String()
}

func runXML(r Run, images map[string]*docxImage) string {
	var b strings.Builder
	// 图片 run: w:drawing 内联(w:t 无文本 —— 与 PageBreak 同口径, 空文本不留痕)
	if r.MediaName != "" {
		if img, ok := images[r.MediaName]; ok {
			b.WriteString(imageRunXML(img, r.MediaName, r.ImageW, r.ImageH))
			return b.String()
		}
	}
	b.WriteString("<w:r>")
	if r.Bold || r.Italic || r.Uline || r.Strike || r.Font != "" ||
		r.Color != "" || r.Bg != "" || r.Size > 0 {
		b.WriteString("<w:rPr>")
		if r.Bold {
			b.WriteString("<w:b/>")
		}
		if r.Italic {
			b.WriteString("<w:i/>")
		}
		if r.Uline {
			b.WriteString(`<w:u w:val="single"/>`)
		}
		if r.Strike {
			b.WriteString("<w:strike/>")
		}
		if r.Font != "" {
			// 三处都写: ascii=西文, hAnsi=ANSI, eastAsia=中文 —— Word 各槽独立,
			// 只写 ascii 会导致中文部分回落到默认字体(用户看到"字体只变一半")
			f := escXML(r.Font)
			b.WriteString(`<w:rFonts w:ascii="` + f + `" w:hAnsi="` + f + `" w:eastAsia="` + f + `"/>`)
		}
		if r.Color != "" {
			b.WriteString(`<w:color w:val="` + r.Color + `"/>`)
		}
		if r.Bg != "" {
			// 字符底纹(Word/WPS 均支持 rPr 级 w:shd; "底色"能力)
			b.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="` + r.Bg + `"/>`)
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
	if r.PageBreak {
		b.WriteString(`<w:br w:type="page"/>`)
	}
	b.WriteString("</w:r>")
	return b.String()
}

// imageRunXML 内联图片 run(w:drawing/wp:inline)。尺寸单位 EMU(1px = 9525 EMU);
// 0 值按默认 300x150px, 防止生成 cx=0 的不可见图片。
func imageRunXML(img *docxImage, name string, w, h int) string {
	if w <= 0 {
		w = 300
	}
	if h <= 0 {
		h = 150
	}
	if img.w > 0 && img.h > 0 && (w != img.w || h != img.h) {
		// 以收集时的尺寸为显示尺寸基准(同一张图多处引用保持大小一致)
		w, h = img.w, img.h
	}
	cx := w * 9525
	cy := h * 9525
	return `<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">` +
		`<wp:extent cx="` + strconv.Itoa(cx) + `" cy="` + strconv.Itoa(cy) + `"/>` +
		`<wp:docPr id="1" name="` + escXML(name) + `"/>` +
		`<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">` +
		`<pic:pic><pic:nvPicPr><pic:cNvPr id="1" name="` + escXML(name) + `"/><pic:cNvPicPr/></pic:nvPicPr>` +
		`<pic:blipFill><a:blip r:embed="` + img.relID + `"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>` +
		`<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="` + strconv.Itoa(cx) + `" cy="` + strconv.Itoa(cy) + `"/></a:xfrm>` +
		`<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>` +
		`</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r>`
}

func tableXML(blk Block, images map[string]*docxImage) string {
	var b strings.Builder
	b.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>`)
	for _, side := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		b.WriteString(`<w:` + side + ` w:val="single" w:sz="4" w:space="0" w:color="B0B0B0"/>`)
	}
	b.WriteString(`</w:tblBorders>`)
	if blk.Shd != "" {
		// 表格底色(逐章节样式的"章节底色"覆盖到表格; tblPr/shd 在
		// tblBorders 之后 tblLayout 之前, 符合 OOXML 子元素顺序)
		b.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="` + blk.Shd + `"/>`)
	}
	b.WriteString(`<w:tblLayout w:type="autofit"/></w:tblPr>`)
	for _, row := range blk.Rows {
		b.WriteString("<w:tr>")
		for _, c := range row.Cells {
			b.WriteString("<w:tc>")
			if c.Width > 0 || c.Shd != "" {
				b.WriteString("<w:tcPr>")
				if c.Width > 0 {
					b.WriteString(`<w:tcW w:w="` + strconv.Itoa(c.Width) + `" w:type="dxa"/>`)
				}
				if c.Shd != "" {
					b.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="` + c.Shd + `"/>`)
				}
				b.WriteString("</w:tcPr>")
			}
			var cellB strings.Builder
			hasText := false
			for _, r := range c.Runs {
				if r.Text != "" || r.MediaName != "" {
					hasText = true
				}
				cellB.WriteString(runXML(r, images))
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

// ReadDocx 解析 .docx, 返回块序列(段落 + 表格, 含内联图片)。
//
// 只关心 body 里的 w:p / w:tbl; 其余元素(sectPr/proofErr 等)忽略 ——
// 读取的用途是"占位符替换 + 内容重排", 不需要完整还原文档对象模型。
// 图片例外必须还原(w:drawing → Run.MediaName/ImageB64): 模板"保存 → 生成"
// 要跨 WriteDocx/HTML 渲染保住 logo, 丢了图片模板就名存实亡。
func ReadDocx(data []byte) ([]Block, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("不是有效的 docx(zip) 文件: %w", err)
	}
	var docData, relsData []byte
	media := map[string][]byte{} // word/media/<name> -> 字节
	for _, f := range zr.File {
		switch {
		case f.Name == "word/document.xml":
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			docData, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
		case f.Name == "word/_rels/document.xml.rels":
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			relsData, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(f.Name, "word/media/"):
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err == nil {
				media[f.Name] = b
			}
		}
	}
	if docData == nil {
		return nil, fmt.Errorf("不是有效的 docx: 缺少 word/document.xml")
	}

	var doc docxDoc
	if err := xml.Unmarshal(docData, &doc); err != nil {
		return nil, fmt.Errorf("document.xml 解析失败: %w", err)
	}

	// 关系表: rIdImgN -> media/<name>(图片引用解析用; 其它关系忽略)
	rels := map[string]string{}
	if len(relsData) > 0 {
		var rx struct {
			Rels []struct {
				Id     string `xml:"Id,attr"`
				Type   string `xml:"Type,attr"`
				Target string `xml:"Target,attr"`
			} `xml:"Relationship"`
		}
		if xml.Unmarshal(relsData, &rx) == nil {
			for _, rel := range rx.Rels {
				if strings.HasSuffix(rel.Type, "/image") {
					rels[rel.Id] = rel.Target
				}
			}
		}
	}
	// 媒体名归一: 关系 Target 可能是 "media/logo.png"(相对) 或 "/word/media/..."(绝对)
	mediaByName := map[string][]byte{}
	for name, b := range media {
		base := strings.TrimPrefix(name, "word/media/")
		mediaByName[base] = b
	}
	imgOf := func(rID, target string) []byte {
		if rID != "" {
			if t, ok := rels[rID]; ok {
				target = t
			}
		}
		if target == "" {
			return nil
		}
		base := strings.TrimPrefix(strings.TrimPrefix(target, "/word/"), "word/")
		if strings.HasPrefix(base, "media/") {
			base = base[len("media/"):]
		}
		return mediaByName[base]
	}

	var blocks []Block
	for _, it := range doc.Body.Items {
		switch it.XMLName.Local {
		case "p":
			blocks = append(blocks, docxItemToParagraph(it, imgOf))
		case "tbl":
			blocks = append(blocks, docxItemToTable(it, imgOf))
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
	TblPr   *docxTblPr `xml:"tblPr"`
}

type docxPPR struct {
	PStyle *docxVal `xml:"pStyle"`
	Jc     *docxVal `xml:"jc"`
	// Shd 段落底纹(逐章节样式的"章节底色"回读, 与写入侧 pPr/shd 对称)
	Shd *docxShd `xml:"shd"`
}

// docxTblPr 表格属性(只取底纹; 表格底色回读, 与写入侧 tblPr/shd 对称)。
type docxTblPr struct {
	Shd *docxShd `xml:"shd"`
}

type docxVal struct {
	Val string `xml:"val,attr"`
}

type docxRun struct {
	RPr *docxRPR         `xml:"rPr"`
	// Drawing 内联图片(w:drawing); nil = 纯文本 run。
	// 用结构体映射而不是 ,any: 属性(embed/cx/cy)在 ,any 里拿不到。
	Drawing *docxDrawing   `xml:"drawing"`
	Ch      []docxRunPart  `xml:",any"`
}

// docxDrawing wp:inline 图片的最小映射(只取显示尺寸与图片关系 id)。
type docxDrawing struct {
	Inline struct {
		Extent struct {
			Cx int `xml:"cx,attr"`
			Cy int `xml:"cy,attr"`
		} `xml:"extent"`
		Graphic struct {
			GraphicData struct {
				Pic struct {
					BlipFill struct {
						Blip struct {
							Embed string `xml:"embed,attr"`
						} `xml:"blip"`
					} `xml:"blipFill"`
					NvPicPr struct {
						CNvPr struct {
							Name string `xml:"name,attr"`
						} `xml:"cNvPr"`
					} `xml:"nvPicPr"`
				} `xml:"pic"`
			} `xml:"graphicData"`
		} `xml:"graphic"`
	} `xml:"inline"`
}

// docxRunPart run 内的顺序子元素(w:t / w:br / w:tab / w:instrText...)。
// 用 ,any + chardata 保住顺序: 逐子元素拼接比"先 t 后 br"的假设更忠实。
type docxRunPart struct {
	XMLName xml.Name
	Text    string `xml:",chardata"`
}

type docxRPR struct {
	B      *docxVal   `xml:"b"`
	I      *docxVal   `xml:"i"`
	U      *docxVal   `xml:"u"`
	Strike *docxVal   `xml:"strike"`
	Color  *docxVal   `xml:"color"`
	Sz     *docxVal   `xml:"sz"`
	Shd    *docxShd   `xml:"shd"`
	// RFonts 字体族(回读 eAstAsia 优先: 模板里的中文标题字体一般设在中文字槽)
	RFonts *docxRFonts `xml:"rFonts"`
}

// docxRFonts w:rFonts —— 中西文各一套字体槽, 读取按 eastAsia → ascii 顺序取首个非空。
type docxRFonts struct {
	ASCII    string `xml:"ascii,attr"`
	HAnsi    string `xml:"hAnsi,attr"`
	EastAsia string `xml:"eastAsia,attr"`
}

// docxShd 底纹(单元格级 w:tcPr/shd 与字符级 w:rPr/shd 同结构)。
type docxShd struct {
	Fill string `xml:"fill,attr"`
}

type docxTr struct {
	Tc []docxTc `xml:"tc"`
}

type docxTc struct {
	TcPr *docxTcPr `xml:"tcPr"`
	P    []docxItem `xml:"p"`
}

// docxTcPr 单元格属性(只取底纹; 表头 F3F4F6 这类底纹回读, 与写入侧对称)。
type docxTcPr struct {
	Shd *docxShd `xml:"shd"`
}

// imgOf 图片引用解析: (关系 id, 关系 Target) -> 图片字节(无则 nil)。
type imgOfFunc func(rID, target string) []byte

func docxItemToParagraph(it docxItem, imgOf imgOfFunc) Block {
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
		if it.PPr.Shd != nil && it.PPr.Shd.Fill != "" && it.PPr.Shd.Fill != "auto" {
			b.Shd = it.PPr.Shd.Fill
		}
	}
	for _, r := range it.R {
		b.Runs = append(b.Runs, docxRunToRun(r, imgOf))
	}
	return b
}

func docxItemToTable(it docxItem, imgOf imgOfFunc) Block {
	b := Block{Kind: "tbl"}
	if it.TblPr != nil && it.TblPr.Shd != nil && it.TblPr.Shd.Fill != "" && it.TblPr.Shd.Fill != "auto" {
		b.Shd = it.TblPr.Shd.Fill
	}
	for _, tr := range it.Tbl {
		var row Row
		for _, tc := range tr.Tc {
			var cell Cell
			if tc.TcPr != nil && tc.TcPr.Shd != nil && tc.TcPr.Shd.Fill != "" && tc.TcPr.Shd.Fill != "auto" {
				cell.Shd = tc.TcPr.Shd.Fill
			}
			for _, p := range tc.P {
				for i, r := range docxItemToParagraph(p, imgOf).Runs {
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

func docxRunToRun(r docxRun, imgOf imgOfFunc) Run {
	out := Run{}
	if r.RPr != nil {
		if r.RPr.B != nil && !isDocxFalse(r.RPr.B.Val) {
			out.Bold = true
		}
		if r.RPr.I != nil && !isDocxFalse(r.RPr.I.Val) {
			out.Italic = true
		}
		if r.RPr.U != nil && r.RPr.U.Val != "" && !isDocxFalse(r.RPr.U.Val) {
			out.Uline = true
		}
		if r.RPr.Strike != nil && !isDocxFalse(r.RPr.Strike.Val) {
			out.Strike = true
		}
		if rf := r.RPr.RFonts; rf != nil {
			for _, f := range []string{rf.EastAsia, rf.ASCII, rf.HAnsi} {
				if s := strings.TrimSpace(f); s != "" {
					out.Font = s
					break
				}
			}
		}
		if r.RPr.Color != nil && r.RPr.Color.Val != "" && r.RPr.Color.Val != "auto" {
			out.Color = r.RPr.Color.Val
		}
		if r.RPr.Sz != nil {
			if n, err := strconv.Atoi(r.RPr.Sz.Val); err == nil {
				out.Size = n
			}
		}
		if r.RPr.Shd != nil && r.RPr.Shd.Fill != "" && r.RPr.Shd.Fill != "auto" {
			out.Bg = r.RPr.Shd.Fill
		}
	}
	// 图片 run: 还原媒体名/数据/尺寸(EMU -> 像素, 1px = 9525 EMU)
	if d := r.Drawing; d != nil {
		name := d.Inline.Graphic.GraphicData.Pic.NvPicPr.CNvPr.Name
		embed := d.Inline.Graphic.GraphicData.Pic.BlipFill.Blip.Embed
		if data := imgOf(embed, name); len(data) > 0 {
			out.MediaName = name
			out.ImageB64 = base64.StdEncoding.EncodeToString(data)
			out.ImageW = d.Inline.Extent.Cx / 9525
			out.ImageH = d.Inline.Extent.Cy / 9525
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
