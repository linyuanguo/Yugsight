// report_tpl_visual_api.go Word 排版模板"可视化编辑器"后端(报告中心装配层)。
//
// 用户口径(2026-09-25): "模板管理里要有个类似 Word 的排版编辑, 让人可以直观
// 的做好" —— 此前 Word 模板要么用内置(用户无法改排版), 要么自己 Word 里做
// 占位符文件上传(不直观)。本模块把排版变成"选项":
//
//   封面(开/关、标题色、副标题、客户名、报告人/时间行) + 章节(勾选+排序)
//   + 页脚/免责声明文案 → 服务端用 report 包现成排版引擎生成 .docx 模板。
//
// 产出物与"手动上传 .docx"完全同轨: report_templates/<name>.docx(排版载体)
// + <name>.visual.json(配置存档, 生成报告时按它选章节/取页脚免责声明)。
// 生成链路与旧 Word 模板路径零改动 —— 可视化模板就是一个"自动生成的 .docx"。
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"   // image.DecodeConfig 需要注册解码器
	_ "image/jpeg" // 同上
	_ "image/png"  // 同上
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"yugsight/internal/report"
	"yugsight/internal/server"
)

// VisualTpl 可视化排版模板配置(存 report_templates/<name>.visual.json)。
// 富文本字段说明(2026-09-25 二轮, 用户清单: 页眉/页脚/标题1/版权信息/检测
// 工具/免责声明/报告人/生成时间, 可编辑可删除, 支持字体颜色/底色/格式):
// Title/Header/Client/Subtitle/Operator/Tool/TimeText/Copyright/Disclaimer/
// Footer 都是"清洗后的白名单 HTML 片段"(b/i/u/br/span, 见 report.SanitizeRichHTML)
// —— 纯文本是合法子集, 旧模板的纯文本值无需迁移。Word 出口由 report.HTMLToRuns
// 烤成 Run 属性, HTML 出口由 RenderWordReport 原样渲染。
// 空值语义: 封面行回退内置占位符(报告数据填充); 版权/免责声明空 = 该章不出。
type VisualTpl struct {
	Name     string `json:"name"`
	Title    string `json:"title,omitempty"`      // 标题1(封面首行, 富文本); 空 = 用报告标题
	Header   string `json:"header,omitempty"`     // 页眉(每页顶部, HTML 打印出口, 富文本); 空 = 默认
	Client   string `json:"client,omitempty"`     // 客户名(封面一行, 富文本, 可空)
	Subtitle string `json:"subtitle,omitempty"`   // 封面副标题(富文本, 可空 = 用报告配置的 subtitle)
	// Operator 报告人(富文本); 空 = 用登录账号
	Operator string `json:"operator,omitempty"`
	// Tool 检测工具(富文本); 空 = 用平台名
	Tool string `json:"tool,omitempty"`
	// TimeMode 生成时间模式: auto(默认, 生成时刻自动填) | custom(用 TimeText)
	TimeMode string `json:"timeMode,omitempty"`
	// TimeText custom 时的自定义生成时间(富文本)
	TimeText   string `json:"timeText,omitempty"`
	Footer     string `json:"footer,omitempty"` // 页脚(每页底部, HTML 打印出口, 富文本, 可空)
	// Copyright 版权信息(报告末尾, 富文本)。*string 区分三态:
	// nil(内置模板/旧版 .visual.json 无此键) = 用默认版权文案;
	// 显式 "" = 用户在模板里删掉了, 不出该章; 非空 = 自定义富文本。
	Copyright  *string `json:"copyright,omitempty"`
	Disclaimer string `json:"disclaimer,omitempty"` // 免责声明(报告末尾, 富文本); 空 = 不出该章
	// Accent 主题色(6 位十六进制不带 #, 可空 = 默认 1F3A5F;
	// 2026-09-26: 默认由靛蓝改沉稳深蓝 —— 用户反馈原色太亮眼)
	Accent string `json:"accent,omitempty"`
	// Cover 是否带封面(关 = 直接 {{content}} 起排)
	Cover bool `json:"cover"`
	// Logo 封面 logo 文件名(logos/ 目录下, 如 "logo.png"); 空 = 无 logo。
	// 服务端从磁盘实况回填(上传/删除接口是唯一写入口), 客户端不决定它。
	Logo      string    `json:"logo,omitempty"`
	Sections  []string  `json:"sections,omitempty"`
	// SectionStyles 逐章节字体样式(2026-09-25 用户要求: 逐章节字体颜色/底色/
	// 格式, 内容不可改)。key = 章节 key; 全空模板无此键, 生成时零差异。
	SectionStyles map[string]report.SectionStyle `json:"sectionStyles,omitempty"`
	UpdatedAt     time.Time                      `json:"updatedAt"`
}

const (
	visualTplMaxText = 200
	// logoMaxBytes 1MB: 封面 logo 不是图片库, 超大图只会拖慢报告渲染
	logoMaxBytes = 1 << 20
	// logoMaxPx 单边 2000px 上限: 超出就是误传了整页截图, 不是 logo
	logoMaxPx = 2000
)

var hexColorRe = regexp.MustCompile(`^[0-9A-Fa-f]{6}$`)

// registerVisualTplRoutes 可视化排版模板路由(写操作与 Word 模板上传同口径:
// adminOrOperator —— 排版是管理动作, 只读用户不该能改全员的报告版式)。
func registerVisualTplRoutes(srv *server.Server) {
	srv.Get("/api/v2/report/word/templates/sections", requireAuth(hVisualTplSections))
	srv.Get("/api/v2/report/word/templates/visual", requireAuth(hVisualTplGet))
	srv.Post("/api/v2/report/word/templates/visual", requireAuth(adminOrOperator(hVisualTplSave)))
	// logo 上传/删除(2026-09-25 用户要求"模板里能放 logo"): 与模板保存同权限口径
	srv.Post("/api/v2/report/word/templates/visual/logo", requireAuth(adminOrOperator(hVisualTplLogoSave)))
	srv.Delete("/api/v2/report/word/templates/visual/logo", requireAuth(adminOrOperator(hVisualTplLogoDelete)))
	// logo 读取(编辑器回显已有模板的 logo; 无则 404)
	srv.Get("/api/v2/report/word/templates/visual/logo", requireAuth(hVisualTplLogoGet))
}

// hVisualTplLogoGet GET /api/v2/report/word/templates/visual/logo?name=
func hVisualTplLogoGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if !validWordTplName(name) {
		server.FailBadRequest(w, "模板名非法")
		return
	}
	f := logoFileName(name)
	if f == "" {
		server.FailNotFound(w, "该模板没有 logo")
		return
	}
	data, err := os.ReadFile(filepath.Join(logoDir(), f))
	if err != nil {
		server.FailInternal(w, "logo 读取失败: "+err.Error())
		return
	}
	ct := map[string]string{".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif"}[strings.ToLower(filepath.Ext(f))]
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// logoDir 模板 logo 目录(exe 同目录 data/outp/logos/; 与模板 .docx 同树,
// 备份/迁移模板目录时 logo 一并带走)。
func logoDir() string {
	return filepath.Join(wordTplDir(), "logos")
}

// logoFileName 模板当前 logo 的文件名(磁盘实况; 无则空串)。
func logoFileName(name string) string {
	dir := logoDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// 命名约定: logos/<模板名>.<png|jpg|jpeg|gif>
		if strings.HasPrefix(e.Name(), name+".") {
			ext := strings.ToLower(filepath.Ext(e.Name()))
			switch ext {
			case ".png", ".jpg", ".jpeg", ".gif":
				return e.Name()
			}
		}
	}
	return ""
}

// hVisualTplLogoSave POST /api/v2/report/word/templates/visual/logo
// {name, data(base64)} → 校验图片 → 存 logos/<name>.<ext>(原子写, 覆盖旧 logo)。
func hVisualTplLogoSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == report.BuiltinWordTemplateName {
		server.FailBadRequest(w, "builtin 为内置保留名, 不支持自定义 logo")
		return
	}
	if !validWordTplName(req.Name) {
		server.FailBadRequest(w, "模板名非法(仅允许中英文/数字/-_./空格, 不能以 . 开头)")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Data))
	if err != nil || len(raw) == 0 {
		server.FailBadRequest(w, "logo 数据无效(须为图片文件的 base64)")
		return
	}
	if len(raw) > logoMaxBytes {
		server.FailBadRequest(w, fmt.Sprintf("logo 超过 %d KB 上限", logoMaxBytes/1024))
		return
	}
	cfg, imgFmt, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		server.FailBadRequest(w, "不是合法图片(png/jpg/gif): "+err.Error())
		return
	}
	if cfg.Width > logoMaxPx || cfg.Height > logoMaxPx {
		server.FailBadRequest(w, fmt.Sprintf("logo 尺寸 %dx%d 超过 %dpx 上限", cfg.Width, cfg.Height, logoMaxPx))
		return
	}
	// DecodeConfig 第二返回值是格式名("png"/"jpeg"/"gif"), 不是 MIME
	ext := map[string]string{"png": ".png", "jpeg": ".jpg", "gif": ".gif"}[imgFmt]
	if ext == "" {
		server.FailBadRequest(w, "不支持的图片格式: "+imgFmt)
		return
	}

	dir := logoDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		server.FailInternal(w, "logo 目录创建失败: "+err.Error())
		return
	}
	if err := writeAtomicFile(filepath.Join(dir, req.Name+ext), raw); err != nil {
		server.FailInternal(w, "logo 写入失败: "+err.Error())
		return
	}
	// 换格式上传时清掉旧扩展名的残留(否则同一个模板挂着两张图, 取哪张看遍历顺序)
	for _, old := range []string{req.Name + ".png", req.Name + ".jpg", req.Name + ".jpeg", req.Name + ".gif"} {
		if old == req.Name+ext {
			continue
		}
		_ = os.Remove(filepath.Join(dir, old))
	}
	d := v2GetDB()
	if d != nil {
		logAudit(d, r, "report.wordtpl.logo.save", req.Name, fmt.Sprintf("size=%dB %s", len(raw), imgFmt))
	}
	server.OK(w, map[string]any{"logo": req.Name + ext})
}

// hVisualTplLogoDelete DELETE /api/v2/report/word/templates/visual/logo?name=
func hVisualTplLogoDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if !validWordTplName(name) {
		server.FailBadRequest(w, "模板名非法")
		return
	}
	f := logoFileName(name)
	if f == "" {
		server.FailNotFound(w, "该模板没有 logo")
		return
	}
	if err := os.Remove(filepath.Join(logoDir(), f)); err != nil {
		server.FailInternal(w, "logo 删除失败: "+err.Error())
		return
	}
	d := v2GetDB()
	if d != nil {
		logAudit(d, r, "report.wordtpl.logo.delete", name, f)
	}
	server.OK(w, map[string]any{"ok": true})
}



// hVisualTplSections GET /api/v2/report/word/templates/sections
// 章节清单(key + 中文标题 + 是否可省略) —— 前端编辑器的章节行数据源,
// 与后端渲染共用 report.SectionList(), 避免前后端两份清单漂移。
func hVisualTplSections(w http.ResponseWriter, r *http.Request) {
	server.OK(w, map[string]any{"list": report.SectionList()})
}

// builtinVisualTpl 内置模板对应的默认可视化配置(编辑器打开 builtin 时的回显值)。
func builtinVisualTpl() *VisualTpl {
	sections := make([]string, 0, len(report.SectionList()))
	for _, m := range report.SectionList() {
		sections = append(sections, m.Key)
	}
	return &VisualTpl{
		Name:       report.BuiltinWordTemplateName,
		Subtitle:   "网络安全扫描与漏洞评估报告",
		Accent:     "1F3A5F",
		Cover:      true,
		Sections:   sections,
		Disclaimer: "本报告基于 Yugsight 自动化扫描结果生成, 结论仅供安全加固参考。",
		UpdatedAt:  time.Time{},
	}
}

// hVisualTplGet GET /api/v2/report/word/templates/visual?name=
// name 缺省 / builtin = 内置默认配置(编辑器初始状态); 否则读 .visual.json。
func hVisualTplGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" || name == report.BuiltinWordTemplateName {
		server.OK(w, builtinVisualTpl())
		return
	}
	cfg, err := loadVisualTplConfig(name)
	if err != nil {
		server.FailNotFound(w, "无该模板的可视化配置: "+name)
		return
	}
	// logo 以磁盘实况为准(上传/删除接口是写入口, .visual.json 里的旧值可能已过期)
	cfg.Logo = logoFileName(name)
	server.OK(w, cfg)
}

// hVisualTplSave POST /api/v2/report/word/templates/visual
// 校验 → 生成 .docx(排版) → 存 .visual.json(配置) → 审计。
func hVisualTplSave(w http.ResponseWriter, r *http.Request) {
	var cfg VisualTpl
	if !decodeJSON(w, r, &cfg) {
		return
	}
	cfg.Name = strings.TrimSpace(cfg.Name)
	if cfg.Name == report.BuiltinWordTemplateName {
		server.FailBadRequest(w, "builtin 为内置保留名, 请用其他模板名")
		return
	}
	if !validWordTplName(cfg.Name) {
		server.FailBadRequest(w, "模板名非法(仅允许中英文/数字/-_./空格, 不能以 . 开头)")
		return
	}
	if err := validateVisualTexts(&cfg); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	// logo 以磁盘实况为准(客户端不传; 传了也忽略, 防止绕过上传接口的校验)
	cfg.Logo = logoFileName(cfg.Name)

	docx, err := buildVisualTplDocx(&cfg)
	if err != nil {
		server.FailInternal(w, "模板生成失败: "+err.Error())
		return
	}

	dir := wordTplDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		server.FailInternal(w, "模板目录创建失败: "+err.Error())
		return
	}
	// 原子写(tmp + rename), 与上传路径同口径
	if err := writeAtomicFile(filepath.Join(dir, cfg.Name+".docx"), docx); err != nil {
		server.FailInternal(w, "模板写入失败: "+err.Error())
		return
	}
	cfg.UpdatedAt = time.Now()
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
	if err := writeAtomicFile(filepath.Join(dir, cfg.Name+".visual.json"), cfgBytes); err != nil {
		server.FailInternal(w, "配置写入失败: "+err.Error())
		return
	}
	d := v2GetDB()
	if d != nil {
		logAudit(d, r, "report.wordtpl.visual.save", cfg.Name,
			fmt.Sprintf("cover=%v sections=%d", cfg.Cover, len(cfg.Sections)))
	}
	server.OK(w, map[string]any{"name": cfg.Name})
}

// validateVisualTexts 文案长度/主题色/章节 key 校验。
// 富文本字段先过 report.SanitizeRichHTML 白名单清洗(2026-09-25 二轮: 粘贴进来
// 的 script/事件属性/未知标签在解析阶段就被拆掉), 长度按纯文本口径算。
func validateVisualTexts(cfg *VisualTpl) error {
	richFields := map[string]*string{
		"标题": &cfg.Title, "页眉": &cfg.Header, "客户名": &cfg.Client, "副标题": &cfg.Subtitle,
		"报告人": &cfg.Operator, "检测工具": &cfg.Tool, "生成时间": &cfg.TimeText,
		"页脚": &cfg.Footer, "免责声明": &cfg.Disclaimer,
	}
	for label, p := range richFields {
		*p = report.SanitizeRichHTML(*p) // 清洗后回写, 落盘的是干净片段
		if len([]rune(report.RichPlainText(*p))) > visualTplMaxText {
			return errInvalidVisual(fmt.Sprintf("「%s」超过 %d 字", label, visualTplMaxText))
		}
	}
	// 版权信息是 *string 三态(nil/空/非空), 非 nil 时同样清洗
	if cfg.Copyright != nil {
		*cfg.Copyright = report.SanitizeRichHTML(*cfg.Copyright)
		if len([]rune(report.RichPlainText(*cfg.Copyright))) > visualTplMaxText {
			return errInvalidVisual(fmt.Sprintf("「版权信息」超过 %d 字", visualTplMaxText))
		}
	}
	if cfg.Accent != "" {
		cfg.Accent = strings.TrimPrefix(cfg.Accent, "#")
		if !hexColorRe.MatchString(cfg.Accent) {
			return errInvalidVisual("主题色须为 6 位十六进制(如 4F46E5)")
		}
	}
	// 生成时间模式只认 auto/custom(空按 auto 处理)
	switch cfg.TimeMode {
	case "", "auto", "custom":
	default:
		return errInvalidVisual("生成时间模式只支持 auto/custom")
	}
	if cfg.TimeMode != "custom" {
		cfg.TimeText = "" // auto 时自定义值无意义, 清掉
	}
	// 章节 key 校验 + 去重(保持用户顺序; 未知 key 拒掉而不是静默丢 ——
	// 静默丢会让"保存后章节神秘消失", 用户排查不到原因)
	valid := map[string]bool{}
	for _, m := range report.SectionList() {
		valid[m.Key] = true
	}
	seen := map[string]bool{}
	for _, k := range cfg.Sections {
		if !valid[k] {
			return errInvalidVisual("未知章节: " + k)
		}
		if seen[k] {
			return errInvalidVisual("章节重复: " + k)
		}
		seen[k] = true
	}
	// 逐章节样式(2026-09-25): 未知章节 key 静默丢弃(与 Order 向前兼容同口径 ——
	// 新增章节后旧配置里的样式残留不该让保存 400); 颜色/字号值必须合法,
	// 非法值 400(用户意图是"存这个颜色", 静默洗成默认会让用户以为保存成功)。
	if cfg.SectionStyles != nil {
		normColor := func(label, c string) (string, error) {
			c = strings.TrimPrefix(c, "#")
			if c == "" {
				return "", nil
			}
			if !hexColorRe.MatchString(c) {
				return "", errInvalidVisual(fmt.Sprintf("「%s」须为 6 位十六进制(如 4F46E5)", label))
			}
			return c, nil
		}
		for k, st := range cfg.SectionStyles {
			if !valid[k] {
				delete(cfg.SectionStyles, k)
				continue
			}
			var err error
			if st.TitleColor, err = normColor("章节标题字色", st.TitleColor); err != nil {
				return err
			}
			if st.TitleBg, err = normColor("章节标题底色", st.TitleBg); err != nil {
				return err
			}
			if st.FontColor, err = normColor("章节正文字色", st.FontColor); err != nil {
				return err
			}
			if st.Bg, err = normColor("章节底色", st.Bg); err != nil {
				return err
			}
			if st.Size < 0 || st.Size > 72 {
				return errInvalidVisual(fmt.Sprintf("章节 %s 的正文字号超出范围(0=继承, 半点)", k))
			}
			cfg.SectionStyles[k] = st
		}
	}
	return nil
}

type visualErr string

func (e visualErr) Error() string { return string(e) }

func errInvalidVisual(msg string) error { return visualErr(msg) }

// buildVisualTplDocx 按配置生成 .docx 模板(封面 + {{content}} 章节注入位)。
// 生成结果必须能被 report.ReadDocx 解析(同上传路径的校验, 防止产出坏模板)。
func buildVisualTplDocx(cfg *VisualTpl) ([]byte, error) {
	accent := cfg.Accent
	if accent == "" {
		accent = "1F3A5F"
	}
	// coverLine 封面行: 富文本片段(已清洗)烤成 Run 序列; 片段为空返回 nil
	// (调用方回退占位符行, 让报告数据在生成时填充)。
	coverLine := func(frag string, base report.Run) []report.Run {
		return report.HTMLToRuns(frag, base)
	}
	// labelLine 带前缀标签的封面行("报告人: xxx"); 片段空返回 nil
	labelLine := func(label, frag string, base report.Run) []report.Run {
		runs := coverLine(frag, base)
		if len(runs) == 0 {
			return nil
		}
		return append([]report.Run{{Text: label, Size: base.Size}}, runs...)
	}

	var blocks []report.Block
	if cfg.Cover {
		// logo(可选): 放封面最顶, 居中; 展示宽 360px, 高按原图比例缩放
		if cfg.Logo != "" {
			if imgRun, ok := loadLogoRun(logoDir(), cfg.Name, cfg.Logo); ok {
				blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: []report.Run{imgRun}})
			}
		}
		// 标题1(首行): 模板自定义(富文本)优先, 否则占位符=报告标题
		if runs := coverLine(cfg.Title, report.Run{Size: 44, Bold: true, Color: accent}); len(runs) > 0 {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: runs})
		} else {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: []report.Run{{Text: "{{title}}", Size: 44, Bold: true, Color: accent}}})
		}
		// 副标题: 模板自定义优先, 否则占位符=报告配置的 subtitle
		if runs := coverLine(cfg.Subtitle, report.Run{Size: 24, Color: "6B7280"}); len(runs) > 0 {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: runs})
		} else {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: []report.Run{{Text: "{{subtitle}}", Size: 24, Color: "6B7280"}}})
		}
		if runs := labelLine("客户: ", cfg.Client, report.Run{Size: 24, Bold: true, Color: "374151"}); len(runs) > 0 {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: runs})
		}
		blocks = append(blocks, report.Block{Kind: "p"})
		if runs := labelLine("报告人: ", cfg.Operator, report.Run{Size: 24}); len(runs) > 0 {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: runs})
		} else {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: []report.Run{{Text: "报告人: {{operator}}", Size: 24}}})
		}
		if runs := labelLine("检测工具: ", cfg.Tool, report.Run{Size: 24}); len(runs) > 0 {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: runs})
		} else {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: []report.Run{{Text: "检测工具: {{tool}}", Size: 24}}})
		}
		// 生成时间: custom 用模板自定义值, auto(默认) 占位符=生成时刻
		if cfg.TimeMode == "custom" {
			if runs := labelLine("生成时间: ", cfg.TimeText, report.Run{Size: 24}); len(runs) > 0 {
				blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: runs})
			}
		} else {
			blocks = append(blocks, report.Block{Kind: "p", Align: "center", Runs: []report.Run{{Text: "生成时间: {{time}}", Size: 24}}})
		}
		blocks = append(blocks,
			report.Block{Kind: "p", Align: "center", Runs: []report.Run{{Text: "整体风险: {{risk}} (评分 {{score}}/100)", Size: 24, Bold: true, Color: "B91C1C"}}},
			report.Block{Kind: "p", Runs: []report.Run{{PageBreak: true}}},
		)
	}
	blocks = append(blocks, report.Block{
		Kind: "p", Runs: []report.Run{{Text: report.ContentMarker, Color: "9CA3AF"}},
	})
	data, err := report.WriteDocx(blocks, report.DocxMeta{Title: cfg.Name})
	if err != nil {
		return nil, err
	}
	if _, err := report.ReadDocx(data); err != nil {
		return nil, err
	}
	return data, nil
}

// loadLogoRun 读 logo 文件 → 图片 Run(base64 + 缩放后尺寸)。
// 展示宽固定 360px, 高按原图比例(防止宽长条 logo 把封面撑爆); 解码失败返回
// ok=false(降级不崩: logo 是装饰, 坏了不能阻断模板保存)。
func loadLogoRun(dir, tplName, file string) (report.Run, bool) {
	data, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		reportLogLine(fmt.Sprintf("模板 %s 的 logo 读取失败, 本次不插图: %v", tplName, err))
		return report.Run{}, false
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		reportLogLine(fmt.Sprintf("模板 %s 的 logo 解码失败, 本次不插图: %v", tplName, err))
		return report.Run{}, false
	}
	const maxW = 360
	w := maxW
	h := cfg.Height * maxW / cfg.Width
	if h < 20 {
		h = 20 // 极扁的条图至少 20px, 否则肉眼不可见
	}
	return report.Run{
		MediaName: file,
		ImageB64:  base64.StdEncoding.EncodeToString(data),
		ImageW:    w,
		ImageH:    h,
	}, true
}

// loadVisualTplConfig 读模板的可视化配置(生成/预览链路用)。
// 目录缺失 / 无 .visual.json = 非可视化模板, 返回 nil(静默, 走默认章节)。
func loadVisualTplConfig(name string) (*VisualTpl, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == report.BuiltinWordTemplateName {
		return nil, nil
	}
	if !validWordTplName(name) {
		return nil, visualErr("模板名非法: " + name)
	}
	p := filepath.Join(wordTplDir(), name+".visual.json")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, nil // 非可视化模板(手动上传的 .docx), 正常情况
	}
	var cfg VisualTpl
	if err := json.Unmarshal(data, &cfg); err != nil {
		// 配置损坏 = 按非可视化处理(降级不崩), 模板本身还能用
		reportLogLine(fmt.Sprintf("可视化模板配置损坏, 按默认章节渲染 file=%s err=%v", p, err))
		return nil, nil
	}
	return &cfg, nil
}

// writeAtomicFile tmp + rename 原子写(与 Word 模板上传路径同口径)。
func writeAtomicFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
