// report_pack_api.go 模板包管理 API(二期报告中心)。
//
// 与 report_word_api.go(旧扁平 .docx 模板)的关系:
//
//	旧接口                       模板包(本文件)
//	report_templates/<名>.docx   report_templates/<名>/{config.yaml, report.html.tpl, report.docx.tpl}
//	只有 Word 出口               同一模板出 HTML / Word / PDF 三份
//
// 两者共用同一个目录(report_templates/): LoadPackDir 把根下的扁平 .docx 也识别成
// 模板(Kind=docx), 老用户的模板不会"突然消失"。旧接口保持不动(既有前端仍在用)。
//
// 开关: settings.json 的 report 节 templateManagement(默认 false —— 模板管理是
// 高级能力, 任务书明确要求配置启用; 未启用时列表接口仍可用但写操作拒绝)。
// 理由: 模板目录在磁盘上, 开放上传/删除等于开放写目录, 默认关更稳妥。
package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"yugsight/internal/pathrel"
	"yugsight/internal/report"
	"yugsight/internal/server"
)

const packMaxBytes = 10 * 1024 * 1024

// registerPackRoutes 挂载模板包管理路由。
func registerPackRoutes(srv *server.Server) {
	srv.Get("/api/v2/report/packs", requireAuth(hPackList))
	srv.Post("/api/v2/report/packs", requireAuth(adminOrOperator(hPackSave)))
	srv.Delete("/api/v2/report/packs/{id}", requireAuth(adminOrOperator(hPackDelete)))
	srv.Get("/api/v2/report/packs/{id}/download", requireAuth(hPackDownload))
}

// packTplDir 模板包根目录(与 Word 模板同目录, 见文件头说明)。
func packTplDir() string { return wordTplDir() }

// packManagementEnabled 模板管理是否启用(写操作门禁)。
//
// 默认开启(用户口径: 开关在页面上, settings.json 只是保存参数的地方): nil = 开,
// 只有用户在页面上显式关闭(写 templateManagement=false)才拒绝写操作。
func packManagementEnabled() bool {
	cfg := loadReportConfig()
	return cfg.TemplateManagement == nil || *cfg.TemplateManagement
}

// hPackList GET /api/v2/report/packs 列出模板包(内置 default 恒在列)。
func hPackList(w http.ResponseWriter, r *http.Request) {
	dir := packTplDir()
	packs, warnings := report.LoadPackDir(dir)
	for _, wn := range warnings {
		reportLogLine("[模板] " + wn)
	}
	out := make([]map[string]any, 0, len(packs))
	for _, p := range packs {
		out = append(out, map[string]any{
			"id": p.ID, "name": p.Name, "kind": p.Kind, "builtin": p.Builtin,
			"config": p.Config, "logo": p.LogoData,
			"hasHtml": p.HasHTML, "hasDocx": p.HasDocx, "hasConfig": p.HasCfg,
		})
	}
	server.OK(w, map[string]any{
		"list": out, "dir": pathrel.Short(dir),
		"management": packManagementEnabled(),
		// 变量清单给前端"模板说明"展示(与 report/data.go 头注释同源)
		"variables": packVariables(),
	})
}

// packVariables 模板可用变量清单(README 与前端说明同源, 改 ReportData 时同步)。
func packVariables() []map[string]string {
	return []map[string]string{
		{"key": ".Title", "desc": "报告标题"},
		{"key": ".Subtitle", "desc": "副标题"},
		{"key": ".Client", "desc": "客户名(config.yaml client)"},
		{"key": ".Operator", "desc": "报告人 / 操作者"},
		{"key": ".Tool", "desc": "工具名与版本"},
		{"key": ".GeneratedAtText", "desc": "生成时间(2006-01-02 15:04)"},
		{"key": ".Targets", "desc": "扫描目标列表"},
		{"key": ".Stats", "desc": "统计(AssetTotal/VulnTotal/RiskScore/RiskLevel 等)"},
		{"key": ".SevRows", "desc": "等级分布行(Key/Label/Count)"},
		{"key": ".Assets", "desc": "资产列表(IP/Hostname/OS/Ports/Tags/Alive)"},
		{"key": ".Vulns", "desc": "漏洞列表(Title/Severity/AssetIP/Port/CVE/Description)"},
		{"key": ".ScansView", "desc": "扫描任务(章节四)"},
		{"key": ".TopoRows", "desc": "拓扑行(章节五)"},
		{"key": ".Logo", "desc": "logo(data URI, config.yaml logo)"},
		{"key": ".Accent", "desc": "主题色"},
		{"key": ".Footer", "desc": "页脚文案"},
		{"key": ".Cover", "desc": "是否渲染封面"},
		{"key": ".Sections", "desc": "章节顺序"},
		{"key": "join", "desc": "函数: 拼接端口/标签列表"},
		{"key": "sevLabel", "desc": "函数: 等级 key 转中文"},
	}
}

type packSaveReq struct {
	ID      string             `json:"id"`
	Name    string             `json:"name"`
	Config  *report.PackConfig `json:"config"`
	HTML    string             `json:"html"`    // report.html.tpl 内容
	Docx    string             `json:"docx"`    // report.docx.tpl 的 base64
	LogoB64 string             `json:"logoB64"` // logo 二进制 base64(可选, 与 config.logo 二选一)
	LogoExt string             `json:"logoExt"` // png/jpg/svg
}

// hPackSave POST /api/v2/report/packs 创建/更新模板包(目录式)。
func hPackSave(w http.ResponseWriter, r *http.Request) {
	if !packManagementEnabled() {
		server.Fail(w, http.StatusForbidden, server.CodeBadRequest,
			"模板管理已关闭: 在页面的功能开关里重新开启即可(无需重启)")
		return
	}
	var req packSaveReq
	if !decodeJSON(w, r, &req) {
		return
	}
	id := strings.TrimSpace(req.ID)
	if !report.ValidPackID(id) || id == report.BuiltinPackID {
		server.FailBadRequest(w, "模板 ID 非法(仅中英文/数字/-_/空格, 不含路径符, 不能是 default)")
		return
	}
	dir := filepath.Join(packTplDir(), id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		server.FailInternal(w, "模板目录创建失败: "+err.Error())
		return
	}
	// 落盘顺序: 先写模板文件, 再写 config(配置文件最后写 = 目录完整性的标志)
	written := []string{}
	if strings.TrimSpace(req.HTML) != "" {
		if len(req.HTML) > packMaxBytes {
			server.FailBadRequest(w, "HTML 模板超过 10MB 上限")
			return
		}
		if err := writeAtomic(filepath.Join(dir, report.PackHTMLFile), []byte(req.HTML)); err != nil {
			server.FailInternal(w, "HTML 模板写入失败: "+err.Error())
			return
		}
		written = append(written, report.PackHTMLFile)
	}
	if strings.TrimSpace(req.Docx) != "" {
		data, err := base64.StdEncoding.DecodeString(req.Docx)
		if err != nil {
			server.FailBadRequest(w, "docx 须为二进制的 base64")
			return
		}
		if len(data) > packMaxBytes {
			server.FailBadRequest(w, "Word 模板超过 10MB 上限")
			return
		}
		// 入口即校验(同旧 Word 上传): 假模板留到生成时才炸, 排查成本高得多
		if _, err := report.ReadDocx(data); err != nil {
			server.FailBadRequest(w, "不是有效的 Word 模板: "+err.Error())
			return
		}
		if err := writeAtomic(filepath.Join(dir, report.PackDocxFile), data); err != nil {
			server.FailInternal(w, "Word 模板写入失败: "+err.Error())
			return
		}
		written = append(written, report.PackDocxFile)
	}
	var logoName string
	if strings.TrimSpace(req.LogoB64) != "" {
		data, err := base64.StdEncoding.DecodeString(req.LogoB64)
		if err != nil || len(data) == 0 {
			server.FailBadRequest(w, "logoB64 非法")
			return
		}
		ext := strings.ToLower(strings.TrimSpace(req.LogoExt))
		switch ext {
		case ".png", "png":
			logoName = "logo.png"
		case ".jpg", ".jpeg", "jpg", "jpeg":
			logoName = "logo.jpg"
		case ".svg", "svg":
			logoName = "logo.svg"
		default:
			server.FailBadRequest(w, "logo 仅支持 png / jpg / svg")
			return
		}
		if err := writeAtomic(filepath.Join(dir, logoName), data); err != nil {
			server.FailInternal(w, "logo 写入失败: "+err.Error())
			return
		}
		written = append(written, logoName)
	}
	cfg := report.PackConfig{}
	if req.Config != nil {
		cfg = *req.Config
	}
	if strings.TrimSpace(req.Name) != "" {
		cfg.Name = strings.TrimSpace(req.Name)
	}
	if cfg.Name == "" {
		cfg.Name = id
	}
	if logoName != "" {
		cfg.Logo = logoName
	}
	if err := writeAtomic(filepath.Join(dir, report.PackConfigFile), []byte(packConfigToYAML(cfg))); err != nil {
		server.FailInternal(w, "配置写入失败: "+err.Error())
		return
	}
	written = append(written, report.PackConfigFile)
	if len(written) == 1 { // 只写了 config: 模板目录没有可用出口, 提示用户
		reportLogLine("[模板] 模板包 " + id + " 只写了 config.yaml, 缺 HTML/Word 出口")
	}
	d := v2GetDB()
	if d != nil {
		logAudit(d, r, "report.pack.save", id, strings.Join(written, ","))
	}
	server.OK(w, map[string]any{"id": id, "written": written})
}

// hPackDelete DELETE /api/v2/report/packs/{id}
func hPackDelete(w http.ResponseWriter, r *http.Request) {
	if !packManagementEnabled() {
		server.Fail(w, http.StatusForbidden, server.CodeBadRequest, "模板管理未启用")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if !report.ValidPackID(id) || id == report.BuiltinPackID {
		server.FailBadRequest(w, "模板 ID 非法或内置模板不可删")
		return
	}
	dir := filepath.Join(packTplDir(), id)
	if _, err := os.Stat(dir); err != nil {
		server.FailNotFound(w, "模板不存在: "+id)
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		server.FailInternal(w, "删除失败: "+err.Error())
		return
	}
	d := v2GetDB()
	if d != nil {
		logAudit(d, r, "report.pack.delete", id, "")
	}
	server.OK(w, map[string]any{"deleted": id})
}

// hPackDownload GET /api/v2/report/packs/{id}/download?kind=zip|html|docx|config
//
// zip 是默认形态: 模板包是"一个目录", 单文件下载拿不到完整模板(logo 会丢),
// 用户拿到 zip 解压后即可直接改完再传回来。
func hPackDownload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if !report.ValidPackID(id) {
		server.FailBadRequest(w, "模板 ID 非法")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	if kind == "" {
		kind = "zip"
	}
	dir := filepath.Join(packTplDir(), id)
	switch kind {
	case "html", "docx", "config":
		var name string
		switch kind {
		case "html":
			name = report.PackHTMLFile
		case "docx":
			name = report.PackDocxFile
		default:
			name = report.PackConfigFile
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			server.FailNotFound(w, "模板文件不存在: "+name)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+id+"_"+name+`"`)
		_, _ = w.Write(data)
		return
	case "zip":
		buf, err := zipPackDir(dir, id)
		if err != nil {
			server.FailNotFound(w, "模板不存在: "+id)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+id+`_template.zip"`)
		_, _ = w.Write(buf)
		return
	default:
		server.FailBadRequest(w, "kind 仅支持 zip / html / docx / config")
	}
}

// zipPackDir 把模板目录打成 zip(内存里完成, 不落临时文件)。
func zipPackDir(dir, id string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		fw, cerr := zw.Create(id + "/" + e.Name())
		if cerr != nil {
			continue
		}
		_, _ = fw.Write(data)
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// packConfigToYAML 生成 config.yaml 文本(自写序列化, 保持与 packyaml.go 对称)。
//
// 手写而不用 yaml.Marshal: 本文件所在包(main)没有 yaml 依赖, 且我们只需要固定
// 顺序的固定字段 —— 生成的注释本身就是模板作者的使用说明。
func packConfigToYAML(c report.PackConfig) string {
	var sb strings.Builder
	sb.WriteString("# Yugsight 报告模板配置\n")
	sb.WriteString("# 修改后重启服务即可生效; 字段缺失一律回落到内置 default 模板。\n\n")
	sb.WriteString("name: " + orDefault(c.Name, "自定义模板") + "\n")
	sb.WriteString("client: " + orDefault(c.Client, "") + "\n")
	if strings.TrimSpace(c.Logo) != "" {
		sb.WriteString("logo: " + c.Logo + "\n")
	}
	sb.WriteString("accent: " + orDefault(c.Accent, report.DefaultAccent) + "\n")
	sb.WriteString("footer: " + orDefault(c.Footer, report.DefaultFooter) + "\n")
	cover := true
	if c.Cover != nil {
		cover = *c.Cover
	}
	sb.WriteString(fmt.Sprintf("cover: %v\n", cover))
	sb.WriteString("\n# 章节顺序(可删减, 未知名称会被忽略)\n")
	sb.WriteString("sections:\n")
	for _, s := range c.Sections {
		if strings.TrimSpace(s) == "" {
			continue
		}
		sb.WriteString("  - " + s + "\n")
	}
	return sb.String()
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// loadPackByID 按 ID 取模板包(目录不存在 = 报错, 不静默回落内置)。
//
// 为什么不存在要报错而不是回落: 用户显式选了某个模板, 静默换成内置会产出
// "样式不对但看不出原因"的报告 —— 这类问题在交给客户后才发现, 代价极高。
func loadPackByID(id string) (*report.Pack, error) {
	id = strings.TrimSpace(id)
	if !report.ValidPackID(id) {
		return nil, fmt.Errorf("模板 ID 非法: %s", id)
	}
	packs, _ := report.LoadPackDir(packTplDir())
	for _, p := range packs {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, fmt.Errorf("模板包不存在: %s (可用: %s)", id, strings.Join(packIDs(packs), ", "))
}

func packIDs(packs []*report.Pack) []string {
	out := make([]string, 0, len(packs))
	for _, p := range packs {
		out = append(out, p.ID)
	}
	return out
}

// renderWithPack 按模板包渲染报告(html / word / pdf 三个出口)。
//
// 三个出口共用同一份 ReportData 与同一个模板包 —— "同一模板改 logo 配色即生效"
// 的落地点: 配色与 logo 来自 config.yaml, 三出口都读它。
func renderWithPack(arch *report.Archive, pack *report.Pack, snap *report.Snapshot,
	stats report.SnapshotStats, cfg ReportConfig, req reportRequest) error {
	data := report.BuildReportData(snap, stats, pack, cfg.Subtitle)
	header := report.EffectiveHeader(req.Header)

	switch arch.Format {
	case report.FormatWord:
		blocks, err := packDocxBlocks(pack)
		if err != nil {
			return err
		}
		values := report.PlaceholderValues(snap, stats)
		values["subtitle"] = cfg.Subtitle
		if pack.Config.Client != "" {
			values["client"] = pack.Config.Client
		}
		full := report.InsertSections(blocks, report.SectionBlocks(snap, stats, header.Disclaimer))
		full = report.ReplacePlaceholders(full, values)
		docx, err := report.WriteDocx(full, report.DocxMeta{Title: snap.Title, Author: snap.Operator})
		if err != nil {
			return fmt.Errorf("Word 文档生成失败: %w", err)
		}
		arch.ContentB64 = base64.StdEncoding.EncodeToString(docx)
	case report.FormatPDF:
		html := renderPackHTML(data, pack)
		// 外部转换器仅在该开关显式打开时尝试; 失败/缺失一律回落打印通道
		if pdfExternalEnabled() {
			pdf, err := report.ConvertHTMLToPDF(html, 60*time.Second)
			if err == nil && len(pdf) > 0 {
				arch.ContentB64 = base64.StdEncoding.EncodeToString(pdf)
				break
			}
			if err != nil {
				reportLogLine("[模板] PDF 外部转换失败, 回落打印通道: " + err.Error())
			}
		}
		arch.Content = report.PrintHTML(html, snap.Title)
	default: // html
		arch.Content = renderPackHTML(data, pack)
	}
	arch.TemplateName = "模板包: " + pack.Name
	return nil
}

// packDocxBlocks 取模板包的 Word 块序列(没有 docx 模板时用内置)。
func packDocxBlocks(pack *report.Pack) ([]report.Block, error) {
	if len(pack.DocxTpl) > 0 {
		blocks, err := report.ReadDocx(pack.DocxTpl)
		if err != nil {
			return nil, fmt.Errorf("Word 模板解析失败(%s): %w", pack.ID, err)
		}
		return blocks, nil
	}
	return report.BuiltinWordTemplate(), nil
}

// renderPackHTML 渲染模板包 HTML; 模板语法错误时回落内置模板并记日志。
func renderPackHTML(data *report.ReportData, pack *report.Pack) string {
	html, err := report.RenderPackHTML(data, pack.HTMLTpl)
	if err != nil {
		reportLogLine("[模板] " + pack.ID + " 渲染失败, 回落内置模板: " + err.Error())
		html, err = report.RenderPackHTML(data, "")
		if err != nil {
			// 内置模板是硬编码常量, 走到这里说明数据有问题, 报告不能为空
			reportLogLine("[模板] 内置模板渲染失败: " + err.Error())
			return "<html><body><p>报告渲染失败: " + htmlEscape(err.Error()) + "</p></body></html>"
		}
	}
	return html
}

// 注: 错误信息落进 HTML 用的 htmlEscape 已在 probe_agent_install.go 定义(同签名), 直接复用。

// writeAtomic 原子写(tmp + rename): 模板写到一半中断不留半截文件。
//
// Windows 上 rename 到已存在文件会失败, 必须先删目标 —— 这是踩过的坑。
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
	}
	return os.Rename(tmp, path)
}
