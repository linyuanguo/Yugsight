// report_word_api.go Word 模板文件管理 API(报告引擎的装配层)。
//
// Word 模板放 exe 同目录 data/outp/(2026-09-25 用户口径; 此前在
// res/report_templates/) —— 不嵌入二进制: 模板是用户自己设计/编辑的 Word
// 文件, 升级中心端不该要求重编译, 也不该让二进制凭空变大; 放 data/ 是因为
// 它属于运行期用户数据(升级重建 dist 不应冲掉用户的模板)。
//
// 安全口径:
//   - 模板名只允许中英文/数字/-_./空格(见 validWordTplName), "builtin" 保留,
//     目录穿越在解析阶段即拒, 不到 IO;
//   - 上传内容必须能通过 report.ReadDocx 解析(真 .docx), 否则 400 ——
//     上传假模板只会让"生成报告"时才炸, 提前在入口挡住;
//   - 10MB 上限: Word 模板是"版式 + 占位符", 正常几 KB 到 1MB 封顶;
//     超大的多半是把整份旧报告当模板传, 拒掉并提示。
package main

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"yugsight/internal/models"
	"yugsight/internal/pathrel"
	"yugsight/internal/report"
	"yugsight/internal/server"
)

const wordTplMaxBytes = 10 * 1024 * 1024

// registerWordTplRoutes 在报告路由上挂载 Word 模板管理。
func registerWordTplRoutes(srv *server.Server) {
	srv.Get("/api/v2/report/word/templates", requireAuth(hWordTplList))
	srv.Post("/api/v2/report/word/templates", requireAuth(adminOrOperator(hWordTplUpload)))
	srv.Delete("/api/v2/report/word/templates/{name}", requireAuth(adminOrOperator(hWordTplDelete)))
	srv.Get("/api/v2/report/word/templates/{name}/preview", requireAuth(hWordTplPreview))
}

// hWordTplList 模板列表: 内置模板 + report_templates/ 下的 .docx 文件。
func hWordTplList(w http.ResponseWriter, r *http.Request) {
	dir := wordTplDir()
	list := []map[string]any{
		{"name": report.BuiltinWordTemplateName, "builtin": true, "size": 0},
	}
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			lower := strings.ToLower(e.Name())
			if !strings.HasSuffix(lower, ".docx") {
				continue
			}
			name := strings.TrimSuffix(lower, ".docx")
			if name == report.BuiltinWordTemplateName || !validWordTplName(name) {
				continue
			}
			fi, ierr := e.Info()
			if ierr != nil {
				continue
			}
			// visual = 该模板带可视化排版配置(.visual.json), 编辑器可回显/续改
			// logo = 封面 logo 已上传(logos/ 下有 <name>.<ext>)
			_, verr := os.Stat(filepath.Join(dir, name+".visual.json"))
			list = append(list, map[string]any{
				"name":    name,
				"builtin": false,
				"size":    fi.Size(),
				"updated": fi.ModTime().Format("2006-01-02 15:04"),
				"visual":  verr == nil,
				"logo":    logoFileName(name) != "",
			})
		}
	}
	// 目录不存在 = 只有内置模板(外部资源可选, 缺失不报错, 项目规则 3)
	server.OK(w, map[string]any{"list": list, "dir": pathrel.Short(dir)})
}

type wordTplUploadReq struct {
	Name string `json:"name"` // 模板名(不含 .docx 扩展名)
	Data string `json:"data"` // docx 二进制 base64
}

// hWordTplUpload 上传 Word 模板(JSON: name + base64 内容)。
func hWordTplUpload(w http.ResponseWriter, r *http.Request) {
	var req wordTplUploadReq
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if !validWordTplName(name) {
		server.FailBadRequest(w, "模板名非法(仅允许中英文/数字/-_./空格, 不能以 . 开头, 且不能是 builtin)")
		return
	}
	if name == report.DefaultWordTemplateName {
		server.FailBadRequest(w, "内置默认模板(default)不可修改, 请另起模板名")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil || len(data) == 0 {
		server.FailBadRequest(w, "data 须为 docx 二进制的 base64")
		return
	}
	if len(data) > wordTplMaxBytes {
		server.FailBadRequest(w, "模板超过 10MB 上限(正常模板只有几 KB~1MB)")
		return
	}
	if _, err := report.ReadDocx(data); err != nil {
		server.FailBadRequest(w, "不是有效的 Word 模板: "+err.Error())
		return
	}
	dir := wordTplDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		server.FailInternal(w, "模板目录创建失败: "+err.Error())
		return
	}
	// 原子写(tmp + rename): 上传中断不留下半截模板文件
	tmp := filepath.Join(dir, name+".docx.tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		server.FailInternal(w, "模板写入失败: "+err.Error())
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, name+".docx")); err != nil {
		_ = os.Remove(tmp)
		server.FailInternal(w, "模板落盘失败: "+err.Error())
		return
	}
	d := v2GetDB()
	if d != nil {
		logAudit(d, r, "report.wordtpl.upload", name, "size="+strconv.Itoa(len(data)))
	}
	server.OK(w, map[string]any{"name": name})
}

// hWordTplDelete 删除模板(内置模板不可删)。
func hWordTplDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if name == report.BuiltinWordTemplateName || name == report.DefaultWordTemplateName {
		server.FailBadRequest(w, "内置默认模板不可删除")
		return
	}
	if !validWordTplName(name) {
		server.FailBadRequest(w, "模板名非法")
		return
	}
	p := filepath.Join(wordTplDir(), name+".docx")
	if _, err := os.Stat(p); err != nil {
		server.FailNotFound(w, "模板不存在: "+name)
		return
	}
	if err := os.Remove(p); err != nil {
		server.FailInternal(w, "删除失败: "+err.Error())
		return
	}
	// 可视化配置随之删除(不留孤儿 .visual.json; Remove 对不存在的文件直接忽略)
	_ = os.Remove(filepath.Join(wordTplDir(), name+".visual.json"))
	d := v2GetDB()
	if d != nil {
		logAudit(d, r, "report.wordtpl.delete", name, "")
	}
	server.OK(w, map[string]any{"name": name})
}

// hWordTplPreview 模板预览: 占位符用示例值替换后转 HTML(浏览器直接看版式)。
// 预览的是"模板外壳 + 示例数据", 不是真实报告 —— 用户据此确认排版无误。
func hWordTplPreview(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	blocks, err := loadWordTemplateBlocks(name)
	if err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	// 放两条不同严重度的示例漏洞: 预览要能看出"漏洞明细表 + 逐条修复章节"的
	// 实际版式(空数据只有一张空表, 看不出排版效果)
	sample := &report.Snapshot{
		Title: "示例安全扫描报告", Operator: "示例报告人", Tool: "Yugsight(示例)",
		CreatedAt: time.Now(), Summary: "这是模板预览, 数据为示例值, 排版以你上传的 Word 模板为准。",
		Assets: []*models.Asset{
			models.NewAsset("192.168.1.10"),
		},
		Vulns: []*models.Vuln{
			{ID: "demo-1", Severity: models.SeverityCritical, Title: "示例: 远程代码执行漏洞",
				AssetIP: "192.168.1.10", Port: 8080, Protocol: "http", CVE: "CVE-2026-0001",
				Confidence: 90, Status: "open", Description: "示例描述: 攻击者可构造恶意请求执行任意代码。",
				FoundAt: time.Now(), LastSeenAt: time.Now()},
			{ID: "demo-2", Severity: models.SeverityHigh, Title: "示例: SQL 注入",
				AssetIP: "192.168.1.10", Port: 3306, Protocol: "mysql",
				Confidence: 80, Status: "open", Description: "示例描述: 输入未过滤可注入 SQL。",
				FoundAt: time.Now(), LastSeenAt: time.Now()},
		},
	}
	stats := report.ComputeStats(sample)
	values := report.PlaceholderValues(sample, stats)
	values["subtitle"] = "网络安全扫描与漏洞评估报告(示例)"
	// 可视化模板: 章节按 .visual.json 的选择/顺序渲染, 副标题用模板自带值。
	// 版权/免责声明的 Skip/Replace 必须与实际生成(generateReport)完全一致, 否则
	// "模板预览"与"真实报告"章节口径不一致(2026-09-26 修: 不勾版权, 预览仍显示)。
	var sections []report.Block
	if vcfg, _ := loadVisualTplConfig(name); vcfg != nil {
		if vcfg.Subtitle != "" {
			values["subtitle"] = vcfg.Subtitle
		}
		sections = report.SectionBlocksWithOptions(sample, stats, vcfg.Disclaimer,
			sectionOptionsFromVisual(vcfg))
	} else {
		sections = report.SectionBlocks(sample, stats, "")
	}
	full := report.ReplacePlaceholders(blocks, values)
	full = report.InsertSections(full, sections)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := report.WordPage{
		Title:  "Word 模板预览: " + orBuiltin(name),
		Header: report.ExpandHeaderValues(report.DefaultHeader(), values),
	}
	_, _ = w.Write([]byte(report.RenderWordReport(full, page)))
}

func orBuiltin(name string) string {
	if strings.TrimSpace(name) == "" {
		return report.BuiltinWordTemplateName
	}
	return name
}

// sectionOptionsFromVisual 把可视化模板配置(.visual.json)翻译成章节渲染选项。
// generateReport(实际生成)与 hWordTplPreview(模板预览)共用, 保证两条路径章节
// 口径完全一致 —— 尤其版权/免责声明的三态(nil=默认文案 / 显式空=不出该章 /
// 非空=富文本注入); 任一遗漏都会让"预览里没有但生成里有"(或反之)。
func sectionOptionsFromVisual(vcfg *VisualTpl) *report.SectionOptions {
	opts := &report.SectionOptions{
		Order:  vcfg.Sections,
		Styles: vcfg.SectionStyles,
	}
	// 版权信息: *string 三态
	if vcfg.Copyright != nil {
		if *vcfg.Copyright == "" {
			opts.Skip = append(opts.Skip, "copyright")
		} else {
			opts.Replace = map[string][]report.Block{
				"copyright": richTextBlocks(*vcfg.Copyright, report.Run{Color: "6B7280", Size: 18}),
			}
		}
	}
	// 免责声明: 含标签走富文本注入(纯文本走字符串路径, 行为不变)
	if vcfg.Disclaimer != "" && strings.ContainsAny(vcfg.Disclaimer, "<") {
		if opts.Replace == nil {
			opts.Replace = map[string][]report.Block{}
		}
		opts.Replace["disclaimer"] = richTextBlocks(vcfg.Disclaimer, report.Run{Color: "6B7280", Size: 18})
	}
	return opts
}
