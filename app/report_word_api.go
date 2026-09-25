// report_word_api.go Word 模板文件管理 API(报告引擎的装配层)。
//
// Word 模板放 exe 同目录 res/report_templates/ —— 外部资源不嵌入二进制(与 agents/
// 探针包、templates/ 扫描模板同一约定): 模板是用户自己设计的 Word 文件, 升级
// 中心端不该要求重编译, 也不该让二进制凭空变大。
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
			list = append(list, map[string]any{
				"name":    name,
				"builtin": false,
				"size":    fi.Size(),
				"updated": fi.ModTime().Format("2006-01-02 15:04"),
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
	if name == report.BuiltinWordTemplateName {
		server.FailBadRequest(w, "内置模板不可删除")
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
	sample := &report.Snapshot{
		Title: "示例安全扫描报告", Operator: "示例报告人", Tool: "Yugsight(示例)",
		CreatedAt: time.Now(), Summary: "这是模板预览, 数据为示例值, 排版以你上传的 Word 模板为准。",
	}
	stats := report.ComputeStats(sample)
	values := report.PlaceholderValues(sample, stats)
	values["subtitle"] = "网络安全扫描与漏洞评估报告(示例)"
	full := report.ReplacePlaceholders(blocks, values)
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
