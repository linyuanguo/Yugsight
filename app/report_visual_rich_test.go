package main

// 可视化模板富文本(2026-09-25 二轮: 页眉/页脚/标题/版权/检测工具/免责声明/
// 报告人/生成时间 可编辑可删除 + 字体颜色/底色/格式)的契约测试:
// ① 保存模板时富文本字段被白名单清洗(script 进不去);
// ② 生成 Word 报告时自定义标题/报告人/版权 烤进 docx 且格式属性不丢;
// ③ 版权信息显式清空 = 不出该章; 旧模板(无 copyright 键) = 默认版权兜底;
// ④ 页脚富文本进 HTML 出口。

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yugsight/internal/report"
)

// saveVisualTpl POST 可视化模板, 返回模板名; 失败 Fatal。
func saveVisualTpl(t *testing.T, h http.Handler, body string) string {
	t.Helper()
	w := doReq(t, h, "POST", "/api/v2/report/word/templates/visual", body)
	if w.Code != 200 {
		t.Fatalf("保存模板失败: %d %s", w.Code, w.Body.String())
	}
	var r struct {
		Data struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil || r.Data.Name == "" {
		t.Fatalf("解析模板名失败: %v %s", err, w.Body.String())
	}
	return r.Data.Name
}

// generateWordReport 生成并存档 Word 报告, 返回 docx 字节。
func generateWordReport(t *testing.T, h http.Handler, title, tpl string) []byte {
	t.Helper()
	body := `{"format":"word","archive":true`
	if title != "" {
		body += `,"title":"` + title + `"`
	}
	if tpl != "" {
		body += `,"wordTemplate":"` + tpl + `"`
	}
	body += `}`
	w := doReq(t, h, "POST", "/api/v2/report/generate", body)
	if w.Code != 200 {
		t.Fatalf("生成报告失败: %d %s", w.Code, w.Body.String())
	}
	var r struct {
		Data struct {
			Report struct {
				ID string `json:"id"`
			} `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil || r.Data.Report.ID == "" {
		t.Fatalf("解析报告 id 失败: %v %s", err, w.Body.String())
	}
	dw := doReq(t, h, "GET", "/api/v2/report/"+r.Data.Report.ID+"/download", "")
	if dw.Code != 200 {
		t.Fatalf("下载报告失败: %d", dw.Code)
	}
	data := dw.Body.Bytes() // 下载端点直接回 docx 二进制
	if len(data) == 0 {
		t.Fatal("报告正文为空")
	}
	return data
}

func readDocxBlocks(t *testing.T, data []byte) []report.Block {
	t.Helper()
	blocks, err := report.ReadDocx(data)
	if err != nil {
		t.Fatalf("ReadDocx: %v", err)
	}
	return blocks
}

// docxTextAll 全块文本拼接(断言章节内容用)。
func docxTextAll(blocks []report.Block) string {
	var sb strings.Builder
	for _, b := range blocks {
		for _, r := range b.Runs {
			sb.WriteString(r.Text)
		}
	}
	return sb.String()
}

func TestVisualTplRichSaveSanitizedAndRendered(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)

	// 标题带 script 注入企图 + 自定义颜色; 报告人/检测工具自定义; 版权自定义
	tplBody := `{
		"name":"富文本模板",
		"cover":true,
		"title":"<b>自定义标题</b><script>alert(1)</script>",
		"operator":"<span style=\"color:#c00000\">张三</span>",
		"tool":"Yugsight + Nmap",
		"copyright":"<span style=\"color:#c00000\">Copyright © 2026 测试公司. 版权所有。</span>",
		"footer":"<i>测试页脚</i>",
		"timeMode":"custom","timeText":"2026-09-25 测试时间"
	}`
	name := saveVisualTpl(t, h, tplBody)

	// ① 落盘的 .visual.json 不应含 script
	cfgPath := filepath.Join(wordTplDir(), name+".visual.json")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("读模板配置: %v", err)
	}
	if strings.Contains(string(raw), "script") || strings.Contains(string(raw), "alert") {
		t.Fatalf("富文本字段必须被白名单清洗, 落盘仍含 script: %s", raw)
	}

	// ② 生成 Word 报告: 标题/报告人/版权/时间 都在且格式属性不丢
	blocks := readDocxBlocks(t, generateWordReport(t, h, "任务A", name))
	text := docxTextAll(blocks)
	for _, want := range []string{"自定义标题", "张三", "Yugsight + Nmap", "2026-09-25 测试时间", "Copyright © 2026 测试公司"} {
		if !strings.Contains(text, want) {
			t.Fatalf("报告缺少「%s」: %s", want, text[:min(len(text), 300)])
		}
	}
	// 标题加粗 + 报告人红色
	var titleBold, opColor, cpColor bool
	for _, b := range blocks {
		for _, r := range b.Runs {
			if r.Text == "自定义标题" && r.Bold {
				titleBold = true
			}
			if r.Text == "张三" && r.Color == "C00000" {
				opColor = true
			}
			if strings.Contains(r.Text, "Copyright © 2026 测试公司") && r.Color == "C00000" {
				cpColor = true
			}
		}
	}
	if !titleBold || !opColor || !cpColor {
		t.Fatalf("格式属性丢失: titleBold=%v opColor=%v cpColor=%v", titleBold, opColor, cpColor)
	}
}

func TestVisualTplCopyrightExplicitEmptySkipped(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)

	// copyright 显式 ""(JSON 键存在) = 用户删掉了版权 → 报告不出该章
	name := saveVisualTpl(t, h, `{"name":"无版权模板","copyright":""}`)
	blocks := readDocxBlocks(t, generateWordReport(t, h, "任务B", name))
	if strings.Contains(docxTextAll(blocks), "版权信息") {
		t.Fatal("显式清空版权后, 报告不应再出现版权信息章节")
	}
}

func TestVisualTplLegacyNoCopyrightKeepsDefault(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)

	// 旧模板(无 copyright 键) → 默认版权兜底保留(兼容存量 .visual.json)
	name := saveVisualTpl(t, h, `{"name":"旧版模板"}`)
	blocks := readDocxBlocks(t, generateWordReport(t, h, "任务C", name))
	if !strings.Contains(docxTextAll(blocks), "Copyright © 2026 yugo") {
		t.Fatal("旧模板(无 copyright 键)应保留默认版权文案")
	}
}

// TestVisualTplSectionStylesInReport 守"逐章节字体颜色/底色/格式"的端到端契约
// (2026-09-25 三轮, 内容不可改只改观感): 编辑器里配的章节样式必须真的落到
// 生成的报告里, 且两个出口(Word/HTML)观感一致。改坏这里 = 用户配的颜色/底色
// 在生成时静默丢失 —— 报告看着没变, 排查不到原因。
func TestVisualTplSectionStylesInReport(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)

	name := saveVisualTpl(t, h, `{
		"name":"章节样式模板",
		"cover":false,
		"sections":["summary","risk","assets","vulns"],
		"sectionStyles":{
			"summary":{"titleColor":"#B91C1C","bg":"F5F3FF","bold":true},
			"vulns":{"fontColor":"#0B5394"},
			"not-a-section":{"bg":"FFFF00"}
		}
	}`)

	// ① 落盘口径: 颜色归一化去 #, 未知章节 key 丢弃(与 Order 向前兼容同口径)。
	//    断言不依赖 JSON 缩进格式(落盘走 MarshalIndent, 键值间有空格)
	raw, err := os.ReadFile(filepath.Join(wordTplDir(), name+".visual.json"))
	if err != nil {
		t.Fatalf("读模板配置: %v", err)
	}
	if strings.Contains(string(raw), "#") {
		t.Fatalf("落盘颜色应归一化(去 #): %s", raw)
	}
	if !strings.Contains(string(raw), "B91C1C") || !strings.Contains(string(raw), "0B5394") {
		t.Fatalf("章节样式未落盘: %s", raw)
	}
	if strings.Contains(string(raw), "not-a-section") {
		t.Fatalf("未知章节 key 应丢弃: %s", raw)
	}

	// ② Word 出口: 标题字色 / 章节底色(段落底纹) / 正文加粗
	blocks := readDocxBlocks(t, generateWordReport(t, h, "任务E", name))
	var headColor, secShd, bodyBold, vulnFontColor, sevKept bool
	for i, b := range blocks {
		if b.Style == "Heading1" && strings.Contains(b.Text(), "总体概况") {
			if len(b.Runs) > 0 && b.Runs[0].Color == "B91C1C" {
				headColor = true
			}
			for _, nb := range blocks[i+1:] {
				if nb.Kind != "p" {
					break // 遇表格即该章正文结束
				}
				if nb.Shd == "F5F3FF" {
					secShd = true
					if len(nb.Runs) > 0 && nb.Runs[0].Bold {
						bodyBold = true
					}
				}
			}
		}
		// 漏洞明细表: 未设色的普通单元格套章节字色, 级别列严重度着色保留
		if b.Kind == "tbl" && len(b.Rows) > 1 && len(b.Rows[1].Cells) > 1 {
			if b.Rows[1].Cells[1].Runs[0].Color == "0B5394" {
				vulnFontColor = true
			}
			if c := b.Rows[1].Cells[0].Runs[0].Color; c != "" && c != "0B5394" {
				sevKept = true
			}
		}
	}
	if !headColor || !secShd || !bodyBold {
		t.Fatalf("Word 出口章节样式缺失: headColor=%v secShd=%v bodyBold=%v", headColor, secShd, bodyBold)
	}
	if !vulnFontColor || !sevKept {
		t.Fatalf("正文字色口径错误(应套色且保留级别列原色): fontColor=%v sevKept=%v", vulnFontColor, sevKept)
	}

	// ③ HTML 出口: 同一份块序列的段落底色必须渲染出来(两出口观感一致)
	gen := doReq(t, h, "POST", "/api/v2/report/generate",
		`{"format":"html","archive":true,"wordTemplate":"`+name+`","title":"任务F"}`)
	if gen.Code != 200 {
		t.Fatalf("生成 HTML 失败: %d %s", gen.Code, gen.Body.String())
	}
	var gr struct {
		Data struct {
			Report struct {
				ID string `json:"id"`
			} `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(gen.Body.Bytes(), &gr); err != nil {
		t.Fatalf("解析: %v", err)
	}
	pw := doReq(t, h, "GET", "/api/v2/report/"+gr.Data.Report.ID+"/preview", "")
	if pw.Code != 200 {
		t.Fatalf("预览失败: %d", pw.Code)
	}
	if !strings.Contains(pw.Body.String(), "background-color:#F5F3FF") {
		t.Fatal("HTML 出口缺章节底色(与 Word 出口不一致)")
	}
}

func TestVisualTplRichFooterInHTML(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)

	name := saveVisualTpl(t, h, `{"name":"富页脚模板","footer":"<u>页脚带下划</u>"}`)
	body := `{"format":"html","archive":true,"wordTemplate":"` + name + `","title":"任务D"}`
	w := doReq(t, h, "POST", "/api/v2/report/generate", body)
	if w.Code != 200 {
		t.Fatalf("生成失败: %d %s", w.Code, w.Body.String())
	}
	var r struct {
		Data struct {
			Report struct {
				ID string `json:"id"`
			} `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatalf("解析: %v", err)
	}
	pw := doReq(t, h, "GET", "/api/v2/report/"+r.Data.Report.ID+"/preview", "")
	if pw.Code != 200 {
		t.Fatalf("预览失败: %d", pw.Code)
	}
	if !strings.Contains(pw.Body.String(), "<u>页脚带下划</u>") {
		t.Fatal("HTML 出口页脚应原样渲染富文本片段")
	}
}
