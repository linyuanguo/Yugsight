package report

// 模板编辑器富文本子集(2026-09-25)的契约测试:
// ① 清洗器必须拆掉 script/事件属性/未知标签(安全边界, 改坏=注入面);
// ② HTMLToRuns 必须把 b/i/u/颜色/底色/字号 正确映射到 Run 属性
//    (Word 出口依赖这条映射, 改坏=模板排版静默丢失);
// ③ 纯文本直通(旧模板的纯文本字段回归不破)。

import (
	"strings"
	"testing"
)

func TestSanitizeStripsScriptsAndHandlers(t *testing.T) {
	in := `<b>安全</b><script>alert(1)</script><span onclick="x()">带事件</span><img src=x onerror=y()>`
	got := SanitizeRichHTML(in)
	if strings.Contains(got, "script") || strings.Contains(got, "alert") {
		t.Fatalf("script 内容必须整体丢弃: %s", got)
	}
	if strings.Contains(got, "onclick") || strings.Contains(got, "onerror") || strings.Contains(got, "img") {
		t.Fatalf("事件属性/未知标签必须剥掉: %s", got)
	}
	if !strings.Contains(got, "<b>安全</b>") || !strings.Contains(got, "带事件") {
		t.Fatalf("合法内容应保留: %s", got)
	}
}

func TestSanitizeKeepsFormattingSubset(t *testing.T) {
	in := `<span style="color: rgb(255, 0, 0); background-color: rgb(255, 255, 0); font-size: 16px;"><b>红字黄底</b></span>`
	got := SanitizeRichHTML(in)
	if !strings.Contains(got, "color:#FF0000") {
		t.Fatalf("rgb() 应归一为 hex: %s", got)
	}
	if !strings.Contains(got, "background-color:#FFFF00") {
		t.Fatalf("底色应保留: %s", got)
	}
	// b 与 span 嵌套顺序不限, 只守"加粗+文本都在"
	if !strings.Contains(got, "<b>") || !strings.Contains(got, "</b>") || !strings.Contains(got, "红字黄底") {
		t.Fatalf("加粗应保留: %s", got)
	}
	// 二次清洗幂等(存盘前再洗一次不能变形)
	if got2 := SanitizeRichHTML(got); got2 != got {
		t.Fatalf("清洗必须幂等: %q vs %q", got, got2)
	}
}

func TestPlainTextPassthrough(t *testing.T) {
	if got := SanitizeRichHTML("网络安全扫描与漏洞评估报告"); got != "网络安全扫描与漏洞评估报告" {
		t.Fatalf("纯文本必须原样直通: %s", got)
	}
	if got := RichPlainText(`<b>页眉</b> | {{time}}`); got != "页眉 | {{time}}" {
		t.Fatalf("纯文本提取错误: %s", got)
	}
}

func TestHTMLToRunsFormats(t *testing.T) {
	base := Run{Size: 24}
	runs := HTMLToRuns(`<b>加粗</b><i>斜体</i><u>下划</u><span style="color:#ff0000">红</span><span style="background-color:#ffff00">黄底</span>`, base)
	if len(runs) != 5 {
		t.Fatalf("应 5 段, 实际 %d: %+v", len(runs), runs)
	}
	if !runs[0].Bold || runs[0].Text != "加粗" {
		t.Fatalf("第 1 段应加粗: %+v", runs[0])
	}
	if !runs[1].Italic || !runs[2].Uline {
		t.Fatalf("斜体/下划线丢失: %+v %+v", runs[1], runs[2])
	}
	if runs[3].Color != "FF0000" {
		t.Fatalf("颜色错误: %+v", runs[3])
	}
	if runs[4].Bg != "FFFF00" {
		t.Fatalf("底色错误: %+v", runs[4])
	}
	for _, r := range runs {
		if r.Size != 24 {
			t.Fatalf("未指定字号应继承 base(24): %+v", r)
		}
	}
}

func TestHTMLToRunsFontSizeAndBreak(t *testing.T) {
	runs := HTMLToRuns(`小字<div>第二行</div>`, Run{Size: 24})
	if len(runs) != 3 { // 小字 / \n / 第二行
		t.Fatalf("块级标签应产生换行段: %+v", runs)
	}
	if runs[1].Text != "\n" {
		t.Fatalf("第 2 段应是换行: %+v", runs[1])
	}
	if got := HTMLToRuns(`<span style="font-size:16px">大</span>`, Run{}); len(got) != 1 || got[0].Size != 24 {
		t.Fatalf("16px 应映射 24 半点: %+v", got)
	}
	if got := HTMLToRuns("", Run{}); got != nil {
		t.Fatalf("空片段应返回 nil: %+v", got)
	}
}

// TestDocxRoundTripRichFormats 富格式 run 的 WriteDocx→ReadDocx 往返不能丢
// (模板"保存→生成报告"链路: 烤入的格式必须活过一次 docx 重打包)。
func TestDocxRoundTripRichFormats(t *testing.T) {
	blocks := []Block{{
		Kind: "p",
		Runs: []Run{{Text: "混合", Bold: true, Italic: true, Uline: true, Color: "C00000", Bg: "FFFF00", Size: 28}},
	}}
	data, err := WriteDocx(blocks, DocxMeta{Title: "t"})
	if err != nil {
		t.Fatalf("WriteDocx: %v", err)
	}
	back, err := ReadDocx(data)
	if err != nil {
		t.Fatalf("ReadDocx: %v", err)
	}
	if len(back) != 1 || len(back[0].Runs) != 1 {
		t.Fatalf("往返块/run 数量不对: %+v", back)
	}
	r := back[0].Runs[0]
	if !r.Bold || !r.Italic || !r.Uline || r.Color != "C00000" || r.Bg != "FFFF00" || r.Size != 28 || r.Text != "混合" {
		t.Fatalf("富格式往返丢失: %+v", r)
	}
}
