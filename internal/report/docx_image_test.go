package report

// docx 图片链路的契约守卫(2026-09-25 用户要求"报告模板能放 logo"):
//
//	模板保存(WriteDocx 带图) → 模板读回(ReadDocx 还原图) → 报告生成
//	(WriteDocx 重打包 / HTML 渲染) —— 三段任何一处丢图, logo 就名存实亡。
// 这里用现场生成的最小 PNG 做闭环验证(离线、无外部文件)。

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

// makeTestPNG 生成 8x4 单色 PNG(够小, 尺寸校验可断言)。
func makeTestPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{0x4F, 0x46, 0xE5, 0xFF})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("生成测试 PNG 失败: %v", err)
	}
	return buf.Bytes()
}

func stdB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func countZipEntry(t *testing.T, docx []byte, name string) int {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(docx), int64(len(docx)))
	if err != nil {
		t.Fatalf("打开 docx 包失败: %v", err)
	}
	n := 0
	for _, f := range zr.File {
		if f.Name == name {
			n++
		}
	}
	return n
}

func TestDocxImageRoundTrip(t *testing.T) {
	pngData := makeTestPNG(t)

	blocks := []Block{
		{Kind: "p", Align: "center", Runs: []Run{{
			MediaName: "logo.png",
			ImageB64:  stdB64(pngData),
			ImageW:    8,
			ImageH:    4,
		}}},
		{Kind: "p", Runs: []Run{{Text: "标题段落"}}},
	}

	docx, err := WriteDocx(blocks, DocxMeta{Title: "img-test"})
	if err != nil {
		t.Fatalf("WriteDocx 失败: %v", err)
	}

	// media 部件必须在包里
	if countZipEntry(t, docx, "word/media/logo.png") != 1 {
		t.Fatal("docx 包缺少 word/media/logo.png 部件")
	}

	// 读回: 图片 run 的数据与尺寸必须还原(尺寸 EMU→px 有 ±1 取整误差, 按近似断言)
	got, err := ReadDocx(docx)
	if err != nil {
		t.Fatalf("ReadDocx 失败: %v", err)
	}
	var imgRun *Run
	for i := range got {
		for j := range got[i].Runs {
			if got[i].Runs[j].MediaName == "logo.png" {
				imgRun = &got[i].Runs[j]
			}
		}
	}
	if imgRun == nil {
		t.Fatal("ReadDocx 未还原图片 run(模板保存→生成会丢 logo)")
	}
	if imgRun.ImageB64 != stdB64(pngData) {
		t.Fatal("图片字节在 docx 往返中变化(logo 会坏)")
	}
	if abs(imgRun.ImageW-8) > 1 || abs(imgRun.ImageH-4) > 1 {
		t.Errorf("图片尺寸还原错误: %dx%d, 期望约 8x4", imgRun.ImageW, imgRun.ImageH)
	}
	// 文本 run 不受影响
	if len(got) < 2 || got[1].Text() != "标题段落" {
		t.Fatal("图片段不应影响后续文本段落")
	}

	// 二次写回(= 报告生成环节): 图片仍在, 且能再次读回
	docx2, err := WriteDocx(got, DocxMeta{Title: "img-test-2"})
	if err != nil {
		t.Fatalf("二次 WriteDocx 失败: %v", err)
	}
	if countZipEntry(t, docx2, "word/media/logo.png") != 1 {
		t.Fatal("二次打包丢失 media 部件")
	}

	// HTML 出口: 图片必须渲染成自包含 data URI(报告不能引用外部图片路径)
	htmlStr := BlocksToHTML(got)
	if !strings.Contains(htmlStr, `<img src="data:image/png;base64,`) {
		t.Fatal("HTML 出口未渲染图片(data URI)")
	}
	if strings.Contains(htmlStr, `src="word/media`) {
		t.Fatal("HTML 出口引用了 docx 内部路径(离线打开会裂图)")
	}
}

// TestDocxImageDedup 同一张图被多个 run 引用时 media 部件只写一份。
func TestDocxImageDedup(t *testing.T) {
	pngData := makeTestPNG(t)
	run := Run{MediaName: "logo.png", ImageB64: stdB64(pngData), ImageW: 8, ImageH: 4}
	blocks := []Block{
		{Kind: "p", Runs: []Run{run}},
		{Kind: "p", Runs: []Run{run}}, // 第二次引用同一张
	}
	docx, err := WriteDocx(blocks, DocxMeta{Title: "dedup"})
	if err != nil {
		t.Fatalf("WriteDocx 失败: %v", err)
	}
	if n := countZipEntry(t, docx, "word/media/logo.png"); n != 1 {
		t.Fatalf("同一图片应只写一个 media 部件, 实际 %d 个", n)
	}
}
