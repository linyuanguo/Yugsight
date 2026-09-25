// pdfconv.go PDF 输出通道(二期预留): 调外部转换器把 HTML 转成 PDF。
//
// ===== 为什么走外部程序 =====
//
// 纯标准库生成"带中文字体、可分页、可选中文本"的 PDF 需要: 字体解析(TrueType
// glyf 表) + CID 字体子集嵌入 + 内容流排版, 数千行且极易出乱码/缺字, 与项目
// "零第三方依赖 + 单二进制"的硬约束直接冲突。行业通行做法是调成熟的转换器。
//
// ===== 降级口径(项目规则 3/4) =====
//
// 转换器不存在 / 执行失败 / 超时, 一律返回错误由装配层回落"浏览器打印通道"
// (PrintHTML): PDF 是增强通道, 绝不能因为没有装 wkhtmltopdf 就让报告生成失败。
// 本文件不主动发起任何子进程 —— 是否调用完全由配置开关决定(默认关)。
package report

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrNoPDFConverter 未找到可用的 PDF 转换器(wkhtmltopdf / LibreOffice)。
var ErrNoPDFConverter = errors.New("未找到 PDF 转换器(需 wkhtmltopdf 或 LibreOffice soffice), 已回落浏览器打印通道")

// PDFConverter 描述一个可用的转换器。
type PDFConverter struct {
	Name string // wkhtmltopdf / libreoffice
	Path string
}

// FindPDFConverter 在 PATH 里找可用转换器(不启动进程, 只查路径)。
func FindPDFConverter() (PDFConverter, bool) {
	for _, name := range []string{"wkhtmltopdf", "wkhtmltopdf.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return PDFConverter{Name: "wkhtmltopdf", Path: p}, true
		}
	}
	for _, name := range []string{"soffice", "libreoffice", "soffice.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return PDFConverter{Name: "libreoffice", Path: p}, true
		}
	}
	return PDFConverter{}, false
}

// ConvertHTMLToPDF 把 HTML 转成 PDF 字节流; 无转换器返回 ErrNoPDFConverter。
//
// 两个转换器的调用差别必须都实现, 不能只做 wkhtmltopdf:
// 内网 Windows 机器上更常见的是装了 LibreOffice(办公软件自带), 而 wkhtmltopdf
// 需要单独下载。只支持一种会让"明明装了 Office 却说没转换器"。
func ConvertHTMLToPDF(html string, timeout time.Duration) ([]byte, error) {
	conv, ok := FindPDFConverter()
	if !ok {
		return nil, ErrNoPDFConverter
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if conv.Name == "wkhtmltopdf" {
		cmd := exec.CommandContext(ctx, conv.Path,
			"--quiet", "--encoding", "utf-8", "--no-outline",
			"--load-error-handling", "ignore", // 报告是自包含 HTML, 外链失败不该中止
			"-", "-") // stdin HTML -> stdout PDF
		cmd.Stdin = bytes.NewReader([]byte(html))
		var out, errBuf bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("wkhtmltopdf 执行失败: %w %s", err, trimErr(errBuf.String()))
		}
		if out.Len() == 0 {
			return nil, errors.New("wkhtmltopdf 未产出内容")
		}
		return out.Bytes(), nil
	}

	// LibreOffice: 只认文件输入, 必须先落临时 HTML 再收 PDF
	dir, err := os.MkdirTemp("", "yugsight-pdf")
	if err != nil {
		return nil, fmt.Errorf("临时目录创建失败: %w", err)
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "report.html")
	if err := os.WriteFile(src, []byte(html), 0o600); err != nil {
		return nil, fmt.Errorf("临时 HTML 写入失败: %w", err)
	}
	cmd := exec.CommandContext(ctx, conv.Path, "--headless", "--norestore",
		"--convert-to", "pdf", "--outdir", dir, src)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	cmd.Stdout = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("LibreOffice 转换失败: %w %s", err, trimErr(errBuf.String()))
	}
	pdf := filepath.Join(dir, "report.pdf")
	data, err := os.ReadFile(pdf)
	if err != nil {
		return nil, fmt.Errorf("PDF 产物读取失败: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("LibreOffice 未产出 PDF")
	}
	return data, nil
}

// trimErr 截断子进程错误输出(转换器的 stderr 可能很长, 只留前 200 字符)。
func trimErr(s string) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > 200 {
		return string([]rune(s)[:200]) + "..."
	}
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}
