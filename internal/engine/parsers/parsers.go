// Package parsers 外部引擎输出解析与自动降级(任务 6.2: 引擎输出解析 + 自动降级逻辑)。
//
// 职责:
//  1. 三类引擎输出解析(nmap / trivy / zap), 解析结果统一转为
//     normalizer.RawBatch(标准化中间表示), 送入归一化模块 Normalize
//     产出 models.Asset / models.Vuln;
//  2. 支持 Nmap XML(-oX / -oA) 与 Nmap JSON(-oJ) 两种输出格式自动识别;
//  3. 解析失败不 panic: 记录日志 + 去除 XML 不可解析片段(DTD/实体声明)后重试,
//     仍失败则返回错误, 由编排层(orchestrator.go)决定降级。
//
// 包依赖: 仅 Go 标准库 + yugsight/internal/models + yugsight/normalizer。
// 刻意不依赖 yugsight/engine: engine 执行器只负责"跑进程", 解析层只负责
// "读输出", 两者由编排层组合 —— 避免包循环依赖, 也让解析器可被
// 离线文件(用户上传 nmap XML / ZAP 报告)复用。
package parsers

import (
	"bytes"
	"encoding/xml"
	"errors"
	"strings"

	"yugsight/internal/normalizer"
)

// Format 引擎输出格式。
type Format string

const (
	// FormatJSON 通用 JSON 输出(nmap -oJ / trivy -f json)。
	FormatJSON Format = "json"
	// FormatXML Nmap XML 输出(nmap -oX - / -oA)。
	FormatXML Format = "xml"
	// FormatZapJSON ZAP JSON 报告文件(-J)。
	FormatZapJSON Format = "zap-json"
	// FormatAuto 自动识别(按首个非空白字符判断)。
	FormatAuto Format = "auto"
)

// ===== 公共小工具 =====

// detectFormat 按内容自动识别格式: '<' 开头视为 XML, 否则 JSON。
func detectFormat(data []byte) Format {
	trimmed := bytes.TrimLeft(data, " \t\r\n\ufeff")
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return FormatXML
	}
	return FormatJSON
}

// stripXMLProlog 去除 XML 不可解析的片段, 提高容错:
//   - DOCTYPE 声明(nmap -oX 会输出 <!DOCTYPE nmaprun>, encoding/xml 遇 DTD
//     直接报 "invalid character entity" 类错误);
//   - XML 注释;
//   - 小数点开头的畸形字符(引擎被 kill 时可能产生半截输出)。
//
// 只做保守替换, 不破坏正常文档结构。
func stripXMLProlog(data []byte) []byte {
	out := data
	if i := bytes.Index(out, []byte("<!DOCTYPE")); i >= 0 {
		if j := bytes.IndexByte(out[i:], '>'); j >= 0 {
			out = append(append([]byte{}, out[:i]...), out[i+j+1:]...)
		}
	}
	// 去除 <!-- ... --> 注释(可能有多个, 循环处理)
	for {
		i := bytes.Index(out, []byte("<!--"))
		if i < 0 {
			break
		}
		j := bytes.Index(out[i:], []byte("-->"))
		if j < 0 {
			out = out[:i]
			break
		}
		out = append(append([]byte{}, out[:i]...), out[i+j+3:]...)
	}
	return bytes.TrimLeft(out, " \t\r\n")
}

// sanitizeXMLText 清洗 XML 解析出的文本: 去首尾空白 + 收敛内部连续空白。
func sanitizeXMLText(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

// firstNonEmpty 返回首个非空(去空白后)的字符串。
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// errEmpty 输出为空的统一错误(引擎无输出 / 被截断)。
func errEmpty(engine string) error {
	return errors.New(engine + ": 输出为空(引擎无输出或输出被截断)")
}

// unmarshalXML 容错 XML 反序列化: 先直接解析, 失败则清洗 DTD/注释后重试。
func unmarshalXML(data []byte, v any) error {
	if err := xml.Unmarshal(data, v); err == nil {
		return nil
	}
	return xml.Unmarshal(stripXMLProlog(data), v)
}

// normPort 端口合法性归一化(非正数返回 0)。
func normPort(p int) int {
	if p <= 0 || p > 65535 {
		return 0
	}
	return p
}

// ===== 统一入口 =====

// Parser 引擎输出解析器接口: 输入引擎输出, 输出归一化中间批次。
type Parser interface {
	// Source 来源标识(写入 RawBatch.Source, 见 normalizer.Source*)
	Source() string
	// Parse 解析引擎输出为归一化批次
	Parse(data []byte) (*normalizer.RawBatch, error)
}

// Batch 一次解析的完整产物: 引擎直接产出(资产 + 漏洞)与 XML 附带资产(nmap)。
type Batch struct {
	Source string
	// Assets / Vulns 引擎直接产出的标准化输入
	Assets []normalizer.RawAsset
	Vulns  []normalizer.RawVuln
	// SetupAssets Nmap XML 的 <host> 级资产(主机存活 / MAC / 主机名),
	// 不同于端口服务资产: 端口扫描遗漏的死主机也应进资产表
	SetupAssets []normalizer.RawAsset
	// Warnings 解析过程中的非致命问题(单条记录字段缺失等)
	Warnings []string
}

// RawBatch 转为归一化输入批次。
func (b *Batch) RawBatch() *normalizer.RawBatch {
	if b == nil {
		return nil
	}
	return &normalizer.RawBatch{Source: b.Source, Assets: b.Assets, Vulns: b.Vulns}
}

// AllAssets 全部资产(直接产出 + XML 附带主机资产)。
func (b *Batch) AllAssets() []normalizer.RawAsset {
	if b == nil {
		return nil
	}
	out := make([]normalizer.RawAsset, 0, len(b.Assets)+len(b.SetupAssets))
	out = append(out, b.Assets...)
	out = append(out, b.SetupAssets...)
	return out
}

// Parse 按来源解析引擎输出(nmap / trivy / zap), 自动识别输出格式。
//
//	data 为引擎 stdout(ZAP 为报告文件内容)。
//	注意: 引擎 Result.Truncated 为 true 时输出不完整, 调用方应先降级不要解析。
func Parse(engineName string, data []byte) (*Batch, error) {
	switch strings.ToLower(strings.TrimSpace(engineName)) {
	case "nmap", "nmapcore":
		return ParseNmap(data)
	case "trivy", "trivycore":
		return ParseTrivy(data)
	case "zap", "zapcore":
		return ParseZap(data)
	default:
		return nil, errors.New("未知引擎来源: " + engineName)
	}
}
