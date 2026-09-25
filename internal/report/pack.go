// pack.go 模板包(二期报告中心): 目录式模板 + 统一报告数据结构 ReportData。
//
// ===== 模板目录结构 =====
//
//   build/report_templates/<模板名>/
//     config.yaml       元信息: 名称 / logo / 主题色 / 页脚 / 封面 / 章节顺序
//     report.html.tpl   HTML 模板(html/template 语法, 可选)
//     report.docx.tpl   Word 模板(可选)
//
// 构建脚本把 build/report_templates 镜像到 exe 同目录 res/report_templates/
// (外部资源, 不打包进二进制 —— 用户改 logo/配色不该要求重编译中心端)。
//
// 兼容旧形态: 目录根下直接放 <名字>.docx 也识别为模板(只有一个 Word 出口)。
//
// ===== 为什么自己解析 config.yaml 而不引 yaml.v3 =====
//
// report 包至今"只依赖 models + 标准库", 这是它能脱离运行时被单测的前提。
// config.yaml 只有标量 + 一个字符串列表两种形态, 为它把 yaml.v3 拖进本包不值
// (yaml.v3 是 scanner 的 Nuclei 模板依赖, 留在那儿即可)。故 packyaml.go 实现
// 极简子集解析: `key: value` 与 `- item`, 其它形态一律跳过并告警, 不报错。
//
// ===== 降级口径(项目规则 3/4) =====
//
// 目录缺失 / 模板文件缺失 / config.yaml 写错, 一律记入 warnings 并回落到
// 内置 default 模板 —— 内置模板恒可用, 文件全丢也能出报告。
package report

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PackConfig config.yaml 的元信息(全部可选, 空值用内置默认)。
type PackConfig struct {
	Name string `json:"name,omitempty"`
	// Client 客户名(报告封面与页脚用)
	Client string `json:"client,omitempty"`
	// Logo 品牌标识: data URI / 外链 URL / 模板目录内的文件名(三种都支持)
	Logo string `json:"logo,omitempty"`
	// Accent 主题色(如 #4f46e5)
	Accent string `json:"accent,omitempty"`
	// Footer 页脚文案
	Footer string `json:"footer,omitempty"`
	// Cover 是否生成封面页(nil = 内置默认 true)
	Cover *bool `json:"cover,omitempty"`
	// Sections 章节顺序(空 = 内置默认顺序)
	Sections []string `json:"sections,omitempty"`
}

// 内置默认(所有模板包缺字段时的兜底值, 单一事实来源)。
const (
	DefaultAccent    = "#4f46e5"
	DefaultFooter    = "本报告由 Yugsight 自动生成, 仅供内部安全评估使用"
	DefaultPackName  = "默认模板"
	BuiltinPackID    = "default"
	PackConfigFile   = "config.yaml"
	PackHTMLFile     = "report.html.tpl"
	PackDocxFile     = "report.docx.tpl"
)

// DefaultSections 内置章节顺序(config.yaml 未指定时用)。
func DefaultSections() []string {
	return []string{"summary", "assets", "vulns", "scans", "topology"}
}

// Pack 一个模板包(目录或单个 .docx)。
type Pack struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Kind: dir(目录式) / docx(旧扁平文件)
	Kind     string `json:"kind"`
	Builtin  bool   `json:"builtin,omitempty"`
	Config   PackConfig `json:"config"`
	HasHTML  bool   `json:"hasHtml"`
	HasDocx  bool   `json:"hasDocx"`
	HasCfg   bool   `json:"hasConfig"`
	// LogoData 展开后的 logo(data URI 或 URL; 空 = 不展示)。
	// 为什么在加载期就展开: 模板文件里的 logo 可能只是个文件名, 渲染期再去
	// 读盘会让渲染依赖磁盘状态(模板被删后报告渲染失败, 但报告已经生成过)。
	LogoData string `json:"logo,omitempty"`
	// Dir 模板目录(内置为空字符串)
	Dir string `json:"-"`
	// HTMLTpl HTML 模板原文(空 = 用内置模板)
	HTMLTpl string `json:"-"`
	// DocxTpl Word 模板原始字节(nil = 用内置模板)
	DocxTpl []byte `json:"-"`
}

// BuiltinPack 内置 default 模板包(无文件时恒可用)。
func BuiltinPack() *Pack {
	cover := true
	return &Pack{
		ID:      BuiltinPackID,
		Name:    DefaultPackName,
		Kind:    "dir",
		Builtin: true,
		Config: PackConfig{
			Name:     DefaultPackName,
			Accent:   DefaultAccent,
			Footer:   DefaultFooter,
			Cover:    &cover,
			Sections: DefaultSections(),
		},
	}
}

// LoadPackDir 扫描模板根目录, 返回 [内置 default] + 所有识别到的模板包。
//
// warnings 是"文件缺失/格式异常"的降级说明, 由调用方记日志(本包不碰日志系统,
// 保持可脱离运行时单测)。目录不存在时返回 (仅内置包, 一条 warning)。
func LoadPackDir(root string) ([]*Pack, []string) {
	out := []*Pack{BuiltinPack()}
	var warnings []string
	entries, err := os.ReadDir(root)
	if err != nil {
		return out, []string{"模板目录不存在(仅内置模板可用): " + root}
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if e.IsDir() {
			// 目录名本身即模板 ID
			if !ValidPackID(name) {
				continue
			}
			p, w := loadOnePack(filepath.Join(root, name), name)
			warnings = append(warnings, w...)
			if p != nil && p.ID != BuiltinPackID {
				out = append(out, p)
			}
			continue
		}
		// 旧形态: 根下扁平 .docx —— 模板 ID 是去掉扩展名后的名字, 校验必须
		// 打在 id 上。若拿带点的文件名去校验, ValidPackID 一律拒绝, 老用户
		// 的模板会在升级后凭空消失(而文件其实还在磁盘上, 极难排查)。
		if !strings.HasSuffix(strings.ToLower(name), ".docx") {
			continue
		}
		id := strings.TrimSuffix(name, filepath.Ext(name))
		if !ValidPackID(id) || id == BuiltinPackID {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(root, name))
		if rerr != nil {
			warnings = append(warnings, "模板读取失败: "+name)
			continue
		}
		out = append(out, &Pack{
			ID: id, Name: id, Kind: "docx", HasDocx: true,
			Config:  PackConfig{Name: id, Accent: DefaultAccent, Footer: DefaultFooter},
			DocxTpl: data,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin // 内置排最前
		}
		return out[i].ID < out[j].ID
	})
	return out, warnings
}

// loadOnePack 读一个模板目录。
func loadOnePack(dir, id string) (*Pack, []string) {
	var warnings []string
	p := &Pack{
		ID: id, Name: id, Kind: "dir", Dir: dir,
		Config: PackConfig{Name: id, Accent: DefaultAccent, Footer: DefaultFooter},
	}
	if b, err := os.ReadFile(filepath.Join(dir, PackConfigFile)); err == nil {
		cfg, w := ParsePackConfig(string(b))
		warnings = append(warnings, w...)
		applyPackConfig(p, cfg)
		p.HasCfg = true
	}
	if b, err := os.ReadFile(filepath.Join(dir, PackHTMLFile)); err == nil && len(b) > 0 {
		p.HTMLTpl = string(b)
		p.HasHTML = true
	}
	if b, err := os.ReadFile(filepath.Join(dir, PackDocxFile)); err == nil && len(b) > 0 {
		p.DocxTpl = b
		p.HasDocx = true
	}
	if !p.HasHTML && !p.HasDocx {
		warnings = append(warnings, "模板目录为空(缺 report.html.tpl 与 report.docx.tpl): "+id)
		return nil, warnings
	}
	p.LogoData = expandLogo(dir, p.Config.Logo)
	if p.LogoData == "" && p.Config.Logo != "" {
		warnings = append(warnings, "logo 文件不可用(已忽略): "+p.Config.Logo)
	}
	return p, warnings
}

// applyPackConfig 把解析出的配置并入模板包(空值保留内置默认)。
func applyPackConfig(p *Pack, cfg PackConfig) {
	if strings.TrimSpace(cfg.Name) != "" {
		p.Config.Name = strings.TrimSpace(cfg.Name)
		p.Name = p.Config.Name
	}
	if strings.TrimSpace(cfg.Client) != "" {
		p.Config.Client = strings.TrimSpace(cfg.Client)
	}
	if strings.TrimSpace(cfg.Logo) != "" {
		p.Config.Logo = strings.TrimSpace(cfg.Logo)
	}
	if strings.TrimSpace(cfg.Accent) != "" {
		p.Config.Accent = strings.TrimSpace(cfg.Accent)
	}
	if strings.TrimSpace(cfg.Footer) != "" {
		p.Config.Footer = strings.TrimSpace(cfg.Footer)
	}
	if cfg.Cover != nil {
		p.Config.Cover = cfg.Cover
	} else {
		c := true
		p.Config.Cover = &c
	}
	if len(cfg.Sections) > 0 {
		p.Config.Sections = cfg.Sections
	} else {
		p.Config.Sections = DefaultSections()
	}
}

// expandLogo 把 config.yaml 的 logo 值展开为可直接写进 src 的字符串。
//
// 三种形态:
//   data:...  /  http(s)://...  -> 原样返回(外链与内联都直接可用)
//   普通文件名                  -> 在模板目录内找, 转成 data URI(自包含,
//                                  报告拷给别人也不会丢图)
func expandLogo(dir, logo string) string {
	logo = strings.TrimSpace(logo)
	if logo == "" {
		return ""
	}
	if strings.HasPrefix(logo, "data:") || strings.HasPrefix(logo, "http://") || strings.HasPrefix(logo, "https://") {
		return logo
	}
	// 文件名形态: 防目录穿越(同名校验在 ValidPackID 已做, 这里再剥一次路径)
	base := filepath.Base(logo)
	if base == "." || base == string(os.PathSeparator) || base != strings.TrimSpace(logo) {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, base))
	if err != nil || len(data) == 0 {
		return ""
	}
	return dataURI(base, data)
}

// dataURI 按扩展名拼 data URI(只放行图片类型, 其它一律拒绝)。
func dataURI(name string, data []byte) string {
	var mime string
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png":
		mime = "image/png"
	case ".jpg", ".jpeg":
		mime = "image/jpeg"
	case ".gif":
		mime = "image/gif"
	case ".svg":
		mime = "image/svg+xml"
	case ".webp":
		mime = "image/webp"
	default:
		return ""
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
}

// ValidPackID 模板 ID 校验: 只允许普通目录名(防目录穿越, 解析阶段即拒)。
func ValidPackID(id string) bool {
	if id == "" || id == "." || id == ".." || len([]rune(id)) > 60 {
		return false
	}
	if strings.ContainsAny(id, "/\\") {
		return false
	}
	if strings.HasPrefix(id, ".") {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == ' ' || c >= 0x4E00: // 中文模板名是主要用法
		default:
			return false
		}
	}
	return true
}

// CoverEnabled 是否渲染封面(nil 视为 true —— 没写 config.yaml 时要有封面)。
func (p *Pack) CoverEnabled() bool {
	if p == nil || p.Config.Cover == nil {
		return true
	}
	return *p.Config.Cover
}

// SectionOrder 章节顺序(空 = 内置顺序; 未知章节名被丢弃但保留用户顺序)。
func (p *Pack) SectionOrder() []string {
	if p == nil || len(p.Config.Sections) == 0 {
		return DefaultSections()
	}
	return p.Config.Sections
}
