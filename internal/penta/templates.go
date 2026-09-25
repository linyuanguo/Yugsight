// templates.go EXP 模板库: 内置验证探针 + 自定义模板导入。
//
// 设计口径:
//
//   - 模板是数据(YAML/JSON), 不是可执行代码 —— 与项目"零第三方依赖 + 单二进制"
//     约束一致, 也与漏洞库规则(vuln/*.json 导入)的既有约定同构;
//   - 内置模板只覆盖"常见漏洞的可观测验证"(未授权访问 / 目录列举 / 版本暴露 /
//     敏感路径 / 路径穿越探测 / 弱口令登录 / TLS 信息), 全部是只读观测型探针,
//     不包含任何破坏性载荷;
//   - 自定义模板放 exe 同目录 penta_templates/(与 vuln/、templates/ 同约定),
//     导入走 API 校验后落盘, 非法 ID/路径一律拒绝。
package penta

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// 自定义模板目录名(exe 同目录, 不入库)。
const CustomTemplateDir = "penta_templates"

// ID 合法字符: 小写字母/数字/中划线(用作文件名, 杜绝路径穿越)。
var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

// BuiltinTemplates 内置 EXP 模板库。
//
// 每条模板的 steps 都是"观测型"探针: 发一个无害请求/交互, 看响应里有没有
// 漏洞行为的特征。这是验证(verification)不是利用(exploitation) ——
// 与 Nuclei 模板的 PoC 语义一致。
var BuiltinTemplates = []Template{
	{
		ID: "redis-unauth", Name: "Redis 未授权访问验证",
		CVE: "", Tags: []string{"redis", "unauth", "tcp"},
		Description: "对 Redis 端口发送 PING, 免认证即回 PONG 则未授权访问成立(只读命令, 无破坏性)。",
		BuiltIn: true,
		Steps: []StepSpec{
			{Name: "ping", Type: StepTCP, Port: 6379, Send: "PING\r\n", Expect: `^\+PONG`, TimeoutMs: 5000},
		},
	},
	{
		ID: "http-dir-listing", Name: "目录列举验证",
		Tags: []string{"http", "info-leak"},
		Description: "访问目录路径, 响应为 Apache/nginx 目录列表则目录列举成立(只读 GET)。",
		BuiltIn: true,
		Steps: []StepSpec{
			{Name: "root", Type: StepHTTP, Method: "GET", Path: "/", ExpectBody: `Index of /|<title>Index of`, TimeoutMs: 8000},
		},
	},
	{
		ID: "http-version-disclosure", Name: "版本信息暴露验证",
		Tags: []string{"http", "info-leak"},
		Description: "检查响应头 Server / X-Powered-By 是否暴露具体版本号(只读 GET)。",
		BuiltIn: true,
		Steps: []StepSpec{
			{Name: "headers", Type: StepHTTP, Method: "GET", Path: "/",
				ExpectHeader: map[string]string{"Server": `\d+\.\d+`, "X-Powered-By": `.`}, TimeoutMs: 8000},
		},
	},
	{
		ID: "http-sensitive-path", Name: "敏感文件探测",
		Tags: []string{"http", "info-leak"},
		Description: "探测 .env 等敏感文件是否可直读(只读 GET, 非 404/403 即疑似可访问)。",
		BuiltIn: true,
		Steps: []StepSpec{
			{Name: "env", Type: StepHTTP, Method: "GET", Path: "/.env",
				ExpectStatus: 200, ExpectBody: `(?i)(appkey|password|secret|token)`, TimeoutMs: 8000},
		},
	},
	{
		ID: "http-path-traversal", Name: "路径穿越探测",
		Tags: []string{"http", "rce-precheck"},
		Description: "以无害路径探测 ../../etc/passwd 是否可被读取(只读探测, 命中即需立即处置)。",
		BuiltIn: true,
		Steps: []StepSpec{
			{Name: "probe", Type: StepHTTP, Method: "GET",
				Path: "/../../../../etc/passwd", ExpectBody: `(?m)^root:`, TimeoutMs: 8000},
		},
	},
	{
		ID: "tcp-banner-grab", Name: "服务 Banner 抓取",
		Tags: []string{"tcp", "info-leak"},
		Description: "对目标端口抓取服务 Banner 并与任务 CVE 关联版本特征比对(通用, 需自定义 Expect 才有意义)。",
		BuiltIn: true,
		Steps: []StepSpec{
			{Name: "banner", Type: StepTCP, Expect: `.`, TimeoutMs: 6000},
		},
	},
	{
		ID: "weakpass-verify", Name: "弱口令登录验证",
		Tags: []string{"weakpass", "auth"},
		Description: "用给定账号口令对目标服务做登录试探(复用弱口令引擎: 限速 + 只试登录不注入)。口令在界面上单独填写。",
		BuiltIn: true,
		Steps: []StepSpec{
			{Name: "login", Type: StepWeakPass, Service: "", Port: 0, TimeoutMs: 15000},
		},
	},
	{
		ID: "http-tls-info", Name: "TLS/HTTP 基线核查",
		Tags: []string{"http", "baseline"},
		Description: "核查 Web 服务可达性与 HTTP→HTTPS 跳转基线(只读 GET, 用于确认漏洞载体在线)。",
		BuiltIn: true,
		Steps: []StepSpec{
			{Name: "reachable", Type: StepHTTP, Method: "GET", Path: "/", TimeoutMs: 8000},
		},
	},
}

// FindBuiltin 按 ID 查内置模板。
func FindBuiltin(id string) *Template {
	for i := range BuiltinTemplates {
		if BuiltinTemplates[i].ID == id {
			t := BuiltinTemplates[i]
			return &t
		}
	}
	return nil
}

// ParseTemplate 解析模板内容(先试 JSON 再试 YAML, 与漏洞规则导入同口径)。
func ParseTemplate(data []byte) (*Template, error) {
	trim := strings.TrimSpace(string(data))
	if trim == "" {
		return nil, fmt.Errorf("模板内容为空")
	}
	if strings.HasPrefix(trim, "{") {
		var t Template
		if err := json.Unmarshal([]byte(trim), &t); err != nil {
			return nil, fmt.Errorf("JSON 解析失败: %s", err)
		}
		return &t, nil
	}
	var t Template
	if err := yaml.Unmarshal([]byte(trim), &t); err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %s", err)
	}
	return &t, nil
}

// ValidateTemplate 校验模板合法性(导入/加载共用)。
func ValidateTemplate(t *Template) error {
	if t == nil {
		return fmt.Errorf("模板为空")
	}
	if !idRe.MatchString(t.ID) {
		return fmt.Errorf("模板 ID 非法(要求小写字母/数字/中划线, 2-64 位, 如 redis-unauth): %q", t.ID)
	}
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	if len(t.Steps) == 0 {
		return fmt.Errorf("模板至少需要一个验证步骤")
	}
	for i, s := range t.Steps {
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("第 %d 步缺少名称", i+1)
		}
		switch s.Type {
		case StepHTTP:
			if s.ExpectStatus < 0 || s.ExpectStatus > 599 {
				return fmt.Errorf("步骤 %s: expectStatus 超出范围", s.Name)
			}
		case StepTCP:
		case StepWeakPass:
			if len(s.Passwords) > maxPasswords {
				return fmt.Errorf("步骤 %s: 口令数超过上限 %d(验证场景不是爆破)", s.Name, maxPasswords)
			}
		case StepExternal:
			if strings.TrimSpace(s.Bin) == "" {
				return fmt.Errorf("步骤 %s: external 步骤必须指定 bin", s.Name)
			}
		default:
			return fmt.Errorf("步骤 %s: 未知类型 %q(可选 http/tcp/weakpass/external)", s.Name, s.Type)
		}
		if s.TimeoutMs < 0 || s.TimeoutMs > int(maxStepTimeout.Milliseconds()) {
			return fmt.Errorf("步骤 %s: timeoutMs 超出范围(0-%d)", s.Name, int(maxStepTimeout.Milliseconds()))
		}
	}
	return nil
}

// LoadCustom 加载 exe 同目录 penta_templates/ 下的全部自定义模板。
//
// 目录缺失 = 空列表(降级不报错, 项目规则 3); 单个文件坏只跳过该文件。
func LoadCustom(dir string) []Template {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Template
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".json") {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			continue
		}
		t, perr := ParseTemplate(data)
		if perr != nil {
			continue
		}
		t.BuiltIn = false
		if verr := ValidateTemplate(t); verr != nil {
			continue
		}
		out = append(out, *t)
	}
	return out
}

// ImportCustom 校验并落盘一个自定义模板, 返回模板与文件路径。
//
// 文件名 = <id>.yaml(与 ID 强绑定, 杜绝上传任意文件名/路径穿越)。
// 与内置模板同 ID 一律拒绝(内置是可信基线, 不允许被覆盖)。
func ImportCustom(dir string, data []byte) (*Template, string, error) {
	t, err := ParseTemplate(data)
	if err != nil {
		return nil, "", err
	}
	if b := FindBuiltin(t.ID); b != nil {
		return nil, "", fmt.Errorf("模板 ID %q 与内置模板冲突, 请换一个 ID", t.ID)
	}
	if err := ValidateTemplate(t); err != nil {
		return nil, "", err
	}
	// 重复导入 = 覆盖(更新语义, 方便修正)
	t.BuiltIn = false
	path := filepath.Join(dir, t.ID+".yaml")
	out, _ := yaml.Marshal(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", fmt.Errorf("创建模板目录失败: %s", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return nil, "", fmt.Errorf("模板写入失败: %s", err)
	}
	return t, path, nil
}

// SuggestTemplate 按漏洞特征推荐一个内置模板(导入漏洞进工作台时用)。
//
// 启发式, 允许为空 —— 执行台里用户仍可手选。
func SuggestTemplate(protocol string, port int, title string) string {
	tl := strings.ToLower(title)
	switch {
	case port == 6379 || strings.Contains(tl, "redis"):
		return "redis-unauth"
	case strings.Contains(tl, "目录") && strings.Contains(tl, "列举") || strings.Contains(tl, "index of"):
		return "http-dir-listing"
	case strings.Contains(tl, "弱口令") || strings.Contains(tl, "空口令") || strings.Contains(tl, "弱密码"):
		return "weakpass-verify"
	case port == 80 || port == 443 || protocol == "http" || protocol == "https":
		return "http-tls-info"
	case port != 0:
		return "tcp-banner-grab"
	}
	return ""
}
