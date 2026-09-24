package weakpass

import (
	"bufio"
	"embed"
	"errors"
	"os"
	"strings"
	"sync"
)

//go:embed top100.txt
var builtinDictFS embed.FS

// BuiltinDict 内置常见口令字典(top100, 打包进二进制, 不依赖外部文件)。
//
// 用 go:embed 而非硬编码切片: 用户想增删条目时只需编辑 top100.txt,
// 不必改 Go 代码 —— 字典是数据不是逻辑。
func BuiltinDict() []string { return parseDict(builtinText()) }

var (
	builtinOnce sync.Once
	builtinRaw  string
	builtinErr  error
)

// builtinText 读内置字典原文(读失败返回空串, 由 parseDict 兜底为空字典)。
func builtinText() string {
	builtinOnce.Do(func() {
		b, err := builtinDictFS.ReadFile("top100.txt")
		if err != nil {
			builtinErr = err
			return
		}
		builtinRaw = string(b)
	})
	return builtinRaw
}

// BuiltinLoadErr 内置字典读取错误(供状态接口提示; 理论上不会发生,
// 发生说明二进制被裁剪过, 必须显式告知而不是静默用空字典)。
func BuiltinLoadErr() error { builtinText(); return builtinErr }

// ErrNoDictFile 用户字典文件未找到(降级用内置字典, 不是致命错误)。
var ErrNoDictFile = errors.New("weakpass: 用户字典文件不存在")

// loadDict 组装本次使用的字典(全量口径: 内置 + 自定义)。
//
// 优先级(从高到低):
//  1. 注入的字典源(weak_password_dict 表 = 内置 349 + 页面自定义), 返回非空则直接用;
//  2. 内置字典 + 用户字典文件(DictFile) —— 字典源未注入 / 返回空(读失败)时的降级链。
//
// 降级不阻断是项目规则 3: 数据库不可用不该让弱口令检测整个跑不了,
// 退回内置字典只是少了自定义条目, 把原因记进审计而不是让任务失败。
func (e *Engine) loadDict() []string {
	e.mu.Lock()
	src := e.dictSource
	e.mu.Unlock()
	if src != nil {
		if full := src(); len(full) > 0 {
			return dedupeStrings(full)
		}
		// 源返回空 = 字典表读失败或表被清空 —— 退回内置(见 DictSource 语义约定),
		// 记一条审计让运维知道"自定义字典没生效", 而不是静默用内置。
		e.record(Attempt{Time: e.timeNow(), Err: "字典源返回空(已降级为内置字典)"})
	}
	out := BuiltinDict()
	path := strings.TrimSpace(e.cfg.DictFile)
	if path == "" {
		return out
	}
	user, err := loadDictFile(path)
	if err != nil {
		e.record(Attempt{Time: e.timeNow(), Err: "用户字典加载失败(已用内置字典): " + err.Error()})
		return out
	}
	return dedupeStrings(append(append([]string{}, out...), user...))
}

// resolveDict 按选项解析本次检测使用的字典(抽成方法便于单测, 逻辑单一)。
//
// 优先级: 显式 Dict > (BuiltinOnly ? 仅内置 : 全量 loadDict)。
// 显式 Dict 表示调用方已给出精确意图, BuiltinOnly 不再生效。
func (e *Engine) resolveDict(opt Options) []string {
	if len(opt.Dict) > 0 {
		return opt.Dict
	}
	if opt.BuiltinOnly {
		return BuiltinDict() // 仅内置: 不读数据库自定义, 也不读用户文件
	}
	return e.loadDict()
}

// dedupeStrings 保序去重(保持"内置在前、自定义在后"的爆破顺序)。
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// loadDictFile 读用户字典文件(每行一个口令; 空行与 # 开头注释行跳过)。
func loadDictFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrNoDictFile
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if strings.HasPrefix(line, "#") {
			continue
		}
		// 口令可以含空格, 只去首尾空白中的换行/制表, 保留中间空格
		line = strings.Trim(line, "\r\n\t")
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// parseDict 解析字典文本(每行一条)。
func parseDict(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.Trim(line, "\r\n\t")
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}
