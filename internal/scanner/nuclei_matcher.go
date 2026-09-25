//go:build !windows || windows

// nuclei_matcher.go 匹配判定层(与解析层 nuclei_parser.go、执行层 nuclei_runner.go 分离)。
//
// 职责边界:
//   - 输入: 解析层产出的 Template/Matcher + 执行层传入的响应上下文 matchCtx
//   - 输出: 布尔命中结果与命中的 matcher 索引(供执行层做降噪/组装)
//   - 不发起任何网络请求, 不持有目标状态, 纯函数式判定;
//     后续替换主机漏洞规则时, 只需实现同样的"matcher 判定"契约即可换层
//
// 包含:
//   - status / word / regex / dsl 四类 matcher 判定(对齐 nuclei 语义)
//   - 基础 DSL 表达式引擎(nuclei dsl 的安全子集, 纯静态解释器, 无代码执行路径)
//   - 进程级正则预编译 / DSL 分词缓存(性能优化, 带内存上限)
package scanner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ===== matcher 性能优化: 进程级预编译缓存 =====
//
// 同一条正则 / DSL 表达式会在多模板、多目标、多请求间反复使用,
// 每次判定都重新 Compile/tokenize 时开销按请求数放大(数千模板场景尤其明显)。
// 这里引入进程级缓存: 每条表达式全进程只编译/分词一次;
// 缓存带上限保护(超限整体重置), 防止模板库持续注入时内存无界增长。
// 编译/分词失败记 Debug 日志(每条表达式仅一次, 走负缓存), 不吞错误。

const matcherCacheLimit = 4096

var (
	reMu    sync.Mutex
	reCache = map[string]*regexp.Regexp{} // 正则预编译缓存; nil 值 = 编译失败(负缓存, 避免重复试编译)

	dslTokMu    sync.Mutex
	dslTokCache = map[string][]dslToken{} // DSL 分词缓存; nil 值 = 表达式非法
)

// cachedRegex 返回预编译正则(首次使用时编译并缓存); 非法正则返回 (nil, false)。
// 并发安全: 持锁编译, 同一 pattern 全进程只编译一次。
func cachedRegex(pattern string) (*regexp.Regexp, bool) {
	reMu.Lock()
	defer reMu.Unlock()
	if len(reCache) > matcherCacheLimit {
		reCache = make(map[string]*regexp.Regexp, 1024)
	}
	if re, ok := reCache[pattern]; ok {
		return re, re != nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
		nucleiLog.Debug("正则编译失败, 该 matcher 不会命中", "pattern", pattern, "err", err)
	}
	reCache[pattern] = re
	return re, re != nil
}

// cachedDslTokens 返回预分词的 DSL token 序列(首次使用时分词并缓存); 非法表达式返回 (nil, false)。
func cachedDslTokens(expr string) ([]dslToken, bool) {
	dslTokMu.Lock()
	defer dslTokMu.Unlock()
	if len(dslTokCache) > matcherCacheLimit {
		dslTokCache = make(map[string][]dslToken, 1024)
	}
	if toks, ok := dslTokCache[expr]; ok {
		return toks, toks != nil
	}
	toks, err := dslTokenize(expr)
	if err != nil || len(toks) == 0 {
		toks = nil
		nucleiLog.Debug("DSL 分词失败, 该表达式不会命中", "expr", expr, "err", err)
	}
	dslTokCache[expr] = toks
	return toks, toks != nil
}

// ===== matcher 引擎 =====

// matchCtx 响应上下文(matcher 判定用)
type matchCtx struct {
	statusCode int
	body       string
	header     string // "Key: Value\n" 格式
	cookies    string
}

func (c *matchCtx) dslEnv() dslEnv {
	return dslEnv{statusCode: c.statusCode, body: c.body, header: c.header, cookies: c.cookies}
}

// evalMatcher 判定单个 matcher。
//
//	Part 决定匹配目标: body(默认) / header / status_code;
//	Condition 决定同 matcher 内多个值如何联合: and=全部命中, or(默认)=任一命中;
//	Negative 对结果取反。
func evalMatcher(m Matcher, c *matchCtx) bool {
	var target string
	switch m.Part {
	case "header":
		target = c.header
	case "status_code":
		target = strconv.Itoa(c.statusCode)
	default:
		target = c.body
	}
	var ok bool
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if s == c.statusCode {
				ok = true
				break
			}
		}
	case "word":
		lt := strings.ToLower(target)
		if strings.EqualFold(m.Condition, "and") {
			ok = len(m.Words) > 0
			for _, w := range m.Words {
				if !strings.Contains(lt, strings.ToLower(w)) {
					ok = false
					break
				}
			}
		} else {
			for _, w := range m.Words {
				if strings.Contains(lt, strings.ToLower(w)) {
					ok = true
					break
				}
			}
		}
	case "regex":
		for _, pat := range m.Regexes {
			if cRe, ok2 := cachedRegex(pat); ok2 && cRe.MatchString(target) {
				ok = true
				break
			}
		}
	case "dsl":
		env := c.dslEnv()
		for _, expr := range m.DSL {
			if hit, err := dslEval(expr, env); err == nil && hit {
				ok = true
				break
			} else if err != nil {
				nucleiLog.Debug("dsl 表达式无效", "expr", expr, "err", err)
			}
		}
	default:
		nucleiLog.Debug("未知 matcher 类型, 跳过", "type", m.Type)
	}
	if m.Negative {
		ok = !ok
	}
	return ok
}

// evalTemplateMatchers 多 matcher 联合判定(对齐 nuclei 语义):
// 任一 matcher 声明 condition=and 时, 所有 matcher 必须同时命中(AND);
// 否则任一命中即算命中(OR)。无 matcher 的模板不产生结果。
func evalTemplateMatchers(ms []Matcher, c *matchCtx) bool {
	hit, _ := evalTemplateMatchersDetail(ms, c)
	return hit
}

// evalTemplateMatchersDetail 同 evalTemplateMatchers, 额外返回逐个命中的 matcher 索引
// (AND 模式下为全部索引, OR 模式下为命中的那个)。供重复响应页降噪判断
// 命中是否来自结构性 matcher(status/header)。
func evalTemplateMatchersDetail(ms []Matcher, c *matchCtx) (bool, []int) {
	if len(ms) == 0 {
		return false, nil
	}
	andMode := false
	for _, m := range ms {
		if strings.EqualFold(m.Condition, "and") {
			andMode = true
			break
		}
	}
	if andMode {
		var idx []int
		for i, m := range ms {
			if !evalMatcher(m, c) {
				return false, nil
			}
			idx = append(idx, i)
		}
		return true, idx
	}
	for i, m := range ms {
		if evalMatcher(m, c) {
			return true, []int{i}
		}
	}
	return false, nil
}

// hasStructuralMatch 命中的 matcher 里是否存在结构性判定(status_code / header 部分)。
// 重复响应页场景下, 这类命中通常有意义(如统一拦截页的 403 状态码), 不应被降噪抑制。
func hasStructuralMatch(ms []Matcher, matchedIdx []int) bool {
	for _, i := range matchedIdx {
		if i < 0 || i >= len(ms) {
			continue
		}
		if ms[i].Part == "status_code" || ms[i].Part == "header" {
			return true
		}
	}
	return false
}

// ===== 基础 DSL 表达式引擎(nuclei dsl 的安全子集) =====
//
// 纯静态解释器, 无代码执行路径:
//   - 变量仅限 status_code(int) / body / header / cookies(string)
//   - 函数仅限 contains/len/lower/upper/starts_with/ends_with
//   - 运算符: && || ! == != > < >= <= ( ) 及函数调用
//
// 示例: status_code == 200 && contains(body, "nginx") && len(body) > 1000

type dslValue struct {
	kind string // int / string / bool
	i    int
	s    string
	b    bool
}

type dslEnv struct {
	statusCode int
	body       string
	header     string
	cookies    string
}

type dslToken struct {
	kind string // num / str / ident / op
	text string
	n    int
}

var (
	dslTwoCharOps = []string{"&&", "||", "==", "!=", ">=", "<="}
	dslOneCharOps = []string{"(", ")", "!", ">", "<", ","}
)

func dslTokenize(s string) ([]dslToken, error) {
	var toks []dslToken
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("字符串未闭合")
			}
			v, err := strconv.Unquote(s[i : j+1])
			if err != nil {
				return nil, fmt.Errorf("字符串无效: %v", err)
			}
			toks = append(toks, dslToken{kind: "str", text: v})
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			n, err := strconv.Atoi(s[i:j])
			if err != nil {
				return nil, err
			}
			toks = append(toks, dslToken{kind: "num", n: n})
			i = j
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_':
			j := i
			for j < len(s) && ((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') ||
				(s[j] >= '0' && s[j] <= '9') || s[j] == '_' || s[j] == '-') {
				j++
			}
			toks = append(toks, dslToken{kind: "ident", text: s[i:j]})
			i = j
		default:
			matched := false
			for _, op := range dslTwoCharOps {
				if i+1 < len(s) && s[i:i+2] == op {
					toks = append(toks, dslToken{kind: "op", text: op})
					i += 2
					matched = true
					break
				}
			}
			if matched {
				continue
			}
			for _, op := range dslOneCharOps {
				if string(c) == op {
					toks = append(toks, dslToken{kind: "op", text: op})
					i++
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("不支持的字符: %q", c)
			}
		}
	}
	return toks, nil
}

// dslParser 递归下降: or -> and -> cmp -> unary -> primary
type dslParser struct {
	toks []dslToken
	pos  int
	env  dslEnv
}

func (p *dslParser) peek() *dslToken {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *dslParser) next() *dslToken {
	t := p.peek()
	if t != nil {
		p.pos++
	}
	return t
}

func (p *dslParser) op(text string) bool {
	t := p.peek()
	if t != nil && t.kind == "op" && t.text == text {
		p.pos++
		return true
	}
	return false
}

func (p *dslParser) parse() (dslValue, error) {
	v, err := p.parseOr()
	if err != nil {
		return dslValue{}, err
	}
	if p.pos != len(p.toks) {
		return dslValue{}, fmt.Errorf("表达式存在多余部分: %s", p.toks[p.pos].text)
	}
	return v, nil
}

func (p *dslParser) parseOr() (dslValue, error) {
	left, err := p.parseAnd()
	if err != nil {
		return dslValue{}, err
	}
	for p.op("||") {
		right, err := p.parseAnd()
		if err != nil {
			return dslValue{}, err
		}
		if left.kind != "bool" || right.kind != "bool" {
			return dslValue{}, fmt.Errorf("|| 两侧必须是布尔")
		}
		left = dslValue{kind: "bool", b: left.b || right.b}
	}
	return left, nil
}

func (p *dslParser) parseAnd() (dslValue, error) {
	left, err := p.parseCmp()
	if err != nil {
		return dslValue{}, err
	}
	for p.op("&&") {
		right, err := p.parseCmp()
		if err != nil {
			return dslValue{}, err
		}
		if left.kind != "bool" || right.kind != "bool" {
			return dslValue{}, fmt.Errorf("&& 两侧必须是布尔")
		}
		left = dslValue{kind: "bool", b: left.b && right.b}
	}
	return left, nil
}

var dslCmpOps = map[string]bool{"==": true, "!=": true, ">": true, "<": true, ">=": true, "<=": true}

func (p *dslParser) parseCmp() (dslValue, error) {
	left, err := p.parseUnary()
	if err != nil {
		return dslValue{}, err
	}
	for {
		t := p.peek()
		if t == nil || t.kind != "op" || !dslCmpOps[t.text] {
			return left, nil
		}
		op := t.text
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return dslValue{}, err
		}
		v, err := dslCompare(op, left, right)
		if err != nil {
			return dslValue{}, err
		}
		left = v
	}
}

func (p *dslParser) parseUnary() (dslValue, error) {
	if p.op("!") {
		v, err := p.parseUnary()
		if err != nil {
			return dslValue{}, err
		}
		if v.kind != "bool" {
			return dslValue{}, fmt.Errorf("取反仅支持布尔")
		}
		return dslValue{kind: "bool", b: !v.b}, nil
	}
	return p.parsePrimary()
}

func (p *dslParser) parsePrimary() (dslValue, error) {
	t := p.next()
	if t == nil {
		return dslValue{}, fmt.Errorf("表达式不完整")
	}
	switch t.kind {
	case "num":
		return dslValue{kind: "int", i: t.n}, nil
	case "str":
		return dslValue{kind: "string", s: t.text}, nil
	case "ident":
		if p.peek() != nil && p.peek().kind == "op" && p.peek().text == "(" {
			p.next()
			return p.parseCall(t.text)
		}
		return dslVar(t.text, &p.env)
	case "op":
		if t.text == "(" {
			v, err := p.parseOr()
			if err != nil {
				return dslValue{}, err
			}
			if !p.op(")") {
				return dslValue{}, fmt.Errorf("缺少 )")
			}
			return v, nil
		}
	}
	return dslValue{}, fmt.Errorf("意外 token: %s", t.text)
}

func (p *dslParser) parseCall(name string) (dslValue, error) {
	var args []dslValue
	if !p.op(")") {
		for {
			a, err := p.parseOr()
			if err != nil {
				return dslValue{}, err
			}
			args = append(args, a)
			if p.op(")") {
				break
			}
			if !p.op(",") {
				return dslValue{}, fmt.Errorf("缺少 , 或 )")
			}
		}
	}
	return dslCall(name, args)
}

func dslVar(name string, env *dslEnv) (dslValue, error) {
	switch name {
	case "status_code":
		return dslValue{kind: "int", i: env.statusCode}, nil
	case "body":
		return dslValue{kind: "string", s: env.body}, nil
	case "header", "headers":
		return dslValue{kind: "string", s: env.header}, nil
	case "cookies":
		return dslValue{kind: "string", s: env.cookies}, nil
	default:
		return dslValue{}, fmt.Errorf("未知变量: %s", name)
	}
}

func dslCall(name string, args []dslValue) (dslValue, error) {
	strArg := func(i int) (string, error) {
		if i >= len(args) || args[i].kind != "string" {
			return "", fmt.Errorf("%s 第 %d 个参数必须是字符串", name, i+1)
		}
		return args[i].s, nil
	}
	need2 := func() (string, string, error) {
		a, err := strArg(0)
		if err != nil {
			return "", "", err
		}
		b, err := strArg(1)
		if err != nil {
			return "", "", err
		}
		return a, b, nil
	}
	switch name {
	case "contains":
		a, b, err := need2()
		if err != nil {
			return dslValue{}, err
		}
		return dslValue{kind: "bool", b: strings.Contains(strings.ToLower(a), strings.ToLower(b))}, nil
	case "len":
		v, err := strArg(0)
		if err != nil {
			return dslValue{}, err
		}
		return dslValue{kind: "int", i: len(v)}, nil
	case "lower":
		v, err := strArg(0)
		if err != nil {
			return dslValue{}, err
		}
		return dslValue{kind: "string", s: strings.ToLower(v)}, nil
	case "upper":
		v, err := strArg(0)
		if err != nil {
			return dslValue{}, err
		}
		return dslValue{kind: "string", s: strings.ToUpper(v)}, nil
	case "starts_with":
		a, b, err := need2()
		if err != nil {
			return dslValue{}, err
		}
		return dslValue{kind: "bool", b: strings.HasPrefix(strings.ToLower(a), strings.ToLower(b))}, nil
	case "ends_with":
		a, b, err := need2()
		if err != nil {
			return dslValue{}, err
		}
		return dslValue{kind: "bool", b: strings.HasSuffix(strings.ToLower(a), strings.ToLower(b))}, nil
	default:
		return dslValue{}, fmt.Errorf("未知函数: %s", name)
	}
}

func dslCompare(op string, l, r dslValue) (dslValue, error) {
	switch {
	case l.kind == "int" && r.kind == "int":
		var b bool
		switch op {
		case "==":
			b = l.i == r.i
		case "!=":
			b = l.i != r.i
		case ">":
			b = l.i > r.i
		case "<":
			b = l.i < r.i
		case ">=":
			b = l.i >= r.i
		case "<=":
			b = l.i <= r.i
		}
		return dslValue{kind: "bool", b: b}, nil
	case l.kind == "string" && r.kind == "string":
		switch op {
		case "==":
			return dslValue{kind: "bool", b: l.s == r.s}, nil
		case "!=":
			return dslValue{kind: "bool", b: l.s != r.s}, nil
		}
		return dslValue{}, fmt.Errorf("字符串仅支持 == / !=")
	default:
		return dslValue{}, fmt.Errorf("类型不匹配: %s 与 %s", l.kind, r.kind)
	}
}

// dslEval 求值一条基础 DSL 表达式, 返回布尔结果; 表达式非法时返回 error(由调用方记日志)。
// 走进程级分词缓存(cachedDslTokens): 同一表达式全进程只分词一次。
func dslEval(expr string, env dslEnv) (bool, error) {
	toks, ok := cachedDslTokens(expr)
	if !ok {
		return false, fmt.Errorf("DSL 表达式非法")
	}
	p := &dslParser{toks: toks, env: env}
	v, err := p.parse()
	if err != nil {
		return false, err
	}
	if v.kind != "bool" {
		return false, fmt.Errorf("表达式结果必须是布尔, 实际为 %s", v.kind)
	}
	return v.b, nil
}
