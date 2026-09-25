package scanner

import (
	"net"
	"strings"
)

// ===== 任务参数解析(中心端 TaskAssign.Args -> Config) =====

// OptionsFromArgs 从中心端下发的 Args 解析扫描配置。
//
// 支持字段(全部可选, 缺省即内置默认, 保证"不带参数也能跑"):
//
//	ports            string  端口串 "22,80,443" / "1-1024"
//	concurrency      number  并发度(上限 512, 防单任务打满探针)
//	timeoutMs        number  单端口连接超时(毫秒)
//	enableNuclei     bool    内置 Nuclei POC 验证(默认 true)
//	nucleiTags       string  模板白名单(tag 或 severity, 逗号分隔)
//	nucleiExclude    string  模板黑名单
//	enableArp        bool    ARP 存活探测(默认 true, 仅 Windows 生效)
//	enableExternal   bool    外部引擎增强(默认 true, bin/ 缺失时自动跳过)
//	synscan          bool    SYN 半开扫描(默认 false; 需 Windows+管理员, 否则自动降级)
//	nmapArgs/trivyArgs/zapArgs  []string 外部引擎追加参数
//
// 数值字段容忍 JSON 解码后的 float64(json.Number 会解成 float64);
// 类型不符一律忽略该字段(防御性: 中心端参数错误不应让探针任务失败)。
func OptionsFromArgs(args map[string]any, base Config) Config {
	cfg := base
	if len(args) == 0 {
		// 无参数: 内置能力默认全开(外部引擎由 bin/ 是否存在自动决定)
		cfg.EnableNuclei = true
		cfg.EnableArp = true
		cfg.EnableExternal = true
		return cfg
	}
	if s, ok := strArg(args, "ports"); ok && strings.TrimSpace(s) != "" {
		if ports, err := ParsePortsParam(s); err == nil && len(ports) > 0 {
			cfg.Ports = ports
		}
	}
	if n, ok := intArg(args, "concurrency"); ok && n > 0 {
		if n > 512 {
			n = 512 // 上限: 探针通常部署在低配机器, 不允许多任务把句柄数打满
		}
		cfg.Concurrency = n
	}
	if n, ok := intArg(args, "timeoutMs"); ok && n > 0 {
		if n > 30000 {
			n = 30000
		}
		cfg.Timeout.Dial = msToDuration(n)
	}
	cfg.EnableNuclei = boolArg(args, "enableNuclei", true)
	cfg.EnableArp = boolArg(args, "enableArp", true)
	cfg.EnableExternal = boolArg(args, "enableExternal", true)
	// SYN 扫描默认关闭(项目规则 5): 它依赖管理员权限与系统策略, 默认开启会让
	// "不支持的环境"每次都多走一遍失败的原始套接字创建。必须中心端显式下发。
	cfg.EnableSynScan = boolArg(args, "synscan", false)
	if s, ok := strArg(args, "nucleiTags"); ok {
		cfg.NucleiTags = splitCSV(s)
	}
	if s, ok := strArg(args, "nucleiExclude"); ok {
		cfg.NucleiTagsExclude = splitCSV(s)
	}
	extra := map[string]any{}
	for _, k := range []string{"nmapArgs", "trivyArgs", "zapArgs"} {
		if v, ok := args[k]; ok {
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		cfg.ExtraArgs = extra
	}
	return cfg
}

// ===== 参数取值小工具(容错: 类型不符即忽略) =====

func strArg(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func boolArg(m map[string]any, key string, def bool) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return def
	}
	b, ok := v.(bool)
	if !ok {
		return def
	}
	return b
}

func intArg(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64: // JSON 数字默认解码为 float64
		return int(n), true
	}
	return 0, false
}

// ===== 目标/端口解析 =====

// ParsePortsParam 解析端口参数("80,443" / "1-1024" / 混合), 空值给常用端口。
//
// 单段上限 5000 个端口: 防止 "1-65535" 这类输入把探针打进长时间扫描
// (探针是远端机器, 用户无法直接 kill, 只能等超时)。
func ParsePortsParam(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DefaultPorts, nil
	}
	var out []int
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "-"); i > 0 {
			lo, err1 := atoiSafe(part[:i])
			hi, err2 := atoiSafe(part[i+1:])
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				continue
			}
			if hi-lo > 5000 {
				hi = lo + 5000
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		p, err := atoiSafe(part)
		if err != nil || p < 1 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return []int{80, 443}, nil
	}
	return out, nil
}

// splitCSV 逗号分隔串切分(去空白与空项)。
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// lookupAddr 反向 DNS 解析(失败返回错误, 由调用方忽略)。
func lookupAddr(host string) ([]string, error) {
	return net.LookupAddr(host)
}
