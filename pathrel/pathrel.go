// Package pathrel 日志/展示用的路径相对化(纯展示口径, 不影响任何功能逻辑)。
//
// 【为什么需要】控制台与日志文件里出现的路径一律尽量显示成相对形式: 引擎/数据/
// 日志都约定放 exe 同目录树下, 绝对路径只是把安装目录重复一遍 —— 换台机器或换个
// 目录部署, 日志全变, 没法对照; 窄控制台里 E:\path\to\yugsight\dist\data\assets.jsonl
// 还会折行。相对路径跨机器一致, 且一眼能看出"就在 exe 旁边"。
//
// 【边界】只相对化 **exe 目录树内** 的路径; 目录外的路径(系统 Java 的
// C:\Program Files、用户手写的任意绝对路径)原样保留, 绝不猜测性截短 ——
// 截短会显示不可定位的假路径, 比长路径更糟。
package pathrel

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// exeDirFn exe 所在目录(相对化的基准), 测试可替换。
// 测试进程里 os.Executable() 指向 go 的临时构建目录, 无法覆盖真实磁盘布局,
// 故留一个函数变量供测试注入(与 envdetect 早期同款手法)。
var exeDirFn = func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

// SetExeDirForTest 测试替换 exe 目录定位。
// 注意: 这是全局状态, 同一测试二进制内多包共用时, 调用方必须 t.Cleanup 还原。
func SetExeDirForTest(fn func() string) {
	if fn != nil {
		exeDirFn = fn
	}
}

// prefix 相对路径前缀: Windows ".\" / 其它 "./"。
func prefix() string {
	if runtime.GOOS == "windows" {
		return ".\\"
	}
	return "./"
}

// Short 把单个绝对路径转成 exe 目录树内的相对短路径(如 ".\bin\nucleicore.exe")。
// 不在 exe 目录下或基准不可得时原样返回, 不做强制截短。
func Short(p string) string {
	if p == "" {
		return ""
	}
	base := exeDirFn()
	if base == "" {
		return p
	}
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return p
	}
	return prefix() + rel
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isSep(c byte) bool { return c == '\\' || c == '/' }

// InMessage 把日志消息中出现的 **exe 目录前缀** 替换为 ".\"/"./"(Windows 大小写不敏感)。
//
// 这是日志入口(logLine)的兜底钩子: 不管哪个模块、哪条消息, 只要出现 exe 目录下的
// 绝对路径就相对化。实现上只匹配 exe 自身目录前缀, 因此对 URL、CIDR、系统路径等
// 内容零误伤; 匹配时做两侧边界检查:
//   - 前一字符不得是字母数字 —— 防止 "XE:\..." 这类长串里的子串误命中;
//   - 后一字符必须是分隔符或消息结尾 —— 防止 exe 目录 "dist" 把 "dist2\..." 的前缀换掉。
func InMessage(msg string) string {
	base := exeDirFn()
	if base == "" {
		return msg
	}
	base = filepath.Clean(base)
	lowerMsg := strings.ToLower(msg)
	lowerBase := strings.ToLower(base)
	if !strings.Contains(lowerMsg, lowerBase) {
		return msg
	}
	p := prefix()
	var b strings.Builder
	b.Grow(len(msg))
	for i := 0; i < len(msg); {
		j := strings.Index(lowerMsg[i:], lowerBase)
		if j < 0 {
			b.WriteString(msg[i:])
			break
		}
		start := i + j
		end := start + len(base)
		if start > 0 && isAlnum(msg[start-1]) || end < len(msg) && !isSep(msg[end]) {
			// 边界不满足: 原样带过, 且至少前进一个字符(否则同一位置反复匹配死循环)
			b.WriteString(msg[i : start+1])
			i = start + 1
			continue
		}
		b.WriteString(msg[i:start])
		b.WriteString(p)
		// p 自带尾分隔符, 必须把原路径里紧跟 base 的那个分隔符一起吞掉,
		// 否则 base\sub 会变成 "..\sub"(两个连续分隔符)
		if end < len(msg) {
			end++
		}
		i = end
	}
	return b.String()
}
