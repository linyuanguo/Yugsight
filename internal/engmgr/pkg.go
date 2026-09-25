// pkg.go 归档解包工具探测与执行(7z / bsdtar), 仅 Windows 需要。
//
// 背景: nmap 官方自 7.93 起不再发布 Windows 免安装 zip, 只有 -setup.exe(7z 自解压)。
// 要在"不手工下载"的前提下拿到 nmap.exe, 唯一可控的路径是:
//   1) 下载官方 setup.exe;
//   2) 从自解压包中抽取 nmap.exe(而非运行安装器 —— 运行安装器需要管理员权限,
//      会污染系统目录, 且静默安装参数不受我们控制, 属于不可接受的行为)。
//
// 第 2 步需要 7z 解包能力。项目零第三方依赖, 所以按优先级探测系统已有的解包器:
//   1. PATH 里的 7z.exe / 7za.exe / 7zr.exe
//   2. 7-Zip 常见安装目录
//   3. Win10 1803+ 自带的 tar.exe(bsdtar, 支持 7z? 不支持 —— 但支持 zip/tar.gz,
//      且这里保留它是为了将来扩展到其它 SFX 格式)
// 探测不到时明确报错(由上层转成"给出官方下载页"的提示), 绝不静默假装成功。
package engmgr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// isWindows 包内共享的平台判定(与 envdetect/engine 的判定口径一致)
var isWindows = runtime.GOOS == "windows"

// executablePerm 解包出的可执行文件权限。Windows 忽略该值, 但交叉编译到
// Linux/macOS 时必须带上 x 位, 否则装入 bin/ 后无法运行(引擎会变成"存在但跑不起来")。
const executablePerm os.FileMode = 0o755

// toolCmd 一个解包工具及其参数构造方式。
//
// 参数因工具而异(7z 用 -o<dir>, bsdtar 用 -C <dir>, 且两者对"从偏移读取归档"
// 的支持完全不同), 所以用构造函数封装, 而不是拼字符串。
type toolCmd struct {
	Path string
	Name string // 展示名(日志/错误信息里用)
	// Args 用给定的归档路径与偏移构造命令行参数
	Args func(archive string, dir string, offset int64) []string
}

// extractTools 可用解包工具集合
type extractTools struct {
	Commands []toolCmd
	Timeout  time.Duration
}

// DetectExtractTools 探测系统可用的解包工具。非 Windows 永远返回空集合
// (非 Windows 平台不需要 SFX 解包: Trivy/nuclei 都有原生 tar.gz)。
//
// 探测是有代价的(要遍历 PATH 与几个固定目录), 但只在"需要从 SFX 取文件"时调用,
// 不在启动路径上。
func DetectExtractTools() extractTools {
	ts := extractTools{Timeout: 3 * time.Minute}
	if !isWindows {
		return ts
	}
	// 1) PATH 中的 7z 系
	for _, n := range []string{"7z", "7za", "7zr"} {
		if p, err := exec.LookPath(n); err == nil {
			ts.Commands = append(ts.Commands, sevenZipCmd(p))
		}
	}
	// 2) 7-Zip 常见安装位置(未加入 PATH 的装机方式)
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "7-Zip", "7z.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "7-Zip", "7z.exe"),
		filepath.Join(os.Getenv("ProgramW6432"), "7-Zip", "7z.exe"),
	} {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			ts.Commands = append(ts.Commands, sevenZipCmd(p))
		}
	}
	// 3) Windows 10 1803+ 自带的 bsdtar(用于 zip/tar.gz, 此处不作为 SFX 主力)
	if p, err := exec.LookPath("tar"); err == nil {
		ts.Commands = append(ts.Commands, bsdtarCmd(p))
	}
	return ts
}

// Available 是否至少有一个解包工具可用
func (t extractTools) Available() bool { return len(t.Commands) > 0 }

// Names 可用工具的展示名(供前端提示"需要 7-Zip"时说明当前探测到什么)
func (t extractTools) Names() []string {
	out := make([]string, 0, len(t.Commands))
	for _, c := range t.Commands {
		out = append(out, c.Name)
	}
	return out
}

// sevenZipCmd 7-Zip CLI: 7z x -y -o<dir> <archive> [文件过滤器]
//
// 关于 SFX 偏移: 7-Zip 能直接把 exe 当归档打开(它会自动定位内嵌归档),
// 因此这里不传偏移 —— 传偏移反而会破坏它的自动识别。
func sevenZipCmd(p string) toolCmd {
	return toolCmd{
		Path: p,
		Name: filepath.Base(p),
		Args: func(archive, dir string, _ int64) []string {
			// -aos 覆盖同名文件? 这里用 -aou 生成不冲突名会污染目录; 用 -y 覆盖更可预测。
			// 只解出 .exe, 避免把整包(含文档/示例)铺到目标目录。
			return []string{"x", "-y", "-o" + dir, archive, "*.exe"}
		},
	}
}

// bsdtarCmd Windows 自带 tar: tar -xf <archive> -C <dir>
//
// bsdtar 不认 7z, 这里保留是为了覆盖"包体其实是 zip 但被当作 SFX 处理"的边角情况;
// 它对 7z 会直接报错, 由调用方按顺序回退。
func bsdtarCmd(p string) toolCmd {
	return toolCmd{
		Path: p,
		Name: filepath.Base(p),
		Args: func(archive, dir string, _ int64) []string {
			return []string{"-xf", archive, "-C", dir}
		},
	}
}

// runTool 执行解包命令并返回合并输出(用于错误信息里带上下文)。
// 失败时即使输出为空也能返回有意义的错误(退出码 + 首行输出)。
func runTool(path string, args []string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("解包超时(超过 %s)", timeout)
	}
	return string(out), err
}

// firstLine 取首行非空输出并限长(错误信息里带上解包器的真实报错, 便于排查)
func firstLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if ln != "" {
			if len([]rune(ln)) > 160 {
				ln = string([]rune(ln)[:160]) + "..."
			}
			return ln
		}
	}
	return "(无输出)"
}
