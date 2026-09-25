// agentpkg 探针"就地补包"工具: 中心端在本机补出当前平台的探针包。
//
// 平台口径: Windows 端为空桩(Supported()=false, 统一走 scripts/build-agents.ps1
// 产出), 非 Windows 为真实实现。见 agentpkg_windows.go / agentpkg_other.go。
//
// 设计边界(与 probe_agent_download.go 呼应):
//  - 只补"当前平台"的包 —— 交叉编译要求服务器下载整套工具链, 且产物无法当场
//    验证, 其它平台交给构建脚本;
//  - 全部失败以 CmdResult(OK=false+Error) 回传, 不返回 error、不 panic:
//    这是便捷功能, 环境不具备工具链/源码是正常状态, 不能拖垮中心端主流程。
package agentpkg

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// CmdResult 就地构建/拷贝操作的结果(调用方据此决定 API 回显)。
type CmdResult struct {
	OK      bool
	Command string // 实际执行的命令(前端日志展示)
	Output  string // 关键输出(截尾)
	Error   string
	Seconds int // 耗时秒
}

// BuildRequest 就地构建请求。
type BuildRequest struct {
	OutPath    string // 必填: 输出路径(如 agents/yugsight-agent_linux_amd64)
	RepoDir    string // 可选: 源码根目录(含 go.mod); 空 = 自动定位
	TimeoutSec int    // 可选: 构建超时(秒); 0 = 默认 300
}

// CacheHit 本地构建产物命中信息。
type CacheHit struct {
	OK      bool
	Command string
	Path    string // 源产物路径
	Error   string // 未命中时的诊断(调用方据此记"为何转真编译"日志)
}

// HostPlatform 当前平台(统一口径, 避免多处各自实现 runtime 取值)。
func HostPlatform() (string, string) {
	return runtime.GOOS, runtime.GOARCH
}

// Toolchain 探测 Go 工具链: 返回 (go 二进制路径, 版本号, 是否可用)。
//
// LookPath + `go version` 双证据: 只查 PATH 无法确认 go 命令真能执行
// (PATH 里可能放着坏的包装脚本)。version 解析 `go version go1.25.0 linux/amd64`
// 的第三段, 去掉 go 前缀。10 秒超时: 工具链卡死不该拖住列表接口。
func Toolchain() (string, string, bool) {
	bin, err := exec.LookPath("go")
	if err != nil {
		return "", "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return "", "", false
	}
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return "", "", false
	}
	return bin, strings.TrimPrefix(fields[2], "go"), true
}

// FindRepoDir 定位源码根目录(含 go.mod 且含 cmd/agent)。
//
// 查找顺序:
//  1. 环境变量 YUGSIGHT_REPO(显式指定, 覆盖 exe 不在源码树内的部署场景;
//     指定了但不合格直接失败, 不再兜底 —— 用户显式意图不应被静默改道);
//  2. 从 exe 所在目录逐级向上(≤8 级): exe 放 dist/ 时, 上一级即源码根。
func FindRepoDir() (string, bool) {
	if env := strings.TrimSpace(os.Getenv("YUGSIGHT_REPO")); env != "" {
		if isRepoDir(env) {
			return filepath.Clean(env), true
		}
		return "", false
	}
	base, err := os.Executable()
	if err != nil {
		return "", false
	}
	dir := filepath.Dir(base)
	for i := 0; i < 8; i++ {
		if isRepoDir(dir) {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}

func isRepoDir(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, "cmd", "agent", "main.go"))
	return err == nil
}

// agentCacheCandidates 可能出现"用户之前跑过 go build ./cmd/agent"产物的目录。
func agentCacheCandidates() []string {
	var dirs []string
	if dir, ok := FindRepoDir(); ok {
		dirs = append(dirs, dir, filepath.Join(dir, "dist"), filepath.Join(dir, "agents"))
	}
	if base, err := os.Executable(); err == nil {
		d := filepath.Dir(base)
		dirs = append(dirs, d, filepath.Join(d, "agents"))
	}
	return dirs
}

// CopyGoCacheAgent 从本机构建目录取一个当前平台可用的 agent 产物(零成本路径,
// 优先于真编译: 秒级完成且不用重编整个依赖树)。
//
// err 只表示环境级故障(输出目录不可写等); "没找到"不算 err —— 以
// hit.OK=false + hit.Error 回传(调用方据此决定是否转真编译并记原因)。
func CopyGoCacheAgent(out string) (CacheHit, error) {
	goOS, goArch := HostPlatform()
	suffix := ""
	if goOS == "windows" {
		suffix = ".exe"
	}
	name := fmt.Sprintf("yugsight-agent_%s_%s", goOS, goArch)

	var best string
	var bestMod time.Time
	for _, dir := range agentCacheCandidates() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // 目录不存在/不可读 = 跳过, 不算失败
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			matched := strings.EqualFold(n, name) || strings.EqualFold(n, name+suffix)
			// 兼容无平台后缀的本地构建命名(手工 go build -o 的产物漂移)
			matched = matched || strings.EqualFold(n, "yugsight-agent") || strings.EqualFold(n, "yugsight-agent"+suffix)
			if !matched {
				continue
			}
			info, err := e.Info()
			if err != nil || info.Size() < 512*1024 {
				continue // 小于 0.5MB 不可能是 agent 二进制(占位/测试文件)
			}
			if best == "" || info.ModTime().After(bestMod) {
				best = filepath.Join(dir, e.Name())
				bestMod = info.ModTime()
			}
		}
	}
	if best == "" {
		return CacheHit{OK: false, Error: "本机构建目录无可用产物(未跑过 go build ./cmd/agent, 或产物不在缓存目录)"}, nil
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return CacheHit{}, err
	}
	if err := copyFile(best, out); err != nil {
		return CacheHit{}, err
	}
	return CacheHit{OK: true, Command: "copy " + best, Path: best}, nil
}

// BuildAgent 就地编译当前平台探针包: 在源码目录执行 go build ./cmd/agent。
//
// 所有异常路径都填充并返回 CmdResult(缺源码/缺工具链/编译失败/超时),
// 顶层 recover 兜底 —— 便捷功能绝不 panic 影响中心端。
func BuildAgent(req BuildRequest) (res CmdResult) {
	defer func() {
		if r := recover(); r != nil {
			res = CmdResult{OK: false, Error: fmt.Sprintf("就地构建异常(已兜底恢复): %v", r)}
		}
	}()
	if strings.TrimSpace(req.OutPath) == "" {
		return CmdResult{OK: false, Error: "输出路径为空"}
	}
	repo := strings.TrimSpace(req.RepoDir)
	if repo == "" {
		dir, ok := FindRepoDir()
		if !ok {
			return CmdResult{OK: false, Error: "未找到源码目录(可用环境变量 YUGSIGHT_REPO 指定源码根目录; 或在开发机用 scripts/build-agents.ps1 产出后放入 agents/)"}
		}
		repo = dir
	}
	goBin, _, toolOK := Toolchain()
	if !toolOK {
		return CmdResult{OK: false, Error: "未找到 Go 工具链(需 Go 1.25+ 且在 PATH 中); 请先在开发机用 scripts/build-agents.ps1 产出探针包"}
	}
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if req.TimeoutSec <= 0 {
		timeout = 300 * time.Second
	}
	cmdline := "go build -trimpath -ldflags \"-s -w\" -o " + req.OutPath + " ./cmd/agent"
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-trimpath", "-ldflags", "-s -w", "-o", req.OutPath, "./cmd/agent")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var outBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	start := time.Now()
	err := cmd.Run()
	secs := int(time.Since(start).Seconds())
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return CmdResult{OK: false, Command: cmdline, Error: fmt.Sprintf("构建超时(%d 秒)", int(timeout.Seconds())), Output: tail(outBuf.String(), 4096), Seconds: secs}
		}
		return CmdResult{OK: false, Command: cmdline, Error: "构建失败: " + err.Error(), Output: tail(outBuf.String(), 4096), Seconds: secs}
	}
	fi, statErr := os.Stat(req.OutPath)
	if statErr != nil || fi.Size() <= 0 {
		return CmdResult{OK: false, Command: cmdline, Error: "构建未产出有效文件: " + req.OutPath, Output: tail(outBuf.String(), 4096), Seconds: secs}
	}
	return CmdResult{
		OK:      true,
		Command: cmdline,
		Output:  fmt.Sprintf("产物已生成: %s (%.1f MB)", req.OutPath, float64(fi.Size())/(1024*1024)),
		Seconds: secs,
	}
}

// copyFile 复制文件(保留只读可写权限, 不保留时间戳 —— 分发场景无意义)。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// tail 取字符串末尾 n 字节(构建日志看尾部: 错误永远在最后)。
func tail(s string, n int) string {
	b := []byte(s)
	if len(b) <= n {
		return s
	}
	return "…" + s[len(b)-n:]
}
