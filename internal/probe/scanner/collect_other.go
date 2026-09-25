//go:build !windows

package scanner

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// collect_other.go 非 Windows 平台的本机枚举实现(与 collect_windows.go 对应)。
//
// 分工(按"标准库能做到哪一步"划分, 不做假实现):
//
//	进程   读 /proc/<pid>/{stat,cmdline,exe} —— Linux 可行, 与 Windows 等价
//	服务   降级为空(Windows 服务管理器无对应物; systemd 需解析 unit 文件与
//	        D-Bus, 标准库都做不到, 与其猜不如明确降级 —— 项目规则 2/3)
//	软件   降级为空(没有跨发行版的统一已装软件库; 硬编 "/var/lib/dpkg/status"
//	        只覆盖 Debian 系, 在 RHEL 系上会静默给出错误结论)
//
// 降级不是"没做": caller 会从 HostEnum.Notes 看到原因, 中心端能区分
// "这台机器确实没有" 与 "这一项没采到"。

// init 只注册进程枚举器; 服务/软件保持 nil, 由 EnumerateHost 走降级分支。
func init() { SetProcessLister(listProcessesProc) }

// listProcessesProc 读 /proc 枚举进程。
//
// /proc 缺失(非 Linux 的 Unix, 如 macOS)时返回错误, 由上层降级并记录原因 ——
// 不返回空列表冒充"这台机器没有进程"。
func listProcessesProc() ([]ProcInfo, error) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []ProcInfo
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid <= 0 {
			continue // /proc 下有一堆非数字目录(self, sys, net...), 跳过
		}
		name := procName(pid)
		if name == "" {
			continue
		}
		out = append(out, ProcInfo{PID: pid, Name: name, Exe: procExe(pid)})
		if len(out) >= 5000 {
			break
		}
	}
	if len(out) == 0 {
		return nil, os.ErrNotExist
	}
	return out, nil
}

// procName 取进程名: 优先 /proc/<pid>/stat 的 comm 字段(带括号, 可能含空格),
// 取不到退回 cmdline 的第一段。
func procName(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	s := string(b)
	l := strings.LastIndex(s, ")")
	i := strings.Index(s, "(")
	if i >= 0 && l > i {
		return strings.TrimSpace(s[i+1 : l])
	}
	return ""
}

// procExe 取进程可执行文件路径(/proc/<pid>/exe 是可读的符号链接)。
func procExe(pid int) string {
	p, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(p)
}
