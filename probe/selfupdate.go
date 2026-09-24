// selfupdate.go 探针端自动更新: 下载新二进制 → 校验 → 原子替换 → 请求重启。
//
// 【为什么放在 probe 包而不是 cmd/agent】中心端与探针端是同一份代码编译的两个
// 二进制, "拿到更新指令后怎么落地"这套逻辑两端都会用到(中心端将来也可能被远程
// 更新), 且它完全不依赖 main 包的装配状态 —— 放这里两端共用, 避免实现漂移。
//
// 【为什么必须校验大小与可选 sha256】更新是"用网络数据覆盖正在运行的程序", 是全
// 项目风险最高的操作。半截下载/被中间设备篡改/中心端 agents 目录里放错文件, 都会
// 造成"替换完探针起不来"。所以: 先下到临时文件, 校验通过才动原文件。
//
// 【为什么替换要"改名旧文件 + 改名新文件"而非直接覆盖】Windows 上正在运行的 exe
// 被内核锁定, 无法直接覆盖(会 ERROR_SHARING_VIOLATION), 但**允许改名**。因此采用:
// 旧 exe 改名为 .old → 新文件改名为原 exe 名 → 提示用户/系统重启。这是 Windows
// 自更新的标准手法, 也是本实现唯一可行的路径。
//
// 【为什么不在本进程内重启】主程序有单实例互斥量, 探针端由用户以控制台方式启动,
// 在本进程 fork 新进程会继承句柄与信号量, 行为不可预期。因此只做替换并返回
// NeedRestart=true, 由 main 提示用户重启(或由系统服务管理器自动拉起)。
package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// UpdateResult 自更新执行结果。
type UpdateResult struct {
	Updated     bool   // 是否完成了文件替换
	NeedRestart bool   // 是否需要重启才能生效(替换成功即为 true)
	Version     string // 更新到的新版本
	Path        string // 落地路径
	Reason      string // 未更新/失败原因(便于日志与前端展示)
}

// SelfUpdater 执行一次探针自更新。
type SelfUpdater struct {
	// Client 下载用 HTTP 客户端(留空则用默认, 带超时)。
	Client *http.Client
	// Logf 日志函数(nil 时静默)。
	Logf func(string)
	// DryRun 为 true 时只校验不替换(用于测试与"仅检查"场景)。
	DryRun bool
}

func (u *SelfUpdater) logf(s string) {
	if u.Logf != nil {
		u.Logf(s)
	}
}

func (u *SelfUpdater) client() *http.Client {
	if u.Client != nil {
		return u.Client
	}
	// 更新包 6-7MB, 内网传输够用; 超时设 60s 避免大包或慢网被误断。
	return &http.Client{Timeout: 60 * time.Second}
}

// Apply 执行更新指令: 下载 → 校验 → 替换当前可执行文件。
//
// 【失败一律降级为"不更新"】任何一步出错都只返回原因, 不 panic 不中断主流程 ——
// 探针更新失败不该影响它继续对外提供扫描能力(规则 4)。旧版本继续跑, 下次注册
// 中心端还会再下发一次, 天然具备重试机会。
func (u *SelfUpdater) Apply(d *UpdateDirective) UpdateResult {
	if d == nil || d.URL == "" {
		return UpdateResult{Reason: "无更新指令"}
	}
	target, err := os.Executable()
	if err != nil {
		return UpdateResult{Reason: "无法定位当前程序: " + err.Error()}
	}
	// 解析软链接: Linux 上用户常用 /usr/local/bin/agent 指向真实文件, 替换软链接
	// 本身会导致链接被改写成普通文件, 必须替换真实路径。
	if real, err := filepath.EvalSymlinks(target); err == nil {
		target = real
	}
	u.logf(fmt.Sprintf("开始自动更新: %s -> %s (来自 %s)", verOrUnknown(d.Version), target, d.URL))

	tmp := target + ".new"
	if err := u.download(d, tmp); err != nil {
		_ = os.Remove(tmp)
		u.logf("自动更新下载失败(保持当前版本): " + err.Error())
		return UpdateResult{Reason: "下载失败: " + err.Error()}
	}
	if err := verifyFile(tmp, d); err != nil {
		_ = os.Remove(tmp)
		u.logf("自动更新校验失败(保持当前版本): " + err.Error())
		return UpdateResult{Reason: "校验失败: " + err.Error()}
	}
	if u.DryRun {
		_ = os.Remove(tmp)
		u.logf("自动更新(演练模式): 校验通过, 未替换文件")
		return UpdateResult{Version: d.Version, Path: target, Reason: "演练模式, 已校验未替换"}
	}
	if err := replaceExecutable(target, tmp); err != nil {
		_ = os.Remove(tmp)
		u.logf("自动更新替换失败(保持当前版本): " + err.Error())
		return UpdateResult{Reason: "替换失败: " + err.Error()}
	}
	// 保留旧文件备份: 新版本启动异常时用户可手动改回(文件名带 .old 后缀)。
	u.logf(fmt.Sprintf("自动更新完成: 已替换为 v%s, 重启后生效", d.Version))
	return UpdateResult{Updated: true, NeedRestart: true, Version: d.Version, Path: target}
}

// download 下载更新包到本地路径。
func (u *SelfUpdater) download(d *UpdateDirective, dst string) error {
	req, err := http.NewRequest(http.MethodGet, d.URL, nil)
	if err != nil {
		return err
	}
	// 标识自己, 便于中心端日志区分"下载更新包"与"用户手动下载"。
	req.Header.Set("User-Agent", "Yugsight-Agent-SelfUpdate/"+d.Version)
	resp, err := u.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 404 是最常见的情形(中心端 agents/ 里没有本平台的包), 单独给出可操作提示
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("中心端未提供本平台(%s/%s)的更新包(HTTP 404)", runtime.GOOS, runtime.GOARCH)
		}
		return fmt.Errorf("中心端返回 HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	// 限制最大体积: 防止被指向异常地址后无限写入磁盘
	// (正常 agent 包 6-7MB, 100MB 已远超合理范围, 属明确的异常信号)。
	const maxUpdateSize = 100 << 20
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxUpdateSize+1))
	if cerr := f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxUpdateSize {
		return fmt.Errorf("更新包体积异常(>%dMB), 已中止", maxUpdateSize>>20)
	}
	if d.Size > 0 && n != d.Size {
		return fmt.Errorf("更新包大小不符: 期望 %d 字节, 实际 %d 字节", d.Size, n)
	}
	return nil
}

// verifyFile 校验下载文件的完整性与可执行性。
func verifyFile(path string, d *UpdateDirective) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return fmt.Errorf("更新包为空")
	}
	// 体积过小必然不是有效的 agent 二进制(实测编译产物 6MB 以上)。
	// 这条能在"中心端 agents/ 里误放了说明文件/占位文件"时提前拦住。
	if st.Size() < 512*1024 {
		return fmt.Errorf("更新包体积过小(%d 字节), 不像有效程序", st.Size())
	}
	if d.SHA256 != "" {
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		if !equalFoldHex(sum, d.SHA256) {
			return fmt.Errorf("SHA256 不匹配(期望 %s, 实际 %s)", d.SHA256, sum)
		}
	}
	return nil
}

// fileSHA256 计算文件 SHA256(十六进制小写)。
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// equalFoldHex 比较十六进制摘要(忽略大小写与首尾空白)。
func equalFoldHex(a, b string) bool {
	return trimLower(a) == trimLower(b)
}

func trimLower(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

// replaceExecutable 用新文件替换正在运行的可执行文件。
//
// 三平台策略:
//   - Unix: 直接 rename 覆盖(运行中的文件允许被 rename, 进程中运行的是旧 inode)。
//   - Windows: 运行中的 exe 不能被覆盖但**能被改名**, 所以先把旧文件改名为 .old,
//     再把新文件改名到原位置。.old 保留作为回滚备份。
//
// 先在同目录内改名(而非跨目录搬运), 保证 rename 是同一文件系统的原子操作。
func replaceExecutable(target, newFile string) error {
	if runtime.GOOS == "windows" {
		backup := target + ".old"
		// 上一次更新残留的 .old 可能还在, 且可能仍被某个进程占用 —— 清理失败不阻断
		// 本次更新(它只是个备份文件, 占着也不影响新文件名被让出来)。
		_ = os.Remove(backup)
		if err := os.Rename(target, backup); err != nil {
			return fmt.Errorf("备份旧程序失败(可能无写入权限): %w", err)
		}
		if err := os.Rename(newFile, target); err != nil {
			// 回滚: 新文件改名失败就把旧文件改回去, 避免"两边都不在原名"导致程序消失
			if rbErr := os.Rename(backup, target); rbErr != nil {
				return fmt.Errorf("替换失败且回滚失败: %v / %v", err, rbErr)
			}
			return fmt.Errorf("替换新程序失败: %w", err)
		}
		return nil
	}
	// Unix: rename 覆盖 + 补可执行位(新文件可能来自 HTTP 下载而丢失权限位)。
	if err := os.Chmod(newFile, 0o755); err != nil {
		return err
	}
	return os.Rename(newFile, target)
}

// SelfUpdateSupported 当前平台是否支持自更新。
//
// 【为什么要有这个判断】更新实现依赖"文件可改名/可覆盖", 在只读文件系统、无写权限
// 目录(如安装在 Program Files 而未提权)下必然失败。提前告知"不支持"比让用户看到
// 一个语焉不详的 rename 失败更好排查。
func SelfUpdateSupported() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	dir := filepath.Dir(exe)
	// 用"能否在程序所在目录创建临时文件"来探测写权限(比 stat 权限位可靠,
	// 因为 Windows 上权限位语义不同)。
	probe := filepath.Join(dir, ".yugsight-write-test")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}
