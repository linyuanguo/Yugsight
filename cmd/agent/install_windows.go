//go:build windows

// install_windows.go 探针 Windows 双击自安装(规则 1: 新功能独立文件)。
//
// 【行为】用户在目标 Windows 机器上双击 yugsight-agent.exe(无任何参数):
//  1. 把程序自拷贝到 C:\YugsightAgent(固定安装目录; 不放 Program Files ——
//     那要 UAC 提权, 与探针"无需管理员"的定位冲突);
//  2. 注册 HKCU Run 开机自启(当前用户级, 同样免提权), 重启后自动连接中心端、
//     自动注册上线;
//  3. 未配置中心端地址时弹输入框让用户填写(复用 dialog_windows.go 的 InputBox),
//     中心端设置了节点密钥时可一并附上(空格分隔), 填入安装目录 probe.json;
//  4. 以后台方式(无窗口)启动安装目录里的实例, 本进程退出。
//
// 【降级】C 盘不可写/拷贝失败: 记日志后回退到原有前台流程(用户照样能用,
// 只是没装进 C 盘) —— 规则 3/4。
//
// 【命令行部署不受影响】带任意参数(-center/-token/-id 等)的启动一律走原流程,
// 只有"零参数"才判定为双击 —— 无人值守部署的既有语义保持不变。
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modKernel32  = syscall.NewLazyDLL("kernel32.dll")
	procCreateMx = modKernel32.NewProc("CreateMutexW")
	procCloseHdl = modKernel32.NewProc("CloseHandle")

	modAdvapi        = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKey = modAdvapi.NewProc("RegCreateKeyExW")
	procRegSetValue  = modAdvapi.NewProc("RegSetValueExW")
	procRegClose     = modAdvapi.NewProc("RegCloseKey")
	// RegDeleteKeyValueW(hKey, lpSubKey, lpValueName): 3 个参数, 卸载时删开机自启用
	procRegDeleteKeyValue = modAdvapi.NewProc("RegDeleteKeyValueW")
)

const (
	hkCU             = 0x80000001 // HKEY_CURRENT_USER 伪句柄
	keyWrite         = 0x20006    // KEY_WRITE = KEY_SET_VALUE | KEY_QUERY_VALUE
	regTypeSZ        = 1          // REG_SZ
	createNoWindow   = 0x08000000 // CREATE_NO_WINDOW: 子进程无控制台窗口
	errAlreadyExists = 183        // ERROR_ALREADY_EXISTS
)

// agentInstalledName 安装后的规范文件名。
//
// 下载文件名可能五花八门(带平台后缀的 yugsight-agent_windows_amd64.exe 等),
// 装进 C 盘后统一规范名: 开机自启、自更新都按这个名字定位, 不会出现
// "注册表指向 A、自更新换了 B" 的错位。
const agentInstalledName = "yugsight-agent.exe"

// 开机自启注册表位置(HKCU Run, 当前用户级, 免管理员)。
const (
	agentRunSubKey = `Software\Microsoft\Windows\CurrentVersion\Run`
	agentRunValue  = "YugsightAgent"
)

// agentUninstallName 安装目录里的卸载程序文件名。
//
// 卸载程序就是本程序换了个名字(同二进制两份): 单文件分发不可能凭空产出第二个
// exe, 而"复制一份改名"零成本、永远与 agent 同版本, 用户双击它就走卸载流程
// (判定见 isUninstallLaunch)。中文名是给"被扫描机器的操作者"看的, 一眼知道点哪个。
const agentUninstallName = "卸载探针.exe"

// isUninstallLaunch 本次启动是不是"以卸载程序身份"运行。
//
// 按文件名判定(而不是要求用户记命令行参数): 卸载场景是操作者在安装目录里双击,
// 传参不现实。同时也接受 -uninstall, 便于脚本批量卸载。
func isUninstallLaunch() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return isUninstallName(filepath.Base(exe))
}

// isUninstallName 判定文件名是否是卸载程序。
//
// 抽成纯函数是为了让"安装时写的名字"与"启动时认的名字"守同一份判定 ——
// 两处各写一份字符串比较, 改了一处忘另一处就会出现"有卸载程序但双击没反应"。
func isUninstallName(base string) bool {
	b := strings.ToLower(strings.TrimSpace(base))
	return b == strings.ToLower(agentUninstallName) || strings.HasPrefix(b, "uninstall")
}

// ensureUninstaller 保证安装目录里有一份卸载程序(已存在则不覆盖)。
//
// 旧版本安装目录里没有它(那时还没有卸载功能), 所以每次进入安装流程都补一次,
// 而不是只在"首次拷贝"时写。
func ensureUninstaller(dir, exe string) {
	dst := filepath.Join(dir, agentUninstallName)
	if _, err := os.Stat(dst); err == nil {
		return
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		logLine("生成卸载程序失败(读取程序失败): " + err.Error())
		return
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		logLine("生成卸载程序失败: " + err.Error())
		return
	}
	logLine("已生成卸载程序: " + dst)
}

// runUninstall 卸载探针: 停止进程 -> 删开机自启 -> 删安装目录。
//
// 三步都做才算干净: 只删目录会留下"开机自启指向不存在的文件"(每次开机报错),
// 只删自启会留下后台进程继续跑。任一步失败都记日志并继续下一步 —— 部分卸载
// 也比"点了一下什么都没发生"强(规则 4)。
//
// 【为什么用延迟 cmd 删目录】Windows 不允许删除正在运行的可执行文件, 而卸载
// 程序自己就在待删目录里。故拉起一个延迟 2 秒的 cmd 子进程, 等本进程退出后删。
func runUninstall() {
	dir := agentInstallDir()
	if !ShowConfirm(agentName, "确定卸载 "+agentName+" 吗?\n\n"+
		"· 停止探针进程\n· 删除开机自启动\n· 删除安装目录 "+dir+"\n\n"+
		"(只影响本机探针, 中心端数据不受影响)") {
		return // 用户取消: 静默退出, 不做任何事
	}
	logLine("开始卸载: 停止探针进程...")
	killAgentProcess()
	if err := deleteHKCUValue(agentRunSubKey, agentRunValue); err != nil {
		logLine("删除开机自启失败, 请手工删除注册表项 HKCU\\"+agentRunSubKey+"\\"+agentRunValue+": "+err.Error())
	} else {
		logLine("已删除开机自启动项")
	}
	cmd := exec.Command("cmd", "/c", `ping -n 3 127.0.0.1 >nul & rd /s /q "`+dir+`"`)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		logLine("删除安装目录失败, 请手工删除 "+dir+": "+err.Error())
		ShowInfo(agentName, "卸载已部分完成\n\n开机自启已删除、探针已停止, 但安装目录删除失败, 请手工删除:\n"+dir)
		os.Exit(1)
	}
	_ = cmd.Process.Release()
	logLine("卸载完成: 安装目录将在数秒后删除 " + dir)
	ShowInfo(agentName, "卸载完成\n\n探针已停止、开机自启已删除, 安装目录:\n"+dir+"\n将在数秒后自动删除。")
	os.Exit(0)
}

// killAgentProcess 结束正在运行的探针进程。
//
// 用系统自带 taskkill(按映像名匹配): 卸载程序自身文件名不同, 不会误杀自己。
// 没有进程在跑时 taskkill 返回非 0, 属正常, 不报错。
func killAgentProcess() {
	cmd := exec.Command("taskkill", "/F", "/T", "/IM", agentInstalledName)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	out, err := cmd.CombinedOutput()
	if err != nil {
		logLine("停止探针进程: " + strings.TrimSpace(string(out)))
		return
	}
	logLine("已停止探针进程")
}

// deleteHKCUValue 删除 HKCU\subkey 下的某个值。
func deleteHKCUValue(subkey, value string) error {
	sp, _ := syscall.UTF16PtrFromString(subkey)
	vp, _ := syscall.UTF16PtrFromString(value)
	r, _, _ := procRegDeleteKeyValue.Call(
		uintptr(hkCU),
		uintptr(unsafe.Pointer(sp)),
		uintptr(unsafe.Pointer(vp)),
	)
	if r != 0 {
		return fmt.Errorf("删除注册表值失败(错误 %d)", r)
	}
	return nil
}

// agentInstallDir 固定安装目录。
//
// 声明为变量便于测试改指临时目录(与 probe_agent_download.go 的 agentDownloadDir
// 同一手法), 否则用例一跑就把开发机 exe 拷进 C 盘。
var agentInstallDir = func() string { return `C:\YugsightAgent` }

// agentMutexName 单实例互斥名(按用户会话, 与主程序 Local\Yugsight 同命名空间)。
const agentMutexName = `Local\YugsightAgent`

var agentInstanceH uintptr

// acquireNamedMutex 创建命名互斥量并返回句柄; 已存在(别的实例持有)返回 0。
//
// 命名互斥是系统级对象: 同一进程内用同一名字 CreateMutexW 第二次也会
// 返回 ALREADY_EXISTS, 不认"自己人" —— "已有实例在跑"的判定就靠这一点。
func acquireNamedMutex(name string) uintptr {
	p, _ := syscall.UTF16PtrFromString(name)
	h, _, lastErr := procCreateMx.Call(uintptr(unsafe.Pointer(p)), 0, 0)
	if h == 0 || lastErr.(syscall.Errno) == errAlreadyExists {
		return 0
	}
	return h
}

// acquireSingleInstance 进程级单实例检查(Windows 所有启动路径共用)。
//
// 同一机器跑两个探针会向中心端发两条同 ID 连接互相顶掉, 没有任何意义。
//
// 三态语义(必须分开, 不能把"创建失败"当成"已有实例"):
//  - 拿到句柄 + 无错误       = 本进程独占, 继续;
//  - 拿到句柄 + ALREADY_EXISTS = 另一实例在跑(命名互斥已存在时仍返回有效句柄), 退出;
//  - 句柄为 0               = 创建失败(安全策略等环境使 CreateMutexW 不可用)。
//    单实例检查只是记账, 失败不该连累探针启动(规则 4: 失败降级不阻断)。
func acquireSingleInstance() bool {
	p, _ := syscall.UTF16PtrFromString(agentMutexName)
	h, _, lastErr := procCreateMx.Call(uintptr(unsafe.Pointer(p)), 0, 0)
	if h != 0 {
		if lastErr.(syscall.Errno) == errAlreadyExists {
			procCloseHdl.Call(h)
			return false
		}
		agentInstanceH = h
		return true
	}
	logLine("单实例检查不可用(CreateMutexW 失败: " + lastErr.Error() + "), 允许启动")
	return true
}

// releaseSingleInstance 释放互斥(未持有时无操作)。
func releaseSingleInstance() {
	if agentInstanceH != 0 {
		procCloseHdl.Call(agentInstanceH)
		agentInstanceH = 0
	}
}

// pathInDir 判断文件 p 是否位于目录 dir 内(归一化后前缀匹配)。
//
// 裸 strings.HasPrefix 会把 "C:\YugsightAgent2" 误判进 "C:\YugsightAgent",
// 前缀后必须紧跟分隔符。
func pathInDir(p, dir string) bool {
	ab := filepath.Clean(p)
	dd := filepath.Clean(dir)
	return strings.HasPrefix(ab, dd+string(os.PathSeparator))
}

// copySelfToDir 把当前程序(及源目录的 probe.json)拷进安装目录。
func copySelfToDir(exe, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建安装目录失败: %w", err)
	}
	dst := filepath.Join(dir, agentInstalledName)
	// 重装/升级: 先删旧文件。删不掉通常是文件被占用(已有实例在跑),
	// 那种情况单实例检查已在前面挡住, 这里如实报错即可。
	if _, err := os.Stat(dst); err == nil {
		if derr := os.Remove(dst); derr != nil {
			return fmt.Errorf("移除旧版本失败(可能已有实例在运行): %w", derr)
		}
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return fmt.Errorf("读取当前程序失败: %w", err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return fmt.Errorf("写入安装目录失败: %w", err)
	}
	// 源目录的 probe.json 一并带入 —— 仅当安装目录还没有配置时。
	// 绝不覆盖已有配置: 重装把已填好的中心端地址/密钥抹掉, 用户会以为
	// "装完了怎么又要重新填"。
	dstCfg := filepath.Join(dir, "probe.json")
	if _, err := os.Stat(dstCfg); os.IsNotExist(err) {
		if data2, rerr := os.ReadFile(filepath.Join(filepath.Dir(exe), "probe.json")); rerr == nil {
			_ = os.WriteFile(dstCfg, data2, 0o644)
		}
	}
	return nil
}

// setHKCUString 在 HKCU\subkey 下写一个 REG_SZ 值(键不存在则创建)。
//
// Go 1.25 的 syscall 包已移除注册表包装函数, 与 envdetect_windows.go 同风格
// 直接对 advapi32.dll 做 FFI。坑: RegCreateKeyExW 共 9 个参数, 少传一个
// 是原生崩溃而不是报错返回。
func setHKCUString(subkey, value, data string) error {
	sp, _ := syscall.UTF16PtrFromString(subkey)
	var h, disp uintptr
	r, _, _ := procRegCreateKey.Call(
		uintptr(hkCU),
		uintptr(unsafe.Pointer(sp)),
		0,
		0,
		0,
		uintptr(keyWrite),
		0,
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&disp)),
	)
	if r != 0 {
		return fmt.Errorf("打开注册表键失败(错误 %d)", r)
	}
	defer procRegClose.Call(h)
	vp, _ := syscall.UTF16PtrFromString(value)
	dbuf, _ := syscall.UTF16FromString(data) // 带结尾 0
	r, _, _ = procRegSetValue.Call(
		h,
		uintptr(unsafe.Pointer(vp)),
		0,
		uintptr(regTypeSZ),
		uintptr(unsafe.Pointer(&dbuf[0])),
		uintptr(len(dbuf)*2),
	)
	if r != 0 {
		return fmt.Errorf("写注册表值失败(错误 %d)", r)
	}
	return nil
}

// ensureAgentRunKey 注册开机自启(HKCU Run 项, 当前用户级, 免管理员)。
//
// 值统一带双引号: Run 项启动命令在路径含空格时需要引号, 对无空格路径
// 带引号同样合法, 统一处理。自启失败不阻塞安装(规则 4): 用户仍可在
// 任务计划里手动加, 日志里说清楚差在哪一步。
func ensureAgentRunKey(dir string) {
	cmd := `"` + filepath.Join(dir, agentInstalledName) + `"`
	if err := setHKCUString(agentRunSubKey, agentRunValue, cmd); err != nil {
		logLine("注册开机自启失败(不影响本次运行): " + err.Error())
		return
	}
	logLine("已注册开机自启动: " + agentRunValue + " -> " + cmd)
}

// launchAgentBackground 无窗口启动安装目录里的实例(后台常驻)。
//
// CREATE_NO_WINDOW: 子进程是控制台子系统程序, 不显式指定会再弹一个黑窗口 ——
// 用户双击看到的是"控制台一闪 + 输入框", 输入框关掉后不该再留一个黑窗口
// 占着任务栏(留了用户会习惯性关掉, 一关探针就没了)。
func launchAgentBackground(dir, center string) error {
	cmd := exec.Command(filepath.Join(dir, agentInstalledName), "-center", center)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		return err
	}
	// 不等子进程(它要常驻); Release 防止进程表持有句柄到本进程退出。
	return cmd.Process.Release()
}

// relaunchSelf 以新的中心端地址重启自身(后台无窗口)。
//
// 用户在弹框里改了地址后必须重启才生效: 运行中的探针会话持有旧地址, 而
// "等用户自己找到进程重启"对后台常驻程序来说等于不会发生。重启前由调用方
// 释放单实例互斥(见 connect_guard.go), 否则子进程会被判定为重复启动。
func relaunchSelf(center string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "-center", center)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// installAndLaunch 执行"双击自安装"全流程。
//
// 只在安装失败(如 C 盘不可写)时返回 false, 调用方应回退原有前台流程;
// 其余路径都在内部以 os.Exit 终结(本函数不返回)。
func installAndLaunch() bool {
	exe, err := os.Executable()
	if err != nil {
		logLine("自安装失败(无法定位当前程序): " + err.Error())
		return false
	}
	dir := agentInstallDir()
	if !pathInDir(exe, dir) {
		if cerr := copySelfToDir(exe, dir); cerr != nil {
			logLine("自安装到 C 盘失败, 回退原地运行: " + cerr.Error())
			return false
		}
		logLine("探针已安装到 " + dir)
	}
	// 卸载程序每次都补一次: 老安装目录里没有它, 只在"首次拷贝"时写会让存量装机
	// 永远拿不到卸载入口。
	ensureUninstaller(dir, exe)
	ensureAgentRunKey(dir)

	probePath := filepath.Join(dir, "probe.json")
	cfg := loadConfig(probePath)
	if cfg.CenterAddr == "" {
		logLine("未配置中心端地址, 等待用户在弹框中填写...")
		raw := promptCenterAddr(agentName,
			"未找到中心端地址, 请输入中心端地址后继续\n\n格式: IP:端口, 例如 192.168.1.10:8600\n如中心端设置了节点密钥, 空格后附上: 192.168.1.10:8600 密钥\n留空则退出", 300)
		addr, token := parseCenterInput(raw)
		if addr == "" {
			ShowInfo(agentName,
				"未填写中心端地址, 探针未启动。\n\n已安装到 "+dir+" 并注册开机自启动,\n之后双击该目录下的 yugsight-agent.exe 填写地址即可。")
			releaseSingleInstance()
			os.Exit(0)
		}
		cfg.CenterAddr = addr
		if token != "" {
			cfg.Token = token
		}
		if serr := saveCenterAddr(probePath, addr, token); serr != nil {
			logLine("中心端地址已用于本次运行, 但写回配置失败(下次仍需重新填写): " + serr.Error())
		} else {
			logLine("中心端地址已保存到 " + probePath + ", 之后启动自动使用: " + addr)
		}
	}

	// 地址是 127.0.0.1/localhost 时说破: 在别的机器上那是探针自己, 连不到中心端
	warnLoopbackCenter(cfg.CenterAddr)

	// 先释放互斥再启动子进程: 子进程启动时会做同样的单实例检查,
	// 本进程不放手它就拿不到锁(命名互斥是系统级对象, 不认"自己人")。
	releaseSingleInstance()
	if lerr := launchAgentBackground(dir, cfg.CenterAddr); lerr != nil {
		ShowInfo(agentName, "探针后台启动失败:\n"+lerr.Error()+"\n\n可直接运行 "+dir+" 下的 yugsight-agent.exe 并按日志排查。")
		logLine("后台启动失败: " + lerr.Error())
		os.Exit(1)
	}
	logLine("御视探针已安装并后台启动: 安装目录=" + dir + ", 中心端=" + cfg.CenterAddr)
	ShowInfo(agentName,
		"Yugsight 探针已安装并启动\n\n"+
			"· 安装目录: "+dir+"\n"+
			"· 已注册开机自启动, 重启后自动连接中心端\n"+
			"· 中心端: "+cfg.CenterAddr+"\n\n"+
			"回到中心端「探针管理」页即可看到本节点上线。")
	os.Exit(0)
	// os.Exit 不会返回, 此行仅满足编译器"所有路径必须有返回值"的要求
	return true
}
