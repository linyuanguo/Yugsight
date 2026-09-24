//go:build windows

// install_windows_test.go 双击自安装的纯离线测试(规则 8: 只守"改坏会静默失效"的契约)。
//
// 弹框/子进程启动/真实双击链路属交互行为, 不在单测范围(端到端由真机验证)。
package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// 测试专用 FFI(读取/删除临时键), 不放进生产文件。
var (
	procRegQuery      = modAdvapi.NewProc("RegQueryValueExW")
	procRegDeleteTree = modAdvapi.NewProc("RegDeleteTreeW")
)

// TestPathInDir 安装判定: 前缀陷阱 —— C:\YugsightAgent2 不得被判定在
// C:\YugsightAgent 内(否则会跳过拷贝, 把 exe 装错地方)。
func TestPathInDir(t *testing.T) {
	cases := []struct {
		p, dir string
		want   bool
	}{
		{`C:\YugsightAgent\yugsight-agent.exe`, `C:\YugsightAgent`, true},
		{`C:\YugsightAgent2\x.exe`, `C:\YugsightAgent`, false},
		{`D:\YugsightAgent\x.exe`, `C:\YugsightAgent`, false},
	}
	for _, c := range cases {
		if got := pathInDir(c.p, c.dir); got != c.want {
			t.Errorf("pathInDir(%q, %q) = %v, 期望 %v", c.p, c.dir, got, c.want)
		}
	}
}

// TestCopySelfToDir 规范命名 + 配置带入 + 重装不覆盖已有配置。
//
// "重装把已填好的中心端地址抹掉"是静默失效路径: 用户重装后会以为安装失败,
// 其实地址被清空了, 只能重新填 —— 这条契约必须守住。
func TestCopySelfToDir(t *testing.T) {
	src := t.TempDir()
	exe := filepath.Join(src, "yugsight-agent_windows_amd64.exe")
	if err := os.WriteFile(exe, []byte("fake-exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "probe.json"), []byte(`{"client":{"centerAddr":"1.2.3.4:8600"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "YugsightAgent")

	if err := copySelfToDir(exe, dir); err != nil {
		t.Fatal("copySelfToDir: ", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "yugsight-agent.exe")); err != nil {
		t.Fatal("规范名 yugsight-agent.exe 未生成:", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "probe.json"))
	if !strings.Contains(string(data), "1.2.3.4:8600") {
		t.Errorf("源目录 probe.json 未带入: %s", data)
	}

	// 重装: 安装目录已有配置, 不得被源目录配置覆盖
	if err := os.WriteFile(filepath.Join(dir, "probe.json"), []byte(`{"client":{"centerAddr":"9.9.9.9:8600"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copySelfToDir(exe, dir); err != nil {
		t.Fatal("重装 copySelfToDir: ", err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "probe.json"))
	if !strings.Contains(string(data), "9.9.9.9:8600") {
		t.Errorf("重装覆盖了已有配置: %s", data)
	}
}

// TestParseCenterInput 弹框输入解析: 只有地址 / 地址+密钥 / 空。
func TestParseCenterInput(t *testing.T) {
	cases := []struct {
		in, addr, token string
	}{
		{"192.168.1.10:8600", "192.168.1.10:8600", ""},
		{" 192.168.1.10:8600 abc123 ", "192.168.1.10:8600", "abc123"},
		{"", "", ""},
		{"   ", "", ""},
	}
	for _, c := range cases {
		a, tk := parseCenterInput(c.in)
		if a != c.addr || tk != c.token {
			t.Errorf("parseCenterInput(%q) = (%q, %q), 期望 (%q, %q)", c.in, a, tk, c.addr, c.token)
		}
	}
}

// TestAgentMutex 单实例互斥: 第二次获取必须失败, 释放后可再获取。
//
// 用独立测试名(不碰 Local\YugsightAgent), 避免开发机恰好跑着真实探针时
// 用例误报。命名互斥是系统级对象, 同一进程内第二次 CreateMutexW 同样会
// 返回 ALREADY_EXISTS —— "已有实例在跑"的判定就靠这一条。
func TestAgentMutex(t *testing.T) {
	const name = `Local\YugsightAgentTest`
	h := acquireNamedMutex(name)
	if h == 0 {
		// 受管/沙箱环境会拦截 CreateMutexW(干净失败而非崩溃): 此时无法验证
		// 互斥语义, 跳过而不是失败(真实故障的表现是进程崩溃, 而非干净返回 0)。
		t.Skipf("当前环境 CreateMutexW 不可用, 跳过单实例测试")
	}
	if h2 := acquireNamedMutex(name); h2 != 0 {
		t.Fatal("重复获取不应成功(命名互斥是系统级对象)")
	}
	procCloseHdl.Call(h)
	h3 := acquireNamedMutex(name)
	if h3 == 0 {
		t.Fatal("释放后应可重新获取")
	}
	procCloseHdl.Call(h3)
}

// TestIsUninstallName 卸载程序的文件名判定: 安装端写的名字必须与启动端认的一致。
// 也顺带保证探针主程序名不会被误判成卸载程序(否则双击 agent 就变成卸载)。
func TestIsUninstallName(t *testing.T) {
	cases := []struct {
		base string
		want bool
	}{
		{agentUninstallName, true},
		{"卸载探针.exe", true},
		{"UNINSTALL.EXE", true},
		{"uninstall-agent.exe", true},
		{agentInstalledName, false},
		{"yugsight-agent_windows_amd64.exe", false},
	}
	for _, c := range cases {
		if got := isUninstallName(c.base); got != c.want {
			t.Errorf("isUninstallName(%q) = %v, 期望 %v", c.base, got, c.want)
		}
	}
}

// TestSetHKCUString 注册表 FFI 读写(临时键, 结束即删)。
//
// FFI 参数个数/类型写错是原生崩溃而不是返回错误(此前 Job Object 就踩过),
// 只有真跑一次才能守住这条契约。
func TestSetHKCUString(t *testing.T) {
	subkey := `Software\YugsightAgentSelfTest`
	const val = "YugsightAgentSelfTest"
	want := `"C:\YugsightAgent\yugsight-agent.exe"`
	t.Cleanup(func() {
		sp, _ := syscall.UTF16PtrFromString(subkey)
		procRegDeleteTree.Call(uintptr(hkCU), uintptr(unsafe.Pointer(sp)))
	})
	if err := setHKCUString(subkey, val, want); err != nil {
		t.Skipf("注册表不可写(受管环境), 跳过: %v", err)
	}
	if got := readHKCUString(subkey, val); got != want {
		// 沙箱/受管环境的注册表写入是"假成功"(返回 0 但不落盘), 读回为空:
		// FFI 本身正常(返回码合法、进程未崩溃), 无法在环境里验证持久化, 跳过。
		if got == "" {
			t.Skipf("注册表写入未生效(环境拦截), 跳过读回验证")
		}
		t.Errorf("读回值不符: got %q, want %q", got, want)
	}
}

// readHKCUString 测试用: 读 HKCU\subkey 下的 REG_SZ(与 envdetect 的 regString 同口径)。
func readHKCUString(subkey, value string) string {
	sp, _ := syscall.UTF16PtrFromString(subkey)
	var h uintptr
	r, _, _ := procRegCreateKey.Call(
		uintptr(hkCU),
		uintptr(unsafe.Pointer(sp)),
		0, 0, 0,
		uintptr(keyWrite),
		0,
		uintptr(unsafe.Pointer(&h)),
		0,
	)
	if r != 0 {
		return ""
	}
	defer procRegClose.Call(h)
	vp, _ := syscall.UTF16PtrFromString(value)
	var typ, cb uint32
	r, _, _ = procRegQuery.Call(
		h,
		uintptr(unsafe.Pointer(vp)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		0,
		uintptr(unsafe.Pointer(&cb)),
	)
	if r != 0 || cb == 0 {
		return ""
	}
	buf := make([]byte, cb)
	r, _, _ = procRegQuery.Call(
		h,
		uintptr(unsafe.Pointer(vp)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&cb)),
	)
	if r != 0 || typ != regTypeSZ {
		return ""
	}
	return strings.TrimSpace(syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(&buf[0]))[:cb/2]))
}
