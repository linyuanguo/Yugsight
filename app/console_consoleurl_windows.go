//go:build windows

package main

import (
	"strings"
	"syscall"
	"unsafe"
)

// setConsoleTitle 设置控制台窗口标题(同时影响任务栏与 Alt+Tab 缩略图)。
//
// 【为什么用 kernel32 的 SetConsoleTitleW 而不是 os 包】Go 标准库没有设置控制台标题的
// 接口(syscall 包在 Go 1.25 已移除大量 Win32 包装函数, 参见 envdetect_windows.go 的注册表
// FFI 决策), 故直接 FFI 调 kernel32。项目既有风格即如此。
//
// 【为什么整体包成"失败即静默"】标题只是便利功能, 在无控制台的 windowsgui 构建下
// SetConsoleTitleW 必然失败(没有控制台可设), 这属预期而非故障; 任何情况下都不该因此
// 报错或影响启动(项目规则 3/4)。
func setConsoleTitle(title string) {
	defer func() { _ = recover() }() // 原生调用异常(极端情况下)也不许带走主进程
	p, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	_, _, _ = procSetConsoleTitleW.Call(uintptr(unsafe.Pointer(p)))
}

// kernel32 句柄复用 win32_windows.go 里的共享声明(与 console_windows.go 同一套),
// 不在此重复定义 —— 重复声明会编译期报 redefined。
var (
	procSetConsoleTitleW           = kernel32.NewProc("SetConsoleTitleW")
	procGetConsoleWindow           = kernel32.NewProc("GetConsoleWindow")
	procGetStdHandle               = kernel32.NewProc("GetStdHandle")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
	procSetConsoleCursorPosition   = kernel32.NewProc("SetConsoleCursorPosition")
	procWriteConsoleW              = kernel32.NewProc("WriteConsoleW")
)

// stdOutputHandle = STD_OUTPUT_HANDLE, 即 (DWORD)-11。
// 直接写位模式 0xFFFFFFF5 而不是 uintptr(-11): Go 里负数转 uintptr 会得到全 1 的 64 位值,
// 而 GetStdHandle 的参数是 DWORD(32 位), 只认低 32 位 —— 两种写法低 32 位一致, 用位模式
// 免去"为什么能传负数"的疑惑。
const stdOutputHandle = uintptr(0xFFFFFFF5)

// 控制台屏幕缓冲区结构(Win32 原样镜像, 字段顺序与对齐不能动 —— 直接按指针传给 FFI)。
type coord struct {
	x, y int16
}

type smallRect struct {
	left, top, right, bottom int16
}

type consoleScreenBufferInfo struct {
	dwSize              coord
	dwCursorPosition    coord
	wAttributes         uint16
	srWindow            smallRect // 当前视口(可见区)在缓冲区坐标中的位置 —— 顶栏定位就靠它
	dwMaximumWindowSize coord
}

// hasConsole 判断当前进程是否挂着一个控制台窗口。
//
// 【为什么不用 -H windowsgui 判断】那是构建期的事, 运行期拿不到。GetConsoleWindow()
// 返回 0 即表示没有控制台 —— 这正是误带 windowsgui 构建时的表现(进程照跑、页面照开,
// 只是没有窗口, 见 console_subsystem_test.go 记录的这个坑)。
func hasConsole() bool {
	defer func() { _ = recover() }()
	h, _, _ := procGetConsoleWindow.Call()
	return h != 0
}

// pinURLTopline 把 URL 行重写钉在当前视口的第一行, 并清掉上一个位置的残影。
//
// 【为什么定位用 srWindow.Top 而不是 0】视口随日志输出沿缓冲区下移(conhost 在写满
// 9001 行缓冲前不滚动内容, 只把可视窗口往下挪), 缓冲区第 0 行早就不可见了; 只有
// srWindow.Top 才是"用户此刻看到的第一行"。
//
// 【为什么整体"失败即静默 + recover"】顶栏是纯便利功能, 任何一步 FFI 失败(句柄无效、
// 结构体版本差异、精简终端不支持)都只该表现为"顶栏不动", 绝不能影响日志输出与服务
// 运行(项目规则 3/4)。
func pinURLTopline() {
	defer func() { _ = recover() }()
	pinMu.Lock()
	defer pinMu.Unlock()

	h, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if h == 0 || h == ^uintptr(0) {
		return
	}
	var csbi consoleScreenBufferInfo
	if r, _, _ := procGetConsoleScreenBufferInfo.Call(h, uintptr(unsafe.Pointer(&csbi))); r == 0 {
		return
	}
	// 用户正回滚看历史: 不重绘不清行, 别打扰阅读(viewportAtBottom 注释详述)
	if !viewportAtBottom(int32(csbi.srWindow.bottom), int32(csbi.dwCursorPosition.y)) {
		return
	}
	top := csbi.srWindow.top
	width := int(csbi.dwSize.x)
	// 先清上一位置的旧 URL 行(位置没变就免了): 不清的话, 视口每下移一次就残留一条
	// 旧 URL, 回看历史满屏都是链接, 点到换端口前的旧地址还会连错服务
	if pinLastTop >= 0 && pinLastTop != top {
		writeConsoleLineAt(h, pinLastTop, strings.Repeat(" ", max(pinLastW-1, 0)), csbi.dwCursorPosition)
	}
	line := consoleURLLineText(width)
	if line == "" || !writeConsoleLineAt(h, top, line, csbi.dwCursorPosition) {
		return
	}
	pinLastTop = top
	pinLastW = width
}

// writeConsoleLineAt 把 text 覆盖写到缓冲区第 row 行行首(不折行), 写完恢复光标。
//
// 【为什么要记 orig 光标并恢复】conhost 的光标是全局的, 我们挪走写完必须送回原位,
// 否则下一条日志会从顶栏行开始写 —— 那正是"撕裂"的来源。
// 【为什么用 WriteConsoleW 而不是 fmt.Fprint】Fprint 走 Go 的 stdout 写入器(按字节),
// 与光标定位之间可能被其它 goroutine 的输出插队; WriteConsoleW 是同步直写缓冲区,
// 移光标+写+移回三步在 logMu + pinMu 双锁内原子完成。
func writeConsoleLineAt(h uintptr, row int16, text string, orig coord) bool {
	if !setCursor(h, coord{x: 0, y: row}) {
		return false
	}
	u16, err := syscall.UTF16FromString(text)
	if err != nil {
		setCursor(h, orig)
		return false
	}
	var written uint32
	r, _, _ := procWriteConsoleW.Call(
		h,
		uintptr(unsafe.Pointer(&u16[0])),
		uintptr(len(u16)-1), // UTF16FromString 末尾补 NUL, 不算字符数
		uintptr(unsafe.Pointer(&written)),
		0)
	setCursor(h, orig)
	return r != 0
}

// setCursor 移动控制台光标到 p。
// COORD 打包: DWORD 低 16 位 = x, 高 16 位 = y。
func setCursor(h uintptr, p coord) bool {
	r, _, _ := procSetConsoleCursorPosition.Call(h, uintptr(uint16(p.x))|uintptr(uint16(p.y))<<16)
	return r != 0
}
