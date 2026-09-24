//go:build windows

package scanner

import (
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// collect_windows.go 本机枚举的 Windows 实现(进程 / 服务 / 已安装软件)。
//
// 全部走 syscall 直连系统 DLL(kernel32 / advapi32), 不引入 cgo、不引入第三方
// 依赖(项目硬约束: 纯标准库单二进制)。
//
// 三条 FFI 铁律(与既有 job_windows.go / collector_windows.go 同口径, 勿违反):
//  1. 指针参数必须给**真实变量地址**, 传 NULL 会 0xC0000005(原生崩溃无 Go panic,
//     recover 拦不住, 现场只表现为"进程静默消失");
//  2. 结构体字段顺序与大小必须和 C 声明逐字节一致, 64 位下要注意对齐填充;
//  3. 每个返回值都要判, 失败时返回 error 让上层降级 —— 不 panic、不静默。

// init 注册 Windows 实现(包初始化即注入, 无需装配层显式调用)。
func init() {
	SetProcessLister(listProcessesWindows)
	SetServiceLister(listServicesWindows)
	SetSoftwareLister(listSoftwareWindows)
}

// ===== 进程: kernel32 CreateToolhelp32Snapshot =====

// processEntry32 对应 PROCESSENTRY32W(64 位布局, dwSize 必须等于结构体大小)。
//
//	C:  DWORD dwSize; DWORD cntUsage; DWORD th32ProcessID; ULONG_PTR th32DefaultHeapID;
//	    DWORD th32ModuleID; DWORD cntThreads; DWORD th32ParentProcessID;
//	    LONG pcPriClassBase; DWORD dwFlags; WCHAR szExeFile[MAX_PATH];
//
// th32ProcessID(4) 之后是 8 字节的 ULONG_PTR, 需要 4 字节对齐填充 —— 漏掉这
// 4 字节会让后续所有字段整体错位, 表现是"进程名全是乱码 / PID 全为 0"。
type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	_               uint32 // 对齐填充(ULONG_PTR 8 字节对齐)
	DefaultHeapID   uint64
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

const (
	th32csSnapProcess = 0x00000002
	invalidHandleValue = ^uintptr(0)
	maxPathW          = 260
)

// listProcessesWindows 枚举进程列表。
func listProcessesWindows() ([]ProcInfo, error) {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	snap := k32.NewProc("CreateToolhelp32Snapshot")
	first := k32.NewProc("Process32FirstW")
	next := k32.NewProc("Process32NextW")
	closeH := k32.NewProc("CloseHandle")

	h, _, err := snap.Call(uintptr(th32csSnapProcess), 0)
	// CreateToolhelp32Snapshot 失败返回 INVALID_HANDLE_VALUE(即 ^uintptr(0)),
	// 不是 0 —— 判成 0 会把无效句柄当成功继续用。
	if h == invalidHandleValue || h == 0 {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot 失败: %v", err)
	}
	defer closeH.Call(h)

	var out []ProcInfo
	var e processEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	// 三个参数中第二、三个是出入参指针, 必须给真实地址(FFI 铁律 1)
	r, _, err := first.Call(h, uintptr(unsafe.Pointer(&e)))
	if r == 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == 24 { // ERROR_BAD_LENGTH
			return nil, fmt.Errorf("PROCESSENTRY32W 大小不符(%d): %v", e.Size, err)
		}
		return nil, fmt.Errorf("Process32FirstW 失败: %v", err)
	}
	for {
		out = append(out, ProcInfo{
			PID:  int(e.ProcessID),
			Name: utf16ToString(e.ExeFile[:]),
		})
		e = processEntry32{}
		e.Size = uint32(unsafe.Sizeof(e))
		r, _, _ = next.Call(h, uintptr(unsafe.Pointer(&e)))
		if r == 0 {
			break // ERROR_NO_MORE_FILES 或结束, 都按结束处理
		}
	}
	return out, nil
}

// utf16ToString UTF-16 数组转字符串(遇到结束符即停, 不做越界读)。
func utf16ToString(b []uint16) string {
	for i, v := range b {
		if v == 0 {
			return string(utf16.Decode(b[:i]))
		}
	}
	return string(utf16.Decode(b))
}

// ===== 服务: advapi32 EnumServicesStatus =====

const (
	scManagerEnumerateService = 0x0004
	serviceWin32              = 0x00000030 // SERVICE_WIN32_OWN_PROCESS | SHARE_PROCESS
	serviceStateAll           = 0x00000003
)

// enumServiceStatus 对应 ENUM_SERVICE_STATUS: 两个指针 + SERVICE_STATUS(7 个 DWORD)。
//
// 尾部那 4 字节填充不能省: C 结构体按自身对齐(此处为 8)补齐, sizeof 是 **48
// 而不是 44**。按 44 步进会让第二个及之后的元素落在 4 字节对齐上(指针字段
// 需要 8 字节对齐), 表现是"第一个服务正常, 后面全是乱码"。
type enumServiceStatus struct {
	// 两个 LPCWSTR 用 unsafe.Pointer 承载(与既有 collector_windows.go 的
	// pcapIf 同一写法): 直接存 uintptr 再转 unsafe.Pointer 会被 go vet 的
	// unsafeptr 检查拦下, 而这里必须解引用才能读到服务名。
	ServiceName             unsafe.Pointer
	DisplayName             unsafe.Pointer
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	_                       uint32
}

// serviceStateName 服务状态码转可读文本。
func serviceStateName(s uint32) string {
	switch s {
	case 1:
		return "已停止"
	case 2:
		return "启动中"
	case 3:
		return "停止中"
	case 4:
		return "运行中"
	case 5:
		return "继续中"
	case 6:
		return "暂停中"
	case 7:
		return "已暂停"
	}
	return fmt.Sprintf("状态%d", s)
}

// listServicesWindows 枚举服务列表(两次调用: 先取所需缓冲大小, 再真正取数据)。
func listServicesWindows() ([]ServiceInfo, error) {
	adv := syscall.NewLazyDLL("advapi32.dll")
	openSCM := adv.NewProc("OpenSCManagerW")
	enumSvc := adv.NewProc("EnumServicesStatusW")
	closeSvc := adv.NewProc("CloseServiceHandle")

	// NULL 机器名/数据库名 = 本机: 传 0 是可接受的(这两个参数允许 NULL)
	scm, _, err := openSCM.Call(0, 0, uintptr(scManagerEnumerateService))
	if scm == 0 {
		return nil, fmt.Errorf("OpenSCManagerW 失败: %v", err)
	}
	defer closeSvc.Call(scm)

	var (
		needed   uint32
		returned uint32
		resume   uint32
	)
	// 第一次: 缓冲传 0 只取所需大小(返回 FALSE + ERROR_MORE_DATA(234) 属预期)
	_, _, _ = enumSvc.Call(scm, uintptr(serviceWin32), uintptr(serviceStateAll),
		0, 0, uintptr(unsafe.Pointer(&needed)),
		uintptr(unsafe.Pointer(&returned)), uintptr(unsafe.Pointer(&resume)))
	if needed == 0 {
		return nil, fmt.Errorf("EnumServicesStatusW 未返回所需缓冲大小")
	}
	// 上限 8MB: 服务数量异常时(数百到数千)也要能扛住, 但不无限扩张
	if needed > 8<<20 {
		needed = 8 << 20
	}
	buf := make([]byte, needed)
	returned, resume = 0, 0
	r, _, err := enumSvc.Call(scm, uintptr(serviceWin32), uintptr(serviceStateAll),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(needed),
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)),
		uintptr(unsafe.Pointer(&resume)))
	if r == 0 {
		return nil, fmt.Errorf("EnumServicesStatusW 失败: %v", err)
	}

	sz := unsafe.Sizeof(enumServiceStatus{})
	out := make([]ServiceInfo, 0, returned)
	for i := uint32(0); i < returned; i++ {
		base := uintptr(i) * sz
		if base+sz > uintptr(len(buf)) {
			break // 防御: 数量与缓冲不一致时截断而不是读越界
		}
		// 用 &buf[base] 取址(切片索引)而不是 uintptr(unsafe.Pointer(&buf[0]))+base
		// 再转回 unsafe.Pointer: 后者在 -race 下会被 checkptr 判"指针跨越多个分配"。
		e := (*enumServiceStatus)(unsafe.Pointer(&buf[base]))
		out = append(out, ServiceInfo{
			Name:    bufString(buf, e.ServiceName),
			Display: bufString(buf, e.DisplayName),
			State:   serviceStateName(e.CurrentState),
		})
	}
	return out, nil
}

// bufString 读 ENUM_SERVICE_STATUS 里的 LPCWSTR(空指针返回空串)。
//
// 关键: 该指针**指向同一个 buf**(Windows 把结构数组与结构成员引用的字符串
// 写在同一块缓冲里, 这正是首次调用要取"所需字节数"的原因 —— 它比 数量×结构体
// 大出字符串那部分)。因此这里不解引用 p, 而是换算成 buf 内的偏移后按字节解码:
//
//  1. 直接 (*[4096]uint16)(p) 在 -race 下是 **fatal error: checkptr: converted
//     pointer straddles multiple allocations** —— 目标类型 8192 字节远大于实际
//     字符串长度, 而 p 在 Go 堆分配的 buf 内, checkptr 必然拦下。这是 fatal
//     error 不是 panic, recover 拦不住、日志也写不进去(项目"通用水位线");
//  2. 换算成偏移后能用 len(buf) 做边界检查: 未终止的字符串只截断, 绝不越界读;
//  3. 全程只做 指针→uintptr 的单向换算, 不把 uintptr 转回指针(FFI 铁律)。
//
// 返回空串的三种情形: 空指针 / 指针不在 buf 内 / 偏移越界 —— 都属"读不到",
// 与"服务名为空"同口径处理, 由上层照常产出该条(状态字段仍可用)。
func bufString(buf []byte, p unsafe.Pointer) string {
	if p == nil || len(buf) == 0 {
		return ""
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	addr := uintptr(p)
	if addr < base {
		return ""
	}
	off := addr - base
	if off >= uintptr(len(buf)) {
		return ""
	}
	return utf16FromBytes(buf[off:])
}

// utf16FromBytes 解码小端 UTF-16 字节(遇 NUL 结束; 无 NUL 则到缓冲尾为止)。
//
// 逐字节组装而不是把 []byte 强转成 []uint16: 后者在 -race 下同样过不了
// checkptr(Go 的切片头转换要求元素类型对齐且长度吻合)。
func utf16FromBytes(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		c := uint16(b[i*2]) | uint16(b[i*2+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// ===== 已安装软件: 注册表 Uninstall 键 =====

const (
	hkeyLocalMachine = 0x80000002
	hkeyCurrentUser  = 0x80000001
	keyRead          = 0x20019 // 项目既有教训: 必须 KEY_READ, 只给 KEY_QUERY_VALUE 会读不动
	errorNoMoreItems = 259
)

// uninstallKeys 需要扫描的卸载信息注册表键(HKLM 两条 + HKCU 一条)。
//
// WOW6432Node 那条是 32 位软件在 64 位系统上的位置 —— 漏掉它会让一半已装软件
// 凭空消失(用户现象: "明明装了却扫不出来")。
var uninstallKeys = []struct {
	root uintptr
	path string
}{
	{hkeyLocalMachine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	{hkeyLocalMachine, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	{hkeyCurrentUser, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
}

// listSoftwareWindows 读注册表卸载键, 汇总已安装软件。
func listSoftwareWindows() ([]SoftwareInfo, error) {
	adv := syscall.NewLazyDLL("advapi32.dll")
	openKey := adv.NewProc("RegOpenKeyExW")
	closeKey := adv.NewProc("RegCloseKey")
	enumKey := adv.NewProc("RegEnumKeyExW")
	queryVal := adv.NewProc("RegQueryValueExW")

	var out []SoftwareInfo
	seen := map[string]bool{}
	var lastErr error
	for _, k := range uninstallKeys {
		hkey := openRegKey(openKey, k.root, k.path)
		if hkey == 0 {
			// 某条根键不存在属正常(如系统没装过 32 位软件), 继续下一条
			lastErr = fmt.Errorf("无法打开注册表键 %s", k.path)
			continue
		}
		for i := uint32(0); len(out) < 2000; i++ {
			name := make([]uint16, 256)
			nameLen := uint32(len(name))
			var ft [8]uint16 // FILETIME 占位, 不关心
			r, _, _ := enumKey.Call(hkey, uintptr(i),
				uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)),
				0, 0, 0, uintptr(unsafe.Pointer(&ft[0])))
			if r != 0 {
				if r != errorNoMoreItems {
					lastErr = fmt.Errorf("RegEnumKeyExW 返回 %d", r)
				}
				break
			}
			sub := openRegKey(openKey, hkey, string(utf16.Decode(name[:nameLen])))
			if sub == 0 {
				continue
			}
			disp := regString(queryVal, sub, "DisplayName")
			if disp == "" {
				// 无 DisplayName 的多半是补丁/运行时组件, 不进资产台账
				closeKey.Call(sub)
				continue
			}
			if key := strings.ToLower(disp); !seen[key] {
				seen[key] = true
				out = append(out, SoftwareInfo{
					Name:      disp,
					Version:   regString(queryVal, sub, "DisplayVersion"),
					Publisher: regString(queryVal, sub, "Publisher"),
				})
			}
			closeKey.Call(sub)
		}
		closeKey.Call(hkey)
	}
	if len(out) == 0 && lastErr != nil {
		return nil, fmt.Errorf("注册表卸载键读取失败: %v", lastErr)
	}
	return out, nil
}

// openRegKey 打开注册表键(失败返回 0)。
func openRegKey(openKey *syscall.LazyProc, root uintptr, path string) uintptr {
	sub, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var out uintptr
	if r, _, _ := openKey.Call(root, uintptr(unsafe.Pointer(sub)), 0,
		uintptr(keyRead), uintptr(unsafe.Pointer(&out))); r != 0 {
		return 0
	}
	return out
}

// regString 读已打开键下的字符串值(读不到返回空串)。
//
// 两步取值: 先拿长度再取内容 —— 注册表字符串长度不定, 一步到位要么截断要么溢出。
func regString(queryVal *syscall.LazyProc, hkey uintptr, value string) string {
	val, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		return ""
	}
	var typ, size uint32
	if r, _, _ := queryVal.Call(hkey, uintptr(unsafe.Pointer(val)), 0,
		uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&size))); r != 0 || size == 0 {
		return ""
	}
	if size > 8<<10 {
		size = 8 << 10
	}
	buf := make([]byte, size)
	if r, _, _ := queryVal.Call(hkey, uintptr(unsafe.Pointer(val)), 0,
		uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size))); r != 0 {
		return ""
	}
	if len(buf) < 2 {
		return ""
	}
	// REG_SZ / REG_EXPAND_SZ 均为 UTF-16(小端), 按 uint16 解码
	n := len(buf) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = uint16(buf[i*2]) | uint16(buf[i*2+1])<<8
	}
	return strings.TrimSpace(utf16ToString(u))
}
