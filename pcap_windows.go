//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// 基于 wpcap.dll(Npcap/WinPcap) 的最小实时抓包封装, 纯 syscall 无外部 Go 依赖
// 需安装 Npcap(免费, Wireshark 同款): https://npcap.com

type pcapTimeval struct {
	TvSec  int32
	TvUsec int32
}

type pcapPkthdr struct {
	Ts     pcapTimeval
	CapLen uint32
	Len    uint32
}

// pcapIfT 对应 Npcap 的 struct pcap_if(字段顺序必须与 C 定义完全一致):
//
//	struct pcap_if {
//	    struct pcap_if *next;        // ← 第一个字段是 next, 不是 name
//	    char *name;                  //   传给 pcap_open_live 的设备名
//	    char *description;           //   设备描述(ANSI, 中文系统为 GBK)
//	    struct pcap_addr *addresses;
//	    bpf_u_int32 flags;
//	};
//
// 曾把 next 写在末尾(name 在前): 于是把 next 指针当 name 去读,
// 解引用野指针直接 0xC0000005 → 枚举子进程 panic, 主进程误判为"驱动异常",
// 界面表现就是"无可用适配器"。改字段顺序务必同步改这里。
type pcapIfT struct {
	Next        *pcapIfT
	Name        *byte
	Description *byte
	Addresses   *pcapAddrT
	Flags       uint32
	_           uint32 // 尾部补齐: 与 C 结构体等长(40 字节)
}

// pcapAddrT 对应 struct pcap_addr(仅需布局一致, 字段不读取)
type pcapAddrT struct {
	Next      *pcapAddrT
	Addr      unsafe.Pointer // struct sockaddr *
	Netmask   unsafe.Pointer
	Broadcast unsafe.Pointer
	Dstaddr   unsafe.Pointer
}

type bpfProgram struct {
	BfLen   uint32
	BfInsns unsafe.Pointer
}

var (
	pcapDLL *syscall.DLL
	pcapOk  bool

	procFindalldevs *syscall.Proc
	procFreealldevs *syscall.Proc
	procOpen        *syscall.Proc // pcap_open_live (libpcap 标准接口; 旧代码误用不存在的 pcap_open)
	procNextEx      *syscall.Proc
	procClose       *syscall.Proc
	procCompile     *syscall.Proc
	procSetfilter   *syscall.Proc
	procSetTimeout  *syscall.Proc // pcap_set_timeout: 让 pcap_next_ex 及时返回, 便于取消
	procSetImmediate *syscall.Proc // pcap_set_immediate_mode: 立即交付(不缓冲), 提升实时性
	procDatalink    *syscall.Proc // pcap_datalink: 查链路层类型(区分以太网/回环/802.11 帧)

	modK32    = syscall.NewLazyDLL("kernel32.dll")
	procMBTWC = modK32.NewProc("MultiByteToWideChar")
	procWCTMB = modK32.NewProc("WideCharToMultiByte")
)

func initPcap() error {
	if pcapOk {
		return nil
	}
	exe, _ := os.Executable()
	// Npcap 的 DLL 装在 System32\npcap\ 子目录(优先), 旧 WinPcap 在 System32 根目录(兜底)
	candidates := []string{
		filepath.Join(filepath.Dir(exe), "wpcap.dll"),
		`C:\Windows\System32\npcap\wpcap.dll`,
		`C:\Program Files\Npcap\wpcap.dll`,
		`C:\Program Files (x86)\Npcap\wpcap.dll`,
		`C:\Windows\System32\wpcap.dll`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		h, err := syscall.LoadLibrary(p)
		if err != nil {
			continue
		}
		dll := &syscall.DLL{Handle: h}
		p, err := dll.FindProc("pcap_findalldevs")
		if err != nil {
			continue
		}
		pcapDLL = dll
		procFindalldevs = p
		procFreealldevs, _ = dll.FindProc("pcap_freealldevs")
		// 关键修复: Npcap/libpcap 的实时抓包接口是 pcap_open_live;
		// 旧代码找 pcap_open(该符号在 Npcap 中不存在)导致 procOpen 为 nil,
		// 调用时直接 panic → 表现为"找不到网卡 / 半天无响应"
		procOpen, _ = dll.FindProc("pcap_open_live")
		if procOpen == nil {
			// 极少数旧 WinPcap 兼容层用 pcap_open, 兜底
			procOpen, _ = dll.FindProc("pcap_open")
		}
		if procOpen == nil {
			syscall.FreeLibrary(h)
			continue
		}
		procNextEx, _ = dll.FindProc("pcap_next_ex")
		procClose, _ = dll.FindProc("pcap_close")
		procCompile, _ = dll.FindProc("pcap_compile")
		procSetfilter, _ = dll.FindProc("pcap_setfilter")
		procSetTimeout, _ = dll.FindProc("pcap_set_timeout")
		procSetImmediate, _ = dll.FindProc("pcap_set_immediate_mode")
		procDatalink, _ = dll.FindProc("pcap_datalink")
		pcapOk = true
		return nil
	}
	return fmt.Errorf("未找到可用的 wpcap.dll, 请先安装 Npcap(免费, https://npcap.com, Wireshark 同款抓包驱动)")
}

func cStr(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	b := (*[1 << 16]byte)(p)
	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	return string(b[:i])
}

// cStrBytes 返回 C 字符串的原始字节(不含结尾 NUL)
func cStrBytes(p unsafe.Pointer) []byte {
	if p == nil {
		return nil
	}
	b := (*[1 << 16]byte)(p)
	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	return b[:i]
}

// cpACP 将 ANSI(中文系统为 GBK)字节按系统代码页转成 Go string(UTF-8)
// 纯 ASCII 内容原样返回, 用于显示网卡描述等本地化文本
func cpACP(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	n, _, _ := procMBTWC.Call(0, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if n == 0 {
		return string(b)
	}
	w := make([]uint16, n)
	procMBTWC.Call(0, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&w[0])), uintptr(n))
	return syscall.UTF16ToString(w)
}

// PcapDevice 捕获适配器: Name 用于打开, Desc 用于界面显示
type PcapDevice struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// isNpfPath 判断是否为 NPF 设备路径
func isNpfPath(s string) bool {
	return strings.HasPrefix(s, `\Device\NPF_`) || strings.HasPrefix(s, `\\.\NPF_`)
}

// PcapDevices 返回可用的捕获适配器列表
func PcapDevices() ([]PcapDevice, error) {
	if err := initPcap(); err != nil {
		return nil, err
	}
	var devs unsafe.Pointer
	errbuf := make([]byte, 256)
	// pcap_findalldevs 返回 0 成功 / -1 失败(失败时 errbuf 才有意义)。
	// 不看返回值的话, 失败时只能给出空列表, 用户看到"无可用适配器"却不知原因。
	r, _, _ := procFindalldevs.Call(uintptr(unsafe.Pointer(&devs)), uintptr(unsafe.Pointer(&errbuf[0])))
	if int32(r) != 0 {
		if msg := cpACP(cStrBytes(unsafe.Pointer(&errbuf[0]))); msg != "" {
			return nil, fmt.Errorf("枚举适配器失败: %s", msg)
		}
		return nil, fmt.Errorf("枚举适配器失败: pcap_findalldevs 返回 %d(请确认 Npcap 驱动正常且网卡已启用)", int32(r))
	}
	if devs == nil {
		return nil, nil
	}
	defer procFreealldevs.Call(uintptr(devs))
	var out []PcapDevice
	for d := (*pcapIfT)(devs); d != nil; d = d.Next {
		name := cStr(unsafe.Pointer(d.Name))
		desc := cpACP(cStrBytes(unsafe.Pointer(d.Description)))
		// 兼容个别 Npcap 版本把设备路径放在 description 的情况
		if !isNpfPath(name) && isNpfPath(desc) {
			name, desc = desc, name
		}
		if name == "" {
			continue
		}
		if desc == "" {
			desc = name
		}
		out = append(out, PcapDevice{Name: name, Desc: desc})
	}
	return out, nil
}

type pcapHandle struct {
	ptr uintptr // pcap_t* (来自 C 返回值, 保持 uintptr 避免 unsafe 转换告警)
	errs int    // 连续读取错误计数(超时不算): 用于判断适配器是否已失效

	// 诊断计数(仅 YUGSIGHT_PCAP_DEBUG=1 时通过 ReadStats 读取):
	// 用于区分"驱动不交付(恒超时)"与"读到了但被上层丢弃"这两种
	// 现象相同(界面 0 包)但根因完全不同的情况。
	got  int
	zero int
	neg  int

	// 最近一次读到的报文头部(诊断用): CapLen/Len 与数据指针是否为空
	lastCap  uint32
	lastLen  uint32
	lastData bool
}

// PcapOpenLive 打开实时抓包, filter 为 BPF 表达式(空则不过滤)
//
// libpcap/Npcap 原型:
//
//	pcap_t *pcap_open_live(const char *device, int snaplen, int promisc,
//	                       int to_ms, char *errbuf);
//
// 注意: 设备名是 ANSI(C 字符串), 但 Npcap 也接受 UTF-8; 这里统一转成
// 系统代码页字节, 避免中文/特殊字符网卡名打不开。
func PcapOpenLive(name string, snapLen uint32, filter string) (*pcapHandle, error) {
	if err := initPcap(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("未指定捕获适配器")
	}
	if snapLen == 0 || snapLen > 262144 {
		snapLen = 65535
	}
	nb := acpBytes(name)
	bName := append(nb, 0)
	errbuf := make([]byte, 512)
	// 超时 300ms: 让 pcap_next_ex 及时返回 0, 上层循环才能感知停止请求
	r, _, lastErr := procOpen.Call(
		uintptr(unsafe.Pointer(&bName[0])),
		uintptr(snapLen),
		1,   // promisc
		300, // to_ms
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if r == 0 {
		if msg := cStr(unsafe.Pointer(&errbuf[0])); msg != "" {
			return nil, fmt.Errorf("打开适配器失败: %s", msg)
		}
		return nil, fmt.Errorf("打开适配器失败: %v", lastErr)
	}
	h := &pcapHandle{ptr: r}
	if filter != "" {
		if err := h.setFilter(filter); err != nil {
			procClose.Call(h.ptr)
			return nil, err
		}
	}
	return h, nil
}

// acpBytes 将 Go string 转成系统代码页(中文系统为 GBK)字节, 供 C 接口使用
//
// WideCharToMultiByte(CodePage=0(CP_ACP), dwFlags=0, lpWideCharStr, cchWideChar=-1, ...)
// 注意: 负数字面量不能直接转 uintptr(编译期溢出), 用 ^uintptr(0) 表示 -1;
// cchWideChar=-1 表示入参以 NUL 结尾, 返回长度已含结尾 NUL。
func acpBytes(s string) []byte {
	if s == "" {
		return nil
	}
	w := syscall.StringToUTF16(s) // 末尾含 NUL
	minus1 := ^uintptr(0)         // (DWORD)-1
	n, _, _ := procWCTMB.Call(0, 0, 0, 0,
		uintptr(unsafe.Pointer(&w[0])), minus1, 0, 0)
	if n == 0 {
		return []byte(s)
	}
	buf := make([]byte, n)
	procWCTMB.Call(0, 0, uintptr(unsafe.Pointer(&buf[0])), n,
		uintptr(unsafe.Pointer(&w[0])), minus1, 0, 0)
	// 去掉结尾 NUL
	for len(buf) > 0 && buf[len(buf)-1] == 0 {
		buf = buf[:len(buf)-1]
	}
	return buf
}

func (h *pcapHandle) setFilter(filter string) error {
	if strings.TrimSpace(filter) == "" {
		return nil // 空过滤器 = 抓全部, 无需编译
	}
	bf := []byte(filter)
	var prog bpfProgram
	// pcap_compile / pcap_setfilter 返回值: 0=成功, -1=失败。
	// 注意: 与多数 Win32 API 的"0=成功、非0=错误"约定不同, 这里失败用 -1 表示。
	// 旧代码把 r==0(成功)误判为失败, 导致合法的 "arp or ip" 也报"编译失败"。
	if r, _, _ := procCompile.Call(h.ptr, uintptr(unsafe.Pointer(&prog)), uintptr(unsafe.Pointer(&bf[0])), 1, 0); r != 0 {
		return fmt.Errorf("BPF 过滤器编译失败: %s", filter)
	}
	if r2, _, _ := procSetfilter.Call(h.ptr, uintptr(unsafe.Pointer(&prog))); r2 != 0 {
		return fmt.Errorf("设置过滤器失败: %s", filter)
	}
	return nil
}

// Next 读取一个报文。ok=false 表示本次没有报文(超时或错误);
// pcap_next_ex 返回值: 1=有报文, 0=超时(正常), -1=错误, -2=EOF(离线文件)
//
// 【调用约定: 必须传 "头部指针的指针", 不是 "结构体指针" 】
// libpcap/Npcap 原型:
//
//	int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);
//
// 第二个参数是 **二层指针** —— 函数把"内部缓冲区的头部地址"**回写**给它, 而
// 不是把内容拷贝进调用者提供的结构体。曾按单层结构体指针传参(ushort 版传 &hdr),
// 结果是: 返回 1(成功)、data 非空, 但 hdr 里读到的全是 0/垃圾(内部指针的低 8 字节
// 被塞进了 ts 字段), 于是 caplen==0, 每个包都被 `if CapLen == 0` 当成空包丢弃。
//
// 现象极具误导性: 驱动侧统计"收到了上万个包"(ReadStats 的 got 在 CapLen 判断之前
// 累加), 链路类型也正常(1=以太网), stderr 只打印 READY, 而 stdout 一个字节都写不出去
// —— 界面显示"正在抓包"却永远 0 个包, 完全看不出是调用约定的问题。
//
// 定位过程(留给后来者): 独立写的最小 wpcap 程序能抓到包, 本程序抓不到 → 差异只可能在
// 封装层 → 加 LastHdr() 打印末包的 caplen/len 才暴露 caplen 恒为 0。
func (h *pcapHandle) Next() ([]byte, bool) {
	// 双层指针: pcap_next_ex 回写内部头部的地址
	var hdrPtr *pcapPkthdr
	var data unsafe.Pointer
	r, _, _ := procNextEx.Call(h.ptr,
		uintptr(unsafe.Pointer(&hdrPtr)),
		uintptr(unsafe.Pointer(&data)))
	if r != 1 {
		if int32(r) == 0 || int32(r) == -2 {
			h.errs = 0 // 超时/EOF: 属正常等待, 清零错误计数
			h.zero++
		} else {
			h.errs++ // -1 真错误: 累计, 超过阈值上层会放弃
			h.neg++
		}
		return nil, false
	}
	h.errs = 0
	h.got++
	if hdrPtr == nil {
		h.lastCap, h.lastLen, h.lastData = 0, 0, data != nil
		return nil, true
	}
	hdr := *hdrPtr
	h.lastCap, h.lastLen, h.lastData = hdr.CapLen, hdr.Len, data != nil
	if hdr.CapLen == 0 || data == nil {
		return nil, true
	}
	// 防御: 驱动报告的长度若异常巨大(内存越界读取会直接崩进程), 按 snaplen 上限截断
	capLen := int(hdr.CapLen)
	if capLen > 262144 {
		capLen = 262144
	}
	buf := make([]byte, capLen)
	copy(buf, (*[1 << 24]byte)(data)[:capLen:capLen])
	return buf, true
}

// ErrCount 返回连续读取错误次数
func (h *pcapHandle) ErrCount() int {
	return h.errs
}

// LastHdr 返回最近一次 pcap_next_ex 填充的头部信息(CapLen/Len)与数据指针是否为空,
// 供诊断用。
//
// 【为什么必须单独暴露】Next() 在 CapLen==0 或 data==nil 时会返回 (nil, true) ——
// 调用方看到的是"成功了但没包", 与"确实没包"无法区分。而这两种情况的表现差异极大:
// 前者说明**收到了数据但头部解析错了**(结构体布局或调用约定问题), 包被静默丢弃,
// 于是 worker 一个字节都写不出去, 界面永远 0 包。
func (h *pcapHandle) LastHdr() (capLen, length uint32, hasData bool) {
	return h.lastCap, h.lastLen, h.lastData
}

// ReadStats 返回累计读包统计(收到/超时/错误), 供诊断用。
//
// 【为什么需要区分这三个数】"界面显示 0 包"有三种完全不同的根因:
//   - 收到=0 超时很多 : 驱动不交付数据(链路/模式/权限问题)
//   - 收到很多       : 驱动正常, 是上层解析或上报环节丢了包
//   - 错误很多       : 句柄已失效(网卡被拔/驱动异常)
//
// 没有这三个数时只能靠猜, 而三者的修复方向完全不同。
func (h *pcapHandle) ReadStats() (got, zero, neg int) {
	return h.got, h.zero, h.neg
}

// LinkType 返回适配器的链路层类型(pcap_datalink)。
//
// 【为什么它重要】不同适配器交付的帧格式不同: 以太网是 DLT_EN10MB(1), 但
// 回环、Wi-Fi 监控模式、部分虚拟网卡会给 DLT_NULL(0)/DLT_RAW(12)/DLT_IEEE802_11(105)。
// 若上层一律按"以太网帧 + 14 字节偏移"解析, 拿到非以太网链路时会把每个包都解成
// 垃圾或直接丢弃, 现象就是"驱动明明收到了包, 界面却一个都没统计到"。
// 返回 -1 表示查询失败。
func (h *pcapHandle) LinkType() int {
	if h.ptr == 0 {
		return -1
	}
	if procDatalink == nil {
		return -1
	}
	r, _, _ := procDatalink.Call(h.ptr)
	return int(int32(r))
}

// nextRaw 暴露 pcap_next_ex 的原始返回值, 仅供诊断测试使用。
//
// 【为什么需要它】Next() 把"超时(0)"和"真错误(-1)"都折叠成了 ok=false, 排查
// "READY 能打印但一个包都读不到"时分不清是哪种情况 —— 这两者的处置完全不同:
//   - 恒 0: 驱动在等待但没交付(过滤条件/网卡模式/驱动状态问题);
//   - 恒 -1: 网卡读取真失败(句柄失效)。
// 生产路径不用它, 只给 pcap_diag_test.go 定位问题。
//
// 返回值语义(与 libpcap 一致): 1=有包, 0=超时, -1=错误, -2=EOF(离线文件)。
func (h *pcapHandle) nextRaw() int {
	var hdr pcapPkthdr
	var data unsafe.Pointer
	r, _, _ := procNextEx.Call(h.ptr, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
	return int(int32(r))
}

func (h *pcapHandle) Close() {
	if h.ptr != 0 {
		procClose.Call(h.ptr)
	}
}

// PcapRelease 停止抓包并释放 wpcap.dll
// (安装/升级 Npcap 时需替换 DLL 文件, 加载着会锁定文件; 抓包子进程持有 DLL, 先结束它)
func PcapRelease() {
	stopCaptureProc()
	if pcapDLL != nil {
		syscall.FreeLibrary(pcapDLL.Handle)
		pcapDLL = nil
		pcapOk = false
	}
}
