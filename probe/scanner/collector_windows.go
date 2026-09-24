//go:build windows

package scanner

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// collector_windows.go 探针端 Npcap 报文采集器(Windows)。
//
// 与主程序 pcap_windows.go 的关系:
//
//	主程序那份实现挂在 main 包, 探针(独立二进制)无法引用; 这里用同样的
//	syscall 直连 wpcap.dll 方式重新实现一个**最小采集器**(只做"打开→读包→回调"),
//	不引入 cgo、不引入第三方依赖(项目硬约束: 纯标准库单二进制)。
//
// 进程隔离说明(与主程序不同):
//
//	主程序把抓包放在独立子进程里跑, 因为 Npcap 驱动异常会导致 native 崩溃;
//	探针端不额外起子进程 —— agent 本身就是个"可被中心端重启的临时角色",
//	崩溃代价低(中心端会看到离线并重新下发), 换来的是实现复杂度大幅下降。
//	若未来探针抓包规模变大, 可复用主程序的 worker 模式(见 capture_worker.go)。
//
// MVP 边界: 只做"抓到就落盘", 不做 BPF 规则编排/分片切割/流式上传。

// pcapPkthdrWin 对应 libpcap 的 struct pcap_pkthdr(字段布局必须一致)。
type pcapPkthdrWin struct {
	TsSec  int32
	TsUsec int32
	CapLen uint32
	Len    uint32
}

// npcapCollector Npcap 采集器。
type npcapCollector struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewNpcapCollector 构造 Npcap 采集器(不做 DLL 加载, Start 时才尝试)。
func NewNpcapCollector() Collector { return &npcapCollector{} }

// Name 采集器名称(能力上报用)。
func (c *npcapCollector) Name() string { return "npcap" }

// Start 打开适配器并开始读包。
//
// sink 返回 false 表示下游写入失败, 应立即停止(避免无意义空转)。
// 本函数阻塞直到 ctx 取消或读包持续失败, 因此调用方应放在独立 goroutine。
func (c *npcapCollector) Start(ctx context.Context, cfg CaptureConfig, sink func([]byte) bool) error {
	dll, closeFn, err := loadWpcap()
	if err != nil {
		return err
	}
	defer closeFn()

	device := cfg.Device
	if device == "" {
		device = firstPcapDevice(dll)
	}
	if device == "" {
		return fmt.Errorf("无可用捕获适配器(请确认 Npcap 已安装且网卡已启用)")
	}
	h, err := openLive(dll, device, 65535, cfg.Filter)
	if err != nil {
		return err
	}
	defer closeLive(dll, h)

	// 取消时关闭句柄让 pcap_next_ex 尽快返回(否则会卡在超时等待里)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.mu.Lock()
	c.cancel = cancel
	c.done = make(chan struct{})
	done := c.done
	c.mu.Unlock()
	defer close(done)

	go func() {
		<-runCtx.Done()
		closeLive(dll, h) // 双关闭: pcap_close 幂等由驱动保证, 这里只求尽快解阻塞
	}()

	var errs int
	for {
		if runCtx.Err() != nil {
			return nil
		}
		pkt, ok, failed := nextPacket(dll, h)
		if failed {
			errs++
			if errs > 20 {
				return fmt.Errorf("适配器读取持续失败(驱动异常或网卡已移除)")
			}
			continue
		}
		errs = 0
		if !ok || len(pkt) == 0 {
			continue // 超时: 正常等待
		}
		if !sink(pkt) {
			return nil
		}
	}
}

// Stop 停止采集。
func (c *npcapCollector) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ===== wpcap.dll FFI(最小集: findalldevs / freealldevs / open_live / next_ex / close) =====

type wpcapDLL struct {
	dll         *syscall.DLL
	findAllDevs *syscall.Proc
	freeAllDevs *syscall.Proc
	openLive    *syscall.Proc
	nextEx      *syscall.Proc
	closeProc   *syscall.Proc
	compile     *syscall.Proc
	setFilter   *syscall.Proc
}

// loadWpcap 加载 wpcap.dll(Npcap 安装路径优先)并解析所需符号。
func loadWpcap() (*wpcapDLL, func(), error) {
	candidates := []string{
		`C:\Windows\System32\npcap\wpcap.dll`,
		`C:\Program Files\Npcap\wpcap.dll`,
		`C:\Program Files (x86)\Npcap\wpcap.dll`,
		`C:\Windows\System32\wpcap.dll`,
	}
	for _, path := range candidates {
		h, err := syscall.LoadLibrary(path)
		if err != nil {
			continue
		}
		dll := &syscall.DLL{Handle: h}
		d := &wpcapDLL{dll: dll}
		var ferr error
		if d.findAllDevs, ferr = dll.FindProc("pcap_findalldevs"); ferr != nil {
			syscall.FreeLibrary(h)
			continue
		}
		d.freeAllDevs, _ = dll.FindProc("pcap_freealldevs")
		// 实时抓包接口是 pcap_open_live(Npcap 无 pcap_open 符号, 找错会 panic)
		if d.openLive, ferr = dll.FindProc("pcap_open_live"); ferr != nil {
			syscall.FreeLibrary(h)
			continue
		}
		d.nextEx, _ = dll.FindProc("pcap_next_ex")
		d.closeProc, _ = dll.FindProc("pcap_close")
		d.compile, _ = dll.FindProc("pcap_compile")
		d.setFilter, _ = dll.FindProc("pcap_setfilter")
		return d, func() { syscall.FreeLibrary(h) }, nil
	}
	return nil, func() {}, fmt.Errorf("未找到 wpcap.dll, 请安装 Npcap(https://npcap.com)")
}

// cStrWin 读取 C 字符串(限长防御, 避免坏指针读飞)。
func cStrWin(p unsafe.Pointer) string {
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

// firstPcapDevice 取第一个可用的 NPF 设备路径。
func firstPcapDevice(d *wpcapDLL) string {
	var devs unsafe.Pointer
	errbuf := make([]byte, 256)
	if r, _, _ := d.findAllDevs.Call(uintptr(unsafe.Pointer(&devs)),
		uintptr(unsafe.Pointer(&errbuf[0]))); int32(r) != 0 || devs == nil {
		return ""
	}
	defer d.freeAllDevs.Call(uintptr(devs))
	// struct pcap_if { next *pcap_if; name *char; description *char; addresses; flags }
	// 注意 next 是第一个字段(顺序写错会把 next 当 name 读, 解引用野指针直接崩)
	type pcapIf struct {
		Next        unsafe.Pointer
		Name        unsafe.Pointer
		Description unsafe.Pointer
		Addresses   unsafe.Pointer
		Flags       uint32
		_           uint32
	}
	for cur := devs; cur != nil; {
		it := (*pcapIf)(cur)
		if name := cStrWin(it.Name); name != "" {
			return name
		}
		cur = it.Next
	}
	return ""
}

// openLive 打开实时抓包(超时 300ms, 便于及时响应取消)。
func openLive(d *wpcapDLL, device string, snapLen uint32, filter string) (uintptr, error) {
	bName := append([]byte(device), 0)
	errbuf := make([]byte, 512)
	r, _, lastErr := d.openLive.Call(
		uintptr(unsafe.Pointer(&bName[0])),
		uintptr(snapLen),
		1,   // promisc
		300, // to_ms: 300ms 超时, 让 next_ex 周期性返回便于检查取消
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if r == 0 {
		if msg := cStrWin(unsafe.Pointer(&errbuf[0])); msg != "" {
			return 0, fmt.Errorf("打开适配器失败: %s", msg)
		}
		return 0, fmt.Errorf("打开适配器失败: %v", lastErr)
	}
	if filter != "" && d.compile != nil && d.setFilter != nil {
		// BPF 编译失败不阻断采集: 过滤只是优化, 拿不到过滤就抓全量
		_ = setBPF(d, r, filter)
	}
	return r, nil
}

// setBPF 编译并设置 BPF 过滤(pcap_compile/pcap_setfilter 返回值 0=成功)。
func setBPF(d *wpcapDLL, h uintptr, filter string) error {
	type bpfProgram struct {
		Len   uint32
		Insns unsafe.Pointer
	}
	bf := []byte(filter)
	var prog bpfProgram
	if r, _, _ := d.compile.Call(h, uintptr(unsafe.Pointer(&prog)),
		uintptr(unsafe.Pointer(&bf[0])), 1, 0); r != 0 {
		return fmt.Errorf("BPF 编译失败: %s", filter)
	}
	if r, _, _ := d.setFilter.Call(h, uintptr(unsafe.Pointer(&prog))); r != 0 {
		return fmt.Errorf("BPF 设置失败: %s", filter)
	}
	return nil
}

// closeLive 关闭抓包句柄(pcap_close 对同一句柄重复调用是安全的,
// 取消协程与 defer 都会调用它, 用于尽快解除 next_ex 的阻塞)。
func closeLive(d *wpcapDLL, h uintptr) {
	if h != 0 && d.closeProc != nil {
		d.closeProc.Call(h)
	}
}

// nextPacket 读一个报文。
//
// 返回 (pkt, ok, failed):
//
//	ok=true       拿到报文
//	ok=false      本次无报文(超时, 正常)
//	failed=true   真实错误(pcap_next_ex 返回 -1)
func nextPacket(d *wpcapDLL, h uintptr) (pkt []byte, ok bool, failed bool) {
	if d.nextEx == nil {
		return nil, false, true
	}
	var hdr pcapPkthdrWin
	var data unsafe.Pointer
	r, _, _ := d.nextEx.Call(h, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
	switch int32(r) {
	case 1:
		if hdr.CapLen == 0 || data == nil {
			return nil, false, false
		}
		buf := make([]byte, int(hdr.CapLen))
		copy(buf, unsafe.Slice((*byte)(data), int(hdr.CapLen)))
		return buf, true, false
	case 0, -2:
		return nil, false, false // 超时 / EOF: 正常
	default:
		return nil, false, true // -1: 真错误
	}
}

// init 注册 Windows 采集器(包初始化即注入, 无需装配层显式调用)。
func init() { SetCollector(NewNpcapCollector()) }
