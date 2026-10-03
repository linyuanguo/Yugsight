//go:build windows

package probe

import (
	"os"
	"strings"
	"syscall"
	"sync"
	"time"
	"unsafe"
)

// ===== Windows: PDH 性能计数器(pdh.dll 纯 FFI, 零依赖) =====
//
// 为什么用 PDH 而不是 GetPhysicalDisk/GetIfTable2:
//  1. PDH 的 "*Bytes/sec" 是内置速率计数器 —— 内部对两次 Collect 的累计差
//     做时间归一, 探针侧不用自己记上一值算窗口差;
//  2. 不需要管理员权限(GetPhysicalDisk 需要, 而探针默认不提权);
//  3. 计数器名按 language=7(美式英语)构造, 中文 Windows 上也恒可用
//     (本地化计数器名会导致硬编码英文路径失效)。
//
// 查询句柄进程生命周期内只建一次(懒初始化); 任何一步失败都永久降级为
// 不报磁盘IO/网络指标(不重试风暴, 不影响心跳)。

var (
	pdhMu     sync.Mutex
	pdhQuery  uintptr      // HQUERY
	pdhCnts   [4][]uintptr // HCOUNTER 分组: 磁盘读/磁盘写/网上行/网下行(组内可能多实例, 求和)
	pdhNames  [4][]string  // 与 pdhCnts 平行的实例名(网卡名), 供 ifaces_windows 按网卡取速率
	pdhReady  bool         // 初始化完成
	pdhFailed bool         // 初始化失败(仅指打开查询失败; 组级失败不整体降级)
)

// pdhCounterSpecs 的分组下标(ifaces_windows 用这两个下标定位"网上行/网下行")
const (
	pdhIdxDiskRead  = 0
	pdhIdxDiskWrite = 1
	pdhIdxNetUp     = 2 // Bytes Sent/sec
	pdhIdxNetDown   = 3 // Bytes Received/sec
)

const (
	pdhFmtDouble         = 0x00000200 // PDH_FMT_DOUBLE(旧代码误用 1, 不是合法格式码)
	pdhNoData            = 0x800007D5 // PDH_NO_DATA: 速率计数器首拍无基线的正常返回
	pdhMoreData          = 0x800007D2 // PDH_MORE_DATA: 取长度时"缓冲区不足, 长度已回填"
	pdhCStatusValidData  = 0x00000000 // PDH_CSTATUS_VALID_DATA
	pdhCStatusNewData    = 0x00000001 // PDH_CSTATUS_NEW_DATA
)

// pdhFmtCounterValue PDH_FMT_COUNTERVALUE: 联合体按 double 视图声明。
// 布局 = {DWORD CStatus; /* 4 字节对齐填充 */; double value}(x64 共 16 字节)。
type pdhFmtCounterValue struct {
	CStatus uint32
	_       uint32 // 对齐填充: double 在 x64 上要求 8 字节对齐
	Double  float64
}

// pdhCounterSpec 一个 PDH 计数器的定位参数(对象(实例) + 计数器名)。
type pdhCounterSpec struct {
	object  string
	counter string
}

var pdhCounterSpecs = []pdhCounterSpec{
	{`PhysicalDisk(_Total)`, `Disk Read Bytes/sec`},
	{`PhysicalDisk(_Total)`, `Disk Write Bytes/sec`},
	{`Network Interface(_Total)`, `Bytes Sent/sec`},
	{`Network Interface(_Total)`, `Bytes Received/sec`},
}

// pdhInit 懒初始化 PDH 查询(成功返回 true; 失败永久降级)。
func pdhInit() bool {
	if pdhReady || pdhFailed {
		return pdhReady
	}
	pdh := syscallNewLazyDLL("pdh.dll")
	openP := pdh.NewProc("PdhOpenQueryW")
	addP := pdh.NewProc("PdhAddCounterW")
	// 英文计数器接口(Vista+): 我们用的是美式英语计数器名, 优先用它解析
	addEngP := pdh.NewProc("PdhAddEnglishCounterW")

	var hQuery uintptr
	if r, _, _ := openP.Call(0, 0, uintptr(unsafe.Pointer(&hQuery))); r != 0 {
		pdhFailed = true
		return false
	}
	pdhQuery = hQuery
	// 每组独立建立: 某组无实例只让该组归 0(整体仍返回样本), 不再把整块指标拖没。
	for i, spec := range pdhCounterSpecs {
		pdhCnts[i], pdhNames[i] = pdhAddCounterGroup(pdh, addP, addEngP, spec)
	}
	pdhReady = true
	return true
}

// pdhAddCounterGroup 建立一组计数器 handle。
//
// 【2026-10-01 真机 bug】原实现直接用 "Network Interface(_Total)" 单条路径:
// 多网卡机器上该对象常常没有 _Total 实例(实测本机只有 Realtek/Wi-Fi 两个实例),
// PdhAddCounterW 失败 → 整个 SampleMetrics 返回 nil —— Windows 侧磁盘 IO 与网络
// 速率长期恒空(探针指标面板与中心端内置监控目标都拿不到数)。
// 修复: _Total 不可用 → 用 PdhExpandCounterPathW 展开该对象的全部实例逐条添加,
// 采样时按组求和(合计口径与 _Total 一致)。
// pdhAddCounterGroup 建立一组计数器, 返回 handle 列表与**平行的实例名列表**
// (网卡名; ifaces_windows 靠它把速率对回具体网卡)。
func pdhAddCounterGroup(pdh *syscall.LazyDLL, addP, addEngP *syscall.LazyProc, spec pdhCounterSpec) ([]uintptr, []string) {
	// 优先展开真实实例而不是用 _Total: ①多网卡机器上 "Network Interface" 常常
	// 根本没有 _Total 实例; ②即便没有, PdhAddCounterW 对不存在的实例也是"延迟
	// 成功"(要等 Collect 才报 NO_DATA), 只看返回码判断不出好坏(2026-10-01 真机)。
	if wild := strings.Replace(spec.object, "(_Total)", "(*)", 1); wild != spec.object {
		var hs []uintptr
		var names []string
		for _, path := range dropTotalInstance(pdhExpandCounterPath(pdh, wild, spec.counter)) {
			h, ok := pdhAddCounterPath(addP, addEngP, path)
			if !ok {
				continue
			}
			hs = append(hs, h)
			names = append(names, pdhInstanceName(path))
		}
		if len(hs) > 0 {
			return hs, names
		}
	}
	if h, ok := pdhAddCounter(addP, addEngP, spec.object, spec.counter); ok {
		return []uintptr{h}, []string{pdhInstanceName(spec.object)}
	}
	return nil, nil
}

// pdhInstanceName 从计数器路径/对象里取出实例名:
// "\\host\Network Interface(Realtek PCIe GbE Family Controller)\Bytes Sent/sec"
// → "Realtek PCIe GbE Family Controller"; 无括号时回退对象名本身(如 _Total)。
//
// 【2026-10-02 真机 bug】旧实现先截"最后一段"再找括号 —— 完整计数器路径的最后
// 一段是计数器名("Bytes Sent/sec", 无括号) → 网卡清单全被命名成 "Bytes Sent/sec"
// (中心端网卡端口明细首上线即踩中)。正确做法: 逐段找带括号的那一段(=对象+实例段)。
func pdhInstanceName(pathOrObject string) string {
	s := pathOrObject
	if strings.Contains(s, `\`) {
		for _, seg := range strings.Split(s, `\`) {
			if a := strings.Index(seg, "("); a >= 0 {
				if b := strings.LastIndex(seg, ")"); b > a {
					return strings.TrimSpace(seg[a+1 : b])
				}
			}
		}
	}
	// 纯对象名(如 "Network Interface(_Total)"): 直接取括号内
	if a := strings.Index(s, "("); a >= 0 {
		if b := strings.LastIndex(s, ")"); b > a {
			return strings.TrimSpace(s[a+1 : b])
		}
	}
	return strings.TrimSpace(s)
}

// dropTotalInstance 展开结果里剔除 _Total 实例: 展开会同时给出 _Total 与各具体
// 实例, 一起求和会把总量算两遍。只有 _Total 一条时保留它(别把可用数据剔没了)。
func dropTotalInstance(paths []string) []string {
	if len(paths) <= 1 {
		return paths
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.Contains(strings.ToLower(p), "(_total)") {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return paths
	}
	return out
}

func pdhAddCounter(addP, addEngP *syscall.LazyProc, object, counter string) (uintptr, bool) {
	return pdhAddCounterPath(addP, addEngP, pdhCounterPath(object, counter))
}

// pdhAddCounterPath 添加一条计数器。
// 优先 PdhAddEnglishCounterW: 我们构造的是美式英语计数器名, 该接口在任意语言
// 系统上都能解析(普通 PdhAddCounterW 在非英语系统可能不认英文名), 取不到该导出
// 时回退普通接口。
func pdhAddCounterPath(addP, addEngP *syscall.LazyProc, path string) (uintptr, bool) {
	pathU, _ := windowsUTF16PtrFromString(path)
	var hCnt uintptr
	procs := []*syscall.LazyProc{addEngP, addP}
	for _, p := range procs {
		if p == nil {
			continue
		}
		if r, _, _ := p.Call(pdhQuery, uintptr(unsafe.Pointer(pathU)), 0, uintptr(unsafe.Pointer(&hCnt))); r == 0 {
			return hCnt, true
		}
	}
	return 0, false
}

// pdhExpandCounterPath 展开通配符计数器路径(如 "Network Interface(*)" 的具体实例)。
// 两次调用: 首次取所需缓冲区长度, 第二次取回 MULTI_SZ(双 \0 结尾)路径列表。
func pdhExpandCounterPath(pdh *syscall.LazyDLL, object, counter string) []string {
	path := pdhCounterPath(object, counter)
	expandP := pdh.NewProc("PdhExpandCounterPathW")
	pathU, _ := windowsUTF16PtrFromString(path)
	var size uint32
	// 取长度那次调用固定返回 PDH_MORE_DATA(缓冲区为 0, 长度回填), 属成功
	if r, _, _ := expandP.Call(uintptr(unsafe.Pointer(pathU)), 0, uintptr(unsafe.Pointer(&size))); r != 0 && r != pdhMoreData {
		return nil
	}
	if size == 0 {
		return nil
	}
	buf := make([]uint16, size)
	if r, _, _ := expandP.Call(uintptr(unsafe.Pointer(pathU)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r != 0 {
		return nil
	}
	return splitMultiSZ(buf)
}

// splitMultiSZ 拆分 MULTI_SZ(连续字符串, 以空串结尾)。
func splitMultiSZ(buf []uint16) []string {
	var out []string
	start := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] != 0 {
			continue
		}
		if i > start {
			out = append(out, windowsUTF16ToString(buf[start:i]))
		}
		start = i + 1
		if i+1 < len(buf) && buf[i+1] == 0 { // 双 \0 = 结束
			break
		}
	}
	return out
}

// pdhCounterPath 构造 PDH 计数器完整路径: \\.\<对象(实例)>\<计数器>。
//
// 【2026-10-01 真机 bug】原实现调 PdhMakeCounterPathW, 但参数表是错的 —— 真 API
// 只收 4 个参数(路径元素结构体指针 / 缓冲区 / 缓冲区长度 / 标志), 原调用把机器名
// 字符串当结构体指针传、还多塞了 language 等参数, 恒返回错误码 → Windows 侧磁盘
// IO 与网络速率长期全空(探针指标面板、中心端内置监控目标都拿不到数)。
// 计数器路径格式是固定的, 直接拼串即可, 不再依赖该 API(少一层 FFI 也少一层风险)。
//
// 机器前缀用主机名而不是 "\\.": 2026-10-01 真机实测, "\\." 这台机器上
// PdhCollectQueryData 恒返回 PDH_NO_DATA(任何计数器, 含 Processor _Total),
// 换成主机名("\\lin-mc\...")或省略前缀立刻正常出数 —— 少见的本机解析问题,
// 主机名是 PDH 官方示例的标准写法, 统一用它。
func pdhCounterPath(object, counter string) string {
	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		return `\\` + strings.TrimSpace(host) + `\` + object + `\` + counter
	}
	return `\` + object + `\` + counter
}

func pdhCloseQuery(pdh *syscall.LazyDLL, hQuery uintptr) {
	_, _, _ = pdh.NewProc("PdhCloseQuery").Call(hQuery)
}

// pdhLastVals/pdhLastAt: 同拍复用缓存(2026-10-02 真机 bug 修复)。
//
// PDH 速率计数器按"两次 PdhCollectQueryData 的间隔"算速率。此前 SampleMetrics 与
// SampleIfaces 各自推一拍 —— 同一拍里连续两拍(中心端 centerMonitorView 每轮都调
// 两个; 探针心跳也是先整机后网卡) → 第二拍间隔微秒级, 网卡明细速率恒 0。
// 现在两入口共用 pdhCollectOnce: 窗口内重复调用直接复用上一拍结果。该速率本就是
// "上一轮采样窗口"的均值, 同拍内重复读语义一致, 不引入新口径。
var (
	pdhLastVals [4][]float64
	pdhLastAt   time.Time
)
const pdhReuseWindow = 5 * time.Second

// pdhCollectOnce 推进一次 PDH 采样, 读回全部组(组内按实例展开)的速率。
// 调用方必须已持有 pdhMu(内部访问 pdhQuery/pdhCnts 不做再加锁)。
// 返回 ok=false = Collect 真失败(非首拍 NO_DATA 正常态)。
func pdhCollectOnce() ([4][]float64, bool) {
	if !pdhLastAt.IsZero() && time.Since(pdhLastAt) < pdhReuseWindow {
		return pdhLastVals, true
	}
	pdh := syscallNewLazyDLL("pdh.dll")
	collectP := pdh.NewProc("PdhCollectQueryData")
	getValP := pdh.NewProc("PdhGetFormattedCounterValue")
	// 速率计数器需要"上一次采样"做基线: 初始化后第一次 Collect 恒返回 PDH_NO_DATA,
	// 这是正常态不是失败(2026-10-01 真机: 旧代码把它当失败 → SampleMetrics 永远
	// 返回 nil, Windows 侧指标全空)。容忍该码: 首拍速率读 0, 次拍起正常出数。
	if r, _, _ := collectP.Call(pdhQuery); r != 0 && r != pdhNoData {
		return [4][]float64{}, false
	}
	var vals [4][]float64
	for g := range pdhCnts {
		vals[g] = make([]float64, len(pdhCnts[g]))
		for i, h := range pdhCnts[g] {
			// PdhGetFormattedCounterValue(hCounter, dwFormat, lpdwType, pValue):
			// 旧代码传的是 (hCounter, 1, &float64, &status) —— 格式码 1 不是合法值, 且
			// pValue 必须指向 PDH_FMT_COUNTERVALUE{CStatus; double}(x64 上 double 有 4
			// 字节对齐填充), 旧写法把 CStatus 当数值读 → 恒 0。这里按真结构布局取值,
			// 并校验 CStatus(非 VALID_DATA 的样本不能当数用)。
			var cv pdhFmtCounterValue
			if r, _, _ := getValP.Call(h, pdhFmtDouble, 0, uintptr(unsafe.Pointer(&cv))); r != 0 {
				continue
			}
			if cv.CStatus != pdhCStatusValidData && cv.CStatus != pdhCStatusNewData {
				continue
			}
			vals[g][i] = cv.Double
		}
	}
	pdhLastVals = vals
	pdhLastAt = time.Now()
	return vals, true
}

func metricsOS(interval time.Duration) *MetricsSample {
	pdhMu.Lock()
	defer pdhMu.Unlock()
	if !pdhInit() {
		return nil
	}
	vals, ok := pdhCollectOnce()
	if !ok {
		return nil
	}
	// 组内多实例(无 _Total 时的展开结果)求和; 空组=0(该指标降级, 不影响其它项)
	sumG := func(g int) float64 {
		var sum float64
		for _, v := range vals[g] {
			sum += v
		}
		return sum
	}
	return &MetricsSample{
		DiskReadBps:  sumG(pdhIdxDiskRead),
		DiskWriteBps: sumG(pdhIdxDiskWrite),
		NetUpBps:     sumG(pdhIdxNetUp),
		NetDownBps:   sumG(pdhIdxNetDown),
	}
}
