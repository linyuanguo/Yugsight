package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"yugsight/scanner"
)

var (
	capSess   = scanner.NewCapture()
	capProc   *exec.Cmd // 抓包子进程(持有 wpcap.dll, 驱动崩溃只死它)
	capProcMu sync.Mutex
	capErr    string

	// 报告中心二期: 当前抓包会话参数(开始时记录, 停止时构建原始报告用)。
	// 不放进 Capture 本身 —— Capture 是 scanner 包的通用采集器, 会话级元数据
	// 属于 main 的 API 层关注点。
	capSessMetaMu sync.Mutex
	capSessMeta   captureSessionMeta

	devCacheMu sync.Mutex
	devCache   []PcapDevice
	devCacheAt time.Time

	capCfgOnce sync.Once
	capCfg     captureConfig

	// 全量采集开关(默认开启): 开着时子进程用 "arp or ip or ipv6" 把帧全收上来再由页面过滤。
	//
	// 【为什么要有这个开关】抓包过滤器一旦在内核里生效, 被滤掉的帧就再也拿不回来
	// (网卡根本不往用户态送)。用户在下拉框里选一个过滤器本意是"看这些", 但之前
	// 选完就再也换不回"看全部"了 —— 想换个条件就得重启抓包、丢掉已有数据。
	// 所以默认全量采集, 过滤交给页面(纯展示层, 可随时改)。
	captureAllDefault = true
)

// captureSessionMeta 一次抓包会话的参数快照(报告中心原始报告的数据源之一)。
// 不放 Capture 本身: Capture 是 scanner 包的通用采集器, 会话级元数据属于
// main 的 API 层关注点。
type captureSessionMeta struct {
	Device        string    // 网卡名称
	Filter        string    // 内核实际执行的 BPF 粗筛
	DisplayFilter string    // 用户填写的展示层过滤(原样记录)
	CaptureAll    bool      // 是否全量采集模式
	StartedAt     time.Time // 会话开始时间
}

// capSessMetaSnapshot 取会话参数副本(报告中心构建原始报告用)。
func capSessMetaSnapshot() captureSessionMeta {
	capSessMetaMu.Lock()
	defer capSessMetaMu.Unlock()
	return capSessMeta
}

// captureConfig 抓包相关配置(exe 同目录 capture.json, 缺失则全用默认值)
type captureConfig struct {
	// LoopDetect 环路检测开关(默认 false)。
	//
	// 【为什么默认关】环路判据的强假设是"同一帧被复制", 在 802.11 重传或抓包点
	// 位于汇聚口时仍可能有噪声。而误报代价很高: 一条假的"疑似环路"会让运维去拔
	// 网线排查。按项目规则 5 由配置显式开启。
	LoopDetect bool `json:"loopDetect"`
	// CaptureAll 是否全量采集(默认 true, 见 captureAllDefault 说明)。
	// 显式设 false 可恢复"内核层按过滤器裁剪"的旧行为(高流量场景省带宽)。
	CaptureAll *bool `json:"captureAll"`
}

// loadCaptureConfig 读 exe 同目录 capture.json 的抓包配置。
//
// 复用 readConfigFile 而非直接 ReadFile: 它会剥掉 Windows 记事本/PowerShell
// 写出的 UTF-8 BOM —— 带 BOM 时 json.Unmarshal 直接失败, 表现为"配置写对了却
// 不生效"(同 engine.json / updater.json 的处理口径)。
func loadCaptureConfig() captureConfig {
	cfg := captureConfig{LoopDetect: false}
	// settings.json 的 capture 节直接是 {loopDetect, captureAll}; 旧 capture.json
	// 外面还包了一层 {"capture":{...}}(历史包袱), 故两条路径的解析方式不同。
	if data, ok := section(secCapture, ""); ok {
		var c captureConfig
		if json.Unmarshal(data, &c) == nil {
			return c
		}
		logLine("settings.json 的 capture 节解析失败, 使用默认抓包配置")
		return cfg
	}
	var raw struct {
		Capture *captureConfig `json:"capture"`
	}
	data, ok := section(secCapture, "")
	if !ok {
		return cfg
	}
	if json.Unmarshal(data, &raw) != nil || raw.Capture == nil {
		return cfg
	}
	cfg = *raw.Capture
	return cfg
}

// instanceCaptureConfig 懒加载抓包配置(单例), 并把结果应用到会话上。
func instanceCaptureConfig() captureConfig {
	capCfgOnce.Do(func() {
		capCfg = loadCaptureConfig()
		capSess.SetLoopDetect(capCfg.LoopDetect)
		// 开与关都打日志: 只打"已启用"会让用户以为功能不存在, 只打"未启用"又
		// 看不出是"配置没写"还是"写了 false"。
		if capCfg.LoopDetect {
			logLine("抓包: 环路检测已启用(判据: 五元组+校验和+载荷哈希, TTL 逐跳递减 1, 5 秒窗口)")
		} else {
			logLine("抓包: 环路检测未启用(capture.loopDetect=true 可开启; 默认关闭是因为误报代价高于漏报)")
		}
		// 【不能调 captureAllEnabled()】那个函数内部会再进 capCfgOnce.Do,
		// 而 sync.Once 不可重入 —— 重入会直接返回(不执行), 此时 capCfg 还没写完,
		// 判定结果随执行顺序漂移。故用纯函数版本。
		if captureAllOn(capCfg) {
			logLine("抓包: 全量采集已启用(网卡收全部帧, 过滤在页面做; capture.captureAll=false 可恢复内核过滤)")
		} else {
			logLine("抓包: 全量采集未启用(内核按过滤器裁剪, 滤掉的帧无法回看)")
		}
	})
	return capCfg
}

// captureAllEnabled 是否全量采集(未配置时默认开启)
func captureAllEnabled() bool {
	c := instanceCaptureConfig()
	return c.CaptureAll == nil || *c.CaptureAll
}

// captureAllOn 纯函数形式的判定(避免调用方在 capCfgOnce.Do 内部重入死锁)
func captureAllOn(c captureConfig) bool {
	return c.CaptureAll == nil || *c.CaptureAll
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// npcapInstalled 验证 Npcap 是否已装好: Npcap 的 DLL 固定装在 System32\npcap\ 子目录
func npcapInstalled() bool {
	if _, err := os.Stat(`C:\Windows\System32\npcap\wpcap.dll`); err == nil {
		return true
	}
	// winpcap 兼容模式下 DLL 也会装到 System32 根目录
	svc, err := exec.LookPath("sc")
	if err == nil {
		out, _ := exec.Command(svc, "query", "npcap").Output()
		return strings.Contains(string(out), "RUNNING")
	}
	return false
}

// runDevicesWorker 在子进程里枚举适配器: 驱动损坏导致 native 崩溃时只死子进程,
// 主进程收到错误后返回友好提示(包含 Npcap 关键字, UI 会显示一键安装/重装按钮)
func runDevicesWorker() ([]PcapDevice, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("无法获取 exe 路径")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// 收集子进程 stderr: worker 崩溃(如 wpcap 调用 panic)时 stdout 为空,
	// 只有带上 stderr 才能知道真实原因, 否则一律显示"驱动异常, 请重装 Npcap"
	var errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, exe, "-pcap=devices")
	cmd.Stderr = &errOut
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("适配器枚举超时(抓包驱动异常), 请重新安装 Npcap")
		}
		if msg := firstLine(errOut.String()); msg != "" {
			logLine("适配器枚举子进程错误: " + msg)
			return nil, fmt.Errorf("适配器枚举失败: %s", msg)
		}
		return nil, fmt.Errorf("适配器枚举失败(抓包驱动异常), 请重新安装 Npcap")
	}
	var res struct {
		Error   string       `json:"error"`
		Devices []PcapDevice `json:"devices"`
	}
	if json.Unmarshal(out, &res) != nil {
		return nil, fmt.Errorf("适配器列表不可读(抓包驱动异常), 请重新安装 Npcap")
	}
	if res.Error != "" {
		return nil, fmt.Errorf("%s", res.Error)
	}
	return res.Devices, nil
}

// firstLine 取首行非空文本并限长, 用于把子进程错误带进界面提示
func firstLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if ln != "" {
			if len([]rune(ln)) > 200 {
				return string([]rune(ln)[:200]) + "..."
			}
			return ln
		}
	}
	return ""
}

// cachedDevices 带 TTL 的适配器缓存: 枚举要起子进程, 频繁切页/轮询时开销明显
func cachedDevices(ttl time.Duration) ([]PcapDevice, error) {
	devCacheMu.Lock()
	if len(devCache) > 0 && time.Since(devCacheAt) < ttl {
		d := devCache
		devCacheMu.Unlock()
		return d, nil
	}
	devCacheMu.Unlock()

	devs, err := runDevicesWorker()
	if err != nil {
		return nil, err
	}
	devCacheMu.Lock()
	devCache, devCacheAt = devs, time.Now()
	devCacheMu.Unlock()
	return devs, nil
}

func handleCaptureDevices(w http.ResponseWriter, r *http.Request) {
	// refresh=1 强制重新枚举(用户刚插拔网卡/装完 Npcap 时用)
	if r.URL.Query().Get("refresh") == "1" {
		devCacheMu.Lock()
		devCache, devCacheAt = nil, time.Time{}
		devCacheMu.Unlock()
	}
	devs, err := cachedDevices(60 * time.Second)
	if err != nil {
		jsonErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	jsonOK(w, map[string]any{"devices": devs})
}

// handleCaptureInstall 一键安装 Npcap: 静默运行 exe 同目录的 npcap-*.exe 官方安装器
func handleCaptureInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "无法获取 exe 路径")
		return
	}
	dir := filepath.Dir(exe)
	entries, _ := os.ReadDir(dir)
	var installer string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasPrefix(n, "npcap-") && strings.HasSuffix(n, ".exe") {
			installer = filepath.Join(dir, n)
			break
		}
	}
	if installer == "" {
		jsonErr(w, http.StatusBadRequest, "未找到 Npcap 安装器: 请将 npcap-*.exe(从 npcap.com 下载)放到 exe 同目录后重试")
		return
	}
	// 免费版 Npcap 安装器不支持 /S 静默(仅 OEM 版支持), 以 GUI 方式运行,
	// 用户跟随安装向导完成即可。注意: 免费版主进程可能提前退出(exit 2)而安装
	// 继续进行, 故不依赖退出码, 轮询验证安装结果(官方文档建议)。
	// 先停止抓包并释放 wpcap.dll, 否则安装器替换文件时会被本进程锁定
	PcapRelease()
	cmd := exec.Command(installer)
	hideConsoleWindow(cmd) // 安装器自身有 GUI 界面, 不需要额外控制台窗口
	if err := cmd.Start(); err != nil {
		jsonErr(w, http.StatusInternalServerError, "启动 Npcap 安装器失败: "+err.Error())
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for i := 0; i < 100; i++ { // 最多等待 5 分钟
		time.Sleep(3 * time.Second)
		if npcapInstalled() {
			logLine("Npcap 安装完成: " + filepath.Base(installer))
			jsonOK(w, map[string]any{"ok": true, "installer": filepath.Base(installer)})
			return
		}
		select {
		case err := <-done:
			// 安装器已退出且未装好: 用户取消或出错
			if err != nil {
				jsonErr(w, http.StatusInternalServerError, "Npcap 安装失败或已取消: "+err.Error())
			} else {
				jsonErr(w, http.StatusInternalServerError, "Npcap 安装器已退出但未检测到安装结果, 请重试")
			}
			return
		default:
		}
	}
	jsonErr(w, http.StatusInternalServerError, "5 分钟内未检测到安装完成, 请确认安装窗口已点完(装完需重启本程序)")
}

// startCaptureProc 启动抓包子进程, 等待其就绪握手后返回。
//
// 子进程协议:
//   - stderr "READY <device>"  打开适配器成功(此后 stdout 才是二进制报文流)
//   - stderr "ERR <msg>"       打开失败, 进程随即退出
//
// 同步等握手的意义: 旧实现在 worker 还没打开网卡时就返回"正在抓包",
// 一旦驱动/适配器有问题, 界面会长时间停在"加载中"而看不到真实原因。
func startCaptureProc(device, filter string) (*exec.Cmd, io.ReadCloser, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("无法获取 exe 路径")
	}
	cmd := exec.Command(exe, "-pcap=capture", "-pcap-dev="+device, "-pcap-filter="+filter)
	// 抓包 worker 与主程序同为一个控制台子系统 exe: 不加 CREATE_NO_WINDOW 会新分配
	// 一个控制台窗口, 任务栏于是多出第二个窗口(和主服务窗口同名, 难以区分)。
	// 它的输出全是二进制报文流, 本就该无窗口。Windows 专属标志, 见 sysproc_windows.go。
	hideConsoleWindow(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	type handshake struct {
		msg string
		err error
	}
	hsCh := make(chan handshake, 1)
	// 握手后 stderr 仍可能继续输出(如运行期错误), 用同一 reader 顺带转发到日志
	go func() {
		br := bufio.NewReaderSize(stderr, 4096)
		first := true
		for {
			line, rerr := br.ReadString('\n')
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				if first {
					first = false
					if strings.HasPrefix(line, "READY") {
						hsCh <- handshake{msg: line}
					} else {
						hsCh <- handshake{err: fmt.Errorf("%s", strings.TrimPrefix(line, "ERR "))}
					}
				} else {
					logLine("抓包 worker: " + line)
				}
			}
			if rerr != nil {
				break
			}
		}
		if first {
			hsCh <- handshake{err: fmt.Errorf("抓包进程未返回就绪信息(可能被驱动崩溃终止), 请重新安装 Npcap")}
		}
	}()

	select {
	case hs := <-hsCh:
		if hs.err != nil {
			_ = cmd.Wait()
			return nil, nil, hs.err
		}
	case <-time.After(8 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil, nil, fmt.Errorf("打开适配器超时(抓包驱动无响应), 请重新安装 Npcap 或改用其它适配器")
	}
	return cmd, stdout, nil
}

// readCaptureStream 从抓包子进程读取 [4字节长度][报文] 流并送入分析会话;
// 子进程异常死亡(驱动崩溃)时记录错误, 主进程保持存活
func readCaptureStream(r io.Reader, cmd *exec.Cmd) {
	br := bufio.NewReaderSize(r, 1<<16)
	for {
		var lenb [4]byte
		if _, err := io.ReadFull(br, lenb[:]); err != nil {
			break
		}
		n := binary.LittleEndian.Uint32(lenb[:])
		if n == 0 || n > 262144 {
			break
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(br, pkt); err != nil {
			break
		}
		capSess.OnPacket(pkt)
	}
	if capSess.Running() {
		capSess.Stop()
		// 主动停止时 stopCaptureProc 已把 capProc 置空 → 不误报;
		// 仍持有 capProc 说明是子进程自己死了(驱动崩溃/网卡被移除), 属真异常
		if isCapturing() {
			stopCaptureProc()
			setCapErr("抓包子进程已退出(疑似抓包驱动异常), 已停止抓包。请重新安装 Npcap 后重试")
			logLine("抓包子进程异常退出, 已停止抓包(主进程保持运行)")
			// 报告中心二期: 异常结束同样留档 —— 缓冲里已有的报文是唯一的现场记录
			if rr := buildRawCaptureReport(); rr != nil {
				autoSaveRawReport(v2DB(), rr)
			}
		}
	}
	_ = cmd.Wait() // 回收子进程
}

// stopCaptureProc 结束抓包子进程(正常停止 / 安装 Npcap 前释放 DLL / 主进程退出前)
func stopCaptureProc() {
	capProcMu.Lock()
	p := capProc
	capProc = nil
	capProcMu.Unlock()
	if p != nil && p.Process != nil {
		_ = p.Process.Kill()
	}
}

// isCapturing 是否有抓包子进程在运行
func isCapturing() bool {
	capProcMu.Lock()
	defer capProcMu.Unlock()
	return capProc != nil
}

func setCapErr(s string) {
	capProcMu.Lock()
	capErr = s
	capProcMu.Unlock()
}

func getCapErr() string {
	capProcMu.Lock()
	defer capProcMu.Unlock()
	return capErr
}

// ===== 全量过滤器探测结果缓存 =====
//
// 编译只能发生在 worker 子进程里(要先打开网卡), 所以"哪个关键字能用"只能靠
// 真跑一次来试。试出来的结果记在这里, 避免每次开始抓包都重跑失败候选。
var (
	captureFilterMu sync.Mutex
	captureFullOK   string
)

func captureFilterCached() string {
	captureFilterMu.Lock()
	defer captureFilterMu.Unlock()
	return captureFullOK
}

func captureFilterRemember(f string) {
	captureFilterMu.Lock()
	captureFullOK = f
	captureFilterMu.Unlock()
}

func handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	if capSess.Running() {
		jsonErr(w, http.StatusBadRequest, "已有抓包会话在进行中")
		return
	}
	var req struct {
		Device, Filter string
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	device := req.Device
	if device == "" {
		if devs, err := cachedDevices(60 * time.Second); err == nil && len(devs) > 0 {
			device = devs[0].Name
		}
	}
	if device == "" {
		jsonErr(w, http.StatusBadRequest, "没有可用的捕获适配器(请在下方下拉框选择, 或先安装 Npcap)")
		return
	}
	// 内核级过滤器: 默认只做粗筛(全量采集), 细过滤交给页面。
	//
	// 【为什么不直接把用户填的过滤器交给内核】BPF 过滤器在内核/驱动层生效, 被滤掉
	// 的帧根本不会送到用户态 —— 用户在下拉框选了 "tcp port 80" 之后, 抓到的数据里
	// 就**再也找不到** ARP/ICMP/DNS 了, 想换个视角只能重启抓包并丢弃全部已有数据。
	// 抓包是排障工具, "先收全再筛"才符合排障时"反复换角度看"的真实用法。
	// 高流量场景可在 capture.json 设 captureAll=false 恢复旧行为。
	//
	// 【为什么是 arp or ip or ipv6】BPF 的 "ip" 只匹配 IPv4 —— 旧粗筛 "arp or ip"
	// 会把 IPv6 流量整体滤掉, 页面上的 IPv6 协议选项永远没有数据, 与"全量采集"
	// 语义矛盾。
	reqFilter := strings.TrimSpace(req.Filter)
	// 内置全量过滤器的候选链(从"收得最全"到"最保守"): 只有**编译失败**(BPF 关键字
	// 不被本机的 Npcap 支持)才顺位降级; 其它错误(网卡打不开等)不换过滤器重试 ——
	// 换了也还是打不开, 只会在日志里多一条噪音。
	//
	// 【为什么 ip6 排在 ipv6 前面】ip6 才是 libpcap 的正统关键字, ipv6 是后来的别名,
	// 部分 Npcap 版本只认前者。实测有机器上 "arp or ip or ipv6" 每次都编译失败并
	// 降级, 日志里刷一屏"编译失败" —— 用户会误以为抓包坏了, 其实只是少收 IPv6。
	//
	// 【为什么要缓存】验证通过的那条记在 captureFullFilter, 下次直接用: 否则每次
	// 开始抓包都要重跑一遍失败候选(每次都拉起一个子进程试编译)。
	candidates := []string{"arp or ip or ip6", "arp or ip or ipv6", "arp or ip"}
	if cached := captureFilterCached(); cached != "" {
		candidates = []string{cached, "arp or ip"}
	}
	if !captureAllEnabled() {
		if reqFilter != "" {
			candidates = []string{reqFilter} // 用户自填过滤器不做降级: 那是显式意图
		}
	}
	var cmd *exec.Cmd
	var stdout io.ReadCloser
	var err error
	var filter string
	for i, f := range candidates {
		c, s, e := startCaptureProc(device, f)
		if e == nil {
			cmd, stdout, filter, err = c, s, f, nil
			if captureAllEnabled() || reqFilter == "" {
				captureFilterRemember(f)
			}
			break
		}
		err = e
		if !strings.Contains(e.Error(), "BPF") || i == len(candidates)-1 {
			break // 非编译错误, 或已到最后一条候选
		}
		logLine("抓包: 全量过滤器 '" + f + "' 编译失败, 降级为 '" + candidates[i+1] + "'")
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "启动抓包子进程失败: "+err.Error())
		return
	}
	capProcMu.Lock()
	capProc = cmd
	capErr = ""
	capProcMu.Unlock()
	capSess.Start()
	capSess.SetDevice(device)
	go readCaptureStream(stdout, cmd)
	// 报告中心二期: 记录会话参数(停止时据此构建原始报告)
	capSessMetaMu.Lock()
	capSessMeta = captureSessionMeta{
		Device: device, Filter: filter, DisplayFilter: reqFilter,
		CaptureAll: captureAllEnabled(), StartedAt: time.Now(),
	}
	capSessMetaMu.Unlock()
	// 把展示层过滤条件回带: 前端据此提示"已全量采集, 当前按 xxx 过滤显示"
	jsonOK(w, map[string]any{
		"device": device,
		"filter": filter,
		// displayFilter 是用户想要的过滤(展示层用), kernelFilter 是内核实际执行
		"displayFilter": reqFilter,
		"captureAll":    captureAllEnabled(),
	})
}

func handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	stopCaptureProc() // 主动停止: 置空 capProc, 后续流读取结束不会被判定为"异常退出"
	setCapErr("")
	capSess.Stop()
	// 报告中心二期: 会话结束 → 原始抓包报告自动存档(best-effort 异步, 不拖慢响应)
	if rr := buildRawCaptureReport(); rr != nil {
		autoSaveRawReport(v2DB(), rr)
	}
	jsonOK(w, map[string]any{"ok": true})
}

// captureLocalIP 本机主 IP, 供抓包页提示"ping 本机自己只走回环适配器"。
//
// 【为什么缓存】state 接口每 1.5s 轮询一次, 每次枚举网卡接口代价不小; 本地 IP
// 在一次进程生命周期内基本不变(DHCP 换租需重启服务才体现, 与启动时展示 UI 地址
// 的口径一致)。
var (
	capLocalIPMu sync.Mutex
	capLocalIP   string
)

func captureLocalIP() string {
	capLocalIPMu.Lock()
	defer capLocalIPMu.Unlock()
	if capLocalIP == "" {
		capLocalIP = strings.TrimSpace(scanner.LocalIP())
	}
	return capLocalIP
}

func handleCaptureState(w http.ResponseWriter, r *http.Request) {
	since := int64(0)
	if s := r.URL.Query().Get("since"); s != "" {
		fmt.Sscanf(s, "%d", &since)
	}
	// npcapInstalled / platform 供前端决定"一键安装 Npcap"按钮是否显示:
	// 只在 Windows 且未装时给入口(Linux/macOS 走 libpcap 系统包, 没有安装器可下)。
	// localIP 供前端提示: 用户 ping 的本机 IP 就出现在这里时, 流量只走回环
	// 适配器 —— 这是"ping 自己抓不到包"最常见的根因, 把本机 IP 直接摆出来
	// 比一句抽象提示有用得多。
	jsonOK(w, map[string]any{
		"running":        capSess.Running(),
		"error":          getCapErr(),
		"stats":          capSess.Stats(),
		"events":         capSess.EventsSince(since),
		"bindings":       capSess.Bindings(),
		"npcapInstalled": npcapInstalled(),
		"platform":       runtime.GOOS,
		"localIP":        captureLocalIP(),
	})
}

func handleCaptureAnalysis(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"text": capSess.Analysis()})
}

// handleCapturePackets GET /api/capture/packets?since=&limit=
//
// 返回解码后的报文列表(页面"报文列表"页签的数据源)。
//
// 【两种取数方式】
//   - since=<seq>: 增量拉取(前端记住上次的最大 seq), 只传新报文, 高频轮询也不浪费;
//   - 不带 since: 返回最近 limit 条(默认 500), 用于首次加载/补齐。
//
// 【为什么是轮询而不是 SSE】报文速率与数量远大于事件流(数千条 vs 数十条), 走 SSE
// 会把大量 JSON 推给可能正停留在其它页签的客户端。轮询由前端按"当前是否可见"决定
// 是否发起, 天然省流量。
func handleCapturePackets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var since int64
	if s := q.Get("since"); s != "" {
		_, _ = fmt.Sscanf(s, "%d", &since)
	}
	limit := 500
	if s := q.Get("limit"); s != "" {
		n := 0
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	var recs []scanner.PacketRecord
	if since > 0 {
		recs = capSess.PacketsSince(since, limit)
	} else {
		recs = capSess.PacketsTail(limit)
	}
	if recs == nil {
		recs = []scanner.PacketRecord{}
	}
	maxSeq := since
	for _, rec := range recs {
		if rec.Seq > maxSeq {
			maxSeq = rec.Seq
		}
	}
	jsonOK(w, map[string]any{
		"packets": recs,
		// maxSeq 供前端下次增量拉取(即使本次为空也回带, 避免 seq 回退)
		"maxSeq":   maxSeq,
		"total":    capSess.Packets().Count(),
		"buffered": capSess.Packets().Len(),
		"capacity": 2000,
	})
}

// handleCaptureExport GET /api/capture/export?since=&limit=
//
// 把环形缓冲里留存的报文拼成标准 pcap 文件返回(Wireshark / tcpdump 可直接打开)。
//
// 【为什么独立端点而不是混进 /packets】/packets 返回 JSON 且每条只有 256 字节
// 摘要(展示用); 导出需要完整帧字节, 混在一起会把每次轮询的 JSON 撑到数 MB。
//
// 【数据语义】只导出内存缓冲(≤2000 条): 抓包数据不落盘, 环形缓冲写满后旧报文
// 被覆盖, 停止抓包/重启后缓冲清空 —— 需要留存就必须及时导出。
func handleCaptureExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var since int64
	if s := q.Get("since"); s != "" {
		_, _ = fmt.Sscanf(s, "%d", &since)
	}
	limit := 2000
	if s := q.Get("limit"); s != "" {
		n := 0
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	var recs []scanner.PacketRecord
	if since > 0 {
		recs = capSess.Packets().Since(since, limit)
	} else {
		recs = capSess.Packets().Tail(limit)
	}
	if len(recs) == 0 {
		// 空文件对用户毫无价值(Wireshark 打开是空白, 会被误判"导出坏了"),
		// 明确 404 提示原因。
		jsonErr(w, http.StatusNotFound, "没有可导出的报文(请先开始抓包; 报文只留存最近 2000 条在内存, 更早的已被覆盖)")
		return
	}
	data := scanner.BuildPcap(recs)
	name := "yugsight_capture_" + time.Now().Format("20060102_150405") + ".pcap"
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Pcap-Packets", fmt.Sprint(len(recs)))
	_, _ = w.Write(data)
	logLine("PCAP 导出: " + name + fmt.Sprintf(" (%d 个报文, %.1f KB)", len(recs), float64(len(data))/1024))
}

// ===== AI 深度分析(可选对接 OpenAI 兼容 API) =====

type aiCfg struct {
	APIBase string `json:"apiBase"`
	APIKey  string `json:"apiKey"`
	Model   string `json:"model"`
}

// aiPath AI 模块的配置来源路径。
//
// 红线「配置唯一」: AI 配置只落在 settings.json 的 ai 节(旧 ai.json 启动时迁入
// 并改名 .migrated)。保留本函数只为 status 展示"配置在哪改", 不再用于读写。
func aiPath() string {
	return settingsFilePath()
}

func loadAICfg() *aiCfg {
	cfg := &aiCfg{APIBase: "https://api.openai.com/v1", Model: "gpt-4o-mini"}
	if data, ok := section(secAI, ""); ok {
		_ = json.Unmarshal(data, cfg)
	}
	return cfg
}

// saveAICfg 将 AI 配置持久化到 settings.json 的 ai 节(经典页"测试并保存"路径)。
//
// 配置口径(2026-09-23 用户要求): 中心端配置一律 settings.json, 不再写独立
// ai.json。必须"读-改-写"合并: aiCfg 只有 apiBase/apiKey/model 三个字段,
// 直接整节覆盖会丢掉 ai 节的 enabled/backend(前端开关就失效了)。
func saveAICfg(cfg *aiCfg) {
	var m map[string]any
	if b, ok := sectionBytes(secAI); ok {
		_ = json.Unmarshal(b, &m)
	}
	if m == nil {
		m = map[string]any{}
	}
	if cfg.APIBase != "" {
		m["apiBase"] = cfg.APIBase
	}
	if cfg.Model != "" {
		m["model"] = cfg.Model
	}
	if cfg.APIKey != "" {
		m["apiKey"] = cfg.APIKey
	}
	if err := writeSection(secAI, m); err != nil {
		logLine("保存 ai 配置失败: " + err.Error())
	}
}

// captureAISystem 抓包分析的系统提示词(角色与输出要求, 与数据分离)
const captureAISystem = "你是资深网络运维专家。基于 Yugsight 抓包分析结果, 请给出: 1) 网络状态结论 2) 风险与根因分析 3) 分步骤排查/处置建议(包含交换机命令)。用中文简洁回答。"

func handleAI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 状态查询(Vue 页"AI 已启用/未开启"徽标的唯一数据源): 返回服务端全局
		// 分析器的真实状态。浏览器 localStorage 里的配置不作数 —— 用户可能本地
		// "配好了", 而服务端 settings.json 的 ai 节是 enabled=false, 只有服务端
		// 状态才是权威。
		cfg := scanner.GlobalConfig()
		jsonOK(w, map[string]any{
			"enabled": cfg.Enabled,
			"backend": cfg.Backend,
			"apiBase": cfg.APIBase,
			"model":   cfg.Model,
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Summary string `json:"summary"`
		Config  *aiCfg `json:"config"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	cfg := loadAICfg()
	if req.Config != nil {
		if req.Config.APIBase != "" {
			cfg.APIBase = req.Config.APIBase
		}
		if req.Config.Model != "" {
			cfg.Model = req.Config.Model
		}
		cfg.APIKey = req.Config.APIKey
		saveAICfg(cfg)
	}
	// 复用 scanner AI 模块: 超时/重试/SSE 与非流式兼容解析/并发限流统一, 不再各自实现 HTTP
	ac := aiModelConfigFromLegacy(cfg)
	if ac.Backend == "openai" && ac.APIKey == "" {
		jsonErr(w, http.StatusBadRequest, "未配置 API Key(在页面填写并保存后再试)")
		return
	}
	if req.Summary == "" {
		req.Summary = capSess.Analysis()
	}
	// 硬性约束: 送入 LLM 的数据必须脱敏(擦除凭据/令牌类字段)
	safe := scanner.DesensitizeRaw(req.Summary, 8*1024)

	an := scanner.NewAIAnalyzer(ac)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ac.TimeoutSec)*time.Second)
	defer cancel()
	full, err := an.StreamChat(ctx, captureAISystem, safe, nil)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, "调用 AI 接口失败: "+err.Error())
		return
	}
	if strings.TrimSpace(full) == "" {
		jsonErr(w, http.StatusBadGateway, "AI 接口无返回内容")
		return
	}
	jsonOK(w, map[string]string{"answer": full})
}

// aiModelConfigFromLegacy 旧 ai.json 格式({apiBase,apiKey,model})转 scanner 模块配置;
// 旧格式无 backend 字段, 按 apiBase 特征推断(11434/ollama=本地, 其余=OpenAI 兼容)
func aiModelConfigFromLegacy(c *aiCfg) scanner.AIModelConfig {
	cfg := scanner.DefaultAIConfig() // Enabled 默认 true(抓包 AI 按次触发, 属显式调用)
	cfg.Backend = "openai"
	cfg.APIKey = c.APIKey
	if c.APIBase != "" {
		cfg.APIBase = c.APIBase
		if strings.Contains(c.APIBase, "11434") || strings.Contains(c.APIBase, "ollama") {
			cfg.Backend = "ollama"
		}
	}
	if c.Model != "" {
		cfg.Model = c.Model
	}
	return cfg
}

// persistAICfg 把 AI 配置写入 settings.json 的 ai 节(合并写, 保留其它节与注释),
// 并热生效到全局分析器。
//
// 【为什么写 settings.json 的 ai 节而不是旧 ai.json】全局分析器(扫描/采集/
// 探针结果的后置 AI 分析)走 initAI, 它优先读 settings.json 的 ai 节; 而
// ai 节一旦存在, 就会完全遮蔽 ai.json —— 本机的 ai 节里就躺着 enabled=false,
// 只保存 ai.json 的结果是"用户以为保存了, 全局功能永远是关的"。
//
// 【为什么保存后要清缓存 + initAI】settings.json 是进程级缓存(启动时快照),
// 不清缓存 section() 继续读到旧 ai 节; initAI 重建全局分析器后, 下一次 AI
// 分析立即使用新配置, 无需重启服务。
func persistAICfg(base, key, model string) error {
	// 与已有 ai 节合并: 用户手写过的 maxTokens/retry/maxConcurrency 等字段
	// 不能被一键保存抹掉(writeSection 是整节替换, 合并必须在这里做)
	prev := map[string]any{}
	if path := settingsFilePath(); path != "" {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			var all map[string]json.RawMessage
			if json.Unmarshal(stripBOM(data), &all) == nil {
				if raw, ok := all[secAI]; ok {
					_ = json.Unmarshal(raw, &prev)
				}
			}
		}
	}
	backend := "openai"
	if strings.Contains(base, "11434") || strings.Contains(base, "ollama") {
		backend = "ollama"
	}
	prev["enabled"] = true
	prev["apiBase"] = base
	prev["apiKey"] = key
	if m := strings.TrimSpace(model); m != "" {
		prev["model"] = m
	}
	prev["backend"] = backend
	if _, has := prev["timeoutSec"]; !has {
		prev["timeoutSec"] = 60
	}
	if err := writeSection(secAI, prev); err != nil {
		return err
	}
	resetSettingsCache() // settings 缓存是启动快照, 不清则 section() 永远读到旧 ai 节
	initAI(false)        // 热生效: 重建全局分析器(带 api key 缺口的兜底校验在内)
	logLine("AI 配置已保存(settings.json ai 节, 已启用): backend=" + backend + " apiBase=" + base + " model=" + fmt.Sprint(prev["model"]))
	return nil
}

// handleAITest POST /api/ai/test
//
// 测试 AI 连通性并列出服务端当前可用的模型, 供页面一键填回模型输入框;
// 测试通过时同时把配置保存到服务端(用户预期: 这个按钮 = 测试连通并保存,
// 失败则不保存 —— 保存一个连不通的配置只会造成"以为存了其实用不了")。
//
// 【为什么要有这个端点】"LLM HTTP 404" 是配置 AI 最常见的报错, 原因几乎总是
// ① API Base 多粘了/少了一截路径 ② 服务端换过模型, 配置的模型名已不存在
// (本次实测: 服务端从 Qwen3.6-35B 换成 Qwen3.8-27B, 旧名即触发 404)。
// 只回状态码用户无法自查; 直接给出"服务端现在有哪些模型"才能闭环。
func handleAITest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		APIBase string `json:"apiBase"`
		APIKey  string `json:"apiKey"`
		Model   string `json:"model"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	base := strings.TrimSpace(req.APIBase)
	if base == "" {
		jsonErr(w, http.StatusBadRequest, "未填 API Base")
		return
	}
	client := &http.Client{Timeout: 15 * time.Second}
	hdr := http.Header{}
	if req.APIKey != "" {
		hdr.Set("Authorization", "Bearer "+req.APIKey)
	}

	// models 端点: 与 chatCompletionsURL 同一口径 —— 用户常把完整端点
	// (…/v1/chat/completions)当 API Base 贴进来, 拼 /models 前必须剥掉。
	modelsURL := strings.TrimRight(base, "/")
	modelsURL = strings.TrimSuffix(modelsURL, "/chat/completions") + "/models"
	models, modelsErr := aiGetModels(client, modelsURL, hdr)

	// 填了模型名时再测一次真实补全: 能抓到"模型不存在/无权限/上下文不足"
	// 这类 /models 看不出来的问题。
	modelOK, modelMsg := false, ""
	if m := strings.TrimSpace(req.Model); m != "" {
		chatURL := strings.TrimRight(base, "/")
		if !strings.HasSuffix(chatURL, "/chat/completions") {
			chatURL += "/chat/completions"
		}
		body, _ := json.Marshal(map[string]any{
			"model": m, "stream": false, "max_tokens": 16,
			"messages": []map[string]any{{"role": "user", "content": "ping"}},
		})
		modelOK, modelMsg = aiTestChat(client, chatURL, hdr, body)
	}
	// 通过 = /models 可达 或 真实补全可达(有些服务端不提供 /models, 此时以
	// 补全为准)。通过才保存; 不通过不保存(原因见函数头注释)。
	ok := modelsErr == "" || modelOK
	if ok {
		if serr := persistAICfg(base, strings.TrimSpace(req.APIKey), strings.TrimSpace(req.Model)); serr != nil {
			// 保存失败必须显式报出来 —— 藏在"测试通过"后面, 用户下次发现
			// 配置没生效时完全无从排查。
			jsonErr(w, http.StatusInternalServerError, "测试通过但保存配置失败: "+serr.Error())
			return
		}
	}
	jsonOK(w, map[string]any{
		"models":    models,
		"modelsErr": modelsErr,
		"modelOk":   modelOK,
		"modelMsg":  modelMsg,
		"saved":     ok,
	})
}

// aiGetModels 拉服务端可用模型列表。
//
// 【为什么两种格式都解析】OpenAI 官方是 {"data":[{"id":...}]}; llama.cpp 的
// OpenAI 兼容端点同时返回 {"models":[{"name":...}]} 与 data —— 合并两种字段
// 去重, 主流实现全覆盖。
func aiGetModels(client *http.Client, url string, hdr http.Header) ([]string, string) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err.Error()
	}
	for k, v := range hdr {
		req.Header.Set(k, v[0])
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "请求失败: " + err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 400 {
		return nil, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, aiTruncBody(raw, 200))
	}
	var m struct {
		Data   []struct{ ID string `json:"id"` }   `json:"data"`
		Models []struct{ Name string `json:"name"` } `json:"models"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return nil, "响应不是模型列表(JSON 解析失败, 请确认 API Base 是否为 OpenAI 兼容端点)"
	}
	seen := map[string]bool{}
	var out []string
	for _, x := range m.Data {
		if x.ID != "" && !seen[x.ID] {
			seen[x.ID] = true
			out = append(out, x.ID)
		}
	}
	for _, x := range m.Models {
		if x.Name != "" && !seen[x.Name] {
			seen[x.Name] = true
			out = append(out, x.Name)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out, ""
}

// aiTestChat 用极小 token 预算发一次真实补全, 验证"模型名在服务器上存在且可调用"。
func aiTestChat(client *http.Client, url string, hdr http.Header, body []byte) (bool, string) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v[0])
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "请求失败: " + err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 400 {
		return false, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, aiTruncBody(raw, 300))
	}
	var m struct {
		Choices []struct {
			Message struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
	}
	_ = json.Unmarshal(raw, &m)
	c := ""
	if len(m.Choices) > 0 {
		c = m.Choices[0].Message.Content
		if strings.TrimSpace(c) == "" {
			c = m.Choices[0].Message.ReasoningContent // 思考型模型可能只回 reasoning
		}
	}
	if strings.TrimSpace(c) == "" {
		return true, "连通正常(模型返回空内容, 思考型模型属正常, 正式分析不受影响)"
	}
	return true, "连通正常"
}

// aiTruncBody 截断响应体用于错误提示(网络数据不受控, 防超长刷爆界面)
func aiTruncBody(raw []byte, n int) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
