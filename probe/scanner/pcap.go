package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ===== PCAP 抓包采集骨架(探针端) =====
//
// 定位(MVP 骨架, 后续迭代优化存储):
//
//	扫描过程可选开启抓包, 捕获本次扫描的交互报文, 落成 PCAP 文件片段,
//	随任务结果回传中心端并绑定到对应资产/漏洞证据(models.Vuln.PcapFile)。
//
// 设计要点:
//   - 默认关闭: 只有任务参数带 capture=true 且平台支持抓包时才启用(项目规则 5);
//   - 采集层抽象(Collector 接口): 真实实现走 Npcap(Windows), 缺失时降级为
//     "记录交互摘要"的文本片段 —— 保证结果结构在无 Npcap 时依然可用;
//   - 输出标准 PCAP 文件格式(全局头 + 每包记录头 + 原始帧), 可直接用
//     Wireshark 打开, 无需自研格式;
//   - 写入即落盘(不缓存在内存): 长时间抓包不会把探针内存吃光;
//   - 文件大小上限与报文数上限双重保护, 防止抓满磁盘。
//
// 当前 MVP 边界(明确不做):
//   - 不做流式回传(整个 PCAP 文件在任务结束时随结果一次性回传);
//   - 不做报文过滤规则的复杂编排(只用 BPF 串 + 目标 IP 白名单);
//   - 不做分片切割(超限即停止采集并标记 truncated, 由中心端决定后续)。

// CaptureConfig 抓包配置。
type CaptureConfig struct {
	// Enabled 是否启用抓包(默认 false)
	Enabled bool
	// Device Npcap 设备名(空则取第一个可用适配器)
	Device string
	// Filter BPF 过滤表达式(空则由目标自动生成, 如 "host 10.0.0.5")
	Filter string
	// MaxBytes 单个 PCAP 文件大小上限(默认 32MB)
	MaxBytes int64
	// MaxPackets 最大报文数(默认 200000)
	MaxPackets int
	// Dir 输出目录(空则 exe 同目录 pcap/)
	Dir string
}

// withDefaults 补齐默认值。
func (c CaptureConfig) withDefaults() CaptureConfig {
	if c.MaxBytes <= 0 {
		c.MaxBytes = 32 << 20 // 32MB
	}
	if c.MaxPackets <= 0 {
		c.MaxPackets = 200000
	}
	if c.Dir == "" {
		c.Dir = exeSubDir("pcap")
	}
	return c
}

// Capture 一次扫描的抓包会话(MVP: 记录交互摘要 + 可选真实报文采集)。
//
// 并发安全: 扫描协程会并发调用 AddPacket/AddNote。
type Capture struct {
	cfg CaptureConfig

	mu       sync.Mutex
	file     *os.File
	written  int64
	packets  int
	notes    []string
	started  time.Time
	stopped  bool
	truncMsg string
	// pcapHdrWritten 延迟写全局头: 只有真正出现第一个报文才创建文件,
	// 避免"零报文但留下空文件"污染回传结果。
	pcapHdrWritten bool
	openErr        error
}

// NewCapture 创建抓包会话(不立即开文件)。
func NewCapture(cfg CaptureConfig) *Capture {
	return &Capture{cfg: cfg.withDefaults(), started: time.Now()}
}

// Enabled 抓包是否实际可用(配置开启且无初始化错误)。
func (c *Capture) Enabled() bool {
	if c == nil || !c.cfg.Enabled {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.openErr == nil
}

// FilePath 当前 PCAP 文件路径(未产生报文时返回空串)。
func (c *Capture) FilePath() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return ""
	}
	return c.file.Name()
}

// Note 记录一条交互摘要(不依赖 Npcap, 任何平台都可用)。
//
// MVP 的核心价值: 即使没有抓包驱动, 探针也能把"对哪个目标做了哪次交互、
// 结果如何"记录下来作为漏洞证据的一部分, 保证证据链完整。
func (c *Capture) Note(format string, args ...any) {
	if c == nil || !c.cfg.Enabled {
		return
	}
	msg := fmt.Sprintf(format, args...)
	boolNote(c, msg)
}

func boolNote(c *Capture, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.notes) >= 2000 {
		return // 上限保护: 摘要只作辅助证据, 不值得无限内存
	}
	c.notes = append(c.notes, time.Now().Format("15:04:05.000")+"  "+truncate(msg, 400))
}

// AddPacket 写入一个原始以太网帧(由平台采集层调用)。
//
// 报文格式: [16 字节 pcap 记录头][原始帧], 配合启动时的 24 字节全局头
// 即构成标准 libpcap 文件(链路类型 LINKTYPE_ETHERNET=1)。
//
// 返回值语义:
//
//	true  已写入 / 已因超限停止采集(调用方无需处理)
//	false 文件系统错误(应停止采集并记日志)
func (c *Capture) AddPacket(pkt []byte) bool {
	if c == nil || !c.cfg.Enabled || len(pkt) == 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped || c.openErr != nil {
		return true
	}
	// 双重上限保护: 先看报文数, 再看字节数
	if c.packets >= c.cfg.MaxPackets || c.written+int64(len(pkt))+16 > c.cfg.MaxBytes {
		c.stopLocked("抓包达到大小/数量上限, 已停止采集")
		return true
	}
	if err := c.ensureFileLocked(); err != nil {
		c.openErr = err
		return false
	}
	var rec [16]byte
	binary.LittleEndian.PutUint32(rec[0:], uint32(time.Now().Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(time.Now().Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt))) // incl_len
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
	if _, err := c.file.Write(rec[:]); err != nil {
		c.openErr = err
		return false
	}
	if _, err := c.file.Write(pkt); err != nil {
		c.openErr = err
		return false
	}
	c.written += int64(len(pkt)) + 16
	c.packets++
	return true
}

// ensureFileLocked 首次写报文时创建文件并写 PCAP 全局头(需持锁)。
func (c *Capture) ensureFileLocked() error {
	if c.file != nil {
		return nil
	}
	if err := os.MkdirAll(c.cfg.Dir, 0o755); err != nil {
		return fmt.Errorf("创建抓包目录失败: %w", err)
	}
	name := "probe-capture-" + time.Now().Format("20060102-150405") + ".pcap"
	f, err := os.Create(filepath.Join(c.cfg.Dir, name))
	if err != nil {
		return fmt.Errorf("创建抓包文件失败: %w", err)
	}
	// PCAP 全局头(24 字节): magic/版本/时区/时间精度/链路类型
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xA1B2C3D4)  // magic(小端)
	binary.LittleEndian.PutUint16(hdr[4:], 2)           // major
	binary.LittleEndian.PutUint16(hdr[6:], 4)           // minor
	binary.LittleEndian.PutUint32(hdr[8:], 0)           // thiszone
	binary.LittleEndian.PutUint32(hdr[12:], 0)          // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:], 262144)     // snaplen
	binary.LittleEndian.PutUint32(hdr[20:], 1)          // LINKTYPE_ETHERNET
	if _, err := f.Write(hdr); err != nil {
		_ = f.Close()
		return fmt.Errorf("写入抓包文件头失败: %w", err)
	}
	c.file = f
	c.written = int64(len(hdr))
	c.pcapHdrWritten = true
	return nil
}

// stopLocked 标记停止(需持锁)。
func (c *Capture) stopLocked(reason string) {
	if c.stopped {
		return
	}
	c.stopped = true
	c.truncMsg = reason
}

// Stop 结束采集: 关闭文件, 返回结果摘要(供任务结果装配)。
//
// 返回的 CaptureResult 即使没有任何报文也会带上 notes(交互摘要),
// 让中心端在无 Npcap 环境下仍能拿到"扫描过程记录"作为证据链的一部分。
func (c *Capture) Stop() CaptureResult {
	if c == nil {
		return CaptureResult{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var path string
	if c.file != nil {
		_ = c.file.Sync()
		_ = c.file.Close()
		path = c.file.Name()
		c.file = nil
	}
	c.stopped = true

	res := CaptureResult{
		Enabled:  c.cfg.Enabled,
		FilePath: path,
		Packets:  c.packets,
		Bytes:    c.written,
		Notes:    append([]string(nil), c.notes...),
		Duration: time.Since(c.started),
	}
	switch {
	case c.openErr != nil:
		res.Error = c.openErr.Error()
	case c.truncMsg != "":
		res.Truncated = true
		res.Reason = c.truncMsg
	case c.packets == 0 && len(c.notes) == 0:
		res.Reason = "本次扫描未采集到交互数据"
	}
	return res
}

// CaptureResult 抓包结果摘要(随任务结果回传中心端)。
type CaptureResult struct {
	Enabled   bool          `json:"enabled"`
	FilePath  string        `json:"filePath,omitempty"` // 本地 PCAP 路径(中心端可据此拉取)
	Packets   int           `json:"packets"`
	Bytes     int64         `json:"bytes"`
	Notes     []string      `json:"notes,omitempty"` // 交互摘要(无 Npcap 时的降级证据)
	Duration  time.Duration `json:"duration"`
	Truncated bool          `json:"truncated,omitempty"`
	Reason    string        `json:"reason,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// Summary 一行摘要(任务结果里展示)。
func (r CaptureResult) Summary() string {
	if !r.Enabled {
		return ""
	}
	if r.Error != "" {
		return "抓包不可用: " + truncate(r.Error, 120)
	}
	if r.FilePath == "" {
		return fmt.Sprintf("抓包已启用但未采集到报文(%d 条交互摘要)", len(r.Notes))
	}
	s := fmt.Sprintf("抓包 PCAP: %d 个报文 / %d 字节, 文件 %s", r.Packets, r.Bytes, filepath.Base(r.FilePath))
	if r.Truncated {
		s += "(已按上限截断)"
	}
	return s
}

// ===== 采集器接口(平台实现注入) =====

// Collector 报文采集器抽象: 平台相关实现(windows 走 Npcap, 其它平台无实现)
// 通过 InitCollector 注入, 扫描层只依赖这个接口。
type Collector interface {
	// Name 采集器名称(日志/能力上报用)
	Name() string
	// Start 开始采集(把报文喂给 sink); 返回错误表示不可用, 调用方降级
	Start(ctx context.Context, cfg CaptureConfig, sink func([]byte) bool) error
	// Stop 停止采集并释放资源
	Stop()
}

var (
	collectorMu sync.Mutex
	collector   Collector
)

// SetCollector 注入平台采集器(装配层调用; 传 nil 表示无采集能力)。
//
// 为什么要注入而不是直接调 Npcap: probe/scanner 包要保持"零平台耦合",
// 才能被 agent 引用并在 Linux/macOS 上编译通过(项目规则 2)。
func SetCollector(c Collector) {
	collectorMu.Lock()
	collector = c
	collectorMu.Unlock()
}

// CurrentCollector 返回当前采集器(可能为 nil)。
func CurrentCollector() Collector {
	collectorMu.Lock()
	defer collectorMu.Unlock()
	return collector
}

// CaptureSupported 当前平台是否支持真实报文采集(供探针能力上报)。
func CaptureSupported() bool { return CurrentCollector() != nil }
