package scheduler

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ===== 调度配置(exe 同目录 scheduler.json, 可选) =====
//
// 与项目其它配置(engine.json / probe.json / updater.json)同一惯例:
// 文件缺失或损坏一律走默认值, 不报错不中断(项目规则 3)。

// Config 调度器配置。
type Config struct {
	// Enabled 总开关。默认 true -> 开箱即用, 排队提交(queue=true)直接可用。
	//
	// 为什么默认开(2026-09-20 用户要求"全部默认配好、自动化、别让用户改配置"):
	// 默认开只影响显式带 queue=true 的提交, /api/scan 的默认"立即执行 + SSE 流"
	// 语义完全不变(见 main.go handleScan 的接管判定), 即时扫描的既有行为零变化。
	// 需要关闭时在 settings.json 的 scheduler 节显式写 enabled=false。
	Enabled bool `json:"enabled"`

	// MaxConcurrency 全局最大并发任务数(所有节点合计), 默认 2。
	//
	// 取小值的原因: 扫描是 IO/带宽密集操作, 并发 2 已能让千兆网卡接近跑满;
	// 开大反而互相抢带宽导致整体更慢, 且更容易触发内网设备告警。
	MaxConcurrency int `json:"maxConcurrency"`

	// NodeConcurrency 单节点默认并发上限(仅作用于**探针**; 探针可各自覆盖), 默认 1。
	//
	// 单探针 1 的原因: 探针多部署在低配机器/边缘网点, 同时跑 2 个大网段扫描
	// 会把它的连接表/内存打满, 反而拖慢所有任务。
	//
	// 刻意**不约束中心本地节点**: 本地的扫描规模由 MaxConcurrency 表达。
	// 若本地也套这个值, 默认配置下全局并发永远只能是 1, MaxConcurrency 就成了
	// 摆设(详见 nodeRegistry.Accept 注释)。
	NodeConcurrency int `json:"nodeConcurrency"`

	// LocalConcurrency 中心本地节点并发上限, 0 = 只受 MaxConcurrency 约束(默认)。
	//
	// 留这个开关是给"中心机器同时还要跑 Web UI/AI 分析"的场景: 运维可以把本地
	// 并发压到 1, 把余量留给探针。
	LocalConcurrency int `json:"localConcurrency"`

	// MaxQueue 队列长度上限(0 = 无上限), 默认 200。
	//
	// 设上限的目的不是省内存(任务对象很小), 而是给提交者及时反馈:
	// 排到几百个任务后面, 用户等一小时才轮到, 不如直接告知"队列满, 稍后再来"。
	MaxQueue int `json:"maxQueue"`

	// DefaultRate 默认发包速率(包/秒), 0 = 不限速, 默认 1000。
	//
	// 1000pps 是经验值: /24 网段 254 主机 x 100 端口 = 25400 个包,
	// 按 1000pps 约 25 秒完成, 对百兆/千兆内网都很温和。
	DefaultRate int `json:"defaultRate"`

	// RateRules 网段专属速率(优先于 DefaultRate)。
	RateRules []RateRule `json:"rateRules"`

	// MaxCPUPercent / MaxMemPercent 探针负载阈值, 超过则中心端不下发新任务
	// (任务保持排队, 等负载降下来自动派发)。0 = 不判负载。
	MaxCPUPercent float64 `json:"maxCpuPercent"`
	MaxMemPercent float64 `json:"maxMemPercent"`

	// MaxTasksRunning 探针自报运行任务数的上限(0 = 不判)。
	MaxTasksRunning int `json:"maxTasksRunning"`

	// DefaultStrategy 未指定策略时使用的模板 ID, 默认 quick。
	//
	// 默认选快速存活探测: 首次使用者的常见诉求是"先看看网段里有什么",
	// 而完整审计会跑很久 —— 默认值应选"代价最小"的那个。
	DefaultStrategy string `json:"defaultStrategy"`

	// MaxAttempts 任务失败自动重分配的最大尝试次数, 默认 2(含首次)。
	MaxAttempts int `json:"maxAttempts"`

	// TaskTimeoutSec 单任务执行超时(秒), 0 = 不限制, 默认 1800(30 分钟)。
	//
	// 必须有上限: 卡死的任务会永久占用并发槽位, 表现为"队列不再流动"。
	TaskTimeoutSec int `json:"taskTimeoutSec"`

	// AutoStart 是否在程序启动时把"上次未完成的任务"重新入队(任务书: 支持续扫)。
	AutoStart bool `json:"autoStart"`
}

// DefaultConfig 默认调度配置。
func DefaultConfig() Config {
	return Config{
		Enabled:         true,
		MaxConcurrency:  2,
		NodeConcurrency: 1,
		MaxQueue:        200,
		DefaultRate:     1000,
		DefaultStrategy: StrategyQuick,
		MaxAttempts:     2,
		TaskTimeoutSec:  1800,
		AutoStart:       false,
	}
}

// normalize 补齐零值/非法值(不改变"显式设为 0 = 不限"的语义字段)。
func (c *Config) normalize() {
	d := DefaultConfig()
	if c.MaxConcurrency <= 0 {
		c.MaxConcurrency = d.MaxConcurrency
	}
	if c.NodeConcurrency <= 0 {
		c.NodeConcurrency = d.NodeConcurrency
	}
	if c.MaxQueue < 0 {
		c.MaxQueue = 0
	}
	if c.DefaultRate < 0 {
		c.DefaultRate = 0
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = d.MaxAttempts
	}
	if strings.TrimSpace(c.DefaultStrategy) == "" {
		c.DefaultStrategy = d.DefaultStrategy
	}
	if c.TaskTimeoutSec < 0 {
		c.TaskTimeoutSec = 0
	}
	// 网段规则清洗: 空网段丢弃, 速率负值视为"不限速"
	rules := c.RateRules[:0]
	for _, r := range c.RateRules {
		if strings.TrimSpace(r.CIDR) == "" {
			continue
		}
		if r.Rate < 0 {
			r.Rate = 0
		}
		rules = append(rules, r)
	}
	c.RateRules = rules
}

// AcceptConfig 从调度配置导出节点接纳判定参数。
func (c Config) AcceptConfig() AcceptConfig {
	return AcceptConfig{
		DefaultMaxConcurrency: c.NodeConcurrency,
		MaxCPUPercent:         c.MaxCPUPercent,
		MaxMemPercent:         c.MaxMemPercent,
		MaxTasksRunning:       c.MaxTasksRunning,
	}
}

// 配置加载注入点(与 db.SetLogger / probe.SetGlobalLogger 同手法):
// scheduler 包不依赖 main, 由装配层注入日志与配置路径。
var (
	logFunc     func(string)
	cfgPathFunc func() string
	cfgReadFunc func() ([]byte, bool)
)

// SetLogger 注入日志函数(并入 yugsight.log)。
func SetLogger(f func(string)) {
	if f != nil {
		logFunc = f
	}
}

// SetConfigPath 注入配置文件路径函数(默认 exe 同目录 scheduler.json)。
func SetConfigPath(f func() string) {
	if f != nil {
		cfgPathFunc = f
	}
}

// SetConfigReader 注入配置内容来源(优先于 SetConfigPath 指定的文件)。
//
// 【为什么需要它】配置统一到 settings.json 后, 调度配置只是其中一个节, 不再
// 是独立文件。若让 scheduler 包自己去解析 settings.json 的顶层结构, 它就得
// 知道"统一配置"这个全局概念 —— 而 scheduler 的定位是"只依赖标准库、可脱离
// 装配层单测"的纯逻辑包, 不该被配置存放形式绑住。
//
// 因此这里只接受一个"给我原始 JSON 字节"的函数: 装配层负责从哪里取(settings.json
// 的 scheduler 节, 或旧 scheduler.json), scheduler 包只管解析自己的字段。
// 返回 (内容, 是否存在), 不存在时走默认配置。
//
// 注入点也便于测试: 用例直接喂一段 JSON 即可覆盖解析逻辑, 不用建临时文件。
func SetConfigReader(f func() ([]byte, bool)) {
	if f != nil {
		cfgReadFunc = f
	}
}

func logf(format string, args ...any) {
	if logFunc == nil {
		return
	}
	logFunc(fmt.Sprintf(format, args...))
}

// ConfigPath 当前使用的配置来源路径(展示用途)。
//
// 红线「配置唯一」(2026-09-23 整改): 中心端不再有 scheduler.json。调度配置
// 只来自装配层注入的 settings.json 的 scheduler 节; 旧文件由主程序启动时
// 迁入 settings.json 并改名 .migrated。本函数返回值仅用于"配置在哪改"的提示。
func ConfigPath() string {
	if cfgPathFunc != nil {
		return cfgPathFunc()
	}
	return "settings.json"
}

// LoadConfig 读取 scheduler.json(可选, 缺失/损坏一律返回默认配置)。
//
// 与 engine_api.go 的 loadEngineConfig 同风格: 返回结构体而非 error ——
// 调用方永远有一个可用配置, 不需要写降级分支。
func LoadConfig() Config {
	cfg := DefaultConfig()
	// 唯一来源: 装配层注入的 settings.json 的 scheduler 节。
	// 不再回退读任何单文件(红线「配置唯一」); 未注入时直接用默认配置。
	data, ok := []byte(nil), false
	if cfgReadFunc != nil {
		data, ok = cfgReadFunc()
	}
	if !ok {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		logf("调度配置解析失败, 使用默认调度配置: %v", err)
		return DefaultConfig()
	}
	cfg.normalize()
	return cfg
}
