// metrics_collect.go 探针性能指标采集(2026-09-26, 用户口径"采集内存/CPU/磁盘
// 空间及 IO, 网络上下行; 累积 30 秒发一次, 间隔中心端可下发")。
//
// 本文件是平台无关入口; 具体实现在 metrics_windows.go(PDH 性能计数器)与
// metrics_other.go(Linux /proc 差值 / macOS 无采集降级)。全部采集失败返回
// nil —— 调用方(心跳)据此降级为"只报 CPU/内存", 不阻断心跳。
package probe

import "time"

// MetricsSample 一个指标窗口的速率采样(字节/秒, 窗口均值)。
type MetricsSample struct {
	DiskReadBps  float64 // 磁盘读速率
	DiskWriteBps float64 // 磁盘写速率
	NetUpBps     float64 // 网络上行(发送)速率
	NetDownBps   float64 // 网络下行(接收)速率
}

// SampleMetrics 采集磁盘 IO / 网络上下行速率。
//
// interval = 当前指标窗口长度(秒)。两种平台实现:
//   - Windows: PDH 的 "*Bytes/sec" 计数器是内置速率计数器, PDH 内部按两次
//     Collect 的时间差算速率, interval 不用;
//   - Linux: /proc/diskstats 与 /proc/net/dev 是累计值, 需自行对窗口做差,
//     interval 即分母。
//
// 返回 nil = 平台不支持或采集失败(调用方降级, 不报错)。
func SampleMetrics(interval time.Duration) *MetricsSample {
	return metricsOS(interval)
}
