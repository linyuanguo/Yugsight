//go:build windows

package probe

import (
	"testing"
	"time"
)

// TestSampleMetricsSurvivesFirstNoData 守 2026-10-01 修复的契约: 速率计数器
// 首拍 PdhCollectQueryData 恒返回 PDH_NO_DATA(正常态, 不是失败)。
//
// 旧实现把它当失败 → SampleMetrics 永远返回 nil → Windows 侧磁盘 IO 与网络速率
// 长期全空(探针指标面板、中心端内置监控目标都拿不到数, 且无任何报错, 静默失效)。
// 断言: 连续两次采样都返回非 nil 样本(数值是否为 0 不约束 —— 空闲机器 0 是真实值)。
func TestSampleMetricsSurvivesFirstNoData(t *testing.T) {
	for i := 0; i < 2; i++ {
		s := SampleMetrics(time.Second)
		if s == nil {
			// 平台无 PDH/查询打不开时本就降级为 nil, 不算回归
			if !pdhReady {
				t.Skip("PDH 不可用(降级路径), 跳过")
			}
			t.Fatalf("第 %d 次采样返回 nil: 首拍 PDH_NO_DATA 被当成失败(回归)", i+1)
		}
		if s.DiskReadBps < 0 || s.DiskWriteBps < 0 || s.NetUpBps < 0 || s.NetDownBps < 0 {
			t.Fatalf("速率出现负值: %+v", s)
		}
		time.Sleep(1100 * time.Millisecond) // 速率计数器需要 >1s 的采样间隔才有值
	}
}
