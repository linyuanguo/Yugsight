//go:build windows

package probe

import (
	"testing"
	"time"
)

// TestSampleIfacesWindows 守 Windows 网卡明细的契约(需求 1, 2026-10-02):
// 有网卡的机器必须出非空清单(清单缺失=前端"暂无端口数据", 属静默失效),
// 速率不得为负(首拍 PDH_NO_DATA 时速率 0 是真实降级, 不算失败)。
//
// PDH 不可用(受限会话)时降级为 nil —— 与平台能力缺失同口径, 跳过不判回归。
func TestSampleIfacesWindows(t *testing.T) {
	if !pdhReady && !pdhInit() {
		t.Skip("PDH 不可用(降级路径), 跳过")
	}
	first := SampleIfaces(time.Second)
	if first == nil {
		t.Fatal("PDH 就绪但 SampleIfaces 返回 nil: 清单静默缺失(回归)")
	}
	if len(first) == 0 {
		t.Fatal("有网卡的机器清单不能为空")
	}
	for i := range first {
		if first[i].Name == "" {
			t.Fatalf("第 %d 条网卡名为空", i)
		}
		if first[i].InBps < 0 || first[i].OutBps < 0 {
			t.Fatalf("速率出现负值: %+v", first[i])
		}
	}
	time.Sleep(1100 * time.Millisecond) // 速率计数器需要 >1s 窗口
	second := SampleIfaces(time.Second)
	if second == nil || len(second) == 0 {
		t.Fatal("第二轮清单为空: 采样不稳定(回归)")
	}
}
