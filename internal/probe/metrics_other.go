//go:build !windows

package probe

import (
	"os"
	"strings"
	"sync"
	"time"
)

// ===== 非 Windows: Linux 读 /proc 累计值做窗口差; macOS 无 /proc 降级为 nil =====
//
// 口径: /proc/diskstats 的扇区数(×512 得字节)与 /proc/net/dev 的收发字节数
// 都是累计值, 两次采样做差除以窗口长度(interval)得到速率。首次采样只建基线
// 返回 nil(本拍不报, 次拍起正常) —— 与 Windows PDH 首拍无数据的行为一致。

var (
	diskPrevMu sync.Mutex
	diskPrev   struct {
		ok  bool
		t   time.Time
		rd  uint64 // 累计读字节
		wr  uint64 // 累计写字节
	}
	netPrevMu sync.Mutex
	netPrev   struct {
		ok  bool
		t   time.Time
		rx  uint64
		tx  uint64
	}
)

func metricsOS(interval time.Duration) *MetricsSample {
	if _, err := os.Stat("/proc/net/dev"); err != nil {
		return nil // 非 Linux(如 macOS): 无 /proc, 不报 IO/网络指标
	}
	s := &MetricsSample{}
	any := false
	if rd, wr, ok := diskRate(interval); ok {
		s.DiskReadBps, s.DiskWriteBps = rd, wr
		any = true
	}
	if down, up, ok := netRate(interval); ok {
		s.NetDownBps, s.NetUpBps = down, up
		any = true
	}
	if !any {
		return nil // 首次采样(只有基线无差值), 本拍降级不报
	}
	return s
}

// diskRate 磁盘读/写速率(字节/秒)。只统计整盘设备, 分区条目(sda1/nvme0n1p1
// 等)会与其父盘重复计数, 必须剔除。
func diskRate(interval time.Duration) (rd, wr float64, ok bool) {
	b, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return 0, 0, false
	}
	var rdS, wrS uint64
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 10 {
			continue
		}
		name := f[2]
		if !isWholeDisk(name) {
			continue
		}
		rdS += atoiSafe(f[5]) // 读扇区
		wrS += atoiSafe(f[9]) // 写扇区
	}
	now := time.Now()
	diskPrevMu.Lock()
	defer diskPrevMu.Unlock()
	if !diskPrev.ok {
		diskPrev.ok, diskPrev.t, diskPrev.rd, diskPrev.wr = true, now, rdS, wrS
		return 0, 0, false
	}
	rdB, wrB := float64(rdS-diskPrev.rd)*512, float64(wrS-diskPrev.wr)*512
	diskPrev.t, diskPrev.rd, diskPrev.wr = now, rdS, wrS
	// 窗口长度用 interval(中心端下发口径), 不信任两次采样的真实时间差
	// (采样由心跳门控, 抖动可能让 dt 偏离 interval)。
	if interval <= 0 {
		return 0, 0, false
	}
	return rdB / interval.Seconds(), wrB / interval.Seconds(), true
}

// netRate 网络下/上行速率(字节/秒), 所有物理网卡之和(lo 回环剔除)。
func netRate(interval time.Duration) (down, up float64, ok bool) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	var rx, tx uint64
	for _, ln := range strings.Split(string(b), "\n") {
		colon := strings.Index(ln, ":")
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:colon])
		if name == "lo" {
			continue
		}
		f := strings.Fields(ln[colon+1:])
		if len(f) < 9 {
			continue
		}
		rx += atoiSafe(f[0])
		tx += atoiSafe(f[8])
	}
	now := time.Now()
	netPrevMu.Lock()
	defer netPrevMu.Unlock()
	if !netPrev.ok {
		netPrev.ok, netPrev.t, netPrev.rx, netPrev.tx = true, now, rx, tx
		return 0, 0, false
	}
	downB, upB := float64(rx-netPrev.rx), float64(tx-netPrev.tx)
	netPrev.t, netPrev.rx, netPrev.tx = now, rx, tx
	if interval <= 0 {
		return 0, 0, false
	}
	return downB / interval.Seconds(), upB / interval.Seconds(), true
}

// isWholeDisk 只认整盘设备名: sdX / vdX / hdX(尾部数字=分区) /
// nvmeXnY(含 "p数字" = 分区)。
func isWholeDisk(name string) bool {
	if strings.HasPrefix(name, "nvme") {
		return !strings.Contains(name[strings.LastIndex(name, "n")+1:], "p")
	}
	for _, pre := range []string{"sd", "vd", "hd"} {
		if strings.HasPrefix(name, pre) {
			c := name[len(name)-1]
			return c < '0' || c > '9' // 尾部无数字 = 整盘
		}
	}
	return false
}
