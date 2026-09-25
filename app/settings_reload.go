// settings_reload.go 配置热重载(二期 15): 改 settings.json 不必重启。
//
// ===== 触发方式 =====
//
//  1. 文件监听(全平台): 每 5 秒比对 settings.json 的修改时间, 变了就重载;
//  2. SIGUSR1(仅 Unix, 见 settings_reload_unix.go): 信号即时触发, 不必等轮询;
//  3. HTTP: POST /api/v2/config/reload(adminOnly), 给没有 shell 的场景用。
//
// Windows 没有 SIGUSR1(signal.Notify 会直接报不支持), 故信号版拆成
// *_unix.go / *_other.go 两个文件, Windows 走空实现 —— 文件监听已覆盖需求。
//
// ===== 重载范围(刻意收窄) =====
//
// 只重载"配置驱动的开关与参数":
//
//	报告配置 / 大屏与地理映射开关 / 监控目标与间隔 / 调度器参数
//
// 不重载: 数据库实例(会丢会话与缓存)、账号与 2FA(重载会把已登录用户踢下去)、
// 已监听的端口。热重载的边界就是"不能让正在用的人被中断"。
package main

import (
	"net/http"
	"os"
	"sync"
	"time"

	"yugsight/internal/server"
)

const reloadWatchInterval = 5 * time.Second

var (
	reloadMu    sync.Mutex
	reloadLast  time.Time
	reloadStop  = make(chan struct{})
	reloadStart sync.Once
)

// StartSettingsWatcher 启动配置文件监听(幂等)。
func StartSettingsWatcher() {
	reloadStart.Do(func() {
		reloadLast = settingsMtime()
		go func() {
			t := time.NewTicker(reloadWatchInterval)
			defer t.Stop()
			for {
				select {
				case <-reloadStop:
					return
				case <-t.C:
					if m := settingsMtime(); !m.IsZero() && !m.Equal(reloadLast) {
						reloadLast = m
						ReloadSettings("settings.json 已修改")
					}
				}
			}
		}()
		logLine("配置热重载已启用: 修改 settings.json 后 5 秒内自动生效(也可 POST /api/v2/config/reload 立即触发)")
	})
}

// StopSettingsWatcher 停止监听(退出路径调用)。
func StopSettingsWatcher() {
	select {
	case <-reloadStop:
		return // 已关闭, 不重复 close(会 panic)
	default:
		close(reloadStop)
	}
}

// settingsMtime 配置文件修改时间(文件不存在返回零值)。
func settingsMtime() time.Time {
	fi, err := os.Stat(settingsFilePath())
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// ReloadSettings 重新加载全部可热更新的配置, 返回生效项数与失败原因。
//
// 单项失败只记日志继续(降级不崩溃): 重载是"尽力而为", 一项没生效不该让
// 其它配置也跟着不生效 —— 用户改五个开关却只生效三个, 比全不生效更难排查。
func ReloadSettings(reason string) (int, []string) {
	reloadMu.Lock()
	defer reloadMu.Unlock()
	var errs []string
	n := 0

	// 报告配置(开关/存档上限/自动触发/模板管理)
	reportCfgMu.Lock()
	reportCfgDone = false
	reportCfgMu.Unlock()
	n++

	// 大屏与 IP 地理映射开关(geoip 实例一并重建, 否则开关变了但段表还是旧的)
	dashCfgMu.Lock()
	dashCfgDone = false
	dashCfgMu.Unlock()
	geoCfgMu.Lock()
	geoCfgDone = false
	geoCfgMu.Unlock()
	// geoip 实例置空后由下次访问重建(instanceGeoIP 用 mutex 而非 Once,
	// 正是为了能这样重建 —— 见 dashboard_api.go 的注释)
	geoipMu.Lock()
	geoipInst = nil
	geoipMu.Unlock()
	n++

	// 监控: 目标/间隔/保留时长即时生效
	if monInst != nil {
		monInst.SetConfig(loadMonitorConfig())
		n++
	}
	// 调度器: 并发/限速/策略参数即时生效(未启用时 instanceScheduler 仍是安全的空转实例)
	if schedulerEnabled() {
		if s := instanceScheduler(); s != nil {
			s.UpdateConfig(loadSchedulerConfig())
			n++
		}
	}
	for _, e := range errs {
		logLine("[配置重载] " + e)
	}
	logLine("配置已热重载(" + reason + "): " + itoa(n) + " 组配置生效(数据库与登录态不受影响)")
	return n, errs
}

// hConfigReload POST /api/v2/config/reload 手动触发热重载。
func hConfigReload(w http.ResponseWriter, r *http.Request) {
	n, errs := ReloadSettings("手动触发")
	server.OK(w, map[string]any{"reloaded": n, "errors": errs})
}

// itoa 小工具(避免为本文件引进 strconv 之外的依赖)。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
