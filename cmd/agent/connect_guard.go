// connect_guard.go 中心端连不上时的交互守卫(Windows)。
//
// 【为什么需要】探针是后台常驻进程, 中心端地址写错或中心端没起来时, 它只会
// 按退避静默重试 —— 用户在中心端页面看不到节点上线, 也没有任何"哪里不对"的
// 提示, 只能去翻日志。这里在"连续离线超过阈值"时弹一次框让用户处理:
//
//	- 填了新地址 -> 写回 probe.json 并以新地址重启本进程(不必等用户手工重启);
//	- 稍后提醒   -> 按所选分钟数静默(期间照常自动重连, 中心端恢复即自动上线);
//	- 退出探针   -> 结束进程(开机自启会在下次开机重新拉起)。
//
// 【非 Windows 不激活】弹框在 Linux 是空桩(dialog_other.go), centerPromptSupported
// 返回 false 时本守卫直接返回 —— 无人值守的服务器不该弹没人点的窗口。
//
// 【为什么不用"连不上就退出"】探针部署在被扫描机器上, 中心端晚一点起来是常态;
// 直接退出等于把"暂时不可达"变成"永久离线", 与探针的定位相反。
package main

import (
	"net"
	"os"
	"strings"
	"time"

	"yugsight/internal/probe"
)

// warnLoopbackCenter 中心端地址指向本机时给一行提示。
//
// 探针装在别的机器上时, 127.0.0.1/localhost 是**探针自己**, 会一直连不上中心端,
// 而日志里只是"连接被拒", 用户很难想到是地址填成了回环。这里显式说破。
// 同机联调(中心端与探针同一台)是合法用法, 因此只提示不阻断。
func warnLoopbackCenter(addr string) {
	host := strings.TrimSpace(addr)
	if host == "" {
		return
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1":
		logLine("提示: 中心端地址 " + addr + " 指向本机 —— 若探针与中心端不在同一台机器, 请改为中心端的局域网 IP")
	}
}

const (
	// guardOfflineBefore 连续离线多久才弹框。太短会把"中心端正在重启/网络抖动"
	// 也弹出来打扰用户; 25s 足够跨过首次注册与几个退避周期。
	guardOfflineBefore = 25 * time.Second
	guardTick          = 5 * time.Second
	// guardDefaultSnooze 弹框超时或静默时长解析失败时的兜底静默时长。
	guardDefaultSnooze = 5 * time.Minute
)

// startConnectGuard 启动连接守卫(仅 Windows 生效, 其它平台无操作)。
//
// 只做观察: 不干预探针自身的重连逻辑, 只在用户给出新地址时重启本进程。
func startConnectGuard(p *probe.Probe, cfg probe.ProbeConfig, cfgPath string) {
	if !centerPromptSupported() {
		return
	}
	go func() {
		var offlineSince, snoozeUntil time.Time
		for {
			time.Sleep(guardTick)
			if p.Online() {
				offlineSince = time.Time{}
				snoozeUntil = time.Time{}
				continue
			}
			now := time.Now()
			if offlineSince.IsZero() {
				offlineSince = now
			}
			if now.Sub(offlineSince) < guardOfflineBefore {
				continue
			}
			if now.Before(snoozeUntil) {
				continue
			}
			addr, token, snoozeMin, wantExit := promptCenterFailure(cfg.CenterAddr, now.Sub(offlineSince))
			if wantExit {
				logLine("用户在弹框中选择退出, 探针停止(开机自启会在下次开机重新拉起)")
				os.Exit(0)
			}
			if addr != "" && addr != cfg.CenterAddr {
				logLine("用户填写了新的中心端地址, 写入配置并重启: " + addr)
				if err := saveCenterAddr(cfgPath, addr, token); err != nil {
					logLine("新地址写回配置失败(仅本次生效): " + err.Error())
				}
				// 先放互斥再重启: 子进程启动时会做同样的单实例检查,
				// 本进程不放手它会被判定为"已有实例在跑"而直接退出。
				releaseSingleInstance()
				if err := relaunchSelf(addr); err != nil {
					logLine("重启失败, 保持本进程继续重试: " + err.Error())
				} else {
					os.Exit(0)
				}
			}
			snooze := guardDefaultSnooze
			if snoozeMin > 0 {
				snooze = time.Duration(snoozeMin) * time.Minute
			}
			if snoozeMin == 0 {
				logLine("用户选择不再提醒, 探针继续在后台自动重连(不再弹框)")
				snooze = 24 * time.Hour // 不再提醒: 静默到"下辈子", 但重连照旧
			} else {
				logLine("中心端仍不可达, 按用户选择静默 " + snooze.String() + " 后再提醒(期间继续自动重连)")
			}
			snoozeUntil = time.Now().Add(snooze)
			offlineSince = time.Now() // 静默期从现在算起, 避免解除静默后立刻再弹
		}
	}()
}
