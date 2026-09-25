// ssh.go SSH 命令采集器 —— Linux 主机侧。
//
// 纯标准库没有 SSH 客户端(x/crypto 是第三方依赖, 项目硬约束不允许), 因此走
// "外部工具"口径(与 nmapcore/trivycore 同模式): 调用系统自带的 ssh 客户端。
// ssh 客户端定位: 先 PATH, 再 exe 同目录与 bin/ 目录(用户可自放一个)。
// 找不到 ssh 客户端时如实报"未安装", 不降级成假数据(采集器假数据比失败危险)。
//
// 远程命令一次拿全(CPU 用 /proc/stat 两次采样差分, 跨发行版不依赖 top/sar):
// 所有输出都来自 /proc 与 df/ps, 解析侧逐段容错 —— 某段缺失只留 0/空,
// 整轮不失败(与 SNMP 采集器"拿不到不猜"同口径)。
package collect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register(ProtoSSH, collectSSH)
}

// sshRemoteCommand 默认远程命令(输出按 MARK 分段, 解析侧按段切)。
//
// 为什么用 /proc 而不是 top/free/sar: 最小发行版(容器/精简 CentOS)可能没有
// procps, /proc 是所有 Linux 都有的; df 在 coreutils 里, 基本必有。
const sshRemoteCommand =
	"(echo MARK-STAT; head -1 /proc/stat; sleep 1; head -1 /proc/stat;" +
	"echo MARK-MEM; grep -E '^(MemTotal|MemAvailable|MemFree)' /proc/meminfo;" +
	"echo MARK-LOAD; cat /proc/loadavg;" +
	"echo MARK-UPTIME; awk '{print int($1)}' /proc/uptime;" +
	"echo MARK-DISK; df -P -B1 2>/dev/null | tail -n +2;" +
	"echo MARK-PROC; ps -eo pid,comm,%cpu,%mem --sort=-%mem 2>/dev/null | head -11;" +
	"echo MARK-EVENTS; (journalctl -p warning -n 5 --no-pager -q 2>/dev/null || dmesg 2>/dev/null | tail -n 5));"

func collectSSH(ctx context.Context, e *Engine, t Task) *Round {
	r := newRound(t, time.Now())
	bin := findSSH()
	if bin == "" {
		r.OK = false
		r.Err = "未找到 ssh 客户端(放入 PATH 或 exe 同目录/bin/)"
		return r
	}
	host, port := hostPort(t.Target, 22)
	if host == "" || t.User == "" {
		r.OK = false
		r.Err = "目标需 host:port 且 user 必填(如 192.168.1.10, user=root)"
		return r
	}
	cmdText := t.Param("command")
	if cmdText == "" {
		cmdText = sshRemoteCommand
	}

	// 只支持密钥登录: BatchMode=yes 拒绝一切交互式密码提示(自动化场景弹密码
	// 输入会挂死进程), 口令登录需求请自行配 ssh-agent/密钥 —— 文档里写清。
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-p", strconv.Itoa(port),
		t.User + "@" + host,
		cmdText,
	}
	ctx2, cancel := context.WithTimeout(ctx, e.Config().TaskTimeout(t))
	defer cancel()
	out, err := exec.CommandContext(ctx2, bin, args...).CombinedOutput()
	if err != nil {
		r.OK = false
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		r.Err = "ssh 执行失败: " + msg
		return r
	}
	parseSSHOutput(r, string(out))
	if len(r.Metrics) == 0 {
		r.OK = false
		r.Err = "输出无法解析(远程主机可能不是 Linux 或命令被改)"
		return r
	}
	r.OK = true
	return r
}

// findSSH 定位 ssh 客户端: PATH → exe 同目录 → bin/ 目录。
func findSSH() string {
	if p, err := exec.LookPath("ssh"); err == nil {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, name := range []string{"ssh.exe", "ssh"} {
			p := filepath.Join(dir, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
			p = filepath.Join(dir, "bin", name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}
	return ""
}

// parseSSHOutput 按 MARK 分段解析。每段独立容错: 某段缺失只跳过该段。
func parseSSHOutput(r *Round, out string) {
	sections := map[string]string{}
	var cur string
	var buf []string
	flush := func() {
		if cur != "" {
			sections[cur] = strings.Join(buf, "\n")
		}
		buf = nil
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "MARK-") {
			flush()
			cur = line
			continue
		}
		if cur != "" {
			buf = append(buf, line)
		}
	}
	flush()

	// CPU: /proc/stat 两行 "cpu user nice system idle iowait irq softirq ..."
	// 百分比 = 1 - Δidle(含 iowait)/Δtotal
	if v, ok := cpuFromStat(sections["MARK-STAT"]); ok {
		r.Metrics = append(r.Metrics, Metric{Name: "cpu", Value: v, Unit: "%"})
	}
	// 内存: MemTotal/MemAvailable(kB)
	var memTotal, memAvail int64
	for _, line := range strings.Split(sections["MARK-MEM"], "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			memTotal = v
		case "MemAvailable:":
			memAvail = v
		}
	}
	if memTotal > 0 {
		used := memTotal - memAvail
		if used < 0 {
			used = 0
		}
		r.Metrics = append(r.Metrics,
			Metric{Name: "mem_total", Value: float64(memTotal) * 1024, Unit: "B"},
			Metric{Name: "mem_used", Value: float64(used) * 1024, Unit: "B"},
			Metric{Name: "mem_used_pct", Value: float64(used) / float64(memTotal) * 100, Unit: "%"},
		)
	}
	// 负载: "0.52 0.48 0.45 2/123 8828"
	if f := strings.Fields(sections["MARK-LOAD"]); len(f) >= 3 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			r.Metrics = append(r.Metrics, Metric{Name: "load1", Value: v, Unit: ""})
		}
	}
	if f := strings.Fields(sections["MARK-UPTIME"]); len(f) >= 1 {
		if v, err := strconv.ParseInt(f[0], 10, 64); err == nil {
			r.Metrics = append(r.Metrics, Metric{Name: "uptime", Value: float64(v), Unit: "s"})
		}
	}
	// 磁盘: df -P -B1 → Filesystem 1024-blocks Used Available Capacity Mounted
	var diskTotal, diskUsed int64
	for _, line := range strings.Split(sections["MARK-DISK"], "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		if strings.HasPrefix(f[0], "/dev/") == false {
			continue // 跳过 tmpfs/overlay 之外的异常行, 只认真实块设备
		}
		total, _ := strconv.ParseInt(f[2], 10, 64)
		used, _ := strconv.ParseInt(f[3], 10, 64)
		if total == 0 {
			continue
		}
		// 第一块真实设备当"磁盘"指标(多盘场景 UI 展开明细)
		if diskTotal == 0 {
			diskTotal, diskUsed = total, used
		}
		r.Metrics = append(r.Metrics, Metric{
			Name: "disk", Value: float64(used), Unit: "B",
			Labels: map[string]string{"fs": f[0], "total": strconv.FormatInt(total, 10), "mounted": f[5]},
		})
	}
	if diskTotal > 0 {
		r.Metrics = append(r.Metrics,
			Metric{Name: "disk_total", Value: float64(diskTotal), Unit: "B"},
			Metric{Name: "disk_used", Value: float64(diskUsed), Unit: "B"},
		)
	}
	// 进程: ps -eo pid,comm,%cpu,%mem → TOP10(第一行是表头)
	lines := strings.Split(strings.TrimSpace(sections["MARK-PROC"]), "\n")
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] == "PID" {
			continue
		}
		pid, _ := strconv.ParseUint(f[0], 10, 64)
		cpu, _ := strconv.ParseFloat(f[2], 64)
		mem, _ := strconv.ParseFloat(f[3], 64)
		r.Metrics = append(r.Metrics, Metric{
			Name: "process", Value: mem, Unit: "%",
			Labels: map[string]string{"pid": fmt.Sprint(pid), "name": f[1], "cpu": fmt.Sprintf("%.1f", cpu)},
		})
	}
	// 系统事件: journalctl/dmesg 的最近告警行
	evLines := strings.Split(strings.TrimSpace(sections["MARK-EVENTS"]), "\n")
	for _, line := range evLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 200 {
			line = line[:200]
		}
		r.Metrics = append(r.Metrics, Metric{
			Name: "system_event", Value: 0,
			Labels: map[string]string{"level": "warn", "msg": line},
		})
	}
}

// cpuFromStat 从 /proc/stat 两行采样算 CPU 使用率。
func cpuFromStat(stat string) (float64, bool) {
	var rows [][]int64
	for _, line := range strings.Split(stat, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		var vals []int64
		for _, s := range f[1:] {
			v, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				break
			}
			vals = append(vals, v)
		}
		if len(vals) >= 4 {
			rows = append(rows, vals)
		}
	}
	if len(rows) < 2 {
		return 0, false
	}
	a, b := rows[0], rows[1]
	var totalA, totalB, idleA, idleB int64
	for _, v := range a {
		totalA += v
	}
	for _, v := range b {
		totalB += v
	}
	idleA = a[3]
	if len(a) > 4 {
		idleA += a[4] // iowait
	}
	idleB = b[3]
	if len(b) > 4 {
		idleB += b[4]
	}
	dt := totalB - totalA
	di := idleB - idleA
	if dt <= 0 {
		return 0, false
	}
	// (1 - Δidle/Δtotal) 是 0-1 的占比, 指标单位是 %, 必须 ×100 ——
	// 漏乘会让 CPU 永远显示 0.2%(真值 21%), 静默错得很难查。
	cpu := (1.0 - float64(di)/float64(dt)) * 100
	if cpu < 0 {
		cpu = 0
	}
	if cpu > 100 {
		cpu = 100
	}
	return cpu, true
}
