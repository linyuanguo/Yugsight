// snmp_host.go 主机 SNMP 采集(HR-MIB, 与网络设备 SNMP 同协议, 口径对齐
// monitor 包对交换机的采集, 真机锐捷已验证该 MIB 口径)。
//
// 采集内容: CPU(hrProcessorLoad 首条)、内存(hrStorageTable 的 RAM 条目)、
// 磁盘(hrStorageTable 非 RAM 的首块)、系统信息(sysDescr/sysName/uptime)。
// 设备不支持的项留 0/空(与 monitor 同口径: 拿不到不猜, 不把磁盘当内存)。
package collect

import (
	"context"
	"strconv"
	"strings"
	"time"

	"yugsight/monitor"
	"yugsight/snmp"
)

func init() {
	Register(ProtoSNMP, collectSNMP)
}

func collectSNMP(ctx context.Context, e *Engine, t Task) *Round {
	r := newRound(t, time.Now())
	timeout := e.Config().TaskTimeout(t)
	// 口令在配置里是密文(与 monitor 同一套加密), 采集前解密;
	// 解密失败返回空串, 设备会因"口令缺失"报明确错误, 而不是把 enc:xxx 当口令发。
	key := monitor.SecretKey()
	community := monitor.DecryptSecret(key, t.Community)
	c := snmp.NewClient(t.Target, community, timeout)
	if strings.TrimSpace(t.User) != "" {
		c.V3 = &snmp.V3Config{
			User:      t.User,
			AuthProto: t.AuthProto,
			AuthPass:  monitor.DecryptSecret(key, t.AuthPass),
			PrivProto: t.PrivProto,
			PrivPass:  monitor.DecryptSecret(key, t.PrivPass),
			Context:   t.Param("context"),
		}
	}

	if err := ctx.Err(); err != nil {
		r.OK = false
		r.Err = err.Error()
		return r
	}
	rep := snmp.Collect(ctx, c)

	for _, sr := range rep.Scalars {
		if sr.Err != nil && !r.OK {
			r.Err = sr.Err.Error()
		}
		switch sr.Metric.Name {
		case "sysDescr":
			r.Metrics = append(r.Metrics, Metric{Name: "sys_descr", Value: 0, Labels: map[string]string{"value": sr.Text}})
		case "sysName":
			r.Metrics = append(r.Metrics, Metric{Name: "sys_name", Value: 0, Labels: map[string]string{"value": sr.Text}})
		case "sysUpTime":
			if v, err := strconv.ParseInt(sr.Text, 10, 64); err == nil {
				r.Metrics = append(r.Metrics, Metric{Name: "uptime", Value: float64(v / 100), Unit: "s"})
			}
		}
	}
	for _, tr := range rep.Tables {
		switch tr.Table.Name {
		case "hrProcessorTable":
			for _, row := range tr.Rows {
				if v, err := strconv.ParseInt(row.Cells["hrProcessorLoad"], 10, 64); err == nil {
					r.Metrics = append(r.Metrics, Metric{Name: "cpu", Value: float64(v), Unit: "%"})
					break
				}
			}
		case "hrStorageTable":
			hasDisk := false
			for _, row := range tr.Rows {
				desc := strings.ToLower(row.Cells["hrStorageDescr"])
				units, _ := strconv.ParseInt(row.Cells["hrStorageUnits"], 10, 64)
				if units <= 0 {
					units = 1
				}
				size, sizeErr := strconv.ParseInt(row.Cells["hrStorageSize"], 10, 64)
				used, usedErr := strconv.ParseInt(row.Cells["hrStorageUsed"], 10, 64)
				isRAM := strings.Contains(desc, "ram") || strings.Contains(desc, "memory")
				if sizeErr != nil || usedErr != nil {
					continue
				}
				if isRAM {
					r.Metrics = append(r.Metrics,
						Metric{Name: "mem_total", Value: float64(size * units), Unit: "B"},
						Metric{Name: "mem_used", Value: float64(used * units), Unit: "B"},
					)
					if size*units > 0 {
						r.Metrics = append(r.Metrics, Metric{
							Name: "mem_used_pct", Unit: "%",
							Value: float64(used*units) / float64(size*units) * 100,
						})
					}
				} else if !isRAM && !hasDisk && !strings.Contains(desc, "virtual") {
					hasDisk = true
					r.Metrics = append(r.Metrics,
						Metric{Name: "disk_total", Value: float64(size * units), Unit: "B"},
						Metric{Name: "disk_used", Value: float64(used * units), Unit: "B"},
						Metric{Name: "disk_desc", Value: 0, Labels: map[string]string{"value": row.Cells["hrStorageDescr"]}},
					)
				}
			}
		}
	}

	if rep.OKCount > 0 {
		r.OK = true
	} else if r.Err == "" {
		r.Err = "设备无响应"
	}
	return r
}
