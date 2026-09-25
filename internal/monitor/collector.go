// collector.go 单目标采集: 复用 snmp 包(v2c GET/GETBULK + 固定 MIB 库)。
//
// 一轮 = snmp.Collect 全量(标量一次批量 GET + ifTable/hr 表 walk), 与
// cmd/snmpcheck 同一口径 —— 真机锐捷交换机已验证该口径(标量 8/8, ifTable 113 行)。
package monitor

import (
	"context"
	"strconv"
	"strings"
	"time"

	"yugsight/internal/snmp"
)

const (
	defaultTimeout  = 3 * time.Second
	defaultInterval = 60 // 秒
)

// EffectiveInterval 配置间隔钳制(防用户写 0/负数/过小值打爆设备)。
func EffectiveInterval(sec int) time.Duration {
	if sec < 5 {
		return time.Duration(defaultInterval) * time.Second
	}
	return time.Duration(sec) * time.Second
}

// CollectTarget 对一个目标跑一轮完整采集。
// 单项 OID 失败只记该项(snmp.Collect 的降级语义), 整轮不中断。
// 设备不可达/超时时所有标量带同一错误, 据首错给出人话。
func CollectTarget(ctx context.Context, t Target) *Sample {
	timeout := time.Duration(t.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	// 口令在配置里是密文(secrets.go), 采集前解密 —— 解密失败返回空串,
	// v3 会因"口令缺失"报明确错误, 而不是把 "enc:xxx" 当口令发去鉴权。
	key := SecretKey()
	community := DecryptSecret(key, t.Community)
	c := snmp.NewClient(t.Addr, community, timeout)
	if strings.TrimSpace(t.User) != "" {
		c.V3 = &snmp.V3Config{
			User:      t.User,
			AuthProto: t.AuthProto,
			AuthPass:  DecryptSecret(key, t.AuthPass),
			PrivProto: t.PrivProto,
			PrivPass:  DecryptSecret(key, t.PrivPass),
			Context:   t.Context,
		}
	}
	rep := snmp.Collect(ctx, c)

	now := time.Now()
	s := &Sample{
		ID:        t.ID + "@" + strconv.FormatInt(now.UnixMilli(), 10),
		TargetID:  t.ID,
		Target:    t.Name,
		At:        now,
		ElapsedMs: rep.Elapsed.Milliseconds(),
	}

	// 标量按 Name 抽取(顺序与 snmp.Scalars 一致, 逐个判断)
	var firstErr error
	for _, sr := range rep.Scalars {
		if sr.Err != nil && firstErr == nil {
			firstErr = sr.Err
		}
		switch sr.Metric.Name {
		case "sysDescr":
			s.SysDescr = sr.Text
		case "sysName":
			s.SysName = sr.Text
		case "sysUpTime":
			// 单位是百分秒(十分之一秒)
			s.UptimeSec, _ = strconv.ParseInt(sr.Text, 10, 64)
			s.UptimeSec /= 100
		case "ifNumber":
			s.IfNumber, _ = strconv.ParseInt(sr.Text, 10, 64)
		}
	}

	// 各表抽取(表顺序: ifTable / hrProcessorTable / hrStorageTable / hrSWRunTable)
	for _, tr := range rep.Tables {
		switch tr.Table.Name {
		case "ifTable":
			// 行聚成接口样本(只取关注列, 列缺失的接口跳过)
			for _, row := range tr.Rows {
				is := IfaceSample{
					Index: row.Index,
					Name:  row.Cells["ifDescr"],
				}
				is.Speed, _ = strconv.ParseInt(row.Cells["ifSpeed"], 10, 64)
				is.Oper, _ = strconv.Atoi(row.Cells["ifOperStatus"])
				is.In, _ = strconv.ParseInt(row.Cells["ifInOctets"], 10, 64)
				is.Out, _ = strconv.ParseInt(row.Cells["ifOutOctets"], 10, 64)
				if is.Name == "" {
					continue
				}
				s.Ifaces = append(s.Ifaces, is)
			}
		case "hrProcessorTable":
			// 取第一条 CPU(多核设备各条相同, 取首条足够展示)
			for _, row := range tr.Rows {
				if v, err := strconv.ParseInt(row.Cells["hrProcessorLoad"], 10, 64); err == nil {
					s.CpuLoad = v
					break
				}
			}
		case "hrStorageTable":
			// 找 RAM 条目: 描述里带 ram/memory(不猜, 无 RAM 匹配就留 0=不支持,
			// 拿磁盘当内存是危险的错误展示)。units 系数乘进去才是字节。
			for _, row := range tr.Rows {
				desc := strings.ToLower(row.Cells["hrStorageDescr"])
				if !strings.Contains(desc, "ram") && !strings.Contains(desc, "memory") {
					continue
				}
				units, _ := strconv.ParseInt(row.Cells["hrStorageUnits"], 10, 64)
				if units <= 0 {
					units = 1
				}
				if size, err := strconv.ParseInt(row.Cells["hrStorageSize"], 10, 64); err == nil {
					s.MemTotal = size * units
					s.MemUsed, _ = strconv.ParseInt(row.Cells["hrStorageUsed"], 10, 64)
					s.MemUsed *= units
					break
				}
			}
		}
	}

	if rep.OKCount > 0 {
		s.OK = true
	} else {
		// 一个标量都没回: 设备哑了或社区串错了, 把首错给人看
		if firstErr != nil {
			s.Err = firstErr.Error()
		} else {
			s.Err = "设备无响应"
		}
	}
	return s
}
