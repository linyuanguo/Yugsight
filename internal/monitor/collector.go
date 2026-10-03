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
				// 2026-09-27: 设备 MAC 取首个 up 接口的物理地址(管理口最代表设备
				// 身份)。全零 MAC(00:00:00:00:00:00, 逻辑接口常见)视为无值跳过;
				// 设备不支持该 OID 时整列为空, s.MAC 留空(页面显示 '-')。
				if s.MAC == "" && is.Oper == 1 {
					if m := strings.TrimSpace(row.Cells["ifPhysAddress"]); m != "" && m != "00:00:00:00:00:00" {
						s.MAC = m
					}
				}
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

	// 带宽修正(接口行聚好之后): ifSpeed 是 Gauge32, 上限 4294967295 bps
	// ≈ 4.29 Gb/s, 万兆及以上接口必然溢出(锐捷 S7805C 实测: TenGigabitEthernet
	// 显示 4.3 Gb/s)。IF-MIB 的 ifHighSpeed(单位 Mbps)是正确来源, 取到就覆盖。
	fixIfSpeedOverflow(ctx, c, s.Ifaces)

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

// ifHighSpeedOID IF-MIB 接口带宽(单位 Mbps, 64 位口径, 不受 32 位上限约束)。
const ifHighSpeedOID = "1.3.6.1.2.1.31.1.1.1.15"

// FixIfSpeedOverflow 是 fixIfSpeedOverflow 的导出包装(2026-10-02 需求 1:
// 主机 SNMP 采集 collect 包也要修万兆口带宽溢出, 与交换机同一口径)。
func FixIfSpeedOverflow(ctx context.Context, c *snmp.Client, ifaces []IfaceSample) {
	fixIfSpeedOverflow(ctx, c, ifaces)
}

// fixIfSpeedOverflow 用 ifHighSpeed 覆盖 32 位溢出的 ifSpeed。
//
// 为什么不整表 walk ifXTable: 那会把 ifXTable 的几十个列全走一遍(113 口交换机
// 采集耗时从 ~8s 涨到 20s+), 而我们只要一列。这里按接口索引**分批 GET**(40 个
// 一批, 113 口 = 3 次往返), 拿不到(老设备不支持/超时)就保留 ifSpeed —— 降级,
// 不影响整轮采集, 也不编造数值。
func fixIfSpeedOverflow(ctx context.Context, c *snmp.Client, ifaces []IfaceSample) {
	if len(ifaces) == 0 {
		return
	}
	const chunk = 40
	for i := 0; i < len(ifaces); i += chunk {
		end := i + chunk
		if end > len(ifaces) {
			end = len(ifaces)
		}
		oids := make([]string, 0, chunk)
		pos := make([]int, 0, chunk)
		for j := i; j < end; j++ {
			if strings.TrimSpace(ifaces[j].Index) == "" {
				continue
			}
			oids = append(oids, ifHighSpeedOID+"."+ifaces[j].Index)
			pos = append(pos, j)
		}
		if len(oids) == 0 {
			continue
		}
		vbs, _, err := c.Get(ctx, oids...)
		if err != nil {
			return // 不支持/不可达: 整段放弃, 保留 ifSpeed
		}
		byOID := make(map[string]string, len(vbs))
		for _, v := range vbs {
			byOID[v.OID] = v.Value
		}
		for k, j := range pos {
			txt, ok := byOID[oids[k]]
			if !ok {
				continue
			}
			mbps, perr := strconv.ParseInt(txt, 10, 64)
			if perr != nil || mbps <= 0 {
				continue // 0 = 设备未上报该值, 保留 ifSpeed
			}
			ifaces[j].Speed = mbps * 1000000
		}
	}
}
