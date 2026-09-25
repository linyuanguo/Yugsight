// mib.go 固定 OID 表("MIB 库")与采集驱动。
//
// 为什么不解析 MIB: 完整 MIB 解析器要处理 SMI 语法 + 依赖树(几百 KB
// MIB 文件 + 数百行代码), 与"单二进制纯标准库"冲突。实践上监控场景
// 80% 只需固定一批公共 OID, 故用三层设计:
//  1. 内置常用 OID 表(本文件) —— 系统/接口/CPU/内存/进程;
//  2. 调用方扩展 —— Collect 的 extra 参数可追加自定义标量
//     (如厂商私有 OID 候选, 用 cmd/snmpcheck -extra 实测后再固化);
//  3. 采集全程降级 —— 任一 OID/表失败只记该项, 不中断整体。
//
// 真机实测结论(2026-09-20, cmd/snmpcheck 打 172.16.199.1 锐捷 S7805C
// 核心交换机, RGOS): 标量 8/8 全支持(sysUpTime 为前导 0x00 填充的 5 字节
// TimeTicks, 解码须宽容); ifTable 113 行完整(与 ifNumber 一致, 含
// ifSpeed/ifOperStatus/流量计数); hr 三表(HOST-RESOURCES-MIB)交换机不
// 支持属预期 —— 保留在表中由实测说话, 服务器型设备大概率可用, 不猜测。
package snmp

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Metric 一个被采集的 OID 指标。
type Metric struct {
	OID    string // 点分数字串
	Name   string // 英文键(机器可读, 接入层/前端用)
	Label  string // 中文名(展示用)
	Cat    string // 分类: system/interface/cpu/memory/process/other
	Hidden bool   // 辅助列: 照常被采集进 Cells, 但不进 SubOrder(不出现在展示行)
}

// TableMib 一张 SNMP 表: 表基 OID + 关注的子列。
type TableMib struct {
	Base     string
	Name     string
	Label    string
	Cat      string
	SubOrder []string       // 行内列展示顺序(Metric.Name)
	Subs     map[int]Metric // 子列索引 → 指标(OID 必须 = Base+"."+子列)
}

// Scalars 标量 OID(GET 一次批量)。
var Scalars = []Metric{
	{OID: "1.3.6.1.2.1.1.1", Name: "sysDescr", Label: "系统描述", Cat: "system"},
	{OID: "1.3.6.1.2.1.1.2", Name: "sysObjectID", Label: "设备类型", Cat: "system"},
	{OID: "1.3.6.1.2.1.1.3", Name: "sysUpTime", Label: "开机时长(百分秒)", Cat: "system"},
	{OID: "1.3.6.1.2.1.1.4", Name: "sysContact", Label: "联系人", Cat: "system"},
	{OID: "1.3.6.1.2.1.1.5", Name: "sysName", Label: "设备名", Cat: "system"},
	{OID: "1.3.6.1.2.1.1.6", Name: "sysLocation", Label: "位置", Cat: "system"},
	{OID: "1.3.6.1.2.1.1.7", Name: "sysServices", Label: "服务层级", Cat: "system"},
	{OID: "1.3.6.1.2.1.2.1", Name: "ifNumber", Label: "接口总数", Cat: "interface"},
}

// Tables 表 OID(GETBULK walk)。ifTable 是交换机监控核心;
// hr 三表是服务器型 OID, 交换机支持与否交给真机实测。
var Tables = []TableMib{
	{
		Base: "1.3.6.1.2.1.2.2.1", Name: "ifTable", Label: "接口表", Cat: "interface",
		SubOrder: []string{"ifDescr", "ifType", "ifSpeed", "ifOperStatus", "ifInOctets", "ifOutOctets"},
		Subs: map[int]Metric{
			2:  {OID: "1.3.6.1.2.1.2.2.1.2", Name: "ifDescr", Label: "接口描述", Cat: "interface"},
			3:  {OID: "1.3.6.1.2.1.2.2.1.3", Name: "ifType", Label: "接口类型", Cat: "interface"},
			5:  {OID: "1.3.6.1.2.1.2.2.1.5", Name: "ifSpeed", Label: "带宽(bps)", Cat: "interface"},
			8:  {OID: "1.3.6.1.2.1.2.2.1.8", Name: "ifOperStatus", Label: "链路状态", Cat: "interface"},
			10: {OID: "1.3.6.1.2.1.2.2.1.10", Name: "ifInOctets", Label: "入流量(累计)", Cat: "interface"},
			16: {OID: "1.3.6.1.2.1.2.2.1.16", Name: "ifOutOctets", Label: "出流量(累计)", Cat: "interface"},
		},
	},
	{
		Base: "1.3.6.1.2.1.25.3.3.1", Name: "hrProcessorTable", Label: "CPU 负载表", Cat: "cpu",
		SubOrder: []string{"hrProcessorLoad", "hrProcessorLabel"},
		Subs: map[int]Metric{
			2: {OID: "1.3.6.1.2.1.25.3.3.1.2", Name: "hrProcessorLoad", Label: "CPU 占用%", Cat: "cpu"},
			3: {OID: "1.3.6.1.2.1.25.3.3.1.3", Name: "hrProcessorLabel", Label: "CPU 描述", Cat: "cpu"},
		},
	},
	{
		Base: "1.3.6.1.2.1.25.2.3.1", Name: "hrStorageTable", Label: "存储表(内存/磁盘)", Cat: "memory",
		SubOrder: []string{"hrStorageDescr", "hrStorageSize", "hrStorageUsed"},
		Subs: map[int]Metric{
			2: {OID: "1.3.6.1.2.1.25.2.3.1.2", Name: "hrStorageDescr", Label: "存储描述", Cat: "memory"},
			4: {OID: "1.3.6.1.2.1.25.2.3.1.4", Name: "hrStorageSize", Label: "总容量(×hrStorageUnits)", Cat: "memory"},
			5: {OID: "1.3.6.1.2.1.25.2.3.1.5", Name: "hrStorageUsed", Label: "已用", Cat: "memory"},
			// hrStorageUnits 是换算系数(每计数代表的字节数): Size/Used 都是"计数",
			// 不乘 units 得到的数字没有物理意义(常见 units=1024 或 32)。
			// Hidden=不进 SubOrder(展示行不需要), 但仍照常被 walk 采集进 Cells。
			6: {OID: "1.3.6.1.2.1.25.2.3.1.6", Name: "hrStorageUnits", Label: "存储单位(字节/计数)", Cat: "memory", Hidden: true},
		},
	},
	{
		Base: "1.3.6.1.2.1.25.5.1", Name: "hrSWRunTable", Label: "进程表", Cat: "process",
		SubOrder: []string{"hrSWRunName", "hrSWRunStatus"},
		Subs: map[int]Metric{
			1: {OID: "1.3.6.1.2.1.25.5.1.1", Name: "hrSWRunName", Label: "进程名", Cat: "process"},
			3: {OID: "1.3.6.1.2.1.25.5.1.3", Name: "hrSWRunStatus", Label: "进程状态", Cat: "process"},
		},
	},
}

// ScalarResult 单个标量 OID 的采集结果。
type ScalarResult struct {
	Metric Metric
	OK     bool
	Text   string // 人类可读值
	Err    error  // 失败原因(设备不支持/不可达/无响应)
}

// TableRow 表一行: 行索引(实例尾弧) + 列值。
type TableRow struct {
	Index string
	Cells map[string]string // Metric.Name → 文本值
}

// TableResult 一张表的采集结果。
type TableResult struct {
	Table TableMib
	OK    bool // 至少取到一行
	Rows  []TableRow
	Err   error
}

// Report 一次完整 MIB 库采集的报告。
type Report struct {
	Target     string
	Community  string
	Elapsed    time.Duration
	Scalars    []ScalarResult
	Tables     []TableResult
	OKCount    int // 成功标量数
	TotalCount int // 标量总数(含 extra)
}

// Collect 跑完整 MIB 库: 所有标量一次批量 GET + 每表一次 walk。
// extra 追加自定义标量(厂商私有 OID 候选探测)。单项失败只记该项。
func Collect(ctx context.Context, c *Client, extra ...Metric) *Report {
	t0 := time.Now()
	rep := &Report{Target: c.Addr, Community: c.Community}

	all := make([]Metric, 0, len(Scalars)+len(extra))
	all = append(all, Scalars...)
	all = append(all, extra...)
	// 标量 GET 必须发实例 OID(对象 OID + ".0"): 真机实测(锐捷 RGOS)证明裸列
	// OID 会被按 noSuchInstance 拒答(sysDescr 即此症状)。已以 .0 结尾的
	// (调用方手写实例 OID)原样保留, 避免双重后缀。
	insts := make([]string, 0, len(all))
	for _, m := range all {
		oid := m.OID
		if !strings.HasSuffix(oid, ".0") {
			oid += ".0"
		}
		insts = append(insts, oid)
	}
	vbs, _, err := c.Get(ctx, insts...)
	byOID := make(map[string]Varbind, len(vbs))
	if err == nil {
		for _, v := range vbs {
			byOID[v.OID] = v
		}
	}
	for i, m := range all {
		sr := ScalarResult{Metric: m}
		if v, ok := byOID[insts[i]]; ok {
			switch {
			case isNoSuchType(v.Type):
				sr.Err = errors.New("设备无此实例(" + v.Type + ")")
			case v.Type == "unknown":
				// hex 内容一并对运维可见: 各厂商设备怪癖 tag 排障需要
				sr.Err = errors.New("值类型无法解码(内容 " + v.Value + ")")
			default:
				sr.OK, sr.Text = true, v.Value
				rep.OKCount++
			}
		} else if err != nil {
			sr.Err = err // 设备不可达/超时/响应解析失败
		} else {
			sr.Err = errors.New("响应缺该 varbind")
		}
		rep.TotalCount++
		rep.Scalars = append(rep.Scalars, sr)
	}

	for _, t := range Tables {
		tr := TableResult{Table: t}
		vbs, werr := c.Walk(ctx, t.Base, 100)
		if werr != nil {
			tr.Err = werr
		} else {
			tr.Rows = groupRows(t, vbs)
			tr.OK = len(tr.Rows) > 0
		}
		rep.Tables = append(rep.Tables, tr)
	}

	rep.Elapsed = time.Since(t0)
	return rep
}

// groupRows 把 walk 结果(列优先的 varbind 流)聚成"行→列"。
// 表基后第一弧是子列索引, 尾部是行索引。
func groupRows(t TableMib, vbs []Varbind) []TableRow {
	baseArc, err := ParseOID(t.Base)
	if err != nil {
		return nil
	}
	rows := map[string]map[string]string{}
	for _, v := range vbs {
		if isNoSuchType(v.Type) || v.Type == "unknown" {
			continue
		}
		arc, perr := ParseOID(v.OID)
		if perr != nil || len(arc) <= len(baseArc) {
			continue
		}
		m, ok := t.Subs[arc[len(baseArc)]]
		if !ok {
			continue // 表内其它子列(未纳入关注集)忽略
		}
		idx := FormatOID(arc[len(baseArc)+1:])
		if rows[idx] == nil {
			rows[idx] = map[string]string{}
		}
		rows[idx][m.Name] = v.Value
	}
	out := make([]TableRow, 0, len(rows))
	for idx, cells := range rows {
		out = append(out, TableRow{Index: idx, Cells: cells})
	}
	// 行索引按数值排序(若全是数字); 字典序会把 10 排到 2 前。
	sort.Slice(out, func(i, j int) bool {
		a, ea := strconv.Atoi(out[i].Index)
		b, eb := strconv.Atoi(out[j].Index)
		if ea == nil && eb == nil {
			return a < b
		}
		return out[i].Index < out[j].Index
	})
	return out
}
