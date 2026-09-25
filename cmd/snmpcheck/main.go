// snmpcheck SNMPv2c 连通性与 MIB 库(OID 表)实测工具。
//
// 用途:
//  1. 对目标设备跑内置 OID 库, 逐项给出 支持/不支持/不可达 ——
//     作为 snmp/mib.go 固化 OID 的依据与接入监控前的连通自检;
//  2. -walk 任意子树自由探索(如厂商私有 MIB 候选);
//  3. -extra 探测额外标量 OID, 命中后可固化进 snmp.Scalars。
//
// 示例:
//   go run ./cmd/snmpcheck -target 172.16.199.1 -community public
//   go run ./cmd/snmpcheck -target 172.16.199.1 -walk 1.3.6.1.4.1.20111 -maxinst 60
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"yugsight/internal/snmp"
)

func main() {
	target := flag.String("target", "", "目标 host[:port](缺省端口 161)")
	community := flag.String("community", "public", "SNMPv2c community")
	timeout := flag.Duration("timeout", 3*time.Second, "单请求超时")
	extra := flag.String("extra", "", "追加标量 OID, 逗号分隔")
	walkBase := flag.String("walk", "", "自由探索: 从该 OID walk")
	maxInst := flag.Int("maxinst", 100, "walk 最多打印实例数")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "用法: snmpcheck -target <host[:port]> [-community public] [-timeout 3s] [-extra oid,oid] [-walk oid [-maxinst 100]]")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	c := snmp.NewClient(*target, *community, *timeout)

	if *walkBase != "" {
		runWalk(ctx, c, *walkBase, *maxInst)
		return
	}

	var extras []snmp.Metric
	for _, o := range strings.Split(*extra, ",") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		extras = append(extras, snmp.Metric{OID: o, Name: "extra(" + o + ")", Label: "自定义探测", Cat: "other"})
	}
	printReport(snmp.Collect(ctx, c, extras...))
}

// runWalk 自由探索一个子树(不套 MIB 库语义, 打印全部实例)。
func runWalk(ctx context.Context, c *snmp.Client, base string, maxInst int) {
	t0 := time.Now()
	vbs, err := c.Walk(ctx, base, 50)
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk 失败: %v\n", err)
		os.Exit(1)
	}
	shown := 0
	for _, v := range vbs {
		if shown >= maxInst {
			break
		}
		fmt.Printf("%-50s %-12s %s\n", v.OID, v.Type, v.Value)
		shown++
	}
	if n := len(vbs) - shown; n > 0 {
		fmt.Printf("…(其余 %d 条省略)\n", n)
	}
	fmt.Printf("\n共 %d 个实例, 耗时 %s\n", len(vbs), time.Since(t0).Round(time.Millisecond))
}

func printReport(r *snmp.Report) {
	fmt.Printf("目标 %s  community=%s  耗时 %s\n\n", r.Target, r.Community, r.Elapsed.Round(time.Millisecond))

	fmt.Println("== 标量 OID ==")
	for _, s := range r.Scalars {
		if s.OK {
			fmt.Printf("  [OK]   %-9s %-16s %-26s %s\n", s.Metric.Cat, s.Metric.Name, s.Metric.OID, s.Text)
		} else {
			reason := "无响应"
			if s.Err != nil {
				reason = s.Err.Error()
			}
			fmt.Printf("  [FAIL] %-9s %-16s %-26s %s\n", s.Metric.Cat, s.Metric.Name, s.Metric.OID, reason)
		}
	}

	for _, t := range r.Tables {
		fmt.Printf("\n== %s (base %s) ==\n", t.Table.Label, t.Table.Base)
		if !t.OK {
			reason := "无数据"
			if t.Err != nil {
				reason = t.Err.Error()
			}
			fmt.Printf("  未取到行: %s\n", reason)
			continue
		}
		const maxShow = 30
		for i, row := range t.Rows {
			if i == maxShow {
				fmt.Printf("  …(其余 %d 行省略)\n", len(t.Rows)-maxShow)
				break
			}
			var parts []string
			for _, name := range t.Table.SubOrder {
				if v, ok := row.Cells[name]; ok {
					parts = append(parts, name+"="+v)
				}
			}
			fmt.Printf("  行 %s: %s\n", row.Index, strings.Join(parts, " | "))
		}
	}

	okTables := 0
	for _, t := range r.Tables {
		if t.OK {
			okTables++
		}
	}
	fmt.Printf("\n== 汇总 ==\n  标量支持 %d/%d, 表有数据 %d/%d\n", r.OKCount, r.TotalCount, okTables, len(r.Tables))
}
