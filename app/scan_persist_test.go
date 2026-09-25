package main

import (
	"strings"
	"testing"

	"yugsight/internal/db"
	"yugsight/internal/models"
	"yugsight/internal/normalizer"
	"yugsight/internal/scanner"
)

// openTestDB 打开一个临时目录的库(不碰生产 ./data)。
func openTestDB(t *testing.T) *db.Database {
	t.Helper()
	d, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// TestScanSinkNormalize 收集器归一化契约:
// finding 自带来源(nuclei)要保留、无 host/port 时回落到扫描目标、
// 事件级误报标记要还原到归一化漏洞、同 IP 多端口资产要合并。
//
// 守的是什么: 大屏/漏洞页的 source 维度与误报徽标全靠这份映射,
// 一旦来源被统一覆盖或误报标记丢失, 页面不会报错只会"看起来没数据"。
func TestScanSinkNormalize(t *testing.T) {
	sink := newScanSink(scanReq{Type: "host"}, "10.0.0.5", 0)
	sink.observe("status", map[string]any{"msg": "非 finding 事件应被忽略"})
	sink.observe("finding", scanner.NewFinding("high", "Redis 未授权访问", "未设置口令", "设置 requirepass"))
	sink.observe("finding", map[string]any{
		"severity": "medium", "title": "组件可能存在已知漏洞", "detail": "nginx 1.18",
		"source": "nuclei", "host": "10.0.0.5", "port": 80, "cve": "CVE-2021-1234",
	})
	sink.observe("finding", map[string]any{
		"severity": "low", "title": "信息泄露", "detail": "d", "falsePositive": true, "fpNote": "已确认无害",
	})
	sink.addServiceAssets([]scanner.ServiceAsset{
		{IP: "10.0.0.5", Port: 6379, Product: "redis"},
		{IP: "10.0.0.5", Port: 80, Product: "nginx", Version: "1.18"},
	})

	res := sink.normalize()
	if res == nil {
		t.Fatal("有数据时归一化不应返回 nil")
	}
	if len(res.Vulns) != 3 {
		t.Fatalf("漏洞数=%d, want 3", len(res.Vulns))
	}
	byTitle := map[string]*models.Vuln{}
	for _, v := range res.Vulns {
		byTitle[v.Title] = v
	}
	redis := byTitle["Redis 未授权访问"]
	if redis == nil {
		t.Fatal("缺内置规则 finding")
	}
	if redis.AssetIP != "10.0.0.5" || redis.Severity != "high" {
		t.Errorf("内置 finding 字段错误: ip=%s sev=%s", redis.AssetIP, redis.Severity)
	}
	if redis.Source != "builtin" {
		t.Errorf("内置规则来源应为 builtin, 实为 %s", redis.Source)
	}
	if !strings.Contains(redis.Description, "修复建议") {
		t.Error("修复建议应并入描述(报告页要能看到处理建议)")
	}
	nuclei := byTitle["组件可能存在已知漏洞"]
	if nuclei == nil {
		t.Fatal("缺 nuclei finding")
	}
	if nuclei.Source != "nuclei" || nuclei.Port != 80 || nuclei.CVE != "CVE-2021-1234" {
		t.Errorf("nuclei finding 来源/端口/CVE 丢失: %+v", nuclei)
	}
	fp := byTitle["信息泄露"]
	if fp == nil {
		t.Fatal("缺误报 finding")
	}
	if !fp.FalsePositive || fp.FPNote != "已确认无害" {
		t.Errorf("误报标记未回填: %+v", fp)
	}
	if len(res.Assets) != 1 {
		t.Fatalf("同 IP 资产应合并为 1 条, 实为 %d", len(res.Assets))
	}
	if len(res.Assets[0].Ports) != 2 || res.Assets[0].Service != "redis" {
		t.Errorf("资产端口/服务错误: %+v", res.Assets[0])
	}
}

// TestPersistScanResultUpsert 落库幂等契约: 同一轮结果写两次不应产生第二条记录,
// 且重复发现要转为 duplicate 状态(大屏的"新增 vs 重复"口径依赖这个状态)。
func TestPersistScanResultUpsert(t *testing.T) {
	d := openTestDB(t)
	res := normalizer.Normalize(&normalizer.RawBatch{
		Source: "builtin",
		Assets: []normalizer.RawAsset{{IP: "10.0.0.9", Ports: []int{80}}},
		Vulns:  []normalizer.RawVuln{{AssetIP: "10.0.0.9", Port: 80, Title: "测试漏洞", Severity: "high"}},
	})
	a, v, f := persistScanResult(d, res)
	if a != 1 || v != 1 || f != 0 {
		t.Fatalf("首次落库 资产=%d 漏洞=%d 失败=%d, want 1/1/0", a, v, f)
	}
	if _, v, f = persistScanResult(d, res); v != 1 || f != 0 {
		t.Fatalf("二次落库 漏洞=%d 失败=%d, want 1/0", v, f)
	}
	assets, err := d.Assets().List()
	if err != nil || len(assets) != 1 {
		t.Fatalf("资产表应有 1 条: n=%d err=%v", len(assets), err)
	}
	vulns, err := d.Vulns().List()
	if err != nil || len(vulns) != 1 {
		t.Fatalf("漏洞表应有 1 条: n=%d err=%v", len(vulns), err)
	}
	if vulns[0].Status != models.VulnStatusDuplicate {
		t.Errorf("重复发现应标记 duplicate, 实为 %s", vulns[0].Status)
	}
}

// TestPersistScanResultNilGuards 落库守卫: 库为 nil / 已 Close 时不得 panic。
//
// 守的是什么: db.Close() 会把各 DAO 置 nil, 装箱进接口后 `== nil` 判不出来,
// 漏掉反射判空就是 nil 解引用崩溃(进程静默消失, recover 都拦不住)。
func TestPersistScanResultNilGuards(t *testing.T) {
	res := normalizer.Normalize(&normalizer.RawBatch{
		Source: "builtin",
		Assets: []normalizer.RawAsset{{IP: "10.0.0.9", Ports: []int{80}}},
		Vulns:  []normalizer.RawVuln{{AssetIP: "10.0.0.9", Port: 80, Title: "测试漏洞", Severity: "high"}},
	})
	if a, v, f := persistScanResult(nil, res); a+v+f != 0 {
		t.Errorf("库为 nil 时应静默跳过, 实为 %d/%d/%d", a, v, f)
	}
	d := openTestDB(t)
	if err := d.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if a, v, f := persistScanResult(d, res); a+v+f != 0 {
		t.Errorf("库已关闭时应静默跳过, 实为 %d/%d/%d", a, v, f)
	}
}
