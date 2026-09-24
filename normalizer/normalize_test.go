package normalizer

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yugsight/models"
)

var (
	tA = time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	tB = time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)
	tC = time.Date(2026, 9, 16, 9, 0, 0, 0, time.UTC)
)

// ===== 多源合并 =====

const nmapSampleMerge = `{
  "hosts": [{
    "address": "10.0.0.1",
    "mac-address": "aa-bb-cc-dd-ee-ff",
    "hostnames": [{"name": "srv1"}],
    "os": [{"name": "Linux 5.x"}],
    "ports": [
      {"portid": 8080, "protocol": "tcp", "state": {"state": "open"},
       "service": {"name": "http", "product": "tomcat", "version": "9.0.50", "extrainfo": "Server: Apache Tomcat"},
       "vulns": [{"id": "CVE-2021-44228", "script-id": "log4j2", "state": "vulnerable",
                  "severity": {"type": "CVSSv3", "value": "9.8"}, "description": "nmap desc"}]}
    ]
  }]
}`

const probeSampleMerge = `{
  "nodeId": "probe-01",
  "scanId": "scan-1",
  "time": "2026-09-16T09:00:00Z",
  "assets": [{"ip": "10.0.0.1", "ports": [22, 8080], "tags": ["server"]}],
  "vulns": [{"ip": "10.0.0.1", "port": 8080, "protocol": "http", "cve": "CVE-2021-44228",
             "title": "Log4j2 RCE", "severity": "high", "evidence": "probe hit",
             "request": "GET /x HTTP/1.1", "response": "resp-probe",
             "confidence": 90, "pcapFile": "/pcap/p1.pcap", "foundAt": "2026-09-16T09:00:00Z"}]
}`

func TestNormalizeMultiSourceMerge(t *testing.T) {
	nb := FromNuclei("10.0.0.1", []NucleiResult{
		{Host: "10.0.0.1", Port: 8080, Scheme: "http", TemplateID: "tpl-a",
			CVE: "cve-2021-44228", Title: "Log4j2 RCE", Severity: "critical",
			RawResponse: "resp-nuclei-1", FoundAt: tA},
		{Host: "10.0.0.1", Port: 8080, Scheme: "http", TemplateID: "tpl-b",
			CVE: "CVE-2021-44228", Title: "Log4j2 RCE", Severity: "high",
			RawResponse: "resp-nuclei-2", FoundAt: tC},
	})
	nb2, err := FromNmapJSON([]byte(nmapSampleMerge))
	if err != nil {
		t.Fatalf("nmap 解析失败: %v", err)
	}
	pb, err := FromProbeJSON([]byte(probeSampleMerge))
	if err != nil {
		t.Fatalf("probe 解析失败: %v", err)
	}
	psb := FromPortScan([]PortScanHost{{
		IP:  "10.0.0.1",
		MAC: "AA-BB-CC-DD-EE-FF",
		Ports: []OpenPort{
			{Port: 22, Protocol: "tcp", Service: "ssh", Version: "8.2", Banner: "OpenSSH 8.2"},
			{Port: 8080, Protocol: "tcp", Service: "http", Version: "9.0.50"},
		},
		Tags:    []string{"linux"},
		FoundAt: tA,
	}})

	res := NormalizeWithOptions(Options{Now: tC}, psb, nb, nb2, pb)

	// 1) 资产合并为 1
	if len(res.Assets) != 1 {
		t.Fatalf("应合并为 1 个资产, 实际 %d", len(res.Assets))
	}
	a := res.Assets[0]
	if a.IP != "10.0.0.1" {
		t.Errorf("资产 IP 错误: %q", a.IP)
	}
	if a.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MAC 应归一化为冒号格式: %q", a.MAC)
	}
	if a.Hostname != "srv1" || a.OS != "Linux 5.x" {
		t.Errorf("hostname/OS 缺失: %+v", a)
	}
	for _, p := range []int{22, 8080} {
		if !containsInt(a.Ports, p) {
			t.Errorf("端口 %d 缺失: %v", p, a.Ports)
		}
	}
	if a.Service == "" || a.Version == "" {
		t.Errorf("主服务/版本缺失: %+v", a)
	}
	for _, tag := range []string{"server", "linux"} {
		if !containsStr(a.Tags, tag) {
			t.Errorf("标签 %q 缺失: %v", tag, a.Tags)
		}
	}

	// 2) 同资产+同 CVE 合并为 1 条, 证据全保留
	if len(res.Vulns) != 1 {
		t.Fatalf("应为 1 条漏洞, 实际 %d", len(res.Vulns))
	}
	v := res.Vulns[0]
	if v.AssetIP != "10.0.0.1" || v.CVE != "CVE-2021-44228" {
		t.Fatalf("合并后漏洞错误: %+v", v)
	}
	for _, s := range []string{SourceNuclei, SourceNmap, SourceProbe, SourcePortScan} {
		if s != SourcePortScan && !containsStr(v.Sources, s) {
			t.Errorf("Sources 应含 %s: %v", s, v.Sources)
		}
	}
	if len(v.EvidenceRecords) != 3 {
		t.Errorf("应保留全部 3 条证据记录(nuclei×2 + probe×1), 实际 %d", len(v.EvidenceRecords))
	}
	for _, want := range []string{"resp-nuclei-1", "resp-nuclei-2", "resp-probe"} {
		found := false
		for _, er := range v.EvidenceRecords {
			if strings.Contains(er.Response, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("原始响应 %q 缺失", want)
		}
	}
	if v.Severity != "critical" {
		t.Errorf("等级应取最高: %q", v.Severity)
	}
	if v.CVSS != 9.8 {
		t.Errorf("CVSS 应取最高: %v", v.CVSS)
	}
	if v.Confidence != 90 {
		t.Errorf("置信度应取最高: %d", v.Confidence)
	}
	if !v.FoundAt.Equal(tA) {
		t.Errorf("应保留最早发现时间: %v", v.FoundAt)
	}
	if v.PcapFile != "/pcap/p1.pcap" {
		t.Errorf("PCAP 路径缺失: %q", v.PcapFile)
	}

	// 3) 无基线 → 全部 new
	if v.Status != models.VulnStatusNew {
		t.Errorf("无基线应全部 new: %q", v.Status)
	}
	if res.Stats.NewCount != 1 || res.Stats.AssetCount != 1 || res.Stats.VulnCount != 1 {
		t.Errorf("统计错误: %+v", res.Stats)
	}
}

func TestNormalizeDifferentCVEKeepBoth(t *testing.T) {
	res := Normalize(&RawBatch{
		Source: SourceNuclei,
		Vulns: []RawVuln{
			{AssetIP: "10.0.0.1", CVE: "CVE-2021-44228", Port: 8080, Title: "A", Severity: "high"},
			{AssetIP: "10.0.0.1", CVE: "CVE-2021-45046", Port: 8080, Title: "B", Severity: "medium"},
			// 无 CVE: 同资产同端口同标题才合并
			{AssetIP: "10.0.0.1", Port: 8080, Protocol: "http", Title: "XSS", Severity: "medium"},
			{AssetIP: "10.0.0.1", Port: 8080, Protocol: "http", Title: "XSS", Severity: "low"},
			{AssetIP: "10.0.0.1", Port: 443, Protocol: "http", Title: "XSS", Severity: "medium"},
		},
	})
	if len(res.Vulns) != 4 {
		t.Fatalf("应保留 4 条漏洞, 实际 %d", len(res.Vulns))
	}
}

// ===== 状态标记 =====

func TestNormalizeStatusWithBaseline(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// 上一轮: 漏洞 A + B
	prev := Normalize(&RawBatch{
		Source: SourceNuclei,
		Vulns: []RawVuln{
			{AssetIP: "10.0.0.1", CVE: "CVE-1000-0001", Port: 80, Title: "A", Severity: "high", FoundAt: old},
			{AssetIP: "10.0.0.1", CVE: "CVE-1000-0002", Port: 80, Title: "B", Severity: "medium", FoundAt: old},
		},
	})
	base := BaselineFromResult(prev)
	if len(base.Vulns) != 2 {
		t.Fatalf("基线应为 2 条: %d", len(base.Vulns))
	}

	// 本轮: A(重复) + C(新), B 未命中(历史已修复)
	cur := NormalizeWithOptions(Options{Baseline: base, Now: tC}, &RawBatch{
		Source: SourceNuclei,
		Vulns: []RawVuln{
			{AssetIP: "10.0.0.1", CVE: "CVE-1000-0001", Port: 80, Title: "A", Severity: "high", FoundAt: tC},
			{AssetIP: "10.0.0.1", CVE: "CVE-1000-0003", Port: 80, Title: "C", Severity: "low", FoundAt: tC},
		},
	})

	byCVE := map[string]*models.Vuln{}
	for _, v := range cur.Vulns {
		byCVE[v.CVE] = v
	}
	if v := byCVE["CVE-1000-0001"]; v == nil || v.Status != models.VulnStatusDuplicate {
		t.Errorf("A 应为 duplicate: %+v", v)
	} else if !v.FoundAt.Equal(old) {
		t.Errorf("重复漏洞应继承最早发现时间: %v", v.FoundAt)
	}
	if v := byCVE["CVE-1000-0003"]; v == nil || v.Status != models.VulnStatusNew {
		t.Errorf("C 应为 new: %+v", v)
	}
	if len(cur.Fixed) != 1 {
		t.Fatalf("应有 1 条历史已修复, 实际 %d", len(cur.Fixed))
	}
	f := cur.Fixed[0]
	if f.CVE != "CVE-1000-0002" || f.Status != models.VulnStatusFixed {
		t.Errorf("fixed 条目错误: %+v", f)
	}
	if f.FixedAt == nil || !f.FixedAt.Equal(tC) {
		t.Errorf("FixedAt 应为当前时间: %v", f.FixedAt)
	}
	if cur.Stats.NewCount != 1 || cur.Stats.DuplicateCount != 1 || cur.Stats.FixedCount != 1 {
		t.Errorf("统计错误: %+v", cur.Stats)
	}
	// 二次基线: fixed 不进入下一轮基线
	base2 := BaselineFromResult(cur)
	if len(base2.Vulns) != 2 {
		t.Errorf("二次基线应只含本轮命中 2 条: %d", len(base2.Vulns))
	}
}

// ===== 基线读写 =====

func TestBaselineSaveLoad(t *testing.T) {
	prev := Normalize(&RawBatch{Source: SourceNuclei, Vulns: []RawVuln{
		{AssetIP: "10.0.0.1", CVE: "CVE-1000-0001", Port: 80, Title: "A", Severity: "high", FoundAt: tA},
	}})
	path := filepath.Join(t.TempDir(), "sub", "baseline.json")
	if err := SaveBaseline(BaselineFromResult(prev), path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if got == nil || len(got.Vulns) != 1 || got.Vulns[0].CVE != "CVE-1000-0001" {
		t.Fatalf("基线内容错误: %+v", got)
	}
	// 文件不存在: 无基线, 无错误
	none, err := LoadBaseline(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || none != nil {
		t.Errorf("不存在的文件应返回 (nil, nil), 实际 %v %v", none, err)
	}
	// 文件损坏: 降级为无基线, 无错误
	badPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badPath, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad, err := LoadBaseline(badPath)
	if err != nil || bad != nil {
		t.Errorf("损坏文件应降级为无基线, 实际 %v %v", bad, err)
	}
}

// ===== 存储与查询 =====

func TestStoreAndQuery(t *testing.T) {
	s := NewStore()
	if s.Get() != nil {
		t.Fatal("初始应为空")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := Normalize(&RawBatch{Source: SourceNuclei, Vulns: []RawVuln{
				{AssetIP: "1.1.1.1", CVE: "CVE-0000-0001", Port: 80, Title: "X", Severity: "high"},
			}})
			s.Set(r)
			_ = s.Get()
		}()
	}
	wg.Wait()
	r := s.Get()
	if r == nil {
		t.Fatal("存储应有结果")
	}
	if a := r.AssetByIP(" 1.1.1.1 "); a == nil {
		t.Error("AssetByIP 应查到资产")
	}
	if vs := r.VulnsByAsset("1.1.1.1"); len(vs) != 1 {
		t.Errorf("VulnsByAsset 错误: %d", len(vs))
	}
	if vs := r.VulnsBySeverity("HIGH"); len(vs) != 1 {
		t.Errorf("VulnsBySeverity 错误: %d", len(vs))
	}
	if vs := r.VulnsByStatus(models.VulnStatusNew); len(vs) != 1 {
		t.Errorf("VulnsByStatus 错误: %d", len(vs))
	}
	if vs := r.VulnsByCVE("cve-0000-0001"); len(vs) != 1 {
		t.Errorf("VulnsByCVE 错误: %d", len(vs))
	}
	data, err := r.JSON()
	if err != nil || len(data) == 0 {
		t.Errorf("JSON 序列化失败: %v", err)
	}
}

func TestNormalizeEmpty(t *testing.T) {
	res := Normalize()
	if len(res.Assets) != 0 || len(res.Vulns) != 0 || len(res.Fixed) != 0 {
		t.Errorf("空输入应产出空结果: %+v", res)
	}
	res2 := Normalize(nil, &RawBatch{})
	if len(res2.Vulns) != 0 {
		t.Errorf("nil 批次应被忽略: %+v", res2)
	}
	if len(res.Sources) != 0 {
		t.Errorf("空输入来源应为空: %v", res.Sources)
	}
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
