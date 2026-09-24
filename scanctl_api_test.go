package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"yugsight/scanner"
)

// TestScanCtlAPI 扫描管控 API 冒烟: 状态 / 白名单增删查 / 误报标记与删除。
// (测试二进制的 exe 同目录为临时目录, 落盘文件不会污染真实部署目录)
func TestScanCtlAPI(t *testing.T) {
	// 状态: 含四级打分模型
	w := httptest.NewRecorder()
	handleCtlStatus(w, httptest.NewRequest("GET", "/api/vuln/control/status", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"tiers"`) {
		t.Fatalf("status code=%d body=%.200s", w.Code, w.Body.String())
	}

	// 白名单: 非法类型 -> 400
	w = httptest.NewRecorder()
	handleWhitelistAdd(w, httptest.NewRequest("POST", "/api/vuln/whitelist/add",
		strings.NewReader(`{"type":"weird","match":"x"}`)))
	if w.Code != 400 {
		t.Fatalf("whitelist add 非法类型 code=%d", w.Code)
	}

	// 白名单: 添加 IP 段 + 列表校验
	w = httptest.NewRecorder()
	handleWhitelistAdd(w, httptest.NewRequest("POST", "/api/vuln/whitelist/add",
		strings.NewReader(`{"type":"cidr","match":"172.20.0.0/16","reason":"smoke"}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("whitelist add code=%d body=%.200s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	handleWhitelistList(w, httptest.NewRequest("GET", "/api/vuln/whitelist", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "172.20.0.0/16") {
		t.Fatalf("whitelist list code=%d body=%.200s", w.Code, w.Body.String())
	}

	// 误报: 标记 + 列表
	w = httptest.NewRecorder()
	handleFPSMark(w, httptest.NewRequest("POST", "/api/vuln/fps/mark",
		strings.NewReader(`{"assetIp":"10.9.9.9","cve":"cve-2020-0001","note":"smoke"}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("fps mark code=%d body=%.200s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	handleFPSList(w, httptest.NewRequest("GET", "/api/vuln/fps", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "CVE-2020-0001") {
		t.Fatalf("fps list code=%d body=%.200s", w.Code, w.Body.String())
	}

	// 清理: 从列表取 ID 后删除, 保持测试隔离
	var wl struct {
		Entries []struct{ ID string `json:"id"` } `json:"entries"`
	}
	_ = json.Unmarshal((func() []byte {
		w := httptest.NewRecorder()
		handleWhitelistList(w, httptest.NewRequest("GET", "/api/vuln/whitelist", nil))
		return w.Body.Bytes()
	})(), &wl)
	var fp struct {
		Rules []struct{ ID string `json:"id"` } `json:"rules"`
	}
	_ = json.Unmarshal((func() []byte {
		w := httptest.NewRecorder()
		handleFPSList(w, httptest.NewRequest("GET", "/api/vuln/fps", nil))
		return w.Body.Bytes()
	})(), &fp)
	for _, e := range wl.Entries {
		if !strings.Contains(e.ID, "172.20.0.0/16") {
			continue
		}
		w = httptest.NewRecorder()
		handleWhitelistRemove(w, httptest.NewRequest("POST", "/api/vuln/whitelist/remove",
			strings.NewReader(`{"id":"`+e.ID+`"}`)))
		if w.Code != 200 {
			t.Fatalf("whitelist remove code=%d", w.Code)
		}
	}
	for _, r := range fp.Rules {
		if !strings.Contains(r.ID, "fps-") {
			continue
		}
		w = httptest.NewRecorder()
		handleFPSRemove(w, httptest.NewRequest("POST", "/api/vuln/fps/remove",
			strings.NewReader(`{"id":"`+r.ID+`"}`)))
		if w.Code != 200 {
			t.Fatalf("fps remove code=%d", w.Code)
		}
	}
}

// TestCtlStatusScoringTiers 打分模型契约: /api/vuln/control/status 必须回带四级区间。
// 扫描控制页按 {tier,name,range,remark} 直接渲染说明表, 服务端字段改名/减级时前端有
// 静态兜底 —— 页面看着正常却是错的(静默失效), 所以这里钉死形状。
func TestCtlStatusScoringTiers(t *testing.T) {
	w := httptest.NewRecorder()
	handleCtlStatus(w, httptest.NewRequest("GET", "/api/vuln/control/status", nil))
	if w.Code != 200 {
		t.Fatalf("status code=%d", w.Code)
	}
	var st struct {
		Scoring struct {
			Tiers []struct {
				Tier   string `json:"tier"`
				Name   string `json:"name"`
				Range  string `json:"range"`
				Remark string `json:"remark"`
			} `json:"tiers"`
		} `json:"scoring"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("status 解析失败: %v", err)
	}
	want := []string{"100", "70-99", "40-69", "0-39"}
	if len(st.Scoring.Tiers) != len(want) {
		t.Fatalf("tiers 数量=%d 期望 %d", len(st.Scoring.Tiers), len(want))
	}
	for i, r := range want {
		got := st.Scoring.Tiers[i]
		if got.Range != r || got.Tier == "" || got.Name == "" || got.Remark == "" {
			t.Fatalf("tier[%d] = %+v 期望区间 %s 且字段非空", i, got, r)
		}
	}
}

// TestFindingKeyInfo finding 事件键提取(内置规则从标题取 CVE / Nuclei 自带字段)
func TestFindingKeyInfo(t *testing.T) {
	title, cve, port := findingKeyInfo(scanner.Finding{Severity: "high", Title: "X CVE-2021-44228 Y"})
	if title == "" || cve != "CVE-2021-44228" || port != 0 {
		t.Fatalf("内置规则提取错误: %s %s %d", title, cve, port)
	}
	title, cve, port = findingKeyInfo(scanner.NucleiFinding{
		Finding: scanner.Finding{Title: "t"}, CVE: "CVE-1", Port: 8080, Host: "10.0.0.1",
	})
	if title != "t" || cve != "CVE-1" || port != 8080 {
		t.Fatalf("Nuclei 提取错误: %s %s %d", title, cve, port)
	}
}

// TestWithFPFlag finding 事件附加误报标记字段
func TestWithFPFlag(t *testing.T) {
	m := withFPFlag(scanner.Finding{Severity: "high", Title: "t"}, "备注")
	b, _ := json.Marshal(m)
	s := string(b)
	if !strings.Contains(s, `"falsePositive":true`) || !strings.Contains(s, `"fpNote":"备注"`) || !strings.Contains(s, `"title":"t"`) {
		t.Fatalf("附加字段错误: %s", s)
	}
}
