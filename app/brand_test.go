// brand_test.go 品牌自定义(brand 节)与首次启动默认配置生成的用例。
//
// 覆盖三类风险:
//  1. brand 节缺失/损坏时回退默认品牌(原始项目名/版权) —— 升级兼容红线;
//  2. ensureSettingsDefaults 只生成不覆盖: 文件不存在时生成全节默认配置,
//     文件已存在时一个字节都不动 —— 覆盖用户配置是数据事故;
//  3. 品牌 API 权限边界: 仅 admin 可保存(operator/auditor 403), 保存后
//     立即生效(热路径, 无需重启)。
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ===== brand 节: 默认值与读取 =====

// TestLoadBrandDefaultWhenSectionMissing 节缺失 = 原始项目品牌(默认值)。
func TestLoadBrandDefaultWhenSectionMissing(t *testing.T) {
	withTempExeDir(t)
	b := loadBrand()
	if b.SystemName != originalName || b.Copyright != originalCopyright {
		t.Fatalf("brand 节缺失应回退原始项目品牌, 实际 %+v", b)
	}
}

// TestLoadBrandFromSection 节存在 = 覆盖默认值; 空白值按未配置处理(防"配了个空字符串"把品牌抹掉)。
func TestLoadBrandFromSection(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"brand":{"system_name":"XX企业安全","copyright":"Copyright © 2026 XX Corp"}}`)
	b := loadBrand()
	if b.SystemName != "XX企业安全" || b.Copyright != "Copyright © 2026 XX Corp" {
		t.Fatalf("应读到 brand 节值, 实际 %+v", b)
	}
	writeTestSettings(t, `{"brand":{"system_name":"   "}}`)
	b = loadBrand()
	if b.SystemName != originalName {
		t.Fatalf("空白 system_name 应按未配置处理(默认 %q), 实际 %q", originalName, b.SystemName)
	}
}

// ===== ensureSettingsDefaults: 首次启动自动生成完整默认配置 =====

// TestEnsureSettingsDefaultsGeneratesFullFile 文件不存在 → 生成含全部节
// (所有现有节 + brand)的完整默认配置。
func TestEnsureSettingsDefaultsGeneratesFullFile(t *testing.T) {
	withTempExeDir(t)
	p := settingsFilePath()
	if _, err := os.Stat(p); err == nil {
		t.Fatalf("测试前提不成立: %s 已存在", p)
	}
	ensureSettingsDefaults()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("settings.json 应被自动生成: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("生成的文件不是合法 JSON: %v", err)
	}
	// 核心要求: 所有现有节 + brand 节全部在场
	for _, sec := range []string{
		secEngine, secAI, secCapture, secUpdater, secProbe, secScheduler, secReport,
		secScreen, secDatabase, secAuth, secWhitelist, secAuthCheck, secTLS, secAudit,
		secMonitor, secDashboard, secGeoIP, secCollect, secPenta, secNVD, secArpProxy, secBrand,
	} {
		if _, ok := doc[sec]; !ok {
			t.Errorf("生成的 settings.json 缺少 %s 节", sec)
		}
	}
	// 默认值抽查(必须与"节缺失"行为等价, 否则等于改变默认运行行为):
	// brand = 原始项目品牌
	var brandSec brandConfig
	if err := json.Unmarshal(doc[secBrand], &brandSec); err != nil ||
		brandSec.SystemName != originalName || brandSec.Copyright != originalCopyright {
		t.Errorf("brand 节默认值不正确: %+v", brandSec)
	}
	// engine.enabled: *bool 缺失 = 启用, 显式 true 与缺失等价
	var engSec map[string]any
	if err := json.Unmarshal(doc[secEngine], &engSec); err == nil && engSec["enabled"] != true {
		t.Errorf("engine.enabled 默认应为 true(外部引擎是默认执行路径): %v", engSec["enabled"])
	}
	// penta: *bool 缺失 = 开启
	var pentaSec map[string]any
	if err := json.Unmarshal(doc[secPenta], &pentaSec); err == nil && pentaSec["enabled"] != true {
		t.Errorf("penta.enabled 默认应为 true(渗透工作台默认开): %v", pentaSec["enabled"])
	}
	// arpproxy.exclude: *bool 缺失 = 排除开启
	var arpSec map[string]any
	if err := json.Unmarshal(doc[secArpProxy], &arpSec); err == nil && arpSec["exclude"] != true {
		t.Errorf("arpproxy.exclude 默认应为 true: %v", arpSec["exclude"])
	}
}

// TestEnsureSettingsDefaultsNeverOverwrites 文件已存在(用户配置) → 绝不覆盖、绝不补节。
func TestEnsureSettingsDefaultsNeverOverwrites(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"engine":{"enabled":false}}`)
	p := settingsFilePath()
	data0, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("预置文件读取失败: %v", err)
	}
	ensureSettingsDefaults()
	data1, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("文件应仍存在: %v", err)
	}
	if string(data0) != string(data1) {
		t.Fatalf("文件已存在时内容必须一个字节都不动")
	}
	var doc map[string]json.RawMessage
	_ = json.Unmarshal(data1, &doc)
	if _, ok := doc[secBrand]; ok {
		t.Fatal("已有文件不能被追加生成的 brand 节")
	}
}

// TestEnsureSettingsDefaultsSkipsWhenLegacyMigrated 旧单文件触发迁移生成了
// settings.json → 不再叠加生成(迁移产物优先, 两种来源不冲突)。
func TestEnsureSettingsDefaultsSkipsWhenLegacyMigrated(t *testing.T) {
	withTempExeDir(t)
	p := settingsFilePath()
	// 放一个旧 engine.json(历史单文件, 生产实际落在 exe 同目录): loadSettings 会把它并入 settings.json
	legacy := filepath.Join(exeDir(), "engine.json")
	if err := os.WriteFile(legacy, []byte(`{"enabled":false}`), 0o600); err != nil {
		t.Fatalf("写旧 engine.json 失败: %v", err)
	}
	t.Cleanup(func() { os.Remove(legacy); os.Remove(legacy + ".migrated") })

	ensureSettingsDefaults()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("迁移应已生成 settings.json: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("生成文件不是合法 JSON: %v", err)
	}
	// 迁移产物只含 engine 节; 完整默认配置不应再叠加
	if _, ok := doc[secBrand]; ok {
		t.Fatal("迁移生成后不应再叠加完整默认配置(会覆盖迁移来源的口径)")
	}
	if _, ok := doc[secEngine]; !ok {
		t.Fatal("迁移的 engine 节应保留")
	}
}

// ===== 品牌 API =====

// TestBrandAPI 读默认 / 保存后立即生效 / 落盘到 brand 节 / 参数校验。
func TestBrandAPI(t *testing.T) {
	withTempExeDir(t)
	h, _ := newV2TestEnv(t)

	// 1) GET: brand 节不存在 → 默认品牌 + original_name
	w := doReq(t, h, http.MethodGet, "/api/v2/brand", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/brand HTTP %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			SystemName string `json:"system_name"`
			Copyright  string `json:"copyright"`
			Original   string `json:"original_name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Data.SystemName != originalName || resp.Data.Copyright != originalCopyright || resp.Data.Original != originalName {
		t.Fatalf("默认品牌响应不正确: %+v", resp.Data)
	}

	// 2) POST: 保存 → 立即生效(无需重启) + 落盘到 brand 节
	w = doReq(t, h, http.MethodPost, "/api/v2/brand", `{"system_name":"XX安全平台","copyright":"Copyright © 2026 XX"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/v2/brand HTTP %d: %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, http.MethodGet, "/api/v2/brand", "")
	if !strings.Contains(w.Body.String(), "XX安全平台") {
		t.Fatalf("保存后应立即生效: %s", w.Body.String())
	}
	data, err := os.ReadFile(settingsFilePath())
	if err != nil {
		t.Fatalf("brand 节应落盘到 settings.json: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil || doc[secBrand] == nil {
		t.Fatalf("settings.json 缺少 brand 节: %s", data)
	}

	// 3) 参数校验: 空值 / 超长
	w = doReq(t, h, http.MethodPost, "/api/v2/brand", `{"system_name":"","copyright":"x"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("空 system_name 应 400, 实际 %d", w.Code)
	}
	w = doReq(t, h, http.MethodPost, "/api/v2/brand", `{"system_name":"x","copyright":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("空 copyright 应 400, 实际 %d", w.Code)
	}
	long := strings.Repeat("a", brandFieldMaxLen+1)
	w = doReq(t, h, http.MethodPost, "/api/v2/brand", `{"system_name":"`+long+`","copyright":"x"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("超长 system_name 应 400, 实际 %d", w.Code)
	}
}

// TestBrandSaveRequiresAdmin 保存是 adminOnly: operator/auditor 403, admin 放行。
func TestBrandSaveRequiresAdmin(t *testing.T) {
	withTempExeDir(t)
	h, d := newV2TestEnv(t)
	setupRoleSessions(t, d)

	body := `{"system_name":"X平台","copyright":"Copyright © 2026 X"}`
	if w := doReqAs(t, h, http.MethodPost, "/api/v2/brand", body, "tok-operator"); w.Code != http.StatusForbidden {
		t.Fatalf("operator 保存品牌 status=%d, 期望 403", w.Code)
	}
	if w := doReqAs(t, h, http.MethodPost, "/api/v2/brand", body, "tok-auditor"); w.Code != http.StatusForbidden {
		t.Fatalf("auditor 保存品牌 status=%d, 期望 403", w.Code)
	}
	if w := doReqAs(t, h, http.MethodPost, "/api/v2/brand", body, "tok-admin"); w.Code != http.StatusOK {
		t.Fatalf("admin 保存品牌 status=%d body=%s, 期望 200", w.Code, w.Body.String())
	}
	// 读取保持 requireAuth(非 admin 也可查看当前品牌 —— 展示型数据, 与
	// 审计配置 GET 同口径)
	if w := doReqAs(t, h, http.MethodGet, "/api/v2/brand", "", "tok-auditor"); w.Code != http.StatusOK {
		t.Fatalf("auditor 读取品牌 status=%d, 期望 200(展示型数据非红线)", w.Code)
	}
}
