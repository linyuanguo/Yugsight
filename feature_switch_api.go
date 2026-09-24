// feature_switch_api.go 功能开关的读写接口(用户口径: 开关在页面上,
// settings.json 只是保存参数的地方 —— 不是"改文件才能开功能")。
//
// 三条原则:
//  1. 默认全部开启: 页面只用来"关掉不需要的", 而不是"找到并打开"的;
//  2. 保存即生效: 写完立刻重置配置缓存并重建依赖实例(geoip 段表), 不要求重启;
//  3. 读哪里就写哪里: report 优先 settings.json 的 report 节(没有则写 report.json,
//     因为读取端有该文件回退); dashboard/geoip 只认 settings.json 的节, 故一律
//     走 writeSection(合并写, 保留用户其它节与注释)。
package main

import (
	"encoding/json"
	"net/http"

	"yugsight/server"
)

// registerFeatureSwitchRoutes 挂载功能开关路由(与 monitor/report 同级)。
func registerFeatureSwitchRoutes(srv *server.Server) {
	srv.Get("/api/v2/config/features", requireAuth(hFeatureSwitchList))
	srv.Post("/api/v2/config/dashboard", requireAuth(adminOrOperator(hSaveDashboardSwitch)))
	srv.Post("/api/v2/config/report", requireAuth(adminOrOperator(hSaveReportSwitch)))
}

// featureSwitchView 页面开关回显结构。
type featureSwitchView struct {
	GeoIP struct {
		Enabled bool   `json:"enabled"`
		Loaded  bool   `json:"loaded"`
		V4      int    `json:"v4Count"`
		V6      int    `json:"v6Count"`
		Note    string `json:"note,omitempty"`
	} `json:"geoip"`
	Dashboard struct {
		Enabled   bool   `json:"enabled"`
		Days      int    `json:"days"`
		TopCities int    `json:"topCities"`
		Note      string `json:"note,omitempty"`
	} `json:"dashboard"`
	Report struct {
		Enabled            bool `json:"enabled"`
		TemplateManagement bool `json:"templateManagement"`
		PDFExternal        bool `json:"pdfExternal"`
		AutoGenerate       bool `json:"autoGenerate"`
	} `json:"report"`
}

// hFeatureSwitchList GET /api/v2/config/features 全部开关的当前值。
func hFeatureSwitchList(w http.ResponseWriter, r *http.Request) {
	var v featureSwitchView
	gcfg := loadGeoIPConfig()
	v.GeoIP.Enabled = gcfg.Enabled
	if v4, v6, c4, c6 := instanceGeoIP().Loaded(); v4 || v6 {
		v.GeoIP.Loaded = true
		v.GeoIP.V4, v.GeoIP.V6 = c4, c6
	} else {
		v.GeoIP.Note = "段表未加载(数据缺失或已关闭)"
	}
	d := loadDashboardConfig()
	v.Dashboard.Enabled = d.Enabled
	v.Dashboard.Days = d.Days
	v.Dashboard.TopCities = d.TopCities
	rc := loadReportConfig()
	v.Report.Enabled = rc.Enabled
	v.Report.TemplateManagement = packManagementEnabled()
	v.Report.PDFExternal = pdfExternalEnabled()
	v.Report.AutoGenerate = rc.AutoGenerate != nil && *rc.AutoGenerate
	server.OK(w, v)
}

// hSaveDashboardSwitch POST /api/v2/config/dashboard
// body: {enabled, days, topCities, geoipEnabled} —— 缺失的字段保持原值。
func hSaveDashboardSwitch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled      *bool `json:"enabled"`
		Days         *int  `json:"days"`
		TopCities    *int  `json:"topCities"`
		GeoIPEnabled *bool `json:"geoipEnabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		server.FailBadRequest(w, "请求格式错误: "+err.Error())
		return
	}
	d := loadDashboardConfig()
	if in.Enabled != nil {
		d.Enabled = *in.Enabled
	}
	if in.Days != nil {
		d.Days = clampInt(*in.Days, 1, 90, 7)
	}
	if in.TopCities != nil {
		d.TopCities = clampInt(*in.TopCities, 1, 200, 50)
	}
	g := loadGeoIPConfig()
	if in.GeoIPEnabled != nil {
		g.Enabled = *in.GeoIPEnabled
	}
	// dashboard/geoip 只从 settings.json 的节读取, 故一律合并写回该节
	if err := writeSection(secDashboard, d); err != nil {
		server.FailInternal(w, "保存失败: "+err.Error())
		return
	}
	if err := writeSection(secGeoIP, g); err != nil {
		server.FailInternal(w, "保存失败: "+err.Error())
		return
	}
	// 立即生效: 重置缓存并按需重建 geoip 段表(不重启)
	ReloadSettings("功能开关保存(大屏/地理映射)")
	logAudit(v2GetDB(), r, "config.dashboard", "",
		"dashboard="+boolText(d.Enabled)+" geoip="+boolText(g.Enabled))
	server.OK(w, map[string]any{"dashboard": d, "geoip": g})
}

// hSaveReportSwitch POST /api/v2/config/report
// body: {enabled, templateManagement, pdfExternal, autoGenerate, maxArchive}
func hSaveReportSwitch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled            *bool `json:"enabled"`
		TemplateManagement *bool `json:"templateManagement"`
		PDFExternal        *bool `json:"pdfExternal"`
		AutoGenerate       *bool `json:"autoGenerate"`
		MaxArchive         *int  `json:"maxArchive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		server.FailBadRequest(w, "请求格式错误: "+err.Error())
		return
	}
	cfg := loadReportConfig()
	if in.Enabled != nil {
		cfg.Enabled = *in.Enabled
	}
	if in.TemplateManagement != nil {
		cfg.TemplateManagement = in.TemplateManagement
	}
	if in.PDFExternal != nil {
		cfg.PDFExternal = in.PDFExternal
	}
	if in.AutoGenerate != nil {
		cfg.AutoGenerate = in.AutoGenerate
	}
	if in.MaxArchive != nil && *in.MaxArchive > 0 {
		cfg.MaxArchive = *in.MaxArchive
	}
	// 配置口径(2026-09-23): 中心端配置一律 settings.json(含 report 节)。
	err := saveReportConfigFile(cfg)
	if err != nil {
		server.FailInternal(w, "保存失败: "+err.Error())
		return
	}
	ReloadSettings("功能开关保存(报告)")
	logAudit(v2GetDB(), r, "config.report", "",
		"enabled="+boolText(cfg.Enabled)+" tplMgmt="+boolText(packManagementEnabled()))
	server.OK(w, map[string]any{
		"enabled":            cfg.Enabled,
		"templateManagement": packManagementEnabled(),
		"pdfExternal":        pdfExternalEnabled(),
		"autoGenerate":       cfg.AutoGenerate != nil && *cfg.AutoGenerate,
		"maxArchive":         cfg.MaxArchive,
	})
}

func boolText(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
