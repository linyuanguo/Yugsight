// settings_defaults.go 首次启动: 自动生成完整的默认 settings.json。
//
// 背景(2026-09-28): 此前首次启动时 settings.json 只会被"第一个保存某节的模块"
// 懒创建(文件里只有那一节, 不是完整模板), 用户需要对照 settings.example.json
// 猜其余结构。现在:
//
//	启动加载完成后, 若 exe 同目录的 settings.json 不存在(既无新配置文件,
//	也无旧配置触发迁移生成), 自动组装所有模块的完整默认配置(所有现有节 +
//	brand 节, 全部填充各自默认值)一次性写入。
//
// 红线:
//  1. 文件已存在(用户配置/迁移生成/手动创建)绝不覆盖 —— 只 os.Stat 判存在,
//     不读不改内容;
//  2. 每个节的默认值严格对齐"该模块在节缺失时的行为"(2026-09-28 逐节对照
//     代码核实, 见 buildDefaultSettings 各字段注释) —— 生成的文件与不生成
//     时的运行行为完全等价, 对既有用户零影响;
//  3. loadSettings / writeSection / migrateLegacyConfigs 逻辑不变 —— 本文件
//     只在启动加载完成之后新增一步判断, 不动原有配置机制。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"yugsight/internal/ai"
	"yugsight/internal/scheduler"
)

// defaultSettingsDoc 完整默认配置文档(字段顺序 = 文件内节展示顺序)。
//
// 值统一用 any 而非各模块结构体: 生成逻辑与各模块的加载代码解耦, 模块结构
// 调整时这里只改"缺省值", 不引入新的编译期耦合。
type defaultSettingsDoc struct {
	Comment   string `json:"_comment"`
	About     string `json:"_about"`
	Engine    any    `json:"engine"`
	AI        any    `json:"ai"`
	Capture   any    `json:"capture"`
	Updater   any    `json:"updater"`
	Probe     any    `json:"probe"`
	Scheduler any    `json:"scheduler"`
	Report    any    `json:"report"`
	Screen    any    `json:"screen"`
	Database  any    `json:"database"`
	Auth      any    `json:"auth"`
	Whitelist any    `json:"whitelist"`
	AuthCheck any    `json:"authcheck"`
	TLS       any    `json:"tls"`
	Audit     any    `json:"audit"`
	Monitor   any    `json:"monitor"`
	Dashboard any    `json:"dashboard"`
	GeoIP     any    `json:"geoip"`
	Collect   any    `json:"collect"`
	Penta     any    `json:"penta"`
	NVD       any    `json:"nvd"`
	ArpProxy  any    `json:"arpproxy"`
	Brand     any    `json:"brand"`
	Https     any    `json:"https"`
}

// buildDefaultSettings 组装所有模块的完整默认配置。
//
// 每一节的值都以"该模块节缺失时的行为"为准(逐节代码核实):
//   - engine: Enabled 为 *bool, 缺失 = 启用(外部引擎是默认执行路径, 二进制
//     缺失自动降级内置) —— 显式写 true 与缺失等价; downloads 用代码兜底函数
//     defaultEngineDownloadConfig()(镜像探测开, 下载/自动补装全关)。
//   - ai: 直接用 ai.DefaultConfig() —— 代码内唯一的 AI 默认来源(与"恢复出厂"
//     重置 AI 配置同一口径), 含完整提示词模板。
//   - capture: 环路检测关, 全量采集开(captureAll 为 *bool, 缺失 = true)。
//   - updater: 节缺失 = 直连官方模板仓库更新开箱即用 —— 显式写 direct.enabled
//     true 与缺失等价; sources/proxy 等保持空值(代码缺省)。
//   - probe: center/client 均显式关闭(缺失 = 单机模式, 与显式 false 同效)。
//   - scheduler: 直接用 scheduler.DefaultConfig()(enabled=true / quick 策略 /
//     2 并发 / 超时 1800s 等代码默认)。
//   - report: enabled=true(用户明确要求默认开启, 2026-09-20), 归档上限 500、
//     副标题/主色跟代码默认; autoGenerate/autoSave 指针字段不写 = 代码默认。
//   - screen: 大屏性能指标关(零值 = 关)。
//   - database: sqlite + 空 dir(空 = 代码默认数据目录); postgres 子节不写
//     (sqlite 模式下不读取)。
//   - auth: enabled=true(缺失 = 登录开启), user/pass 为初始账号默认
//     (admin/admin123, 仅全新安装自动建号时读取)。
//   - whitelist: 空列表(无任何豁免条目)。
//   - authcheck / tls / collect: 零值 = 关闭, 显式写 false 与缺失等价。
//   - audit: 保留 90 天(代码默认, 仅 admin 可改)。
//   - dashboard / geoip: 加载器用 hasExplicitEnabled 区分"未写"与"显式 false"
//     —— 显式写 true 与"未写"同为默认开, 行为等价。
//   - penta: enabled 为 *bool, 缺失 = 开启(渗透工作台默认开) —— 显式写 true。
//   - arpproxy: exclude 为 *bool, 缺失 = 排除开启 —— 显式写 true。
//   - nvd: 自由键节(存 API Key 等), 可选配置, 写空对象。
//   - brand: 品牌自定义默认值(= 原始项目名/版权, 见 brand.go)。
func buildDefaultSettings() defaultSettingsDoc {
	return defaultSettingsDoc{
		Comment: "settings.json —— 统一配置文件(首次启动自动生成: 全模块完整默认配置)",
		About:   "各节相互独立: 缺失时对应功能走代码默认值(见各模块注释); 存在时只覆盖已写字段。修改本文件一般需重启服务生效(个别支持热重载, 见页内说明)。\n节速查: engine=引擎编排 ai=AI分析 capture=抓包 updater=规则库更新 probe=分布式探针 scheduler=调度队列 report=报告 screen=大屏指标 database=持久化 auth=登录账号 whitelist=漏洞规则白名单 authcheck=弱口令检测 tls=HTTPS audit=审计日志 monitor=节点监控 dashboard=可视化大盘 geoip=3D地图 collect=采集底座 penta=渗透工作台 nvd=NVD Key arpproxy=ARP幽灵资产排除 brand=品牌自定义 https=HTTPS访问白名单",
		Engine: map[string]any{
			"enabled":   true, // *bool: 缺失 = 启用; 显式 true 与缺失等价
			"downloads": defaultEngineDownloadConfig(),
		},
		AI:        ai.DefaultConfig(),
		Capture:   map[string]any{"loopDetect": false, "captureAll": true},
		Updater: map[string]any{
			"sources":    []string{},
			"proxy":      "",
			"interval":   "24h",
			"autoUpdate": false,
			"tieredLoad": false,
			"onDemandKB": 512,
			"direct": map[string]any{
				"enabled":        true, // 缺失 = 直连官方模板仓库更新(开箱即用)
				"templatesRepo":  "projectdiscovery/nuclei-templates",
				"templatesRef":   "main",
				"severities":     []string{"critical", "high", "medium"},
				"maxTemplates":   0,
			},
		},
		Probe: map[string]any{
			"center": map[string]any{"enabled": false, "listen": ":8600", "token": "", "heartbeatSec": 15, "offlineSec": 0, "maxProbes": 200, "metricsSec": 30},
			"client": map[string]any{"enabled": false, "centerAddr": "", "token": "", "id": "", "name": "", "heartbeatSec": 15, "reconnectSec": 5, "metricsSec": 30},
		},
		Scheduler: scheduler.DefaultConfig(),
		Report: map[string]any{
			"enabled":         true, // 默认开启(2026-09-20 用户口径)
			"maxArchive":      500,
			"maxRaw":          500,
			"defaultOperator": "",
			"subtitle":        "网络安全扫描与漏洞评估报告",
			"accent":          "#1f3a5f",
			"showRaw":         false,
		},
		Screen:   map[string]any{"metrics": false},
		Database: map[string]any{"type": "sqlite", "dir": ""}, // 空 dir = 代码默认数据目录
		Auth:     map[string]any{"enabled": true, "user": "admin", "pass": "admin123"},
		Whitelist: map[string]any{"entries": []string{}},
		AuthCheck: map[string]any{"enabled": false},
		TLS:       map[string]any{"enabled": false},
		Audit:     map[string]any{"retentionDays": 90},
		Monitor:   map[string]any{"enabled": true, "intervalSec": 60, "targets": []string{}},
		Dashboard: map[string]any{
			"enabled":   true,
			"days":      7,
			"topCities": 50,
			"center":    map[string]any{"lat": 0, "lon": 0, "name": ""},
		},
		GeoIP:    map[string]any{"enabled": true},
		Collect:  map[string]any{"enabled": false, "tasks": []any{}},
		Penta:    map[string]any{"enabled": true},
		NVD:      map[string]any{},
		ArpProxy: map[string]any{"exclude": true},
		Brand:    map[string]any{"system_name": originalName, "copyright": originalCopyright},
		// https: HTTPS 访问白名单默认空(ips=[]) = 不启用, 不限制任何 IP;
		// 用户在前端添加 IP/网段后启用(只放行列表内来源)。
		Https: map[string]any{"ips": []string{}},
	}
}

// ensureSettingsDefaults 启动加载完成后的自动补全: 若 settings.json 不存在,
// 生成全模块完整默认配置; 文件已存在则绝不触碰。
//
// 调用时机(main 启动序列): migrateLegacyDirs 之后、loadAuth/initDefaultAccount
// 之前 —— 后两者会写 auth 节(首次登录初始化), 若它们先创建了 settings.json
// (文件里只有 auth 一节), 本函数会误判"文件已存在"而跳过完整配置生成。
//
// 内部先调 loadSettings(): 触发 migrateLegacyConfigs —— 若存在历史单文件配置
// (engine.json 等), 此步骤已把它们并入 settings.json, 随后的存在性检查会把
// 迁移产物视为"文件已存在", 不再叠加生成(两种来源不冲突, 迁移文件优先)。
func ensureSettingsDefaults() {
	loadSettings()
	if _, err := os.Stat(settingsFilePath()); err == nil {
		return // 文件已存在(用户配置/迁移生成/手动创建): 绝不覆盖
	}
	doc := buildDefaultSettings()
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		logLine("默认配置组装失败(不影响启动, 各模块按默认值运行): " + err.Error())
		return
	}
	path := settingsFilePath()
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	// 与 writeSection 同口径的原子写(tmp + rename): 避免半截文件被下次启动读到
	if err := os.WriteFile(path+".tmp", body, 0o600); err != nil {
		logLine("settings.json 写入失败(不影响启动, 各模块按默认值运行): " + err.Error())
		return
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		os.Remove(path + ".tmp")
		logLine("settings.json 落盘改名失败(不影响启动): " + err.Error())
		return
	}
	resetSettingsCache() // 同步内存缓存到盘(下次读取打印节清单日志)
	logLine(fmt.Sprintf("首次启动: 未检测到 %s, 已自动生成全模块完整默认配置(含 brand 节)", settingsFileName))
}
