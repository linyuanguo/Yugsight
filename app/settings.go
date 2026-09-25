// settings.go 统一配置中心(exe 同目录 settings.json)。
//
// ===== 为什么要有这个文件 =====
//
// 项目此前把配置拆成 11 个独立 JSON: engine.json / ai.json / capture.json /
// updater.json / probe.json / scheduler.json / report.json / screen.json /
// config.json / users.json / whitelist.json。好处是每块独立、语义清晰; 坏处是
// 用户得记住 11 个文件名, 想改一个开关先要翻文档找"这功能归哪个文件管", 而
// 且配置一多, 目录里全是散落的 .json, 分不清哪些是配置哪些是程序数据。
//
// 现在统一到 settings.json 的**顶层分节**:
//
//	{
//	  "engine":    { ... },   // 原 engine.json 全文
//	  "ai":        { ... },   // 原 ai.json 全文
//	  "capture":   { ... },   // 原 capture.json 的 capture 节内容
//	  "updater":   { ... },   // 原 updater.json 全文
//	  "probe":     { "center": {...}, "client": {...} },  // 原 probe.json 全文
//	  "scheduler": { ... },   // 原 scheduler.json 全文
//	  "report":    { ... },   // 原 report.json 全文
//	  "screen":    { ... },   // 原 screen.json 全文
//	  "database":  { ... },   // 原 config.json 的 database 节内容
//	  "auth":      { ... },   // 原 users.json(程序读写)
//	  "whitelist": { ... }    // 原 whitelist.json(程序读写)
//	}
//
// ===== 关键设计: 每个节的"缺失"语义各不相同 =====
//
// 合并最大的陷阱是**把"用户没写这个节"和"用户写了但字段为空"混为一谈**。
// 各模块的默认值策略本来就不一致, 举例:
//
//   - updater 段缺失 → 启用"官方模板仓库直连更新"(开箱即用策略);
//     但显式写了 {"direct":{"enabled":false}} 就该彻底关闭。
//   - engine 段缺失 → 外部引擎关闭(默认关);
//   - scheduler/report 段缺失 → 功能关闭(默认关)。
//
// 所以本文件提供的是 **Section(name) (内容, 是否存在)** 两返回值 API: 各模块
// 自己决定"不存在时怎么办", 而不是由配置中心统一填默认值。这样各模块原有的
// 降级语义一行都不用改。
//
// ===== 与旧文件的关系: 双读兼容 =====
//
// settings.json **优先生效**; 某节不在 settings.json 里时, 回退读旧的单文件。
// 这样:
//   - 新用户只维护 settings.json 一个文件;
//   - 老机器上遗留的 engine.json / capture.json 等继续生效, 不会因为升级就
//     "配置静默失效"(那是最难排查的一类问题);
//   - 迁移是渐进的: 把旧文件内容挪进 settings.json 对应节, 删掉旧文件即可。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// settingsFileName 统一配置文件名(exe 同目录)。
const settingsFileName = "settings.json"

// 各配置节的名称常量。
//
// 用常量而非散落的字面量: 节名拼错不会报错, 只会静默读不到配置 —— 这类问题
// 排查成本极高, 集中定义至少保证编译期能挡住本文件内的笔误。
const (
	secEngine    = "engine"
	secAI        = "ai"
	secCapture   = "capture"
	secUpdater   = "updater"
	secProbe     = "probe"
	secScheduler = "scheduler"
	secReport    = "report"
	secScreen    = "screen"
	secDatabase  = "database"
	secAuth      = "auth"
	secWhitelist = "whitelist"
	secAuthCheck = "authcheck"
	secTLS       = "tls"
	secAudit     = "audit"
	secMonitor   = "monitor"
	secDashboard = "dashboard"
	secGeoIP     = "geoip"
	secCollect   = "collect" // 节点监控采集底座(阶段 1)
	secPenta     = "penta"   // 渗透工作台(阶段 5, 默认开启, 见 PentaConfig 注释)
	secNVD       = "nvd"     // NVD API Key(一键同步用, 可选; 缺省匿名限速档)
)

var (
	settingsMu   sync.RWMutex
	settingsRaw  map[string]json.RawMessage
	settingsDone bool
	// settingsLogged 标记"配置已加载"日志是否打过(见 loadSettings)。
	// 只打一次: 写配置后要 resetSettingsCache 同步缓存, 那之后的重载是内部
	// 行为, 每次都打会在高频写配置的场景刷屏 —— NVD 分批同步每批写一次
	// resume, 109 批就是 109 行同样的"已加载"。
	settingsLogged bool
)

// loadSettings 读取并缓存 settings.json 的顶层分节。
//
// 只解析到 map[string]RawMessage 一层, 各模块拿到自己那节的原始 JSON 再解析成
// 自己的结构体 —— 这样配置中心完全不需要知道任何模块的字段定义, 新增配置项
// 或改字段都不会波及本文件。这是"分层解耦"的直接收益。
//
// 【必须剥 BOM】Windows 记事本与 PowerShell 的 Set-Content -Encoding UTF8 都会
// 写出 EF BB BF, json.Unmarshal 遇到会报 "invalid character 'ï'", 用户现象是
// "我明明写了配置却不生效"。这个坑在 probe.json / screen.json / engine.json 上
// 都实测踩过, 这里是所有配置的唯一入口, 容错必须做在这里。
func loadSettings() map[string]json.RawMessage {
	settingsMu.RLock()
	if settingsDone {
		m := settingsRaw
		settingsMu.RUnlock()
		return m
	}
	settingsMu.RUnlock()

	m := map[string]json.RawMessage{}
	// 必须走 settingsFilePath() 而不是直接拼 exe 目录: 后者不认测试注入口
	// (setSettingsTestPath), 表现为"测试里写进临时目录的配置读不回来"——
	// 写路径早已走 settingsFilePath, 读路径漏掉会造成读写两个路径不一致。
	data, err := os.ReadFile(settingsFilePath())
	if err == nil && len(data) > 0 {
		data = stripBOM(data)
		if uerr := json.Unmarshal(data, &m); uerr != nil {
			// 解析失败时**保持空 map**让各模块走各自的默认值, 而不是退出。
			// 说清是哪个文件、什么原因, 否则用户只会看到"配置没生效"。
			logLine(settingsFileName + " 解析失败(将回退读取各单文件配置): " + uerr.Error())
			m = map[string]json.RawMessage{}
		}
	}

	// 红线「配置唯一」: settings.json 是中心端唯一配置文件。历史版本散落的
	// 单文件配置在此一次性迁进来(老机器升级后配置继续生效), 迁移后原文件
	// 改名 .migrated 不再被读取。
	migrateLegacyConfigs(m)

	settingsMu.Lock()
	settingsRaw, settingsDone = m, true
	// 首次标记也放在锁内: 并发首次加载时只能有一个 goroutine 拿到 first=true
	first := !settingsLogged
	if first {
		settingsLogged = true
	}
	settingsMu.Unlock()

	if len(m) > 0 && first {
		logLine(settingsFileName + " 已加载: " + strings.Join(settingsSectionNames(m), ", "))
	}
	return m
}

// legacyConfigFiles 历史单文件配置 -> settings.json 节名映射。
//
// 这些文件不再是配置项来源(红线: 中心端禁止出现 probe.json / ai.json /
// report.json / netconf.json 等独立配置文件), 只在升级时读一次用于迁移。
// 注意 cmd/agent 的 probe.json 不在此列 —— 红线允许 agent 端保留本地配置。
var legacyConfigFiles = []struct {
	file    string
	section string
}{
	{"capture.json", secCapture},
	{"engine.json", secEngine},
	{"scheduler.json", secScheduler},
	{"updater.json", secUpdater},
	{"report.json", secReport},
	{"screen.json", secScreen},
	{"ai.json", secAI},
	{"probe.json", secProbe},
	{"whitelist.json", secWhitelist},
	{"authcheck.json", secAuthCheck},
	{"netconf.json", "netconf"},
}

// legacyDatabaseFile 数据库配置的历史文件(config.json 的 database 节)。
const legacyDatabaseFile = "config.json"

// migrateLegacyConfigs 把历史单文件配置并入 settings.json(仅补缺失的节)。
//
// 只补"settings.json 里没有的节": 用户在 settings.json 里的显式配置优先,
// 迁移不能把新配置覆盖回旧值。原文件改名 .migrated 而非删除 —— 迁移是
// 不可逆的写操作, 留一份同名备份, 出问题能一眼找回。
func migrateLegacyConfigs(m map[string]json.RawMessage) {
	dir := filepath.Dir(settingsFilePath())
	migrated := 0
	for _, l := range legacyConfigFiles {
		migrated += migrateOneLegacy(m, filepath.Join(dir, l.file), l.section, "")
	}
	migrated += migrateOneLegacy(m, filepath.Join(dir, legacyDatabaseFile), secDatabase, "database")
	if migrated > 0 {
		logLine(fmt.Sprintf("配置收敛: %d 个历史单文件配置已迁入 %s(原文件改名 *.migrated 保留备份)", migrated, settingsFileName))
	}
}

// migrateOneLegacy 迁移单个历史文件; sub 非空表示取该文件的这个子节。
func migrateOneLegacy(m map[string]json.RawMessage, path, section, sub string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	raw = stripBOM(raw)
	body := raw
	if sub != "" {
		var doc map[string]json.RawMessage
		if json.Unmarshal(raw, &doc) != nil {
			return 0
		}
		v, ok := doc[sub]
		if !ok {
			return 0
		}
		body = v
	}
	if len(bytes.TrimSpace(body)) == 0 || string(bytes.TrimSpace(body)) == "null" {
		return 0
	}
	// 节已存在: 不覆盖, 但仍要把历史文件改名(否则它就是"还在起作用的第二份配置")
	if _, exists := m[section]; !exists {
		m[section] = json.RawMessage(body)
		if err := writeSection(section, json.RawMessage(body)); err != nil {
			logLine(fmt.Sprintf("配置迁移写入失败(节 %s): %v", section, err))
		} else {
			logLine(fmt.Sprintf("配置迁移: %s -> %s 的 %s 节", filepath.Base(path), settingsFileName, section))
		}
	}
	if err := os.Rename(path, path+".migrated"); err != nil {
		logLine(fmt.Sprintf("历史配置 %s 改名失败(请手工删除以免误解): %v", filepath.Base(path), err))
	}
	return 1
}

// settingsSectionNames 返回已配置的节名(排序后, 供日志展示)。
// 排序是为了让日志稳定可比对 —— 顺序随机的日志在 diff 时是噪声。
func settingsSectionNames(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		// 以下划线开头的键当作注释说明(与 engine.json 的 _comment 同一约定),
		// 不计入"已配置的节", 否则日志里会混进 _comment 这种非配置项。
		if strings.HasPrefix(k, "_") {
			continue
		}
		out = append(out, k)
	}
	// 固定顺序展示: 按预定义节序排, 未知节追加在后
	order := []string{secEngine, secAI, secCapture, secUpdater, secProbe,
		secScheduler, secReport, secScreen, secDatabase, secAuth, secWhitelist, secAuthCheck, secTLS, secAudit, secMonitor, secDashboard, secGeoIP, secCollect, secPenta, secNVD}
	var sorted, rest []string
	for _, name := range order {
		for _, got := range out {
			if got == name {
				sorted = append(sorted, name)
			}
		}
	}
	for _, got := range out {
		known := false
		for _, name := range order {
			if got == name {
				known = true
				break
			}
		}
		if !known {
			rest = append(rest, got)
		}
	}
	return append(sorted, rest...)
}

// section 取指定节的原始 JSON。
//
// 返回 (内容, 是否存在)。**是否存在必须由调用方判断**: 各模块对"节缺失"的处理
// 策略不同(见文件头说明), 由配置中心统一决定会破坏原有降级语义。
//
// 红线「配置唯一」(2026-09-23 整改): legacyName 参数已废弃 —— 不再回退读
// 任何单文件。老机器的历史配置由 migrateLegacyConfigs 在启动时一次性并入
// settings.json, 运行期配置来源只有一个文件。
//
// 保留形参是为了不改全部调用点(十几处), 调用方传什么都会被忽略;
// 新增代码请直接传空串。
func section(name, legacyName string) ([]byte, bool) {
	if raw, ok := loadSettings()[name]; ok && len(raw) > 0 {
		// 显式写了 null 视为未配置, 不能把 "null" 三个字节当内容解析:
		// 各模块的 json.Unmarshal 遇到 null 会成功但字段全零, 看起来像
		// "配置被读到了但值是空的", 比直接报缺失更难排查。
		if string(raw) != "null" {
			return raw, true
		}
	}
	return nil, false
}

// settingsFilePath settings.json 的完整路径(供测试与提示信息使用)。
func settingsFilePath() string {
	// 测试注入口: 把配置指到临时目录, 避免测试污染真实 exe 目录的 settings.json
	if p := testSettingsPath(); p != "" {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return settingsFileName
	}
	return filepath.Join(filepath.Dir(exe), settingsFileName)
}

var settingsPathOverride atomic.Value // string, 空 = 用真实路径

// setSettingsTestPath 测试注入配置路径("" = 还原真实路径)。
func setSettingsTestPath(p string) { settingsPathOverride.Store(p) }

func testSettingsPath() string {
	if v, ok := settingsPathOverride.Load().(string); ok {
		return v
	}
	return ""
}

// resetSettingsCache 清空配置缓存(写配置后同步内存; 测试用它隔离用例)。
//
// 写配置后必须重置: writeSection 只落盘, 内存里仍是旧快照, 不重置会读到过期值
// (NVD 续传进度刚写进 Next=57, 缓存里还是 56, 下次续传判断直接错位)。
//
// 必须有这个入口: settings 是进程级缓存, 测试若不能重置, 用例之间会互相污染,
// 表现为"单跑通过、全量跑失败"。同理适用于所有 Once 风格的单例 —— 项目在
// scheduler / bigscreen 上已踩过同类坑。
//
// 刻意不清 settingsLogged: 重载日志只在进程内打一次, 这里的重置是实现细节。
func resetSettingsCache() {
	settingsMu.Lock()
	settingsRaw, settingsDone = nil, false
	settingsMu.Unlock()
}

// stripBOM 剥掉 UTF-8 BOM(EF BB BF)。
// 独立成函数是因为多个模块都要用, 且必须保证口径完全一致。
func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// writeSection 把某个节写回 settings.json, **保留其它节与注释不变**。
//
// ===== 为什么必须是"合并写"而不是整文件重写 =====
//
// 程序需要持久化两样东西: 账号库(auth)与白名单(whitelist)。如果把内存里的
// settings 结构体整体 Marshal 后覆盖写盘, 会带来两个后果:
//
//  1. **用户的注释全部丢失** —— settings.json 是给人手写的, 里面必然有
//     `_comment` 说明、空行、字段顺序偏好。程序一次保存就把它们抹平, 用户
//     下次打开发现"我写的东西没了", 而这类丢失是不可逆的。
//  2. **并发写互相覆盖** —— 账号保存与白名单保存若各自整文件写, 后写的那个
//     会带上自己那份(可能已过期的)其它节快照, 把对方刚写的内容冲掉。
//
// 所以这里读盘 → 只替换目标节 → 写回。其它节的字节原样保留(用 RawMessage
// 承载, 不做解析再序列化), 因此用户的注释与格式在**非目标节**里完全不受影响。
//
// 注意: 目标节自身会被重新序列化(那是程序生成的数据), 这是预期行为。
//
// 原子写(临时文件 + rename)与项目其它落盘路径一致: 写一半断电不会留下损坏的
// settings.json —— 那会导致**所有**配置一起失效, 比单个文件损坏严重得多。
func writeSection(name string, v any) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()

	path := settingsFilePath()
	// 重新读盘而非用内存缓存: 内存缓存是启动时快照, 而 settings.json 可能被
	// 用户在运行期编辑过(项目允许改配置后重启生效, 但这里不能假设用户没动过)。
	// 读盘能拿到"当前真实内容", 避免用陈旧快照覆盖用户的新修改。
	diskRaw := map[string]json.RawMessage{}
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if uerr := json.Unmarshal(stripBOM(data), &diskRaw); uerr != nil {
			// 解析失败则从空开始 —— 此时若继续写会丢掉原文件里所有无法解析的内容,
			// 故先备份一份, 让用户还有机会人工抢救。
			_ = os.WriteFile(path+".bak", data, 0o600)
			logLine(settingsFileName + " 解析失败, 已备份为 " + settingsFileName + ".bak 后重建")
			diskRaw = map[string]json.RawMessage{}
		}
	}

	blob, err := json.Marshal(v)
	if err != nil {
		return err
	}
	diskRaw[name] = json.RawMessage(blob)

	out, err := json.MarshalIndent(diskRaw, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		os.Remove(path + ".tmp")
		return err
	}
	return nil
}

// sectionBytes 取节的原始字节(供需要自行解析模块使用, 语义同 section)。
func sectionBytes(name string) ([]byte, bool) {
	return section(name, "")
}
