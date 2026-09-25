//go:build !windows || windows

// whitelist.go 漏洞白名单(基础数据模型 + 匹配)。
//
// 设计:
//   - 数据模型: WhitelistEntry 按 5 种类型匹配(CVE 号 / 规则 ID / 主机 IP /
//     端口 / 标题子串), 支持启用开关与有效期(过期条目自动失效);
//     基础模型即完整模型, 后续归一化模块可直接复用
//   - 存储: exe 同目录 whitelist.json(可选外部资源, 文件缺失 = 白名单为空,
//     零影响, 降级运行不报错); 原子写(临时文件 + rename)
//   - 开关语义: 默认关闭(进程内启用开关 wlOn=false); 通过 AddWhitelistEntry
//     写入条目视为用户显式操作, 自动开启开关; SetWhitelistEnabled 可随时
//     强制关闭(关闭时 IsWhitelisted 恒 false, 不影响任何扫描行为)
//   - 匹配入口: IsWhitelisted 接收统一漏洞模型 *Vulnerability(见 model.go),
//     返回 (是否命中, 命中的条目); FilterWhitelisted 批量过滤并打标
//
// 依赖: 仅 Go 标准库。
package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"yugsight/internal/pathrel"
)

// whitelistLog 组件日志
var whitelistLog = slog.Default().With("component", "whitelist")

// 白名单条目类型
const (
	WLTypeCVE   = "cve"   // 按 CVE 号匹配(大小写不敏感)
	WLTypeRule  = "rule"  // 按规则 ID 匹配(模板 ID / YUGSIGHT-000X 等, 大小写不敏感)
	WLTypeHost  = "host"  // 按主机 IP 匹配
	WLTypePort  = "port"  // 按端口匹配(数字串)
	WLTypeTitle = "title" // 按漏洞标题子串匹配(大小写不敏感)
)

// WhitelistEntry 白名单条目
type WhitelistEntry struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"` // cve / rule / host / port / title
	Match   string    `json:"match"`
	Reason  string    `json:"reason,omitempty"`
	Enabled bool      `json:"enabled"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires,omitempty"` // 零值 = 永不过期
}

var (
	wlMu      sync.RWMutex
	wlEntries []WhitelistEntry
	wlOn      bool // 进程内启用开关(默认关闭)
)

// whitelistFile 测试用文件覆盖(空 = exe 同目录 whitelist.json)
var whitelistFile = ""

// WhitelistHook 白名单持久化注入点。
//
// 【为什么需要注入】白名单配置统一到 settings.json 的 whitelist 节后, scanner 包
// 就不该知道 settings.json 的存在 —— 它是扫描引擎, 定位是"可脱离装配层单测"。
// 由装配层注入读/写两个函数, scanner 只管自己的语义:
//   - Load  : 返回该节的原始 JSON(不存在返回 false)
//   - Save  : 把该节内容合并写回(保留其它节与注释)
//
// 未注入时自动回退读写独立的 whitelist.json 文件, 因此单独使用 scanner 包的
// 测试与旧部署都不受影响。
type WhitelistHook struct {
	Load func() ([]byte, bool)
	Save func(data []byte) error
}

var (
	whitelistHookMu sync.RWMutex
	whitelistHook   WhitelistHook
)

// SetWhitelistHook 注入白名单持久化实现(由装配层在启动时调用一次)。
func SetWhitelistHook(h WhitelistHook) {
	whitelistHookMu.Lock()
	whitelistHook = h
	whitelistHookMu.Unlock()
}

func currentWhitelistHook() WhitelistHook {
	whitelistHookMu.RLock()
	defer whitelistHookMu.RUnlock()
	return whitelistHook
}

// whitelistPath 白名单文件路径(默认 exe 同目录 whitelist.json)
func whitelistPath() string {
	if whitelistFile != "" {
		return whitelistFile
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "whitelist.json")
	}
	return "whitelist.json"
}

// LoadWhitelist 从 whitelist.json 加载白名单(可选文件)。
// 文件不存在返回 (0, nil) —— 白名单为空, 不影响任何行为;
// 解析失败保留已有条目并返回错误(只记日志, 不中断)。
func LoadWhitelist() (int, error) {
	var (
		data []byte
		err  error
		// src 记录内容来源, 仅用于日志: 白名单读不到时, 用户最需要知道的是
		// "程序到底去哪找的"(settings.json 的 whitelist 节 vs 独立的文件)。
		src = settingsSectionLabel
	)
	if h := currentWhitelistHook(); h.Load != nil {
		// 注入路径: 内容来自 settings.json 的 whitelist 节
		var ok bool
		data, ok = h.Load()
		if !ok {
			return 0, nil
		}
	} else {
		// 红线「配置唯一」(2026-09-23 整改): 未注入时也不再读独立 whitelist.json,
		// 而是直接读唯一配置文件 settings.json 的 whitelist 节(旧文件由主程序
		// 启动时迁入)。scanner 包不能引用 main 的节名常量, 故在此重复字面量。
		src = settingsSectionLabel
		data, err = readWhitelistSection()
		if err != nil {
			return 0, nil
		}
	}
	var f struct {
		Entries []WhitelistEntry `json:"entries"`
	}
	if uerr := json.Unmarshal(data, &f); uerr != nil {
		return 0, fmt.Errorf("白名单配置解析失败: %s", uerr)
	}
	for i := range f.Entries {
		if f.Entries[i].ID == "" {
			f.Entries[i].ID = "wl-" + strings.TrimSpace(f.Entries[i].Type) + "-" + strings.TrimSpace(f.Entries[i].Match)
		}
	}
	wlMu.Lock()
	wlEntries = f.Entries
	wlMu.Unlock()
	if len(f.Entries) > 0 {
		// src 可能是路径也可能是来源标签; pathrel.Short 对非路径原样返回, 无副作用
		whitelistLog.Info("白名单已加载", "file", pathrel.Short(src), "entries", len(f.Entries))
	}
	return len(f.Entries), nil
}

// readWhitelistSection 从唯一配置文件 settings.json 取 whitelist 节内容。
//
// 为什么整文件读再取节而不是直接拼 whitelist.json: 中心端只承认一个配置文件
// (红线「配置唯一」), 子包即使拿不到主程序的注入也必须走同一份文件。
// 文件不存在 / 没有该节都返回错误 —— 白名单为空是合法状态, 由调用方降级处理。
func readWhitelistSection() ([]byte, error) {
	path := whitelistSettingsFile()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// 剥 BOM: 手工编辑的 JSON 常带 EF BB BF(与 probe.json 同一个坑)
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	sec, ok := doc["whitelist"]
	if !ok || string(bytes.TrimSpace(sec)) == "null" {
		return nil, os.ErrNotExist
	}
	return sec, nil
}

// settingsFileName 唯一配置文件名(与主程序 settings.go 同值)。
const settingsFileName = "settings.json"

// whitelistSettingsFile settings.json 路径(默认 exe 同目录)。
//
// settingsOverride 是**测试注入口**(与 db / scheduler 的可注入配置同源思路):
// 子包拿不到主程序的 settingsFilePath, 若不能改指临时目录, 用例就会互相污染
// 甚至写坏开发机配置。
var settingsOverride atomic.Value // string, 空 = 用 exe 同目录

// SetWhitelistSettingsPath 注入 settings.json 路径(主要供测试; "" = 还原)。
func SetWhitelistSettingsPath(p string) { settingsOverride.Store(p) }

func whitelistSettingsFile() string {
	if v, ok := settingsOverride.Load().(string); ok && v != "" {
		return v
	}
	exe, err := os.Executable()
	if err != nil {
		return settingsFileName
	}
	return filepath.Join(filepath.Dir(exe), settingsFileName)
}

// settingsSectionLabel 注入模式下的日志来源标识。
// 独立成常量是因为它出现在日志里, 一旦写错会误导排查方向(用户会去找一个
// 不存在的文件名)。scanner 包不能引用 main 的节名常量, 故在此重复一份字面量。
const settingsSectionLabel = "settings.json#whitelist"

// SaveWhitelist 把当前白名单原子写入文件(临时文件 + rename)
func SaveWhitelist() error {
	wlMu.RLock()
	out := make([]WhitelistEntry, len(wlEntries))
	copy(out, wlEntries)
	wlMu.RUnlock()
	f := struct {
		Entries []WhitelistEntry `json:"entries"`
	}{Entries: out}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	// 注入路径: 交给装配层合并写回 settings.json 的 whitelist 节
	// (保留其它节与用户注释; 整文件覆盖会把用户写的注释抹掉)
	if h := currentWhitelistHook(); h.Save != nil {
		return h.Save(data)
	}
	// 未注入时也必须写 settings.json(红线「配置唯一」): 不能再落 whitelist.json。
	return writeWhitelistSection(data)
}

// writeWhitelistSection 把 whitelist 节合并写回 settings.json(原子写)。
//
// 与装配层 hook 的区别只是"谁来写": 这里是为了让子包在未注入时也不产生
// 独立配置文件。必须合并写 —— 整文件覆盖会抹掉用户其它节与注释。
func writeWhitelistSection(sec []byte) error {
	p := whitelistSettingsFile()
	raw, err := os.ReadFile(p)
	doc := map[string]json.RawMessage{}
	if err == nil {
		raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
		if uerr := json.Unmarshal(raw, &doc); uerr != nil {
			return fmt.Errorf("settings.json 解析失败, 白名单未保存: %s", uerr)
		}
	}
	doc["whitelist"] = json.RawMessage(sec)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// SetWhitelistEnabled 设置白名单总开关(默认关闭)。
// 关闭时 IsWhitelisted 恒 false, 白名单不影响任何扫描行为。
func SetWhitelistEnabled(on bool) {
	wlMu.Lock()
	wlOn = on
	wlMu.Unlock()
}

// WhitelistEnabled 返回白名单总开关状态
func WhitelistEnabled() bool {
	wlMu.RLock()
	defer wlMu.RUnlock()
	return wlOn
}

// AllWhitelistEntries 返回全部白名单条目(副本)
func AllWhitelistEntries() []WhitelistEntry {
	wlMu.RLock()
	defer wlMu.RUnlock()
	out := make([]WhitelistEntry, len(wlEntries))
	copy(out, wlEntries)
	return out
}

// entryActive 条目是否生效(启用 + 未过期)
func entryActive(e WhitelistEntry, now time.Time) bool {
	if !e.Enabled {
		return false
	}
	if !e.Expires.IsZero() && now.After(e.Expires) {
		return false
	}
	return true
}

// matchEntry 单条目匹配判定
func matchEntry(e WhitelistEntry, v *Vulnerability) bool {
	switch e.Type {
	case WLTypeCVE:
		return v.CVE != "" && strings.EqualFold(strings.TrimSpace(e.Match), v.CVE)
	case WLTypeRule:
		return v.RuleID != "" && strings.EqualFold(strings.TrimSpace(e.Match), v.RuleID)
	case WLTypeHost:
		return strings.TrimSpace(e.Match) == v.Asset.IP
	case WLTypePort:
		return v.Asset.Port != 0 && strings.TrimSpace(e.Match) == itoa(v.Asset.Port)
	case WLTypeTitle:
		m := strings.TrimSpace(e.Match)
		return m != "" && strings.Contains(strings.ToLower(v.Title), strings.ToLower(m))
	default:
		return false
	}
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

// IsWhitelisted 判断统一漏洞模型是否命中白名单, 返回 (是否命中, 命中条目)。
// 总开关关闭 / 条目列表为空 / 漏洞为 nil 时返回 (false, nil)。
func IsWhitelisted(v *Vulnerability) (bool, WhitelistEntry) {
	if v == nil {
		return false, WhitelistEntry{}
	}
	wlMu.RLock()
	on := wlOn
	entries := wlEntries
	wlMu.RUnlock()
	if !on || len(entries) == 0 {
		return false, WhitelistEntry{}
	}
	now := time.Now()
	for _, e := range entries {
		if entryActive(e, now) && matchEntry(e, v) {
			return true, e
		}
	}
	return false, WhitelistEntry{}
}

// FilterWhitelisted 批量过滤: 返回未命中白名单的漏洞(原列表不被修改),
// 命中的漏洞在副本上打 Whitelisted=true 标记(调用方可自行保留展示)。
// 返回 (保留列表, 被白名单过滤掉的副本列表)。
func FilterWhitelisted(vs []*Vulnerability) ([]*Vulnerability, []*Vulnerability) {
	var kept, filtered []*Vulnerability
	for _, v := range vs {
		if v == nil {
			continue
		}
		hit, _ := IsWhitelisted(v)
		if hit {
			c := *v
			c.Whitelisted = true
			filtered = append(filtered, &c)
		} else {
			kept = append(kept, v)
		}
	}
	return kept, filtered
}

// AddWhitelistEntry 新增白名单条目并持久化。
// 自动补全 ID(空时)与 Created(零值时), 重复 ID 直接覆盖;
// 写入条目视为用户显式操作, 自动开启白名单总开关。
// 返回 (最终条目, 错误); type/match 非法返回错误不落盘。
func AddWhitelistEntry(e WhitelistEntry) (WhitelistEntry, error) {
	e.Type = strings.ToLower(strings.TrimSpace(e.Type))
	e.Match = strings.TrimSpace(e.Match)
	switch e.Type {
	case WLTypeCVE, WLTypeRule, WLTypeHost, WLTypePort, WLTypeTitle:
	default:
		return WhitelistEntry{}, fmt.Errorf("未知白名单类型: %s (仅支持 %s/%s/%s/%s/%s)",
			e.Type, WLTypeCVE, WLTypeRule, WLTypeHost, WLTypePort, WLTypeTitle)
	}
	if e.Match == "" {
		return WhitelistEntry{}, fmt.Errorf("白名单匹配值不能为空")
	}
	if e.ID == "" {
		e.ID = "wl-" + e.Type + "-" + e.Match
	}
	if e.Created.IsZero() {
		e.Created = time.Now()
	}
	e.Enabled = true // 新增条目默认启用(JSON 布尔无法区分"未设置"与"显式关闭")

	wlMu.Lock()
	// 重复 ID 覆盖
	for i := range wlEntries {
		if wlEntries[i].ID == e.ID {
			wlEntries[i] = e
			wlOn = true
			wlMu.Unlock()
			return e, SaveWhitelist()
		}
	}
	wlEntries = append(wlEntries, e)
	wlOn = true // 显式操作 = 启用
	wlMu.Unlock()
	return e, SaveWhitelist()
}

// RemoveWhitelistEntry 按 ID 删除白名单条目并持久化, 返回是否删除成功
func RemoveWhitelistEntry(id string) (bool, error) {
	wlMu.Lock()
	for i := range wlEntries {
		if wlEntries[i].ID == id {
			wlEntries = append(wlEntries[:i], wlEntries[i+1:]...)
			wlMu.Unlock()
			return true, SaveWhitelist()
		}
	}
	wlMu.Unlock()
	return false, nil
}
