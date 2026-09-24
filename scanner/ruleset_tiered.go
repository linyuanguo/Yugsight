//go:build !windows || windows

// ruleset_tiered.go 体积分级加载策略(控制内存占用, 任务 2 检查点 4)。
//
// 策略(默认关闭, SetTieredLoad(true) 启用; 关闭时与原有行为完全一致):
//   - 常驻(resident): 内置基础包(Builtin)与高危(critical/high)模板常驻内存,
//     保证高危漏洞始终可验证
//   - 按需(ondemand): 非高危且原始文件体积超过阈值(默认 512KB)的大体量低频
//     模板非常驻 —— 规则集加载完成后解析对象即从常驻集剔除, 只保留轻量
//     元数据(ID / 路径 / 严重级 / 体积, 每条几十字节)
//
// 按需加载闭环:
//   - LoadOnDemand(ids): 扫描开始前按计划从磁盘解析进工作集(首次访问也可
//     经 GetRuleByID 自动触发懒加载)
//   - ReleaseOnDemand(): 扫描结束调用, 释放工作集内存
//   - 兜底: 工作集闲置超过 10 分钟自动释放(防调用方漏调)
//
// 与 ruleset.go 的衔接(调用方需持有 rulesMu, 见各内部函数注释):
//   - rulesLocked 合并后调用 splitTiered 做分级拆分
//   - Rules / GetRuleByID / RuleCount 经 effectiveRulesLocked /
//     loadOnDemandLocked / ondemandMetaCountLocked 拿到"有效规则集"
//
// 依赖: 仅 Go 标准库。
package scanner

import (
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 加载层级标记
const (
	TierResident = "resident" // 常驻: 内置基础包 + 高危模板
	TierOnDemand = "ondemand" // 按需: 大体量低频模板
)

const defaultOnDemandKB = 512 // 按需阈值默认 512KB(原始文件字节)

var onDemandIdle = 10 * time.Minute // 工作集闲置自动释放阈值(测试可调整)

var (
	tierMu     sync.Mutex
	tierOn     bool
	onDemandKB = defaultOnDemandKB
	tierMeta   map[string]RuleMeta // 按需模板元数据(id -> 轻量元数据, 不含解析对象)
	tierBytes  int64               // 按需模板原始总字节(可节省内存量)
	working    map[string]Rule     // 当前已加载进内存的按需模板(工作集)
	lastUsed   time.Time           // 工作集最近一次访问时间
	tierWGonce sync.Once           // 后台闲置释放协程(进程级一次)
)

// RuleMeta 按需模板的轻量元数据(常驻内存, 单条几十字节)
type RuleMeta struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Severity string `json:"severity,omitempty"`
	Size     int64  `json:"size"`  // 原始文件字节
	Builtin  bool   `json:"builtin"`
	Tier     string `json:"tier"` // 胜出来源层级(builtin / official / custom)
}

// TierStat 分级加载统计(供 /api 展示)
type TierStat struct {
	Enabled       bool   `json:"enabled"`
	ThresholdKB   int    `json:"thresholdKB"`
	ResidentCount int    `json:"residentCount"`  // 常驻规则数
	OnDemandCount int    `json:"onDemandCount"`  // 按需规则数(未加载, 仅元数据)
	OnDemandBytes int64  `json:"onDemandBytes"`  // 按需模板原始总字节(即节省的内存量级)
	LoadedCount   int    `json:"loadedCount"`    // 工作集当前已加载数
	LastUsed      string `json:"lastUsed,omitempty"`
}

// SetTieredLoad 分级加载总开关(默认关闭; 关闭时规则集全量常驻, 行为与原实现一致)
func SetTieredLoad(on bool) {
	tierMu.Lock()
	tierOn = on
	tierMu.Unlock()
}

// TieredLoadOn 返回分级加载开关状态
func TieredLoadOn() bool {
	tierMu.Lock()
	on := tierOn
	tierMu.Unlock()
	return on
}

// SetOnDemandThreshold 设置按需阈值(KB); kb <= 0 恢复默认 512KB
func SetOnDemandThreshold(kb int) {
	tierMu.Lock()
	if kb <= 0 {
		kb = defaultOnDemandKB
	}
	onDemandKB = kb
	tierMu.Unlock()
}

func onDemandThreshold() int64 {
	tierMu.Lock()
	defer tierMu.Unlock()
	return int64(onDemandKB) << 10
}

// ruleTierOf 纯函数: 按"高危基础包常驻 / 大体量低频按需"判定单条规则的加载层级。
// 判定顺序: 内置基础包 -> 常驻; 高危(critical/high) -> 常驻;
// 非高危且文件体积超阈值 -> 按需; 其余 -> 常驻(小文件常驻无内存压力, 安全默认)。
func ruleTierOf(r Rule) string {
	if r.Builtin {
		return TierResident
	}
	if ruleSeverityHigh(r) {
		return TierResident
	}
	if fileSize64(r.Path) > onDemandThreshold() {
		return TierOnDemand
	}
	return TierResident
}

func ruleSeverityHigh(r Rule) bool {
	if r.Info == nil {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(r.Info.Severity))
	return s == "critical" || s == "high"
}

func fileSize64(p string) int64 {
	if p == "" {
		return 0
	}
	st, err := os.Stat(p)
	if err != nil || st == nil {
		return 0
	}
	return st.Size()
}

// ===== 分级拆分(rulesLocked 内调用, 需持有 rulesMu) =====

// splitTiered 对三级合并集做分级拆分: 按需模板的解析对象从常驻集剔除
// (merged / mergedByID 只保留常驻规则), 元数据记入 tierMeta;
// 工作集整体重建(规则集变化后旧工作集失效)。开关关闭时为空操作。
func splitTiered(merged *[]Rule, mergedByID *map[string]Rule, tierOf map[string]string) {
	if !TieredLoadOn() {
		return
	}
	resident := make([]Rule, 0, len(*merged))
	meta := make(map[string]RuleMeta, 16)
	var metaBytes int64
	for _, r := range *merged {
		if ruleTierOf(r) == TierOnDemand {
			m := RuleMeta{ID: r.ID, Path: r.Path, Size: fileSize64(r.Path), Builtin: r.Builtin, Tier: tierOf[r.ID]}
			if r.Info != nil {
				m.Severity = r.Info.Severity
			}
			meta[r.ID] = m
			metaBytes += m.Size
			delete(*mergedByID, r.ID) // 剔除解析对象, 交给 GC
			continue
		}
		resident = append(resident, r)
	}
	tierMu.Lock()
	tierMeta = meta
	tierBytes = metaBytes
	working = make(map[string]Rule)
	lastUsed = time.Time{}
	tierMu.Unlock()
	*merged = resident
	if len(meta) > 0 {
		ruleLog.Info("分级加载: 按需模板已剔除出常驻集",
			"onDemand", len(meta), "evictedBytes", metaBytes, "thresholdKB", onDemandThreshold()>>10)
	}
}

// effectiveRulesLocked 有效规则集(需持有 rulesMu):
// 关闭 = merged(与原行为一致); 开启 = 常驻 + 按需工作集(按 ID 排序, 确定序)。
func effectiveRulesLocked() []Rule {
	if !TieredLoadOn() {
		return merged
	}
	tierMu.Lock()
	defer tierMu.Unlock()
	out := make([]Rule, 0, len(merged)+len(working))
	out = append(out, merged...)
	if len(working) > 0 {
		ids := make([]string, 0, len(working))
		for id := range working {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			out = append(out, working[id])
		}
	}
	return out
}

// ondemandMetaCountLocked 按需模板数量(需持有 rulesMu, 读 tierMu 极短临界区)
func ondemandMetaCountLocked() int {
	tierMu.Lock()
	defer tierMu.Unlock()
	return len(tierMeta)
}

// ===== 按需加载 / 释放 =====

// LoadOnDemand 按需加载指定的按需模板(从磁盘解析并缓存进工作集)。
// 返回 (成功加载数, 警告列表)。常驻/未知 ID 不重复加载, 记入警告。
// 典型用法: 扫描开始前按计划加载本批资产需要的模板, 扫描结束调 ReleaseOnDemand。
func LoadOnDemand(ids []string) (int, []string) {
	var warns []string
	loaded := 0
	if !TieredLoadOn() {
		for _, id := range ids {
			if s := strings.TrimSpace(id); s != "" {
				warns = append(warns, s+": 分级加载未启用(无需按需加载, 规则集已全量常驻)")
			}
		}
		return 0, warns
	}
	rulesMu.Lock()
	rulesLocked(false)
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if n, w := loadOnDemandLocked(id); n > 0 {
			loaded++
		} else {
			warns = append(warns, w)
		}
	}
	rulesMu.Unlock()
	return loaded, warns
}

// loadOnDemandLocked 单条按需模板懒加载(需持有 rulesMu)。
// 常驻规则直接命中; 工作集命中则刷新访问时间; 否则从磁盘重新解析进工作集。
func loadOnDemandLocked(id string) (int, string) {
	if _, ok := mergedByID[id]; ok {
		return 1, "" // 常驻规则: 已在内存
	}
	tierMu.Lock()
	if _, ok := working[id]; ok {
		lastUsed = time.Now()
		tierMu.Unlock()
		return 1, ""
	}
	m, ok := tierMeta[id]
	tierMu.Unlock()
	if !ok {
		return 0, id + ": 非按需模板(未知 ID)"
	}
	data, err := os.ReadFile(m.Path)
	if err != nil {
		return 0, id + ": 磁盘读取失败 " + err.Error()
	}
	tpl, perr := ParseNucleiTemplate(data)
	if perr != nil {
		return 0, id + ": 解析失败 " + perr.Error()
	}
	if tpl == nil {
		return 0, id + ": 非 HTTP 模板"
	}
	tpl.SHA256 = sha256Hex(data)
	tpl.Builtin = m.Builtin
	tierMu.Lock()
	working[id] = *tpl
	lastUsed = time.Now()
	tierMu.Unlock()
	startTierAutoRelease()
	return 1, ""
}

// ReleaseOnDemand 释放按需工作集(归还内存), 元数据保留, 下次访问可重新加载。
// 返回释放的规则数。扫描结束应调用本函数控制内存占用。
func ReleaseOnDemand() int {
	tierMu.Lock()
	n := len(working)
	working = make(map[string]Rule)
	lastUsed = time.Time{}
	tierMu.Unlock()
	if n > 0 {
		ruleLog.Info("按需模板工作集已释放", "count", n)
	}
	return n
}

// startTierAutoRelease 启动后台闲置释放协程(进程级一次, 1 分钟巡检)
func startTierAutoRelease() {
	tierWGonce.Do(func() {
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for range t.C {
				checkIdleRelease(time.Now())
			}
		}()
	})
}

// checkIdleRelease 工作集闲置超过阈值时自动释放; 返回是否发生释放。
// now 注入时间便于测试(生产由后台巡检协程以 time.Now() 调用)。
func checkIdleRelease(now time.Time) bool {
	tierMu.Lock()
	defer tierMu.Unlock()
	if len(working) == 0 || lastUsed.IsZero() {
		return false
	}
	if now.Sub(lastUsed) >= onDemandIdle {
		working = make(map[string]Rule)
		lastUsed = time.Time{}
		ruleLog.Info("按需模板工作集闲置超时, 自动释放")
		return true
	}
	return false
}

// ===== 统计 =====

// TieredStats 返回分级加载统计(供 /api/rules/update/status 展示)
func TieredStats() TierStat {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	tierMu.Lock()
	defer tierMu.Unlock()
	st := TierStat{
		Enabled:       tierOn,
		ThresholdKB:   onDemandKB,
		ResidentCount: len(merged),
		OnDemandCount: len(tierMeta),
		OnDemandBytes: tierBytes,
		LoadedCount:   len(working),
	}
	if !lastUsed.IsZero() {
		st.LastUsed = lastUsed.Format("2006-01-02 15:04:05")
	}
	return st
}
