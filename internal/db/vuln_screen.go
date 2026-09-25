package db

import (
	"strconv"
	"sync"
	"time"

	"yugsight/internal/models"
)

// 漏洞表大屏聚合(任务: db 聚合下推)。
//
// 背景: JSONL 文件引擎的数据常驻内存(Table.items map), "聚合慢"不在磁盘 I/O,
// 而在"全表 List() 拷贝 + 上层多次重复遍历" —— 大屏 15s 轮询一次, 每次把漏洞表
// 拷一遍再走 4 遍(risky 过滤/趋势分桶/资产聚合/误报计数), 十万级数据下每秒浪费
// 几十毫秒纯 CPU 在重复遍历上。本文件把"大屏一次轮询需要的全部漏洞统计"合并为
// DAO 侧单遍遍历, 并配写入代数失效的 TTL 缓存(同一轮询窗口内的重复请求零遍历)。
//
// 口径与 bigscreen.Build 既有逻辑逐条一致(那是报告/大屏共同的数据契约, 改口径
// 会让大屏数字与漏洞列表对不上):
//
//	Total        全部漏洞(含 fixed 与误报)
//	Fixed        status == fixed
//	FalsePos     FalsePositive == true
//	Sev          风险类分布(排除 fixed; 误报按 includeFP 决定是否排除; 等级经 NormalizeSeverity)
//	TrendNew     按自然日新增(FoundAt 落在 days 窗口内)
//	TrendFixed   按自然日修复(status==fixed 且 FixedAt 落在 days 窗口内)
//	FindingsToday FoundAt 严格晚于今日 00:00(与 Since(today) 同口径, 是 After 不是 >=)
//	AssetRisk    按资产 IP 聚合(critical/high 各计数且计入 Risk; medium/low 只计 Risk)
//	Risky        风险列表指针引用(供 TOP 榜排序, 不拷贝实体)

// AssetRiskAgg 单资产的风险聚合(与 bigscreen.assetRisk 同口径)。
type AssetRiskAgg struct {
	Risk     int
	Critical int
	High     int
}

// VulnScreenAgg 漏洞表单遍聚合结果。
type VulnScreenAgg struct {
	Total         int
	Fixed         int
	FalsePos      int
	Sev           map[string]int // 风险类等级分布(键为归一化等级)
	TrendNew      []int          // 长度 = days, 下标 i = 窗口第 i 天新增数
	TrendFixed    []int          // 长度 = days, 下标 i = 窗口第 i 天修复数
	FindingsToday int
	AssetRisk     map[string]*AssetRiskAgg
	Risky         []*Vuln
}

// vulnScreenCacheTTL 聚合缓存有效期。默认 15s 对齐大屏轮询间隔: 一轮询周期内
// 数据没变(Version 相同)就直接复用, 变过就重算 —— 大屏拿到的数字不会比 15s 旧。
// 测试可置 0 关闭缓存。
var vulnScreenCacheTTL = 15 * time.Second

// VulnDAO 的聚合缓存(每表一份; 字段经私有 mutex 保护)。
// 注意: 缓存字段不进 Table 泛型 —— 它是 VulnDAO 特化的统计缓存, 放 Table 会让
// 所有表背上一个用不上的锁。
type vulnScreenCache struct {
	mu    sync.Mutex
	ver   uint64
	key   string
	at    time.Time
	val   *VulnScreenAgg
}

// ScreenAgg 单遍计算大屏所需的全部漏洞统计(带 TTL 缓存)。
//
// start 为趋势窗口起点(通常为 dayStart(now).AddDate(0,0,-(days-1))); days 为窗口
// 天数; includeFP=true 时误报计入风险分布(默认 false = 排除, 与报告导出同口径)。
//
// 缓存键 = 表写入代数 + 参数三元组: 数据一变代数即变, 旧结果自动作废, 无需写路径
// 挂失效钩子。命中的结果返回浅拷贝(切片复制, Risky 的实体指针共享 —— 调用方只读)。
func (d *VulnDAO) ScreenAgg(start time.Time, days int, includeFP bool) (*VulnScreenAgg, error) {
	if days < 1 {
		days = 1
	}
	if days > 366 {
		days = 366
	}
	key := cacheKey(start, days, includeFP)

	t := d.Table
	if t != nil {
		if c := d.screenCache(); c != nil && vulnScreenCacheTTL > 0 {
			c.mu.Lock()
			if c.val != nil && c.key == key && c.ver == t.Version() &&
				time.Since(c.at) < vulnScreenCacheTTL {
				v := c.val
				c.mu.Unlock()
				return v.copy(), nil
			}
			c.mu.Unlock()
		}
	}

	agg, err := d.computeScreenAgg(start, days, includeFP)
	if err != nil {
		return nil, err
	}
	if t != nil {
		if c := d.screenCache(); c != nil && vulnScreenCacheTTL > 0 {
			c.mu.Lock()
			c.val, c.key, c.ver, c.at = agg, key, t.Version(), time.Now()
			c.mu.Unlock()
		}
	}
	return agg, nil
}

// computeScreenAgg 单遍遍历全部漏洞, 产出聚合(无缓存, 纯计算)。
func (d *VulnDAO) computeScreenAgg(start time.Time, days int, includeFP bool) (*VulnScreenAgg, error) {
	list, err := d.List()
	if err != nil {
		return nil, err
	}
	// 日首索引: 与 bigscreen 趋势图同口径(自然日分桶而非 24h 滑窗)
	idx := make(map[int64]int, days)
	for i := 0; i < days; i++ {
		d := start.AddDate(0, 0, i)
		idx[dayUnix(d)] = i
	}
	today := start.AddDate(0, 0, days - 1)

	agg := &VulnScreenAgg{
		Sev:       map[string]int{},
		TrendNew:  make([]int, days),
		TrendFixed: make([]int, days),
		AssetRisk: map[string]*AssetRiskAgg{},
	}
	for _, v := range list {
		agg.Total++
		fixed := v.Status == models.VulnStatusFixed
		if fixed {
			agg.Fixed++
		}
		if v.FalsePositive {
			agg.FalsePos++
		}
		// 趋势两方向各用不同字段(口径提醒: 新增=FoundAt, 修复=FixedAt;
		// 不能都用 LastSeenAt, 否则老漏洞重新命中会被误报成新增)
		if !v.FoundAt.IsZero() {
			if i, ok := idx[dayUnix(v.FoundAt)]; ok {
				agg.TrendNew[i]++
			}
			if v.FoundAt.After(today) {
				agg.FindingsToday++
			}
		}
		if fixed && v.FixedAt != nil {
			if i, ok := idx[dayUnix(*v.FixedAt)]; ok {
				agg.TrendFixed[i]++
			}
		}
		if fixed || (v.FalsePositive && !includeFP) {
			continue
		}
		sev := models.NormalizeSeverity(v.Severity)
		agg.Sev[sev]++
		a := agg.AssetRisk[v.AssetIP]
		if a == nil {
			a = &AssetRiskAgg{}
			agg.AssetRisk[v.AssetIP] = a
		}
		switch sev {
		case "critical":
			a.Critical++
			a.Risk++
		case "high":
			a.High++
			a.Risk++
		case "medium", "low":
			a.Risk++
		}
		agg.Risky = append(agg.Risky, v)
	}
	return agg, nil
}

// copy 浅拷贝: 切片复制, Risky 的实体指针共享(调用方只读, 不修改实体字段)。
func (a *VulnScreenAgg) copy() *VulnScreenAgg {
	out := &VulnScreenAgg{
		Total: a.Total, Fixed: a.Fixed, FalsePos: a.FalsePos,
		FindingsToday: a.FindingsToday,
	}
	out.Sev = make(map[string]int, len(a.Sev))
	for k, v := range a.Sev {
		out.Sev[k] = v
	}
	out.TrendNew = append([]int(nil), a.TrendNew...)
	out.TrendFixed = append([]int(nil), a.TrendFixed...)
	out.AssetRisk = make(map[string]*AssetRiskAgg, len(a.AssetRisk))
	for k, v := range a.AssetRisk {
		cp := *v
		out.AssetRisk[k] = &cp
	}
	out.Risky = append([]*Vuln(nil), a.Risky...)
	return out
}

// screenCache 聚合缓存访问器(VulnDAO 惰性持有; 表关闭后置 nil 语义由调用方守卫)。
func (d *VulnDAO) screenCache() *vulnScreenCache {
	if d == nil || d.Table == nil {
		return nil
	}
	return d.cache
}

// dayUnix 取某时刻所在自然日的 00:00 Unix 秒(本地时区) —— 用作分桶索引,
// 与 bigscreen.dayStart 同口径。
func dayUnix(t time.Time) int64 {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location()).Unix()
}

// cacheKey 聚合缓存参数键(参数三元组序列化, 参数不同则缓存不复用)。
func cacheKey(start time.Time, days int, includeFP bool) string {
	return start.Format(time.RFC3339Nano) + "/" + strconv.Itoa(days) + "/" + strconv.FormatBool(includeFP)
}
