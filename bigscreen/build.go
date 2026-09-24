package bigscreen

import (
	"encoding/json"
	"math"
	"sort"
	"time"

	"yugsight/db"
	"yugsight/models"
)

// Options 聚合参数(全部可选, 零值即默认)。
type Options struct {
	Days       int  // 趋势天数(默认 7)
	TopN       int  // TOP 榜条数(默认 10)
	MaxRecent  int  // 最近任务条数(默认 8)
	IncludeFP  bool // 是否把误报标记的漏洞计入风险指标(默认 false = 排除)
}

// withDefaults 填充默认值并做上下限钳制。
//
// 钳制上界不是洁癖: Days 直接决定响应里的点数, TopN/MaxRecent 决定数组长度,
// 都是前端可传参的, 不设上限等于把响应体积交给调用方控制。
func (o Options) withDefaults() Options {
	if o.Days < 1 {
		o.Days = TrendDays
	}
	if o.Days > 90 {
		o.Days = 90
	}
	if o.TopN < 1 {
		o.TopN = MaxTopList
	}
	if o.TopN > 50 {
		o.TopN = 50
	}
	if o.MaxRecent < 1 {
		o.MaxRecent = 8
	}
	if o.MaxRecent > 50 {
		o.MaxRecent = 50
	}
	return o
}

// Build 聚合大屏快照。
//
// 降级策略: 任一 DAO 查询失败只记入 Warnings 并跳过该段(对应指标保持零值),
// 而不是整包失败 —— 大屏是常驻监看页, 因为"某张表读失败"就让整屏空白,
// 运维会误判成"系统挂了", 实际可能只是审计/报告表不可用。
func Build(d *db.Database, now time.Time, opt Options) *Snapshot {
	opt = opt.withDefaults()
	snap := &Snapshot{
		GeneratedAt: now,
		TrendDays:   opt.Days,
		Severity:    []SevBar{},
		Probes:      []ProbeNode{},
		TopVulns:    []TopVuln{},
		TopAssets:   []TopAsset{},
		RecentTasks: []TaskBrief{},
	}
	if d == nil {
		// 库不可用时仍返回结构完整的快照(趋势点/等级项/数组齐备):
		// 前端拿到的是"零值 + 告警"而非字段缺失, 渲染逻辑无需到处判空。
		snap.Warnings = append(snap.Warnings, "数据库不可用(大屏数据来源缺失)")
		snap.Trend = buildTrendFromAgg(dayStart(now).AddDate(0, 0, -(opt.Days-1)), opt.Days, nil, nil)
		snap.Severity = buildSevBars(SevCount{})
		return snap
	}
	warn := func(msg string) { snap.Warnings = append(snap.Warnings, msg) }

	// ===== 资产 =====
	// Count/CountAlive 单遍计数, 不再全表 List() 拷贝 —— 资产表只贡献两个数字。
	if dao := d.Assets(); dao != nil {
		if n, err := dao.Count(); err != nil {
			warn("资产查询失败: " + err.Error())
		} else {
			snap.Overview.Assets = n
		}
		if n, err := dao.CountAlive(); err != nil {
			warn("存活资产统计失败: " + err.Error())
		} else {
			snap.Overview.AssetsAlive = n
		}
	}
	snap.Overview.AssetsDown = snap.Overview.Assets - snap.Overview.AssetsAlive

	// ===== 漏洞 =====
	// 单遍聚合(db.VulnDAO.ScreenAgg, 带写入代数失效的 TTL 缓存): 一次遍历算出
	// 总数/修复/误报/等级分布/趋势分桶/今日新增/资产风险聚合/风险列表。
	// 取代原先"List() 全表拷贝 + 4 遍重复遍历"—— 大屏 15s 轮询下这是最大的 CPU 浪费点。
	today := dayStart(now)
	start := today.AddDate(0, 0, -(opt.Days - 1))
	var vagg *db.VulnScreenAgg
	if dao := d.Vulns(); dao != nil {
		aggOut, aggErr := dao.ScreenAgg(start, opt.Days, opt.IncludeFP)
		if aggErr != nil {
			warn("漏洞查询失败: " + aggErr.Error())
		} else {
			vagg = aggOut
		}
	}
	risky := make([]*db.Vuln, 0)
	if vagg != nil {
		snap.Overview.VulnTotal = vagg.Total
		snap.Overview.VulnFixed = vagg.Fixed
		snap.Overview.FalsePosCount = vagg.FalsePos
		for sev, n := range vagg.Sev {
			snap.Overview.Vulns.add(sev, n)
		}
		// 趋势: 新增按 FoundAt, 修复按 FixedAt(口径说明见 db.VulnDAO.ScreenAgg 注释)
		snap.Trend = buildTrendFromAgg(start, opt.Days, vagg.TrendNew, vagg.TrendFixed)
		snap.Overview.FindingsWeek = snap.Trend.NewTotal
		snap.Overview.FixedWeek = snap.Trend.FixedTotal
		snap.Overview.FindingsToday = vagg.FindingsToday
		risky = vagg.Risky
	}

	// 风险占比
	snap.Severity = buildSevBars(snap.Overview.Vulns)

	// TOP 高危漏洞 + 风险资产(资产风险聚合已在 ScreenAgg 单遍内算好;
	// vagg 为 nil = 漏洞段降级, 榜单保持空而不是 panic)
	agg := make(map[string]*assetRisk)
	if vagg != nil {
		agg = make(map[string]*assetRisk, len(vagg.AssetRisk))
		for ip, a := range vagg.AssetRisk {
			agg[ip] = &assetRisk{risk: a.Risk, critical: a.Critical, high: a.High}
		}
	}
	snap.TopVulns = buildTopVulns(risky, opt.TopN)
	snap.TopAssets = buildTopAssets(d, agg, opt.TopN, warn)

	// ===== 探针 =====
	if dao := d.Probes(); dao != nil {
		list, err := dao.List()
		if err != nil {
			warn("探针查询失败: " + err.Error())
		} else {
			snap.Overview.Probes = len(list)
			snap.Probes = buildProbes(list)
			for _, p := range snap.Probes {
				if p.Online {
					snap.Overview.ProbesOnline++
				} else {
					snap.Overview.ProbesOffline++
				}
			}
		}
	}

	// ===== 任务 =====
	if dao := d.ScanTasks(); dao != nil {
		list, err := dao.List()
		if err != nil {
			warn("任务查询失败: " + err.Error())
		} else {
			for _, t := range list {
				switch t.Status {
				case db.TaskRunning, db.TaskPending:
					snap.Overview.TasksRunning++
				case db.TaskSuccess:
					snap.Overview.TasksSuccess++
				case db.TaskFailed, db.TaskCancelled:
					snap.Overview.TasksFailed++
				}
				// 今日=按自然日, 用 CreatedAt 而非 StartedAt: 排队中的任务没有
				// StartedAt, 用它会让"今天提交的还没跑"的任务从今日统计消失。
				if t.CreatedAt.After(today) || t.CreatedAt.Equal(today) {
					snap.Overview.TasksToday++
				}
			}
			snap.RecentTasks = buildRecentTasks(list, opt.MaxRecent)
		}
	}

	// ===== 管控数据(白名单) =====
	// 误报计数已在 ScreenAgg 单遍内算出(Overview.FalsePosCount), 不再二次遍历漏洞表。
	if dao := d.Whitelists(); dao != nil {
		if list, err := dao.EnabledOnly(); err == nil {
			snap.Overview.WhitelistCount = len(list)
		}
	}
	return snap
}

// sevOf 归一化等级(复用 models 的口径, 保证与漏洞列表/报告一致)。
func sevOf(s string) string { return models.NormalizeSeverity(s) }

// buildTrendFromAgg 用 db 层单遍聚合好的日计数组装趋势图。
//
// 分桶在 db.VulnDAO.ScreenAgg 内完成(自然日分桶而非 24 小时滑窗: 大屏是给人
// 看的日历图, "9-16 新增 3 条"必须等于当天 00:00~24:00, 否则用户按日期核对
// 漏洞列表时永远对不上), 这里只负责日期标签与合计。
func buildTrendFromAgg(start time.Time, days int, newByDay, fixedByDay []int) Trend {
	t := Trend{Days: days, Points: make([]TrendPoint, days)}
	for i := 0; i < days; i++ {
		d := start.AddDate(0, 0, i)
		p := TrendPoint{Date: d.Format("2006-01-02"), Label: d.Format("01-02")}
		if i < len(newByDay) {
			p.New = newByDay[i]
		}
		if i < len(fixedByDay) {
			p.Fixed = fixedByDay[i]
		}
		p.Opened = p.New - p.Fixed
		t.Points[i] = p
		t.NewTotal += p.New
		t.FixedTotal += p.Fixed
	}
	return t
}

// dayStart 取某时刻所在自然日的 00:00(本地时区)。
func dayStart(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func dayKey(t time.Time) string { return t.Format("2006-01-02") }

// buildSevBars 计算各等级占比。
//
// 占比基数用"风险类合计"(不含 info): info 是加固建议而非风险, 混进分母会把
// 严重漏洞的占比稀释到无意义的小数(上百条 info 能让 10 条严重只占 5%)。
// info 本身仍作为一项返回(Count 有值, Pct 为 0), 前端可单独展示数量。
func buildSevBars(c SevCount) []SevBar {
	base := float64(c.Risk)
	out := make([]SevBar, 0, len(SevOrder))
	for _, k := range SevOrder {
		n := sevCountOf(c, k)
		bar := SevBar{Key: k, Count: n}
		if base > 0 && k != SevInfo {
			bar.Pct = math.Round(float64(n)/base*1000) / 10
		}
		out = append(out, bar)
	}
	return out
}

// sevCountOf 取某等级计数。
func sevCountOf(c SevCount, key string) int {
	switch key {
	case SevCritical:
		return c.Critical
	case SevHigh:
		return c.High
	case SevMedium:
		return c.Medium
	case SevLow:
		return c.Low
	case SevInfo:
		return c.Info
	}
	return 0
}

// buildTopVulns 生成高危漏洞 TOP 榜。
//
// 排序: 严重级别降序 -> CVSS 降序 -> 置信度降序 -> 首次发现时间升序。
// 最后一项不是凑数: 同级同分时"更早发现还挂着的"更该被优先处理, 且能让
// 相同数据的排序结果稳定(否则前端每次刷新榜单顺序跳动, 看着像数据在变)。
func buildTopVulns(list []*db.Vuln, n int) []TopVuln {
	items := make([]*db.Vuln, len(list))
	copy(items, list)
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if ra, rb := severityRank(sevOf(a.Severity)), severityRank(sevOf(b.Severity)); ra != rb {
			return ra > rb
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.FoundAt.Before(b.FoundAt)
	})
	if len(items) > n {
		items = items[:n]
	}
	out := make([]TopVuln, 0, len(items))
	for _, v := range items {
		out = append(out, TopVuln{
			ID: v.ID, AssetIP: v.AssetIP, Port: v.Port, Protocol: v.Protocol,
			Severity: sevOf(v.Severity), Title: v.Title, CVE: v.CVE, CVSS: v.CVSS,
			Confidence: v.Confidence, Source: v.Source,
			FoundAt: v.FoundAt, LastSeenAt: v.LastSeenAt,
		})
	}
	return out
}

// severityRank 等级排序权重(越大越严重)。
func severityRank(sev string) int {
	switch sev {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// buildTopAssets 生成风险资产排行(按风险类漏洞数降序, IP 升序保稳定)。
//
// 资产基础信息(主机名/OS/端口数)从资产表补齐; 漏洞涉及的 IP 若不在资产表里
// (例如资产已被清理、或漏洞是经 API 直接回传的), 仍会出现在榜单上并保留 IP ——
// 漏掉它们会得到"有 20 条高危漏洞但 TOP 资产是空的"这种自相矛盾的大屏。
func buildTopAssets(d *db.Database, agg map[string]*assetRisk, n int, warn func(string)) []TopAsset {
	// 只取榜单上那几十个 IP 的资产信息(GetMany 单遍找齐早退), 不再全表 List() 拷贝。
	ips := make([]string, 0, len(agg))
	for ip := range agg {
		ips = append(ips, ip)
	}
	meta := map[string]*db.Asset{}
	if dao := d.Assets(); dao != nil {
		if got, err := dao.GetMany(ips); err == nil {
			meta = got
		} else {
			warn("风险资产详情补齐失败: " + err.Error())
		}
	}
	out := make([]TopAsset, 0, len(agg))
	for ip, a := range agg {
		it := TopAsset{IP: ip, Risk: a.risk, Critical: a.critical, High: a.high}
		if m := meta[ip]; m != nil {
			it.Hostname = m.Hostname
			it.OS = m.OS
			it.OpenPorts = len(m.Ports)
		}
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// buildProbes 组装探针状态与负载。
func buildProbes(list []*db.Probe) []ProbeNode {
	out := make([]ProbeNode, 0, len(list))
	for _, p := range list {
		n := ProbeNode{
			ID: p.ID, Name: p.Name, Status: p.Status, Online: p.Status == db.ProbeOnline,
			Addr: p.Addr, Capabilities: p.Capabilities,
			TaskTotal: p.TaskTotal, TaskSuccess: p.TaskSuccess, TaskFailed: p.TaskFailed,
			LastSeenAt: p.LastSeenAt,
		}
		// Load / NodeInfo 在 db 层是 any(弱类型, 避免 db 依赖 probe 包),
		// 这里经 JSON 往返解析成本低且天然容错: 字段缺失/类型不符都不会 panic,
		// 只是拿不到该指标。直接断言具体类型会因探针版本差异而失败。
		var load struct {
			CPUPercent   float64 `json:"cpuPercent"`
			MemPercent   float64 `json:"memPercent"`
			TasksRunning int     `json:"tasksRunning"`
			CurrentTask  string  `json:"currentTask"`
		}
		if decodeAny(p.Load, &load) {
			n.CPUPercent = floatPtr(load.CPUPercent)
			n.MemPercent = floatPtr(load.MemPercent)
			n.TasksRunning = load.TasksRunning
			n.CurrentTask = load.CurrentTask
		}
		var ni struct {
			Hostname  string `json:"hostname"`
			OS        string `json:"os"`
			CPUCores  int    `json:"cpuCores"`
			MemTotal  uint64 `json:"memTotal"`
			MemUsed   uint64 `json:"memUsed"`
			DiskTotal uint64 `json:"diskTotal"`
			DiskUsed  uint64 `json:"diskUsed"`
		}
		if decodeAny(p.NodeInfo, &ni) {
			n.Hostname, n.OS, n.CPUCores = ni.Hostname, ni.OS, ni.CPUCores
			n.MemTotal, n.MemUsed = ni.MemTotal, ni.MemUsed
			if ni.DiskTotal > 0 {
				n.DiskPercent = floatPtr(float64(ni.DiskUsed) / float64(ni.DiskTotal) * 100)
			}
			// 心跳未带负载时用节点信息里的内存占用兜底(注册信息里有 MemUsed),
			// 否则面板会显示"-", 而实际上内存占用是已知的。
			if n.MemPercent == nil && ni.MemTotal > 0 {
				n.MemPercent = floatPtr(float64(ni.MemUsed) / float64(ni.MemTotal) * 100)
			}
		}
		out = append(out, n)
	}
	// 在线优先, 再按名称/ID 稳定排序(离线节点排后面但仍在榜, 便于发现掉线)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// buildRecentTasks 最近任务列表(按创建时间倒序)。
func buildRecentTasks(list []*db.ScanTask, n int) []TaskBrief {
	items := make([]*db.ScanTask, len(list))
	copy(items, list)
	sort.SliceStable(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	if len(items) > n {
		items = items[:n]
	}
	out := make([]TaskBrief, 0, len(items))
	for _, t := range items {
		out = append(out, TaskBrief{
			ID: t.ID, Type: t.Type, Target: t.Target, Status: t.Status,
			ProbeNode: t.ProbeNode, CreatedAt: t.CreatedAt, FinishedAt: t.FinishedAt,
		})
	}
	return out
}

// decodeAny 把 db 层的弱类型字段(any)解析为目标结构。
//
// 走 JSON 往返而非类型断言的收益: 即便某天探针上报结构体换成 map/string,
// 或者字段增删, 这里都不会 panic, 最坏只是解析失败返回 false。
func decodeAny(v any, out any) bool {
	if v == nil {
		return false
	}
	// 已是字节流直接解(测试与内部调用可能直接塞 []byte)
	if b, ok := v.([]byte); ok {
		return json.Unmarshal(b, out) == nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, out) == nil
}

func floatPtr(f float64) *float64 {
	v := math.Round(f*10) / 10
	return &v
}
