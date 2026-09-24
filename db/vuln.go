package db

import (
	"errors"
	"strings"
	"time"

	"yugsight/models"
)

// Vuln 漏洞表实体。
// 内嵌 models.Vuln 保证与归一化层数据契约完全一致; 扩展关联扫描任务 ID。
type Vuln struct {
	models.Vuln
	ScanTaskID string `json:"scanTaskId,omitempty"`
}

// NewVuln 构造漏洞实体(自动计算稳定 ID)。
func NewVuln(assetIP, title, severity string) *Vuln {
	v := &Vuln{Vuln: models.Vuln{
		AssetIP:  assetIP,
		Title:    title,
		Severity: models.NormalizeSeverity(severity),
		FoundAt:  time.Now(),
		Status:   models.VulnStatusNew,
	}}
	v.ID = v.StableID()
	return v
}

// EntityID 稳定漏洞 ID(同资产+同漏洞跨扫描不变)。
func (v *Vuln) EntityID() string {
	if v.ID == "" {
		v.ID = v.StableID()
	}
	return v.ID
}

// Validate 自检: 资产 IP / 标题必填, 等级归一化, 缺省字段补全。
func (v *Vuln) Validate() error {
	if v.AssetIP == "" {
		return errors.New("漏洞资产 IP 不能为空")
	}
	if strings.TrimSpace(v.Title) == "" {
		return errors.New("漏洞标题不能为空")
	}
	v.AssetIP = models.NormIP(v.AssetIP)
	v.CVE = models.NormalizeCVE(v.CVE)
	v.Severity = models.NormalizeSeverity(v.Severity)
	if v.ID == "" {
		v.ID = v.StableID()
	}
	if v.FoundAt.IsZero() {
		v.FoundAt = time.Now()
	}
	if v.LastSeenAt.IsZero() {
		v.LastSeenAt = v.FoundAt
	}
	if v.Status == "" {
		v.Status = models.VulnStatusNew
	}
	return nil
}

// VulnQuery 漏洞多维筛选条件(空字段 = 不过滤)。
type VulnQuery struct {
	Severity string // critical|high|medium|low|info
	CVE      string // CVE 编号(归一化后精确匹配)
	AssetIP  string // 资产 IP(归一化后匹配)
	Title    string // 标题关键字(大小写不敏感包含匹配)
	Source string // 来源引擎
	Status string // new|duplicate|open|fixed; "open" 是用户两态口径 = 非 fixed
}

// Match 判断漏洞是否满足全部筛选条件。
//
// Status 的 "open" 是特殊值: 用户视角只有"开放/已修复"两态, 而库内还有
// new/duplicate/open 三个"开放"细态 —— 筛"开放"必须把它们全部纳入,
// 否则前端选"开放"会漏掉 new/duplicate 的历史数据。
func (q VulnQuery) Match(v *Vuln) bool {
	if q.Severity != "" && v.Severity != q.Severity {
		return false
	}
	if q.CVE != "" && v.CVE != q.CVE {
		return false
	}
	if q.AssetIP != "" && v.AssetIP != q.AssetIP {
		return false
	}
	if q.Title != "" && !strings.Contains(strings.ToLower(v.Title), strings.ToLower(q.Title)) {
		return false
	}
	if q.Source != "" && v.Source != q.Source {
		return false
	}
	if q.Status != "" {
		if q.Status == models.VulnStatusOpen {
			if models.IsFixedStatus(v.Status) {
				return false
			}
		} else if v.Status != q.Status {
			return false
		}
	}
	return true
}

// VulnDAO 漏洞管理 DAO: 基础 CRUD + 分页 + 多维度筛选。
type VulnDAO struct {
	*Table[*Vuln]
	// cache 大屏聚合结果缓存(按写入代数失效, TTL 见 vulnScreenCacheTTL)。
	// 放在 DAO 而非 Table: 它是 Vuln 表特化的统计缓存, 不该让泛型 Table 背负。
	cache *vulnScreenCache
}

// newVulnTable 打开漏洞表。
func newVulnTable(path string) (*VulnDAO, error) {
	t, err := NewTable[*Vuln]("vulns", path, func() *Vuln { return &Vuln{} })
	if err != nil {
		return nil, err
	}
	return &VulnDAO{Table: t, cache: &vulnScreenCache{}}, nil
}

// DeleteAll 清空全部漏洞记录, 返回删除条数(前端"清空全部漏洞"按钮)。
//
// 只清空漏洞表: 资产表是独立的"发现过的资产"清单, 不随漏洞一起清 ——
// 否则用户只想清掉漏洞数据, 却把资产台账也一起删了(不可逆)。
func (d *VulnDAO) DeleteAll() (int, error) {
	return d.Clear()
}

// Search 多维度筛选(不分页)。
func (d *VulnDAO) Search(q VulnQuery) ([]*Vuln, error) {
	return d.Query(func(v *Vuln) bool { return q.Match(v) })
}

// SearchPage 多维度筛选 + 分页, 返回页内记录与总数。
// page 从 1 起; size<=0 默认 20, 上限 200。
func (d *VulnDAO) SearchPage(q VulnQuery, page, size int) ([]*Vuln, int, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}
	all, err := d.Search(q)
	if err != nil {
		return nil, 0, err
	}
	total := len(all)
	offset := (page - 1) * size
	if offset >= total {
		return []*Vuln{}, total, nil
	}
	end := offset + size
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

// Since 查指定时间之后"出现"的漏洞(时间基准由调用方决定, 见 SinceNew / SinceLastSeen)。
//
// 显式传入 time 而非 "nDays int": 时间窗对比最容易错的不是天数, 而是
// "用哪个时间字段" —— 由调用方把语义写在参数上, 避免函数内部暗含口径。
func (d *VulnDAO) Since(t time.Time) ([]*Vuln, error) {
	return d.Query(func(v *Vuln) bool { return v.FoundAt.After(t) })
}

// SinceLastSeen 查指定时间之后"仍在被命中"的漏洞(按最后命中时间)。
//
// 【口径提醒(任务 7.2 踩过的坑)】: FoundAt 是首次发现, LastSeenAt 是最后命中,
// 跨轮次 Upsert 会覆盖。要判断"窗口内有活动的漏洞"必须用 LastSeenAt ——
// 只看 FoundAt 会把"老资产上一直存在、本轮仍在"的漏洞漏掉, 得出
// "资产已无风险"的相反结论。大屏趋势图的"新增/修复"两个方向各用其一:
//   新增 = FoundAt ∈ 窗口(首次出现在窗口内)
//   修复 = FixedAt ∈ 窗口(状态在窗口内转为 fixed)
// 不用 LastSeenAt 参与"新增", 否则老漏洞重新命中会被误报成新增。
func (d *VulnDAO) SinceLastSeen(t time.Time) ([]*Vuln, error) {
	return d.Query(func(v *Vuln) bool { return v.LastSeenAt.After(t) })
}

// Open 未修复漏洞(状态非 fixed)。
func (d *VulnDAO) Open() ([]*Vuln, error) {
	return d.Query(func(v *Vuln) bool { return v.Status != models.VulnStatusFixed })
}

// FixedSince 指定时间之后被标记修复的漏洞(按 FixedAt)。
func (d *VulnDAO) FixedSince(t time.Time) ([]*Vuln, error) {
	return d.Query(func(v *Vuln) bool {
		return v.Status == models.VulnStatusFixed && v.FixedAt != nil && v.FixedAt.After(t)
	})
}

// MarkFixed 标记漏洞已修复(置 fixed 状态与修复时间)。
func (d *VulnDAO) MarkFixed(id string) (*Vuln, error) {
	v, err := d.Get(id)
	if err != nil {
		return nil, err
	}
	v.Status = models.VulnStatusFixed
	now := time.Now()
	v.FixedAt = &now
	if err := d.Update(v); err != nil {
		return v, err
	}
	return v, nil
}
