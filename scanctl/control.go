//go:build !windows || windows

// control.go 扫描管控门面: 置信度打分 + 白名单过滤 + 误报自动标记。
//
// Controller 聚合白名单与误报两个管理器(各自基于统一 DAO 持久化),
// 对外提供单一入口 FilterVulns / CheckFinding:
//   - FilterVulns: 归一化漏洞批量处理 —— 先误报自动标记(就地打标,
//     保留展示, 报告导出时由前端排除), 再白名单过滤(命中的不进入
//     报告和统计)
//   - CheckFinding: 扫描管线 SSE finding 事件的逐条判定(白名单命中
//     直接吞掉; 误报命中附加标记字段透传给前端)
//
// 开关语义(与既有白名单约定一致): 无条目时零行为(等效默认关闭);
// 存在条目(用户显式配置)即生效。
//
// 依赖: 仅 Go 标准库 + yugsight/models。
package scanctl

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"yugsight/models"
	"yugsight/pathrel"
)

var ctlLog = slog.Default().With("component", "scanctl")

// Controller 扫描管控门面
type Controller struct {
	wl  *Whitelist
	fps *FPS
}

// NewController 以指定数据目录构建门面(白名单 whitelist.jsonl +
// 误报 fps.jsonl, 均 JSONL 文件 DAO)。dataDir 为空取 DefaultDataDir。
// 文件缺失 = 空集, 零行为, 降级运行不报错。
func NewController(dataDir string) (*Controller, error) {
	if dataDir == "" {
		dataDir = DefaultDataDir()
	}
	wlDAO, err := NewFileDAO[WhitelistEntry](filepath.Join(dataDir, "whitelist.jsonl"), func() WhitelistEntry { return WhitelistEntry{} })
	if err != nil {
		return nil, fmt.Errorf("白名单存储初始化失败: %s", err)
	}
	fpsDAO, err := NewFileDAO[FPSRule](filepath.Join(dataDir, "fps.jsonl"), func() FPSRule { return FPSRule{} })
	if err != nil {
		return nil, fmt.Errorf("误报存储初始化失败: %s", err)
	}
	wl, err := NewWhitelist(wlDAO)
	if err != nil {
		return nil, err
	}
	fps, err := NewFPS(fpsDAO)
	if err != nil {
		return nil, err
	}
	c := &Controller{wl: wl, fps: fps}
	// dir 走 pathrel.Short: slog 结构化属性不经过 logLine 的相对化兜底,
	// 控制台口径"出现路径就用相对"必须在属性值上显式处理
	ctlLog.Info("扫描管控模块就绪", "dir", pathrel.Short(dataDir),
		"whitelist", wl.Count(), "fps", fps.Count())
	return c, nil
}

// NewControllerWithDAOs 注入自定义 DAO 构建门面(测试 / 未来 SQLite 实现)
func NewControllerWithDAOs(wlDAO DAO[WhitelistEntry], fpsDAO DAO[FPSRule]) (*Controller, error) {
	wl, err := NewWhitelist(wlDAO)
	if err != nil {
		return nil, err
	}
	fps, err := NewFPS(fpsDAO)
	if err != nil {
		return nil, err
	}
	return &Controller{wl: wl, fps: fps}, nil
}

// NewMemoryController 纯内存门面(磁盘存储不可用时的降级兜底:
// 功能可用但不持久化, 进程重启后丢失)
func NewMemoryController() (*Controller, error) {
	return NewControllerWithDAOs(
		NewMemDAO[WhitelistEntry](func() WhitelistEntry { return WhitelistEntry{} }),
		NewMemDAO[FPSRule](func() FPSRule { return FPSRule{} }),
	)
}

// Whitelist 白名单管理器
func (c *Controller) Whitelist() *Whitelist { return c.wl }

// FPS 误报管理器
func (c *Controller) FPS() *FPS { return c.fps }

// Enabled 是否有任何生效条目(无条目 = 零行为, 等效关闭)
func (c *Controller) Enabled() bool {
	return c != nil && (c.wl.Enabled() || c.fps.Count() > 0)
}

// FilterVulns 批量处理归一化漏洞:
//  1. 误报自动标记(就地, 同资产+同 CVE 命中即标 FalsePositive + 备注)
//  2. 白名单过滤(命中项移入 filtered, 不进入报告和统计)
//
// 返回 (保留列表, 被白名单过滤列表, 误报标记条数)。
// c 为 nil / 无任何条目时原样返回(零行为)。
func (c *Controller) FilterVulns(assets []*models.Asset, vulns []*models.Vuln) (kept, filtered []*models.Vuln, fpMarked int) {
	if c == nil || !c.Enabled() {
		return vulns, nil, 0
	}
	fpMarked = c.fps.AutoMark(assets, vulns)
	kept, filtered = c.wl.Filter(assets, vulns)
	if fpMarked > 0 || len(filtered) > 0 {
		ctlLog.Info("扫描管控生效", "fpMarked", fpMarked, "whitelistFiltered", len(filtered))
	}
	return kept, filtered, fpMarked
}

// CheckFinding 判定单条扫描 finding(管线 SSE 事件用):
// 返回 (白名单命中, 命中白名单条目, 误报规则)。
// 白名单命中 -> 调用方应吞掉该事件(不进报告与统计);
// 误报命中 -> 调用方附加 falsePositive/fpNote 字段继续推送(前端展示标记)。
func (c *Controller) CheckFinding(ip string, port int, cve, title string) (bool, WhitelistEntry, FPSRule) {
	if c == nil || !c.Enabled() {
		return false, WhitelistEntry{}, FPSRule{}
	}
	a := &models.Asset{IP: models.NormIP(ip)}
	v := &models.Vuln{AssetIP: models.NormIP(ip), Port: port, CVE: models.NormalizeCVE(cve), Title: title}
	if hit, e := c.wl.Match(a, v); hit {
		return true, e, FPSRule{}
	}
	if _, r := c.fps.Match(a, v); r.ID != "" {
		return false, WhitelistEntry{}, r
	}
	return false, WhitelistEntry{}, FPSRule{}
}

// Status 门面状态(供 /api/vuln/control/status)
type Status struct {
	Enabled        bool         `json:"enabled"`
	WhitelistCount int          `json:"whitelistCount"`
	FPSCount       int          `json:"fpsCount"`
	Scoring        ScoringModel `json:"scoring"`
}

// StatusOf 返回门面状态
func (c *Controller) StatusOf() Status {
	if c == nil {
		return Status{Scoring: Model()}
	}
	return Status{
		Enabled:        c.Enabled(),
		WhitelistCount: c.wl.Count(),
		FPSCount:       c.fps.Count(),
		Scoring:        Model(),
	}
}

// ===== 全局门面(懒加载, 单例) =====

var (
	ctlOnce sync.Once
	ctlInst *Controller
	ctlErr  error
)

// Instance 全局门面懒加载: 首次调用时以默认数据目录初始化。
// 磁盘初始化失败时降级为内存模式(功能可用但不持久化, 错误已记日志),
// 正常路径不返回 nil。
func Instance() *Controller {
	ctlOnce.Do(func() {
		c, err := NewController("")
		if err != nil {
			ctlErr = err
			ctlLog.Error("扫描管控模块磁盘初始化失败, 降级为内存模式(不持久化)", "err", err.Error())
			if mc, merr := NewMemoryController(); merr == nil {
				ctlInst = mc
			}
			return
		}
		ctlInst = c
	})
	return ctlInst
}

// ResetForTest 测试用: 重置全局单例(仅 _test 引用, 生产代码勿调)
func ResetForTest() {
	ctlOnce = sync.Once{}
	ctlInst = nil
	ctlErr = nil
}
