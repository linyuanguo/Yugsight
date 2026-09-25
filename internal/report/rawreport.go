// rawreport.go 报告中心二期: 原始结构化报告(报告存储与多报告合并底座)。
//
// 与既有报告引擎(任务 7.2, Archive)的分工:
//
//	原始报告(RawReport) = 四大业务模块(实时抓包/扫描作业/弱口令/节点监控)
//	                      执行完成后的"原始结构化结果", 自动存入报告中心;
//	渲染报告(Archive)   = 从数据库聚合渲染 HTML/Word/PDF 的交付材料。
//
// 数据流(二期的底座定位):
//
//	抓包 / 扫描 / 弱口令 / 节点监控 → 原始结构化报告(本文件)
//	                                  → [阶段 3 AI 模块读取分析, 结果写回 AI 三字段]
//	                                  → [可选] 渲染报告交付
//
// 为什么放 report 包而不是 db 包: 与 Archive 同一口径 —— 实体是业务数据结构
// (单一事实来源), db 包只建表(单向依赖 report, 无循环引用); 本文件是纯逻辑,
// 合并算法可脱离运行时单测。
//
// AI 三字段(阶段 3 已落地): 业务页触发 AI 分析后, 研判结果写回
// AINote(全文)/AIData(结构化审计元数据)/AIAnalyzedAt(分析时间),
// 报告中心据此展示"原始结构化数据 + AI 研判内容"; 合并报告把各源的
// AI 内容随 mergedFrom 一并保留(见 MergeRawReports)。
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// 原始报告的来源模块(区分报告来自哪个业务模块)。
const (
	RawModCapture  = "capture"  // 实时抓包
	RawModScan     = "scan"     // 扫描作业(含探针下发)
	RawModWeakPass = "weakpass" // 弱口令检测
	RawModMonitor  = "monitor"  // 节点监控(SNMP 设备监控 + 节点采集)
	RawModMerged   = "merged"   // 多报告合并的汇总报告
)

// RawModules 全部来源模块(固定顺序: 列表统计/合并分组的展示顺序)。
var RawModules = []string{RawModCapture, RawModScan, RawModWeakPass, RawModMonitor, RawModMerged}

// IsKnownRawModule 是否为已知的来源模块。
func IsKnownRawModule(m string) bool {
	for _, x := range RawModules {
		if x == m {
			return true
		}
	}
	return false
}

// RawModuleLabel 来源模块的中文展示名(前端徽标/统计用)。
func RawModuleLabel(m string) string {
	switch m {
	case RawModCapture:
		return "实时抓包"
	case RawModScan:
		return "扫描作业"
	case RawModWeakPass:
		return "弱口令检测"
	case RawModMonitor:
		return "节点监控"
	case RawModMerged:
		return "合并报告"
	}
	return m
}

// RawPayloadMaxSize 单份原始报告的正文上限(8MB)。
//
// 抓包会话按环形缓冲 2000 条报文计约 0.7MB, 扫描/弱口令/监控远小于此;
// 上限是为了防"多份大报告合并"把 JSONL 单行撑到数十 MB —— JSONL 引擎
// 每次写都是整文件重写, 单行过大意味着每次落库都是几十 MB 的拷贝。
const RawPayloadMaxSize = 8 << 20

// RawStats 原始报告的快速统计(列表页直接展示, 无需解析正文)。
type RawStats struct {
	// Items 主条目数(抓包=报文数 / 扫描=漏洞数 / 弱口令=目标数 / 监控=样本数)
	Items int `json:"items"`
	// ByModule 各来源模块的报告数(仅合并报告非空)
	ByModule map[string]int `json:"byModule,omitempty"`
	// Extra 模块专属的次要计数(如 扫描: assets/alive; 弱口令: found)
	Extra map[string]int `json:"extra,omitempty"`
}

// RawReport 一份原始结构化报告(业务模块执行完成后的原始结果快照)。
//
// Payload 是各模块自己产出的结构化数据(JSON): 抓包=会话参数+统计+报文,
// 扫描=漏洞+资产+存活+端口, 弱口令=批次结果+审计, 监控=目标配置+最新样本。
// 为什么正文用 json.RawMessage 而不是 any: RawMessage 按原样存取, 避免
// 每次读改写都把嵌套结构重新编码一次(合并时还要整体搬运, 二次编码
// 既慢又可能在字段顺序上产生漂移)。
type RawReport struct {
	ID        string    `json:"id"`
	Module    string    `json:"module"` // 来源模块(capture/scan/weakpass/monitor/merged)
	Title     string    `json:"title"`
	Source    string    `json:"source,omitempty"` // 来源标记(执行节点: local / probe:<id> / 子来源)
	Operator  string    `json:"operator,omitempty"`
	CreatedAt time.Time `json:"createdAt"`

	// Tags 报告标签(用户可标注, 合并时取并集; 前端按标签筛选)
	Tags []string `json:"tags,omitempty"`
	// Target 主目标(展示与检索用, 如网段/URL/设备地址)
	Target string `json:"target,omitempty"`
	// Assets 涉及的资产 IP(资产筛选维度)
	Assets []string `json:"assets,omitempty"`
	// DurationMs 执行耗时(监控类快照为 0)
	DurationMs int64 `json:"durationMs,omitempty"`
	// Summary 一行摘要(列表页第二行)
	Summary string `json:"summary,omitempty"`
	// Stats 快速统计
	Stats RawStats `json:"stats"`

	// Payload 原始结构化数据(模块执行完成时的完整结果, 自包含)。
	// omitempty: 列表接口用 ReleasePayload 剥离正文(置 nil), 不带 omitempty
	// 会序列化成 "payload":null —— 前端拿到 null 再 JSON.parse 会炸。
	Payload json.RawMessage `json:"payload,omitempty"`
	// SourceIDs 合并报告的来源报告 ID(可下钻到源报告; 非合并报告为空)
	SourceIDs []string `json:"sourceIds,omitempty"`

	// ===== AI 分析字段(阶段 3 落地: 业务页触发分析后由分析器写入) =====
	// AIAnalyzedAt AI 分析完成时间(nil = 未分析)。
	// 必须是 *time.Time: time.Time 是结构体, omitempty 对它无效, 零值会
	// 序列化成 "0001-01-01T00:00:00Z" —— 前端会误以为"已分析于公元元年"。
	AIAnalyzedAt *time.Time `json:"aiAnalyzedAt,omitempty"`
	// AINote AI 研判全文(LLM 输出)
	AINote string `json:"aiNote,omitempty"`
	// AIData AI 分析的结构化审计元数据(模型/模板/RAG 命中/记忆条数/耗时,
	// schema 由 ai 包 Result.AIData 定义)
	AIData json.RawMessage `json:"aiData,omitempty"`
}

// EntityID 实现 db.Entity 契约。
func (r *RawReport) EntityID() string {
	if r.ID == "" {
		r.ID = NewRawReportID()
	}
	return r.ID
}

// Validate 自检: 来源模块必填(它是报告中心区分模块的核心维度, 缺了就
// 无法归类), 其余字段缺省补全(宽松, 与 Archive 同口径)。
func (r *RawReport) Validate() error {
	r.Module = strings.TrimSpace(r.Module)
	if r.Module == "" {
		return errors.New("原始报告缺少来源模块(module)")
	}
	if strings.TrimSpace(r.Title) == "" {
		r.Title = RawModuleLabel(r.Module) + "原始报告 " + time.Now().Format("2006-01-02 15:04")
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	if len(r.Payload) == 0 {
		r.Payload = json.RawMessage(`{}`)
	}
	if len(r.Payload) > RawPayloadMaxSize {
		return fmt.Errorf("原始报告正文超限(%d > %d 字节)", len(r.Payload), RawPayloadMaxSize)
	}
	return nil
}

// IsMerged 是否为合并报告。
func (r *RawReport) IsMerged() bool { return r != nil && r.Module == RawModMerged }

// mergedFromEntry 合并报告对来源报告的引用(下钻用: 合并报告 → 源报告详情)。
//
// AI 字段: 源报告的 AI 研判(若已分析)随引用保留 —— 源报告的 AI 三字段
// 在 RawReport 包装层而非 Payload 内, sections 只照搬 Payload 会丢掉
// 它们, 所以把 AI 内容打包进本条目(合并报告 = 原始报告 + AI 报告的
// 整合, 口径与"多选合并原始报告 + AI 分析报告"一致)。
type mergedFromEntry struct {
	ID        string    `json:"id"`
	Module    string    `json:"module"`
	Title     string    `json:"title"`
	Source    string    `json:"source,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	Summary   string    `json:"summary,omitempty"`
	AI        json.RawMessage `json:"ai,omitempty"` // 源报告的 AI 研判(未分析时省略)
}

// mergedSection 合并报告按来源模块分组的一个章节(保持固定模块顺序,
// 同一模块的多份报告按时间升序排在前端里稳定可读)。
type mergedSection struct {
	Module  string            `json:"module"`
	Count   int               `json:"count"`
	Reports []json.RawMessage `json:"reports"`
}

// mergedPayload 合并报告的正文结构。
type mergedPayload struct {
	MergedFrom []mergedFromEntry `json:"mergedFrom"`
	Sections   []mergedSection   `json:"sections"`
}

// aiSnapshot 源报告 AI 研判的打包(合并报告里保留该源的分析结果)。
// 仅当源报告已分析(AIAnalyzedAt 或 AINote 非空)时才生成。
func aiSnapshot(r *RawReport) json.RawMessage {
	if r == nil || (r.AIAnalyzedAt == nil && r.AINote == "") {
		return nil
	}
	blob, err := json.Marshal(map[string]any{
		"aiAnalyzedAt": r.AIAnalyzedAt,
		"aiNote":       r.AINote,
		"aiData":       r.AIData,
	})
	if err != nil {
		return nil // 打包失败不阻断合并(AI 内容属附属信息)
	}
	return blob
}

// MergeRawReports 多选合并: 把 N 份原始报告整合为一份汇总报告。
//
// 合并口径(底座语义, 只做整合不做业务聚合):
//
//   - 各源报告正文按来源模块分组进 sections(保序: capture→scan→weakpass→
//     monitor→merged), 原文照搬不改写 —— AI 模块读到的仍是原始结构;
//   - 已分析的源报告, 其 AI 研判随 mergedFrom 保留(见 aiSnapshot);
//   - 资产/标签取并集, SourceIDs 记录来源 ID(合并报告可下钻);
//   - 统计做加法(条目总数 + 各模块报告数);
//   - 合并报告本身就是一份普通原始报告: 可再被合并、可筛选、可删除。
//
// 至少需要 2 份有效报告(单份合并无意义, 直接报 400 而不是静默透传)。
func MergeRawReports(reports []*RawReport, title string, tags []string, operator string) (*RawReport, error) {
	valid := make([]*RawReport, 0, len(reports))
	seen := map[string]bool{}
	for _, r := range reports {
		if r == nil || r.ID == "" || seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		valid = append(valid, r)
	}
	if len(valid) < 2 {
		return nil, errors.New("合并至少需要 2 份不同的原始报告")
	}

	// 按固定模块顺序分组(同一模块内按时间升序)
	byMod := make(map[string][]*RawReport, len(valid))
	for _, r := range valid {
		m := r.Module
		if m == "" {
			m = RawModMerged // 理论上 Validate 已挡, 兜底不丢数据
		}
		byMod[m] = append(byMod[m], r)
	}
	var sections []mergedSection
	var froms []mergedFromEntry
	for _, m := range RawModules {
		group := byMod[m]
		if len(group) == 0 {
			continue
		}
		sort.SliceStable(group, func(i, j int) bool {
			return group[i].CreatedAt.Before(group[j].CreatedAt)
		})
		rep := make([]json.RawMessage, 0, len(group))
		for _, r := range group {
			rep = append(rep, r.Payload)
			froms = append(froms, mergedFromEntry{
				ID: r.ID, Module: r.Module, Title: r.Title,
				Source: r.Source, CreatedAt: r.CreatedAt, Summary: r.Summary,
				AI: aiSnapshot(r),
			})
		}
		sections = append(sections, mergedSection{Module: m, Count: len(group), Reports: rep})
	}

	mp := mergedPayload{MergedFrom: froms, Sections: sections}
	payload, err := json.Marshal(mp)
	if err != nil {
		return nil, fmt.Errorf("合并正文序列化失败: %w", err)
	}
	if len(payload) > RawPayloadMaxSize {
		return nil, fmt.Errorf("合并结果超出正文上限(%d 字节), 请减少合并的报告数量", RawPayloadMaxSize)
	}

	// 资产并集(保持出现顺序)
	assetSet := map[string]bool{}
	var assets []string
	for _, r := range valid {
		for _, ip := range r.Assets {
			k := strings.TrimSpace(ip)
			if k == "" || assetSet[k] {
				continue
			}
			assetSet[k] = true
			assets = append(assets, k)
		}
	}
	// 标签并集: 用户指定标签在前, 各源报告标签去重追加
	tagSet := map[string]bool{}
	var tagsOut []string
	addTag := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || tagSet[t] {
			return
		}
		tagSet[t] = true
		tagsOut = append(tagsOut, t)
	}
	for _, t := range tags {
		addTag(t)
	}
	for _, r := range valid {
		for _, t := range r.Tags {
			addTag(t)
		}
	}

	stats := RawStats{ByModule: map[string]int{}}
	for _, r := range valid {
		stats.Items += r.Stats.Items
		m := r.Module
		if m == "" {
			m = RawModMerged
		}
		stats.ByModule[m]++
	}

	// 摘要: 合并 N 份(按模块计数, 如 "扫描 2 / 抓包 1"); 含 AI 研判的源
	// 报告单独计数(列表页一眼看出"汇总里带了几份分析结论")
	aiCount := 0
	for _, r := range valid {
		if r.AIAnalyzedAt != nil || r.AINote != "" {
			aiCount++
		}
	}
	var parts []string
	for _, m := range RawModules {
		if n := stats.ByModule[m]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", RawModuleLabel(m), n))
		}
	}
	if aiCount > 0 {
		parts = append(parts, fmt.Sprintf("含 AI 分析 %d", aiCount))
	}

	t := strings.TrimSpace(title)
	if t == "" {
		t = "合并报告 " + time.Now().Format("2006-01-02 15:04")
	}
	ids := make([]string, 0, len(valid))
	for _, r := range valid {
		ids = append(ids, r.ID)
	}
	return &RawReport{
		Module:    RawModMerged,
		Title:     t,
		Source:    "merged",
		Operator:  operator,
		CreatedAt: time.Now(),
		Tags:      tagsOut,
		Assets:    assets,
		Summary:   fmt.Sprintf("合并 %d 份原始报告(%s)", len(valid), strings.Join(parts, " / ")),
		Stats:     stats,
		Payload:   json.RawMessage(payload),
		SourceIDs: ids,
	}, nil
}
