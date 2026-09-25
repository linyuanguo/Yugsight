// probe_normalize.go 任务 6.4: 探针结果回传 → 中心端归一化统一处理。
//
// 背景: 探针(agentexec)回传 TaskResult 时携带结构化 Report(normalizer.ProbeReport 口径)。
// 本文件是"探针链路"与"任务 3 归一化模块"的唯一连接点:
//
//	探针 Report → normalizer.FromProbeReport → NormalizeWithOptions
//	           → models.Asset / models.Vuln → db 落库(v2 资产/漏洞表) + 白名单/误报过滤
//
// 为什么在中心端归一化而不是探针端:
//
//  1. 归一化需要跨节点上下文(资产合并、误报管理), 这些数据只在中心端;
//  2. 探针二进制要保持小(只有 scanner + probe), 不能因归一化而链入 db 全量;
//  3. 中心端是唯一写入方, 避免多节点并发写同一资产导致覆盖冲突。
//
// 降级: 解析失败/无数据一律记日志跳过, 不影响任务结果落库(项目规则 4)。

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/models"
	"yugsight/internal/normalizer"
	"yugsight/internal/probe"
	"yugsight/internal/scanctl"
	"yugsight/internal/sse"
)

// probeIngestStat 一次归一化入库的统计(供日志/SSE 展示)。
type probeIngestStat struct {
	Assets      int `json:"assets"`
	Vulns       int `json:"vulns"`
	NewVulns    int `json:"newVulns"`
	Duplicates  int `json:"duplicates"`
	FilteredWL  int `json:"filteredWl"` // 被白名单过滤的条数
	FilteredFP  int `json:"filteredFp"` // 被误报规则过滤的条数
	PersistFail int `json:"persistFail"`
}

// Total 有效漏洞总数(排除过滤项)。
func (s *probeIngestStat) Total() int {
	if s == nil {
		return 0
	}
	return s.Vulns
}

// ingestProbeResult 中心端收到探针任务结果后的归一化入库。
//
// 流程:
//
//	1. 提取结构化报告(优先 Report; 旧探针无 Report 时回落解析 Raw)
//	2. normalizer.FromProbeReport → NormalizeWithOptions(统一模型)
//	3. 白名单/误报过滤(scanctl: 中心端本地生效的规则)
//	4. 落 db(v2 资产/漏洞表), 供 Vue 前端与报告使用
//	5. 广播 SSE 事件(大屏与实时事件页消费)
//
// 任何一步失败都只记日志并继续(返回已完成的统计), 不阻断任务状态流转。
func ingestProbeResult(probeID string, res *probe.TaskResult) *probeIngestStat {
	stat := &probeIngestStat{}
	report, ok := extractProbeReport(res)
	if !ok {
		return stat
	}
	// 探针标识补齐: 探针侧原本填的是任务 ID(它不知道自己在中心端的 ID),
	// 由中心端统一覆写, 保证资产/漏洞的来源节点字段正确归属到节点。
	report.NodeID = probeID
	if report.ScanID == "" && res != nil {
		report.ScanID = res.TaskID
	}

	// ---- 归一化: 与 nmap/trivy/zap/nuclei 走完全相同的出口 ----
	batch := normalizer.FromProbeReport(report)
	if batch == nil {
		return stat
	}
	nres := normalizer.NormalizeWithOptions(normalizer.Options{ScanID: report.ScanID}, batch)
	if nres == nil {
		return stat
	}

	// ---- 白名单 / 误报过滤(scanctl 本地规则, 与经典页扫描口径一致) ----
	// 传入资产列表: cidr / tag 型白名单需要资产上下文才能命中
	vulns := filterProbeVulns(nres.Assets, nres.Vulns, stat)

	stat.Assets = len(nres.Assets)
	stat.Vulns = len(vulns)
	for _, v := range vulns {
		switch v.Status {
		case models.VulnStatusNew:
			stat.NewVulns++
		case models.VulnStatusDuplicate:
			stat.Duplicates++
		}
	}

	// ---- 落库(v2 资产/漏洞表; provider 缺失时静默跳过) ----
	persistProbeFindings(probeID, nres.Assets, vulns, stat)

	// ---- SSE 广播: 前端实时看到探针带来的资产/漏洞增量 ----
	sse.Default().Publish("probe", marshalProbeEvent(map[string]any{
		"event": "ingest", "probeId": probeID, "scanId": report.ScanID,
		"assets": stat.Assets, "vulns": stat.Vulns,
		"newVulns": stat.NewVulns, "duplicates": stat.Duplicates,
		"filtered": stat.FilteredWL + stat.FilteredFP,
	}))
	// 归一化统计属数据流过程, 只落盘不进面板: 每次探针任务都会产生一行, 而结果
	// (新增/过滤了多少)在漏洞页与探针任务详情里都能看到。
	// 保留落盘是为了排障 —— "任务成功但漏洞没入库"时这行是唯一能看出入了几条的依据。
	probeFlowLine(fmt.Sprintf("探针 %s 结果归一化: 资产 %d, 漏洞 %d(新增 %d/重复 %d), 过滤 白名单%d/误报%d",
		probeID, stat.Assets, stat.Vulns, stat.NewVulns, stat.Duplicates,
		stat.FilteredWL, stat.FilteredFP))
	return stat
}

// extractProbeReport 从任务结果里取出结构化报告。
//
// 兼容三条路径(按优先级):
//
//	1. res.Report 已是 normalizer.ProbeReport(同进程直接返回, 如 -probe=both 联调场景)
//	2. res.Report 是 map / JSON 串(跨进程通信经 JSON 编解码后的正常路径)
//	3. res.Raw 是报告 JSON(老探针只填 Raw 的兜底路径)
func extractProbeReport(res *probe.TaskResult) (normalizer.ProbeReport, bool) {
	if res == nil {
		return normalizer.ProbeReport{}, false
	}
	switch v := res.Report.(type) {
	case normalizer.ProbeReport:
		return v, hasProbeData(v)
	case *normalizer.ProbeReport:
		if v != nil {
			return *v, hasProbeData(*v)
		}
	case map[string]any:
		if b, err := json.Marshal(v); err == nil {
			var rep normalizer.ProbeReport
			if json.Unmarshal(b, &rep) == nil {
				return rep, hasProbeData(rep)
			}
		}
	case string:
		if v != "" {
			var rep normalizer.ProbeReport
			if json.Unmarshal([]byte(v), &rep) == nil {
				return rep, hasProbeData(rep)
			}
		}
	}
	// 兜底: Raw 里存放的报告 JSON
	if strings.TrimSpace(res.Raw) != "" {
		var rep normalizer.ProbeReport
		if json.Unmarshal([]byte(res.Raw), &rep) == nil && hasProbeData(rep) {
			return rep, true
		}
	}
	return normalizer.ProbeReport{}, false
}

// hasProbeData 报告是否含有效数据(空报告不触发归一化, 避免无意义写盘)。
func hasProbeData(rep normalizer.ProbeReport) bool {
	return len(rep.Assets) > 0 || len(rep.Vulns) > 0
}

// filterProbeVulns 应用白名单与人工误报标记(scanctl 模块, 中心端本地生效)。
//
// 与经典页扫描的差异: 经典页在 finding 事件流里逐条过滤,
// 这里是"归一化后按 models.Vuln 过滤"(白名单支持 cidr/tag 等更丰富的维度),
// 两者共用同一份 scanctl 数据, 因此结论一致。
func filterProbeVulns(assets []*models.Asset, vulns []*models.Vuln, stat *probeIngestStat) []*models.Vuln {
	if len(vulns) == 0 {
		return nil
	}
	ctl := scanctl.Instance()
	for _, v := range vulns {
		if v == nil {
			continue
		}
		// 标记来源: 中心端后续报告可区分"本机扫描"与"各探针上报"
		v.Source = normalizer.SourceProbe
		v.Sources = appendUnique(v.Sources, normalizer.SourceProbe)
	}
	// FilterVulns 会就地标记误报(FalsePositive)并把白名单命中项移出 kept;
	// 资产列表必须传入: cidr / tag 型白名单依赖资产上下文才能命中。
	kept, filtered, fpMarked := ctl.FilterVulns(assets, vulns)
	stat.FilteredWL = len(filtered)
	stat.FilteredFP = fpMarked
	return kept
}

// persistProbeFindings 把归一化后的资产/漏洞写入 v2 数据库。
//
// 落库失败只记日志并计数(不阻断): 中心端可能未启用 v2 db(纯探针模式),
// 此时结果仍可通过任务明细(probe_tasks)查看。
func persistProbeFindings(probeID string, assets []*models.Asset, vulns []*models.Vuln, stat *probeIngestStat) {
	d := v2DB()
	// 三重守卫, 缺一不可:
	//  1. d == nil            —— 未配置/初始化失败
	//  2. Assets()/Vulns() nil —— 数据库已 Close(Close 会把各 DAO 置 nil,
	//     此时调用 DAO 方法会 nil 解引用直接 panic —— 这是插件式落库最常见的崩溃点)
	//  3. postgres 骨架未实现 —— 上层返回错误而不是 panic
	// 探针结果落库失败必须降级(记日志跳过)而不是让中心端崩溃(项目规则 4)。
	if d == nil {
		return
	}
	assetDAO, vulnDAO := d.Assets(), d.Vulns()
	if assetDAO == nil || vulnDAO == nil {
		stat.PersistFail += len(assets) + len(vulns)
		probeLogLine("探针结果未落库: 数据库不可用(已关闭或初始化失败)")
		return
	}
	// 资产: 按 IP 幂等 upsert, 合并标签(多次扫描同一主机的标签取并集)
	for _, a := range assets {
		if a == nil || a.IP == "" {
			continue
		}
		a.ProbeNode = probeID
		if err := upsertProbeAsset(assetDAO, probeID, a); err != nil {
			stat.PersistFail++
			probeLogLine("探针资产落库失败: " + err.Error())
		}
	}
	// 漏洞: 按稳定 ID upsert(同资产+同漏洞跨扫描不重复增长)
	for _, v := range vulns {
		if v == nil || v.AssetIP == "" {
			continue
		}
		if err := upsertProbeVuln(vulnDAO, probeID, v); err != nil {
			stat.PersistFail++
			probeLogLine("探针漏洞落库失败: " + err.Error())
		}
	}
}

// upsertProbeAsset 资产幂等写入(已存在则合并标签与端口, 保留首次发现时间)。
//
// 使用 Table.Upsert 而非 Create: 探针多次扫描同一资产是常态,
// Upsert 返回 (是否新建, error), 天然幂等, 无需先查再判。
func upsertProbeAsset(dao *db.AssetDAO, probeID string, a *models.Asset) error {
	if existing, err := dao.FindByIP(a.IP); err == nil && len(existing) > 0 {
		cur := existing[0]
		cur.AddTags(a.Tags...)
		cur.Hostname = firstNonEmpty(cur.Hostname, a.Hostname)
		cur.OS = firstNonEmpty(cur.OS, a.OS)
		cur.MAC = firstNonEmpty(cur.MAC, a.MAC)
		cur.Ports = mergeInts(cur.Ports, a.Ports)
		cur.Service = firstNonEmpty(cur.Service, a.Service)
		cur.Version = firstNonEmpty(cur.Version, a.Version)
		cur.Banner = firstNonEmpty(cur.Banner, a.Banner)
		cur.ProbeNode = probeID
		_, err = dao.Upsert(cur)
		return err
	}
	a.ProbeNode = probeID
	_, err := dao.Upsert(&db.Asset{Asset: *a})
	return err
}

// upsertProbeVuln 漏洞幂等写入: 同稳定 ID 视为重复发现,
// 保留首次发现时间, 刷新最后发现时间, 证据取更完整的一份。
//
// 【已修复漏洞再次命中】(用户两态口径的关键语义): 标过 fixed 的漏洞若被本轮
// 扫描再次命中, 说明修复未生效 —— 必须回退为 open 并清掉修复时间, 否则
// "修复了又被扫出来"的漏洞会永远停在"已修复", 与事实相反。
func upsertProbeVuln(dao *db.VulnDAO, probeID string, v *models.Vuln) error {
	id := v.StableID()
	if cur, err := dao.Get(id); err == nil && cur != nil {
		cur.LastSeenAt = time.Now()
		if models.IsFixedStatus(cur.Status) {
			cur.Status = models.VulnStatusOpen
			cur.FixedAt = nil
		} else {
			cur.Status = models.VulnStatusDuplicate
		}
		if len(v.Evidence) > len(cur.Evidence) {
			cur.Evidence = v.Evidence
		}
		if v.Request != "" && cur.Request == "" {
			cur.Request = v.Request
		}
		if v.Response != "" && cur.Response == "" {
			cur.Response = v.Response
		}
		// PCAP 证据路径: 探针抓包后回传, 绑定到漏洞便于在详情里关联报文
		if v.PcapFile != "" && cur.PcapFile == "" {
			cur.PcapFile = v.PcapFile
		}
		// 置信度取更高值: 同一漏洞被更强证据命中时应升级而非降级
		if v.Confidence > cur.Confidence {
			cur.Confidence = v.Confidence
		}
		_, err = dao.Upsert(cur)
		return err
	}
	if v.FoundAt.IsZero() {
		v.FoundAt = time.Now()
	}
	v.LastSeenAt = time.Now()
	_, err := dao.Upsert(&db.Vuln{Vuln: *v, ScanTaskID: probeID})
	return err
}

// ===== 小工具 =====

// firstNonEmpty 取第一个非空串(合并两个来源的同一字段时用)。
func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// mergeInts 整数切片并集(保持原顺序, 去重)。
func mergeInts(a, b []int) []int {
	seen := make(map[int]bool, len(a)+len(b))
	out := make([]int, 0, len(a)+len(b))
	for _, list := range [][]int{a, b} {
		for _, v := range list {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// appendUnique 字符串去重追加。
func appendUnique(list []string, s string) []string {
	if s == "" {
		return list
	}
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// marshalProbeEvent 序列化 SSE 事件体(失败返回 nil; 仅用于广播, 不阻断主流程)。
func marshalProbeEvent(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// ===== 探针任务完成后的统一入口(由 taskRecorder.Result 调用) =====

// onProbeResultIngest 探针任务结果归一化入口(带 recover 兜底)。
//
// 单独包一层的原因: 归一化会触碰 db/scanctl/sse 等有状态的子系统,
// 任何异常都不能反噬 probe 包的连接 goroutine(项目规则 4)。
func onProbeResultIngest(probeID string, res *probe.TaskResult) {
	defer func() {
		if p := recover(); p != nil {
			probeLogLine(fmt.Sprintf("探针结果归一化异常(已恢复): %v", p))
		}
	}()
	start := time.Now()
	stat := ingestProbeResult(probeID, res)
	if stat == nil {
		return
	}
	// 耗时属过程指标, 只落盘(见 probeFlowLine)
	probeFlowLine(fmt.Sprintf("探针 %s 归一化完成, 耗时 %dms", probeID, time.Since(start).Milliseconds()))
	// 报告中心二期: 探针扫描结果 → 原始报告自动存档(best-effort 异步)
	if rr := buildRawProbeScanReport(probeID, res, stat); rr != nil {
		autoSaveRawReport(v2DB(), rr)
	}
}
