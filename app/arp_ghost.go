// arp_ghost.go 代理 ARP 幽灵资产排除(2026-09-26, 用户拍板: 删除幽灵 + 排除默认开)。
//
// 背景: 网段里存在对整段代答 ARP 的设备(网关/防火墙 proxy-arp/邮件网关), 被代答的
// IP 会"ARP 确认存活"并进资产表, 资产清单里出现大量不存在的 IP。识别特征与判定
// 口径在 internal/scanner/proxy_arp_classify.go(纯函数, 三处共用):
//
//   - 同(真实)MAC 聚集 ≥2 台构成组;
//   - 组内有 ICMP/开放端口证据的成员 = 真身, 保留;
//   - 仅 ARP 证据的成员 = 幽灵, 删除;
//   - 全组无证据 = 无法定位真身(可能在段外/禁 ping), 一个都不删, 只提示。
//
// 三个落点:
//  1. 本地扫描(scanSink.reportArpGhosts): 落库前剔除幽灵 + 汇总日志/SSE;
//  2. 探针回传(filterProbeGhostAssets): 落库前剔除(探针回报无 ICMP 字段,
//     口径退化为"无开放端口"判幽灵);
//  3. 存量数据(/api/v2/assets/arp-ghosts): 按资产表 MAC 分组, 预览 + 手动确认
//     后批量删除(删除是破坏性操作, 必须人工触发)。
//
// 开关: settings.json 的 arpproxy.exclude, **默认 true**(用户 2026-09-26 显式
// 决定排除默认开, 覆盖规则 5 的"默认关"); 显式写 {"arpproxy":{"exclude":false}}
// 回退到"只提示不排除"的旧行为。
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"yugsight/internal/db"
	"yugsight/internal/models"
	"yugsight/internal/normalizer"
	"yugsight/internal/scanner"
	"yugsight/internal/server"
	"yugsight/internal/sse"
)

// arpGhostExcludeEnabled 幽灵排除开关, 缺失/解析失败/显式 null 均按默认 true。
//
// 用 *bool 而非 bool: 区分"用户显式写 false"(关)与"没写"(默认开)—— 后者若
// 直接按零值 false 处理, 等于默认关, 与拍板口径相反(踩配置默认值坑的标准姿势)。
func arpGhostExcludeEnabled() bool {
	raw, ok := section(secArpProxy, "")
	if !ok {
		return true
	}
	var c struct {
		Exclude *bool `json:"exclude"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Exclude == nil {
		return true
	}
	return *c.Exclude
}

// ===== 落点 1: 本地扫描落库前剔除 =====

// arpEvidence 收集本轮每个 IP 的 ARP 证据(MAC/ICMP/开放端口), 供代答分组判定。
//
// 数据源就是落库用的 mergedAlive(ip 事件权威 + 端口证据)与 port 事件明细,
// 不重新探测 —— 判定必须与"将要入账的资产"完全同源, 否则会出现"删了没入账的、
// 留了已入账的"错位。
func (s *scanSink) arpEvidence() map[string]scanner.ArpEvidence {
	alive := s.mergedAlive()
	s.mu.Lock()
	ports := make(map[string][]int, len(s.ports))
	for ip, recs := range s.ports {
		if len(recs) == 0 {
			continue
		}
		ps := make([]int, len(recs))
		for i, r := range recs {
			ps[i] = r.port
		}
		ports[ip] = ps
	}
	s.mu.Unlock()
	out := make(map[string]scanner.ArpEvidence, len(alive))
	for ip, rec := range alive {
		out[ip] = scanner.ArpEvidence{MAC: rec.mac, ICMP: rec.icmp, Ports: ports[ip]}
	}
	return out
}

// reportArpGhosts 本地扫描结果落库前判定代理 ARP 幽灵并剔除(开关默认开)。
//
// 只做减法(从 res.Assets 里移除幽灵), 不产生也不丢弃结果本身; res 为 nil 时
// 照常给出无真身组的提示(全幽灵且无 finding 的扫描 res 就是 nil)。
func (s *scanSink) reportArpGhosts(res *normalizer.Result) *normalizer.Result {
	if !arpGhostExcludeEnabled() {
		return res
	}
	rep := scanner.ClassifyArpGhosts(s.arpEvidence())
	if rep == nil || len(rep.Groups) == 0 {
		return res
	}
	if len(rep.Ghosts) > 0 && res != nil {
		ghost := make(map[string]bool, len(rep.Ghosts))
		for _, ip := range rep.Ghosts {
			ghost[ip] = true
		}
		kept := make([]*models.Asset, 0, len(res.Assets))
		for _, a := range res.Assets {
			if a != nil && a.IP != "" && ghost[models.NormIP(a.IP)] {
				continue
			}
			kept = append(kept, a)
		}
		res.Assets = kept
	}
	for _, g := range rep.Groups {
		var msg string
		switch {
		case g.Unresolved:
			msg = fmt.Sprintf("提示: %d 台主机以同一 MAC %s 应答 ARP 但组内无真身证据(ICMP/开放端口), 无法定位代答设备, 未删除(可查交换机 MAC 表复核)", len(g.IPs), g.MAC)
		case len(g.Ghosts) > 0:
			msg = fmt.Sprintf("检测到 ARP 代答: MAC %s(真身: %s)代答 %d 个 IP(%s), 未入账资产台账",
				g.MAC, strings.Join(g.Real, ", "), len(g.Ghosts), joinIPsShort(g.Ghosts))
		default:
			continue // 正常多 IP 主机: 无幽灵, scanner 侧已有 buildMACWarnings 提示, 不重复
		}
		logLine(msg)
		publishStatusEvent(msg)
	}
	return res
}

// publishStatusEvent 状态行推全局 SSE 流(实时事件页展示; 扫描自身的 SSE 流在
// flush 时可能已收尾, 不依赖它)。hub 非阻塞, 失败不影响主流程。
func publishStatusEvent(msg string) {
	b, err := json.Marshal(map[string]any{"msg": msg})
	if err != nil {
		return
	}
	_ = sse.Default().Publish("status", b)
}

// joinIPsShort IP 列表压短(最多 10 个, 其余折叠), 防止 /24 全代答时日志行爆炸。
func joinIPsShort(ips []string) string {
	if len(ips) <= 10 {
		return strings.Join(ips, ", ")
	}
	return strings.Join(ips[:10], ", ") + fmt.Sprintf(" … 另有 %d 个", len(ips)-10)
}

// ===== 落点 2: 探针结果落库前剔除 =====

// filterProbeGhostAssets 剔除探针结果里的代答幽灵, 返回 (保留的资产, 幽灵 IP 列表)。
//
// 探针回报(ProbeAsset)不带 ICMP 字段, 证据维度退化为"MAC + 开放端口": 同 MAC 组内
// 无开放端口的成员判幽灵。比本地口径略保守(禁 ping 但开端口的真身仍能保住),
// 且"全组无端口的组不删"的红线与本地一致; 漏网之鱼由落点 3 的存量清理兜底。
func filterProbeGhostAssets(assets []*models.Asset) ([]*models.Asset, []string) {
	if len(assets) < 2 {
		return assets, nil
	}
	ev := make(map[string]scanner.ArpEvidence, len(assets))
	for _, a := range assets {
		if a == nil {
			continue
		}
		ip := models.NormIP(a.IP)
		if ip == "" {
			continue
		}
		ev[ip] = scanner.ArpEvidence{MAC: a.MAC, Ports: a.Ports}
	}
	rep := scanner.ClassifyArpGhosts(ev)
	if rep == nil || len(rep.Ghosts) == 0 {
		return assets, nil
	}
	ghost := make(map[string]bool, len(rep.Ghosts))
	for _, ip := range rep.Ghosts {
		ghost[ip] = true
	}
	kept := make([]*models.Asset, 0, len(assets))
	for _, a := range assets {
		if a != nil && a.IP != "" && ghost[models.NormIP(a.IP)] {
			continue
		}
		kept = append(kept, a)
	}
	return kept, rep.Ghosts
}

// ===== 落点 3: 存量数据预览 + 手动清理 =====

// arpGhostsFromTable 按资产表现有数据(MAC + 开放端口)做代答分组判定。
//
// 表内无 ICMP 历史证据, 口径与探针落点一致(端口为证据维度); 资产表里 MAC 为空的
// 行(手动录入/仅端口入账)不参与分组。
func arpGhostsFromTable(d *db.Database) (*scanner.ArpGhostReport, error) {
	list, err := d.Assets().List()
	if err != nil {
		return nil, err
	}
	ev := make(map[string]scanner.ArpEvidence, len(list))
	for _, a := range list {
		if a == nil || a.MAC == "" {
			continue
		}
		ip := models.NormIP(a.IP)
		if ip == "" {
			continue
		}
		ev[ip] = scanner.ArpEvidence{MAC: a.MAC, Ports: a.Ports}
	}
	return scanner.ClassifyArpGhosts(ev), nil
}

// hV2ArpGhostPreview GET /api/v2/assets/arp-ghosts
//
// 只读预览(前端"清理幽灵资产"确认框的数据源): 返回全部同 MAC 组与应删幽灵计数。
func hV2ArpGhostPreview(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	rep, err := arpGhostsFromTable(d)
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	groups := []scanner.ArpGroup{}
	count := 0
	if rep != nil {
		if rep.Groups != nil {
			groups = rep.Groups
		}
		count = len(rep.Ghosts)
	}
	server.OK(w, map[string]any{
		"enabled": arpGhostExcludeEnabled(),
		"groups":  groups,
		"count":   count,
	})
}

// hV2ArpGhostCleanup POST /api/v2/assets/arp-ghosts/cleanup
//
// 按当前表数据重新判定后批量删除幽灵(Purge 一次落盘), 写审计留痕。
// 重复调用幂等: 删完再调 count=0, 不删任何东西。
func hV2ArpGhostCleanup(w http.ResponseWriter, r *http.Request) {
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	rep, err := arpGhostsFromTable(d)
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	if rep == nil || len(rep.Ghosts) == 0 {
		server.OK(w, map[string]any{"deleted": 0, "groups": []scanner.ArpGroup{}})
		return
	}
	ghost := make(map[string]bool, len(rep.Ghosts))
	for _, ip := range rep.Ghosts {
		ghost[ip] = true
	}
	n, err := d.Assets().Purge(func(a *db.Asset) bool {
		return a.IP != "" && ghost[models.NormIP(a.IP)]
	})
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	logAudit(d, r, "asset.clean_arp_ghost", "", fmt.Sprintf("deleted=%d groups=%d", n, len(rep.Groups)))
	server.OK(w, map[string]any{"deleted": n, "groups": rep.Groups})
}
