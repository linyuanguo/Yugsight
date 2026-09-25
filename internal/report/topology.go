package report

import (
	"sort"
	"strconv"
	"strings"

	"yugsight/internal/models"
)

// 拓扑节点类型。
const (
	KindAsset   = "asset"
	KindPort    = "port"
	KindService = "service"
)

// RiskNone 无风险节点的风险等级(前端据此画灰色)。
const RiskNone = "none"

// BuildTopology 由资产与漏洞构建资产拓扑(IP -> 端口 -> 服务)。
//
// 设计要点:
//
//  1. 节点 ID 采用可读的层级串("10.0.0.5" / "10.0.0.5:80" / "10.0.0.5:80/http"),
//     而不是随机 ID —— 前端点击资产详情时可直接从节点 ID 反解 IP 与端口,
//     无需再查一次映射表; 也方便排查问题时肉眼对照。
//
//  2. 风险等级取"该节点下所有漏洞的最高等级": 资产节点聚合其全部端口,
//     端口/服务节点只聚合该端口上的漏洞。这是用户看图时最需要的语义 ——
//     一眼看出哪台机器/哪个端口最危险。
//
//  3. 端口→服务的父子结构: 一个端口可能同时命多个服务指纹(如 8080 上
//     HTTP 与 Tomcat), 这里以"端口节点 + 服务节点"两级表达, 而不是把服务
//     信息塞进端口节点 —— 后者会让画布无法按服务聚合。
//
// 参数 assets / vulns 均为 nil 时返回空拓扑(不是 nil, 避免调用方判空遗漏)。
func BuildTopology(assets []*models.Asset, vulns []*models.Vuln) *Topology {
	topo := &Topology{Nodes: []TopoNode{}, Edges: []TopoEdge{}}

	// ---- 1) 按 IP 聚合漏洞(端口维度 + 资产维度) ----
	type vulnAgg struct {
		byPort    map[int][]*models.Vuln
		all       []*models.Vuln
		sevCount  map[string]int
		maxRisk   string
		maxRank   int
	}
	aggByIP := map[string]*vulnAgg{}
	for _, v := range vulns {
		if v == nil {
			continue
		}
		ip := models.NormIP(v.AssetIP)
		if ip == "" {
			continue
		}
		a, ok := aggByIP[ip]
		if !ok {
			a = &vulnAgg{byPort: map[int][]*models.Vuln{}, sevCount: map[string]int{}, maxRisk: RiskNone, maxRank: -1}
			aggByIP[ip] = a
		}
		a.all = append(a.all, v)
		a.byPort[v.Port] = append(a.byPort[v.Port], v)
		sev := models.NormalizeSeverity(v.Severity)
		a.sevCount[sev]++
		if r := models.SeverityRank(sev); r > a.maxRank {
			a.maxRank = r
			a.maxRisk = sev
		}
	}

	// ---- 2) 资产节点 + 端口节点 + 服务节点 ----
	assetSeen := map[string]bool{}
	for _, ast := range assets {
		if ast == nil {
			continue
		}
		ip := models.NormIP(ast.IP)
		if ip == "" {
			continue
		}
		assetSeen[ip] = true
		agg := aggByIP[ip]
		node := TopoNode{
			ID:        ip,
			Kind:      KindAsset,
			Label:     assetLabel(ast),
			IP:        ip,
			Online:    true, // 在库资产均来自存活探测命中
			Risk:      RiskNone,
			OS:        ast.OS,
			Hostname:  ast.Hostname,
			Tags:      ast.Tags,
			ProbeNode: ast.ProbeNode,
		}
		if agg != nil {
			node.Risk = agg.maxRisk
			node.VulnCount = len(agg.all)
			node.Severity = agg.sevCount
		}
		if strings.TrimSpace(ast.ProbeNode) == "" {
			node.ProbeNode = LocalNode
		}
		topo.Nodes = append(topo.Nodes, node)
		topo.Stats.Assets++
		topo.Stats.Online++
		if models.SeverityRank(node.Risk) >= models.SeverityRank(models.SeverityHigh) {
			topo.Stats.AtRisk++
		}

		// 端口节点
		ports := append([]int(nil), ast.Ports...)
		sort.Ints(ports)
		svcTokens := parseServices(ast.Service)
		for _, p := range ports {
			pID := ip + ":" + strconv.Itoa(p)
			pNode := TopoNode{
				ID:        pID,
				Kind:      KindPort,
				Label:     strconv.Itoa(p),
				IP:        ip,
				Port:      p,
				Proto:     protoOfPort(p),
				Service:   svcTokens[p],
				Online:    true,
				Risk:      RiskNone,
				ProbeNode: node.ProbeNode,
			}
			if agg != nil {
				if vs := agg.byPort[p]; len(vs) > 0 {
					pNode.VulnCount = len(vs)
					pNode.Risk = maxRiskOf(vs)
				}
			}
			topo.Nodes = append(topo.Nodes, pNode)
			topo.Edges = append(topo.Edges, TopoEdge{From: ip, To: pID, Kind: "host-port", Risk: pNode.Risk})
			topo.Stats.Ports++

			// 服务节点(端口上有服务指纹时才建)
			if svc := pNode.Service; svc != "" {
				sID := pID + "/" + svc
				sNode := TopoNode{
					ID: sID, Kind: KindService, Label: svc,
					IP: ip, Port: p, Proto: pNode.Proto, Service: svc,
					Version: versionOfService(ast.Version, svc),
					Online:  true, Risk: pNode.Risk, VulnCount: pNode.VulnCount,
					ProbeNode: node.ProbeNode,
				}
				topo.Nodes = append(topo.Nodes, sNode)
				topo.Edges = append(topo.Edges, TopoEdge{From: pID, To: sID, Kind: "port-service", Label: svc, Risk: sNode.Risk})
				topo.Stats.Services++
			}
		}
	}

	// ---- 3) 补漏: 有漏洞但资产未入库(资产表可能未回填) ----
	for ip, agg := range aggByIP {
		if assetSeen[ip] {
			continue
		}
		node := TopoNode{
			ID: ip, Kind: KindAsset, Label: ip, IP: ip,
			// 资产信息缺失: 在线状态未知, 前端应显示为"未知"而不是"离线"
			Online: false, Unknown: true,
			Risk: agg.maxRisk, VulnCount: len(agg.all), Severity: agg.sevCount,
		}
		topo.Nodes = append(topo.Nodes, node)
		topo.Stats.Assets++
		topo.Stats.Offline++
		if models.SeverityRank(node.Risk) >= models.SeverityRank(models.SeverityHigh) {
			topo.Stats.AtRisk++
		}
		for p, vs := range agg.byPort {
			pID := ip + ":" + strconv.Itoa(p)
			pNode := TopoNode{
				ID: pID, Kind: KindPort, Label: strconv.Itoa(p),
				IP: ip, Port: p, Proto: protoOfPort(p),
				Online: false, Unknown: true,
				Risk: maxRiskOf(vs), VulnCount: len(vs),
			}
			topo.Nodes = append(topo.Nodes, pNode)
			topo.Edges = append(topo.Edges, TopoEdge{From: ip, To: pID, Kind: "host-port", Risk: pNode.Risk})
			topo.Stats.Ports++
		}
	}
	return topo
}

// assetLabel 资产节点显示文本: 主机名优先, 否则 IP。
func assetLabel(a *models.Asset) string {
	if a == nil {
		return ""
	}
	if h := strings.TrimSpace(a.Hostname); h != "" {
		return h
	}
	return models.NormIP(a.IP)
}

// maxRiskOf 取一组漏洞的最高风险等级。
func maxRiskOf(vs []*models.Vuln) string {
	best, bestRank := RiskNone, -1
	for _, v := range vs {
		if v == nil {
			continue
		}
		sev := models.NormalizeSeverity(v.Severity)
		if r := models.SeverityRank(sev); r > bestRank {
			best, bestRank = sev, r
		}
	}
	return best
}

// parseServices 解析资产 Service 字段为 端口 -> 服务名 映射。
//
// 口径来源: probe/scanner 的 ingestPorts 把服务写成 "80/http,443/https" 形式;
// scanner/host.go 也沿用同一形式。这里同时兼容 "80/tcp" 这类只有协议的形式。
func parseServices(s string) map[int]string {
	out := map[int]string{}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		i := strings.Index(tok, "/")
		if i <= 0 {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(tok[:i]))
		if err != nil || port <= 0 {
			continue
		}
		svc := strings.TrimSpace(tok[i+1:])
		if svc == "" {
			continue
		}
		out[port] = svc
	}
	return out
}

// versionOfService 取指定服务的版本信息。
//
// 现有模型只在资产级别存一个 Version(首个开放端口的版本), 无法精确到端口;
// 这里仅在"服务名能对上且确实只有一个版本"时返回, 否则留空 —— 宁可留空也
// 不能把 A 端口的版本标到 B 端口上(那是错误信息, 比缺失更有害)。
func versionOfService(version, svc string) string {
	if strings.TrimSpace(version) == "" {
		return ""
	}
	// 版本串形如 "Apache/2.4.41" 时, 与服务名做前缀匹配
	if v := strings.TrimSpace(version); strings.HasPrefix(strings.ToLower(v), strings.ToLower(svc)) {
		return v
	}
	return ""
}

// protoOfPort 按端口推断协议(仅用于拓扑展示与前端图标选择)。
func protoOfPort(p int) string {
	switch p {
	case 443, 8443, 993, 995, 465, 636:
		return "https"
	case 80, 8080, 8000, 8888, 9000, 3000, 9200, 7001:
		return "http"
	case 22, 23, 21, 25, 110, 143, 587:
		return "tcp"
	}
	return "tcp"
}
