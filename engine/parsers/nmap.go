package parsers

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"yugsight/models"
	"yugsight/normalizer"
)

// Nmap 输出解析(任务 6.2):
//
//   - XML(-oX - / -oA): 提取资产 / 端口 / 服务 / 版本 / Banner + NSE 漏洞插件;
//   - JSON(-oJ -): 兼容 normalizer.FromNmapJSON 已实现的口径, 直接复用;
//   - 格式自动识别: 首字符 '<' = XML, 否则 JSON。
//
// 说明: Nmap XML 中 <hostscript>/<script> 的 NSE 结果是漏洞的主要来源
// (如 smb-vuln-ms17-010), 与端口级 <script> 一并解析。

// ===== XML 结构(只声明用到的字段, 其余忽略) =====

type nmapXMLDoc struct {
	XMLName  struct{}       `xml:"nmaprun"`
	Args     string         `xml:"args,attr"`
	Hosts    []nmapXMLHost  `xml:"host"`
	RunStats nmapXMLRunStat `xml:"runstats"`
}

type nmapXMLRunStat struct {
	Finished nmapXMLFinished `xml:"finished"`
}

type nmapXMLFinished struct {
	Elapsed  string `xml:"elapsed,attr"`  // 秒(浮点)
	Exit     string `xml:"exit,attr"`     // success | error
	ErrMsg   string `xml:"errormsg,attr"` // 失败原因
	Summary  string `xml:"summary,attr"`
	Time     string `xml:"timestr,attr"`
	HostsUp  int    `xml:"hosts,attr"`
	HostsTot int    `xml:"total,attr"`
}

type nmapXMLHost struct {
	Status     nmapXMLStatus   `xml:"status"`
	Addresses  []nmapXMLAddr   `xml:"address"`
	Hostnames  []nmapXMLHName  `xml:"hostnames>hostname"`
	Ports      []nmapXMLPort   `xml:"ports>port"`
	OS         []nmapXMLOS     `xml:"os>osmatch"`
	HostScript []nmapXMLScript `xml:"hostscript>script"`
}

type nmapXMLStatus struct {
	State  string `xml:"state,attr"` // up | down
	Reason string `xml:"reason,attr"`
}

type nmapXMLAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"` // ipv4 | ipv6 | mac
	Vendor   string `xml:"vendor,attr"`
}

type nmapXMLHName struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapXMLPort struct {
	Protocol string          `xml:"protocol,attr"`
	PortID   int             `xml:"portid,attr"`
	State    nmapXMLStatus   `xml:"state"`
	Service  nmapXMLService  `xml:"service"`
	Scripts  []nmapXMLScript `xml:"script"`
}

type nmapXMLService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"`
	Method    string `xml:"method,attr"`
	Conf      string `xml:"conf,attr"`
	CPE       string `xml:"cpe"`
}

type nmapXMLOS struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// nmapXMLScript NSE 脚本结果(output 或 table 元素均可出现)
type nmapXMLScript struct {
	ID     string           `xml:"id,attr"`
	Output string           `xml:"output,attr"`
	Tables []nmapXMLTable   `xml:"table"`
}

type nmapXMLTable struct {
	Key    string         `xml:"key,attr"`
	Elems  []nmapXMLElem  `xml:"elem"`
	Tables []nmapXMLTable `xml:"table"`
}

type nmapXMLElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// ===== 入口 =====

// ParseNmap 解析 Nmap 输出(XML 或 JSON 自动识别)为归一化批次。
func ParseNmap(data []byte) (*Batch, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errEmpty("nmap")
	}
	if detectFormat(data) == FormatXML {
		return parsersNmapXML(data)
	}
	// JSON: 复用归一化模块既有适配器(资产 + NSE 漏洞), 只做一层包装补主机资产
	raw, err := normalizer.FromNmapJSON(data)
	if err != nil {
		return nil, err
	}
	b := &Batch{Source: normalizer.SourceNmap, Assets: raw.Assets, Vulns: raw.Vulns}
	return b, nil
}

// parsersNmapXML 解析 Nmap XML 输出。
func parsersNmapXML(data []byte) (*Batch, error) {
	var doc nmapXMLDoc
	if err := unmarshalXML(data, &doc); err != nil {
		return nil, fmt.Errorf("nmap: XML 解析失败: %w", err)
	}
	b := &Batch{Source: normalizer.SourceNmap}
	now := time.Now()

	for _, h := range doc.Hosts {
		ip, mac, hostname, osName := nmapHostInfo(h)
		if ip == "" {
			b.Warnings = append(b.Warnings, "nmap: 跳过无地址的 host 记录")
			continue
		}
		// 主机级资产: 无论 status 是否为 up 都记录(端口扫描遗漏的死主机也应进资产表),
		// 但 down 主机不加端口, 避免误报开放端口
		hostAsset := normalizer.RawAsset{
			IP:       ip,
			MAC:      mac,
			Hostname: hostname,
			OS:       osName,
			FoundAt:  now,
		}
		up := strings.EqualFold(h.Status.State, "up")

		svc := normalizer.RawAsset{IP: ip, MAC: mac, Hostname: hostname, OS: osName, FoundAt: now}
		for _, p := range h.Ports {
			if !nmapPortOpen(p) {
				continue
			}
			port := normPort(p.PortID)
			if port == 0 {
				continue
			}
			svc.Ports = append(svc.Ports, port)
			if svc.Service == "" {
				svc.Service = strings.TrimSpace(p.Service.Name)
				svc.Version = nmapServiceVersion(p.Service)
				svc.Banner = strings.TrimSpace(p.Service.ExtraInfo)
			}
			// 端口级 NSE 漏洞
			for _, sc := range p.Scripts {
				if v, ok := nmapScriptToVuln(sc, ip, port, p.Protocol); ok {
					b.Vulns = append(b.Vulns, v)
				}
			}
		}
		// 主机级 NSE 漏洞(hostscript)
		for _, sc := range h.HostScript {
			if v, ok := nmapScriptToVuln(sc, ip, 0, "tcp"); ok {
				b.Vulns = append(b.Vulns, v)
			}
		}

		if len(svc.Ports) > 0 {
			hostAsset.Ports = svc.Ports
			hostAsset.Service = svc.Service
			hostAsset.Version = svc.Version
			hostAsset.Banner = svc.Banner
		}
		if !up && len(svc.Ports) == 0 {
			b.Warnings = append(b.Warnings, "nmap: 主机 "+ip+" 状态 "+h.Status.State+"(可能已下线)")
		}
		b.SetupAssets = append(b.SetupAssets, hostAsset)
	}
	return b, nil
}

// nmapHostInfo 取主机地址 / MAC / 主机名 / 操作系统。
// 地址优先取 ipv4/ipv6(非 mac), MAC 单独返回。
func nmapHostInfo(h nmapXMLHost) (ip, mac, hostname, osName string) {
	for _, a := range h.Addresses {
		t := strings.ToLower(strings.TrimSpace(a.AddrType))
		if t == "mac" {
			if mac == "" {
				mac = strings.TrimSpace(a.Addr)
			}
			continue
		}
		if ip == "" {
			ip = strings.TrimSpace(a.Addr)
		}
	}
	if ip == "" {
		// 少数输出只有 mac 地址, 无法作为资产键
		return "", mac, "", ""
	}
	for _, n := range h.Hostnames {
		if s := strings.TrimSpace(n.Name); s != "" {
			hostname = s
			break
		}
	}
	best, bestAcc := "", -1
	for _, o := range h.OS {
		if s := strings.TrimSpace(o.Name); s != "" {
			acc, _ := strconv.Atoi(strings.TrimSpace(o.Accuracy))
			if acc > bestAcc {
				best, bestAcc = s, acc
			}
		}
	}
	return ip, mac, hostname, best
}

func nmapPortOpen(p nmapXMLPort) bool {
	return strings.EqualFold(strings.TrimSpace(p.State.State), "open")
}

// nmapServiceVersion 服务版本串: product + version(拼成 "Apache httpd 2.4.49")。
func nmapServiceVersion(s nmapXMLService) string {
	switch {
	case s.Product != "" && s.Version != "":
		return strings.TrimSpace(s.Product + " " + s.Version)
	case s.Product != "":
		return strings.TrimSpace(s.Product)
	default:
		return strings.TrimSpace(s.Version)
	}
}

// nmapScriptToVuln NSE 脚本结果 → 原始漏洞。
//
// 仅当脚本输出判定为"命中漏洞"时返回 true:
//   - 脚本 id 以 vuln- 开头(vuln-ms17-010 等标准漏洞脚本);
//   - 输出含 VULNERABLE / CVE-xxxx-xxxx;
//   - 输出含状态标记(State: VULNERABLE / LIKELY VULNERABLE)。
//
// 其余脚本(如 http-title 的正常输出)不产生漏洞, 避免噪声。
func nmapScriptToVuln(sc nmapXMLScript, ip string, port int, protocol string) (normalizer.RawVuln, bool) {
	out := strings.TrimSpace(sc.Output)
	if out == "" {
		out = nmapScriptTableText(sc.Tables)
	}
	id := strings.TrimSpace(sc.ID)
	if !nmapScriptHit(id, out) {
		return normalizer.RawVuln{}, false
	}
	cve := nmapFirstCVE(out)
	title := id
	if cve != "" {
		title = cve + " (" + id + ")"
	}
	return normalizer.RawVuln{
		AssetIP:     ip,
		Port:        port,
		Protocol:    strings.ToLower(strings.TrimSpace(protocol)),
		CVE:         cve,
		Title:       title,
		Description: out,
		Evidence:    out,
	}, true
}

// nmapScriptHit 判定 NSE 脚本输出是否为漏洞命中。
func nmapScriptHit(id, out string) bool {
	lid := strings.ToLower(id)
	lout := strings.ToUpper(out)
	if strings.HasPrefix(lid, "vuln-") || strings.Contains(lid, "vuln") {
		// vuln-* 脚本: 仍需输出非空(未命中时 nmap 通常不输出该 script 节点)
		return out != ""
	}
	if strings.Contains(lout, "VULNERABLE") {
		return true
	}
	if strings.Contains(lout, "CVE-") {
		return true
	}
	return false
}

// nmapFirstCVE 从脚本输出里提取首个 CVE 编号。
func nmapFirstCVE(s string) string {
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && r != '-'
	}) {
		if models.IsCVE(f) {
			return models.NormalizeCVE(f)
		}
	}
	return ""
}

// nmapScriptTableText 把 NSE table 结构拍平成文本(无 output 属性时的兜底)。
func nmapScriptTableText(ts []nmapXMLTable) string {
	var parts []string
	var walk func([]nmapXMLTable)
	walk = func(list []nmapXMLTable) {
		for _, t := range list {
			if k := strings.TrimSpace(t.Key); k != "" {
				parts = append(parts, k)
			}
			for _, e := range t.Elems {
				v := sanitizeXMLText(e.Value)
				if v == "" {
					continue
				}
				if k := strings.TrimSpace(e.Key); k != "" {
					parts = append(parts, k+": "+v)
				} else {
					parts = append(parts, v)
				}
			}
			walk(t.Tables)
		}
	}
	walk(ts)
	return strings.Join(parts, "\n")
}
