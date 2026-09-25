// winrm.go WinRM(WS-Management)采集器 —— Windows 主机侧。
//
// 协议: HTTP(S) + SOAP XML(纯标准库 net/http + encoding/xml, 无第三方):
//   1. POST /wsman            CreateShell → 拿 shell id
//   2. POST /wsman/{shellId}  Run(对象 shell 命名空间) → 执行 PowerShell,
//      输出在 <StdOut><Output> 里(base64)
//   3. POST /wsman/{shellId}  Close 关 shell
//
// 采集命令是一条 PowerShell(一次往返拿全 CPU/内存/磁盘/进程/启动时间),
// 进程取内存 TOP10 —— 单次 PowerShell 启动约 1-2s, 60s 间隔下可接受。
//
// 认证: HTTP Basic(Windows 默认开 Basic; Negotiate 需要域环境, 纯标准库
// 不支持, 遇到 Negotiate 直接如实报错误)。
// TLS: 5986 端口或 params.tls=true 走 https; 内网自签证书常见,
// params.insecure=false 才开启证书校验(默认不校验, 与 RESTCONF 同口径)。
package collect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"yugsight/internal/monitor"
)

func init() {
	Register(ProtoWinRM, collectWinRM)
}

// winRMPowerShell 采集命令(单行, 输出压缩 JSON)。
//
// 字段口径:
//   - cpu: Win32_Processor LoadPercentage 均值(瞬时值)
//   - memTotal/memUsed: Win32_ComputerSystem(1KB 单位 → 换算字节)
//   - procs: 按内存 TOP10, cpuTime = Win32_Process.CPU(累计 CPU 秒, 非百分比)
// 整条命令用双引号包 -Command 参数, 因此脚本内部只能出现单引号 ——
// CreateProcess 按双引号切分参数, 内部再有双引号会直接切碎命令(实测坑)。
const winRMPowerShell =
	"$c=(Get-CimInstance Win32_Processor|Measure-Object LoadPercentage -Average).Average;" +
	"$cs=Get-CimInstance Win32_ComputerSystem;" +
	"$h=Get-CimInstance Win32_OperatingSystem;" +
	"$ps=Get-CimInstance Win32_Process|Sort-Object WorkingSetSize -Descending|Select-Object -First 10;" +
	"$d=Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3';" +
	"[pscustomobject]@{" +
	"cpu=[math]::Round($c,1);" +
	"memTotal=[int64]($cs.TotalVisibleMemorySize*1KB);" +
	"memUsed=[int64](($cs.TotalVisibleMemorySize-$cs.FreePhysicalMemory)*1KB);" +
	"boot=$h.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss');" +
	"procs=@($ps|%{[pscustomobject]@{pid=$_.ProcessId;name=$_.Name;cpuTime=[math]::Round($_.CPU,1);mem=[math]::Round($_.WorkingSetSize/1MB,1)}});" +
	"disks=@($d|%{[pscustomobject]@{letter=$_.DeviceID;totalGB=[math]::Round($_.Size/1GB,1);usedGB=[math]::Round(($_.Size-$_.FreeSpace)/1GB,1)}})" +
	"}|ConvertTo-Json -Compress -Depth 4"

type wsmanEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		CreateShellResp struct {
			ShellID string `xml:"ShellId"`
		} `xml:"CreateShellResponse"`
		RunResp struct {
			StdOut   struct {
				Output string `xml:"Output"`
			} `xml:"StdOut"`
			StdErr   struct {
				Output string `xml:"Output"`
			} `xml:"StdErr"`
			ExitCode int `xml:"ExitCode"`
		} `xml:"RunResponse"`
	} `xml:"Body"`
}

type winrmClient struct {
	base    string
	client  *http.Client
	user    string
	pass    string
	timeout time.Duration
}

func newWinRMClient(host string, port int, tlsOn bool, user, pass string, timeout time.Duration, verify bool) *winrmClient {
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verify}, //nolint:gosec // 内网自签常见, 默认不校验
	}
	return &winrmClient{
		base:    scheme + "://" + netJoin(host, port),
		client:  &http.Client{Transport: transport, Timeout: timeout},
		user:    user,
		pass:    pass,
		timeout: timeout,
	}
}

// netJoin 拼 host:port(手写, 避开 net.JoinHostPort 对 IPv6 的括号处理差异
// —— WinRM 目标以 IPv4/主机名为主, 手写足够且行为可预期)。
func netJoin(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

func (c *winrmClient) post(ctx context.Context, path, body string) (*wsmanEnvelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("WSMan", "1.0")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var env wsmanEnvelope
	if err := xml.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("响应解析失败: %s", err)
	}
	return &env, nil
}

func collectWinRM(ctx context.Context, e *Engine, t Task) *Round {
	r := newRound(t, time.Now())
	host, port := hostPort(t.Target, 5985)
	if host == "" {
		r.OK = false
		r.Err = "目标不能为空"
		return r
	}
	tlsOn := port == 5986 || strings.EqualFold(t.Param("tls"), "true")
	verify := strings.EqualFold(t.Param("insecure"), "false")
	key := monitor.SecretKey()
	c := newWinRMClient(host, port, tlsOn, t.User, monitor.DecryptSecret(key, t.AuthPass),
		e.Config().TaskTimeout(t), verify)

	shellBody := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsm="http://docs.oasis-open.org/wsm/x/2004/11/wsm"><s:Body><CreateShell xmlns="http://schemas.microsoft.com/wm/ws/2004/04/objectshell"><ShellId></ShellId></CreateShell></s:Body></s:Envelope>`
	env, err := c.post(ctx, "/wsman", shellBody)
	if err != nil {
		r.OK = false
		r.Err = "创建会话失败: " + err.Error()
		return r
	}
	shellID := env.Body.CreateShellResp.ShellID
	if shellID == "" {
		r.OK = false
		r.Err = "服务端未返回 shell id(可能只支持 Negotiate 认证, 纯标准库不支持)"
		return r
	}
	defer c.post(ctx, "/wsman/"+shellID, closeShellXML(shellID)) // 关会话(失败不影响结果)

	runBody := fmt.Sprintf(
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsm="http://docs.oasis-open.org/wsm/x/2004/11/wsm"><s:Body><Run xmlns="http://schemas.microsoft.com/wm/ws/2004/04/objectshell" wsm:ResourceURI="http://schemas.microsoft.com/wm/ws/2004/04/objectshell/shell/%s" wsm:Action="http://schemas.microsoft.com/wm/ws/2004/04/objectshell/Run"><Command>%s</Command><Timeout>PT60S</Timeout></Run></s:Body></s:Envelope>`,
		xmlEscape(shellID), xmlEscape("powershell -NoProfile -NonInteractive -Command \""+winRMPowerShell+"\""))
	env, err = c.post(ctx, "/wsman/"+shellID, runBody)
	if err != nil {
		r.OK = false
		r.Err = "执行采集命令失败: " + err.Error()
		return r
	}
	out := env.Body.RunResp
	if out.ExitCode != 0 {
		r.OK = false
		r.Err = "PowerShell 退出码 " + fmt.Sprint(out.ExitCode) + " " + decodeWSMAN(out.StdErr.Output)
		return r
	}
	data := []byte(decodeWSMAN(out.StdOut.Output))
	if len(data) == 0 {
		r.OK = false
		r.Err = "无输出"
		return r
	}

	var parsed struct {
		CPU      float64 `json:"cpu"`
		MemTotal int64   `json:"memTotal"`
		MemUsed  int64   `json:"memUsed"`
		Boot     string  `json:"boot"`
		Procs    []struct {
			PID     uint32  `json:"pid"`
			Name    string  `json:"name"`
			CPUTime float64 `json:"cpuTime"`
			Mem     float64 `json:"mem"`
		} `json:"procs"`
		Disks []struct {
			Letter  string  `json:"letter"`
			TotalGB float64 `json:"totalGB"`
			UsedGB  float64 `json:"usedGB"`
		} `json:"disks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		r.OK = false
		r.Err = "输出解析失败: " + err.Error()
		return r
	}

	r.OK = true
	r.Metrics = append(r.Metrics,
		Metric{Name: "cpu", Value: parsed.CPU, Unit: "%"},
		Metric{Name: "mem_total", Value: float64(parsed.MemTotal), Unit: "B"},
		Metric{Name: "mem_used", Value: float64(parsed.MemUsed), Unit: "B"},
	)
	if parsed.MemTotal > 0 {
		r.Metrics = append(r.Metrics, Metric{Name: "mem_used_pct", Value: float64(parsed.MemUsed) / float64(parsed.MemTotal) * 100, Unit: "%"})
	}
	if parsed.Boot != "" {
		r.Metrics = append(r.Metrics, Metric{Name: "boot_time", Value: 0, Labels: map[string]string{"value": parsed.Boot}})
	}
	for _, p := range parsed.Procs {
		r.Metrics = append(r.Metrics, Metric{
			Name: "process", Value: p.Mem, Unit: "MB",
			Labels: map[string]string{"pid": fmt.Sprint(p.PID), "name": p.Name, "cpuTime": fmt.Sprintf("%.1f", p.CPUTime)},
		})
	}
	for _, d := range parsed.Disks {
		r.Metrics = append(r.Metrics,
			Metric{Name: "disk_total", Value: d.TotalGB * 1024, Unit: "MB", Labels: map[string]string{"disk": d.Letter}},
			Metric{Name: "disk_used", Value: d.UsedGB * 1024, Unit: "MB", Labels: map[string]string{"disk": d.Letter}},
		)
	}
	return r
}

func closeShellXML(shellID string) string {
	return fmt.Sprintf(
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsm="http://docs.oasis-open.org/wsm/x/2004/11/wsm"><s:Body><Close xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman" wsm:ResourceURI="http://schemas.microsoft.com/wm/ws/2004/04/objectshell/shell/%s" wsm:Action="http://schemas.dmtf.org/wbem/wsman/1/close"/></s:Body></s:Envelope>`,
		xmlEscape(shellID))
}

// decodeWSMAN WinRM 输出段是 base64(可能为空); 解码失败原样返回(展示层兜底)。
func decodeWSMAN(b64 string) string {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return b64
	}
	return string(bytes.TrimSpace(b))
}

// xmlEscape XML 文本转义(命令里含引号/反引号, 必须转义 & < >)。
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}
