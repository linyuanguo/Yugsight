package scanner

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ===== 目标/端口解析 =====

// TestParseTargetHost 目标串归一化: scheme 前缀剥离 + 路径截断。
// 顺序不可调换(先剥前缀再切路径), 否则 "http://a:8080/x" 会被切成 "http:"。
func TestParseTargetHost(t *testing.T) {
	cases := map[string]string{
		"http://10.0.0.5:8080/x?y=1": "10.0.0.5:8080",
		"https://10.0.0.5/":          "10.0.0.5",
		"image:nginx:latest":         "nginx:latest",
		"fs:/app":                    "app",
		"10.0.0.5":                   "10.0.0.5",
		"  10.0.0.5  ":               "10.0.0.5",
		"":                           "",
	}
	for in, want := range cases {
		if got := ParseTargetHost(in); got != want {
			t.Errorf("ParseTargetHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParsePortsParam 端口参数解析: 单端口/范围/混合/非法值过滤/上限保护。
func TestParsePortsParam(t *testing.T) {
	// 空值 -> 默认端口集
	if got, _ := ParsePortsParam(""); len(got) == 0 {
		t.Fatal("空参数应返回默认端口集")
	}
	cases := []struct {
		in   string
		want []int
	}{
		{"80,443", []int{80, 443}},
		{"80,80,443", []int{80, 443}}, // 去重
		{"22-25", []int{22, 23, 24, 25}},
		{"80,100-102", []int{80, 100, 101, 102}},
		{"0,99999,abc,-5,80", []int{80}}, // 非法值全部丢弃, 保留合法的
	}
	for _, c := range cases {
		got, err := ParsePortsParam(c.in)
		if err != nil {
			t.Fatalf("ParsePortsParam(%q) 报错: %v", c.in, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("ParsePortsParam(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("ParsePortsParam(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
	// 范围上限保护: 1-65535 会被截断到 5001 个端口, 不允许打满全端口
	got, _ := ParsePortsParam("1-65535")
	if len(got) > 5001 {
		t.Fatalf("范围应被截断到 5001 个端口, 实际 %d", len(got))
	}
}

// TestOptionsFromArgs 中心端参数解析: 字段容忍类型错误, 数值上限钳制。
func TestOptionsFromArgs(t *testing.T) {
	// 无参数: 内置能力全开
	cfg := OptionsFromArgs(nil, Config{})
	if !cfg.EnableNuclei || !cfg.EnableExternal {
		t.Fatal("无参数时内置能力应全开")
	}

	// 正常参数
	cfg = OptionsFromArgs(map[string]any{
		"ports": "8080", "concurrency": float64(64), "timeoutMs": float64(2000),
		"enableNuclei": false, "nucleiTags": "cve,critical",
		"nmapArgs": []any{"-sS"},
	}, Config{})
	if len(cfg.Ports) != 1 || cfg.Ports[0] != 8080 {
		t.Fatalf("端口解析错误: %v", cfg.Ports)
	}
	if cfg.Concurrency != 64 {
		t.Fatalf("并发解析错误: %d", cfg.Concurrency)
	}
	if cfg.Timeout.Dial != 2*time.Second {
		t.Fatalf("超时解析错误: %v", cfg.Timeout.Dial)
	}
	if cfg.EnableNuclei {
		t.Fatal("enableNuclei=false 应生效")
	}
	if len(cfg.NucleiTags) != 2 {
		t.Fatalf("tag 解析错误: %v", cfg.NucleiTags)
	}
	if len(cfg.extraArgsForTest("nmapArgs")) != 1 {
		t.Fatal("nmapArgs 应被解析")
	}

	// 类型错误 + 超限: 应被忽略/钳制而不是失败
	cfg = OptionsFromArgs(map[string]any{
		"concurrency": "not-a-number", "ports": 12345, "timeoutMs": float64(999999),
	}, Config{Concurrency: 100, Ports: []int{80}})
	if cfg.Concurrency != 100 {
		t.Fatalf("非法并发应保留默认值, 实际 %d", cfg.Concurrency)
	}
	if len(cfg.Ports) != 1 || cfg.Ports[0] != 80 {
		t.Fatalf("非法端口应保留默认值, 实际 %v", cfg.Ports)
	}
	if cfg.Timeout.Dial != 30*time.Second {
		t.Fatalf("超时应钳制到 30s, 实际 %v", cfg.Timeout.Dial)
	}

	// 并发上限 512
	cfg = OptionsFromArgs(map[string]any{"concurrency": float64(99999)}, Config{})
	if cfg.Concurrency != 512 {
		t.Fatalf("并发应钳制到 512, 实际 %d", cfg.Concurrency)
	}
}

// extraArgsForTest 测试内暴露 extraArgs(避免导出生产代码只为测试)。
func (c Config) extraArgsForTest(key string) []string {
	t := &Task{cfg: c}
	return t.extraArgs(key)
}

// TestExpandTargets 目标展开: CIDR / 单 IP / 非法输入。
func TestExpandTargets(t *testing.T) {
	got, err := ExpandTargets("10.0.0.0/30")
	if err != nil {
		t.Fatalf("CIDR 展开失败: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("CIDR 应展开出主机")
	}
	if got, err := ExpandTargets("10.0.0.5"); err != nil || len(got) != 1 {
		t.Fatalf("单 IP 展开失败: %v %v", got, err)
	}
	if _, err := ExpandTargets("!!!"); err == nil {
		t.Fatal("非法目标应报错")
	}
}

// ===== 内网小工具 =====

// TestJoinPorts 端口列表压缩: 连续段用 a-b 表示, 非连续保持逗号分隔。
func TestJoinPorts(t *testing.T) {
	cases := []struct {
		in   []int
		want string
	}{
		{[]int{80, 443}, "80,443"},
		{[]int{22, 23, 24, 25}, "22-25"},
		{[]int{80, 100, 101, 102, 443}, "80,100-102,443"},
		{[]int{443, 80, 22}, "22,80,443"}, // 排序
		{nil, "80,443"},                   // 兜底
	}
	for _, c := range cases {
		if got := joinPorts(c.in); got != c.want {
			t.Errorf("joinPorts(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestVersionOf 从横幅里提取组件版本。
func TestVersionOf(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_8.2p1 Ubuntu": "OpenSSH 8.2",
		"Server: nginx/1.18.0":         "nginx 1.18.0",
		"220 FTP Server ready":         "",
	}
	for in, want := range cases {
		if got := versionOf(in); got != want {
			t.Errorf("versionOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestVulnKey 漏洞去重键: 有 CVE 按 资产|CVE, 无 CVE 退化到 资产|协议:端口|标题。
func TestVulnKey(t *testing.T) {
	a := vulnKey(probeVulnForTest("10.0.0.5", "cve-2021-1234", "tcp", 80, "标题A"))
	b := vulnKey(probeVulnForTest("10.0.0.5", "CVE-2021-1234", "tcp", 443, "标题B"))
	if a != b {
		t.Fatalf("同资产同 CVE 应同键: %q vs %q", a, b)
	}
	c := vulnKey(probeVulnForTest("10.0.0.5", "", "tcp", 80, "标题A"))
	d := vulnKey(probeVulnForTest("10.0.0.5", "", "tcp", 80, "标题B"))
	if c == d {
		t.Fatal("无 CVE 时不同标题应不同键")
	}
}

// TestIPLess IP 排序: 数字段序而非字典序(10.0.0.9 < 10.0.0.10)。
func TestIPLess(t *testing.T) {
	if !ipLess("10.0.0.9", "10.0.0.10") {
		t.Fatal("IP 应按数字段序比较")
	}
	if ipLess("10.0.0.10", "10.0.0.9") {
		t.Fatal("IP 比较方向错误")
	}
}

// ===== Task 生命周期与报告 =====

// TestTaskAddAssetMerge 同 IP 多次登记应合并端口并集与标签。
func TestTaskAddAssetMerge(t *testing.T) {
	task := NewTask("port", "10.0.0.5", Config{})
	task.addAsset(probeAssetForTest("10.0.0.5", []int{80, 443}, "banner1"))
	task.addAsset(probeAssetForTest("10.0.0.5", []int{443, 8080}, "banner2"))

	rep := task.Report()
	if len(rep.Assets) != 1 {
		t.Fatalf("同 IP 应合并为 1 条资产, 实际 %d", len(rep.Assets))
	}
	if len(rep.Assets[0].Ports) != 3 {
		t.Fatalf("端口应取并集(80/443/8080), 实际 %v", rep.Assets[0].Ports)
	}
	// 端口应升序输出
	for i := 1; i < len(rep.Assets[0].Ports); i++ {
		if rep.Assets[0].Ports[i-1] >= rep.Assets[0].Ports[i] {
			t.Fatalf("端口未升序: %v", rep.Assets[0].Ports)
		}
	}
}

// TestTaskAddVulnDedup 同资产同 CVE 漏洞应去重, 且保留更完整的证据。
func TestTaskAddVulnDedup(t *testing.T) {
	task := NewTask("host", "10.0.0.5", Config{})
	v1 := probeVulnForTest("10.0.0.5", "CVE-2021-1234", "tcp", 80, "标题")
	v1.Evidence = ""
	task.addVuln(v1)

	v2 := probeVulnForTest("10.0.0.5", "CVE-2021-1234", "tcp", 80, "标题")
	v2.Evidence = "更完整的证据"
	v2.Confidence = 90
	task.addVuln(v2)

	rep := task.Report()
	if len(rep.Vulns) != 1 {
		t.Fatalf("同资产同 CVE 应去重为 1 条, 实际 %d", len(rep.Vulns))
	}
	if rep.Vulns[0].Evidence != "更完整的证据" {
		t.Fatalf("应保留更完整的证据, 实际 %q", rep.Vulns[0].Evidence)
	}
	if rep.Vulns[0].Confidence != 90 {
		t.Fatalf("置信度应取更高值, 实际 %d", rep.Vulns[0].Confidence)
	}
}

// TestTaskReportSorted 报告漏洞应按严重级别降序输出。
func TestTaskReportSorted(t *testing.T) {
	task := NewTask("host", "10.0.0.5", Config{})
	task.addVuln(withSeverity(probeVulnForTest("10.0.0.5", "", "tcp", 1, "低危"), "low"))
	task.addVuln(withSeverity(probeVulnForTest("10.0.0.5", "", "tcp", 2, "高危"), "high"))
	task.addVuln(withSeverity(probeVulnForTest("10.0.0.5", "", "tcp", 3, "严重"), "critical"))

	rep := task.Report()
	if len(rep.Vulns) != 3 {
		t.Fatalf("应有 3 条漏洞, 实际 %d", len(rep.Vulns))
	}
	want := []string{"critical", "high", "low"}
	for i, w := range want {
		if rep.Vulns[i].Severity != w {
			t.Fatalf("漏洞未按级别降序, 第 %d 条 = %v, want %v (完整顺序 %v/%v/%v)",
				i, rep.Vulns[i].Severity, w, rep.Vulns[0].Severity, rep.Vulns[1].Severity, rep.Vulns[2].Severity)
		}
	}
}

// TestRunEmptyTarget 空目标必须报错(而不是返回空报告让中心端误读为"无发现")。
func TestRunEmptyTarget(t *testing.T) {
	task := NewTask("port", "  ", Config{})
	if _, err := Run(context.Background(), task, nil); err == nil {
		t.Fatal("空目标应报错")
	}
}

// TestRunUnsupportedKind 不支持的 Kind 必须报错。
func TestRunUnsupportedKind(t *testing.T) {
	task := NewTask("synscan", "10.0.0.5", Config{})
	if _, err := Run(context.Background(), task, nil); err == nil {
		t.Fatal("不支持的 Kind 应报错")
	}
}

// TestRunCanceled 任务取消应返回 ErrCanceled 且不 panic。
func TestRunCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立刻取消
	task := NewTask("port", "127.0.0.1", Config{Ports: []int{1, 2, 3}})
	_, err := Run(ctx, task, nil)
	if err == nil {
		t.Fatal("已取消的 context 应返回错误")
	}
}

// TestRunProgress 进度回调应被调用且 nil 安全。
func TestRunProgress(t *testing.T) {
	var msgs []string
	task := NewTask("port", "127.0.0.1", Config{Ports: []int{1}})
	if _, err := Run(context.Background(), task, func(m string) { msgs = append(msgs, m) }); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("应收到进度回调")
	}
	// nil 回调不得 panic
	task2 := NewTask("port", "127.0.0.1", Config{Ports: []int{1}})
	if _, err := Run(context.Background(), task2, nil); err != nil {
		t.Fatalf("nil 进度回调应安全: %v", err)
	}
}

// ===== 端口扫描(真实回环监听) =====

// loopbackTCPAllowed 探测当前环境是否允许回环 TCP 连接。
//
// 为什么需要: 本项目既有约定 —— 沙箱会拦截回环外连(dial 到已监听端口会超时,
// 而不是立即成功或连接被拒)。此时任何"用回环服务验证端口扫描"的用例都必然失败,
// 且失败原因与代码质量无关。因此先探测, 不可用则 Skip 并说明, 把真实网络行为的
// 覆盖留给真机联调(与项目既有测试约定一致)。
//
// 判定方式: 监听一个端口后 dial 它。若 dial 失败则说明回环被拦。
func loopbackTCPAllowed() bool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestScanPortsRawOpenPort 用一个真实监听的回环端口验证"开放端口可被识别"。
func TestScanPortsRawOpenPort(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过(该场景由真机联调覆盖)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听回环端口: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_8.2p1\r\n"))
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	task := NewTask("port", "127.0.0.1", Config{Ports: []int{port}, Concurrency: 4})
	res := task.scanPortsRaw(context.Background(), "127.0.0.1", []int{port}, true)
	if len(res) != 1 {
		t.Fatalf("应有 1 条端口结果, 实际 %d", len(res))
	}
	if res[0].State != "open" {
		t.Fatalf("回环监听端口应为 open, 实际 %s", res[0].State)
	}
	if !strings.Contains(res[0].Banner, "OpenSSH") {
		t.Fatalf("应读到 SSH 横幅, 实际 %q", res[0].Banner)
	}
	// 服务名不在这里断言: scanPortsRaw 只做"端口→服务名表"映射, 回环监听的是
	// 随机高端口, 表里没有映射就是空 —— 这是正确行为(宁可空着也不猜)。服务名
	// 映射本身的正确性由 scanner.ServiceName 的用例覆盖。
}

// TestScanPortsRawClosedPort 未监听端口应判为 closed(不 panic 不误报开放)。
func TestScanPortsRawClosedPort(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过(该场景由真机联调覆盖)")
	}
	// 占一个端口后立即释放, 得到一个当前不太可能被占用的端口号
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听回环端口: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	time.Sleep(50 * time.Millisecond)

	task := NewTask("port", "127.0.0.1", Config{Ports: []int{port}, Concurrency: 4})
	res := task.scanPortsRaw(context.Background(), "127.0.0.1", []int{port}, false)
	if len(res) != 1 {
		t.Fatalf("应有 1 条端口结果, 实际 %d", len(res))
	}
	if res[0].State != "closed" {
		t.Fatalf("未监听端口应为 closed, 实际 %s", res[0].State)
	}
}

// TestReadBanner 横幅读取的净化: 控制字符替换为 '.', 超长截断。
func TestReadBanner(t *testing.T) {
	if !loopbackTCPAllowed() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过(该场景由真机联调覆盖)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听回环端口: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("OK\x00\x01\x02service v1.0\r\n"))
		_ = c.Close()
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("无法连接回环端口: %v", err)
	}
	defer c.Close()
	banner := readBanner(c, time.Second)
	if strings.ContainsAny(banner, "\x00\x01\x02") {
		t.Fatalf("控制字符应被替换: %q", banner)
	}
	if len(banner) > 200 {
		t.Fatalf("横幅应限长 200, 实际 %d", len(banner))
	}
	if !strings.Contains(banner, "service v1.0") {
		t.Fatalf("横幅内容应保留: %q", banner)
	}
}

// ===== PCAP 抓包骨架 =====

// TestCaptureDisabledByDefault 抓包默认关闭: 未显式开启时不产生任何文件与开销。
func TestCaptureDisabledByDefault(t *testing.T) {
	task := NewTask("port", "10.0.0.5", Config{})
	if task.StartCapture(CaptureConfig{}) {
		t.Fatal("未开启抓包时不应启用")
	}
	if res := task.CaptureResult(); res.Enabled {
		t.Fatal("未启用抓包时结果应为空")
	}
}

// TestCaptureWritesValidPcap 抓包骨架应产出格式合法的 PCAP 文件。
//
// 校验点(PCAP 全局头 24 字节):
//
//	magic 0xA1B2C3D4 / version 2.4 / snaplen / LINKTYPE_ETHERNET=1
func TestCaptureWritesValidPcap(t *testing.T) {
	dir := t.TempDir()
	task := NewTask("port", "10.0.0.5", Config{})
	if !task.StartCapture(CaptureConfig{Enabled: true, Dir: dir}) {
		t.Fatal("应能开启抓包")
	}
	task.cap.Note("测试交互摘要")
	// 写入两个伪造的以太网帧
	if !task.cap.AddPacket([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}) {
		t.Fatal("写入报文失败")
	}
	if !task.cap.AddPacket(make([]byte, 64)) {
		t.Fatal("写入报文失败")
	}
	res := task.CaptureResult()
	if !res.Enabled {
		t.Fatal("抓包结果应标记启用")
	}
	if res.Packets != 2 {
		t.Fatalf("应记录 2 个报文, 实际 %d", res.Packets)
	}
	if res.FilePath == "" {
		t.Fatal("应产出 PCAP 文件")
	}
	data, err := os.ReadFile(res.FilePath)
	if err != nil {
		t.Fatalf("读取 PCAP 失败: %v", err)
	}
	if len(data) < 24 {
		t.Fatalf("PCAP 文件过短: %d 字节", len(data))
	}
	// magic(小端)
	if data[0] != 0xD4 || data[1] != 0xC3 || data[2] != 0xB2 || data[3] != 0xA1 {
		t.Fatalf("PCAP magic 错误: % x", data[:4])
	}
	if data[4] != 2 || data[6] != 4 { // major=2, minor=4
		t.Fatalf("PCAP 版本错误: %d.%d", data[4], data[6])
	}
	if data[20] != 1 { // LINKTYPE_ETHERNET
		t.Fatalf("链路类型应为 1(以太网), 实际 %d", data[20])
	}
	// 全局头 24 + 2*(16 头 + 帧长)
	want := 24 + (16 + 6) + (16 + 64)
	if len(data) != want {
		t.Fatalf("PCAP 长度应为 %d, 实际 %d", want, len(data))
	}
	// 摘要应随结果返回(无 Npcap 时的降级证据)
	if len(res.Notes) == 0 {
		t.Fatal("交互摘要应随结果返回")
	}
}

// TestCaptureNoPacketNoFile 零报文时不应留下空 PCAP 文件。
func TestCaptureNoPacketNoFile(t *testing.T) {
	dir := t.TempDir()
	task := NewTask("port", "10.0.0.5", Config{})
	task.StartCapture(CaptureConfig{Enabled: true, Dir: dir})
	res := task.CaptureResult()
	if res.FilePath != "" {
		t.Fatalf("零报文不应创建文件, 实际 %s", res.FilePath)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("目录应为空, 实际 %d 个文件", len(entries))
	}
}

// TestCaptureMaxPackets 报文数上限必须生效(防止抓满磁盘)。
func TestCaptureMaxPackets(t *testing.T) {
	dir := t.TempDir()
	task := NewTask("port", "10.0.0.5", Config{})
	task.StartCapture(CaptureConfig{Enabled: true, Dir: dir, MaxPackets: 3})
	for i := 0; i < 10; i++ {
		task.cap.AddPacket(make([]byte, 32))
	}
	res := task.CaptureResult()
	if res.Packets != 3 {
		t.Fatalf("应在上限处停止(3), 实际 %d", res.Packets)
	}
	if !res.Truncated {
		t.Fatal("超限应标记 Truncated")
	}
}

// TestCaptureMaxBytes 文件大小上限必须生效。
func TestCaptureMaxBytes(t *testing.T) {
	dir := t.TempDir()
	task := NewTask("port", "10.0.0.5", Config{})
	// 上限 200 字节: 每个报文 100 字节 + 16 头, 第 2 个就会超限
	task.StartCapture(CaptureConfig{Enabled: true, Dir: dir, MaxBytes: 200})
	for i := 0; i < 5; i++ {
		task.cap.AddPacket(make([]byte, 100))
	}
	res := task.CaptureResult()
	if res.Packets > 1 {
		t.Fatalf("应在字节上限处停止(1), 实际 %d", res.Packets)
	}
	if !res.Truncated {
		t.Fatal("超限应标记 Truncated")
	}
}

// TestCaptureNilSafe nil 抓包会话的所有方法都必须安全(未开启时不 panic)。
func TestCaptureNilSafe(t *testing.T) {
	var c *Capture
	c.Note("x")
	if c.Enabled() {
		t.Fatal("nil 抓包不应启用")
	}
	if c.FilePath() != "" {
		t.Fatal("nil 抓包路径应为空")
	}
	if c.AddPacket([]byte{1}) != true {
		t.Fatal("nil 抓包写入应返回 true(视为已忽略)")
	}
	if res := c.Stop(); res.Enabled {
		t.Fatal("nil 抓包结果应为空结构")
	}
}

// TestCaptureSummary 抓包摘要文案(前端/日志展示)。
func TestCaptureSummary(t *testing.T) {
	if s := (CaptureResult{Enabled: false}).Summary(); s != "" {
		t.Fatalf("未启用应返回空串, 实际 %q", s)
	}
	r := CaptureResult{Enabled: true, FilePath: filepath.Join("x", "a.pcap"), Packets: 5, Bytes: 100}
	if s := r.Summary(); !strings.Contains(s, "5 个报文") {
		t.Fatalf("摘要应含报文数: %q", s)
	}
}

// TestSubDirForExe exe 同目录拼路径。
func TestSubDirForExe(t *testing.T) {
	got := exeSubDir("bin")
	if !strings.HasSuffix(got, "bin") {
		t.Fatalf("应以 bin 结尾: %q", got)
	}
}

// TestEngineBinPathMissing bin/ 不存在时应返回空串而不是报错(降级不崩溃)。
func TestEngineBinPathMissing(t *testing.T) {
	if p := engineBinPath("nonexistent-engine-xyz"); p != "" {
		t.Fatalf("不存在的引擎应返回空串, 实际 %q", p)
	}
}

// TestIsTrivyTarget 目标形态判定: 路径/镜像走 trivy, 裸 IP 与 URL 不走。
func TestIsTrivyTarget(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.5":        false,
		"10.0.0.5:8080":   false,
		"http://a.com":    false,
		"/app/src":        true,
		"./project":       true,
		"C:\\work\\proj":  true,
		"nginx:latest":    true,
		"registry/x:v1":   true,
	}
	for in, want := range cases {
		if got := isTrivyTarget(in); got != want {
			t.Errorf("isTrivyTarget(%q) = %v, want %v", in, got, want)
		}
	}
}

// ===== 按端口推断的风险 =====

// TestPortRisk 高危端口风险库: 已知端口有结论, 未知端口返回空。
func TestPortRisk(t *testing.T) {
	if sev, title, _ := portRisk(6379); sev != "high" || title == "" {
		t.Fatalf("6379 应判为高危, 实际 %s/%s", sev, title)
	}
	if _, title, _ := portRisk(8888); title != "" {
		t.Fatalf("未知端口不应有结论, 实际 %q", title)
	}
}

// TestProtocolOf 端口到协议推断。
func TestProtocolOf(t *testing.T) {
	cases := map[int]string{
		443: "https", 8443: "https", 80: "http", 8080: "http",
		161: "udp", 53: "udp", 22: "tcp",
	}
	for port, want := range cases {
		if got := protocolOf(port); got != want {
			t.Errorf("protocolOf(%d) = %q, want %q", port, got, want)
		}
	}
}

// TestArpHardwareAvailableNoRecursion 能力探测必须立即返回, 不能自我递归。
//
// 背景(真实踩过的坑): probe/scanner 的 ArpHardwareAvailable 是转发 scanner 包的
// 同名函数, 若误写成 `return ArpHardwareAvailable()` 就是自身递归 —— Go 的栈溢出
// 属 fatal error, recover 拦不住、日志也写不进去, 现场只表现为"进程静默消失"。
// 本用例用超时守住这条线。
func TestArpHardwareAvailableNoRecursion(t *testing.T) {
	done := make(chan bool, 1)
	go func() { done <- ArpHardwareAvailable() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ArpHardwareAvailable 未返回(可能自我递归导致栈溢出)")
	}
}

// TestCaptureSupportedNoRecursion 同上: CaptureSupported 也必须立即返回。
func TestCaptureSupportedNoRecursion(t *testing.T) {
	done := make(chan bool, 1)
	go func() { done <- CaptureSupported() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CaptureSupported 未返回(可能自我递归导致栈溢出)")
	}
}

// TestEngineBinPathExported 导出版引擎路径查找与内部实现一致。
func TestEngineBinPathExported(t *testing.T) {
	if got, want := EngineBinPath("nmap"), engineBinPath("nmap"); got != want {
		t.Fatalf("导出版与内部实现不一致: %q vs %q", got, want)
	}
}

// TestGuessOSByPorts 端口组合推断系统(粗粒度)。
func TestGuessOSByPorts(t *testing.T) {
	if got := guessOSByPorts(portResultsForTest(135, 139, 445)); got != "Windows" {
		t.Fatalf("Windows 特征端口应判为 Windows, 实际 %q", got)
	}
	if got := guessOSByPorts(portResultsForTest(22, 111, 2049)); got != "Linux / Unix" {
		t.Fatalf("Unix 特征端口应判为 Linux/Unix, 实际 %q", got)
	}
	if got := guessOSByPorts(portResultsForTest(80)); got != "" {
		t.Fatalf("无特征端口应返回空, 实际 %q", got)
	}
}
