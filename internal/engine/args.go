package engine

import (
	"strconv"
	"strings"
)

// ===== 各引擎默认参数组装 =====
//
// 输出格式与 normalizer 适配器对齐:
//   - nmap  -oJ  → JSON 到 stdout   → normalizer.FromNmapJSON
//   - trivy -f json → JSON 到 stdout → normalizer.FromTrivyJSON
//   - zap   -J <file> → JSON 报告文件 → normalizer.FromZAPJSON
//
// opts 变参为追加的引擎参数(插入在目标参数之前), 调用方可按需覆盖默认行为。

// ArgsNmap Nmap 参数: TCP 连接扫描 + 跳过主机发现 + 只列开放端口 + JSON 输出到 stdout。
//
//	nmap -sT -Pn -p <ports> --open -oJ - <target> [追加参数]
//
// ports 为空时默认扫 80,443。
//
// 【Windows 平台注意(2026-09-20 实测, 勿改回)】Windows 版 nmap(7.94 官方构建)
// 的 -oJ 完全不可用: "-oJ -" 与 "-oJ <file>" 的值都会被当成扫描目标(报
// Failed to resolve "-"/"...json")。Windows 请改用 ArgsNmapFile(XML 落文件);
// 本函数仅适用于 Linux("-oX -" 亦可用)。-Pn 同因 Windows 主机发现依赖 pcap
// 嗅探(VPN 虚拟网卡/无 Npcap 时 pcap_create 失败直接 QUITTING)而默认加上。
func ArgsNmap(target string, ports []int, opts ...string) []string {
	args := []string{"-sT", "-Pn", "-p", joinPorts(ports), "--open", "-oJ", "-"}
	args = append(args, opts...)
	return append(args, target)
}

// ArgsNmapFile Nmap 参数(XML 落文件版, 跨平台可用): 输出写 XML 报告文件,
// 由调用方读回后交给 parsers.ParseNmap(首字符自动识别 XML/JSON)。
//
//	nmap -sT -Pn -p <ports> --open -oX <reportFile> <target> [追加参数]
//
// 与 ArgsNmap 的差异只在输出通道: Windows 版 nmap 的 -oJ 不可用(见上),
// 且 XML 报告含 hostscript NSE 结果, 信息量大于 JSON。中心端编排器
// (parsers.buildArgs + parsers.NmapArtifact)统一走本形态。
func ArgsNmapFile(target string, ports []int, reportFile string, opts ...string) []string {
	args := []string{"-sT", "-Pn", "-p", joinPorts(ports), "--open", "-oX", reportFile}
	args = append(args, opts...)
	return append(args, target)
}

// ArgsTrivyFS Trivy 参数: 文件系统 / 依赖扫描, JSON 输出到 stdout。
//
//	trivy fs -f json <目标路径> [追加参数]
func ArgsTrivyFS(target string, opts ...string) []string {
	args := []string{"fs", "-f", "json"}
	args = append(args, opts...)
	return append(args, target)
}

// ArgsTrivyImage Trivy 参数: 容器镜像扫描, JSON 输出到 stdout。
//
//	trivy image -f json <镜像> [追加参数]
func ArgsTrivyImage(image string, opts ...string) []string {
	args := []string{"image", "-f", "json"}
	args = append(args, opts...)
	return append(args, image)
}

// ArgsZap ZAP 参数: 无界面自动化扫描(spider + 主动扫描), JSON 报告写入文件。
//
//	zap -cmd -quickurl <目标URL> -quickout <报告文件> [追加参数]
//
// 【实测记录(2026-09, ZAP 2.17.0, Windows)】本函数原先用的是 "-g 0 -t <url> -J <file>",
// 这是一个**双重的错误**, 实测后修正:
//
//	错误1: 缺 -cmd → ZAP 以 Swing GUI 模式启动, 弹出窗口并常驻等用户操作。
//	错误2: -t / -J 不是 ZAP 2.17 的可用参数 → ZAP 打印帮助后直接退出,
//	       既不扫描也不生成报告。表现为"扫了但没结果", 极难从日志看出问题。
//
// 修正后实测(对本地 127.0.0.1 静态站点):
//
//	无窗口弹出; 174s 自动退出; 生成 11420 字节合法 JSON 报告。
//
// 【为什么必须有 -cmd(关键, 别删)】ZAP 是 Java **Swing GUI** 程序, zap.bat/zap.sh
// 不带 -cmd 时会进图形界面模式, 命令行的自动化选项执行完也不退出。这对本项目是
// 致命的 —— 中心端/探针都在后台无人值守运行, 弹 GUI 会 ①任务永远不结束,
// ②无桌面的服务器上直接启动失败。其官方语义见 -help 输出:
//
//	-cmd   Run inline (exits when command line options complete)
//
// 与 -daemon 的区别: -daemon 是常驻无 UI 代理服务(供反复调 API), 本场景要一次性
// 扫完即退, 用 -cmd。
//
// 【为什么用 -quickurl/-quickout 而不是 -t/-J】ZAP 的 -help 明确写了
//
//	-quickurl <target url>   要扫描的 URL, 例如 http://www.example.com
//	-quickout <filename>     报告写到文件, 类型由扩展名决定(.json/.html/.xml/.md)
//
// -quickurl 会同时跑 spider + 主动扫描, 一步到位; 报告类型靠**文件扩展名**区分,
// 所以调用方传的 reportFile 必须以 .json 结尾(与 normalizer.FromZAPJSON 对接)。
//
// 特别注意: Go 侧 job_windows.go 设的 CREATE_NO_WINDOW **拦不住** GUI 窗口 ——
// 它只抑制 Windows 控制台窗口, 而 Swing 窗口由 JVM 自行创建, 属于另一套机制。
// 唯一可靠的手段是让 ZAP 自己以命令行方式运行, 即 -cmd。
func ArgsZap(targetURL, reportFile string, opts ...string) []string {
	args := []string{"-cmd", "-quickurl", targetURL, "-quickout", reportFile}
	args = append(args, opts...)
	return args
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return "80,443"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
