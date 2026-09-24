// probe_agent_update.go 探针自动更新的中心端装配: 版本比对 + 更新包分发。
//
// 为什么单独成文件(项目规则 1: 新增功能优先独立文件):
//
//	probe_agent_download.go 已有"用户手动下载 agent 包"的完整链路(平台白名单、
//	文件名容忍、目录穿越防护、ServeContent 续传)。本文件复用它的全部查找逻辑,
//	只补上"中心端主动告诉探针该更新了, 并提供一条探针能免会话下载的通道"。
//	probe_api.go 只加两处接线(注入版本提供者 + 注册一条路由), 既有流程零改动。
//
// 设计要点:
//
//  1. 版本比对是**中心端单向判断**: 中心端手上 agents/ 里有哪个版本, 探针就该是
//     哪个版本。探针不参与"谁更新"的决策, 避免两边各自判断导致版本来回横跳。
//  2. 更新包下载必须**免会话**: 探针只有一条 TCP 长连接, 没有浏览器 cookie, 而
//     现有 /agent/download 走 requireAuth 会话鉴权。这里不改既有路由的鉴权(那会
//     把用户下载通道一并打开), 而是新增一条用**节点密钥签名**的通道。
//  3. 签名而非明文 token: URL 会进日志/代理记录。用 HMAC(token, 路径+过期) 让
//     密钥本身不出现在 URL 里, 且签名带有效期(过期后即使 URL 泄漏也无法复用)。
//  4. 全链路降级: 未配置 probe / agents 目录为空 / 平台包缺失, 一律返回"无更新"
//     而非错误 —— 自动更新是增强能力, 任何一环缺失都不该影响探针正常上线(规则 3/4)。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"yugsight/probe"
	"yugsight/server"
)

// probeVerText 版本号为空时给人话说法(与 probe 包内的 verOrUnknown 同口径,
// 但那是未导出函数, 主包不能直接用)。
func probeVerText(v string) string {
	if v == "" {
		return "未知"
	}
	return v
}

// mainFileSHA256 计算文件 SHA256(十六进制小写)。
//
// 与 probe 包内的同名函数各自独立: probe 是通信层, 主包不应为了算个摘要而导出
// 它的内部工具(那会把(实现细节固化进公共 API)。二十行代码重复一次, 换取两个
// 包可以各自演进, 是划算的。
func mainFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ===== 版本比对 =====

// agentUpdateVersion 中心端当前对外提供的 agent 版本。
//
// 与探针端 cmd/agent 的 agentVersion 同源(都是构建时注入的 appVersion)。
// 两者由同一份源码编译, 版本号应当一致; 不一致即表示探针是旧包。
func agentUpdateVersion() string {
	return appVersion
}

// centerUpdateDirective 版本比对: 返回该版本探针应执行的更新指令(nil = 无需更新)。
//
// probeOS/probeArch 来自探针注册上报的 NodeInfo(见 protocol.NodeInfo.OS/Arch),
// 因此中心端**能精确知道该发哪个平台的包**, 不需要猜。
//
// 【判据为什么是"不相等"而不是"小于"】版本号没有可靠的比较依据(可能是
// 1.0.0 / 1.0.0-rc1 / 自定义构建号, 语义化比较对这些非标准串不可靠)。而
// "与中心端不一致就同步成中心端的"这个口径在此场景下是正确的 —— 中心端是唯一
// 权威来源, 用户要的就是"所有探针和中心端保持同一版本"。降级(探针比中心端新)
// 同样会被纠正, 这也符合预期: 中心端才是发布基线。
//
// 返回 nil 表示无需更新或不支持更新(平台越界/该平台无包/地址推导不出)。
func centerUpdateDirective(reportVer, probeOS, probeArch string) *probe.UpdateDirective {
	cur := agentUpdateVersion()
	if reportVer == cur {
		return nil
	}
	// 平台必须在白名单内, 且中心端手上要有该平台的包 —— 否则更新必然 404,
	// 不如直接不下发(探针端就不必白跑一次下载)。
	o, a, _, _, ok := agentPlatform(probeOS, probeArch)
	if !ok {
		return nil
	}
	if _, _, found := findAgentBinary(o, a); !found {
		return nil
	}
	url := updateDownloadURL(o, a)
	if url == "" {
		return nil
	}
	return &probe.UpdateDirective{
		Version: cur,
		URL:     url,
		Force:   true,
		Note:    fmt.Sprintf("中心端版本 %s, 探针当前 %s", cur, probeVerText(reportVer)),
	}
}

// updateDownloadURL 拼出探针可免会话下载的更新包地址(带签名与有效期)。
//
// 地址用中心端实际监听地址(agentAdvertiseAddr)拼装 —— 探针能连通中心端说明该
// 地址对它可达, 这是最可靠的来源(比让用户配置"对外地址"更不容易出错)。
func updateDownloadURL(osName, arch string) string {
	token := probeCfg.Center.Token
	if strings.TrimSpace(token) == "" {
		// 未设密钥(内网免鉴权部署): 签名失去意义, 直接用无签名通道。
		// 此时中心端本身就不校验身份, 更新包也不比扫描能力更敏感。
		return ""
	}
	exp := time.Now().Add(24 * time.Hour).Unix()
	sig := agentUpdateSign(token, osName, arch, exp)
	base := updateBaseURL()
	if base == "" {
		return ""
	}
	return fmt.Sprintf("%s/api/v2/probe/agent/update?os=%s&arch=%s&exp=%d&sig=%s",
		base, osName, arch, exp, sig)
}

// updateBaseURL 探针下载更新包的基地址(不含路径)。
//
// 复用地址推导(它已处理 "0.0.0.0:8600"/":8600" 这类绑全网卡写法, 退化为局域网 IP)。
// 用 OrDefault 变体而非原函数: 中心端 listen 未配置时会按默认 :8600 监听, 此时
// 原函数返回空串会让更新静默失效(探针明明连上了却永远下不到包)。
// 真推导不出地址时返回空串 → 不下发更新, 而不是给一个探针连不上的地址让它反复重试。
func updateBaseURL() string {
	addr := agentAdvertiseAddrOrDefault()
	if addr == "" {
		return ""
	}
	scheme := "http"
	// 中心端是否启用 HTTPS 由主程序决定(见 server 包); 此处按主程序当前监听
	// 方案推导: 默认 http(本项目默认无 TLS, 内网部署)。若将来加 TLS, 应在此处
	// 按 server 配置返回 https —— 保留 TODO 注释是为了让后续改动有明确落点。
	return scheme + "://" + addr
}

// ===== 下载签名 =====

// agentUpdateSign 计算更新下载签名: HMAC-SHA256(token, "os|arch|exp")。
//
// 把平台与有效期一并签进去, 而不是只签 token: 否则一个签名就能下载任意平台、
// 且永久有效。签入内容后, 签名与"这一份、这段时间"绑定。
func agentUpdateSign(token, osName, arch string, exp int64) string {
	mac := hmac.New(sha256.New, []byte(token))
	fmt.Fprintf(mac, "%s|%s|%d", osName, arch, exp)
	return hex.EncodeToString(mac.Sum(nil))
}

// agentUpdateSignOK 校验下载签名(定长比较避免时序侧信道)。
func agentUpdateSignOK(token, osName, arch string, exp int64, sig string) bool {
	if token == "" {
		return false // 未设密钥时不允许走签名通道(该场景走无签名分支, 见 updateDownloadURL)
	}
	if time.Now().Unix() > exp {
		return false
	}
	want := agentUpdateSign(token, osName, arch, exp)
	return hmac.Equal([]byte(want), []byte(strings.ToLower(strings.TrimSpace(sig))))
}

// ===== HTTP 接口 =====

// hAgentUpdate GET /api/v2/probe/agent/update?os=&arch=&exp=&sig=
//
// 探针免会话下载更新包。鉴权走 URL 签名(见 agentUpdateSign), **不走 requireAuth** —
// 探针没有会话 cookie。
//
// 与 /agent/download 的区别: 后者给人在浏览器里用(会话鉴权 + 附件文件名), 前者给
// 探针用(签名鉴权 + 无 Content-Disposition 干扰)。两条通道分离后, 任一方的安全
// 策略调整都不会影响另一方。
func hAgentUpdate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	osName := strings.TrimSpace(q.Get("os"))
	arch := strings.TrimSpace(q.Get("arch"))
	o, a, _, _, ok := agentPlatform(osName, arch)
	if !ok {
		// 平台越界一律 404: 不回显可用平台列表(那是管理信息, 不该给未鉴权请求)。
		server.FailNotFound(w, "更新包不存在")
		return
	}
	exp, err := strconv.ParseInt(strings.TrimSpace(q.Get("exp")), 10, 64)
	if err != nil {
		server.FailBadRequest(w, "签名参数无效")
		return
	}
	if !agentUpdateSignOK(probeCfg.Center.Token, o, a, exp, q.Get("sig")) {
		// 过期与签名错误合并为一条 403: 分开回显会给攻击者提供"签名对不对"
		// 的判定信息, 而合法探针遇到这两种情况都只需重新注册(会拿到新签名)。
		server.Fail(w, http.StatusForbidden, 40300, "更新签名无效或已过期, 请重新注册获取新的下载地址")
		return
	}
	path, _, found := findAgentBinary(o, a)
	if !found {
		server.FailNotFound(w, "中心端未提供该平台的更新包")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		server.FailInternal(w, "更新包读取失败: "+err.Error())
		return
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		server.FailInternal(w, "更新包状态读取失败: "+err.Error())
		return
	}
	// 不设 Content-Disposition: 探针是按字节流处理, 不需要"另存为"文件名。
	// (若沿用附件头, 某些 HTTP 客户端会据此改写保存名, 反而干扰)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	// 暴露摘要给探针端做完整性校验: 比在协议里传 sha256 更省事, 且永远与文件同步。
	if sum, err := mainFileSHA256(path); err == nil {
		w.Header().Set("X-Yugsight-SHA256", sum)
	}
	http.ServeContent(w, r, agentOutputName(o, a), fi.ModTime(), f)
}

// ===== 接线 =====

// setupAgentAutoUpdate 把版本提供者注入中心端(在 startCenter 之后调用)。
//
// 注入后: 探针每次注册, 中心端都会按探针上报的 OS/Arch 精确分发对应平台的更新
// 指令; 未注入时行为与升级前完全一致(无更新能力), 保证默认关闭(规则 5)。
//
// 【为什么守卫用 probeCfg 而不是 probeEnabled()(关键, 别改回)】本函数运行在
// instanceProbe 的 probeOnce.Do 闭包内(startCenter 调用它), 而 probeEnabled 内部
// 走 registerProbeOnce -> instanceProbe, 即对**同一个 sync.Once 二次 Do**。
// sync.Once 不可重入: 同 goroutine 内二次 Do 会永久阻塞等待第一次 Do 完成, 而
// 第一次 Do 又停在这里 —— 死锁, 表现是主程序启动后卡在"探针中心端已启动"之后,
// Web 服务永远起不来(浏览器不弹页面、8420 不监听)。probeCfg 在同一 Do 闭包开头
// 已赋值(早于 startCenter), 同 goroutine 直接读取安全。
func setupAgentAutoUpdate() {
	if probeCenter == nil {
		return
	}
	if !probeCfg.Center.Enabled {
		return
	}
	probeCenter.SetUpdateProvider(centerUpdateDirective)
}
