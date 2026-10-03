//go:build windows

// certtrust_windows.go — 判定中心自签根 CA 是否已装入 Windows 信任存储。
//
// 背景: 浏览器不向网页 JS 暴露"证书是否受系统信任" —— 受信(锁标)与"用户点了
// 继续访问"(地址栏"不安全")两种情况 isSecureContext 都是 true, 前端永远做不到
// "装了就不提示、没装就提示"。但中心端进程是原生 Windows 进程, 能直接读证书
// 存储, 这是唯一可靠的依据。handleAuthStatus 据此返回 certTrusted, 登录页按
// 真实状态自动显示/隐藏安装引导条:
//   - 根 CA 在机器存储或当前用户存储 → 受信 → 不提示(无需点任何按钮);
//   - 两处都没有 → 提示(用户卸载证书后刷新页面提示自动回来, 含 certmgr 手动卸载)。
//
// 实现: 取 rootCA.crt(generateCertPair 的固定根 CA)的 SHA1 指纹, 用 certutil 列
// "受信任的根证书颁发机构"(Root)存储, 在输出里找指纹十六进制串。指纹与系统
// 显示语言无关, 只匹配 hex 串、不解析 certutil 的中英文输出结构, 规避本地化
// 坑。结果缓存 5s(登录页每次加载拉一次 status, 避免高频起 certutil 进程)。
//
// 降级: 任何读取失败(certutil 缺失/存储读失败/根 CA 未加载)返回 false —— 登录
// 页按"未受信"显示引导条, 属安全方向(宁多提示, 不漏提示)。

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
)

// certTrustMu 只用于串行化并发请求(避免同时起多个 certutil 进程), 不做时间
// 缓存: 登录页每次加载只调一次 /api/auth/status, 低频无性能顾虑; 而"装完证书
// 刷新页面提示立刻消失"要求每次都读到存储的最新真实状态, 时间缓存会在此场景
// 读到旧值(提示不消失), 故弃用。
var certTrustMu sync.Mutex

// certTrustedBySystem 返回自签根 CA 是否已装入机器或当前用户的根证书存储。
// 根 CA 不可用(未启用 TLS)时返回 false —— 此时登录页 selfSigned 也为 false,
// 引导条同样不会出现。
func certTrustedBySystem() bool {
	certTrustMu.Lock()
	defer certTrustMu.Unlock()
	thumb := rootCaFingerprint()
	if thumb == "" {
		return false
	}
	// 两个存储任一命中即受信: 浏览器按两存储并集校验; 历史安装路径可能落在
	// 机器存储(certutil -addstore)或用户存储(-user -addstore)。
	ok := storeHasCert("", thumb) || storeHasCert("-user", thumb)
	slog.Info("根证书信任态检查", "trusted", ok)
	return ok
}

// rootCaFingerprint 返回根 CA 的 SHA1 指纹(十六进制, 无连字符, 大写); 未加载返空。
// rootCACert 启动期由 ensureCertAssets 一次性写入后只读(GetCertificate 回调同口径),
// 此处直接读不锁, 与 issueCertForHost 一致。
func rootCaFingerprint() string {
	if rootCACert == nil {
		return ""
	}
	sum := sha1.Sum(rootCACert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// storeHasCert 列出 Root(受信任的根证书颁发机构)存储, 判断输出中是否含指纹。
// userFlag: ""=机器存储, "-user"=当前用户存储。
// 只匹配指纹十六进制串(去非 hex 字符后大写比较): 指纹与显示语言无关, 输出里
// 无论"指纹 = XXXX-..."还是"Fingerprint = XXXX-..."都会归一成纯 hex 命中。
func storeHasCert(userFlag, thumb string) bool {
	args := []string{"-store", "Root"}
	if userFlag != "" {
		args = []string{userFlag, "-store", "Root"}
	}
	out, err := exec.Command("certutil", args...).Output()
	if err != nil {
		return false
	}
	norm := make([]byte, 0, len(out)/3)
	for _, b := range out {
		if (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f') {
			norm = append(norm, b)
		}
	}
	return strings.Contains(strings.ToUpper(string(norm)), thumb)
}
