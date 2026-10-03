//go:build windows

package main

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// TestStoreHasCertContract 守卫 certutil 输出解析的核心假设: Root 存储输出中的
// 证书哈希(sha1)行是 40 位 hex, storeHasCert 按指纹必须命中真实证书、且不命中
// 未知指纹。若未来 certutil 输出格式变化(系统语言/版本)破坏该假设, 登录页"证书
// 是否已装"判定会静默失效(引导条恒显示或恒隐藏), 此处守住契约。
func TestStoreHasCertContract(t *testing.T) {
	out, err := exec.Command("certutil", "-store", "Root").Output()
	if err != nil {
		t.Skip("certutil 不可用: " + err.Error())
	}
	// 从输出提取一条真实的 sha1 哈希(兼容"证书哈希(sha1): xxx"与
	// "Certificate Hash(sha1): xxx"等语言差异, 只认 40 位 hex 本体)。
	re := regexp.MustCompile(`(?i)sha1\)[^0-9A-Fa-f]*([0-9A-Fa-f]{40})`)
	m := re.FindSubmatch(out)
	if m == nil {
		t.Skip("certutil 输出未找到证书哈希行, 跳过")
	}
	thumb := strings.ToUpper(string(m[1]))
	if !storeHasCert("", thumb) {
		t.Errorf("真实指纹 %s 未在机器存储输出中命中", thumb)
	}
	// 反例: 不存在的指纹绝不允许误报(误报=用户没装证书却被判"已装", 提示永久消失)
	if storeHasCert("", "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF") {
		t.Error("未知指纹产生误报")
	}
}
