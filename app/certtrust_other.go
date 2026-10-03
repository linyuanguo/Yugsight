//go:build !windows

// certtrust_other.go — 非 Windows 平台空桩。
//
// 非 Windows 下中心端无法可靠读取"访问者浏览器所在机器"的信任存储(远程访问时
// 浏览器在另一台机器上, 读本机存储无意义), 一律返回 false: 登录页回退为"自签
// 部署恒显示引导条", 用户可点"不再提示"永久收起(前端 localStorage 兜底, 见
// Login.vue)。保证全平台可编译(规则 2)。

package main

// certTrustedBySystem 见 certtrust_windows.go 同名函数; 非 Windows 恒 false。
func certTrustedBySystem() bool { return false }
