// version_test.go 版本号注入的护栏测试。
//
// 【背景】用户要求"正常每次更新会加 1, 比如 1.0.0.1 升为 1.0.0.2"; 自增逻辑在
// scripts/version.ps1(构建时把仓库根 VERSION 末位 +1, 再用 -ldflags 注入)。
//
// 这里守的是"注入通道本身"能不能用 —— 脚本再对, 若 main.appVersion 是 const,
// 链接器就无法改写它(-X 只能作用于变量), 表现为"构建成功但版本号永远不变",
// 且不报任何错。这类静默失效必须被测试挡住。
package main

import (
	"regexp"
	"testing"
)

// versionRe 版本号形态: 数字点分, 至少两段(与 scripts/version.ps1 的口径一致)
var versionRe = regexp.MustCompile(`^\d+(\.\d+)+$`)

// TestAppVersionFormat 版本号必须是合法的数字点分形态。
//
// 为什么重要: 这个值会被拼进 UI 页脚、报告署名("Yugsight v1.0.4")、探针上报,
// 一旦构建脚本注入了空串或带 BOM 的乱码(项目里多次踩过 UTF-8 BOM 的坑:
// PowerShell 5.1 的 Set-Content -Encoding UTF8 会写 BOM), 界面就会出现
// "Yugsight v" 这种残缺署名。
func TestAppVersionFormat(t *testing.T) {
	if appVersion == "" {
		t.Fatal("appVersion 不能为空(会导致 UI 出现 'Yugsight v' 残缺署名)")
	}
	// BOM 是最隐蔽的一种污染: 肉眼看不出, 但正则与比较都会失配
	if len(appVersion) > 0 && appVersion[0] == 0xEF {
		t.Fatalf("appVersion 带 UTF-8 BOM(构建脚本写 VERSION 时应使用无 BOM 编码): %q", appVersion)
	}
	if !versionRe.MatchString(appVersion) {
		t.Fatalf("appVersion 形态非法: %q(应为 1.0.0 这样的数字点分形态)", appVersion)
	}
}

// TestAppVersionIsSettableByLdflags 守住"appVersion 必须是变量"这一前提。
//
// ldflags 的 -X 只能改写**变量**, 对 const 会报错或静默无效。这里用编译期+运行期
// 双重方式确认它是可赋值的变量: 若有人把它改回 const, 本文件将无法编译,
// 从而在 go test/go build 阶段就暴露, 而不是等到用户发现"版本号不涨"。
func TestAppVersionIsSettableByLdflags(t *testing.T) {
	orig := appVersion
	defer func() { appVersion = orig }()
	appVersion = "9.9.9"
	if appVersion != "9.9.9" {
		t.Fatal("appVersion 不是可赋值变量(若被改成 const, ldflags 注入会失效)")
	}
}
