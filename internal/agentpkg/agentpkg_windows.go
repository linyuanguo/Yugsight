//go:build windows

package agentpkg

// Supported Windows 端为空桩: 不做就地补包。
//
// 设计决策: Windows 上统一走 scripts/build-agents.ps1 产出(脚本已处理 6 平台
// 矩阵、CGO 静态链接、环境变量清理), 中心端不另开第二条补包路径 —— 两条路径
// 并存的产物口径漂移会让"下载到的包"与"脚本产出的包"不一致, 排查成本更高。
// 前端按 Supported()==false + SupportNote() 决定按钮置灰与原因文案。
func Supported() bool { return false }

// SupportNote 空桩平台给用户的说明。前端 list 接口的 build.note 与补包接口
// 400 的错误文案都用它 —— 必须说清"该怎么做"(用构建脚本), 不能只说"不支持"。
func SupportNote() string {
	return "当前平台(windows)不支持就地补包: 请在开发机运行 scripts/build-agents.ps1 产出 6 平台探针包, 再放入 exe 同目录的 agents/ 目录"
}
