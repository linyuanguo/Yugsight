//go:build !windows

package agentpkg

// Supported 非 Windows(服务器中心端场景): 提供就地补包能力
// (工具链 + 源码目录齐备时, 中心端可直接补出当前平台的探针包)。
func Supported() bool { return true }

// SupportNote 非空桩平台无"不可用原因", 返回空串;
// 前端仅在空桩平台用它展示置灰原因。
func SupportNote() string { return "" }
