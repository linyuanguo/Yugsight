//go:build !windows

package scanner

import (
	"context"
	"time"

	"yugsight/internal/scanner"
)

// syn_other.go 非 Windows 平台的 SYN 扫描空桩(与 syn_windows.go 对应, 项目规则 2)。
//
// 这里返回"不支持"而不是实现一个"总是失败"的版本: 后者会让 SynScanSupported() 为真,
// 中心端据此把节点当"有 SYN 能力"调度, 结果每次都降级 —— 能力上报必须说实话。
//
// Linux/macOS 若要支持, 在此文件按 AF_INET+SOCK_RAW+IPPROTO_TCP 实现 synPlatformSupported
// 与 synScanPorts 即可(报文构造与判定在 syn.go, 全平台通用, 无需改动)。

func synPlatformSupported() bool { return false }

func synScanPorts(ctx context.Context, host string, ports []int, timeout time.Duration) ([]scanner.PortResult, error) {
	return nil, errSynUnsupported
}
