//go:build !windows

package envdetect

// 非 Windows 平台空桩: Npcap 是 Windows 抓包驱动, 此处保证全平台编译通过。

import (
	"fmt"
	"os/exec"
)

func detectNpcap() NpcapStatus {
	return NpcapStatus{Supported: false, Installed: false, Source: "non-windows"}
}

// StartInstaller 非 Windows 平台不支持安装 Npcap
func StartInstaller(_ string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("Npcap 为 Windows 专属组件, 当前平台不支持安装")
}
