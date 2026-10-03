//go:build !windows

package scanner

import "syscall"

// setIPTTL 设置套接字发出数据包的 TTL(路由跟踪逐跳控制的关键)。
// Linux/macOS 的 syscall.SetsockoptInt 收 int。
func setIPTTL(fd uintptr, ttl int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}
