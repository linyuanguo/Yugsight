package scanner

import "syscall"

// setIPTTL 设置套接字发出数据包的 TTL(路由跟踪逐跳控制的关键)。
// Windows 的 syscall.SetsockoptInt 收 Handle(其他平台是 int, 见 ttl_other.go)。
func setIPTTL(fd uintptr, ttl int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}
