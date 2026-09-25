package scanner

import "net"

// LocalIPs 返回本机所有非回环 IPv4 地址
func LocalIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			ips = append(ips, ipn.IP.String())
		}
	}
	return ips
}

// LocalIP 检测本机主局域网 IP
// 通过 UDP 路由选择出口网卡(不实际发送数据包), 失败则退回第一个非回环 IPv4
func LocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			if ip4 := addr.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4.String()
			}
		}
	}
	if ips := LocalIPs(); len(ips) > 0 {
		return ips[0]
	}
	return "127.0.0.1"
}
