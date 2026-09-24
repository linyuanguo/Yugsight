package weakpass

import (
	"context"
	"net"
	"strings"
)

// Checker 单协议口令尝试器。
//
// 约定: TryAuth 只负责"在已建立的连接上完成一次认证尝试", 连接的建立/超时/
// 关闭由 Engine 统一处理 —— 这样每个协议实现只需关心协议本身, 也便于用
// net.Pipe 替身做纯离线单测(把 conn 换成管道即可)。
type Checker interface {
	// Name 协议名(与 Target.Service 对齐)
	Name() string
	// TryAuth 用 user/pass 尝试一次认证。ok=true 表示认证通过。
	// 返回 error 表示本次尝试未能完成(网络/协议错), 不代表"口令错误"。
	TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error)
}

// Supported 已支持的协议名(供状态接口展示与前端提示)。
//
// 返回副本: 调用方改动不会影响包内注册表。
func Supported() []string {
	names := make([]string, 0, len(registry))
	for _, n := range order {
		names = append(names, n)
	}
	return names
}

// UnsupportedProtocols 明确不支持的协议(标准库实现成本过高, 不伪造结果)。
//
// 单独列出来是为了让调用方能给出**可操作的提示**: 用户看到"MSSQL 不支持"时
// 应该知道这是能力边界, 而不是"MSSQL 没有弱口令"。
//
// 目前只剩 mssql: TDS 登录需要 SQL Server 私有的"口令混淆算法"(把口令的
// UTF-16 字节按位翻转后异或 0xA5 再交换半字节) —— 那个算法本身是公开且可实现的,
// 但它要求先完成 TDS 预登录协商(含服务端证书/加密协商), 在纯标准库下无法稳定
// 覆盖所有版本, 因此暂不实现, 而不是给一个不可靠的判定。
func UnsupportedProtocols() []string {
	return []string{"mssql"}
}

var (
	// order 决定 Supported() 的输出顺序(map 遍历顺序不稳定, 状态接口需要稳定输出)
	order = []string{
		"redis", "mysql", "postgresql", "telnet", "ftp",
		"ssh", "smb", "vnc", "rdp", "oracle",
	}
	registry = map[string]Checker{
		"redis":      redisChecker{},
		"mysql":      mysqlChecker{},
		"postgresql": postgresChecker{},
		"telnet":     telnetChecker{},
		"ftp":        ftpChecker{},
		"ssh":        sshChecker{},
		"smb":        smbChecker{},
		"vnc":        vncChecker{},
		"rdp":        rdpChecker{},
		"oracle":     oracleChecker{},
	}
)

// normalizeService 归一化服务名(去空白、小写, 并按端口/别名推断)。
func normalizeService(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "redis", "redis-server":
		return "redis"
	case "mysql", "mariadb":
		return "mysql"
	case "telnet", "text", "login", "generic":
		return "telnet"
	case "ftp", "ftp-data":
		return "ftp"
	case "ssh", "sshd":
		return "ssh"
	case "rdp", "ms-wbt-server", "3389":
		return "rdp"
	case "smb", "microsoft-ds", "samba":
		return "smb"
	case "mssql", "ms-sql-s", "sqlserver":
		return "mssql"
	case "oracle":
		return "oracle"
	case "postgresql", "postgres":
		return "postgresql"
	case "vnc":
		return "vnc"
	}
	return s
}

// checkerOf 按服务名取实现; 不支持的协议返回 nil(由调用方转 ErrUnsupported)。
func checkerOf(service string) Checker {
	return registry[normalizeService(service)]
}

// ===== 读写小工具(各协议共用) =====

// writeAll 写入全部字节(带 ctx 取消感知: 连接已设 deadline, 这里只做错误包装)。
func writeAll(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// readLine 读到 \r\n 或 \n 为止(逐字节读, 够用且不会多吞数据)。
//
// 逐字节读是刻意的: 一次 Read 到缓冲里再切分, 会把下一轮的响应字节一并吃掉,
// 而 Redis/FTP 的多行应答正是靠"下一轮继续读"来解析的。
func readLine(conn net.Conn, max int) (string, error) {
	var sb strings.Builder
	one := make([]byte, 1)
	for i := 0; i < max; i++ {
		n, err := conn.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return strings.TrimSuffix(sb.String(), "\r"), nil
			}
			sb.WriteByte(one[0])
			continue
		}
		if err != nil {
			if sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
	}
	return sb.String(), nil
}

// readUntil 持续读取直到数据中出现任一关键字, 或达到上限/出错。
//
// 用于 telnet 这类"先吐横幅再给提示符"的交互式服务: 提示符出现的位置不固定,
// 只能边读边判。
func readUntil(conn net.Conn, keys []string, max int) (string, bool, error) {
	var sb strings.Builder
	buf := make([]byte, 512)
	for sb.Len() < max {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			got := strings.ToLower(sb.String())
			for _, k := range keys {
				if strings.Contains(got, k) {
					return sb.String(), true, nil
				}
			}
			continue
		}
		if err != nil {
			return sb.String(), false, err
		}
	}
	return sb.String(), false, nil
}
