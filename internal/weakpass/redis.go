package weakpass

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// redisChecker Redis 弱口令 / 未授权访问检测。
//
// 判定口径:
//
//  1. 先发 PING: 返回 +PONG 说明**无需认证即可执行命令**—— 这是未授权访问,
//     比弱口令更严重, 且与具体口令无关, 一次尝试即可定性。
//  2. 服务端要求认证(-NOAUTH)时, 再发 AUTH <pass>: +OK 即口令正确。
//
// 用内联命令(inline command)而非 RESP 数组: Redis 两者都支持, 内联在文本层
// 更易读也更好排错, 且不受 RESP2/RESP3 协商差异影响。
type redisChecker struct{}

func (redisChecker) Name() string { return "redis" }

func (redisChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	resp, err := redisCmd(conn, "PING")
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(resp, "+PONG") {
		return true, nil // 免认证: 未授权访问
	}
	// 其余情况(含 -NOAUTH)都继续按口令尝试
	resp, err = redisCmd(conn, "AUTH", pass)
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(resp, "+OK") {
		return true, nil
	}
	if strings.HasPrefix(resp, "-") {
		return false, nil // -ERR / -WRONGPASS / -NOAUTH: 口令不对
	}
	return false, nil
}

// redisCmd 发一条内联命令并读一行应答。
func redisCmd(conn net.Conn, args ...string) (string, error) {
	cmd := strings.Join(args, " ") + "\r\n"
	if err := writeAll(conn, []byte(cmd)); err != nil {
		return "", fmt.Errorf("redis 发送失败: %w", err)
	}
	line, err := readLine(conn, 4096)
	if err != nil {
		return "", fmt.Errorf("redis 读取应答失败: %w", err)
	}
	return line, nil
}
