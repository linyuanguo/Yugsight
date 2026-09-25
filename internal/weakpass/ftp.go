package weakpass

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// ftpChecker FTP 弱口令 / 匿名访问检测。
//
// 判定口径(纯文本状态码, 标准库足够):
//
//	220 服务就绪(连上即收到)
//	USER <user> -> 331 需要口令 / 230 已登录(免口令账号)
//	PASS <pass> -> 230 登录成功 / 530 登录失败
//
// 空口令场景: 用户名为 anonymous 时多数 FTP 允许任意口令(匿名访问),
// 用空口令尝试能直接暴露这类配置。
type ftpChecker struct{}

func (ftpChecker) Name() string { return "ftp" }

func (ftpChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	// 220 欢迎横幅(有些实现不发, 拿不到不阻断)
	readLine(conn, 4096)

	if err := writeAll(conn, []byte("USER "+user+"\r\n")); err != nil {
		return false, fmt.Errorf("ftp 发送 USER 失败: %w", err)
	}
	resp, err := readLine(conn, 4096)
	if err != nil {
		return false, fmt.Errorf("ftp 读取 USER 应答失败: %w", err)
	}
	if strings.HasPrefix(resp, "230") {
		return true, nil // 用户名即登录(无需口令)
	}
	if !strings.HasPrefix(resp, "331") {
		return false, fmt.Errorf("ftp USER 应答异常: %s", truncate(resp, 80))
	}
	if err := writeAll(conn, []byte("PASS "+pass+"\r\n")); err != nil {
		return false, fmt.Errorf("ftp 发送 PASS 失败: %w", err)
	}
	resp, err = readLine(conn, 4096)
	if err != nil {
		return false, fmt.Errorf("ftp 读取 PASS 应答失败: %w", err)
	}
	switch {
	case strings.HasPrefix(resp, "230"):
		return true, nil
	case strings.HasPrefix(resp, "530"), strings.HasPrefix(resp, "501"), strings.HasPrefix(resp, "503"):
		return false, nil
	}
	return false, fmt.Errorf("ftp PASS 应答未识别: %s", truncate(resp, 80))
}

// truncate 截断字符串(错误信息里回显服务端原文时限制长度)。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
