package weakpass

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// telnetChecker 类 Telnet 文本登录服务检测。
//
// 覆盖对象: Telnet, 以及所有"先给 login 提示符、再要 password"的文本服务
// (串口服务器、交换机 Console、部分工控设备的 TCP 管理口等)。
//
// 判定口径(交互是"提示符驱动"的, 没有统一状态码, 只能按文本判):
//
//  1. 连上就直接给 shell 提示符(# / $ / >)而从未要 login → **免认证**, 命中。
//  2. 正常流程: 送用户名 → 等 password 提示符 → 送口令 → 读回应:
//     - 出现失败关键字(incorrect / failed / denied / invalid) → 口令错误;
//     - 又回到 login 提示符 → 口令错误(重登);
//     - 出现 shell 提示符 → 登录成功。
//
// 判定保守: 只要出现失败关键字就判失败(宁可漏报也不误报成"弱口令"),
// 因为误报会让人去改一个其实很强的口令, 而漏报只是少一条提示。
type telnetChecker struct{}

func (telnetChecker) Name() string { return "telnet" }

var (
	// loginPrompts 用户名提示符关键字(用片段而非全词: "Login:" / "login:" / "ogin:" 都要认)
	loginPrompts = []string{"login:", "username:", "user:", "用户", "username", "login"}
	// passPrompts 口令提示符关键字
	passPrompts = []string{"password:", "passwd:", "口令", "密码", "password"}
	// failKeys 登录失败关键字
	failKeys = []string{"incorrect", "failed", "failure", "denied", "invalid",
		"错误", "失败", "拒绝", "invalid password", "authentication failed"}
)

func (telnetChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	// 1) 等用户名提示符(先读一段横幅; 横幅里可能什么都不给)
	banner, gotLogin, err := readUntil(conn, loginPrompts, 8192)
	if err != nil && !gotLogin && banner == "" {
		return false, fmt.Errorf("telnet 读取横幅失败: %w", err)
	}
	if !gotLogin {
		// 从没要用户名就给了命令提示符 = 免认证(比弱口令更严重)
		if looksLikeShell(banner) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("telnet 未出现登录提示符: %w", err)
		}
		return false, fmt.Errorf("telnet 未出现登录提示符(无法判定, 不猜测)")
	}
	// 2) 送用户名
	if err := writeAll(conn, []byte(user+"\r\n")); err != nil {
		return false, fmt.Errorf("telnet 发送用户名失败: %w", err)
	}
	// 3) 等口令提示符
	_, gotPass, err := readUntil(conn, passPrompts, 8192)
	if err != nil && !gotPass {
		return false, fmt.Errorf("telnet 等待口令提示符失败: %w", err)
	}
	if !gotPass {
		// 送了用户名却不要口令: 该服务只认用户名, 属免认证
		return true, nil
	}
	// 4) 送口令
	if err := writeAll(conn, []byte(pass+"\r\n")); err != nil {
		return false, fmt.Errorf("telnet 发送口令失败: %w", err)
	}
	// 5) 读回应并判定
	resp, _, err := readUntil(conn, append(append([]string{}, failKeys...), shellKeys...), 8192)
	if err != nil && resp == "" {
		return false, fmt.Errorf("telnet 读取登录回应失败: %w", err)
	}
	low := strings.ToLower(resp)
	for _, k := range failKeys {
		if strings.Contains(low, k) {
			return false, nil
		}
	}
	// 又回到 login 提示符 = 被踢回重登。
	//
	// 必须只看**最后一行**是否以提示符结尾: 登录成功的横幅里常见
	// "Last login: Mon ..." 这种字样, 用全串 Contains 会把成功判成失败。
	if endsWithLoginPrompt(resp) {
		return false, nil
	}
	return looksLikeShell(resp), nil
}

// loginPromptEnds 行尾形态的登录提示符(用于"被踢回重登"判定)。
var loginPromptEnds = []string{"login:", "login", "username:", "username", "user:", "user name:", "ogin:"}

// endsWithLoginPrompt 最后一行是否以登录提示符结尾。
//
// 只取最后一个非空行: 登录回应可能前面带横幅("Last login: ..."),
// 只有"最终停在提示符上"才说明又要重新登录。
func endsWithLoginPrompt(s string) bool {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.ToLower(strings.TrimSpace(strings.TrimRight(lines[i], "\r \t")))
		if line == "" {
			continue
		}
		for _, k := range loginPromptEnds {
			if strings.HasSuffix(line, k) {
				return true
			}
		}
		return false
	}
	return false
}

// shellKeys 命令提示符关键字(用于 readUntil 提前收敛)。
var shellKeys = []string{"#", "$ ", "> ", "~"}

// looksLikeShell 文本里是否出现命令提示符。
//
// 只认"行尾形态"的提示符(前边有换行或就是首字符), 否则横幅里随便一个
// '#' 或 '>' 都会被当成 shell —— 那种误判会让所有目标都报"免认证"。
func looksLikeShell(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r \t")
		line = strings.TrimSpace(line)
		switch {
		case strings.HasSuffix(line, "#"), strings.HasSuffix(line, "$"),
			strings.HasSuffix(line, ">"), strings.HasSuffix(line, "%"):
			return true
		}
	}
	return false
}
