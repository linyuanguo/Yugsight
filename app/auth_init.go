// auth_init.go 初始账号自动创建 + 登录鉴权开关(settings.json 的 auth 节)。
//
// 需求背景: 此前全新安装必须先在登录页手动"注册"才能用 —— 用户双击 exe 后面对
// 一个要求自己发明账号密码的表单, 而不是能直接登录的账号。现改为:
//   - 首次启动自动创建初始账号(默认 admin / admin123), 并把明文账密写进
//     settings.json 的 auth 节 —— 用户打开配置文件即可看到、可修改;
//   - auth 节的 enabled=false 可整体关闭登录(所有接口免鉴权), 默认开启。
//
// 设计取舍:
//   - 明文 user/pass 只作为"初始值", 校验始终走 salt+sha256 哈希(users 映射),
//     不存在"改配置文件明文就能登录"的旁门; 修改密码 = 删掉 auth 节的 users/salt
//     后重启, 程序按 user/pass 重建(示例文件里有说明);
//   - 建号只在账号库为空时发生一次: 若每次启动都按明文重置, 用户在页面侧做的
//     任何账号变更都会被配置文件覆盖, 属于灾难性行为;
//   - 免登录模式下不建号: 账号此时无人使用, 往配置文件写默认密码反而让用户
//     困惑"这个密码是干嘛的"。
package main

import "fmt"

// applyAuthSwitch 应用 settings.json auth 节的 enabled 开关(缺省=开启鉴权)。
// 显式 false 时复用既有 authDisabled 通道: requireAuth 全放行、whoami 返回
// 免登录态, 前端零改动直进主界面 —— 与 -no-auth / test_mode.txt 同一语义,
// 只是入口从命令行/文件换成了配置节。必须在 loadAuth() 之后调用。
func applyAuthSwitch() {
	if authStore == nil || authStore.Enabled == nil || *authStore.Enabled {
		return
	}
	authDisabled = true
	logLine("settings.json auth.enabled=false: 已关闭登录鉴权, 所有接口免登录(自用模式)")
}

// initDefaultAccount 全新安装(账号库为空且未免登录)时按 settings.json auth 节的
// user/pass 创建初始账号; 未配置时用默认 admin/admin123 并把明文回写配置文件。
// 必须在 loadAuth() 之后调用(依赖已加载的 authStore)。
func initDefaultAccount() {
	if authDisabled {
		// -no-auth / test_mode.txt / auth.enabled=false 三种免登录来源都不建号
		return
	}
	authMu.Lock()
	defer authMu.Unlock()
	if authStore == nil || len(authStore.Users) > 0 {
		return
	}
	user, pass := authStore.User, authStore.Pass
	if user == "" {
		user = "admin"
	}
	if pass == "" {
		pass = "admin123"
	}
	if !validUser(user) || len(pass) < minPassLen {
		// 配置不合法时降级为旧注册模式, 不报错不崩溃 —— 用户改好配置重启即可
		logLine(fmt.Sprintf("settings.json auth 节初始账号不合法(user=%q): 用户名需 2-20 位字母/数字/_/-, 密码至少 %d 位; 已忽略, 请在登录页手动注册", user, minPassLen))
		return
	}
	// User/Pass 一并写回: 明文账密留在 settings.json 里供用户查看(需求本意)
	authStore.User, authStore.Pass = user, pass
	authStore.Users[user] = userRec{PassHash: hashPass(authStore.Salt, pass)}
	saveAuth()
	logLine(fmt.Sprintf("已创建初始账号 %s / %s (明文账密见 settings.json 的 auth 节, 登录后请尽快修改)", user, pass))
}
