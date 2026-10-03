// factory_reset_api.go 一键恢复出厂(授权与模型页"服务管理"区, 2026-09-26)。
//
// 场景: 把 dist/ 打包发给别人前, 清空所有运行期数据 —— 人为保存的 AI 配置、
// 用户配置、审计日志、渗透审计、资产、扫描任务记录、报告中心全部报告。保留
// 软件本体与规则库(vuln/ res/), 对方拿到即全新出厂状态。
//
// POST /api/v2/factory-reset  body: { "cleanEnv": bool }
//   - cleanEnv=false(默认): 只清"用户数据 + 配置"(23 张表 + settings.json + auth
//     账号库), 安全, 不碰运行中的外部引擎/日志;
//   - cleanEnv=true: 额外清 bin/(外部引擎 + .engmgr-blobs 下载缓存) data/agents/
//     (探针包, 2026-09-29 起归入 data) logs/(运行日志), 回收数百 MB —— 发分发包前用这个。
//
// adminOnly: 与同页清空审计/用户管理同档(破坏性红线操作, 操作员不能碰)。
//
// 清理顺序: 先清内存(防"内存回写复活") → 删磁盘文件 → 重置配置 → 重建初始账号。
// 目录删除 best-effort: 引擎运行中/日志被进程锁时删不掉, 记日志不阻断; 彻底干净
// 靠"恢复出厂 → 停止服务 → 复制 dist"(停止服务后内存释放, 残留不再复活)。
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"yugsight/internal/server"
)

func hV2FactoryReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CleanEnv bool `json:"cleanEnv"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	d := v2NeedDB(w)
	if d == nil {
		return
	}
	base := exeDir()

	// 1. 清空 23 张业务表(内存 + 磁盘): 资产/漏洞/扫描任务/通用审计/渗透审计/
	//    报告/原始报告/用户/会话/AI 文档等, 一次清光。
	cleared := d.ClearAll()

	// 2. 删次要数据子目录(无内存 DAO 对应, 删了不会复活):
	//    cache(模板下载缓存) / outp(Word 报告模板, 启动会 ensureWordTplDir 重建) /
	//    scanctl(扫描管线本地白名单)。
	for _, sub := range []string{"cache", "outp", "scanctl"} {
		if err := os.RemoveAll(filepath.Join(base, "data", sub)); err != nil {
			logLine("恢复出厂: 删除 data/"+sub+"/ 失败: "+err.Error())
		}
	}
	// test_mode.txt 免登录开关一并清 —— 发出去的包不该自带免登录。
	if err := os.Remove(filepath.Join(base, "test_mode.txt")); err != nil && !os.IsNotExist(err) {
		logLine("恢复出厂: 删除 test_mode.txt 失败: "+err.Error())
	}

	// 3. cleanEnv: 回收外部引擎 / 探针包 / 运行日志(数百 MB)。best-effort: 引擎
	//    正在被扫描进程占用、或当前日志文件被本进程锁住时删不掉, 记日志不阻断。
	var envCleared []string
	if req.CleanEnv {
		// 探针包已归入 data/agents/(2026-09-29 起), 与 bin/ logs/ 一并回收
		for _, dir := range []string{"bin", filepath.Join("data", "agents"), "logs"} {
			p := filepath.Join(base, dir)
			if err := os.RemoveAll(p); err != nil {
				logLine("恢复出厂: 删除 "+dir+"/ 失败(可能有文件被占用): "+err.Error())
			} else {
				envCleared = append(envCleared, dir)
			}
		}
	}

	// 4. 重置统一配置 settings.json(删文件 + 清进程内缓存) → 对方启动回默认。
	//    2026-09-29 起配置在 data/ 下, 但旧位置(exe 同目录)可能残留迁移前/未迁移的
	//    副本, 两处都删, 防止重启后旧配置"复活"。进程内存里各模块已加载的旧配置
	//    不回收, 靠"停止服务"释放(发分发包前本就要停)。
	for _, p := range []string{settingsFilePath(), filepath.Join(base, settingsFileName)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			logLine("恢复出厂: 删除 settings.json 失败: "+err.Error())
		}
	}
	resetSettingsCache()

	// 5. 重建初始账号: 清光后恢复出厂账号 admin/admin123。initDefaultAccount 在
	//    非免登录且账号库为空时按默认账密建号并写回 settings.json 的 auth 节。
	authMu.Lock()
	if authStore != nil {
		authStore.Users = map[string]userRec{}
		authStore.User = ""
		authStore.Pass = ""
	}
	authMu.Unlock()
	initDefaultAccount()

	logLine(fmt.Sprintf("恢复出厂完成: 清空数据表 %d 条; cleanEnv=%v 清除目录=%v", cleared, req.CleanEnv, envCleared))
	server.OK(w, map[string]any{
		"ok":         true,
		"cleared":    cleared,
		"cleanEnv":   req.CleanEnv,
		"envCleared": envCleared,
		"hint":       "数据与配置已清空, 初始账号 admin/admin123 已重建。请点\"停止服务\"退出后再复制 dist 分发, 以保证彻底干净。",
	})
}
