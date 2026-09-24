package main

// 任务 4.2: 环境检测 API(本地引擎 ./bin/ + Npcap 驱动状态上报 / 安装触发)。
// 引擎缺失时由 envdetect 自动标记降级(切换内置引擎), 前端据此置灰。

import (
	"net/http"
	"runtime"
	"time"

	"yugsight/envdetect"
)

// handleEnvStatus GET /api/env: 当前环境检测快照(引擎列表/版本 + Npcap 驱动 + 降级标记)
func handleEnvStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, envdetect.Get())
}

// handleEnvRefresh POST /api/env/refresh: 触发重新检测(重扫 bin/ + 重读注册表)
func handleEnvRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	envdetect.Refresh()
	jsonOK(w, envdetect.Get())
}

// handleEnvInstall POST /api/env/install: 执行项目根目录(exe 同目录)的 Npcap 安装器。
// 免费版安装器不支持静默, 拉起 GUI 安装向导并轮询安装结果(与抓包"一键安装"同策略:
// 不依赖退出码, 以驱动实际装好为准)。
func handleEnvInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if runtime.GOOS != "windows" {
		jsonErr(w, http.StatusBadRequest, "Npcap 为 Windows 专属组件, 当前平台不支持安装该驱动")
		return
	}
	st := envdetect.Get()
	if st.Npcap.Installed {
		jsonErr(w, http.StatusBadRequest, "Npcap 驱动已安装, 无需重复安装")
		return
	}
	if st.Npcap.Installer == "" {
		jsonErr(w, http.StatusBadRequest, "未找到 Npcap 安装器: 请先将 npcap-setup.exe(或 npcap-*.exe 官方安装器)放到项目根目录(exe 同目录)")
		return
	}
	// 先停抓包释放 wpcap.dll 占用, 否则安装器替换文件时会失败
	PcapRelease()
	cmd, err := envdetect.StartInstaller(st.Npcap.Installer)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "启动 Npcap 安装器失败: "+err.Error())
		return
	}
	done := make(chan error, 1)
	if cmd != nil {
		go func() { done <- cmd.Wait() }()
	}
	for i := 0; i < 100; i++ { // 最多等待 5 分钟(安装向导全程)
		time.Sleep(3 * time.Second)
		if npcapInstalled() {
			envdetect.Refresh() // 重读注册表, 前端刷新即见"已安装"
			logLine("Npcap 安装完成(环境检测页触发): " + st.Npcap.Installer)
			jsonOK(w, map[string]any{"ok": true, "installer": st.Npcap.Installer})
			return
		}
		if cmd != nil {
			select {
			case werr := <-done:
				// 安装器已退出且未装好: 用户取消或出错
				if werr != nil {
					jsonErr(w, http.StatusInternalServerError, "Npcap 安装失败或已取消: "+werr.Error())
				} else {
					jsonErr(w, http.StatusInternalServerError, "Npcap 安装器已退出但未检测到安装结果, 请重试")
				}
				return
			default:
			}
		}
	}
	jsonErr(w, http.StatusInternalServerError, "5 分钟内未检测到安装完成, 请确认安装向导已点完(装完需重启本程序)")
}
