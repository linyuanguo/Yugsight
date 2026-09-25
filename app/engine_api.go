package main

// 任务 6.2: 引擎输出解析 + 自动降级 —— 编排层装配与状态上报。
//
// 本文件是"engine 执行器(6.1)"与"engine/parsers 解析/降级(6.2)"在 main 包的
// 唯一接线点(最小侵入, 不改动既有扫描流程):
//
//   - instanceOrchestrator(): 全局单例, 接好外部引擎执行器 + 内置引擎兜底 Runner;
//   - handleEngineStatus GET /api/engine/status: 引擎就绪状态 + 版本 + 降级统计,
//     与 envdetect(4.2) 的 /api/env 互为补充(env 是"文件探测", 这里是"实际使用统计");
//   - handleEngineRefresh POST /api/engine/refresh: 重读 engine.json 并重建编排器。
//
// 降级策略见 engine/parsers/orchestrator.go 头部注释: 引擎缺失/执行失败/输出截断/
// 解析失败 → 自动切换内置引擎; 超时/取消 → 不重复扫描直接返回。
// engine.json(exe 同目录, 可选)可调开关, 缺失即默认值(默认关闭外部引擎, 零影响)。

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"yugsight/internal/engine"
	"yugsight/internal/engine/parsers"
	"yugsight/internal/envdetect"
	"yugsight/internal/normalizer"
	"yugsight/internal/scanner"
)

// EngineConfig 外部引擎编排配置(exe 同目录 engine.json, 可选)。
// 缺省: 外部引擎关闭(enabled=false), 一切走内置引擎, 与旧版本行为一致。
type EngineConfig struct {
	// Enabled 总开关: true 时才把外部引擎接入扫描编排(默认 false)
	Enabled bool `json:"enabled"`
	// Engines 启用的引擎名(nmap/trivy/zap), 空 = 全部
	Engines []string `json:"engines,omitempty"`
	// TimeoutSec 单引擎执行超时(秒), 0 = 取默认 600
	TimeoutSec int `json:"timeoutSec,omitempty"`
	// DisableFallback 关闭自动降级(仅调试用: 失败直接返回错误)
	DisableFallback bool `json:"disableFallback,omitempty"`
	// BinDir 引擎二进制目录, 空 = exe 同目录 bin/
	BinDir string `json:"binDir,omitempty"`
}

var (
	engOnce sync.Once
	engCfg  EngineConfig
	engOrch *parsers.Orchestrator
	engLog  []string // 最近若干条编排/降级日志(供面板展示, 环形)
	engMu   sync.Mutex
)

const engLogMax = 100

// instanceOrchestrator 返回全局引擎编排器(懒加载单例, 并发安全)。
// 未启用外部引擎时仍返回可用编排器: 任何请求都会走内置降级路径。
func instanceOrchestrator() *parsers.Orchestrator {
	engOnce.Do(func() {
		engCfg = loadEngineConfig()
		cfg := engine.Config{}
		if engCfg.TimeoutSec > 0 {
			cfg.Timeout = time.Duration(engCfg.TimeoutSec) * time.Second
		}
		if dir := strings.TrimSpace(engCfg.BinDir); dir != "" {
			cfg.BinDir = dir
		}
		ex := engine.NewExecutor(cfg)
		engOrch = parsers.NewEngineOrchestrator(ex, builtinRunner)
		engOrch.DisableFallback = engCfg.DisableFallback
		engOrch.SetLogger(engineLog)
		if !engCfg.Enabled {
			// 总开关关闭: 断开外部执行器 -> 所有请求直接走内置降级(零外部进程调用)
			engOrch.SetExec(nil)
			engineLog("外部引擎编排: 未启用(engine.enabled=false), 全部使用内置引擎")
		} else {
			engineLog("外部引擎编排: 已启用, 引擎 " + engineSummary() + " (失败自动降级为内置引擎)")
		}
	})
	return engOrch
}

func engineSummary() string {
	if len(engCfg.Engines) == 0 {
		return "nmap/trivy/zap(全部)"
	}
	return strings.Join(engCfg.Engines, "/")
}

// engineEnabled 外部引擎是否已启用(前端据此提示"当前为内置引擎模式")
func engineEnabled() bool {
	instanceOrchestrator()
	return engCfg.Enabled
}

// engineLog 记录编排/降级日志(并入 yugsight.log 并保留最近 100 条供面板展示)
func engineLog(s string) {
	logLine("引擎编排: " + s)
	engMu.Lock()
	engLog = append(engLog, time.Now().Format("15:04:05")+"  "+s)
	if len(engLog) > engLogMax {
		engLog = engLog[len(engLog)-engLogMax:]
	}
	engMu.Unlock()
}

// 引擎配置的文件名常量已删除(2026-09-23 红线整改): 引擎相关配置(enabled /
// binDir / downloads)全部落在 settings.json 的 engine 节, 不再有 engine.json。
// 读取统一走 section(secEngine, ""), 保存统一走 writeSection(secEngine, ...)。

// loadEngineConfig 读 exe 同目录 engine.json(可选, 缺失/损坏一律用默认值不报错)。
//
// 用 readConfigFile 而非直接 ReadFile: 它会剥掉 Windows 记事本/PowerShell 写出的
// UTF-8 BOM。带 BOM 时 json.Unmarshal 会失败, 表现为"engine.json 里 enabled=true
// 却不生效" —— 而用户手写这个文件正是主路径(实测踩过)。
func loadEngineConfig() EngineConfig {
	var cfg EngineConfig
	// 优先读 settings.json 的 engine 节, 回退 engine.json(旧单文件)。
	data, ok := section(secEngine, "")
	if !ok {
		return cfg
	}
	if json.Unmarshal(data, &cfg) != nil {
		logLine("engine 配置解析失败, 使用默认配置(外部引擎关闭)")
		return EngineConfig{}
	}
	return cfg
}


// engineBinDir 引擎二进制目录(与 engine/envdetect 约定一致: exe 同目录 bin/)。
func engineBinDir() string {
	if dir := strings.TrimSpace(engCfg.BinDir); dir != "" {
		return dir
	}
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(".", "bin")
	}
	return filepath.Join(filepath.Dir(exe), "bin")
}

// builtinRunner 内置引擎兜底(降级目标)。
//
// 说明: 内置能力按"目标 + 端口"做 TCP 存活/端口探测, 不发起漏洞利用;
// 漏洞判定仍由内置规则库(vuln_builtin.json)+ Nuclei 模板承担(既有流程)。
// 这里只保证"外部引擎不可用时任务不中断, 且有资产结果可用"。
func builtinRunner(ctx context.Context, req parsers.Request) (*normalizer.RawBatch, error) {
	rb := &normalizer.RawBatch{Source: normalizer.SourcePortScan}
	host := parseTargetHost(req.Target)
	if host == "" {
		return rb, nil
	}
	ports := req.Ports
	if len(ports) == 0 {
		ports = []int{80, 443}
	}
	// 兜底阶段的进度不推送 SSE(emit 必须非 nil, 否则 ScanPorts 内会空指针),
	// 结果统一走返回的 RawBatch 由调用方归一化
	results := scanner.ScanPorts(ctx, host, ports, 800*time.Millisecond, 100, func(string, any) {})
	for _, r := range results {
		if r.State != "open" {
			continue
		}
		rb.Assets = append(rb.Assets, normalizer.RawAsset{IP: host, Ports: []int{r.Port}})
	}
	return rb, nil
}

// parseTargetHost 从目标串里取出主机。
//
// 两阶段顺序是关键: 先剥 scheme/前缀, 再切首段路径。
//   - "http://10.0.0.5:8080/x" -> 剥 http:// -> "10.0.0.5:8080/x" -> 切路径 -> "10.0.0.5:8080" -> 去端口 -> 10.0.0.5
//   - "fs:/app"                -> 剥 fs:     -> "/app"            -> 切路径(首字符) -> "app"
// 反过来先切路径会把 "http://a" 砍成 "http:", 因此顺序不可调换。
func parseTargetHost(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	for _, p := range []string{"http://", "https://", "image:", "fs:"} {
		if strings.HasPrefix(strings.ToLower(t), p) {
			t = t[len(p):]
			break
		}
	}
	// 切首段路径; 剥前缀后首字符是 / 时(如 fs:/app)先跳过分隔符
	t = strings.TrimLeft(t, "/\\")
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	return t
}

// ===== API =====

// handleEngineStatus GET /api/engine/status: 引擎编排状态(开关/统计/降级日志)
func handleEngineStatus(w http.ResponseWriter, r *http.Request) {
	o := instanceOrchestrator()
	st := o.Stats()
	engMu.Lock()
	logs := append([]string(nil), engLog...)
	engMu.Unlock()

	jsonOK(w, map[string]any{
		"enabled":       engCfg.Enabled,
		"engines":       engCfg.Engines,
		"timeoutSec":    effectiveTimeoutSec(),
		"binDir":        engineBinDir(),
		"execReady":     st.ExecReady,
		"fallbackReady": st.FallbackReady,
		"lastSource":    st.LastSource,
		"degradeCount":  st.DegradeCount,
		"detected":      envdetect.Get(), // 4.2 的文件探测结果(引擎路径/版本/降级标记)
		"degradeLog":    logs,
	})
}

// handleEngineRefresh POST /api/engine/refresh: 重新读取 engine.json 并重建编排器
func handleEngineRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resetOrchestrator()
	jsonOK(w, map[string]any{"ok": true, "enabled": engineEnabled()})
}

// resetOrchestrator 重置单例(配置改动后调用; 同时清空编排日志)
func resetOrchestrator() {
	engMu.Lock()
	engLog = nil
	engMu.Unlock()
	engOnce = sync.Once{}
	_ = instanceOrchestrator()
}

func effectiveTimeoutSec() int {
	if engCfg.TimeoutSec > 0 {
		return engCfg.TimeoutSec
	}
	return 600
}

// EngineStatusSnapshot 供 /api/info 与面板共用的精简快照
type EngineStatusSnapshot struct {
	Enabled      bool   `json:"enabled"`
	ExecReady    bool   `json:"execReady"`
	LastSource   string `json:"lastSource,omitempty"`
	DegradeCount int    `json:"degradeCount"`
}

// engineSnapshot 精简状态(供 /api/info 内联)
func engineSnapshot() EngineStatusSnapshot {
	o := instanceOrchestrator()
	st := o.Stats()
	return EngineStatusSnapshot{
		Enabled:      engCfg.Enabled,
		ExecReady:    st.ExecReady,
		LastSource:   st.LastSource,
		DegradeCount: st.DegradeCount,
	}
}
