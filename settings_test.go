// settings_test.go 统一配置中心(settings.json)的用例。
//
// 重点覆盖三类风险(都是"静默失效"型缺陷, 不加守护会长期潜伏):
//  1. **优先级**: settings.json 的节必须优先于旧单文件, 否则用户迁移后
//     会发现"新的不生效、旧的还在起作用", 极其困惑;
//  2. **回退兼容**: settings.json 没有该节时必须回退读旧文件, 否则升级即
//     静默丢失老配置(最容易造成生产事故的一类变更);
//  3. **合并写**: 写某个节不能破坏其它节 —— 用户的注释与其它配置必须原样保留。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"yugsight/engine/parsers"
	"yugsight/scheduler"
)

// settingsTestMu 串行化本文件的所有用例。
//
// 【为什么必须串行 —— 这是踩出来的, 不是预防性加锁】
// 本文件的用例都要往"测试进程 exe 同目录"写 settings.json(见 writeTestSettings
// 的说明), 而该路径是**整个包共享的唯一文件**。同时 settings / scheduler 的配置
// 都是进程级缓存与包级注入变量(scheduler.SetConfigReader/SetConfigPath), 一旦两个
// 用例并发跑, 就会出现:
//
//   - A 用例写了 settings.json, B 用例正在读 → B 读到 A 的数据;
//   - A 用例的 Cleanup 删了文件, B 用例尚未读完 → 读到"配置不存在";
//   - A 注入的 scheduler reader 未复位, B 的调度器读到了 A 的配置 →
//     表现为**完全无关的用例失败**(实测: TestSchedulerSaveFallsBackToLegacy 与
//     TestSchedSubmitAndControl 并发时, 后者报"取消后状态错误: failed")。
//
// 这类失败是**偶发**的(取决于调度顺序与机器负载), 单跑必过、全量跑偶尔挂 ——
// 比稳定失败更危险, 因为很容易被当成"flaky 忽略掉"。所以这里用互斥锁把整个
// 文件内的用例串起来, 把不确定性彻底消掉。
//
// 用 Mutex 而非 t.Parallel: 这些用例本质是"独占修改全局配置", 天然不该并行。
var settingsTestMu sync.Mutex

// withTempExeDir 取得配置测试的独占权并重置配置缓存。
//
// 返回的目录仅用于让调用方放置回退用的旧单文件(如 capture.json); settings.json
// 本身固定写在测试进程的 exe 同目录(见 writeTestSettings)。
//
// settings.json 与各回退文件的定位都基于 os.Executable() 的目录, 无法用参数改写
// (那样测的就不是生产路径了)。因此隔离手段是"独占 + 用完即清", 而不是换目录。
func withTempExeDir(t *testing.T) string {
	t.Helper()
	settingsTestMu.Lock()
	t.Cleanup(settingsTestMu.Unlock)
	resetSettingsCache()
	t.Cleanup(resetSettingsCache)
	return t.TempDir()
}

// writeTestSettings 把 settings.json 内容写入测试进程 exe 目录并重置缓存。
//
// 【为什么必须写真实文件而不是注入内存缓存】本项目的读写路径都经 os.Executable(),
// 若为测试专门加一个"路径可注入"的分支, 测的就不是生产路径了 —— 那样的用例无法
// 发现"路径解析本身"的错误。测试进程的 exe 位于 Go 构建的临时目录, 写在那里不会
// 碰到开发机的真实配置。**调用方必须先经 withTempExeDir 取得独占权**。
func writeTestSettings(t *testing.T, content string) {
	t.Helper()
	resetSettingsCache()
	p := settingsFilePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("写 settings.json 失败: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(p)
		os.Remove(p + ".bak")
		resetSettingsCache()
	})
}

// TestSettingsSectionBasic 基本读取: 各节能按名取到, 未配置的节返回不存在。
func TestSettingsSectionBasic(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{
	  "_comment": "这是注释, 不应出现在节列表里",
	  "capture": {"loopDetect": true, "captureAll": false},
	  "screen": {"metrics": true}
	}`)

	// 已配置的节
	data, ok := sectionBytes(secCapture)
	if !ok {
		t.Fatal("capture 节应存在")
	}
	var c struct {
		LoopDetect bool `json:"loopDetect"`
		CaptureAll bool `json:"captureAll"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("解析 capture 节失败: %v", err)
	}
	if !c.LoopDetect || c.CaptureAll {
		t.Fatalf("capture 节字段错位: %+v", c)
	}

	// 未配置的节: 必须返回 false, 由调用方决定默认值。
	// 这里显式断言"不存在"而不是"返回零值" —— 若实现改成永远返回零值 JSON,
	// 调用方就无法区分"用户没写"与"用户写了空配置", 各模块的降级策略会全部失效。
	if _, ok := sectionBytes(secScheduler); ok {
		t.Fatal("scheduler 节未配置, 应返回 false")
	}
}

// TestSettingsSectionNull 显式写 null 视为未配置。
//
// 若把 "null" 当内容返回, json.Unmarshal 会成功但字段全零, 调用方看到的是
// "配置读到了但值都是空的" —— 比"未配置"更难排查。
func TestSettingsSectionNull(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"report": null}`)
	if _, ok := sectionBytes(secReport); ok {
		t.Fatal("显式 null 应视为未配置")
	}
}

// TestSettingsBOM 带 UTF-8 BOM 的 settings.json 必须能解析。
//
// Windows 记事本与 PowerShell Set-Content -Encoding utf8 都会写 BOM, 而用户
// 手写配置是主路径。这个坑在 probe.json / screen.json / engine.json 上分别
// 踩过, 统一入口这里必须一次挡住。
func TestSettingsBOM(t *testing.T) {
	withTempExeDir(t)
	// 前提校验: 先确认未剥 BOM 时确实会失败, 避免用例恒真
	raw := []byte(`{"screen":{"metrics":true}}`)
	bom := append([]byte{0xEF, 0xBB, 0xBF}, raw...)
	var probe map[string]json.RawMessage
	if json.Unmarshal(bom, &probe) == nil {
		t.Fatal("前提失效: 带 BOM 的内容竟然能直接解析, 本用例失去意义")
	}

	writeTestSettings(t, string(bom))
	if _, ok := sectionBytes(secScreen); !ok {
		t.Fatal("带 BOM 的 settings.json 应能正常解析出 screen 节")
	}
}

// TestSettingsFallbackToLegacy 节缺失时回退读旧单文件(升级不丢配置)。
//
// 这是本次改造最关键的兼容性保证: 老机器上已有的 engine.json / capture.json
// 必须继续生效。若只认 settings.json, 升级后老配置会**静默失效** —— 用户不会
// 收到任何提示, 只会发现"我明明配了环路检测怎么不生效"。
func TestSettingsFallbackToLegacy(t *testing.T) {
	withTempExeDir(t)
	// settings.json 存在但不含 capture 节
	writeTestSettings(t, `{"screen":{"metrics":true}}`)

	// 旧文件里有 capture 配置
	legacy := filepath.Join(filepath.Dir(settingsFilePath()), "capture.json")
	if err := os.WriteFile(legacy, []byte(`{"capture":{"loopDetect":true}}`), 0o600); err != nil {
		t.Fatalf("写 capture.json 失败: %v", err)
	}
	t.Cleanup(func() { os.Remove(legacy) })

	data, ok := section(secCapture, "capture.json")
	if !ok {
		t.Fatal("settings.json 无 capture 节时应回退读到 capture.json")
	}
	if !strings.Contains(string(data), "loopDetect") {
		t.Fatalf("回退内容不对: %s", data)
	}
}

// TestSettingsPriority settings.json 优先于旧单文件。
//
// 若优先级反了, 用户把配置搬进 settings.json 后会发现"改新的没用", 而旧文件
// 还在暗中生效 —— 这比"读不到"更难排查, 因为两处配置看起来都"写对了"。
func TestSettingsPriority(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"screen":{"metrics":true}}`)

	// 旧文件里放相反的值
	legacy := filepath.Join(filepath.Dir(settingsFilePath()), "screen.json")
	if err := os.WriteFile(legacy, []byte(`{"metrics":false}`), 0o600); err != nil {
		t.Fatalf("写 screen.json 失败: %v", err)
	}
	t.Cleanup(func() { os.Remove(legacy) })

	data, ok := section(secScreen, "screen.json")
	if !ok {
		t.Fatal("screen 节应可读")
	}
	if !strings.Contains(string(data), "true") {
		t.Fatalf("应取 settings.json 的值, 实际: %s", data)
	}
}

// TestSettingsMalformed 非法 JSON 时降级为空(各模块走各自默认值), 不 panic。
func TestSettingsMalformed(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"capture": {"loopDetect": true`) // 截断的 JSON

	// 不应 panic; 且应返回"未配置"(各模块自行降级)
	if _, ok := sectionBytes(secCapture); ok {
		t.Fatal("非法 JSON 应视为未配置")
	}
}

// TestWriteSectionPreservesOthers 合并写: 写一个节不得破坏其它节与注释。
//
// 这是程序自动保存(账号库/白名单)高频路径的核心保证。整文件重写会抹掉用户
// 手写的 _comment 与格式, 且这类丢失不可逆 —— 用户下次打开发现"我写的东西
// 没了", 却无从判断是程序干的。
func TestWriteSectionPreservesOthers(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{
	  "_comment": "用户手写的说明, 必须保留",
	  "capture": {"loopDetect": true},
	  "screen": {"metrics": true}
	}`)

	if err := writeSection(secWhitelist, map[string]any{
		"entries": []map[string]any{{"id": "wl-1", "type": "cve", "match": "CVE-2021-1"}},
	}); err != nil {
		t.Fatalf("合并写失败: %v", err)
	}

	raw, err := os.ReadFile(settingsFilePath())
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	s := string(raw)

	// 关键断言: 用户内容原样保留
	if !strings.Contains(s, "_comment") || !strings.Contains(s, "用户手写的说明") {
		t.Fatalf("用户注释被抹掉:\n%s", s)
	}
	if !strings.Contains(s, "loopDetect") {
		t.Fatalf("capture 节被破坏:\n%s", s)
	}
	if !strings.Contains(s, `"metrics"`) {
		t.Fatalf("screen 节被破坏:\n%s", s)
	}
	// 新节已写入
	if !strings.Contains(s, "wl-1") {
		t.Fatalf("whitelist 节未写入:\n%s", s)
	}

	// 二次写入另一个节, 前面写的仍要在(验证是合并而非覆盖)
	if err := writeSection(secAuth, map[string]any{"salt": "abc"}); err != nil {
		t.Fatalf("二次合并写失败: %v", err)
	}
	raw2, _ := os.ReadFile(settingsFilePath())
	s2 := string(raw2)
	if !strings.Contains(s2, "wl-1") || !strings.Contains(s2, "abc") || !strings.Contains(s2, "用户手写的说明") {
		t.Fatalf("多次合并写后内容丢失:\n%s", s2)
	}
}

// TestWriteSectionBackupOnCorrupt 文件损坏时先备份再重建, 让用户有机会抢救。
//
// 若直接覆盖, 用户配置被静默清空且无法恢复 —— 备份是最后一道防线。
func TestWriteSectionBackupOnCorrupt(t *testing.T) {
	withTempExeDir(t)
	p := settingsFilePath()
	if err := os.WriteFile(p, []byte(`{"broken": `), 0o600); err != nil {
		t.Fatalf("写坏文件失败: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(p)
		os.Remove(p + ".bak")
	})

	if err := writeSection(secScreen, map[string]any{"metrics": true}); err != nil {
		t.Fatalf("损坏文件应能重建: %v", err)
	}
	if _, err := os.Stat(p + ".bak"); err != nil {
		t.Fatal("损坏文件应被备份为 .bak")
	}
	if _, ok := sectionBytes(secScreen); !ok {
		t.Fatal("重建后应能读到新写入的节")
	}
}

// TestSettingsSectionNames 节列表用于日志展示, 有固定顺序且排除注释键。
func TestSettingsSectionNames(t *testing.T) {
	m := map[string]json.RawMessage{
		"_comment":  json.RawMessage(`"x"`),
		"screen":    json.RawMessage(`{}`),
		"engine":    json.RawMessage(`{}`),
		"__note":    json.RawMessage(`"y"`),
		"custom":    json.RawMessage(`{}`),
		"whitelist": json.RawMessage(`{}`),
	}
	got := settingsSectionNames(m)
	// 已知节按预定义顺序在前(engine < screen < whitelist), 未知节追加在后
	want := []string{"engine", "screen", "whitelist", "custom"}
	if len(got) != len(want) {
		t.Fatalf("节数不符: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("节顺序不符: got=%v want=%v", got, want)
		}
	}
	for _, n := range got {
		if strings.HasPrefix(n, "_") {
			t.Fatalf("下划线键不应出现在节列表: %v", got)
		}
	}
}

// TestStripBOM 剥 BOM 的边界: 有 BOM / 无 BOM / 只有 BOM / 短内容。
func TestStripBOM(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"带BOM", []byte{0xEF, 0xBB, 0xBF, '{', '}'}, "{}"},
		{"无BOM", []byte("{}"), "{}"},
		{"只有BOM", []byte{0xEF, 0xBB, 0xBF}, ""},
		{"空", []byte{}, ""},
		{"短内容", []byte{0xEF}, "\xef"}, // 不足 3 字节不算 BOM
	}
	for _, c := range cases {
		if got := string(stripBOM(c.in)); got != c.want {
			t.Errorf("%s: got=%q want=%q", c.name, got, c.want)
		}
	}
}

// TestSchedulerConfigFromSettings settings.json 的 scheduler 节被装配层正确送达 scheduler 包。
//
// 验证的是"注入链路"而非"解析逻辑": 解析逻辑由 scheduler 包自己的用例覆盖,
// 这里只需确认装配层确实把 settings.json 的内容喂了进去(注入点接错会表现为
// "配置写了但不生效", 而 scheduler 包内部用例完全测不到)。
func TestSchedulerConfigFromSettings(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"scheduler":{"enabled":true,"maxConcurrency":7,"nodeConcurrency":3}}`)
	// 复位 scheduler 包级注入(原因见 TestSchedulerSaveGoesToSettings 的说明)
	t.Cleanup(func() {
		scheduler.SetConfigReader(func() ([]byte, bool) { return nil, false })
	})

	cfg := loadSchedulerConfig()
	if !cfg.Enabled {
		t.Fatal("settings.json 的 scheduler.enabled=true 未生效")
	}
	if cfg.MaxConcurrency != 7 {
		t.Fatalf("maxConcurrency 未送达: %d", cfg.MaxConcurrency)
	}
	if cfg.NodeConcurrency != 3 {
		t.Fatalf("nodeConcurrency 未送达: %d", cfg.NodeConcurrency)
	}
}

// TestEngineConfigFromSettings settings.json 的 engine 节被 engine 配置加载读取。
//
// 注意 engine.json 的结构: 顶层直接是 {enabled, engines, downloads:{...}}。
// 与之对比 capture 节是 {loopDetect, captureAll}(旧 capture.json 外面多包一层
// "capture")。两者结构不同, 用例分别守护, 避免统一时想当然地套用同一层包装。
func TestEngineConfigFromSettings(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"engine":{"enabled":true,"engines":["nmap"],"downloads":{"autoInstall":true}}}`)

	cfg := loadEngineConfig()
	if !cfg.Enabled {
		t.Fatal("engine.enabled 未生效")
	}
	if len(cfg.Engines) != 1 || cfg.Engines[0] != "nmap" {
		t.Fatalf("engines 未生效: %v", cfg.Engines)
	}
	dl := loadEngineDownloadConfig()
	if !dl.AutoInstall {
		t.Fatal("engine.downloads.autoInstall 未生效")
	}
}

// TestCaptureConfigFromSettings capture 节的结构与旧文件不同层, 单独守护。
func TestCaptureConfigFromSettings(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"capture":{"loopDetect":true,"captureAll":false}}`)

	cfg := loadCaptureConfig()
	if !cfg.LoopDetect {
		t.Fatal("capture.loopDetect 未生效")
	}
	if cfg.CaptureAll == nil || *cfg.CaptureAll {
		t.Fatalf("capture.captureAll=false 未生效: %v", cfg.CaptureAll)
	}
}

// TestDownloadAllowedSemantics 下载开关的隐含关系不受配置来源影响。
//
// 这是纯函数, 与配置来源无关, 但放在这里是因为它是"配置读到了但语义不对"的
// 典型 —— autoInstall 蕴含 allowDownload, 写错会让用户以为"开了补装却没反应"。
func TestDownloadAllowedSemantics(t *testing.T) {
	if !downloadsAllowed(engineDownloadConfig{AutoInstall: true}) {
		t.Fatal("autoInstall 应蕴含允许下载")
	}
	if downloadsAllowed(engineDownloadConfig{}) {
		t.Fatal("两项都未开时不应允许下载")
	}
}

// TestSchedulerSaveGoesToSettings 保存调度配置必须写回 settings.json 的 scheduler 节。
//
// 【为什么必须有这个用例】"读哪里就写哪里"是本模块最容易被破坏的不变式:
// 读路径改到 settings.json 后, 若保存仍写旧的 scheduler.json, 就会出现
// ——用户在页面上改完保存、重启后被 settings.json 里的旧值覆盖——
// 表现为"保存功能坏了"。这类缺陷在单测里能一眼看穿, 上线后极难定位。
func TestSchedulerSaveGoesToSettings(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"scheduler":{"enabled":false,"maxConcurrency":2}}`)

	// 【必须在用例结束时复位 scheduler 包的注入状态】
	// loadSchedulerConfig 会设置 scheduler.SetConfigReader/SetConfigPath, 二者是
	// **包级变量**, 不复位就会泄漏给同包后续用例 —— 实测表现为完全无关的
	// TestSchedSubmitAndControl 读到这里的配置后报"取消后状态错误"(偶发, 取决于
	// 用例执行顺序与并行度, 极难定位)。
	// 注意: SetConfigReader/SetConfigPath 内部有 `if f != nil` 守卫, **传 nil 无法
	// 复位**, 因此这里显式在失败时提示, 避免后来者以为传 nil 有效。
	oldPath := schedConfigPath
	t.Cleanup(func() {
		schedConfigPath = oldPath
		// 复位为"总是返回不存在"的空 reader, 等价于回到未注入状态
		scheduler.SetConfigReader(func() ([]byte, bool) { return nil, false })
	})

	cfg := loadSchedulerConfig()
	cfg.MaxConcurrency = 9
	if err := saveSchedulerConfig(cfg); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	// 关键: 必须落在 settings.json 的 scheduler 节, 而不是新建 scheduler.json
	legacyDir := filepath.Dir(settingsFilePath())
	if _, err := os.Stat(filepath.Join(legacyDir, "scheduler.json")); err == nil {
		t.Fatal("已有 scheduler 节时不应另外写 scheduler.json(会导致读写不一致)")
	}
	raw, err := os.ReadFile(settingsFilePath())
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if !strings.Contains(string(raw), "\"scheduler\"") {
		t.Fatalf("scheduler 节丢失:\n%s", raw)
	}
	if !strings.Contains(string(raw), "9") {
		t.Fatalf("新值未写入:\n%s", raw)
	}
}

// TestSchedulerSaveAlwaysToSettings 即使 settings.json 没有 scheduler 节,
// 保存也必须写进 settings.json 的 scheduler 节, 而不是散落成独立 scheduler.json。
//
// 语义(2026-09-23 用户要求): 中心端所有配置一律 settings.json。"配置散落在
// 多份文件"会让用户改 A 文件、服务读 B 文件 —— 因此保存永远落 settings,
// 读取保留 scheduler.json 回退只是兼容存量部署。
func TestSchedulerSaveAlwaysToSettings(t *testing.T) {
	withTempExeDir(t)
	dir := filepath.Dir(settingsFilePath())
	legacy := filepath.Join(dir, "scheduler.json")
	t.Cleanup(func() {
		scheduler.SetConfigReader(func() ([]byte, bool) { return nil, false })
	})

	cfg := scheduler.DefaultConfig()
	cfg.MaxConcurrency = 4
	if err := saveSchedulerConfig(cfg); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if _, err := os.Stat(legacy); err == nil {
		t.Fatal("保存不应再写独立 scheduler.json(配置须统一在 settings.json)")
	}
	raw, err := os.ReadFile(settingsFilePath())
	if err != nil {
		t.Fatalf("读回 settings.json 失败: %v", err)
	}
	if !strings.Contains(string(raw), "\"scheduler\"") || !strings.Contains(string(raw), "4") {
		t.Fatalf("scheduler 节未写入 settings.json:\n%s", raw)
	}
}

// TestParsersImportGuard 确保测试文件引用的 parsers 包未被误删(编译期护栏)。
// (parsers 是 engine 配置相关的解析层, 这里只是防止 import 变成未使用。)
var _ = parsers.Request{}
