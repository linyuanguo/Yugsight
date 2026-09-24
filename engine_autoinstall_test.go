// engine_autoinstall_test.go 引擎自动补装的目标筛选测试。
//
// 为什么单独测"筛谁"而不是"真下载": 自动补装的真风险不是下载失败(那只是白费流量),
// 而是**选错了目标** —— 该跳过的没跳过(无差别下载 233MB 的 ZAP)、已装的重复下载、
// 平台不支持的装到一半失败。这三条都在目标筛选里, 所以把筛选逻辑钉死最有价值。
//
// 不触网: 只调 engineAutoInstallTargets, 不调 Install。
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yugsight/engmgr"
)

// writeDummyEngine 在 bin/ 下造一个"已安装"的占位文件, 让 Info().Installed 变为 true。
//
// 【为什么不硬编码文件名】engmgr 的落位名(trivycore.exe 之类)是包内约定, 在这里抄一遍
// 会在 engmgr 改名后变成"假通过": 造了个永远不被识别为已装的文件, 断言成了恒真, 测试
// 还在绿。所以从 engmgr.FindEngine 取权威的 InstallName, 写完再用 Info().Installed 确认。
func writeDummyEngine(t *testing.T, dir, engine string) {
	t.Helper()
	spec, err := engmgr.FindEngine(engmgr.Engine(engine))
	if err != nil {
		t.Fatalf("engmgr.FindEngine(%s) 失败: %v", engine, err)
	}
	name := spec.Want.InstallName
	if name == "" {
		t.Fatalf("%s 未配置 InstallName, 无法造占位文件", engine)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("dummy"), 0o755); err != nil {
		t.Fatalf("造 %s 占位文件失败: %v", name, err)
	}
	m := newTestEngineMgr(t, dir)
	if !engineInfoInstalled(m, engine) {
		t.Fatalf("写入 %s 后 %s 仍未被视为已安装(落位名与检测口径不一致)", name, engine)
	}
}

// engineInfoInstalled 查询某引擎是否被判定为已安装
func engineInfoInstalled(m *engmgr.Manager, engine string) bool {
	for _, info := range m.Info() {
		if string(info.Engine) == engine {
			return info.Installed
		}
	}
	return false
}

// withEngineBin 把引擎目录改指临时目录并在用例结束恢复。
//
// 必须改: 否则会读开发机真实 bin/, "是否已装"的断言随环境漂移(本机装了 trivy 就红)。
func withEngineBin(t *testing.T) string {
	t.Helper()
	prev := engCfg.BinDir
	dir := t.TempDir()
	engCfg.BinDir = dir
	t.Cleanup(func() { engCfg.BinDir = prev })
	return dir
}

// newTestEngineMgr 构造只用于查询 Info() 的 Manager(不启动任何任务)
func newTestEngineMgr(t *testing.T, binDir string) *engmgr.Manager {
	t.Helper()
	m := engmgr.New(binDir)
	m.SetLogger(func(string) {}) // 静音: 测试输出只留断言失败信息
	return m
}

// TestAutoInstallSkipsDefaultOff 未点名引擎时, DefaultOff 的引擎(ZAP)必须被跳过。
//
// 这是自动补装最容易被骂的地方: 用户想要"自动装好能用的", 结果后台闷头下了 233MB
// 的 ZAP, 还因为缺 Java 用不了。
func TestAutoInstallSkipsDefaultOff(t *testing.T) {
	dir := withEngineBin(t)
	m := newTestEngineMgr(t, dir)

	got := engineAutoInstallTargets(engineDownloadConfig{AutoInstall: true}, m)
	for _, name := range got {
		if name == "zap" {
			t.Fatalf("未点名时不应自动安装 DefaultOff 的 ZAP, 实际目标: %v", got)
		}
	}
	// 反向保障: 不能因为要跳过 ZAP 就把所有引擎都跳了(自动补装等于没做)
	if len(got) == 0 {
		t.Fatalf("应至少筛出部分可自动安装的引擎(除非当前平台全不支持), 实际: %v", got)
	}
}

// TestAutoInstallNamesOverride DefaultOff 的引擎被显式点名时必须安装 ——
// "默认跳过"是策略, 不是禁止。
func TestAutoInstallNamesOverride(t *testing.T) {
	dir := withEngineBin(t)
	m := newTestEngineMgr(t, dir)

	got := engineAutoInstallTargets(engineDownloadConfig{
		AutoInstall:        true,
		AutoInstallEngines: []string{"zap"},
	}, m)
	// 平台支持才应出现; 不支持时(某些平台的 ZAP 无官方包)允许为空, 但不能出现别的引擎
	for _, n := range got {
		if n != "zap" {
			t.Fatalf("显式点名 zap 时不应混入其它引擎: %v", got)
		}
	}
	if len(got) == 0 {
		t.Log("当前平台 ZAP 无官方发行包, 已按 supported=false 跳过(符合预期)")
	}
}

// TestAutoInstallSkipsInstalled 已安装的引擎不能重复下载 —— 几百 MB 流量不该白花。
//
// 注意每个断言阶段都要新建 Manager: Info() 是快照语义。
func TestAutoInstallSkipsInstalled(t *testing.T) {
	dir := withEngineBin(t)
	m := newTestEngineMgr(t, dir)

	// 先拿到未装时的目标集合, 取其中一个造出"已装"状态
	before := engineAutoInstallTargets(engineDownloadConfig{AutoInstall: true}, m)
	if len(before) == 0 {
		t.Skip("当前平台没有可自动安装的引擎, 跳过")
	}
	target := before[0]

	// 在 bin/ 里放一个同名文件即让 Manager 判定为已装(它只看目标文件是否存在,
	// 不校验内容 —— 这里正是要验证这一口径)
	writeDummyEngine(t, dir, target)

	// 【每次都必须重新构造 Manager】Info() 结果带缓存(m.info 快照, 只在 refreshInfo 时
	// 更新), 复用旧的 m 会一直读到"未装"的旧快照 —— 这是本用例第一版的真实踩坑:
	// 断言拿到的仍是 before 那份列表, 看起来像"已装不生效"。
	m2 := newTestEngineMgr(t, dir)
	after := engineAutoInstallTargets(engineDownloadConfig{AutoInstall: true}, m2)
	for _, n := range after {
		if n == target {
			t.Fatalf("已安装的 %s 不应再次成为自动安装目标: %v", target, after)
		}
	}
	if len(after) != len(before)-1 {
		t.Fatalf("已装一个后目标数应减 1: before=%v after=%v", before, after)
	}
}

// TestAutoInstallUsesEnginesAsFallback autoInstallEngines 为空时应回落到 engines 字段
// —— 那是用户"我关心哪些引擎"的既有表达, 不必逼他抄第二遍。
func TestAutoInstallUsesEnginesAsFallback(t *testing.T) {
	dir := withEngineBin(t)
	m := newTestEngineMgr(t, dir)

	got := engineAutoInstallTargets(engineDownloadConfig{
		AutoInstall: true,
		Engines:     []string{"trivy"},
	}, m)
	for _, n := range got {
		if n != "trivy" {
			t.Fatalf("engines=[trivy] 时不应出现其它引擎: %v", got)
		}
	}
	// autoInstallEngines 优先于 engines
	got2 := engineAutoInstallTargets(engineDownloadConfig{
		AutoInstall:        true,
		Engines:            []string{"trivy"},
		AutoInstallEngines: []string{"nuclei"},
	}, m)
	for _, n := range got2 {
		if n != "nuclei" {
			t.Fatalf("autoInstallEngines 应优先于 engines: %v", got2)
		}
	}
}

// TestAutoInstallDisabledIsSilent 开关关闭时不得有任何动作(零网络行为)。
//
// 断言点在配置解析层: 空配置(等价于"用户没写 engine.json")必须解析出 AutoInstall=false,
// 这样 startEngineAutoInstall 会直接 return, 不起 goroutine、不发请求。
func TestAutoInstallDisabledIsSilent(t *testing.T) {
	// 默认零值配置 = 全关(项目规则 5: 新增功能默认关闭)
	var cfg engineDownloadConfig
	if cfg.AutoInstall {
		t.Fatal("默认配置不应开启自动补装")
	}
	if downloadsAllowed(cfg) {
		t.Fatal("默认配置不应允许下载(零网络行为)")
	}
	// 配置解析也要尊重这个默认: 缺文件时返回零值
	prev := engineDownloadConfigPath
	engineDownloadConfigPath = func() string { return "" }
	t.Cleanup(func() { engineDownloadConfigPath = prev })
	got := loadEngineDownloadConfig()
	if got.AutoInstall || got.AllowDownload {
		t.Fatalf("无配置文件时应为全关, 实际 %+v", got)
	}
}

// TestDownloadsEnabledImpliesAutoInstall autoInstall 开启时下载总开关也必须为真 ——
// 否则会出现"引擎被自动装好了, 但页面上一键安装按钮全是灰的"这种自相矛盾状态。
//
// 注意直接测纯函数下载开关判定, 不碰 engDlOnce 单例: sync.Once 一旦执行过就无法
// "重置", 强行顶掉它会污染同包其它用例(它们依赖单例已初始化的状态)。这里把判定
// 规则抽成 downloadsAllowed(cfg) 正是为了可测。
func TestDownloadsEnabledImpliesAutoInstall(t *testing.T) {
	if !downloadsAllowed(engineDownloadConfig{AutoInstall: true}) {
		t.Fatal("autoInstall=true 时下载总开关应为真(自动补装蕴含允许下载)")
	}
	if !downloadsAllowed(engineDownloadConfig{AllowDownload: true}) {
		t.Fatal("allowDownload=true 时应允许下载")
	}
	if downloadsAllowed(engineDownloadConfig{}) {
		t.Fatal("两个开关都关时不应允许下载")
	}
}

// TestHumanMB 体积格式化边界。
//
// 这个函数只服务于日志可读性, 但**写错会让用户误判进度**: 若把 1.5MB 显示成 "2MB"
// 或把未知长度(-1)显示成 "0B", 用户看到"下完了却停在 0"会以为卡死而关掉窗口(这正是
// 自动补装第一版的真实故障)。所以 0 / 负数 / 各量级边界都要钉住。
func TestHumanMB(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{-1, "?"},        // 未知长度必须有别于 0, 否则用户以为下完了
		{0, "0B"},        // 真·零字节
		{999, "999B"},    // 小于 1KB 不进位
		{1000, "1KB"},    // 1000 进制(与浏览器下载显示口径一致)
		{1500, "2KB"},    // 四舍五入到整数 KB
		{1_000_000, "1.0MB"},
		{1_500_000, "1.5MB"},
		{1_000_000_000, "1.00GB"},
	}
	for _, c := range cases {
		if got := humanMB(c.in); got != c.want {
			t.Errorf("humanMB(%d) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// TestAutoInstallProgressThrottling 进度回调必须"能看到推进 + 不刷爆日志"。
//
// 直接测回调的节流行为, 不跑真下载: 回调是纯函数(闭包持有 lastPct/lastStage),
// 喂一串人造 Progress 就能验证。用户在下载的几分钟里**必须**看到百分比变化
// (否则以为卡死 -> 关窗口 -> 下载中断, 实测踩过); 同时 200 次同百分比回调
// 只能产生极少量日志(否则 yugsight.log 几秒内涨到几十 MB)。
func TestAutoInstallProgressThrottling(t *testing.T) {
	var lines []string
	prevLog := engDlLog
	engDlLog = func(s string) { lines = append(lines, s) }
	t.Cleanup(func() { engDlLog = prevLog })

	pf := autoInstallProgress()
	// 模拟一次 50MB 下载: 每 1% 回调一次 = 100 次下载回调
	const each = int64(500_000)
	for pct := 0; pct <= 100; pct++ {
		pf(engmgr.Progress{
			Engine:  "trivy",
			Status:  engmgr.StDownloading,
			Percent: pct,
			Bytes:   int64(pct) * each,
			TotalB:  100 * each,
			Speed:   2_000_000,
		})
	}
	// 100 次回调里应只在跨 10 的倍数时产出(0,10,...,100 = 11 条)
	if len(lines) > 15 {
		t.Fatalf("节流失效: 100 次下载回调产生了 %d 条日志, 应 <=15 条", len(lines))
	}
	if len(lines) < 5 {
		t.Fatalf("进度过于稀疏, 用户看不到推进: 仅 %d 条日志", len(lines))
	}
	// 必须出现真实的百分比数字, 而不是只在开头结尾各一条
	hasPct := false
	for _, l := range lines {
		if strings.Contains(l, "%") {
			hasPct = true
		}
	}
	if !hasPct {
		t.Fatalf("日志里没有百分比推进信息: %v", lines)
	}
}

// TestAutoInstallProgressStageSwitch 阶段切换必须上报, 且切换后百分比记忆要重置。
//
// 重置是关键: 下载阶段走到 50% 后切到解包阶段(Percent 从头计数), 若不清 lastPct,
// "50% -> 5%" 这种回退会被节流逻辑当成"没跨过 10 的倍数"而沉默, 用户看到进度倒退后
// 突然没有下文。
func TestAutoInstallProgressStageSwitch(t *testing.T) {
	var lines []string
	prevLog := engDlLog
	engDlLog = func(s string) { lines = append(lines, s) }
	t.Cleanup(func() { engDlLog = prevLog })

	pf := autoInstallProgress()
	pf(engmgr.Progress{Engine: "trivy", Status: engmgr.StDownloading, Percent: 50, TotalB: 1000, Bytes: 500})
	// 切到解包: 新阶段从低百分比开始, 必须仍然打出来
	pf(engmgr.Progress{Engine: "trivy", Status: engmgr.StExtracting, Phase: "正在解包"})

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, engmgr.StExtracting) {
		t.Fatalf("阶段切换未上报: %v", lines)
	}
	if !strings.Contains(joined, "正在解包") {
		t.Fatalf("阶段说明未输出(Phase 字段被丢弃): %v", lines)
	}
}
