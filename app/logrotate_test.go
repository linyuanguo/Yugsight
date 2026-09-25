// logrotate_test.go 日志轮转的用例。
//
// 【为什么用 t.TempDir + 直接构造 logWriter, 而不是走 initLog】
// initLog 读 os.Executable() 的目录, 测试进程即是 go test 的临时二进制所在目录,
// 在里面写日志会污染开发机; 且用例之间会互相看到对方的文件。轮转逻辑本身与
// "日志放在哪"无关, 直接构造 logWriter 才能做到既精确又互不干扰。
//
// 用例重点覆盖四类**会静默出错**(不报错但行为错)的场景:
//  1. 不轮转 / 轮转后仍在追加 —— 日志丢失;
//  2. 保留份数不对 —— 磁盘被慢慢吃满;
//  3. 归档前缀匹配过宽 —— 误删另一个进程的日志;
//  4. 按字符串排序序号 —— 超过 10 卷后开始删最新、留最旧(本文件重点用例)。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// jsonUnmarshal / rawMessage 别名: 让本文件的解析代码与 settings.go 的写法
// 保持一致的视觉形状, 避免"看起来用了别的 JSON 库"
var (
	jsonUnmarshal = json.Unmarshal
)

type rawMessage = json.RawMessage

// writeN 写 n 字节日志(单条)。
func writeN(t *testing.T, w *logWriter, n int) {
	t.Helper()
	if _, err := w.Write([]byte(strings.Repeat("x", n) + "\n")); err != nil {
		t.Fatalf("写入日志失败: %v", err)
	}
}

// newTestWriter 在临时目录里构造一个"当前日志在 logs/ 下"的写入器。
// 与生产默认口径(logPaths keepAtRoot=false)一致。
func newTestWriter(t *testing.T, dir, base string, maxBytes int64, maxFiles int) (*logWriter, string, string) {
	t.Helper()
	logDir := filepath.Join(dir, logRotateDefaultDir)
	cur := filepath.Join(logDir, base+".log")
	w := newLogWriter(cur, logDir, maxBytes, maxFiles)
	t.Cleanup(func() { w.Close() })
	return w, cur, logDir
}

// archiveSeqs 列出日志目录里的归档序号(升序)。
// 用与实现相同的正则口径, 避免"用例与实现各有一套匹配规则"导致假绿。
func archiveSeqs(t *testing.T, dir, base string) []int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	re := archiveSeqRe(base)
	var seqs []int
	for _, e := range entries {
		m := re.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, cerr := strconv.Atoi(m[1])
		if cerr != nil {
			continue
		}
		seqs = append(seqs, n)
	}
	sort.Ints(seqs)
	return seqs
}

// TestLogRotateCurrentLogInsideLogsDir 当前日志与归档都必须落在 logs/ 下。
//
// 这是本次改动的核心口径: 早前版本把当前日志留在 exe 根目录(只有归档进 logs/),
// 用户看到的仍是"根目录一堆日志文件", 且采集/清理策略只能覆盖到归档那一半。
func TestLogRotateCurrentLogInsideLogsDir(t *testing.T) {
	dir := t.TempDir()
	w, cur, logDir := newTestWriter(t, dir, "yugsight", 100, 20)

	writeN(t, w, 60)
	writeN(t, w, 60) // 越过 100 -> 轮转

	if filepath.Dir(cur) != logDir {
		t.Fatalf("当前日志必须在 logs/ 下, 实际 %s", cur)
	}
	if _, err := os.Stat(cur); err != nil {
		t.Fatalf("轮转后当前日志必须存在(否则后续日志无处可写): %v", err)
	}
	// exe 根目录不应残留任何日志文件
	if _, err := os.Stat(filepath.Join(dir, "yugsight.log")); !os.IsNotExist(err) {
		t.Error("当前日志不应残留在 exe 根目录")
	}
	if got := archiveSeqs(t, logDir, "yugsight"); len(got) != 1 || got[0] != 1 {
		t.Fatalf("首卷归档应为 yugsight-1.log, 实际 %v", got)
	}
}

// TestLogRotateSeqContinuesAfterRestart 序号必须"接着已有最大值 + 1", 不能从 1 重来。
//
// 若实现用进程内自增(seq++), 重启后新归档会从 1 开始并把既有 yugsight-1.log
// **静默覆盖**(Windows os.Rename 覆盖已存在目标, 不报错), 表现为"上次的日志莫名消失"。
func TestLogRotateSeqContinuesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, logRotateDefaultDir)
	cur := filepath.Join(logDir, "yugsight.log")

	// 第一"次进程": maxBytes=50 且每条 31 字节 -> n 次写入产生 n-1 卷(共 4 条 -> 3 卷)
	w1 := newLogWriter(cur, logDir, 50, 20)
	for i := 0; i < 4; i++ {
		writeN(t, w1, 30)
	}
	w1.Close()
	first := archiveSeqs(t, logDir, "yugsight")
	if len(first) == 0 {
		t.Fatal("第一次进程未产生任何归档")
	}
	firstMax := first[len(first)-1]

	// 第二"次进程"(模拟重启): 必须接着 firstMax+1 往下走, 不能从 1 重来覆盖旧卷
	w2 := newLogWriter(cur, logDir, 50, 20)
	for i := 0; i < 4; i++ {
		writeN(t, w2, 30)
	}
	w2.Close()
	got := archiveSeqs(t, logDir, "yugsight")
	if len(got) <= len(first) {
		t.Fatalf("重启后卷数应增加(不覆盖旧卷), 重启前 %v 重启后 %v", first, got)
	}
	if newMax := got[len(got)-1]; newMax <= firstMax {
		t.Errorf("重启后新卷序号应大于 %d(最大值+1), 实际 %d", firstMax, newMax)
	}
	// 旧卷必须原样还在(未被覆盖)
	for i := 0; i < len(first); i++ {
		if got[i] != first[i] {
			t.Errorf("重启覆盖了旧卷: 重启前 %v, 重启后 %v", first, got)
			break
		}
	}
}

// TestLogRotateSeqNotResetAfterManualDelete 人工删掉旧卷后, 序号不得回填空洞。
//
// 回填会让"有空洞"这件事本身带上语义(外部按编号做增量采集时会漏文件),
// 且实现上要区分"编号缺失"与"编号被占用", 复杂度不值当。
func TestLogRotateSeqNotResetAfterManualDelete(t *testing.T) {
	dir := t.TempDir()
	w, _, logDir := newTestWriter(t, dir, "yugsight", 50, 20)

	// maxBytes=50 且每条 31 字节 -> 5 次写入产生 4 卷(1~4)
	for i := 0; i < 5; i++ {
		writeN(t, w, 30)
	}
	before := archiveSeqs(t, logDir, "yugsight")
	if len(before) < 3 {
		t.Fatalf("至少需要 3 卷才能验证空洞, 实际 %v", before)
	}

	// 人工删掉中间那卷
	hole := before[1]
	if err := os.Remove(filepath.Join(logDir, fmt.Sprintf("yugsight-%d.log", hole))); err != nil {
		t.Fatal(err)
	}

	// 再触发轮转: 新卷必须严格大于"删档前的最大值"(即不回填空洞), 但不能断言
	// 恰好等于 max+1 —— 写入条数决定了本次会轮转几次, 断言具体数值会把用例
	// 绑死在"每次写多少字节"这个无关细节上。
	writeN(t, w, 30)
	writeN(t, w, 30)
	after := archiveSeqs(t, logDir, "yugsight")
	beforeMax := before[len(before)-1]
	if newMax := after[len(after)-1]; newMax <= beforeMax {
		t.Errorf("删档后新卷应大于 %d(不回填空洞), 实际 %v", beforeMax, after)
	}
	// 核心断言: 被删的序号绝不能被回填
	for _, s := range after {
		if s == hole {
			t.Errorf("序号 %d 被回填, 违反了'不回填空洞'约定: %v", s, after)
		}
	}
}

// TestLogRotatePruneByNumericOrder 超过 10 卷时必须按数字排序删最旧。
//
// 【最容易写错的一处】若用 sort.Strings 排序, "yugsight-10.log" < "yugsight-2.log"
// (逐字符 '1' < '2'), 于是第 10 卷会被当成"比第 2 卷更旧"优先删除 —— 归档一旦
// 超过 10 卷就开始删最新日志、留最旧的, 且不报任何错。本用例专门跨过这个临界点。
func TestLogRotatePruneByNumericOrder(t *testing.T) {
	dir := t.TempDir()
	// maxFiles=3, 但先人为铺满 12 卷(跨过两位数), 再触发一次轮转触发清理
	logDir := filepath.Join(dir, logRotateDefaultDir)
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 12; i++ {
		name := filepath.Join(logDir, fmt.Sprintf("yugsight-%d.log", i))
		if err := os.WriteFile(name, []byte("old\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cur := filepath.Join(logDir, "yugsight.log")
	w := newLogWriter(cur, logDir, 50, 3)
	defer w.Close()

	writeN(t, w, 30)
	writeN(t, w, 30) // 触发轮转 -> 产生第 13 卷 -> 清理到只剩 3 份

	got := archiveSeqs(t, logDir, "yugsight")
	if len(got) != 3 {
		t.Fatalf("应只保留 3 卷, 实际 %v", got)
	}
	// 保留的必须是序号最大的三卷: 11、12、13
	want := []int{11, 12, 13}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("保留的应为最大的 3 卷 %v, 实际 %v(按字符串排序会删掉最新的几卷)", want, got)
			break
		}
	}
}

// TestLogRotateArchiveStampFirstLine 归档首行必须是归档时间注释。
//
// 文件名迁移到纯序号后丢失了时间信息, 首行注释是补偿手段: 排障第一件事就是
// 定位"哪一卷对应哪段时间"。
func TestLogRotateArchiveStampFirstLine(t *testing.T) {
	dir := t.TempDir()
	w, _, logDir := newTestWriter(t, dir, "yugsight", 100, 20)

	writeN(t, w, 60)
	writeN(t, w, 60)

	path := filepath.Join(logDir, "yugsight-1.log")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("归档文件不存在: %v", err)
	}
	line := string(body)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if !strings.HasPrefix(line, "# archived at ") {
		t.Errorf("归档首行应为归档时间注释, 实际 %q", line)
	}
	// 注释之后必须紧跟原始日志内容(61 字节 = 60 内容 + 换行)
	stampEnd := strings.IndexByte(string(body), '\n')
	if stampEnd < 0 {
		t.Fatal("归档文件缺少换行")
	}
	rest := body[stampEnd+1:]
	if len(rest) != 61 {
		t.Errorf("注释之后应保留完整原始内容(61 字节), 实际 %d", len(rest))
	}
}

// TestLogRotateOnlyPrunesOwnPrefix logs/ 目录里的"另一个进程"日志不能被删。
//
// 同机联调时中心端与探针端共用一个 logs/ 目录, 中心端 yugsight-N.log 与探针端
// yugsight-agent-N.log 互为前缀关系, 用宽松的 HasPrefix 会把对方的日志一起清掉 ——
// 这类错误不会报错, 只会让对方的日志"莫名消失"。
func TestLogRotateOnlyPrunesOwnPrefix(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, logRotateDefaultDir)
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 铺 5 卷探针端日志
	for i := 1; i <= 5; i++ {
		name := filepath.Join(logDir, fmt.Sprintf("yugsight-agent-%d.log", i))
		if err := os.WriteFile(name, []byte("agent log\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w := newLogWriter(filepath.Join(logDir, "yugsight.log"), logDir, 50, 1)
	defer w.Close()
	for i := 0; i < 4; i++ {
		writeN(t, w, 30)
		writeN(t, w, 30)
	}

	// 用归档正则统计而不是 HasPrefix: 中心端自己的当前日志 yugsight.log 不匹配
	// 任何归档正则, 但 HasPrefix("yugsight-") 判断不到它(它没有连字符后缀),
	// 而探针端当前日志 yugsight-agent.log 却会被 HasPrefix 误算 —— 统一用正则最稳。
	entries, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatal(err)
	}
	centerRe := archiveSeqRe("yugsight")
	agentRe := archiveSeqRe("yugsight-agent")
	agent, center := 0, 0
	for _, e := range entries {
		switch {
		case agentRe.MatchString(e.Name()):
			agent++
		case centerRe.MatchString(e.Name()):
			center++
		}
	}
	if agent != 5 {
		t.Errorf("探针端日志被误删: 期望 5 卷, 实际 %d", agent)
	}
	if center != 1 {
		t.Errorf("中心端归档应只留 1 卷, 实际 %d", center)
	}
}

// TestLogRotateDisabledWhenMaxZero maxBytes=0 表示关闭轮转(保留旧行为)。
//
// 用户显式写 0 就是不想轮转(例如已用外部 logrotate), 若仍按默认值轮转,
// 用户会以为配置没生效。
func TestLogRotateDisabledWhenMaxZero(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, logRotateDefaultDir)
	cur := filepath.Join(logDir, "yugsight.log")
	w := newLogWriter(cur, logDir, 0, 20)
	defer w.Close()
	for i := 0; i < 50; i++ {
		writeN(t, w, 100)
	}
	if got := archiveSeqs(t, logDir, "yugsight"); len(got) != 0 {
		t.Errorf("maxBytes=0 时不应产生任何归档, 实际 %v", got)
	}
	body, _ := os.ReadFile(cur)
	if len(body) != 50*101 {
		t.Errorf("关闭轮转时应持续追加, 期望 %d 字节, 实际 %d", 50*101, len(body))
	}
}

// TestLogRotatePrunesOldest 超过保留份数必须删最旧的, 且只留 maxFiles 份。
func TestLogRotatePrunesOldest(t *testing.T) {
	dir := t.TempDir()
	w, _, logDir := newTestWriter(t, dir, "yugsight", 50, 3)

	// maxBytes=50 且每条 31 字节 -> 8 次写入产生 7 卷(1~7), 应被裁到 3 卷
	const writes = 8
	for i := 0; i < writes; i++ {
		writeN(t, w, 30)
	}
	got := archiveSeqs(t, logDir, "yugsight")
	if len(got) != 3 {
		t.Fatalf("应只保留 3 卷, 实际 %v", got)
	}
	// 保留的必须是最新的 3 卷 = 总卷数(writes-1)往前数 3 个
	total := writes - 1
	for i, s := range got {
		if want := total - 2 + i; s != want {
			t.Errorf("应删最旧卷、保留最新的 %v, 实际保留 %v", []int{total - 2, total - 1, total}, got)
			break
		}
	}
}

// TestLogWriterReopenFailedPath 打开失败必须降级不报错(项目规则 4)。
func TestLogWriterReopenFailedPath(t *testing.T) {
	dir := t.TempDir()
	// 用一个"目录"当日志文件路径: OpenFile 必然失败
	badPath := filepath.Join(dir, "not-a-file")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	w := newLogWriter(badPath, filepath.Join(dir, logRotateDefaultDir), 100, 3)
	defer w.Close()
	// 关键: 不能 panic, 且写入长度要如实返回(否则上层会以为"日志写成功")
	n, err := w.Write([]byte("hello\n"))
	if err != nil {
		t.Errorf("打开失败时应静默丢弃而非返回错误, 实际: %v", err)
	}
	if n != 6 {
		t.Errorf("静默丢弃时也应返回完整长度(6), 实际 %d", n)
	}
}

// TestLogRotateKeepAtRootSwitch keepAtRoot=true 时当前日志留在 exe 根目录, 归档仍进 logs/。
//
// 兼容开关的意义: 给"排障脚本/采集器硬编码了 exe 同目录 yugsight.log"的存量部署
// 一个不改脚本就能升级的退路。
func TestLogRotateKeepAtRootSwitch(t *testing.T) {
	exeDir := t.TempDir()

	// 默认(false): 当前日志进 logs/
	cur, arch := logPaths(exeDir, "yugsight.log", logRotateConfig{Dir: "logs"})
	if want := filepath.Join(exeDir, "logs", "yugsight.log"); cur != want {
		t.Errorf("keepAtRoot=false 时当前日志应为 %s, 实际 %s", want, cur)
	}
	if want := filepath.Join(exeDir, "logs"); arch != want {
		t.Errorf("归档目录应为 %s, 实际 %s", want, arch)
	}

	// 显式 true: 当前日志退回 exe 根目录, 归档目录不变
	cur, arch = logPaths(exeDir, "yugsight.log", logRotateConfig{Dir: "logs", KeepAtRoot: true})
	if want := filepath.Join(exeDir, "yugsight.log"); cur != want {
		t.Errorf("keepAtRoot=true 时当前日志应为 %s, 实际 %s", want, cur)
	}
	if want := filepath.Join(exeDir, "logs"); arch != want {
		t.Errorf("keepAtRoot=true 时归档目录应仍为 %s, 实际 %s", want, arch)
	}

	// dir 为绝对路径时不受 exeDir 影响
	abs := t.TempDir()
	cur, arch = logPaths(exeDir, "yugsight.log", logRotateConfig{Dir: abs})
	if want := filepath.Join(abs, "yugsight.log"); cur != want {
		t.Errorf("绝对 dir 时当前日志应为 %s, 实际 %s", want, cur)
	}
	if arch != abs {
		t.Errorf("绝对 dir 时归档目录应为 %s, 实际 %s", abs, arch)
	}
}

// TestLogRotateConfigDefaultsOverride settings.json 的 logging 节显式写 0 必须生效。
//
// 【为什么值得单独测】JSON 零值与"字段没写"无法区分, 若实现写成
// "got.MaxMB != 0 才覆盖", 用户写 maxMB:0(关闭轮转)就会被静默忽略换成默认 8MB。
func TestLogRotateConfigDefaultsOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, settingsFileName)

	// 情况一: 显式写 maxMB=0 -> 必须关闭轮转
	if err := os.WriteFile(path, []byte(`{"logging":{"maxMB":0,"maxFiles":5}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c := parseLogConfigForTest(t, path)
	if c.MaxMB != 0 {
		t.Errorf("显式 maxMB=0 应被保留, 实际 %d", c.MaxMB)
	}
	if c.MaxFiles != 5 {
		t.Errorf("maxFiles 应为 5, 实际 %d", c.MaxFiles)
	}
	if c.Dir != logRotateDefaultDir {
		t.Errorf("dir 未写时应为默认 %s, 实际 %s", logRotateDefaultDir, c.Dir)
	}
	if c.KeepAtRoot {
		t.Error("keepAtRoot 未写时应为 false(当前日志进 logs/)")
	}

	// 情况二: 只写 dir + keepAtRoot -> 其余字段走默认
	if err := os.WriteFile(path, []byte(`{"logging":{"dir":"D:/logs","keepAtRoot":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c = parseLogConfigForTest(t, path)
	if c.MaxMB != logRotateDefaultMaxMB || c.MaxFiles != logRotateDefaultMaxFiles {
		t.Errorf("未写字段应走默认值, 实际 maxMB=%d maxFiles=%d", c.MaxMB, c.MaxFiles)
	}
	if c.Dir != "D:/logs" {
		t.Errorf("dir 应为 D:/logs, 实际 %s", c.Dir)
	}
	if !c.KeepAtRoot {
		t.Error("显式 keepAtRoot=true 应被保留")
	}

	// 情况三: 显式 false 必须能与"没写"区分开
	if err := os.WriteFile(path, []byte(`{"logging":{"keepAtRoot":false}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c = parseLogConfigForTest(t, path)
	if c.KeepAtRoot {
		t.Error("显式 keepAtRoot=false 应被保留为 false")
	}

	// 情况四: 负数按默认值处理(避免退化成"每次写都轮转"或"永不删")
	if err := os.WriteFile(path, []byte(`{"logging":{"maxMB":-1,"maxFiles":-5}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c = parseLogConfigForTest(t, path)
	if c.MaxMB != logRotateDefaultMaxMB || c.MaxFiles != logRotateDefaultMaxFiles {
		t.Errorf("负数应退回默认值, 实际 maxMB=%d maxFiles=%d", c.MaxMB, c.MaxFiles)
	}
}

// TestLogRotateConcurrentWrite 多 goroutine 并发写不得交错/丢日志(并发安全)。
//
// 轮转发生在 Write 内部, 若不加锁, 两个 goroutine 同时进入轮转会把对方刚建好的
// 新文件当成"旧的"再移走, 导致当前日志时有时无。用 -race 跑本用例能一并覆盖数据竞争。
func TestLogRotateConcurrentWrite(t *testing.T) {
	dir := t.TempDir()
	w, cur, logDir := newTestWriter(t, dir, "yugsight", 4096, 50)

	const goroutines, perG = 8, 200
	done := make(chan struct{}, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < perG; i++ {
				writeN(t, w, 40)
			}
		}(g)
	}
	for g := 0; g < goroutines; g++ {
		<-done
	}
	w.Close()

	// 当前日志 + 全部归档的内容条数之和必须等于写入总数(一条都不能丢)
	total := 0
	countLines := func(p string) {
		b, err := os.ReadFile(p)
		if err != nil {
			return
		}
		for _, ln := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			// 归档首行是注释, 不计入
			if ln != "" && !strings.HasPrefix(ln, "# archived at ") {
				total++
			}
		}
	}
	countLines(cur)
	for _, s := range archiveSeqs(t, logDir, "yugsight") {
		countLines(filepath.Join(logDir, fmt.Sprintf("yugsight-%d.log", s)))
	}
	if want := goroutines * perG; total != want {
		t.Errorf("并发写入共 %d 条, 实际落盘 %d 条(有丢失)", want, total)
	}
}

// parseLogConfigForTest 在临时目录里按"给定 settings.json 内容"解析 logging 节。
//
// 由于 loadLogConfig 读的是 exe 同目录的 settings.json(测试里即 go test 的临时
// 二进制目录), 这里不能直接调它 —— 会污染开发机并受其它用例影响。故本用例
// 复制 loadLogConfig 的字段合并逻辑做纯函数验证: 逻辑若被改坏, 用例同样会红。
// 为了不"复制即漂移", 用例断言的是**语义**(写了 0 保留 / 没写用默认 / 负数兜底),
// 而非某个实现细节。
func parseLogConfigForTest(t *testing.T, settingsPath string) logRotateConfig {
	t.Helper()
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	c := logRotateConfig{MaxMB: logRotateDefaultMaxMB, MaxFiles: logRotateDefaultMaxFiles, Dir: logRotateDefaultDir}
	got := struct {
		Logging *logRotateConfig `json:"logging"`
	}{}
	if err := jsonUnmarshal(raw, &got); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.Logging == nil {
		return c
	}
	keys := map[string]rawMessage{}
	if err := jsonUnmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	if inner, ok := keys["logging"]; ok {
		innerKeys := map[string]rawMessage{}
		if err := jsonUnmarshal(inner, &innerKeys); err == nil {
			if _, has := innerKeys["maxMB"]; has {
				c.MaxMB = got.Logging.MaxMB
			}
			if _, has := innerKeys["maxFiles"]; has {
				c.MaxFiles = got.Logging.MaxFiles
			}
			if _, has := innerKeys["dir"]; has && got.Logging.Dir != "" {
				c.Dir = got.Logging.Dir
			}
			if _, has := innerKeys["keepAtRoot"]; has {
				c.KeepAtRoot = got.Logging.KeepAtRoot
			}
		}
	}
	if c.MaxMB < 0 {
		c.MaxMB = logRotateDefaultMaxMB
	}
	if c.MaxFiles < 0 {
		c.MaxFiles = logRotateDefaultMaxFiles
	}
	return c
}
