// logrotate_test.go 探针端日志轮转的用例。
//
// 【为什么必须单独测一份】cmd/agent/logrotate.go 是根包 logrotate.go 的实现副本
// (理由见该文件头: agent 不能 import main 包)。副本意味着"改一份忘另一份"的漂移
// 风险 —— 项目历史上已出现过同名函数冲突、行为不一致导致的问题。本文件把副本的
// **关键语义**也钉住, 使漂移在测试阶段就暴露, 而不是等用户看到"中心端归档正常、
// 探针端归档乱"。
//
// 用例口径与根包 logrotate_test.go 对齐(序号续编、不回填空洞、数字排序清理、
// 首行时间注释、只清自己的前缀), 额外覆盖探针端特有的 keepAtRoot 配置解析。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// writeAgent 写 n 字节日志(单条)。
func writeAgent(t *testing.T, w *agentLogWriter, n int) {
	t.Helper()
	if _, err := w.Write([]byte(strings.Repeat("x", n) + "\n")); err != nil {
		t.Fatalf("写入日志失败: %v", err)
	}
}

// agentArchiveSeqs 列出归档序号(升序), 与实现同一套正则口径。
func agentArchiveSeqs(t *testing.T, dir, base string) []int {
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

// newAgentTestWriter 构造"当前日志在 logs/ 下"的探针写入器(与生产默认口径一致)。
func newAgentTestWriter(t *testing.T, dir, base string, maxBytes int64, maxFiles int) (*agentLogWriter, string) {
	t.Helper()
	logDir := filepath.Join(dir, "logs")
	cur := filepath.Join(logDir, base+".log")
	w := newAgentLogWriterAt(cur, logDir, maxBytes, maxFiles)
	t.Cleanup(func() { w.Close() })
	return w, cur
}

// TestAgentLogWriterCurrentLogInLogsDir 当前日志与归档都必须落在 logs/ 下。
func TestAgentLogWriterCurrentLogInLogsDir(t *testing.T) {
	dir := t.TempDir()
	w, cur := newAgentTestWriter(t, dir, "yugsight-agent", 100, 20)

	writeAgent(t, w, 60)
	writeAgent(t, w, 60) // 越过 100 -> 轮转

	if _, err := os.Stat(cur); err != nil {
		t.Fatalf("轮转后当前日志必须存在: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "yugsight-agent.log")); !os.IsNotExist(err) {
		t.Error("当前日志不应残留在 exe 根目录")
	}
	if got := agentArchiveSeqs(t, filepath.Join(dir, "logs"), "yugsight-agent"); len(got) != 1 || got[0] != 1 {
		t.Fatalf("首卷应为 yugsight-agent-1.log, 实际 %v", got)
	}
}

// TestAgentLogWriterSeqContinuesAfterRestart 重启后序号接着最大值 +1, 不覆盖旧卷。
func TestAgentLogWriterSeqContinuesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	cur := filepath.Join(logDir, "yugsight-agent.log")

	w1 := newAgentLogWriterAt(cur, logDir, 50, 20)
	for i := 0; i < 4; i++ {
		writeAgent(t, w1, 30)
	}
	w1.Close()
	first := agentArchiveSeqs(t, logDir, "yugsight-agent")
	if len(first) == 0 {
		t.Fatal("第一次进程未产生归档")
	}
	firstMax := first[len(first)-1]

	w2 := newAgentLogWriterAt(cur, logDir, 50, 20)
	for i := 0; i < 4; i++ {
		writeAgent(t, w2, 30)
	}
	w2.Close()
	got := agentArchiveSeqs(t, logDir, "yugsight-agent")
	if newMax := got[len(got)-1]; newMax <= firstMax {
		t.Errorf("重启后新卷序号应大于 %d, 实际 %v", firstMax, got)
	}
	for i := 0; i < len(first); i++ {
		if got[i] != first[i] {
			t.Errorf("重启覆盖了旧卷: 重启前 %v, 重启后 %v", first, got)
			break
		}
	}
}

// TestAgentLogWriterPruneByNumericOrder 跨两位数后必须按数字排序删最旧(不能按字符串)。
func TestAgentLogWriterPruneByNumericOrder(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 12; i++ {
		name := filepath.Join(logDir, fmt.Sprintf("yugsight-agent-%d.log", i))
		if err := os.WriteFile(name, []byte("old\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w := newAgentLogWriterAt(filepath.Join(logDir, "yugsight-agent.log"), logDir, 50, 3)
	defer w.Close()
	writeAgent(t, w, 30)
	writeAgent(t, w, 30) // 轮转 -> 第 13 卷 -> 裁到 3 卷

	got := agentArchiveSeqs(t, logDir, "yugsight-agent")
	if len(got) != 3 {
		t.Fatalf("应只保留 3 卷, 实际 %v", got)
	}
	for i, want := range []int{11, 12, 13} {
		if got[i] != want {
			t.Errorf("应保留最大的 3 卷 [11 12 13], 实际 %v(按字符串排序会删掉最新几卷)", got)
			break
		}
	}
}

// TestAgentLogWriterArchiveStampFirstLine 归档首行必须是归档时间注释。
func TestAgentLogWriterArchiveStampFirstLine(t *testing.T) {
	dir := t.TempDir()
	w, _ := newAgentTestWriter(t, dir, "yugsight-agent", 100, 20)

	writeAgent(t, w, 60)
	writeAgent(t, w, 60)

	path := filepath.Join(dir, "logs", "yugsight-agent-1.log")
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
}

// TestAgentLogWriterOnlyPrunesOwnPrefix logs/ 里中心端的日志不能被探针端清掉。
//
// 这是最容易出事的一组: 中心端归档名 yugsight-N.log 与探针端 yugsight-agent-N.log
// 中, 后者以前者为前缀。任何用 HasPrefix 的实现都会把中心端日志一起删掉。
func TestAgentLogWriterOnlyPrunesOwnPrefix(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		name := filepath.Join(logDir, fmt.Sprintf("yugsight-%d.log", i))
		if err := os.WriteFile(name, []byte("center log\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w := newAgentLogWriterAt(filepath.Join(logDir, "yugsight-agent.log"), logDir, 50, 1)
	defer w.Close()
	for i := 0; i < 4; i++ {
		writeAgent(t, w, 30)
		writeAgent(t, w, 30)
	}

	// 统计口径必须用归档正则而不是 HasPrefix: 探针端的**当前日志**叫
	// yugsight-agent.log(不带序号), 它不匹配任何归档正则, 但 HasPrefix("yugsight-")
	// 会把它误算成中心端的卷 —— 用例自身就会因此给出错误结论。
	entries, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatal(err)
	}
	centerRe := archiveSeqRe("yugsight")
	agentRe := archiveSeqRe("yugsight-agent")
	center, agent := 0, 0
	for _, e := range entries {
		switch {
		case agentRe.MatchString(e.Name()):
			agent++
		case centerRe.MatchString(e.Name()):
			center++
		}
	}
	if center != 5 {
		t.Errorf("中心端日志被误删: 期望 5 卷, 实际 %d", center)
	}
	if agent != 1 {
		t.Errorf("探针端归档应只留 1 卷, 实际 %d", agent)
	}
}

// TestAgentLogWriterKeepAtRootConfig probe.json 的 keepAtRoot 解析必须生效。
//
// 三种写法都要覆盖: 没写(false, 当前日志进 logs/) / 显式 false / 显式 true
// (当前日志留 exe 根目录)。用 *bool 的理由就是必须能区分"没写"与"写了 false"。
func TestAgentLogWriterKeepAtRootConfig(t *testing.T) {
	cases := []struct {
		name     string
		json     string
		wantRoot bool
	}{
		{"未写 keepAtRoot", `{"log":{"maxMB":1}}`, false},
		{"显式 false", `{"log":{"keepAtRoot":false}}`, false},
		{"显式 true", `{"log":{"keepAtRoot":true}}`, true},
		{"client 段内", `{"client":{"log":{"keepAtRoot":true}}}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "probe.json"), []byte(c.json), 0o644); err != nil {
				t.Fatal(err)
			}
			w := newAgentLogWriter(dir, "yugsight-agent.log")
			defer w.Close()
			gotRoot := filepath.Dir(w.path) == dir
			if gotRoot != c.wantRoot {
				t.Errorf("keepAtRoot=%v 时当前日志应在根目录=%v, 实际路径 %s",
					c.wantRoot, c.wantRoot, w.path)
			}
		})
	}
}

// TestAgentLogWriterBOMConfig 带 UTF-8 BOM 的 probe.json 必须能解析。
//
// Windows 记事本/PowerShell Set-Content -Encoding UTF8 都会写 BOM, 不剥会让
// json.Unmarshal 失败并静默回退默认配置 —— 用户现象是"改了配置没生效"。
func TestAgentLogWriterBOMConfig(t *testing.T) {
	dir := t.TempDir()
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"log":{"keepAtRoot":true}}`)...)
	if err := os.WriteFile(filepath.Join(dir, "probe.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	w := newAgentLogWriter(dir, "yugsight-agent.log")
	defer w.Close()
	if filepath.Dir(w.path) != dir {
		t.Errorf("BOM 配置应被正确解析(keepAtRoot=true), 当前日志路径 %s", w.path)
	}
}

// TestAgentLogWriterConcurrent 并发写不得丢日志(并发安全, 配合 -race)。
func TestAgentLogWriterConcurrent(t *testing.T) {
	dir := t.TempDir()
	w, cur := newAgentTestWriter(t, dir, "yugsight-agent", 4096, 50)

	const goroutines, perG = 8, 200
	done := make(chan struct{}, goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < perG; i++ {
				writeAgent(t, w, 40)
			}
		}()
	}
	for g := 0; g < goroutines; g++ {
		<-done
	}
	w.Close()

	logDir := filepath.Join(dir, "logs")
	total := 0
	count := func(p string) {
		b, err := os.ReadFile(p)
		if err != nil {
			return
		}
		for _, ln := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if ln != "" && !strings.HasPrefix(ln, "# archived at ") {
				total++
			}
		}
	}
	count(cur)
	for _, s := range agentArchiveSeqs(t, logDir, "yugsight-agent") {
		count(filepath.Join(logDir, fmt.Sprintf("yugsight-agent-%d.log", s)))
	}
	if want := goroutines * perG; total != want {
		t.Errorf("并发写入共 %d 条, 实际落盘 %d 条(有丢失)", want, total)
	}
}
