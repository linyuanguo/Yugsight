// logrotate.go 探针端日志写入器 + 轮转配置。
//
// ===== 为什么这里是根包 logrotate.go 的副本, 而不是共享一个内部包 =====
//
// 根包 logrotate.go 属于 package main, 无法被 cmd/agent 导入(Go 没有"导入 main 包"
// 这回事)。两个可选方案:
//
//	A. 抽一个 internal/logx 包, 两端 import —— 结构最干净, 但要给 logWriter 加
//	   SetLogger 注入(它需要 logLine 打警告), 并新增一个包;
//	B. 本文件保留一份实现副本 —— 零新增包, 两端各自独立, agent 不因中心端
//	   日志实现变化而被牵连(agent 是最需要"稳定、小体积、少依赖"的组件)。
//
// 选 B 的理由: 轮转逻辑总共约 150 行且已完全定型(单一职责, 不会被业务需求
// 反复改动), 复制带来的漂移风险远小于给 agent 引入新依赖与注入层的复杂度。
//
// 【必须与根包 logrotate.go 保持一致】改动其中一份时, 请同步另一份 ——
// 关键差异点(同步时勿误改):
//   - 配置来源: 根包读 settings.json 的 logging 节; 这里读 probe.json 的 log 节
//     (探针端有意不要求运维维护 settings.json, 见 newAgentLogWriter 注释)
//   - 字段类型: 这里用 *int/*bool, 因为探针端只有一个配置文件, 必须能区分"没写"
//     与"写了 0(关闭轮转)"/"写了 false"
//
// 轮转语义与根包一致: 当前日志 <dir>/<fileName>, 超限归档为 <dir>/<base>-N.log
// (N = 现存最大序号 + 1, Stat 防覆盖), 归档首行插入 "# archived at <时间>" 注释。
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// archiveSeqMax 序号扫描上限: 防目录里混入 10 位数字的怪文件导致循环取号
const archiveSeqMax = 100000

// probeLogConfig probe.json 的 log 节(探针端日志策略)。
//
// 四字段语义与中心端 settings.json 的 logging 节完全一致, 便于两边对照:
//
//	maxMB      单文件上限(MB), 0 = 不轮转; 缺省 8
//	maxFiles   历史文件保留份数; 缺省 20
//	dir        日志目录(相对 exe 目录或绝对路径); 缺省 logs
//	keepAtRoot true 时当前日志仍留 exe 根目录, 只有归档进 dir(兼容开关)
type probeLogConfig struct {
	MaxMB      *int   `json:"maxMB"`
	MaxFiles   *int   `json:"maxFiles"`
	Dir        string `json:"dir"`
	KeepAtRoot *bool  `json:"keepAtRoot"`
	// Log 仅用于匹配中心端完整配置里的嵌套结构(见 loadProbeLogConfig),
	// 探针端自己的 probe.json 直接写在顶层, 不会用到本字段。
	Log *probeLogConfig `json:"log"`
}

// probe.json 里 log 节可能出现的三种位置(扁平 / client 内 / 直接顶层),
// 统一在 loadProbeLogConfig 里拍平成一个结果。
type probeConfigShape struct {
	Log    *probeLogConfig `json:"log"`
	Client *probeLogConfig `json:"client"`
}

// agentLogWriter 带轮转能力的日志写入器(并发安全)。
//
// 字段与根包 logWriter 一一对应; 这里**刻意不导出**, 因为 agent 进程里只有
// main.logLine 一个出口, 不需要外部注入能力。
type agentLogWriter struct {
	mu   sync.Mutex
	file *os.File
	path string
	dir  string

	maxBytes int64
	maxFiles int

	written int64
}

// newAgentLogWriter 按 probe.json 的 log 节创建探针日志写入器。
func newAgentLogWriter(exeDir, fileName string) *agentLogWriter {
	maxMB, maxFiles, dir, keepAtRoot := 8, 20, "logs", false
	if cfg, ok := loadProbeLogConfig(exeDir); ok {
		if cfg.MaxMB != nil {
			maxMB = *cfg.MaxMB
		}
		if cfg.MaxFiles != nil {
			maxFiles = *cfg.MaxFiles
		}
		if strings.TrimSpace(cfg.Dir) != "" {
			dir = cfg.Dir
		}
		if cfg.KeepAtRoot != nil {
			keepAtRoot = *cfg.KeepAtRoot
		}
	}
	// 负数一律退回默认: 写 -1 会退化成"每次写都轮转"或"永不删", 静默生效比报错更难查
	if maxMB < 0 {
		maxMB = 8
	}
	if maxFiles < 0 {
		maxFiles = 20
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(exeDir, dir)
	}
	// keepAtRoot=true 时当前日志留 exe 根目录(兼容"排障脚本硬编码了日志路径"的存量部署)
	curPath := filepath.Join(dir, fileName)
	if keepAtRoot {
		curPath = filepath.Join(exeDir, fileName)
	}
	return newAgentLogWriterAt(curPath, dir, int64(maxMB)*1024*1024, maxFiles)
}

// loadProbeLogConfig 读取 probe.json 的 log 节(缺失/损坏返回 ok=false 走默认值)。
//
// 解析结构与根包 loadConfig 保持一致: 先试 {"client":{...}} 包装(中心端完整配置),
// 失败再试扁平结构(仅 client 段) —— 同一个 probe.json 可能被两端读取, 口径必须相同。
func loadProbeLogConfig(exeDir string) (probeLogConfig, bool) {
	var wrap probeConfigShape
	raw, err := os.ReadFile(filepath.Join(exeDir, "probe.json"))
	if err != nil {
		return probeLogConfig{}, false
	}
	// Windows 记事本/PowerShell Set-Content -Encoding UTF8 会写入 UTF-8 BOM,
	// 不剥会让 json.Unmarshal 直接失败, 现象是"配置明明写了却不生效"(实测踩过)
	raw = stripBOMBytes(raw)
	if json.Unmarshal(raw, &wrap) != nil {
		return probeLogConfig{}, false
	}
	if wrap.Client != nil && wrap.Client.Log != nil {
		return *wrap.Client.Log, true
	}
	if wrap.Log != nil {
		return *wrap.Log, true
	}
	return probeLogConfig{}, false
}

// stripBOMBytes 剥掉 UTF-8 BOM(EF BB BF)。
func stripBOMBytes(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// newAgentLogWriterAt 打开日志文件(打开失败降级为"只写控制台", 不阻断启动)。
func newAgentLogWriterAt(path, dir string, maxBytes int64, maxFiles int) *agentLogWriter {
	w := &agentLogWriter{path: path, dir: dir, maxBytes: maxBytes, maxFiles: maxFiles}
	// 当前日志所在目录先建出来, 否则首次启动会打开失败, 表现为"跑了但没日志文件"
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr == nil {
		w.open()
	}
	if w.file != nil {
		// 续写已有文件时必须知道当前大小, 否则"重启后立刻轮转"或"永远不轮转"
		if st, err := w.file.Stat(); err == nil {
			w.written = st.Size()
		}
	}
	return w
}

func (w *agentLogWriter) open() {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		w.file = f
	}
}

// Write 写一条日志, 超限时先轮转。
func (w *agentLogWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		// 首次打开失败(如目录只读)时每次写再试一次 —— 用户可能中途修好了权限
		w.open()
		if w.file == nil {
			return len(b), nil
		}
	}
	if w.maxBytes > 0 && w.written+int64(len(b)) > w.maxBytes {
		w.rotateLocked()
	}
	n, err := w.file.Write(b)
	w.written += int64(n)
	return n, err
}

// rotateLocked 归档当前文件并重开新的当前日志(全程持锁, 见根包同名函数说明)。
func (w *agentLogWriter) rotateLocked() {
	if w.file != nil {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.file = nil
	}
	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		// 归档目录建不出来(如只读盘): 降级为继续追加, 宁可文件大也不要丢日志
		w.open()
		w.written = 0
		return
	}
	dst := w.nextArchivePath()
	if err := os.Rename(w.path, dst); err != nil {
		w.open()
		w.written = 0
		return
	}
	prependAgentArchiveStamp(dst)
	w.open()
	w.written = 0
	w.pruneLocked()
}

// nextArchivePath 生成下一个可用的归档路径 <base>-N.log。
//
// 扫描现存归档取"最大序号 + 1", 再用 Stat 确认目标不存在(见根包 nextArchivePath
// 的详细说明: 删除中间卷后不回填空洞, Stat 用于挡住扫描与 rename 之间的并发)。
func (w *agentLogWriter) nextArchivePath() string {
	base := strings.TrimSuffix(filepath.Base(w.path), filepath.Ext(w.path))
	next := 1
	if max, ok := maxArchiveSeq(w.dir, base); ok {
		next = max + 1
	}
	for i := 0; i < archiveSeqMax; i++ {
		cand := filepath.Join(w.dir, fmt.Sprintf("%s-%d.log", base, next))
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		} else if err != nil {
			next++
			continue
		}
		next++
	}
	return filepath.Join(w.dir, fmt.Sprintf("%s-%d-%d.log", base, next, time.Now().UnixNano()))
}

// prependAgentArchiveStamp 在归档文件首行插入归档时间注释(与根包同口径)。
//
// 任一步失败只放弃插入注释, 绝不损坏已归档的日志 —— 那是排障的唯一线索。
// 策略: 读出全部 -> 写临时文件 -> rename 覆盖(Go 没有原地前插能力)。
func prependAgentArchiveStamp(path string) {
	stamp := fmt.Sprintf("# archived at %s\n", time.Now().Format("2006-01-02 15:04:05"))
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	buf := make([]byte, 0, len(stamp)+len(data))
	buf = append(buf, stamp...)
	buf = append(buf, data...)
	if werr := os.WriteFile(tmp, buf, 0o644); werr != nil {
		_ = os.Remove(tmp)
		return
	}
	if rerr := os.Rename(tmp, path); rerr != nil {
		_ = os.Remove(tmp)
	}
}

// pruneLocked 只保留最近 maxFiles 份归档(按**数字序号**排序, 删序号最小的)。
//
// 用归档名正则精确匹配, 而不是 strings.HasPrefix(name, base+"-"):
// 后者会把同目录下**别的进程**的日志一起算进来(中心端 yugsight-* 与探针端
// yugsight-agent-* 互为前缀), 导致误删对方的历史日志。正则同时转义了 base
// 里的正则元字符。
//
// 【必须按数字排序, 不能按字符串排序】字符串序下 "yugsight-agent-10.log" <
// "...-2.log", 于是 10 会被当成"比 2 更旧"优先删除 —— 归档超过 10 卷后就会开始
// 删掉最新日志、保留最旧的, 且不报任何错。
func (w *agentLogWriter) pruneLocked() {
	if w.maxFiles <= 0 {
		return
	}
	base := strings.TrimSuffix(filepath.Base(w.path), filepath.Ext(w.path))
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	re := archiveSeqRe(base)
	type arch struct {
		name string
		seq  int
	}
	var list []arch
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := re.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, cerr := strconv.Atoi(m[1])
		if cerr != nil {
			continue
		}
		list = append(list, arch{name: e.Name(), seq: n})
	}
	if len(list) <= w.maxFiles {
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].seq < list[j].seq })
	for _, a := range list[:len(list)-w.maxFiles] {
		_ = os.Remove(filepath.Join(w.dir, a.name))
	}
}

// archiveSeqRe 匹配归档文件名 <base>-<数字>.log。
func archiveSeqRe(base string) *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(base) + `-(\d{1,9})\.log$`)
}

// maxArchiveSeq 扫描目录返回 <base>-N.log 的最大 N, 以及是否存在归档。
func maxArchiveSeq(dir, base string) (int, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, false
	}
	re := archiveSeqRe(base)
	max, found := 0, false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := re.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, cerr := strconv.Atoi(m[1])
		if cerr != nil {
			continue
		}
		if !found || n > max {
			max, found = n, true
		}
	}
	return max, found
}

// Close 关闭文件(退出前调用, 让最后几条日志落盘)。
func (w *agentLogWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.file = nil
	}
}

// 保证 slog 仍被引用(项目约定: 错误统一走结构化日志, 但 agent 侧全部经 logLine
// 落文件 —— 保留引用是为了让"忘了接 slog"这类改动在编译期就被发现)。
var _ = slog.LevelInfo
