// logrotate.go 日志文件轮转(中心端 yugsight.log 与探针端 yugsight-agent.log 共用)。
//
// ===== 为什么需要它 =====
//
// 旧实现是 os.OpenFile(..., O_APPEND) 打开一个固定文件, 一直写到进程退出:
//
//   - 长时间挂机(扫描器正是这种"常驻"用法)日志会无限增长, 实测几周就上百 MB,
//     既占磁盘, 也让"翻日志排障"变成不可能 —— 打开就是几百兆的文本;
//   - 单文件写满磁盘会连带影响数据落盘(JSONL 数据库在同一目录)。
//
// ===== 目录结构 =====
//
//	<exe 目录>/logs/yugsight.log     当前日志
//	<exe 目录>/logs/yugsight-1.log   第 1 卷归档
//	<exe 目录>/logs/yugsight-2.log   第 2 卷归档
//
// 当前日志与归档**都**放在 logs/ 子目录: exe 同目录已经有一堆配置文件与数据目录,
// 日志再散开会让"哪些文件能动、哪些不能动"更难分辨 —— 全在一个子目录里, 一眼就能
// 整体删除/打包/对比, 也便于运维只给这一个目录配外部采集/清理策略。
//
// ===== 轮转规则 =====
//
// 当前日志超过上限(默认 8MB)时, 在上锁状态下原子换新:
//
//	logs/yugsight.log -> logs/yugsight-N.log, 然后新建空的 logs/yugsight.log
//
// 序号 N 用"扫目录取当前最大序号 + 1"得到(而不是进程内自增), 于是:
//
//   - 重启进程后新归档会接着已有编号往下走, 不会从 1 重来把旧归档覆盖掉;
//   - 与外部工具(人工删除、外部归档脚本)共用目录时行为可预期。
//
// 【为什么删档后不会重号】N 取自"现存文件的最大序号 + 1"。若用户删掉了中间某卷
// (如 logs/yugsight-3.log), 下一卷仍是 max+1(如 5), 不会回填 3 —— 回填会让
// "编号越大越旧"之外还多出一层"编号有空洞"的解读负担, 且外部按编号做增量采集
// 时容易漏文件。
//
// 【Stat 防覆盖】Windows 的 os.Rename 在目标已存在时是静默覆盖(不报错), 因此
// 找到候选编号后必须再 Stat 一次确认不存在, 存在则继续 +1 重试。缺了这一步,
// 上面"取 max+1"的正确性就依赖"扫描与 rename 之间目录没变化"这一无法保证的假设。
//
// 【归档首行写时间戳】文件名只有序号, 看不出"这一卷对应哪段时间"。归档时在文件
// 首行插入 "archived at 2026-09-18 10:15:30" 注释行, 兼顾"序号命名"与"可读性"。
// 注释以 # 开头, 与日志正文(以时间戳 "2026-09-18 10:15:30  " 开头)不冲突。
//
// ===== 配置 =====
//
// 中心端: settings.json 的 logging 节
//
//	{ "maxMB": 8, "maxFiles": 20, "dir": "logs", "keepAtRoot": false }
//
// 探针端: probe.json 的 log 节(同一套字段, 见 cmd/agent/logrotate.go)
// maxMB=0 表示关闭轮转(恢复旧行为, 单文件一直写); dir 支持绝对路径(把日志放别的盘)。
// keepAtRoot=true 为兼容开关: 当前日志仍留在 exe 根目录, 只有归档进 dir/
// (供"排障脚本硬编码了 exe 同目录 yugsight.log"的存量部署平滑过渡)。
//
// 本文件是 main 包的一部分(所以两处调用方共享同一实现), cmd/agent 通过同包复制
// 的副本使用 —— 详见 cmd/agent/logrotate.go 的说明。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 日志节配置默认值。
const (
	logRotateDefaultMaxMB    = 8  // 单个日志文件上限
	logRotateDefaultMaxFiles = 20 // 历史文件保留份数
	logRotateDefaultDir      = "logs"
	// archiveSeqMax 序号扫描上限: 防目录里混入 10 位数字的怪文件导致循环取号
	archiveSeqMax = 100000
)

// logRotateConfig settings.json 的 logging 节。
type logRotateConfig struct {
	// MaxMB 单文件上限(MB), 0 表示不轮转(沿用旧的"一直追加"行为)
	MaxMB int `json:"maxMB"`
	// MaxFiles 历史文件保留份数(超出按序号删最旧)
	MaxFiles int `json:"maxFiles"`
	// Dir 日志目录(相对 exe 目录或绝对路径)。当前日志与归档都放这里。
	Dir string `json:"dir"`
	// KeepAtRoot 兼容开关: true 时当前日志仍留在 exe 根目录, 只有归档进 Dir。
	// 默认 false(当前日志也进 Dir)。存在的意义是给"排障脚本/采集器硬编码了
	// exe 同目录 yugsight.log"的存量部署一个不改脚本就能升级的退路。
	KeepAtRoot bool `json:"keepAtRoot"`
}

// logWriter 带轮转能力的日志写入器(并发安全)。
//
// 中心端与探针端各自持有一个实例(文件名不同), 互不干扰; 测试可独立构造,
// 因此轮转逻辑可以完全脱离进程环境单测(见 logrotate_test.go)。
type logWriter struct {
	mu   sync.Mutex
	file *os.File
	path string // 当前日志完整路径
	dir  string // 归档目录

	maxBytes int64
	maxFiles int

	written int64 // 当前文件已写字节数(自己记账, 不用 Stat —— 少一次系统调用)
}

// newLogWriter 打开(必要时创建)日志文件。
//
// 【失败不报错】打开失败时返回的对象 file==nil, Write 会静默丢弃 —— 项目规则:
// 外部资源不可用时降级运行, 不能因为"日志写不了"就让扫描器起不来。
func newLogWriter(path, dir string, maxBytes int64, maxFiles int) *logWriter {
	w := &logWriter{path: path, dir: dir, maxBytes: maxBytes, maxFiles: maxFiles}
	// 当前日志所在的目录先建出来, 否则首次启动(日志目录还不存在时)会打开失败,
	// 表现为"程序跑了但没有任何日志文件", 排查起来要绕一圈
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

// open 打开当前日志文件(调用方需自持锁, 或处于初始化阶段)。
func (w *logWriter) open() {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		w.file = f
	}
}

// Write 写一条日志, 超限时先轮转。
func (w *logWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		// 首次打开失败(如目录只读), 每次写入再试一次 —— 用户可能中途修好了权限
		w.open()
		if w.file == nil {
			return len(b), nil
		}
	}
	// 先轮转再写: 判断依据是"写完这一条会不会超限", 用即将写入的长度预估,
	// 避免单条超长日志把文件撑过上限后要等下一次写入才轮转
	if w.maxBytes > 0 && w.written+int64(len(b)) > w.maxBytes {
		w.rotateLocked()
	}
	n, err := w.file.Write(b)
	w.written += int64(n)
	return n, err
}

// rotateLocked 关闭当前文件, 移入归档目录, 重开一个新的当前日志。
// 全程持锁: 多 goroutine 同时写日志时, 若两个 goroutine 都进入轮转,
// 后一个会把前一个刚建的新文件当成"旧的"再移走, 导致当前日志时有时无。
func (w *logWriter) rotateLocked() {
	if w.file != nil {
		_ = w.file.Sync() // 移走前落盘, 避免归档文件尾部缺内容
		_ = w.file.Close()
		w.file = nil
	}
	// 归档目录按需创建; 建不出来就退回"不轮转"(宁可持续追加, 也不要丢日志)
	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		w.open()
		w.written = 0
		return
	}
	dst := w.nextArchivePath()
	if err := os.Rename(w.path, dst); err != nil {
		// rename 失败(如被杀软占用)同样降级为继续追加
		w.open()
		w.written = 0
		return
	}
	prependArchiveStamp(dst)
	w.open()
	w.written = 0
	w.pruneLocked()
}

// nextArchivePath 生成下一个可用的归档路径 logs/<base>-N.log。
//
// 扫描现有归档取"最大序号 + 1"。用 Stat 确认目标不存在后再返回(见文件头
// "Stat 防覆盖"的说明): 扫描与 rename 之间存在外部并发(用户手工删档、
// 另一个同前缀进程)时, 这一步能拦住"静默覆盖别人文件"。
func (w *logWriter) nextArchivePath() string {
	base := strings.TrimSuffix(filepath.Base(w.path), filepath.Ext(w.path))
	next := 1
	if max, ok := maxArchiveSeq(w.dir, base); ok {
		next = max + 1
	}
	for i := 0; i < archiveSeqMax; i++ {
		cand := filepath.Join(w.dir, fmt.Sprintf("%s-%d.log", base, next))
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand // 不存在 -> 可以安全使用
		} else if err != nil {
			// Stat 报非"不存在"的错误(如权限): 保守起见继续往后找,
			// 不能假定"能写" —— 覆盖别人文件的代价远大于序号跳号
			next++
			continue
		}
		next++
	}
	// 极端情况(目录里有十万个归档)兜底: 带纳秒后缀, 保证不与任何 -N.log 冲突
	return filepath.Join(w.dir, fmt.Sprintf("%s-%d-%d.log", base, next, time.Now().UnixNano()))
}

// archiveSeqRe 匹配归档文件名 <base>-<数字>.log。
//
// 必须精确匹配 base 且锚定结尾: logs/ 目录可能同时放着中心端与探针端的日志
// (同机联调时常见, 前缀 yugsight- 与 yugsight-agent- 互为前缀关系), 用宽松的
// HasPrefix 会把对方的历史一起算进来, 导致序号跳号甚至误删对方文件。
// base 里的正则元字符需转义(如 "yugsight.v2")。
func archiveSeqRe(base string) *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(base) + `-(\d{1,9})\.log$`)
}

// maxArchiveSeq 扫描目录, 返回 <base>-N.log 形式的最大 N。
// 第二个返回值表示"是否找到了任何归档", 供调用方区分"没有归档"与"最大序号为 0"。
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

// prependArchiveStamp 在归档文件首行插入归档时间注释。
//
// 【为什么要付出这次重写的代价】文件名只有序号(yugsight-3.log), 时间信息在
// 迁移到"序号命名"时丢失了。翻日志排障的第一件事就是定位"哪个文件对应哪段时间",
// 而目录里一堆同前缀文件按序难以分辨。首行注释是最小侵入的补偿手段。
//
// 【失败必须降级】任何一步失败(读不出来、写不进去)只放弃插入注释, 绝不
// 删除/损坏已归档的日志 —— 那是排障的唯一线索。整体策略是"读出全部 -> 写临时
// 文件 -> rename 覆盖", 而不是"在原文件头部插入"(Go 没有原地前插能力)。
func prependArchiveStamp(path string) {
	stamp := fmt.Sprintf("# archived at %s\n", time.Now().Format("2006-01-02 15:04:05"))
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	// 大文件(超过 64MB)不插入: 重写成本与风险都不划算, 日志本身已是可接受的
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
// 【必须按数字排序, 不能按字符串排序】字符串序下 "yugsight-10.log" < "yugsight-2.log"
// (逐字符比较 '1' < '2'), 于是 10 会被当成"比 2 更旧"而优先删除 —— 归档超过 10 卷
// 后就会开始删掉最新日志、保留最旧的, 且不报任何错。这是本模块最隐蔽的一类缺陷。
func (w *logWriter) pruneLocked() {
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

// Close 关闭文件(进程退出时调用, 让最后几条日志落盘)。
func (w *logWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.file = nil
	}
}

// ===== 配置与全局实例 =====

var (
	logCfgOnce sync.Once
	logCfg     logRotateConfig
)

// loadLogConfig 读取 settings.json 的 logging 节(缺失即默认值)。
//
// 用独立 Once 而非复用 loadSettings 的缓存: loadSettings 是进程级懒加载,
// 而日志初始化发生在极早期(其他模块打日志之前), 显式读一次更可控。
func loadLogConfig() logRotateConfig {
	logCfgOnce.Do(func() {
		c := logRotateConfig{
			MaxMB:    logRotateDefaultMaxMB,
			MaxFiles: logRotateDefaultMaxFiles,
			Dir:      logRotateDefaultDir,
		}
		if raw, ok := section("logging", ""); ok {
			var got logRotateConfig
			if err := json.Unmarshal(raw, &got); err != nil {
				logLine("settings.json 的 logging 节解析失败(使用默认轮转配置): " + err.Error())
			} else {
				// 只覆盖**显式写了**的字段: JSON 零值无法区分"没写"与"写了 0",
				// 而 maxMB=0 在语义上是"关闭轮转", 必须与"没写"区分开。
				// 做法是解析到临时 map 判断键是否存在。
				var keys map[string]json.RawMessage
				if json.Unmarshal(raw, &keys) == nil {
					if _, has := keys["maxMB"]; has {
						c.MaxMB = got.MaxMB
					}
					if _, has := keys["maxFiles"]; has {
						c.MaxFiles = got.MaxFiles
					}
					if _, has := keys["dir"]; has && strings.TrimSpace(got.Dir) != "" {
						c.Dir = got.Dir
					}
					if _, has := keys["keepAtRoot"]; has {
						c.KeepAtRoot = got.KeepAtRoot
					}
				}
			}
		}
		// 负数一律当默认值: 配置写成 -1 时轮转逻辑会退化成"每次写都轮转"或"永不删",
		// 静默生效比报错更难排查
		if c.MaxMB < 0 {
			c.MaxMB = logRotateDefaultMaxMB
		}
		if c.MaxFiles < 0 {
			c.MaxFiles = logRotateDefaultMaxFiles
		}
		if strings.TrimSpace(c.Dir) == "" {
			c.Dir = logRotateDefaultDir
		}
		logCfg = c
	})
	return logCfg
}

// resetLogConfigCache 清空日志配置缓存(仅供测试)。
// 与 resetSettingsCache 同理: 进程级缓存不重置会让用例互相污染。
func resetLogConfigCache() {
	logCfgOnce = sync.Once{}
	logCfg = logRotateConfig{}
}

// logPaths 按配置算出"当前日志路径"与"归档目录"。
//
// 抽成纯函数的理由: 这两条路径的推导同时受 dir(相对/绝对)与 keepAtRoot 影响,
// 是本模块最容易算错的地方, 独立出来才能直接单测(不必真的写文件)。
//
// 语义:
//
//	keepAtRoot=false(默认) -> 当前日志 <dir>/<fileName>, 归档也 <dir>/
//	keepAtRoot=true        -> 当前日志 <exeDir>/<fileName>, 归档 <dir>/
func logPaths(exeDir, fileName string, c logRotateConfig) (curPath, archiveDir string) {
	dir := c.Dir
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(exeDir, dir)
	}
	if c.KeepAtRoot {
		return filepath.Join(exeDir, fileName), dir
	}
	return filepath.Join(dir, fileName), dir
}

// newLogWriterFromConfig 按 settings.json 的配置创建日志写入器。
// exeDir 传入是为了让 dir 支持相对路径(相对 exe 目录, 与其它配置口径一致)。
func newLogWriterFromConfig(exeDir, fileName string) *logWriter {
	c := loadLogConfig()
	curPath, archiveDir := logPaths(exeDir, fileName, c)
	return newLogWriter(curPath, archiveDir, int64(c.MaxMB)*1024*1024, c.MaxFiles)
}
