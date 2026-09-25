package main

// 控制台 URL 常显(不随日志滚屏刷走)。
//
// 【要解决的问题】控制台窗口 = 服务界面, 所有运行日志实时打到 stdout。启动日志里的
// "UI 地址: http://192.168.1.143:8420" 几秒后就被后续日志顶出可视区, 用户关掉浏览器
// 想重新打开时, 只能往回滚屏找那一行 —— 而启动阶段日志量大, 那一行往往已经滚出
// 缓冲区(scrollback)之外, 再也找不回来。用户还要求 URL 可以直接点击打开。
//
// 【采用的方案】三个互补的手法:
//   1) URL 钉在视口第一行: 每条日志输出完后(与 logLine 同锁内), 把 URL 行重写在当前
//      视口顶部(srWindow.Top, 不是缓冲区第 0 行 —— 视口随日志下移, 钉第 0 行用户根本
//      看不到)。Windows 控制台没有"固定某行"的 API, 这是唯一的模拟手法; 上一位置的
//      URL 行同时清空, 避免回看历史时满屏都是旧 URL(点旧链接会打开旧端口)。
//      用户用滚动条回看历史时不重绘不清行 —— 不能破坏用户正在看的内容。
//   2) 控制台标题栏(SetConsoleTitleW): 标题常驻, 任务栏缩略图悬浮也能看到;
//   3) 后台 goroutine 常驻监听键盘: 按 O 键用系统默认浏览器打开该地址。
//
// 【点击打开由谁负责】交给控制台自己的 URL 检测(用户确认的方案): Windows 10+ 的
// conhost 与 Windows Terminal 都支持"按住 Ctrl 点击 URL 打开浏览器"(悬停会出下划线),
// 对屏幕上任何纯文本 URL 生效 —— 顶栏这行就是普通文本, 零额外依赖, 也不抢占控制台
// 原有的鼠标框选复制功能(若程序自己接管鼠标事件, 框选复制就废了)。

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// consoleConfig settings.json 的 console 节。
//
// 【为什么默认 true 而不是像其它新功能一样默认 false】项目规则 5 的"默认关闭"针对的是
// **会改变执行链路**的功能(扫描、探针、调度器), 关错了会静默改变扫描结果; 这里只是往
// 标题栏写一个字符串 + 监听一个按键, 不改任何执行链路, 关掉反而让用户少一个"关掉网页
// 后怎么回去"的答案 —— 与"大屏不加开关"同一判断口径。
type consoleConfig struct {
	// Hint 是否启用"地址常显"(顶栏 URL 行 + 标题栏地址 + 按 O 打开页面)。
	// 显式写 false 可关闭(如把程序服务化、stdin 被接管、不想让程序碰控制台屏幕时)。
	Hint *bool `json:"hint"`
}

var (
	consoleCfgOnce sync.Once
	consoleCfg     consoleConfig
)

// consoleHintEnabled 读 settings.json 的 console 节, 缺失即默认开启。
func consoleHintEnabled() bool {
	consoleCfgOnce.Do(func() {
		raw, ok := section("console", "")
		if !ok {
			return
		}
		if err := json.Unmarshal(raw, &consoleCfg); err != nil {
			logLine("settings.json 的 console 节解析失败(使用默认值: 启用控制台地址常显): " + err.Error())
		}
	})
	// 用 *bool: JSON 零值无法区分"没写"与"写了 false", 而 false 在语义上是"明确关闭"。
	// 不写成 *bool 的话, 用户写了 {"hint":false} 会被零值 false 与"没写"混为一谈 —— 结果
	// 虽然一致(都关), 但反过来"没写"被当成 false 就错了(默认该是开)。
	if consoleCfg.Hint == nil {
		return true
	}
	return *consoleCfg.Hint
}

// resetConsoleConfigCache 清空配置缓存(仅供测试, 同 logrotate.go 的 resetLogConfigCache)。
func resetConsoleConfigCache() {
	consoleCfgOnce = sync.Once{}
	consoleCfg = consoleConfig{}
}

// uiURL 当前 UI 地址(启动成功后在 main 里赋值)。
//
// 用 sync.Once 之外的普通变量 + 互斥保护: 写入只发生一次(main 启动阶段), 读取发生在
// 标题刷新 goroutine 与键盘监听 goroutine, 属跨 goroutine 访问, 需要加锁。
var (
	uiURLMu    sync.RWMutex
	uiURLValue string
)

// 顶栏 pin 状态。pinActive 用 atomic: consolePinAfterLog 在每条日志路径上都要跑,
// 未启用时必须是一次无锁读(日志洪峰时这个函数每秒被调几十次)。
// pinMu 保护 pinLastTop/pinLastW 与"清旧行+写新行"两步的原子性(两层锁顺序恒为
// logMu -> pinMu, 无死锁路径)。
var (
	pinActive  atomic.Bool
	pinMu      sync.Mutex
	pinLastTop int16 = -1 // 上次写 URL 行的缓冲区行号; -1 = 尚未写过
	pinLastW   int        // 上次写时的窗口宽度(清旧行要按旧宽清, resize 变窄才清得干净)
)

// SetUIURL 记录当前 UI 地址并立即刷新控制台标题与顶栏首刷。
// 由 main 在 startServer 成功后调用(端口顺延后的真实端口只有此刻才知道)。
func SetUIURL(u string) {
	uiURLMu.Lock()
	uiURLValue = u
	uiURLMu.Unlock()
	refreshConsoleTitle()
	initConsolePin()
}

// GetUIURL 返回当前 UI 地址(未启动完成时为空串)。
func GetUIURL() string {
	uiURLMu.RLock()
	defer uiURLMu.RUnlock()
	return uiURLValue
}

// refreshConsoleTitle 把标题刷成 "御视 (Yugsight) v1.0.0 — http://ip:port"。
//
// 【为什么要带版本】同一台机器上常有多个版本的 exe 在跑(见历史踩坑: 两个进程名不同的
// 二进制同时存在导致"新路由 404")。标题里带版本, 用户一眼能看出当前这个窗口跑的是哪个
// 版本, 省掉一轮排查。
//
// 【为什么 bind 信息也顺带带上】地址本身就是"打开哪个页面"的答案; 端口是顺延后的真实值,
// 不以日志行(已被刷走)为唯一来源。
func refreshConsoleTitle() {
	u := GetUIURL()
	title := displayCnName + " v" + appVersion
	if u != "" {
		title += " — " + u
	}
	setConsoleTitle(title)
}

// startConsoleHint 启动控制台常驻提示。
//
// 【为什么用 goroutine 而不是塞进主消息循环】项目当前用控制台"窗口"当界面(见
// console_windows.go 的决策: 自绘窗口消息循环曾出 0xC0000005 原生崩溃, recover 捕不到,
// 故彻底放弃自绘 UI)。这里只读键盘, 不创建任何窗口、不注册窗口过程, 因此不存在那条
// 崩溃路径; 用一个普通 goroutine 即可, 退出靠 quit 通道。
//
// 默认开启, 但可被 settings.json 的 console 节关闭(项目规则 5 口径): 有人把日志重定向到
// 文件读取, 不希望程序在读 stdin(某些 CI/服务化场景下 stdin 被接管, 读它可能干扰)。
func startConsoleHint(quit <-chan struct{}) {
	if !consoleHintEnabled() {
		return
	}
	// initConsolePin 幂等: SetUIURL 在 main 里先于本函数调用, 已激活的话这里是空操作。
	// 放它的原因: 单独以 -no-browser 之外路径直启时 SetUIURL 总会先跑, 但把激活逻辑
	// 收敛到一个函数里, 两处入口谁先谁后都不影响行为(项目规则 4: 不依赖调用顺序)。
	initConsolePin()
	go consoleKeyLoop(quit)
	logLine(fmt.Sprintf("提示: 网页关闭后按 O 键重新打开 %s", GetUIURL()))
}

// ===== 顶栏常显(URL 钉在视口第一行) =====

// initConsolePin 激活顶栏常显并做首刷。
//
// 激活条件 = 配置开关开 + 存在控制台。首刷时机: SetUIURL 时视口必然贴底(启动阶段
// 日志一路向下), URL 立即出现在视口顶; 之后每条日志输出后由 consolePinAfterLog 维持。
func initConsolePin() {
	if pinActive.Load() {
		return
	}
	if !consoleHintEnabled() || !hasConsole() {
		return
	}
	pinActive.Store(true)
	pinURLTopline()
}

// consolePinAfterLog 由 logLine 在"往控制台写完一行日志"后调用(必须与输出同锁内)。
//
// 【为什么挂在日志后面而不是前面】日志输出会把视口往下推 —— 若先重绘后输出, URL 行
// 立刻被顶出视口顶; 输出完再重绘, URL 才稳定停在新视口的顶行。
//
// 【为什么必须与日志输出互斥】重绘 = "移光标 -> 写行 -> 移回光标"三步, 若与并发的
// logLine 输出交错, 日志会写进顶栏行中间(撕裂)。调用方持 logMu 保证顺序执行。
func consolePinAfterLog() {
	if !pinActive.Load() || GetUIURL() == "" {
		return
	}
	pinURLTopline()
}

// consoleURLLineText 拼装顶栏整行文本: 标记 + URL + 操作提示 + 尾部空格填充。
//
// 【为什么整行覆盖而不是只写 URL】只写 URL 的话, 上一次更长的内容(如换端口前的旧
// 地址、resize 前的宽行)会残留在行尾 —— 用户 Ctrl+点击点到的可能是残影里的旧链接。
// 【为什么填到 width-1 而不是 width】写满最后一列会触发 conhost 的自动折行标志,
// 下一次日志输出前先折行, 顶栏下方会凭空多出空行。
func consoleURLLineText(width int) string {
	u := GetUIURL()
	if u == "" || width < 20 {
		return ""
	}
	target := width - 1
	body := "  >> UI 界面: " + u + "   (按 O 键打开页面)"
	if w := displayWidth(body); w > target {
		// 窗口太窄, 逐级降级: 丢提示语 -> 丢 ">>" 前缀 -> 硬截断。URL 本身的优先级最高
		// —— 链接不完整就点不开了, 剩下的装饰都可以牺牲。顶栏绝不能超宽: 超宽折行等于
		// 把"钉一行"变成"钉多行", 每条日志都会把日志区顶下去几行。
		body = "  >> " + u
		if displayWidth(body) > target {
			body = "  " + u
			if displayWidth(body) > target {
				r := []rune(body)
				for len(r) > 0 && displayWidth(string(r)) > target {
					r = r[:len(r)-1]
				}
				body = string(r)
			}
		}
	}
	return body + strings.Repeat(" ", target-displayWidth(body))
}

// displayWidth 估算字符串在控制台里的显示列数(中文等全宽字符按 2 列)。
//
// 【为什么不用第三方 runewidth】项目纯标准库零依赖(工程约束), 且这里只做行内填充,
// 差 1 列的后果只是行尾残留 1 个空格 —— 覆盖写会把它盖掉, 自实现的粗算完全够用。
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r < 0x80: // ASCII
			w++
		case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
			r >= 0x2E80 && r <= 0xA4CF,   // CJK 部首~彝文
			r >= 0xAC00 && r <= 0xD7A3,   // Hangul 音节
			r >= 0xF900 && r <= 0xFAFF,   // CJK 兼容表意
			r >= 0xFE30 && r <= 0xFE4F,   // CJK 兼容形式
			r >= 0xFF00 && r <= 0xFF60,   // 全角形式
			r >= 0xFFE0 && r <= 0xFFE6,   // 全角符号
			r >= 0x20000 && r <= 0x3FFFD: // CJK 扩展 B+
			w += 2
		default:
			w++
		}
	}
	return w
}

// viewportAtBottom 判断视口是否贴底(跟随最新输出)。
//
// 【为什么要有这个判断】用户用滚动条回看历史时视口不贴底 —— 此时重绘会把 URL 写进
// 用户正看着的历史中间, 清旧行更会把用户正在阅读的行抹掉。让用户安静看完, 回到
// 底部(或新日志到达时)顶栏自然恢复。容差 1 行: 日志长行折行时视口可能滞后 1 行。
func viewportAtBottom(srBottom, cursorY int32) bool {
	return srBottom >= cursorY-1
}

// consoleKeyLoop 读 stdin 单字节, 命中 O/o 就用浏览器打开 UI 地址。
//
// 【为什么读单字节而不是按行读】按行读需要用户敲回车, 且会把用户"顺手输入的其它内容"
// 吞掉。单字节读对用户无感: 敲什么都没反应(不往日志里回显), 只有 O 生效。
//
// 【坑: stdin 可能是 EOF 或不可读】被 --no-browser 之外的方式启动时 stdin 可能已被关闭
// (例如某些打包器/服务封装), os.Stdin.Read 会立刻反复返回 EOF —— 不加退避的话这里会变成
// 死循环空转烧 CPU。故 EOF 时直接退出循环(不再需要这个功能), 出错则退避 1s 重试。
func consoleKeyLoop(quit <-chan struct{}) {
	// 兜底: 这个 goroutine 里任何 panic 都不该带走主进程(项目规则 4)
	defer func() {
		if r := recover(); r != nil {
			logLine(fmt.Sprintf("控制台快捷键监听已退出: %v", r))
		}
	}()
	setStdinRaw() // Windows: 去掉行缓冲+回显, 按 O 立即触发(无需回车)
	buf := make([]byte, 1)
	for {
		select {
		case <-quit:
			return
		default:
		}
		n, err := os.Stdin.Read(buf)
		if err != nil {
			if isEOF(err) {
				// stdin 关闭: 这是正常情况(重定向/服务化), 不是错误, 静默退出
				return
			}
			select {
			case <-quit:
				return
			case <-time.After(time.Second):
			}
			continue
		}
		if n == 0 {
			continue
		}
		switch buf[0] {
		// O 键(打开页面)。同时接受 o 与回车之外的常见"打开"键位, 但刻意不做太多:
		// 控制台是用户可能在等待扫描时顺手敲字的地方, 键位越多越容易误触。
		case 'o', 'O':
			u := GetUIURL()
			if u == "" {
				continue
			}
			logLine("收到快捷键 O: 打开页面 " + u)
			openBrowser(u)
		}
	}
}

// isEOF 判断读 stdin 的错误是否等同于"输入结束"。
// 单独抽出来是为了让非 Windows 平台也能用同一份逻辑(不引 io 之外的东西)。
func isEOF(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "EOF") || strings.Contains(s, "file already closed")
}
