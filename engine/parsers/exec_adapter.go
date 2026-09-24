package parsers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"yugsight/engine"
)

// ExecFuncOf 把 engine.Executor 适配为编排器需要的 ExecFunc。
//
// 本函数是 engine 包与 parsers 包之间唯一的连接点(独立文件, 便于按需裁剪):
// 编排器本身不依赖 engine, 由调用方在装配阶段把执行器注入进来。
//
// 注意: 需要 ReadArtifact 的引擎(如 zap 落报告文件)由调用方自行准备参数
// (engine.ArgsZap 的 reportFile), 并在 Request.ReadArtifact 中读取该文件。
func ExecFuncOf(ex *engine.Executor) ExecFunc {
	if ex == nil {
		return nil
	}
	return func(ctx context.Context, engineName string, args []string) ([]byte, bool, error) {
		res, err := ex.Run(ctx, engine.Spec{Engine: engineName, Args: args})
		if res != nil {
			// 引擎缺失 / 启动失败 / 崩溃: 统一返回错误, 由编排器决定降级
			if err != nil || !res.OK {
				if res.Error != "" {
					if res.TimedOut {
						return nil, res.Truncated, context.DeadlineExceeded
					}
					if res.Cancelled {
						return nil, res.Truncated, context.Canceled
					}
					return []byte(res.Stdout), res.Truncated, errors.New(res.Error)
				}
				if err != nil {
					return []byte(res.Stdout), res.Truncated, err
				}
			}
			return []byte(res.Stdout), res.Truncated, nil
		}
		if err != nil {
			return nil, false, err
		}
		return nil, false, errors.New("引擎执行未返回结果")
	}
}

// NewEngineOrchestrator 装配一个接好外部引擎执行器的编排器。
//
//	o := parsers.NewEngineOrchestrator(engine.Default(), nil)
//	o.SetFallback(func(ctx, req) (*normalizer.RawBatch, error) { ... 内置引擎 ... })
//	out, err := o.Run(ctx, parsers.Request{Kind: "nmap", Target: "10.0.0.1", Ports: []int{80}})
//
// ex 为 nil 时等价于纯内置模式(任何请求都走降级路径)。
func NewEngineOrchestrator(ex *engine.Executor, fallback Runner) *Orchestrator {
	return NewOrchestrator(ExecFuncOf(ex), fallback)
}

// ZapArtifact 为 ZAP 类"报告落文件"的引擎准备报告路径与读取回调。
//
// ZAP 的 JSON 报告不支持输出到 stdout, 必须指定 -J <file>; 返回的 args 追加项
// 与 read 回调成对使用:
//
//	args, read, cleanup := parsers.ZapArtifact(os.TempDir(), "zap-123")
//	defer cleanup()
//	out, _ := o.Run(ctx, parsers.Request{Kind: "zap", Target: url,
//	    Args: args, ReadArtifact: read})
//
// dir 为空时用系统临时目录; 读取成功后自动删除报告文件。
func ZapArtifact(dir, id string) (args []string, read func() ([]byte, error), cleanup func()) {
	if strings.TrimSpace(dir) == "" {
		dir = os.TempDir()
	}
	if strings.TrimSpace(id) == "" {
		id = "zap"
	}
	file := filepath.Join(dir, "yugsight-"+sanitizeName(id)+".json")
	read = func() ([]byte, error) { return os.ReadFile(file) }
	cleanup = func() { _ = os.Remove(file) }
	return []string{"-J", file}, read, cleanup
}

// NmapArtifact 为 Nmap 类"报告落文件"的引擎准备报告路径与读取回调(与 ZapArtifact 同模式)。
//
// 【为什么不用 -oJ - (stdout), 实测记录 2026-09-20】
//
//	Windows 版 nmap(7.94 官方构建实测): "-oJ -" 与 "-oJ <file>" 的值都会被
//	当成扫描目标(报 Failed to resolve "-"/"...json", 文件路径进了目标列表),
//	即 -oJ 在 Windows 构建上完全不可用; 而 -oX/-oN 落文件正常。
//	Linux 版 nmap 7.80/7.94 的 "-oX -"(stdout) 可用(探针侧 nmapArgs 在用)。
//
// 为跨平台一致, 中心端统一走 XML 落文件: ParseNmap 首字符识别格式, XML 与
// JSON 两条解析路径等价(XML 还含 hostscript NSE, 信息量更大)。
//
//	args, read, cleanup := parsers.NmapArtifact(os.TempDir(), "scan-1")
//	defer cleanup()
//	out, _ := o.Run(ctx, parsers.Request{Kind: "port", Target: ip,
//	    Args: args, ReadArtifact: read})
//
// dir 为空时用系统临时目录; 读取成功后由调用方 cleanup 删除报告文件。
func NmapArtifact(dir, id string) (args []string, read func() ([]byte, error), cleanup func()) {
	if strings.TrimSpace(dir) == "" {
		dir = os.TempDir()
	}
	if strings.TrimSpace(id) == "" {
		id = "nmap"
	}
	file := filepath.Join(dir, "yugsight-nmap-"+sanitizeName(id)+".xml")
	read = func() ([]byte, error) { return os.ReadFile(file) }
	cleanup = func() { _ = os.Remove(file) }
	return []string{"-oX", file}, read, cleanup
}

// sanitizeName 文件名安全化(去掉路径分隔符与冒号等非法字符)。
func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "zap"
	}
	return b.String()
}
