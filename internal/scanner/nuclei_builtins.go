//go:build !windows || windows

// nuclei_builtins.go 内置 Nuclei 模板(解析层 · 内置数据源)。
//
// 设计:
//   - 内置模板经 embed 打包进 exe(单文件 exe 场景无需外部目录, 开箱即用)
//   - 内容为 Yugsight 自研的通用 Web 风险模板(templates_builtin/), 不复制任何第三方
//     模板库内容 —— 用户自配外部模板时请自行遵守对应模板库的许可协议
//   - 与外部模板目录(支持热更新, 见 nuclei_parser.go)合并后使用:
//     模板 ID 冲突时外部模板覆盖内置(用户可修正/下线内置模板)
//   - 内置模板是不可变的内存数据(embed), 全进程只解析一次, 不参与热更新
//
// 命中溯源: 内置模板产出的 finding 带 Source="nuclei-builtin",
// 外部模板为 Source="nuclei", 与内置规则(vuln_builtin.json, 无 Source)区分。
package scanner

import (
	"embed"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed templates_builtin
var builtinTemplatesFS embed.FS

var (
	builtinOnce  sync.Once
	builtinCache []Template
	builtinErrs  []string
)

// LoadBuiltinTemplates 返回打包进 exe 的内置模板(解析一次后缓存)。
// 返回 (模板列表, 错误列表); 单文件失败只记日志不中断整体加载。
func LoadBuiltinTemplates() ([]Template, []string) {
	builtinOnce.Do(func() {
		builtinCache, builtinErrs = loadBuiltinTemplatesLocked()
	})
	return builtinCache, builtinErrs
}

// BuiltinTemplateCount 返回内置模板数量, 供 /api/info 展示
func BuiltinTemplateCount() int {
	LoadBuiltinTemplates()
	return len(builtinCache)
}

func loadBuiltinTemplatesLocked() ([]Template, []string) {
	var tpls []Template
	var errs []string
	_ = fs.WalkDir(builtinTemplatesFS, "templates_builtin", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // 不中断
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, rerr := builtinTemplatesFS.ReadFile(path)
		if rerr != nil {
			nucleiLog.Error("内置模板读取失败, 跳过", "file", path, "err", rerr)
			errs = append(errs, path+": 读取失败 "+rerr.Error())
			return nil
		}
		tpl, perr := ParseNucleiTemplate(data)
		if perr != nil {
			nucleiLog.Error("内置模板解析失败, 跳过", "file", path, "err", perr)
			errs = append(errs, path+": 解析失败 "+perr.Error())
			return nil
		}
		if tpl == nil {
			return nil // 非 http 类型, 静默跳过
		}
		tpl.Builtin = true
		tpl.SHA256 = sha256Hex(data)
		if ps := validateTemplate(tpl); len(ps) > 0 {
			for _, p := range ps {
				nucleiLog.Warn("内置模板 matcher 无效, 对应 matcher 不会命中",
					"tpl", tpl.ID, "file", path, "problem", p)
			}
		}
		tpls = append(tpls, *tpl)
		return nil
	})
	nucleiLog.Info("内置模板加载完成", "count", len(tpls), "errors", len(errs))
	return tpls, errs
}

// LoadAllTemplates 返回合并后的模板集: 内置(exe 打包) + 外部(目录, 预加载缓存+热更新)。
// ID 冲突时外部覆盖内置; 内置模板保持原顺序在前, 外部新增模板追加在后。
// 返回 (合并列表, 两路错误合集)。
func LoadAllTemplates(dir string) ([]Template, []string) {
	builtin, bErrs := LoadBuiltinTemplates()
	external, eErrs := LoadTemplateCache(dir)
	errs := make([]string, 0, len(bErrs)+len(eErrs))
	errs = append(errs, bErrs...)
	errs = append(errs, eErrs...)
	return mergeTemplates(builtin, external), errs
}

// mergeTemplates 合并两个模板集, 外部(external)按模板 ID 覆盖内置(builtin)
func mergeTemplates(builtin, external []Template) []Template {
	out := make([]Template, 0, len(builtin)+len(external))
	seen := make(map[string]int, len(builtin)+len(external)) // id -> out 下标
	for _, t := range builtin {
		seen[t.ID] = len(out)
		out = append(out, t)
	}
	for _, t := range external {
		if i, ok := seen[t.ID]; ok {
			out[i] = t // 外部覆盖内置
			continue
		}
		seen[t.ID] = len(out)
		out = append(out, t)
	}
	return out
}
