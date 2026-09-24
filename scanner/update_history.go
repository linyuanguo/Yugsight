//go:build !windows || windows

// update_history.go 更新版本记录 + 旧版本自动备份 + 更新日志(任务 2 检查点 5)。
//
// 能力:
//   - 版本记录: 本地已应用 commit 存于 rules/.commit / cpe/.commit(在线更新模块
//     写入); LocalRuleCommit / LocalCPECommit 提供只读访问, RulesDir 供 Web 展示
//   - 更新日志: 每轮规则/CPE 更新(成功或回滚)追加一条 JSONL 到 exe 同目录
//     update.log; 写入失败只记 slog, 绝不影响更新主流程
//   - 旧版本自动备份: 应用新版本前, 把当前正式模板文件拷贝到 rules/backup/<旧commit短名>/
//     (CPE 库为 cpe/backup/), 保留最近 3 版, 超出自动清理
//   - 回滚: 更新失败时在线更新模块本身不动正式文件(等价停留在上一可用版本);
//     RestoreRulesBackup 提供"回滚至指定备份版本"的显式能力(恢复后热加载)
//
// 依赖: 仅 Go 标准库。
package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"yugsight/pathrel"
)

// backupRetention 备份保留版本数(按修改时间从新到旧保留)
const backupRetention = 3

// UpdateLogEntry 单条更新日志
type UpdateLogEntry struct {
	Time       time.Time `json:"time"`
	Kind       string    `json:"kind"` // "rules" / "cpe"
	FromCommit string    `json:"fromCommit"`
	ToCommit   string    `json:"toCommit,omitempty"`
	Files      int       `json:"files"`
	Status     string    `json:"status"` // "success" / "rollback"(校验/下载/应用失败, 已回滚)
	Error      string    `json:"error,omitempty"`
	DurationMS int64     `json:"durationMs"`
}

// updateLogPath 更新日志文件路径(exe 同目录 update.log, JSONL)
func updateLogPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "update.log")
	}
	return "update.log"
}

// logUpdateEntry 追加一条更新日志(任何失败只记 slog, 不返回错误, 不影响主流程)
func logUpdateEntry(e UpdateLogEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		updateLog.Warn("更新日志序列化失败", "err", err)
		return
	}
	b = append(b, '\n')
	f, err := os.OpenFile(updateLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		updateLog.Warn("更新日志写入失败", "err", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		updateLog.Warn("更新日志写入失败", "err", err)
	}
}

// ReadUpdateLog 返回最近 limit 条更新日志(新 -> 旧); 文件缺失返回 nil
func ReadUpdateLog(limit int) []UpdateLogEntry {
	if limit <= 0 {
		limit = 50
	}
	data, err := os.ReadFile(updateLogPath())
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	out := make([]UpdateLogEntry, 0, limit)
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var e UpdateLogEntry
		if err := json.Unmarshal([]byte(line), &e); err == nil {
			out = append(out, e)
		}
	}
	return out
}

// ===== 版本记录(只读访问) =====

// LocalRuleCommit 返回规则库本地已应用 commit(未更新过返回空串)
func LocalRuleCommit() string {
	return readLocalCommit(rulesOfficialDir())
}

// LocalCPECommit 返回 CPE 库本地已应用 commit(未更新过返回空串)
func LocalCPECommit() string {
	return readLocalCommit(cpeDir())
}

// RulesDir 返回规则库官方扩展包目录(exe 同目录 rules/), 供 Web 展示
func RulesDir() string {
	return rulesOfficialDir()
}

// ===== 旧版本自动备份 =====

// sanitizeLabel 备份目录名净化(仅保留字母数字, 截断 12 位; 空 -> "pre")
func sanitizeLabel(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 12 {
		s = s[:12]
	}
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "pre"
	}
	return b.String()
}

// backupOldVersion 把 dir 下当前正式模板文件整体备份到 dir/backup/<label>/,
// 返回备份目录名(已存在同名备份时跳过拷贝直接返回)。
// 只备份规则包 *.yaml / CPE 库 *.json 普通文件; 排除 .staging / backup / custom 子目录
// (custom 是用户自定义规则, 不属于官方版本)。失败只记日志, 不中断更新。
func backupOldVersion(dir, kind, label string) string {
	label = sanitizeLabel(label)
	backupDir := filepath.Join(dir, "backup", label)
	if _, err := os.Stat(backupDir); err == nil {
		return label // 已有同名备份, 跳过
	}
	exts := []string{".yaml", ".yml"}
	if kind == "cpe" {
		exts = []string{".json"}
	}
	var copied int
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(p)
			if p != dir && (base == "backup" || base == ".staging" || base == "custom") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		ok := false
		for _, e := range exts {
			if ext == e {
				ok = true
				break
			}
		}
		if !ok {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return nil
		}
		dst := filepath.Join(backupDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil
		}
		data, rerr2 := os.ReadFile(p)
		if rerr2 != nil {
			return nil
		}
		if werr := os.WriteFile(dst, data, 0o644); werr == nil {
			copied++
		}
		return nil
	})
	if copied > 0 {
		updateLog.Info("旧版本已自动备份", "dir", pathrel.Short(backupDir), "files", copied, "label", label)
	}
	pruneBackups(dir)
	return label
}

// pruneBackups 按修改时间从新到旧保留最近 backupRetention 个备份, 超出的整体删除
func pruneBackups(dir string) {
	backupRoot := filepath.Join(dir, "backup")
	entries, err := os.ReadDir(backupRoot)
	if err != nil {
		return
	}
	type bk struct {
		name string
		mod  time.Time
	}
	var bks []bk
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		bks = append(bks, bk{name: e.Name(), mod: info.ModTime()})
	}
	if len(bks) <= backupRetention {
		return
	}
	sort.Slice(bks, func(i, j int) bool { return bks[i].mod.After(bks[j].mod) })
	for _, b := range bks[backupRetention:] {
		if err := os.RemoveAll(filepath.Join(backupRoot, b.name)); err == nil {
			updateLog.Info("旧备份已清理", "backup", b.name)
		}
	}
}

// ListBackups 列出 dir 下可用的备份版本名(无备份返回 nil)
func ListBackups(dir string) []string {
	entries, err := os.ReadDir(filepath.Join(dir, "backup"))
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// RestoreRulesBackup 把指定备份版本恢复到 rules/ 正式目录(覆盖当前同名文件)
// 并热加载, 即"回滚至上一可用版本"。返回恢复的文件数。
func RestoreRulesBackup(label string) (int, error) {
	label = sanitizeLabel(label)
	if label == "" {
		return 0, errors.New("备份名非法")
	}
	dir := rulesOfficialDir()
	backupDir := filepath.Join(dir, "backup", label)
	if _, err := os.Stat(backupDir); err != nil {
		return 0, fmt.Errorf("备份版本不存在: %s", label)
	}
	var n int
	_ = filepath.Walk(backupDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rel, rerr := filepath.Rel(backupDir, p)
		if rerr != nil {
			return nil
		}
		dst := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil
		}
		data, rerr2 := os.ReadFile(p)
		if rerr2 != nil {
			return nil
		}
		if werr := os.WriteFile(dst, data, 0o644); werr == nil {
			n++
		}
		return nil
	})
	if n == 0 {
		return 0, fmt.Errorf("备份版本 %s 为空(无可恢复文件)", label)
	}
	RefreshRules()
	updateLog.Info("规则库已回滚到备份版本", "backup", label, "files", n)
	return n, nil
}
