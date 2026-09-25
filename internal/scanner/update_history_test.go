package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ===== 版本备份 + 更新日志(任务 2 检查点 5) =====

// TestBackupOldVersion 旧版本自动备份: 只备份规则包 yaml, 排除 custom / 非 yaml
func TestBackupOldVersion(t *testing.T) {
	rulesDir, _ := withDirs(t)
	httpDir := filepath.Join(rulesDir, "http")
	if err := os.MkdirAll(httpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(httpDir, "a.yaml"), []byte("id: a\nrequest:\n  path: /\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(httpDir, "b.yml"), []byte("id: b\nrequest:\n  path: /\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "readme.txt"), []byte("not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rulesDir, "custom"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "custom", "c.yaml"), []byte("id: c\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	label := backupOldVersion(rulesDir, "rules", "aa11bb22cc33")
	if label != "aa11bb22cc33" {
		t.Errorf("备份名错误: %s", label)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "backup", label, "http", "a.yaml")); err != nil {
		t.Errorf("备份应含 a.yaml: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "backup", label, "http", "b.yml")); err != nil {
		t.Errorf("备份应含 b.yml: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "backup", label, "readme.txt")); !os.IsNotExist(err) {
		t.Error("非 yaml 文件不应备份")
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "backup", label, "custom")); !os.IsNotExist(err) {
		t.Error("custom 用户规则目录不应备份(不属于官方版本)")
	}
	// 同名备份重复调用: 跳过拷贝不报错
	if got := backupOldVersion(rulesDir, "rules", "aa11bb22cc33"); got != label {
		t.Errorf("重复备份应返回同名: %s", got)
	}
}

// TestBackupPrune 备份保留策略: 超出 3 版按修改时间从旧到新清理
func TestBackupPrune(t *testing.T) {
	rulesDir, _ := withDirs(t)
	httpDir := filepath.Join(rulesDir, "http")
	if err := os.MkdirAll(httpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(httpDir, "x.yaml"), []byte("id: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	names := []string{"v1", "v2", "v3", "v4"}
	for i, name := range names {
		backupOldVersion(rulesDir, "rules", name)
		mod := time.Now().Add(time.Duration(i) * time.Second)
		if err := os.Chtimes(filepath.Join(rulesDir, "backup", name), mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	got := ListBackups(rulesDir)
	if len(got) != backupRetention {
		t.Fatalf("应保留 %d 版, got %d: %v", backupRetention, len(got), got)
	}
	for _, g := range got {
		if g == "v1" {
			t.Errorf("最旧备份 v1 应被清理: %v", got)
		}
	}
}

// TestUpdateLog 更新日志: JSONL 追加 + 读取(新 -> 旧)
func TestUpdateLog(t *testing.T) {
	marker := "logtest-" + time.Now().Format("150405")
	logUpdateEntry(UpdateLogEntry{Time: time.Now(), Kind: "rules",
		FromCommit: "aaaa1111", ToCommit: "bbbb2222", Files: 2, Status: "success", DurationMS: 42})
	logUpdateEntry(UpdateLogEntry{Time: time.Now(), Kind: "cpe",
		FromCommit: "cccc3333", Status: "rollback", Error: marker, DurationMS: 7})

	es := ReadUpdateLog(50)
	if len(es) == 0 {
		t.Fatal("更新日志不应为空")
	}
	var okSuccess, okRollback bool
	for _, e := range es {
		if e.Kind == "rules" && e.FromCommit == "aaaa1111" && e.ToCommit == "bbbb2222" &&
			e.Status == "success" && e.Files == 2 && e.DurationMS == 42 {
			okSuccess = true
		}
		if e.Kind == "cpe" && e.Error == marker && e.Status == "rollback" {
			okRollback = true
		}
	}
	if !okSuccess || !okRollback {
		t.Errorf("日志应包含刚写入的记录: success=%v rollback=%v", okSuccess, okRollback)
	}
}

// TestRestoreRulesBackup 回滚: 删除正式文件后从备份恢复 + 热加载
func TestRestoreRulesBackup(t *testing.T) {
	rulesDir, _ := withDirs(t)
	httpDir := filepath.Join(rulesDir, "http")
	if err := os.MkdirAll(httpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := []byte("id: old-rule\ninfo:\n  name: o\n  severity: high\nrequest:\n  method: GET\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n")
	if err := os.WriteFile(filepath.Join(httpDir, "old.yaml"), old, 0o644); err != nil {
		t.Fatal(err)
	}
	writeCommit(rulesDir, "aaaa1111")
	label := backupOldVersion(rulesDir, "rules", "aaaa1111")

	if _, err := os.Stat(filepath.Join(rulesDir, "backup", label, "http", "old.yaml")); err != nil {
		t.Fatalf("备份应含旧版本文件: %v", err)
	}
	// 模拟新版本覆盖后出问题: 旧文件丢失
	if err := os.Remove(filepath.Join(httpDir, "old.yaml")); err != nil {
		t.Fatal(err)
	}
	n, err := RestoreRulesBackup(label)
	if err != nil || n != 1 {
		t.Fatalf("恢复失败: n=%d err=%v", n, err)
	}
	data, rerr := os.ReadFile(filepath.Join(httpDir, "old.yaml"))
	if rerr != nil || !bytes.Equal(data, old) {
		t.Errorf("恢复后文件内容应与备份一致: %v", rerr)
	}
	if _, ok := GetRuleByID("old-rule"); !ok {
		t.Error("恢复后热加载应能查到规则")
	}
	// 不存在的备份: 明确报错
	if _, err := RestoreRulesBackup("nope9999"); err == nil {
		t.Error("不存在的备份应返回错误")
	}
}

// TestRuleUpdateBackupAndLog 全流程: 在线更新前自动备份旧版本 + 成功后写更新日志
func TestRuleUpdateBackupAndLog(t *testing.T) {
	rulesDir, _ := withDirs(t)
	httpDir := filepath.Join(rulesDir, "http")
	if err := os.MkdirAll(httpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := []byte("id: keep-old\ninfo:\n  name: o\n  severity: medium\nrequest:\n  method: GET\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n")
	if err := os.WriteFile(filepath.Join(httpDir, "old.yaml"), old, 0o644); err != nil {
		t.Fatal(err)
	}
	writeCommit(rulesDir, "c1111111")

	newT := []byte("id: new-rule\ninfo:\n  name: n\n  severity: high\nrequest:\n  method: GET\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n")
	base := "https://cdn.example/rules/"
	fn := &fakeNet{files: map[string][]byte{
		base + "rules-manifest.json": mustJSON(t, RemoteManifest{
			Commit: "c2222222", Name: "rules",
			Files: []RemoteFile{{Path: "http/new.yaml", Size: int64(len(newT)), SHA256: sha256Hex(newT)}},
		}),
		base + "http/new.yaml": newT,
	}}
	withFakeNet(t, fn)
	withUpdater(t, base)

	res, err := DownloadRuleUpdate(nil)
	if err != nil || !res.Updated {
		t.Fatalf("更新失败: %v", err)
	}
	// 旧版本自动备份(commit 短名命名)
	if got := ListBackups(rulesDir); len(got) != 1 || got[0] != "c1111111" {
		t.Errorf("应自动备份旧版本: %v", got)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "backup", "c1111111", "http", "old.yaml")); err != nil {
		t.Error("备份应包含旧版本文件")
	}
	// 更新日志含成功记录(版本变化 c1111111 -> c2222222)
	ok := false
	for _, e := range ReadUpdateLog(50) {
		if e.Kind == "rules" && e.FromCommit == "c1111111" && e.ToCommit == "c2222222" && e.Status == "success" {
			ok = true
		}
	}
	if !ok {
		t.Error("更新日志应有成功记录")
	}
	// 回滚到备份版本: 旧文件恢复
	if n, err := RestoreRulesBackup("c1111111"); err != nil || n != 1 {
		t.Errorf("回滚恢复失败: n=%d err=%v", n, err)
	}
	data, _ := os.ReadFile(filepath.Join(httpDir, "old.yaml"))
	if !bytes.Equal(data, old) {
		t.Error("回滚后文件内容应与旧版本一致")
	}
}
