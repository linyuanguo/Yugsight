package scanner

// rule_updater_manifest_test.go 校验"生成器产物 -> 客户端落地"这条链路的字段兼容性。
//
// 背景: 仓库里有两套产 manifest 的实现 —— 客户端直连通道(scanner/rule_direct.go)与
// 源端生成器(cmd/gen-rules-manifest/main.go)。两者各写各的 JSON, 字段名/语义一旦漂移,
// 现象是"更新显示成功但规则数不变"或"校验全失败", 且很难定位。这里用生成器真实产出的
// JSON 文本(逐字节复制自冒烟测试输出)喂给客户端解析, 把这份契约钉死。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// genRulesManifestSample 生成器产出的真实样例(含缩进格式, 覆盖 MarshalIndent 的输出形状)
const genRulesManifestSample = `{
  "commit": "testrev",
  "name": "rules",
  "files": [
    {
      "path": "http/cves/CVE-2024-1111.yaml",
      "size": 181,
      "sha256": "b743efbd1d6d853f0c401e43a2e383edf40c845210a15c4a3d4cb9cf774b1d6f"
    }
  ]
}`

// TestGeneratorManifestParsesIntoRemoteManifest 生成器产出的清单必须能被客户端反序列化
func TestGeneratorManifestParsesIntoRemoteManifest(t *testing.T) {
	var m RemoteManifest
	if err := json.Unmarshal([]byte(genRulesManifestSample), &m); err != nil {
		t.Fatalf("客户端解析生成器清单失败(字段名已漂移?): %v", err)
	}
	if m.Commit != "testrev" {
		t.Errorf("commit = %q, 期望 testrev", m.Commit)
	}
	if len(m.Files) != 1 {
		t.Fatalf("files 数量 = %d, 期望 1", len(m.Files))
	}
	f := m.Files[0]
	if f.Path != "http/cves/CVE-2024-1111.yaml" {
		t.Errorf("path 应带 http/ 前缀, 实得 %q", f.Path)
	}
	if f.Size != 181 {
		t.Errorf("size = %d, 期望 181", f.Size)
	}
	if len(f.SHA256) != 64 {
		t.Errorf("sha256 应是 64 位十六进制, 实得 %d 位", len(f.SHA256))
	}
}

// TestGeneratorManifestAppliesLocally 端到端: 生成器产物经客户端落地流程后,
// 文件出现在 rules/<path> 且 checksum 登记、commit 写入。
//
// 这是"自建源"链路的等效验证 —— 用本地暂存模式代替 HTTP 拉取(沙箱拦回环),
// 下载之外的每一步(过滤/校验收敛/原子替换/登记/热加载)都是真实执行的。
func TestGeneratorManifestAppliesLocally(t *testing.T) {
	rulesDir, _ := withDirs(t)
	var m RemoteManifest
	if err := json.Unmarshal([]byte(genRulesManifestSample), &m); err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 构造与清单一致的本地包体(sha256 必须对得上, 否则校验阶段会拒绝)。
	// 模板形状必须符合本项目解析口径: request 是**映射**不是序列(Reference 类型),
	// path 才是序列 —— 写成序列会让热加载阶段报 "cannot unmarshal !!seq into Request",
	// 用例仍会通过但日志里会留一条误导性的解析失败。
	rel := m.Files[0].Path
	body := []byte(httpTemplate("CVE-2024-1111", "critical"))
	if int64(len(body)) != m.Files[0].Size {
		// 大小不符说明样例被改动过; 直接按实际内容重算清单, 保证一致性
		m.Files[0].Size = int64(len(body))
	}
	m.Files[0].SHA256 = sha256Hex(body)

	stage := t.TempDir()
	dst := filepath.Join(stage, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := applyManifest(&m, "", nil, stage)
	if err != nil {
		t.Fatalf("落地失败: %v", err)
	}
	if !res.Updated || res.Files != 1 {
		t.Fatalf("结果不符: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, filepath.FromSlash(rel))); err != nil {
		t.Fatalf("产物未落到 rules/: %v", err)
	}
	if c := readLocalCommit(rulesDir); c != "testrev" {
		t.Fatalf(".commit = %q, 期望 testrev", c)
	}
	if cs := loadRuleChecksums(rulesDir); cs[rel] != m.Files[0].SHA256 {
		t.Fatalf("checksum 未登记: %v", cs)
	}
}
