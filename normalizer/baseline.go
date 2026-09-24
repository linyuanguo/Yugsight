package normalizer

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"yugsight/models"
)

// Baseline 上一轮扫描基线（用于 new / duplicate / fixed 状态标记）。
type Baseline struct {
	ScanID      string           `json:"scanId"`
	GeneratedAt time.Time        `json:"generatedAt"`
	Vulns       []*models.Vuln   `json:"vulns"`
}

// BaselineFromResult 由归一化结果生成基线（供下一轮对比）。
// 仅收录本轮命中漏洞（new / duplicate），已修复项不入库。
func BaselineFromResult(r *Result) *Baseline {
	if r == nil {
		return nil
	}
	b := &Baseline{ScanID: r.ScanID, GeneratedAt: r.GeneratedAt}
	for _, v := range r.Vulns {
		if v == nil {
			continue
		}
		c := *v
		b.Vulns = append(b.Vulns, &c)
	}
	return b
}

// LoadBaseline 读取基线文件。
// 文件不存在 / 为空返回 (nil, nil)（无基线）；文件损坏记录 WARN 并降级为无基线，不阻断流程。
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		slog.Warn("normalizer: 基线文件损坏, 忽略基线", "path", path, "err", err)
		return nil, nil
	}
	return &b, nil
}

// SaveBaseline 原子写入基线文件（tmp + rename），自动创建父目录。
func SaveBaseline(b *Baseline, path string) error {
	if b == nil {
		return nil
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
