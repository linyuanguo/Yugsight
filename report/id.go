package report

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// newID 生成带前缀的唯一 ID: 前缀 + UnixNano + 随机 3 字节 hex。
// 与 db 包的 newID 同口径(不 import db: report 包要与存储层解耦)。
func newID(prefix string) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s%d-%s", prefix, time.Now().UnixNano(), hex.EncodeToString(b))
}

// NewArchiveID 生成报告存档 ID。
func NewArchiveID() string { return newID("rp") }

// NewTemplateID 生成报告模板 ID。
func NewTemplateID() string { return newID("tpl") }

// NewRawReportID 生成原始报告 ID（rr 前缀，与渲染报告存档 rp 区分）。
func NewRawReportID() string { return newID("rr") }
