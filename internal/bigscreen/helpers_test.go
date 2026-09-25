package bigscreen

import (
	"strconv"
	"sync/atomic"
)

// 测试辅助: 避免在测试里 import strconv(保持测试文件聚焦业务断言)。
func itoa(n int) string { return strconv.Itoa(n) }

var seq int64

// statusSeq 返回递增序号, 用于生成不重复的探针 ID。
func statusSeq() int { return int(atomic.AddInt64(&seq, 1)) }


