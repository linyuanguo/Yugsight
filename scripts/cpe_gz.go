//go:build ignore

// cpe_gz.go 重新生成 scanner/cpe_builtin.json.gz(内置 CPE 库 gzip 嵌入形态)。
//
// 用法(仓库根目录): go run scripts/cpe_gz.go
//
// 背景: cpe.go 嵌入 cpe_builtin.json(原始兜底), cpe_engine.go 嵌入
// cpe_builtin.json.gz(精简体积)。两份必须来自同一个 json 源文件 —— 手工
// 维护两份极易漂移, 故统一由本脚本从 json 源生成 gz。
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
)

func main() {
	// 约定在仓库根目录执行: go run scripts/cpe_gz.go
	src, err := os.ReadFile("scanner/cpe_builtin.json")
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(src); err != nil {
		panic(err)
	}
	if err := gw.Close(); err != nil {
		panic(err)
	}
	if err := os.WriteFile("scanner/cpe_builtin.json.gz", buf.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("scanner/cpe_builtin.json.gz regenerated: %dB (source %dB)\n", len(buf.Bytes()), len(src))
}
