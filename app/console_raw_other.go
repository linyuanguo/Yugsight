//go:build !windows

package main

// setStdinRaw 非 Windows 平台 stdin 无行缓冲问题, 空实现。
func setStdinRaw() {}
