//go:build !windows

package main

// ensureAdmin 非 Windows 平台无 UAC 提权
func ensureAdmin() {}

// ensureSingleInstance 非 Windows 平台暂不做单实例检查
func ensureSingleInstance() {}
