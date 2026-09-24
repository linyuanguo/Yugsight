//go:build windows

package scanner

import (
	"strings"
	"testing"
	"unsafe"
)

// 本文件是 Windows FFI 枚举的护栏测试(非 Windows 平台整文件不参与编译,
// 与 collect_windows.go 同口径 —— 没有 build 约束会在 linux/darwin 上编译失败)。

// TestEnumServiceStatusLayout ENUM_SERVICE_STATUS 的布局必须与 Windows 一致。
//
// 这是"改坏了会静默失效"的典型: 结构体大小/字段顺序错了, EnumServicesStatusW
// 照样成功返回, 只是服务名全成乱码或空, 没有任何报错可循。尾部那 4 字节填充
// 尤其容易被当成冗余删掉 —— 删掉后步进变 44, 从第二个服务起全错。
func TestEnumServiceStatusLayout(t *testing.T) {
	if got := unsafe.Sizeof(enumServiceStatus{}); got != 48 {
		t.Fatalf("ENUM_SERVICE_STATUS 应为 48 字节(两指针 + 7 个 DWORD + 尾部对齐填充), 实际 %d", got)
	}
}

// TestListServicesWindows 真实枚举一次服务, 断言读到的服务名可用。
//
// 同时是 checkptr 的回归护栏: 曾用 (*[4096]uint16)(p) 读结构里的 LPCWSTR, 而该
// 指针落在 Go 堆分配的缓冲区内 → -race 下 **fatal error: checkptr**(不是 panic,
// recover 拦不住、日志写不进去, 现场只表现为进程静默消失)。改 bufString 按缓冲
// 偏移解码后才安全。
func TestListServicesWindows(t *testing.T) {
	svcs, err := listServicesWindows()
	if err != nil {
		t.Skipf("本机服务枚举不可用(受限会话): %v", err)
	}
	if len(svcs) == 0 {
		t.Fatal("服务枚举不应返回空列表")
	}
	empty := 0
	for _, s := range svcs {
		if strings.TrimSpace(s.Name) == "" {
			empty++
		}
		if s.State == "" {
			t.Fatalf("服务 %q 缺少状态文本", s.Name)
		}
	}
	if empty > len(svcs)/2 {
		t.Fatalf("服务名大面积为空(%d/%d), 多半是结构体布局或字符串读取错了", empty, len(svcs))
	}
}

// TestBufString bufString 的偏移换算与边界(不依赖真实 Windows API)。
//
// 守的是"结构里的指针要换算成缓冲内偏移再解码"这条口径 —— 直接解引用会在
// -race 下 checkptr 崩, 而偏移算错则表现为字符串错位/空串, 两者都不报错。
func TestBufString(t *testing.T) {
	var buf [32]byte
	// 偏移 8 处放 UTF-16 "AB"
	buf[8], buf[10] = 'A', 'B'
	if got := bufString(buf[:], unsafe.Pointer(&buf[8])); got != "AB" {
		t.Fatalf("缓冲内字符串应为 AB, 实际 %q", got)
	}
	// 越界与空指针一律空串(绝不越界读、不解引用野指针)
	if got := bufString(buf[:], nil); got != "" {
		t.Fatalf("空指针应返回空串, 实际 %q", got)
	}
	if got := bufString(buf[:], unsafe.Pointer(&buf[30])); got != "" {
		t.Fatalf("偏移越界应返回空串, 实际 %q", got)
	}
}
