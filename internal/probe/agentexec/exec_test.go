package agentexec

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"yugsight/internal/probe"
)

// TestParseTargetHost 目标串归一化: scheme 前缀剥离 + 路径截断。
//
// 顺序不可调换是这里的核心约束: 先剥前缀再切路径, 否则 "http://a:8080/x"
// 会被切成 "http:"。用例同时锁住这个顺序。
func TestParseTargetHost(t *testing.T) {
	cases := map[string]string{
		"http://10.0.0.5:8080/x?y=1": "10.0.0.5:8080",
		"https://10.0.0.5/":          "10.0.0.5",
		"image:nginx:latest":         "nginx:latest",
		"fs:/app":                    "app",
		"10.0.0.5":                   "10.0.0.5",
		"  10.0.0.5  ":               "10.0.0.5",
		"":                           "",
	}
	for in, want := range cases {
		if got := ParseTargetHost(in); got != want {
			t.Errorf("ParseTargetHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParsePortsParam 端口参数解析: 列表/区间/混合/越界/空值。
func TestParsePortsParam(t *testing.T) {
	if got := ParsePortsParam("80,443"); !reflect.DeepEqual(got, []int{80, 443}) {
		t.Fatalf("逗号列表解析错误: %v", got)
	}
	// 区间展开
	got := ParsePortsParam("80-83")
	if !reflect.DeepEqual(got, []int{80, 81, 82, 83}) {
		t.Fatalf("区间解析错误: %v", got)
	}
	// 混合 + 越界项应被丢弃
	got = ParsePortsParam("22,70000,abc,80")
	if !reflect.DeepEqual(got, []int{22, 80}) {
		t.Fatalf("混合解析应丢弃越界/非法项: %v", got)
	}
	// 空值给常用端口(非空)
	if got := ParsePortsParam(""); len(got) == 0 {
		t.Fatal("空值应返回常用端口集")
	}
	// 全非法时兜底 80/443
	if got := ParsePortsParam("abc,def"); !reflect.DeepEqual(got, []int{80, 443}) {
		t.Fatalf("全非法应兜底 80/443: %v", got)
	}
}

// TestParsePortsParamRangeCap 单区间上限防呆: 1-65535 不得展开成 6 万项。
func TestParsePortsParamRangeCap(t *testing.T) {
	got := ParsePortsParam("1-65535")
	if len(got) > 5001 {
		t.Fatalf("区间未做上限防呆, 展开出 %d 项", len(got))
	}
	if len(got) == 0 || got[0] != 1 {
		t.Fatalf("区间起点错误: %v", got[:min(3, len(got))])
	}
}

// TestExpandCIDR 网段展开: CIDR 去网络/广播地址, 单 IP, 逗号列表。
func TestExpandCIDR(t *testing.T) {
	got, err := ExpandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("CIDR 展开失败: %v", err)
	}
	// /30 共 4 个地址, 去掉网络与广播后剩 2 个
	if !reflect.DeepEqual(got, []string{"192.168.1.1", "192.168.1.2"}) {
		t.Fatalf("/30 展开错误(应去网络/广播): %v", got)
	}
	if got, _ := ExpandCIDR("10.0.0.1"); !reflect.DeepEqual(got, []string{"10.0.0.1"}) {
		t.Fatalf("单 IP 展开错误: %v", got)
	}
	// 逗号列表: 合法 IP 逐个展开
	if got, _ := ExpandCIDR("10.0.0.1,10.0.0.2"); !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("逗号列表展开错误: %v", got)
	}
	// 逗号列表含非法项: 整体报错(与 scanner.ParseHosts 口径一致)
	if _, err := ExpandCIDR("10.0.0.1,bad..ip"); err == nil {
		t.Fatal("含非法项的列表应报错")
	}
	if _, err := ExpandCIDR("   "); err == nil {
		t.Fatal("空目标应返回错误")
	}
}

// TestRunUnsupportedKind 不支持的 Kind 必须**回传失败结果**(而不是返回 error)。
//
// 语义约定: 探针的任务失败也是一种结果 —— 返回 error 会让调用方把结果整个丢掉,
// 中心端只能看到"超时无响应", 无法知道是"能力缺失"还是"网络不可达"。
// 因此断言的是 Result.Status/Error, 不是函数返回值。
func TestRunUnsupportedKind(t *testing.T) {
	res, err := Run(context.Background(), &probe.TaskAssign{TaskID: "t1", Kind: "synscan", Target: "10.0.0.1"}, func(string) {})
	if err != nil {
		t.Fatalf("任务失败应通过结果表达, 不应返回 error: %v", err)
	}
	if res == nil || res.Status != probe.TaskFailed {
		t.Fatalf("不支持的 Kind 应回传失败状态, 实际 %+v", res)
	}
	if !strings.Contains(res.Error, "不支持") {
		t.Fatalf("错误信息应说明原因, 实际 %q", res.Error)
	}
}

// TestSupportedKindSCA SCA 类型(image/fs/container)必须在 supportedKind 白名单里。
//
// 守的是"agentexec 白名单与 probe/scanner.Run 的 switch 分支保持一致"的契约 ——
// agentexec 是探针任务入口的守门员, 若漏加 SCA 类型, 中心端下发的 image 任务会被
// "探针不支持的任务类型"在入口就拒绝, 探针的 trivy 能力根本用不上(表面看像中心端
// 没下发, 实际是探针自己挡了)。2026-09-26 远程扫容器联调时踩到: scanner.Run 加了
// image 分支, 忘了同步这里的白名单。
func TestSupportedKindSCA(t *testing.T) {
	for _, k := range []string{"image", "fs", "container"} {
		if !supportedKind(k) {
			t.Errorf("supportedKind(%q) 应为 true(SCA 类型探针需支持, 与 scanner.Run 一致)", k)
		}
	}
	// 反向: 真不支持的类型仍拒绝(避免白名单被误放宽到任意字符串)。
	if supportedKind("synscan") {
		t.Error("未知类型 synscan 不应被支持")
	}
}

// TestRunPortEmptyTarget 空目标必须回传失败结果, 且不发起任何真实扫描。
func TestRunPortEmptyTarget(t *testing.T) {
	res, err := Run(context.Background(), &probe.TaskAssign{TaskID: "t2", Kind: "port", Target: "   "}, func(string) {})
	if err != nil {
		t.Fatalf("任务失败应通过结果表达, 不应返回 error: %v", err)
	}
	if res == nil || res.Status != probe.TaskFailed {
		t.Fatalf("空目标应回传失败状态, 实际 %+v", res)
	}
	if !strings.Contains(res.Error, "目标为空") {
		t.Fatalf("错误信息应说明原因, 实际 %q", res.Error)
	}
}

// TestRunProgressCallback port 任务应至少回调一次进度(开始执行),
// 保证中心端能看到任务已进入执行态而不是一直挂着"已下发"。
func TestRunProgressCallback(t *testing.T) {
	var msgs []string
	// 目标用保留测试网段, 不发起真实外网扫描; 端口给 1 个以尽快返回。
	_, err := Run(context.Background(), &probe.TaskAssign{
		TaskID: "t3", Kind: "port", Target: "127.0.0.1", Ports: "1",
	}, func(m string) { msgs = append(msgs, m) })
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("未收到任何进度回调")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
