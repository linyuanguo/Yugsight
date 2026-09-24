package main

// 报告自动触发契约测试(任务: 扫描结束自动生成报告)。
//
// 守的契约: report.json 的 autoGenerate 开关(规则 5 默认关闭)——
// 判定一旦写反, 每次扫描结束都会自动归档一份报告: 磁盘持续增长,
// 用户看到"没点过生成"的报告, 而这类问题不会报错, 只会慢慢被发现。
// 开关关闭必须零副作用(不建归档、不写库)。

import (
	"testing"
	"time"
)

// TestMaybeAutoGenerateReportOffByDefault 开关关闭(含"未配置"默认态)
// 时零副作用: 调用后报告存档表必须为空。
func TestMaybeAutoGenerateReportOffByDefault(t *testing.T) {
	_, d := newReportTestEnv(t, false)
	seedReportData(t, d)

	maybeAutoGenerateReport("host", "10.0.0.1")
	// 归档在 goroutine 里异步发生; 给一个观察窗口确认"确实没发生"
	time.Sleep(150 * time.Millisecond)
	if n, _ := d.Reports().Count(); n != 0 {
		t.Fatalf("autoGenerate 未开启却自动归档了 %d 份报告(规则 5: 默认关闭)", n)
	}
}

// TestMaybeAutoGenerateReportEnabled 开关打开时, 扫描结束自动归档一份
// 报告且正文非空(空正文的归档会让下载拿到空文件)。
func TestMaybeAutoGenerateReportEnabled(t *testing.T) {
	_, d := newReportTestEnv(t, true)
	setReportConfig(ReportConfig{
		Enabled:      true,
		MaxArchive:   50,
		AutoGenerate: boolPtr(true),
		Subtitle:     "测试报告",
		Accent:       "#4f46e5",
	})
	seedReportData(t, d)

	maybeAutoGenerateReport("host", "10.0.0.1")

	deadline := time.Now().Add(3 * time.Second)
	for {
		n, _ := d.Reports().Count()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("autoGenerate 开启后 3 秒内未自动归档报告")
		}
		time.Sleep(50 * time.Millisecond)
	}
	list, err := d.Reports().List()
	if err != nil || len(list) == 0 {
		t.Fatalf("读取自动归档报告失败: %v", err)
	}
	if list[0].Content == "" {
		t.Fatal("自动归档的报告正文为空(下载会拿到空文件)")
	}
}
