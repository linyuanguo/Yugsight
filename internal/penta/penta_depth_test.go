package penta

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestRunLogDepthAndRisk 守"日志要体现渗透深度与隐患"的契约(2026-09-25 用户口径):
// 执行日志末尾必须给出 ① 渗透深度(到达哪一层/几步连通) ② 命中步骤的隐患文案。
// 之前日志只有一行"结论: N 步命中", 用户看不出"渗透到什么程度、有什么风险"。
func TestRunLogDepthAndRisk(t *testing.T) {
	// 命中场景: PING -> +PONG, 步骤带 Risk 文案
	tpl := &Template{ID: "t", Steps: []StepSpec{
		{Name: "ping", Type: StepTCP, Send: "PING\r\n", Expect: `\+PONG`,
			Risk: "Redis 未授权访问成立: 攻击者可免认证读写全部数据"},
	}}
	eng := &Engine{Now: time.Now, Dial: prefixDialer(map[string]string{"PING": "+PONG\r\n"})}
	out := eng.Run(context.Background(), testTask(), tpl, nil)

	if !strings.Contains(out.Log, "=== 验证结论 ===") {
		t.Fatalf("日志缺验证结论块: %s", out.Log)
	}
	if !strings.Contains(out.Log, "渗透深度:") {
		t.Fatalf("日志缺渗透深度行: %s", out.Log)
	}
	if !strings.Contains(out.Log, "服务响应层") {
		t.Fatalf("渗透深度应标明到达的服务响应层: %s", out.Log)
	}
	if !strings.Contains(out.Log, "发现隐患:") {
		t.Fatalf("命中时日志缺隐患块: %s", out.Log)
	}
	if !strings.Contains(out.Log, "Redis 未授权访问成立") {
		t.Fatalf("隐患块应引用步骤 Risk 文案: %s", out.Log)
	}
	if out.Steps[0].Risk == "" {
		t.Fatal("命中步骤的 Risk 字段应回填(前端步骤列表展示用)")
	}

	// 未命中场景: 服务可达(有响应)但无漏洞行为 -> 隐患行说明"未观测到", 不能留白
	tpl2 := &Template{ID: "t2", Steps: []StepSpec{
		{Name: "ping", Type: StepTCP, Send: "PING\r\n", Expect: `\+PONG`},
	}}
	engNoHit := &Engine{Now: time.Now, Dial: prefixDialer(map[string]string{"PING": "-ERR unknown command\r\n"})}
	out2 := engNoHit.Run(context.Background(), testTask(), tpl2, nil)
	if !strings.Contains(out2.Log, "未观测到本模板覆盖的漏洞行为") {
		t.Fatalf("未命中日志应说明未观测到漏洞行为: %s", out2.Log)
	}
	if strings.Contains(out2.Log, "发现隐患:") {
		t.Fatalf("未命中不应出现'发现隐患'块: %s", out2.Log)
	}

	// 不可达场景: 深度 = 连接层, 隐患 = 无法评估
	eng3 := &Engine{Now: time.Now, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}}
	out3 := eng3.Run(context.Background(), testTask(), tpl2, nil)
	if !strings.Contains(out3.Log, "连接层") {
		t.Fatalf("不可达时渗透深度应为连接层: %s", out3.Log)
	}
	if !strings.Contains(out3.Log, "无法评估") {
		t.Fatalf("不可达时隐患应为'无法评估': %s", out3.Log)
	}
}

// weakpass 步骤的隐患文案必须带口令明细(空口令/弱口令两种口径)。
func TestRunWeakPassRiskText(t *testing.T) {
	tpl := &Template{ID: "wp", Steps: []StepSpec{
		{Name: "login", Type: StepWeakPass, Service: "redis", Port: 6379},
	}}
	// 空口令命中: redis 流程先 PING, 回 +PONG = 免认证即可执行命令(未授权访问)
	engEmpty := &Engine{Now: time.Now, Dial: prefixDialer(map[string]string{
		"PING": "+PONG\r\n",
	})}
	out := engEmpty.Run(context.Background(), testTask(), tpl, nil)
	if !out.Steps[0].Hit {
		t.Fatalf("空口令场景应命中(替身 AUTH 回 +OK): %s", out.Summary)
	}
	if !strings.Contains(out.Steps[0].Risk, "免口令登录") {
		t.Fatalf("空口令命中的隐患文案应说明免口令: %q", out.Steps[0].Risk)
	}
	if !strings.Contains(out.Log, "免口令登录") {
		t.Fatalf("日志隐患块应包含空口令口径: %s", out.Log)
	}
}
