package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"yugsight/internal/dockerlist"
)

// TestScaEngineTimeout 覆盖: SCA 单目标超时抬升到 15 分钟(大镜像), 用户配置更长时尊重配置。
func TestScaEngineTimeout(t *testing.T) {
	cfg := Config{Timeout: Timeouts{Engine: 5 * time.Minute}}
	if got := scaEngineTimeout(cfg); got != SCAEngineTimeout {
		t.Fatalf("默认 5 分钟应抬到 15 分钟, 实际 %v", got)
	}
	cfg2 := Config{Timeout: Timeouts{Engine: 30 * time.Minute}}
	if got := scaEngineTimeout(cfg2); got != 30*time.Minute {
		t.Fatalf("用户配置的 30 分钟应被尊重, 实际 %v", got)
	}
}

// withFakeDocker 注入假 docker 执行(退出自动恢复, 测试间互不污染)。
func withFakeDocker(t *testing.T, out string, err error) {
	t.Helper()
	prev := dockerlist.DockerRun
	dockerlist.DockerRun = func(ctx context.Context, args ...string) (string, error) { return out, err }
	t.Cleanup(func() { dockerlist.DockerRun = prev })
}

// TestScaTargetsAutoEnumerate 覆盖: image/container 目标为空或"自动枚举"占位 →
// 本机 docker 全量枚举(2026-09-27 探针端自动识别: 用户不用知道探针主机有哪些镜像)。
func TestScaTargetsAutoEnumerate(t *testing.T) {
	prev := dockerlist.DockerRun
	dockerlist.DockerRun = func(ctx context.Context, args ...string) (string, error) {
		// 按子命令区分: images 有 <none> 占位(应剔除), ps 只回容器名(无占位概念)
		if len(args) > 0 && args[0] == "ps" {
			return "web-1\ndb-1\n", nil
		}
		return "nginx:1.25-alpine\nredis:7\n<none>:<none>\n", nil
	}
	t.Cleanup(func() { dockerlist.DockerRun = prev })
	cases := []struct {
		kind, target string
		want         []string
	}{
		{"image", "", []string{"nginx:1.25-alpine", "redis:7"}},
		{"image", scaAutoTarget, []string{"nginx:1.25-alpine", "redis:7"}},
		{"container", "", []string{"db-1", "web-1"}},
		{"container", scaAutoTarget, []string{"db-1", "web-1"}},
	}
	for _, tc := range cases {
		task := NewTask(tc.kind, tc.target, Config{})
		sub, targets, err := task.scaTargets(context.Background())
		if err != nil {
			t.Fatalf("kind=%s target=%q: %v", tc.kind, tc.target, err)
		}
		if sub != tc.kind {
			t.Fatalf("kind=%s 子命令应为 %s, 实际 %s", tc.kind, tc.kind, sub)
		}
		if len(targets) != len(tc.want) {
			t.Fatalf("kind=%s 自动枚举数量不符: %v", tc.kind, targets)
		}
		for i := range tc.want {
			if targets[i] != tc.want[i] {
				t.Fatalf("kind=%s 自动枚举结果不符: %v (期望 %v)", tc.kind, targets, tc.want)
			}
		}
	}
}

// TestScaTargetsExplicit 覆盖: 显式目标 → 单目标透传, 不触发 docker 枚举。
func TestScaTargetsExplicit(t *testing.T) {
	called := false
	prev := dockerlist.DockerRun
	dockerlist.DockerRun = func(ctx context.Context, args ...string) (string, error) {
		called = true
		return "", nil
	}
	t.Cleanup(func() { dockerlist.DockerRun = prev })
	task := NewTask("image", "nginx:1.25", Config{})
	sub, targets, err := task.scaTargets(context.Background())
	if err != nil || sub != "image" || len(targets) != 1 || targets[0] != "nginx:1.25" {
		t.Fatalf("显式目标口径不符: sub=%s targets=%v err=%v", sub, targets, err)
	}
	if called {
		t.Fatal("显式目标不应触发 docker 枚举")
	}
}

// TestScaTargetsFSEmpty 覆盖: fs(本地文件/目录)空目标必须报错 —— "扫所有目录"
// 没有意义, 与 image/container 的自动枚举口径区分。
func TestScaTargetsFSEmpty(t *testing.T) {
	task := NewTask("fs", "  ", Config{})
	if _, _, err := task.scaTargets(context.Background()); err == nil {
		t.Fatal("fs 空目标应报错")
	}
}

// TestScaTargetsDockerMissing 覆盖: 自动枚举失败(docker 未装)→ 明确报错,
// 不能静默成空列表(否则中心端会把"能力缺失"误读成"扫描无发现")。
func TestScaTargetsDockerMissing(t *testing.T) {
	withFakeDocker(t, "", dockerlist.ErrDockerNotFound)
	task := NewTask("image", scaAutoTarget, Config{})
	_, _, err := task.scaTargets(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Docker") {
		t.Fatalf("应报 docker 缺失错误, 实际: %v", err)
	}
}

// TestScaTargetsEmptyList 覆盖: docker 可用但列表为空 → 报错(任务明确失败,
// 而不是"成功扫描 0 个目标")。
func TestScaTargetsEmptyList(t *testing.T) {
	withFakeDocker(t, "", nil)
	task := NewTask("image", "", Config{})
	_, _, err := task.scaTargets(context.Background())
	if err == nil || !strings.Contains(err.Error(), "没有可扫") {
		t.Fatalf("应报 无镜像可扫 错误, 实际: %v", err)
	}
}
