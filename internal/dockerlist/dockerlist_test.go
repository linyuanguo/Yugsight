package dockerlist

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// withFakeDocker 注入假 DockerRun 并保证恢复(测试间互不污染)。
func withFakeDocker(t *testing.T, fake func(ctx context.Context, args ...string) (string, error)) {
	t.Helper()
	prev := DockerRun
	DockerRun = fake
	t.Cleanup(func() { DockerRun = prev })
}

// TestListImages 覆盖: 正常枚举 + <none> 占位剔除 + 去重 + 排序。
func TestListImages(t *testing.T) {
	withFakeDocker(t, func(ctx context.Context, args ...string) (string, error) {
		if len(args) == 0 || args[0] != "images" {
			t.Fatalf("应执行 docker images, 实际 %v", args)
		}
		return "nginx:1.25-alpine\n<none>:<none>\nredis:7\nnginx:1.25-alpine\nlibrary/nginx:1.25\n\n", nil
	})
	list, err := ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages 不应报错: %v", err)
	}
	want := []string{"library/nginx:1.25", "nginx:1.25-alpine", "redis:7"}
	if strings.Join(list, "|") != strings.Join(want, "|") {
		t.Fatalf("枚举结果不符(应去重/剔除<none>/排序): %v", list)
	}
}

// TestListContainers 覆盖: 只回传容器名, 去重排序。
func TestListContainers(t *testing.T) {
	withFakeDocker(t, func(ctx context.Context, args ...string) (string, error) {
		if len(args) == 0 || args[0] != "ps" {
			t.Fatalf("应执行 docker ps, 实际 %v", args)
		}
		return "web-1\nweb-1\ndb-1\n", nil
	})
	list, err := ListContainers(context.Background())
	if err != nil {
		t.Fatalf("ListContainers 不应报错: %v", err)
	}
	if len(list) != 2 || list[0] != "db-1" || list[1] != "web-1" {
		t.Fatalf("容器列表不符: %v", list)
	}
}

// TestListImagesDockerMissing 覆盖: 未安装 docker 时返回 ErrDockerNotFound(明确原因,
// 而不是静默空列表 —— 空列表会被上层误读成"没有镜像"而漏报)。
func TestListImagesDockerMissing(t *testing.T) {
	withFakeDocker(t, func(ctx context.Context, args ...string) (string, error) {
		return "", ErrDockerNotFound
	})
	if _, err := ListImages(context.Background()); !errors.Is(err, ErrDockerNotFound) {
		t.Fatalf("应返回 ErrDockerNotFound, 实际 %v", err)
	}
}

// TestListImagesDaemonDown 覆盖: daemon 未启动等执行失败 —— 错误要带 docker 首行原因。
func TestListImagesDaemonDown(t *testing.T) {
	withFakeDocker(t, func(ctx context.Context, args ...string) (string, error) {
		return "", errors.New("docker images 执行失败: Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
	})
	_, err := ListImages(context.Background())
	if err == nil || !strings.Contains(err.Error(), "daemon") {
		t.Fatalf("错误应包含 docker 原因, 实际 %v", err)
	}
}

// TestParseList 覆盖纯解析逻辑(不依赖 exec)。
func TestParseList(t *testing.T) {
	got := parseList("  a:1 \n\nb:2\na:1\n<none>:x\nc:3\n", true)
	if len(got) != 3 || got[0] != "a:1" || got[1] != "b:2" || got[2] != "c:3" {
		t.Fatalf("dropNone 解析不符: %v", got)
	}
	// 不剔 <none> 时: 全部保留, 排序按 ASCII 序("<" 在字母前)
	got2 := parseList("a:1\n<none>:x\n", false)
	if len(got2) != 2 || got2[0] != "<none>:x" || got2[1] != "a:1" {
		t.Fatalf("不剔 <none> 时解析不符: %v", got2)
	}
}
