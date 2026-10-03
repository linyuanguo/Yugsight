// Package dockerlist 枚举本机 Docker 镜像 / 运行中容器(2026-09-27 SCA 自动识别)。
//
// 背景: trivy 镜像/容器扫描此前必须手工填镜像名或容器名, 用户不知道本机有哪些
// 镜像就无从填起("不写又不能扫")。trivy 本身就跑在本机(中心本地执行或探针主机),
// 所以"自动识别"不需要任何跨机通道 —— 执行方直接跑 docker images / docker ps
// 枚举本机即可。中心端(app)与探针端(internal/probe/scanner)共用本包, 保证两条
// 执行链的枚举口径一致(同样的过滤/去重/排序规则)。
package dockerlist

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// ErrDockerNotFound 本机未安装 docker(docker 命令不存在)。
// 与"docker 已装但 daemon 未启动/权限不足"区分开 —— 后者是 DockerRun 的其它错误。
var ErrDockerNotFound = errors.New("未检测到 Docker(本机没有 docker 命令)")

// DockerRun 执行一条 docker 命令并返回 stdout(测试注入点: 默认走真实 exec)。
// args 形如 ["images", "--format", "{{.Repository}}:{{.Tag}}"]。
// 返回的 error 需保留 exec 语义(LookPath 失败 → ErrDockerNotFound)。
var DockerRun = func(ctx context.Context, args ...string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", ErrDockerNotFound
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// daemon 未启动 / 权限不足等: 附上输出便于用户排错(docker 的报错在 stderr)
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return "", fmt.Errorf("docker %s 执行失败: %s", strings.Join(args, " "), firstLine(msg))
		}
		return "", fmt.Errorf("docker %s 执行失败: %v", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// ListImages 枚举本机 Docker 镜像(repo:tag 形态)。
//
// 过滤口径: <none> 占位(未打标签/悬空镜像)不可作为 trivy image 的目标
// (docker 无法按 "<none>" 定位镜像), 一律剔除; 重复项去重; 排序保证展示稳定。
func ListImages(ctx context.Context) ([]string, error) {
	out, err := DockerRun(ctx, "images", "--format", "{{.Repository}}:{{.Tag}}")
	if err != nil {
		return nil, err
	}
	return parseList(out, true), nil
}

// ListContainers 枚举本机运行中的容器(按容器名, trivy container 的目标口径)。
// 只取运行中(docker ps 默认不含已退出容器 —— 退出的容器没有可扫的运行态)。
func ListContainers(ctx context.Context) ([]string, error) {
	out, err := DockerRun(ctx, "ps", "--format", "{{.Names}}")
	if err != nil {
		return nil, err
	}
	return parseList(out, false), nil
}

// parseList 解析 docker --format 输出: 逐行 trim、去重、排序;
// dropNone 时剔除含 <none> 的项(镜像的未打标签/悬空占位)。
func parseList(out string, dropNone bool) []string {
	seen := make(map[string]bool)
	var list []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if dropNone && strings.Contains(line, "<none>") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		list = append(list, line)
	}
	sort.Strings(list)
	return list
}

// firstLine 取多行输出的首行(docker 报错首行即原因, 余下是 stack/usage 噪声)。
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
