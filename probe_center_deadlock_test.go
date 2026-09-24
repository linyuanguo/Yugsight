package main

// 回归测试: 探针中心端启用时, 启动装配(instanceProbe -> startCenter ->
// setupAgentAutoUpdate)不得死锁。
//
// 守护的 bug: setupAgentAutoUpdate 曾用 probeEnabled() 做守卫, 而 probeEnabled
// 走 registerProbeOnce -> instanceProbe, 在 instanceProbe 自己的 probeOnce.Do
// 闭包内对同一个 sync.Once 二次 Do —— sync.Once 不可重入, 同 goroutine 二次 Do
// 永久阻塞, 主程序启动后卡在"探针中心端已启动", Web 服务起不来(浏览器不弹页面)。
// 用超时守卫断言: 若未来再次引入重入, 本测试会在 10s 后失败而不是"看起来通过"。
//
// 为什么先重置探针全局单例: 全量跑时, 本包其它用例(如 TestProbeHelpersNoSideEffect)
// 可能已用"空配置"消费过 probeOnce, 届时本测试的 instanceProbe 会直接短路, 根本
// 走不到 startCenter —— 回归守护形同虚设。先换成全新 Once + 空配置, 保证每次都
// 真实走完整装配路径(与 schedAPITestMode 处理 schedOnce 是同一手法)。
import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestProbeCenterStartupNoDeadlock(t *testing.T) {
	// 保存并重置探针单例, 结束后恢复(不影响其它用例)
	prevOnce, prevCfg, prevCenter, prevClient, prevRecorder := probeOnce, probeCfg, probeCenter, probeClient, probeRecorder
	probeOnce, probeCfg, probeCenter, probeClient, probeRecorder = &sync.Once{}, ProbeConfig{}, nil, nil, nil
	t.Cleanup(func() {
		stopProbe()
		probeOnce, probeCfg, probeCenter, probeClient, probeRecorder = prevOnce, prevCfg, prevCenter, prevClient, prevRecorder
	})

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// loadProbeConfig 从 exe 同目录读 probe.json, 测试二进制在临时目录, 需自己放一份
	// (内容对齐 dist/probe.json, 端口换成 18600 避免与其它测试/本机服务冲突)
	probeJSON := filepath.Join(filepath.Dir(exe), "probe.json")
	if err := os.WriteFile(probeJSON,
		[]byte(`{"center":{"enabled":true,"listen":":18600","token":"verify-token-e2e","heartbeatSec":5,"offlineSec":30},"client":{"enabled":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(probeJSON) })

	done := make(chan struct{})
	go func() {
		instanceProbe()
		instanceScheduler()
		close(done)
	}()
	select {
	case <-done:
		// 装配完成; 中心端由 Cleanup 的 stopProbe 关闭
	case <-time.After(10 * time.Second):
		t.Fatal("启动装配 10s 未完成: instanceProbe/startCenter 路径存在重入死锁(见文件头说明)")
	}
}
