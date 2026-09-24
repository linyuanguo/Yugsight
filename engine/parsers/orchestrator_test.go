package parsers

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"yugsight/normalizer"
)

// fakeExec 可编程的执行器替身: 按调用序号或预设行为返回。
type fakeExec struct {
	mu       sync.Mutex
	calls    int
	stdout   []byte
	trunc    bool
	err      error
	block    time.Duration
	lastArgs []string
}

func (f *fakeExec) run(ctx context.Context, engine string, args []string) ([]byte, bool, error) {
	f.mu.Lock()
	f.calls++
	f.lastArgs = append([]string(nil), args...)
	stdout, trunc, err, block := f.stdout, f.trunc, f.err, f.block
	f.mu.Unlock()
	if block > 0 {
		select {
		case <-time.After(block):
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
	return stdout, trunc, err
}

func (f *fakeExec) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// builtinFallback 内置引擎替身: 返回固定资产/漏洞。
func builtinFallback(assets, vulns int) Runner {
	return func(ctx context.Context, req Request) (*normalizer.RawBatch, error) {
		rb := &normalizer.RawBatch{Source: normalizer.SourcePortScan}
		for i := 0; i < assets; i++ {
			rb.Assets = append(rb.Assets, normalizer.RawAsset{
				IP:    "10.9.9." + string(rune('1'+i)),
				Ports: []int{80},
			})
		}
		for i := 0; i < vulns; i++ {
			rb.Vulns = append(rb.Vulns, normalizer.RawVuln{
				AssetIP: "10.9.9.1", Port: 80, Title: "内置引擎命中", Severity: "medium",
			})
		}
		return rb, nil
	}
}

func newTestOrch(exec ExecFunc, fb Runner) *Orchestrator {
	o := NewOrchestrator(exec, fb)
	o.SetLogger(func(string) {})
	return o
}

// ===== 主链路: 引擎可用时不降级 =====

func TestOrchestratorExternalOK(t *testing.T) {
	fe := &fakeExec{stdout: []byte(trivySample)}
	o := newTestOrch(fe.run, builtinFallback(1, 1))
	o.NormalizeOpts = normalizer.Options{}

	out, err := o.Run(context.Background(), Request{Kind: "trivy", Target: "nginx:1.21"})
	if err != nil {
		t.Fatalf("主链路不应报错: %v", err)
	}
	if out.Degraded {
		t.Fatalf("引擎成功时不应降级: %+v", out)
	}
	if out.Source != normalizer.SourceTrivy {
		t.Errorf("来源应为 trivy, 实际 %s", out.Source)
	}
	if out.Result == nil || len(out.Result.Vulns) == 0 {
		t.Fatalf("应产出漏洞: %+v", out.Result)
	}
	if fe.callCount() != 1 {
		t.Errorf("应只调用外部引擎一次, 实际 %d", fe.callCount())
	}
	if st := o.Stats(); st.LastSource != normalizer.SourceTrivy || st.DegradeCount != 0 {
		t.Errorf("统计错误: %+v", st)
	}
}

// ===== 降级 1: 引擎文件缺失(执行返回错误) =====

func TestOrchestratorDegradeOnExecError(t *testing.T) {
	fe := &fakeExec{err: errors.New("引擎文件缺失: nmapcore not found")}
	o := newTestOrch(fe.run, builtinFallback(2, 1))

	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1", Ports: []int{80}})
	if err != nil {
		t.Fatalf("降级成功时不应返回错误: %v", err)
	}
	if !out.Degraded {
		t.Fatal("应标记降级")
	}
	if !strings.Contains(out.DegradeReason, "引擎执行失败") {
		t.Errorf("降级原因错误: %q", out.DegradeReason)
	}
	if out.Source != normalizer.SourcePortScan {
		t.Errorf("降级来源应为内置, 实际 %s", out.Source)
	}
	if out.Result == nil || len(out.Result.Assets) != 2 {
		t.Fatalf("应拿到内置引擎结果: %+v", out.Result)
	}
	if len(out.Warnings) == 0 {
		t.Error("应记录降级警告")
	}
	if st := o.Stats(); st.DegradeCount != 1 {
		t.Errorf("降级计数错误: %+v", st)
	}
}

// ===== 降级 2: 输出被截断 =====

func TestOrchestratorDegradeOnTruncated(t *testing.T) {
	fe := &fakeExec{stdout: []byte(`{"Results":[{"Target":"a","Vulnerab`), trunc: true}
	o := newTestOrch(fe.run, builtinFallback(1, 0))

	out, err := o.Run(context.Background(), Request{Kind: "trivy", Target: "img:1"})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if !out.Degraded || !strings.Contains(out.DegradeReason, "截断") {
		t.Fatalf("应因截断降级: %+v", out)
	}
}

// ===== 降级 3: 解析失败(非法 JSON) =====

func TestOrchestratorDegradeOnParseError(t *testing.T) {
	fe := &fakeExec{stdout: []byte("this is not json at all")}
	o := newTestOrch(fe.run, builtinFallback(1, 1))

	out, err := o.Run(context.Background(), Request{Kind: "trivy", Target: "img:1"})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if !out.Degraded || !strings.Contains(out.DegradeReason, "解析失败") {
		t.Fatalf("应因解析失败降级: %+v", out)
	}
	if out.EngineError != "" {
		t.Errorf("解析失败不应记为引擎错误: %q", out.EngineError)
	}
}

// ===== 降级 4: 引擎无输出 =====

func TestOrchestratorDegradeOnEmptyOutput(t *testing.T) {
	fe := &fakeExec{stdout: []byte("  \n ") }
	o := newTestOrch(fe.run, builtinFallback(1, 0))
	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if !out.Degraded || !strings.Contains(out.DegradeReason, "无输出") {
		t.Fatalf("应因无输出降级: %+v", out)
	}
}

// ===== 降级 5: 未配置外部引擎(如 ./bin 缺失) =====

func TestOrchestratorNoExecConfigured(t *testing.T) {
	o := newTestOrch(nil, builtinFallback(1, 0))
	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if !out.Degraded || !strings.Contains(out.DegradeReason, "未配置外部引擎") {
		t.Fatalf("应降级并说明原因: %+v", out)
	}
}

// ===== 不降级: 超时/取消(避免重复扫描) =====

func TestOrchestratorTimeoutNoDegrade(t *testing.T) {
	fe := &fakeExec{block: 500 * time.Millisecond}
	o := newTestOrch(fe.run, builtinFallback(1, 1))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	out, err := o.Run(ctx, Request{Kind: "nmap", Target: "10.0.0.1", Timeout: 100 * time.Millisecond})
	if err == nil {
		t.Fatal("超时应返回错误")
	}
	if out == nil {
		t.Fatal("超时也应返回 outcome(带引擎错误)")
	}
	if out.Degraded {
		t.Error("超时不应降级重扫")
	}
	if out.EngineError == "" {
		t.Error("应记录引擎错误")
	}
}

func TestOrchestratorCancelNoDegrade(t *testing.T) {
	fe := &fakeExec{block: 2 * time.Second}
	o := newTestOrch(fe.run, builtinFallback(1, 1))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(40 * time.Millisecond); cancel() }()
	out, err := o.Run(ctx, Request{Kind: "nmap", Target: "10.0.0.1"})
	if err == nil {
		t.Fatal("取消应返回错误")
	}
	if out == nil || out.Degraded {
		t.Fatalf("取消不应降级: %+v", out)
	}
}

// ===== 空结果不算失败(目标无开放端口是正常情况) =====

func TestOrchestratorEmptyResultNoDegrade(t *testing.T) {
	empty := `<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports/></host></nmaprun>`
	fe := &fakeExec{stdout: []byte(empty)}
	fbCalled := false
	o := newTestOrch(fe.run, func(ctx context.Context, req Request) (*normalizer.RawBatch, error) {
		fbCalled = true
		return &normalizer.RawBatch{Source: normalizer.SourcePortScan}, nil
	})
	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if out.Degraded {
		t.Error("空结果不应降级")
	}
	if fbCalled {
		t.Error("空结果不应触发内置引擎")
	}
	if out.Source != normalizer.SourceNmap {
		t.Errorf("来源应为 nmap, 实际 %s", out.Source)
	}
}

// ===== 无内置兜底: 降级但不报错(不中断主服务) =====

func TestOrchestratorNoFallbackRunner(t *testing.T) {
	fe := &fakeExec{err: errors.New("boom")}
	o := newTestOrch(fe.run, nil)
	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"})
	if err != nil {
		t.Fatalf("无兜底时也不应报错(不中断任务): %v", err)
	}
	if !out.Degraded || out.Result == nil {
		t.Fatalf("应返回空结果 + 降级标记: %+v", out)
	}
	if len(out.Result.Vulns) != 0 {
		t.Error("无兜底应返回空漏洞集")
	}
	found := false
	for _, w := range out.Warnings {
		if strings.Contains(w, "未接入") {
			found = true
		}
	}
	if !found {
		t.Errorf("应提示内置能力未接入: %v", out.Warnings)
	}
}

// ===== 内置兜底自身失败: 记录并向上返回错误 =====

func TestOrchestratorFallbackFails(t *testing.T) {
	fe := &fakeExec{err: errors.New("引擎缺失")}
	o := newTestOrch(fe.run, func(ctx context.Context, req Request) (*normalizer.RawBatch, error) {
		return nil, errors.New("内置引擎也被拒绝")
	})
	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"})
	if err == nil {
		t.Fatal("兜底失败应返回错误")
	}
	if out == nil || !out.Degraded {
		t.Fatalf("仍应返回降级 outcome: %+v", out)
	}
}

// ===== RunToStore 写库 =====

func TestOrchestratorRunToStore(t *testing.T) {
	fe := &fakeExec{stdout: []byte(nmapXMLSample)}
	o := newTestOrch(fe.run, nil)
	store := normalizer.NewStore()
	var got *normalizer.Result
	store.Set(got) // 置空, 后续由 RunToStore 覆盖

	out, err := o.RunToStore(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"}, store)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	cur := store.Get()
	if cur == nil {
		t.Fatal("结果应写入 store")
	}
	if len(cur.Assets) == 0 {
		t.Errorf("store 中应有资产: %+v", cur)
	}
	if out.Result == nil || len(out.Result.Assets) != len(cur.Assets) {
		t.Errorf("返回值与 store 不一致")
	}
}

// 降级结果同样写入 store(保证 Web / 报告有数据)
func TestOrchestratorRunToStoreDegraded(t *testing.T) {
	fe := &fakeExec{err: errors.New("缺失")}
	o := newTestOrch(fe.run, builtinFallback(1, 1))
	store := normalizer.NewStore()
	out, _ := o.RunToStore(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"}, store)
	if !out.Degraded {
		t.Fatal("应降级")
	}
	if cur := store.Get(); cur == nil || len(cur.Assets) == 0 {
		t.Fatalf("降级结果也应写入 store: %+v", cur)
	}
}

// ===== 参数组装 =====

func TestOrchestratorArgs(t *testing.T) {
	fe := &fakeExec{stdout: []byte(nmapXMLSample)}
	o := newTestOrch(fe.run, nil)
	_, _ = o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1", Ports: []int{22, 80, 443}})
	got := strings.Join(fe.lastArgs, " ")
	// -oX 落文件(而非 -oJ -): Windows nmap 的 -oJ 值会被当成目标(实测, 见 buildArgs
	// 注释); -Pn 跳过 pcap 主机发现。-oX 的值必须是 .xml 临时文件路径。
	for _, want := range []string{"-sT", "-Pn", "-oX", "22,80,443", "10.0.0.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("nmap 参数缺 %q: %s", want, got)
		}
	}
	if strings.Contains(got, "-oJ") {
		t.Errorf("nmap 参数不应含 -oJ(Windows 不可用): %s", got)
	}
	if !strings.Contains(got, ".xml") {
		t.Errorf("nmap 参数应落 .xml 报告文件: %s", got)
	}

	fe2 := &fakeExec{stdout: []byte(trivySample)}
	o2 := newTestOrch(fe2.run, nil)
	_, _ = o2.Run(context.Background(), Request{Kind: "trivy", Target: "image:nginx:1.21"})
	got2 := strings.Join(fe2.lastArgs, " ")
	if !strings.Contains(got2, "image -f json") || strings.Contains(got2, "image:nginx") {
		t.Errorf("trivy image 子命令组装错误: %s", got2)
	}

	// zap: 必须带 -cmd(否则弹 GUI 窗口) + -quickurl/-quickout(2.17 唯一可用扫描参数),
	// 且报告路径以 .json 结尾(报告类型由扩展名决定)。
	// 原断言钉的是 "-g 0", 那套参数在 ZAP 2.17 上只会打印帮助并退出 —— 实测确认。
	fe3 := &fakeExec{stdout: []byte(zapSample)}
	o3 := newTestOrch(fe3.run, nil)
	_, _ = o3.Run(context.Background(), Request{Kind: "zap", Target: "http://10.0.0.5:8080"})
	got3 := strings.Join(fe3.lastArgs, " ")
	if !strings.Contains(got3, "-cmd") {
		t.Errorf("zap 参数缺 -cmd(会导致弹窗并常驻): %s", got3)
	}
	if !strings.Contains(got3, "-quickurl") || !strings.Contains(got3, "http://10.0.0.5:8080") {
		t.Errorf("zap 参数缺 -quickurl/目标: %s", got3)
	}
	if strings.Contains(got3, "-t ") || strings.Contains(got3, "-g 0") {
		t.Errorf("zap 仍在使用 2.17 已失效的 -t/-g 参数: %s", got3)
	}
	if !strings.Contains(got3, "-quickout") || !strings.Contains(got3, ".json") {
		t.Errorf("zap 缺 -quickout 或报告非 .json: %s", got3)
	}

	// 调用方已通过 req.Args 指定 -quickout 时, 不得再补默认值(否则两个 -quickout 冲突)
	fe4 := &fakeExec{stdout: []byte(zapSample)}
	o4 := newTestOrch(fe4.run, nil)
	_, _ = o4.Run(context.Background(), Request{Kind: "zap", Target: "http://10.0.0.5:8080",
		Args: []string{"-quickout", "my-report.json"}})
	got4 := strings.Join(fe4.lastArgs, " ")
	if strings.Count(got4, "-quickout") != 1 {
		t.Errorf("-quickout 被重复添加(%d 次): %s", strings.Count(got4, "-quickout"), got4)
	}
}

// ZAP 走报告文件: 执行无 stdout, 由 ReadArtifact 提供内容
func TestOrchestratorReadArtifact(t *testing.T) {
	fe := &fakeExec{stdout: nil}
	o := newTestOrch(fe.run, nil)
	out, err := o.Run(context.Background(), Request{
		Kind: "zap", Target: "http://10.0.0.5:8080",
		ReadArtifact: func() ([]byte, error) { return []byte(zapSample), nil },
	})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if out.Degraded {
		t.Fatalf("读文件成功不应降级: %+v", out)
	}
	if len(out.Result.Vulns) == 0 {
		t.Error("应解析出漏洞")
	}
}

// 读文件失败 → 降级
func TestOrchestratorReadArtifactError(t *testing.T) {
	fe := &fakeExec{stdout: nil}
	o := newTestOrch(fe.run, builtinFallback(1, 0))
	out, err := o.Run(context.Background(), Request{
		Kind: "zap", Target: "http://10.0.0.5:8080",
		ReadArtifact: func() ([]byte, error) { return nil, errors.New("报告文件不存在") },
	})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if !out.Degraded || !strings.Contains(out.DegradeReason, "报告文件") {
		t.Fatalf("应因读报告失败降级: %+v", out)
	}
}

// 未知扫描类型: 直接返回错误(调用方参数问题, 非引擎故障)
func TestOrchestratorUnknownKind(t *testing.T) {
	o := newTestOrch(nil, nil)
	if _, err := o.Run(context.Background(), Request{Kind: "weird"}); err == nil {
		t.Fatal("未知类型应返回错误")
	}
}

// ===== 并发安全 + panic 兜底 =====

func TestOrchestratorConcurrent(t *testing.T) {
	fe := &fakeExec{stdout: []byte(nmapXMLSample)}
	o := newTestOrch(fe.run, builtinFallback(1, 1))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"}); err != nil {
				t.Errorf("并发执行失败: %v", err)
			}
		}()
	}
	wg.Wait()
	if st := o.Stats(); st.LastSource != normalizer.SourceNmap {
		t.Errorf("最后一次来源应为 nmap: %+v", st)
	}
}

// 执行函数 panic: 必须被 recover 并降级, 不崩溃主服务
func TestOrchestratorExecPanic(t *testing.T) {
	o := newTestOrch(func(ctx context.Context, engine string, args []string) ([]byte, bool, error) {
		panic("执行器内部炸了")
	}, builtinFallback(1, 0))
	out, err := o.Run(context.Background(), Request{Kind: "nmap", Target: "10.0.0.1"})
	if err != nil {
		t.Fatalf("panic 应被兜底且不报错: %v", err)
	}
	if out == nil || !out.Degraded {
		t.Fatalf("panic 应触发降级: %+v", out)
	}
}

// 归一化选项透传(ScanID 等)
func TestOrchestratorNormalizeOpts(t *testing.T) {
	fe := &fakeExec{stdout: []byte(trivySample)}
	o := newTestOrch(fe.run, nil)
	o.NormalizeOpts = normalizer.Options{ScanID: "scan-123"}
	out, err := o.Run(context.Background(), Request{Kind: "trivy", Target: "nginx:1.21"})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if out.Result == nil {
		t.Fatal("应产出结果")
	}
	if out.Result.ScanID != "scan-123" {
		t.Errorf("ScanID 未透传: %q", out.Result.ScanID)
	}
}

func TestEngineForKind(t *testing.T) {
	cases := map[string]string{
		"nmap": "nmap", "port": "nmap", "host": "nmap",
		"trivy": "trivy", "image": "trivy", "container": "trivy",
		"zap": "zap", "web": "zap", "url": "zap",
	}
	for kind, want := range cases {
		if _, got, ok := engineForKind(kind); !ok || got != want {
			t.Errorf("kind=%s 应映射为 %s, 实际 %s(ok=%v)", kind, want, got, ok)
		}
	}
	if _, _, ok := engineForKind("nope"); ok {
		t.Error("未知类型不应通过")
	}
}
