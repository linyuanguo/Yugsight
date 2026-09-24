package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// icmpEchoFrame 构造一个合法的 以太网+IPv4+ICMP echo request 帧(与抓包 worker
// 送来的数据同构), 供导出契约测试注入。
func icmpEchoFrame() []byte {
	f := make([]byte, 14+20+8)
	copy(f[0:6], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) // dst MAC
	copy(f[6:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}) // src MAC
	binary.BigEndian.PutUint16(f[12:14], 0x0800)               // IPv4
	f[14] = 0x45
	binary.BigEndian.PutUint16(f[16:18], 28) // 总长 = IP 头 20 + ICMP 8
	f[23] = 64
	f[24] = 1 // ICMP
	copy(f[26:30], net.IPv4(192, 168, 1, 6).To4())
	copy(f[30:34], net.IPv4(192, 168, 1, 100).To4())
	f[34] = 8 // echo request
	return f
}

// TestCaptureExportPcap 导出端点契约:
//  1. 有报文 → 200 + 标准 pcap(魔数/链路类型/帧长/原始字节逐段核对);
//  2. 无报文 → 404 带原因(空文件对用户毫无价值, 会被误判"导出坏了")。
//
// 报文只存在于内存环形缓冲(不落盘), 这是产品的既定口径, 本测试同时锁住
// "缓冲里的帧能完整导出"这条链路(注入 → Append 拷贝 → BuildPcap → 响应)。
func TestCaptureExportPcap(t *testing.T) {
	capSess.Packets().Reset()
	defer capSess.Packets().Reset()

	frame := icmpEchoFrame()
	capSess.OnPacket(frame)

	// 1) 有报文: 完整 pcap
	w := httptest.NewRecorder()
	handleCaptureExport(w, httptest.NewRequest(http.MethodGet, "/api/capture/export?limit=2000", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("导出应 200, 实际 %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/vnd.tcpdump.pcap" {
		t.Errorf("Content-Type 应为 pcap, 实际 %q", ct)
	}
	data := w.Body.Bytes()
	if len(data) != 24+16+len(frame) {
		t.Fatalf("pcap 长度 = 24 + 16 + %d, 实际 %d", len(frame), len(data))
	}
	if binary.LittleEndian.Uint32(data[0:4]) != 0xa1b2c3d4 {
		t.Errorf("魔数错误: 0x%08x", binary.LittleEndian.Uint32(data[0:4]))
	}
	if binary.LittleEndian.Uint32(data[20:24]) != 1 {
		t.Errorf("链路类型应为 1(以太网)")
	}
	if binary.LittleEndian.Uint32(data[32:36]) != uint32(len(frame)) {
		t.Errorf("incl_len 应为 %d, 实际 %d", len(frame), binary.LittleEndian.Uint32(data[32:36]))
	}
	if !bytes.Equal(data[40:], frame) {
		t.Errorf("导出的原始帧字节与注入的不一致")
	}

	// 2) 无报文: 404
	capSess.Packets().Reset()
	w2 := httptest.NewRecorder()
	handleCaptureExport(w2, httptest.NewRequest(http.MethodGet, "/api/capture/export", nil))
	if w2.Code != http.StatusNotFound {
		t.Fatalf("空缓冲导出应 404, 实际 %d", w2.Code)
	}
	body, _ := io.ReadAll(bytes.NewReader(w2.Body.Bytes()))
	if len(body) == 0 {
		t.Errorf("404 应带原因说明")
	}
}

// TestAITestEndpointContract AI 测试端点契约:
//  1. 未填 API Base → 400;
//  2. 服务端可达 → 回带模型列表(兼容 OpenAI data[] 与 llama.cpp models[] 两种格式)。
//
// 【配置隔离】测试端点"连通即保存", 必须把 settings.json 指到临时目录,
// 否则测试会把假 apiBase 写进 exe 同目录的真实配置。
func TestAITestEndpointContract(t *testing.T) {
	dir := t.TempDir()
	setSettingsTestPath(filepath.Join(dir, "settings.json"))
	t.Cleanup(func() {
		setSettingsTestPath("")
		loadSettings() // 重新预热缓存(恢复测试前状态, 否则后续用例读到空缓存)
		initAI(false)  // 测试把假配置注进了全局分析器, 恢复为真实配置
	})

	// 1) 缺 Base
	w := httptest.NewRecorder()
	handleAITest(w, httptest.NewRequest(http.MethodPost, "/api/ai/test",
		bytes.NewReader([]byte(`{"apiBase":""}`))))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺 API Base 应 400, 实际 %d", w.Code)
	}

	// 2) llama.cpp 格式(同时带 models 与 data, 验证去重合并)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"models":[{"name":"Qwen3.8-27B-UD-Q3_K_XL.gguf"}],"data":[{"id":"Qwen3.8-27B-UD-Q3_K_XL.gguf"}]}`))
	}))
	defer srv.Close()

	w2 := httptest.NewRecorder()
	handleAITest(w2, httptest.NewRequest(http.MethodPost, "/api/ai/test",
		bytes.NewReader([]byte(`{"apiBase":"`+srv.URL+`","apiKey":"k"}`))))
	if w2.Code != http.StatusOK {
		t.Fatalf("测试端点应 200, 实际 %d: %s", w2.Code, w2.Body.String())
	}
	// 解析 models 字段: 两个来源同名去重后应只剩 1 个
	var res struct {
		Models []string `json:"models"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &res); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if len(res.Models) != 1 || res.Models[0] != "Qwen3.8-27B-UD-Q3_K_XL.gguf" {
		t.Errorf("模型列表应去重为 1 项, 实际 %v", res.Models)
	}
}

// TestAITestSavesOnlyOnSuccess "测试并保存"契约:
//  1. 连通通过 → saved=true, settings.json 的 ai 节落盘且 enabled=true;
//  2. 连通失败 → saved=false, 不写任何配置(保存一个连不通的配置, 用户会
//     以为"存了"其实用不了, 比不保存更糟)。
//
// 这是按钮语义的核心契约: 改回"无条件保存"或"测试也保存"都会静默破坏。
func TestAITestSavesOnlyOnSuccess(t *testing.T) {
	dir := t.TempDir()
	setSettingsTestPath(filepath.Join(dir, "settings.json"))
	t.Cleanup(func() {
		setSettingsTestPath("")
		loadSettings()
		initAI(false)
	})

	// 1) 可达: 保存
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"data":[{"id":"m1"}]}`))
	}))
	defer srv.Close()
	w := httptest.NewRecorder()
	handleAITest(w, httptest.NewRequest(http.MethodPost, "/api/ai/test",
		bytes.NewReader([]byte(`{"apiBase":"`+srv.URL+`","apiKey":"k","model":"m1"}`))))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, 实际 %d: %s", w.Code, w.Body.String())
	}
	var res struct {
		Saved bool `json:"saved"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if !res.Saved {
		t.Fatalf("连通通过应保存, 响应: %s", w.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		t.Fatalf("settings.json 应落盘: %v", err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		t.Fatalf("settings.json 不是合法 JSON: %v", err)
	}
	var aiSec struct {
		Enabled bool   `json:"enabled"`
		Model   string `json:"model"`
	}
	if err := json.Unmarshal(all["ai"], &aiSec); err != nil {
		t.Fatalf("ai 节应存在: %v (内容: %s)", err, string(data))
	}
	if !aiSec.Enabled || aiSec.Model != "m1" {
		t.Errorf("ai 节应 enabled=true 且 model=m1: %s", string(data))
	}

	// 2) 不可达(服务端 500): 不保存
	bad := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Error(rw, "boom", http.StatusInternalServerError)
	}))
	defer bad.Close()
	dir2 := t.TempDir()
	setSettingsTestPath(filepath.Join(dir2, "settings.json"))
	w2 := httptest.NewRecorder()
	handleAITest(w2, httptest.NewRequest(http.MethodPost, "/api/ai/test",
		bytes.NewReader([]byte(`{"apiBase":"`+bad.URL+`"}`))))
	var res2 struct {
		Saved bool `json:"saved"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &res2); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if res2.Saved {
		t.Errorf("连通失败不应保存, 响应: %s", w2.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir2, "settings.json")); !os.IsNotExist(err) {
		t.Errorf("连通失败时不应写 settings.json (err=%v)", err)
	}
}
