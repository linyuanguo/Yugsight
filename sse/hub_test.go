package sse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 多客户端并发接收同一条广播
func TestHubBroadcast(t *testing.T) {
	h := NewHub()
	ch1, c1 := h.Subscribe(0)
	ch2, c2 := h.Subscribe(0)
	defer c1()
	defer c2()

	if err := h.PublishJSON("status", map[string]string{"msg": "hi"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	for i, ch := range []<-chan Event{ch1, ch2} {
		select {
		case ev := <-ch:
			if ev.Name != "status" || ev.ID != 1 {
				t.Fatalf("client %d: got %+v", i, ev)
			}
		case <-time.After(time.Second):
			t.Fatalf("client %d: 未收到广播", i)
		}
	}
	if h.Clients() != 2 {
		t.Fatalf("clients = %d, want 2", h.Clients())
	}
}

// 重连补发: Last-Event-ID 之后的事件从环形缓冲补发
func TestHubReplay(t *testing.T) {
	h := NewHub()
	for i := 1; i <= 3; i++ {
		if err := h.PublishJSON("e", map[string]int{"i": i}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	ch, cancel := h.Subscribe(2) // 只补发 id>2
	defer cancel()
	select {
	case ev := <-ch:
		if ev.ID != 3 {
			t.Fatalf("replay id = %d, want 3", ev.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到补发事件")
	}
}

// 环形缓冲上限: 超出 ringSize 的旧事件不再补发
func TestHubRingBound(t *testing.T) {
	h := NewHub()
	for i := 0; i < ringSize+10; i++ {
		if err := h.PublishJSON("e", map[string]int{}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	ch, cancel := h.Subscribe(0)
	defer cancel()
	var n int
	deadline := time.After(time.Second)
	for {
		select {
		case <-ch:
			n++
		case <-deadline:
			if n != ringSize {
				t.Fatalf("replay 数 = %d, want %d", n, ringSize)
			}
			return
		}
	}
}

// RingStats 反映补发窗口使用量与最新序号(中心端运行状态面板的"消息队列健康")
func TestHubRingStats(t *testing.T) {
	h := NewHub()
	if used, cap, seq := h.RingStats(); used != 0 || cap != ringSize || seq != 0 {
		t.Fatalf("初始状态异常: used=%d cap=%d seq=%d", used, cap, seq)
	}
	for i := 1; i <= 3; i++ {
		if err := h.PublishJSON("e", map[string]int{"i": i}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	if used, cap, seq := h.RingStats(); used != 3 || cap != ringSize || seq != 3 {
		t.Fatalf("异常: used=%d cap=%d seq=%d", used, cap, seq)
	}
}

// 慢客户端(从不读通道)被断开, 不影响后续新客户端
func TestHubSlowClientDropped(t *testing.T) {
	h := NewHub()
	_, cancelStuck := h.Subscribe(0) // 慢客户端: 注册后从不读取通道
	defer cancelStuck()

	// 灌满慢客户端缓冲(clientBuf)后再发, 慢客户端应被断开
	dropped := false
	for i := 0; i < clientBuf+5 && !dropped; i++ {
		_ = h.PublishJSON("e", map[string]int{"i": i})
		dropped = h.Clients() == 0
	}
	if !dropped {
		t.Fatal("慢客户端未被断开")
	}
	// 之后新订阅的客户端仍能收到广播(不回放旧事件: lastID 取超大值)
	ch, cancel := h.Subscribe(1 << 62)
	defer cancel()
	_ = h.PublishJSON("status", map[string]string{"msg": "ok"})
	select {
	case ev := <-ch:
		if ev.Name != "status" {
			t.Fatalf("got %s", ev.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("正常客户端未收到事件")
	}
}

// SSE 端点: 同步执行 handler(短超时让长连接自然结束), 验证 SSE 头/retry/hello 事件格式
func TestHandlerStreams(t *testing.T) {
	h := NewHub()
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	h.Handler()(rec, req) // 阻塞到 ctx 超时后返回, 无并发, 可直接读响应

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %s", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "retry: 3000") {
		t.Fatalf("缺 retry 指令: %q", body)
	}
	if !strings.Contains(body, "event: hello") {
		t.Fatalf("缺 hello 事件: %q", body)
	}
}

// SSE 端点: 新连接时从环形缓冲补发之前的事件(重连不丢窗口)
func TestHandlerReplayOnConnect(t *testing.T) {
	h := NewHub()
	if err := h.PublishJSON("finding", map[string]string{"title": "历史漏洞"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	h.Handler()(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "event: finding") {
		t.Fatalf("未补发历史事件: %q", body)
	}
	if !strings.Contains(body, "event: hello") {
		t.Fatalf("缺 hello 事件: %q", body)
	}
}

// 非 GET 拒绝
func TestHandlerMethod(t *testing.T) {
	h := NewHub()
	rec := httptest.NewRecorder()
	h.Handler()(rec, httptest.NewRequest(http.MethodPost, "/api/events", strings.NewReader("{}")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
