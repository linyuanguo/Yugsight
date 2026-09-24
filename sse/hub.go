// Package sse SSE 实时推送中枢(任务 4.2)。
//
// 全局广播 hub, 支持多客户端(多浏览器标签/窗口)并发长连接:
//   - 扫描任务(handleScan)把每个扫描事件 Publish 到 hub,
//     所有订阅者实时收到: 扫描日志(status) / 资产发现(ip/port) / 漏洞结果(finding) / AI(ai) / 完成(done)
//   - 客户端通过 GET /api/events(SSE 长连接)订阅, 断线由浏览器 EventSource 自动重连,
//     重连时凭 Last-Event-ID 从环形缓冲区补发近期事件, 不丢最近一窗口的数据
//
// 纯标准库零第三方依赖; 慢客户端直接断开(不阻塞广播, 断开后自动重连补发)。
package sse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Event 一条 SSE 事件: ID 单调递增, Name 事件名, Data JSON 负载
type Event struct {
	ID   int64
	Name string
	Data []byte
}

const (
	// ringSize 环形缓冲大小(重连补发窗口, 条数)
	ringSize = 256
	// clientBuf 每客户端发送缓冲; 必须大于 ringSize, 否则新客户端补发占满缓冲后
	// 会被误判为慢客户端直接断开
	clientBuf = 512
	// heartbeat 心跳间隔: 发 SSE 注释行保活, 防止代理/浏览器空闲断连
	heartbeat = 15 * time.Second
)

// Hub 事件广播中枢
type Hub struct {
	mu      sync.Mutex
	clients map[chan Event]struct{}
	ring    []Event
	seq     int64
}

var defaultHub = NewHub()

// Default 返回全局单例 hub(扫描事件统一走它, 保证所有客户端收到同一事件流)
func Default() *Hub { return defaultHub }

// NewHub 创建独立 hub(测试用; 生产用全局 Hub())
func NewHub() *Hub {
	return &Hub{clients: make(map[chan Event]struct{})}
}

// Publish 向所有订阅者广播一条事件(非阻塞: 缓冲满的慢客户端被断开)。
// data 为已序列化的 JSON 字节; 空负载返回错误且不产生事件。
func (h *Hub) Publish(name string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty event data")
	}
	h.mu.Lock()
	h.seq++
	ev := Event{ID: h.seq, Name: name, Data: data}
	h.ring = append(h.ring, ev)
	if len(h.ring) > ringSize {
		h.ring = h.ring[len(h.ring)-ringSize:]
	}
	for ch := range h.clients {
		select {
		case ch <- ev:
		default:
			// 慢客户端: 断开避免队头阻塞, 浏览器会自动重连并凭 Last-Event-ID 补发
			delete(h.clients, ch)
			close(ch)
		}
	}
	h.mu.Unlock()
	return nil
}

// PublishJSON 序列化 data 后广播(Publish 的便捷封装)
func (h *Hub) PublishJSON(name string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return h.Publish(name, b)
}

// Subscribe 注册客户端: 先补发环形缓冲中 id > lastID 的事件(重连补窗口),
// 再开始接收新事件。返回事件通道与取消函数(取消后通道关闭)。
func (h *Hub) Subscribe(lastID int64) (<-chan Event, func()) {
	h.mu.Lock()
	ch := make(chan Event, clientBuf)
	h.clients[ch] = struct{}{}
	var replay []Event
	for _, ev := range h.ring {
		if ev.ID > lastID {
			replay = append(replay, ev)
		}
	}
	for _, ev := range replay {
		select {
		case ch <- ev:
		default:
		}
	}
	h.mu.Unlock()
	cancel := func() {
		h.mu.Lock()
		if _, ok := h.clients[ch]; ok {
			delete(h.clients, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
	return ch, cancel
}

// Clients 当前在线订阅者数量
func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// RingStats 环形缓冲使用量(可重连补发的事件条数)与最新事件序号。
//
// 供中心端运行状态面板的"消息队列健康"展示: ringUsed 长期 == cap 说明事件
// 产出速度超过补发窗口, 慢客户端重连时拿不到最新数据(订阅者数 >0 时值得
// 留意); lastSeq 用于判断链路是否还在推进(不增长=没有事件在广播)。
func (h *Hub) RingStats() (used, cap int, lastSeq int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.ring), ringSize, h.seq
}

// Handler 处理 SSE 长连接(GET):
//
//	retry: 3000 告诉浏览器断线 3s 后自动重连;
//	每 15s 发注释行心跳保活; 客户端断开(r.Context().Done)即释放。
func (h *Hub) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		lastID := int64(0)
		if v := r.Header.Get("Last-Event-ID"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				lastID = n
			}
		}
		ch, cancel := h.Subscribe(lastID)
		defer cancel()

		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "retry: 3000\n\n")
		fl.Flush()
		// hello 事件: 客户端连接确认 + 当前在线数(走广播, 所有客户端都能感知)
		_ = h.PublishJSON("hello", map[string]any{"clients": h.Clients(), "msg": "已接入 SSE 事件流"})

		tick := time.NewTicker(heartbeat)
		defer tick.Stop()
		for {
			select {
			case ev, ok := <-ch:
				if !ok {
					return
				}
				fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.ID, ev.Name, ev.Data)
				fl.Flush()
			case <-tick.C:
				fmt.Fprint(w, ": ping\n\n")
				fl.Flush()
			case <-r.Context().Done():
				return
			}
		}
	}
}
