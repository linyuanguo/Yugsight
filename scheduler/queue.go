package scheduler

import (
	"sort"
	"sync"
)

// ===== 任务队列 =====
//
// 数据结构选择: 排序切片而非 container/heap。
//
//	队列长度在运维场景是"百级"(同时间内提交的扫描任务不会上万), 切片插入
//	O(n) 完全够用; 换来的是 Pick 能按"优先级 + 节点亲和"做任意筛选, 而
//	container/heap 只支持"取堆顶", 无法跳过"堆顶任务的节点已满"继续找下一个
//	可用任务 —— 那会导致队头阻塞(head-of-line blocking): 一个大网段任务把
//	所有并发槽位占满后, 后面针对空闲节点的任务也全部干等。
type queue struct {
	mu    sync.Mutex
	items []*Task
}

func newQueue() *queue { return &queue{} }

// Push 入队(按优先级 + 提交时间插入到有序位置)。
//
// 排序键: Priority 升序 -> QueueAt 升序(同优先级先到先服务)。
// 不做"优先级抢占": 已运行的任务不会因为来了更高优先级的任务被打断 ——
// 扫描被打断意味着结果不完整, 代价远大于等一会儿。
func (q *queue) Push(t *Task) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if t.QueueAt.IsZero() {
		t.QueueAt = t.CreatedAt
	}
	q.items = append(q.items, t)
	sort.SliceStable(q.items, func(i, j int) bool {
		if q.items[i].Priority != q.items[j].Priority {
			return q.items[i].Priority < q.items[j].Priority
		}
		return q.items[i].QueueAt.Before(q.items[j].QueueAt)
	})
}

// Pick 取出首个满足 accept 条件的任务(不满足的保留在队列中)。
//
// accept 用于判定"该任务的执行节点当前是否还有空闲槽位":
//
//	本地任务  -> 全局并发是否已满
//	探针任务  -> 全局并发 + 该探针并发是否都已开
//
// 这是"分布式探针适配 + 队头阻塞规避"的核心: 找不到可执行任务时返回 nil,
// 调度循环等下一次事件(任务完成/节点状态变化)再试。
func (q *queue) Pick(accept func(*Task) bool) *Task {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, t := range q.items {
		if accept(t) {
			q.items = append(q.items[:i], q.items[i+1:]...)
			return t
		}
	}
	return nil
}

// Remove 从队列中摘除任务(取消操作; 返回是否摘到)。
func (q *queue) Remove(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, t := range q.items {
		if t.ID == id {
			q.items = append(q.items[:i], q.items[i+1:]...)
			return true
		}
	}
	return false
}

// Snapshot 队列快照(按当前调度顺序)。
func (q *queue) Snapshot() []*Task {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*Task, len(q.items))
	copy(out, q.items)
	return out
}

// Len 队列长度。
func (q *queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
