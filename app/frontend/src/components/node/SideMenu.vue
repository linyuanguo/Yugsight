<!--
  SideMenu.vue 通用多级可缩进手风琴菜单(2026-09-28 节点监控左侧导航)。

  用法: <SideMenu :items="tree" :model-value="activeKey" storage-key="..." @select="fn" />
  树节点: { key, label, children?: [...] }

  规则:
  - 多级缩进: 每深一级 padding-left 增加 14px, 叶子节点带占位箭头保持同级标签对齐
  - 手风琴: 同一层级展开一个父级时, 收起同级其它有子级的兄弟
  - 平滑过渡: 子级容器用 grid-template-rows 0fr→1fr 动画(无需测高度)
  - 状态记忆: 展开状态持久化到 localStorage(storageKey), 刷新不丢;
    首次进入默认展开 items[0](节点监控根), 即「设备总览」所在层级
  - 激活高亮: modelValue 对应行高亮; modelValue 变化时自动展开其祖先(深链场景)
  - 父级加粗, 子级常规字重; 箭头展开向下/收起向右

  递归: SFC 按文件名自引用(Vue 3.2+)。展开状态统一提升到 depth=0 的根实例
  持有, 子层经 provide/inject 共享 —— 子层不再各自读写 localStorage(多实例
  写同一键会互相覆盖)。
-->
<template>
  <nav class="sm" :class="{ 'sm-root': depth === 0 }">
    <div v-for="node in items" :key="node.key" class="sm-item">
      <div
        class="sm-row"
        :class="{ parent: hasChildren(node), open: isOpen(node), active: modelValue === node.key }"
        :style="{ paddingLeft: (12 + depth * 14) + 'px' }"
        :title="node.label"
        @click="onClick(node)"
      >
        <span v-if="hasChildren(node)" class="sm-arrow" :class="{ open: isOpen(node) }"></span>
        <span v-else class="sm-arrow-ph"></span>
        <span class="sm-label">{{ node.label }}</span>
      </div>
      <div v-if="hasChildren(node)" class="sm-kids" :class="{ open: isOpen(node) }">
        <div class="sm-clip">
          <SideMenu :items="node.children" :model-value="modelValue" :depth="depth + 1"
                    :storage-key="storageKey" @select="onChildSelect" />
        </div>
      </div>
    </div>
  </nav>
</template>

<script setup>
import { ref, watch, provide, inject } from 'vue'

const props = defineProps({
  items: { type: Array, required: true },
  modelValue: { type: String, default: '' },
  depth: { type: Number, default: 0 },
  storageKey: { type: String, default: '' }
})
const emit = defineEmits(['select'])

const root = props.depth === 0
// 子层注入根实例的上下文(根实例自己无 ctx)
const ctx = root ? null : inject('sm_ctx')

const hasChildren = (n) => Array.isArray(n.children) && n.children.length > 0

// ===== 状态(仅根实例持有) =====
const expanded = ref({})

function defaultExpanded() {
  // 首次进入: 展开根节点(节点监控), 露出「设备总览」所在层级
  const d = {}
  if (props.items[0] && hasChildren(props.items[0])) d[props.items[0].key] = true
  return d
}

function loadState() {
  if (!props.storageKey) { expanded.value = defaultExpanded(); return }
  try {
    const raw = JSON.parse(localStorage.getItem(props.storageKey) || 'null')
    if (raw && typeof raw === 'object') expanded.value = raw
    else expanded.value = defaultExpanded()
  } catch (e) {
    expanded.value = defaultExpanded()
  }
}

function persist() {
  if (!props.storageKey) return
  try {
    localStorage.setItem(props.storageKey, JSON.stringify(expanded.value))
  } catch (e) { /* 忽略 */ }
}

// 从根到目标节点的完整路径(找不到返回 null)
function findPath(key, nodes = props.items, trail = []) {
  for (const n of nodes) {
    const t = [...trail, n]
    if (n.key === key) return t
    if (hasChildren(n)) {
      const r = findPath(key, n.children, t)
      if (r) return r
    }
  }
  return null
}

// 展开某父级(手风琴语义: 同时收起同级其它有子级的兄弟)
function openNode(node) {
  const path = findPath(node.key)
  if (path && path.length >= 2) {
    const siblings = path[path.length - 2].children
    for (const s of siblings) {
      if (s.key !== node.key && hasChildren(s)) expanded.value[s.key] = false
    }
  }
  expanded.value[node.key] = true
}

function toggle(node) {
  if (!hasChildren(node)) return
  if (expanded.value[node.key]) expanded.value[node.key] = false
  else openNode(node)
  persist()
}

// 激活项变化时自动展开其祖先(深链/刷新后从 URL 恢复的场景)
function syncActive(key) {
  if (!key) return
  const path = findPath(key)
  if (!path) return
  let changed = false
  for (const p of path) {
    if (hasChildren(p) && !expanded.value[p.key]) {
      openNode(p)
      changed = true
    }
  }
  if (changed) persist()
}

// ===== 行为(根/子层共用入口, 内部按角色分派) =====
function isOpen(node) {
  return root ? !!expanded.value[node.key] : !!ctx.expanded.value[node.key]
}
function onClick(node) {
  if (root) {
    if (hasChildren(node)) toggle(node)
    else emit('select', node.key)
    return
  }
  if (ctx.hasChildren(node)) ctx.toggle(node)
  else emit('select', node.key)   // 逐级冒泡回根实例统一 emit
}
function onChildSelect(key) { emit('select', key) }

if (root) {
  loadState()
  provide('sm_ctx', { expanded, toggle, hasChildren })
  watch(() => props.modelValue, (k) => syncActive(k), { immediate: true })
}
</script>

<style scoped>
.sm {
  display: block;
}
.sm-root {
  background: var(--panel2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 8px;
}
.sm-item { margin-bottom: 2px; }
.sm-row {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 10px; border-radius: 8px;
  font-size: 13.5px; color: var(--text);
  cursor: pointer; user-select: none;
  border: 1px solid transparent;
  transition: background .15s, color .15s, border-color .15s;
}
.sm-row:hover { background: rgba(56, 189, 248, .08); color: var(--accent); }
/* 父级加粗, 叶子常规字重(样式规范) */
.sm-row.parent { font-weight: 700; }
.sm-row.active {
  background: linear-gradient(90deg, rgba(56, 189, 248, .16), rgba(99, 102, 241, .10));
  border-color: var(--border2);
  color: var(--accent);
}
.sm-row.active .sm-label { font-weight: 600; }

/* 箭头: 右边框+下边框折成 chevron。收起=向右, 展开=向下, 带过渡 */
.sm-arrow {
  width: 7px; height: 7px; flex-shrink: 0;
  border-right: 2px solid currentColor; border-bottom: 2px solid currentColor;
  transform: rotate(-45deg) translateY(-1px);
  opacity: .65;
  transition: transform .2s ease;
}
.sm-arrow.open { transform: rotate(45deg) translateY(-2px); }
/* 叶子占位: 与箭头同宽, 让同级标签左对齐 */
.sm-arrow-ph { width: 7px; flex-shrink: 0; }

/* 子级容器: grid 0fr→1fr 实现高度平滑过渡(内容始终在 DOM 里, 只塌高度) */
.sm-kids { display: grid; grid-template-rows: 0fr; transition: grid-template-rows .22s ease; }
.sm-kids.open { grid-template-rows: 1fr; }
.sm-clip { overflow: hidden; min-height: 0; }
</style>
