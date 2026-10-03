<!--
  AssistantWidget.vue 小 Y 问答助手悬浮组件(2026-09-27)。

  形态: 右下角固定悬浮圆形图标(可拖拽调位, 位置持久化 localStorage) +
  点击展开的侧边问答面板。挂载在 Layout.vue 根节点(登录页不套 Layout,
  登录页自然无助手)。

  行为:
    - 总开关关闭(effective=false)时全局隐藏(30s 轮询状态, 管理员开启后
      其它用户页面无需刷新自动出现);
    - 新消息到达且面板收起时, 图标呼吸灯提示(breathe);
    - "清空对话"只清空面板内聊天记录回到欢迎态 —— 不动后端会话上下文、
      不关面板(任务书口径);
    - 页面上下文: 路由变化自动上报(POST /api/v1/ai/context), 提问时
      collectContext() 实时采集随请求覆盖传参(用户无感知)。

  零第三方依赖: Markdown 渲染用本地 md.js, 流式读取用 fetch + ReadableStream
  (POST 不能走 EventSource, 自己解析 SSE 文本)。
-->
<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api/http'
import { collectContext, quickQuestions } from '../assistant/context'
import { md } from '../assistant/md'

const route = useRoute()

// ctxName 面板标题下的"当前页面"提示(随路由切换更新, 让用户一眼看到
// 小 Y 答的是哪个页面的数据)
const ctxName = computed(() => {
  const c = collectContext()
  return c.pageName || c.pageType
})

// ===== 状态: 显隐依据(effective = 全局 AI 开 && 小 Y 开) =====
const st = ref(null)
let statusTimer = null
async function loadStatus() {
  try {
    st.value = await api('/api/v1/ai/assistant')
  } catch {
    st.value = null // 未登录/异常: 隐藏, 不影响页面
  }
}

// ===== 面板与对话 =====
const visible = ref(false)
const msgs = ref([]) // [{role:'user'|'ai', text, html, pending}]
const input = ref('')
const sending = ref(false)
const hasNew = ref(false) // 面板收起时新消息到达 → 图标呼吸灯
const msgsEl = ref(null)

const quicks = computed(() => quickQuestions().slice(0, 3))

function togglePanel() {
  visible.value = !visible.value
  if (visible.value) {
    hasNew.value = false
    nextTick(scrollBottom)
  }
}

// 清空对话: 只清面板聊天记录回欢迎态 —— 不动后端会话上下文, 不关面板
function clearMsgs() {
  msgs.value = []
  hasNew.value = false
}

function scrollBottom() {
  if (msgsEl.value) msgsEl.value.scrollTop = msgsEl.value.scrollHeight
}

// 路由变化 → 自动上报最新页面上下文(静默, 失败不阻塞)
function reportContext() {
  if (!(st.value && st.value.effective)) return
  try {
    api('/api/v1/ai/context', { method: 'POST', body: collectContext() }).catch(() => {})
  } catch { /* 忽略 */ }
}

// ===== 问答(SSE 流式) =====
async function send(q) {
  q = String(q || '').trim()
  if (!q || sending.value) return
  input.value = ''
  if (visible.value) hasNew.value = false
  msgs.value.push({ role: 'user', text: q, html: '' })
  const aiMsg = { role: 'ai', text: '', html: '', pending: true }
  msgs.value.push(aiMsg)
  sending.value = true
  nextTick(scrollBottom)

  const ctx = collectContext() // 提问时实时采集(覆盖传参, 优先于暂存值)
  let streamErr = null
  try {
    const r = await fetch('/api/v1/ai/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        question: q,
        pageType: ctx.pageType,
        pageName: ctx.pageName,
        query: ctx.query,
        params: ctx.params,
        data: ctx.data
      })
    })
    if (!r.ok || !r.body) {
      const t = await r.text()
      streamErr = 'HTTP ' + r.status + (t ? ' ' + t.slice(0, 200) : '')
    } else {
      await readSSE(r, aiMsg)
    }
  } catch (e) {
    streamErr = e.message
  }
  if (streamErr && !aiMsg.text) {
    aiMsg.text = '请求失败: ' + streamErr
    aiMsg.html = md(aiMsg.text)
  }
  aiMsg.pending = false
  sending.value = false
  if (!visible.value) hasNew.value = true // 收起状态收到回答 → 呼吸灯
  nextTick(scrollBottom)
}

// readSSE 从 fetch 响应流里解析 SSE 事件(delta/done/error)。
async function readSSE(r, aiMsg) {
  const reader = r.body.getReader()
  const dec = new TextDecoder()
  let buf = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buf += dec.decode(value, { stream: true })
    let idx
    while ((idx = buf.indexOf('\n\n')) >= 0) {
      const raw = buf.slice(0, idx)
      buf = buf.slice(idx + 2)
      let event = 'message'
      let data = ''
      for (const line of raw.split('\n')) {
        if (line.startsWith('event:')) event = line.slice(6).trim()
        else if (line.startsWith('data:')) data += line.slice(5).trim()
      }
      if (!data) continue
      let p
      try { p = JSON.parse(data) } catch { continue }
      if (event === 'delta') {
        aiMsg.text += p.t || ''
        aiMsg.html = md(aiMsg.text)
        nextTick(scrollBottom)
      } else if (event === 'done') {
        if (p.full) aiMsg.text = p.full
        aiMsg.html = md(aiMsg.text)
      } else if (event === 'error') {
        aiMsg.text = (aiMsg.text ? aiMsg.text + '\n' : '') + '请求出错: ' + (p.error || '未知错误')
        aiMsg.html = md(aiMsg.text)
      }
    }
  }
}

// ===== 图标拖拽(位置持久化; 移动 <4px 视为点击 → 展开/收起) =====
const FAB = 52
const pos = ref({ x: 0, y: 0 })
let dragState = null

function initPos() {
  let p = null
  try { p = JSON.parse(localStorage.getItem('ys_xy_pos')) } catch { /* 忽略 */ }
  if (p && typeof p.x === 'number' && typeof p.y === 'number') {
    pos.value = clampPos(p)
  } else {
    pos.value = { x: window.innerWidth - FAB - 20, y: window.innerHeight - FAB - 28 }
  }
}
function clampPos(p) {
  return {
    x: Math.max(8, Math.min(p.x, window.innerWidth - FAB - 8)),
    y: Math.max(8, Math.min(p.y, window.innerHeight - FAB - 8))
  }
}
function savePos() {
  try { localStorage.setItem('ys_xy_pos', JSON.stringify(pos.value)) } catch { /* 忽略 */ }
}
function startDrag(e) {
  if (e.button !== 0) return
  e.preventDefault()
  const sx = e.clientX, sy = e.clientY
  const orig = { ...pos.value }
  let moved = false
  function mv(ev) {
    const dx = ev.clientX - sx, dy = ev.clientY - sy
    if (Math.abs(dx) + Math.abs(dy) > 4) moved = true
    if (moved) pos.value = clampPos({ x: orig.x + dx, y: orig.y + dy })
  }
  function up() {
    document.removeEventListener('mousemove', mv)
    document.removeEventListener('mouseup', up)
    dragState = null
    savePos()
    if (!moved) togglePanel() // 没拖动 = 点击
  }
  dragState = { moved }
  document.addEventListener('mousemove', mv)
  document.addEventListener('mouseup', up)
}

// 窗口尺寸变化时把图标/面板钳回可视区
function onResize() {
  pos.value = clampPos(pos.value)
}

const fabStyle = computed(() => ({ left: pos.value.x + 'px', top: pos.value.y + 'px' }))
// 面板锚在图标左上方(随拖拽位置移动)
const panelStyle = computed(() => ({
  bottom: Math.max(12, window.innerHeight - pos.value.y + 10) + 'px',
  right: Math.max(12, window.innerWidth - pos.value.x - 64) + 'px'
}))

onMounted(async () => {
  initPos()
  await loadStatus()
  statusTimer = setInterval(loadStatus, 30000) // 30s 轮询开关状态
  window.addEventListener('resize', onResize)
  reportContext()
})
onBeforeUnmount(() => {
  if (statusTimer) clearInterval(statusTimer)
  window.removeEventListener('resize', onResize)
})
// 路由变化: 上报上下文 + 快捷提问随页面切换
watch(() => route.fullPath, () => {
  reportContext()
  if (visible.value) nextTick(scrollBottom)
})
</script>

<template>
  <!-- effective=false(总开关关/未登录/异常)时整个组件不渲染 -->
  <template v-if="st && st.effective">
    <!-- 悬浮图标: 圆形 + 简笔笑脸(CSS 画, 无图片资源) -->
    <div
      class="xy-fab"
      :class="{ breathe: hasNew && !visible, open: visible, dragging: !!dragState && dragState.moved }"
      :style="fabStyle"
      title="小 Y 助手(点击展开, 按住拖拽)"
      @mousedown="startDrag"
    >
      <span class="xy-face">
        <span class="xy-eye"></span><span class="xy-eye"></span>
        <span class="xy-mouth"></span>
      </span>
      <span class="xy-fab-badge" v-if="hasNew && !visible">1</span>
      <span class="xy-fab-tip">小Y</span>
    </div>

    <!-- 问答面板 -->
    <div class="xy-panel" v-show="visible" :style="panelStyle">
      <div class="xy-phead">
        <div class="xy-ident">
          <span class="xy-mini-face">
            <span class="xy-eye"></span><span class="xy-eye"></span><span class="xy-mouth"></span>
          </span>
          <div>
            <div class="xy-title">小 Y 助手</div>
            <div class="xy-sub mono">{{ ctxName }}</div>
          </div>
        </div>
        <div class="xy-pops">
          <button class="xy-op" title="清空对话(仅清空面板记录, 不影响页面上下文)" @click="clearMsgs">清空对话</button>
          <button class="xy-op" title="收起面板" @click="visible = false">收起</button>
        </div>
      </div>

      <div class="xy-msgs" ref="msgsEl">
        <div class="xy-welcome" v-if="!msgs.length">
          <p>你好, 我是小 Y。</p>
          <p>我可以基于你<b>当前页面的数据</b>回答运维问题(漏洞统计 / 节点状态 / 扫描任务等), 点下面的快捷提问试试, 或直接输入问题。</p>
        </div>
        <div class="xy-msg" v-for="(m, i) in msgs" :key="i" :class="'xy-' + m.role">
          <div class="xy-bubble" :class="{ pending: m.pending }" v-if="m.role === 'ai'" v-html="m.html || (m.pending ? '小 Y 正在思考…' : '')"></div>
          <div class="xy-bubble" v-else>{{ m.text }}</div>
        </div>
      </div>

      <!-- 场景化快捷提问(按当前页面推荐) -->
      <div class="xy-quick" v-if="!sending">
        <button class="xy-q" v-for="q in quicks" :key="q" @click="send(q)">{{ q }}</button>
      </div>

      <div class="xy-inputrow">
        <input
          class="xy-input"
          v-model="input"
          :disabled="sending"
          placeholder="问小 Y 关于当前页面的问题…(Enter 发送)"
          @keyup.enter="send(input)"
        />
        <button class="xy-send" :disabled="sending || !input.trim()" @click="send(input)">
          <span class="spinner" v-if="sending"></span> 发送
        </button>
      </div>
    </div>
  </template>
</template>

<style scoped>
/* ===== 悬浮图标 ===== */
.xy-fab {
  position: fixed;
  z-index: 2000;
  width: 52px;
  height: 52px;
  border-radius: 50%;
  background: linear-gradient(135deg, #4c8dff, #7aa2f7);
  box-shadow: 0 4px 14px rgba(76, 141, 255, 0.45);
  cursor: pointer;
  user-select: none;
  transition: transform 0.15s;
  touch-action: none;
}
.xy-fab:hover { transform: scale(1.06); }
.xy-fab.dragging { cursor: grabbing; transform: scale(1.02); }
.xy-fab.open { box-shadow: 0 4px 18px rgba(76, 141, 255, 0.65); }
/* 新消息呼吸灯(面板收起时) */
.xy-fab.breathe { animation: xyBreathe 1.6s ease-in-out infinite; }
@keyframes xyBreathe {
  0%, 100% { box-shadow: 0 4px 14px rgba(76, 141, 255, 0.45); }
  50% { box-shadow: 0 4px 26px rgba(76, 141, 255, 0.95); transform: scale(1.07); }
}
.xy-face {
  position: relative;
  display: block;
  width: 34px;
  height: 34px;
  margin: 9px auto 0;
}
.xy-eye {
  position: absolute;
  top: 10px;
  width: 5px;
  height: 7px;
  border-radius: 3px;
  background: #fff;
}
.xy-eye:first-child { left: 9px; }
.xy-eye:nth-child(2) { right: 9px; }
.xy-mouth {
  position: absolute;
  left: 10px;
  top: 18px;
  width: 14px;
  height: 7px;
  border-bottom: 2.5px solid #fff;
  border-radius: 0 0 12px 12px;
}
.xy-fab-badge {
  position: absolute;
  top: -3px;
  right: -3px;
  min-width: 17px;
  height: 17px;
  padding: 0 4px;
  border-radius: 9px;
  background: #e5484d;
  color: #fff;
  font-size: 11px;
  line-height: 17px;
  text-align: center;
}
.xy-fab-tip {
  position: absolute;
  top: 100%;
  left: 50%;
  transform: translateX(-50%);
  margin-top: 4px;
  font-size: 11px;
  color: #cfe0ff;
  text-shadow: 0 1px 3px rgba(0, 0, 0, 0.6);
  white-space: nowrap;
}

/* ===== 问答面板 ===== */
.xy-panel {
  position: fixed;
  z-index: 1999;
  width: 380px;
  max-width: calc(100vw - 24px);
  height: 560px;
  max-height: calc(100vh - 40px);
  display: flex;
  flex-direction: column;
  background: var(--bg2, #101318);
  border: 1px solid var(--border, #232833);
  border-radius: 12px;
  box-shadow: 0 10px 34px rgba(0, 0, 0, 0.5);
}
.xy-phead {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border, #232833);
}
.xy-ident { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; }
.xy-mini-face {
  position: relative;
  display: inline-block;
  width: 26px;
  height: 26px;
  border-radius: 50%;
  background: linear-gradient(135deg, #4c8dff, #7aa2f7);
  flex: none;
}
.xy-mini-face .xy-eye { top: 8px; width: 3.5px; height: 5px; }
.xy-mini-face .xy-eye:first-child { left: 7px; }
.xy-mini-face .xy-eye:nth-child(2) { right: 7px; }
.xy-mini-face .xy-mouth { left: 8px; top: 14px; width: 10px; height: 5px; border-bottom-width: 2px; }
.xy-title { font-size: 13px; font-weight: 600; color: var(--text, #d7dbe0); }
.xy-sub { font-size: 11px; color: var(--muted, #8b93a7); }
.xy-pops { display: flex; gap: 6px; flex: none; }
.xy-op {
  background: transparent;
  border: 1px solid var(--border, #232833);
  border-radius: 6px;
  color: var(--muted, #8b93a7);
  font-size: 11px;
  padding: 3px 8px;
  cursor: pointer;
}
.xy-op:hover { color: var(--text, #d7dbe0); border-color: #3a4150; }

.xy-msgs {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.xy-welcome {
  font-size: 12.5px;
  color: var(--muted, #8b93a7);
  line-height: 1.7;
  padding: 6px 2px;
}
.xy-welcome p { margin: 0 0 8px; }
.xy-msg { display: flex; }
.xy-user { justify-content: flex-end; }
.xy-ai { justify-content: flex-start; }
.xy-bubble {
  max-width: 88%;
  padding: 8px 11px;
  border-radius: 10px;
  font-size: 13px;
  line-height: 1.65;
  word-break: break-word;
}
.xy-user .xy-bubble {
  background: rgba(76, 141, 255, 0.18);
  border: 1px solid rgba(76, 141, 255, 0.35);
  color: var(--text, #d7dbe0);
  white-space: pre-wrap;
}
.xy-ai .xy-bubble {
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid var(--border, #232833);
  color: var(--text, #d7dbe0);
}
.xy-ai .xy-bubble.pending { color: var(--muted, #8b93a7); }

/* Markdown 渲染产物(md.js 输出的类名) */
:deep(.xy-p) { margin: 0 0 8px; }
:deep(.xy-p:last-child) { margin-bottom: 0; }
:deep(.xy-h) { margin: 10px 0 6px; font-size: 13.5px; font-weight: 600; }
:deep(.xy-ul), :deep(.xy-ol) { margin: 4px 0 8px; padding-left: 18px; }
:deep(.xy-ul li), :deep(.xy-ol li) { margin: 2px 0; }
:deep(.xy-code) {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px;
  background: rgba(122, 162, 247, 0.12);
  border-radius: 3px;
  padding: 1px 4px;
}
:deep(.xy-pre) {
  margin: 6px 0;
  padding: 8px 10px;
  background: #0a0c10;
  border: 1px solid var(--border, #232833);
  border-radius: 6px;
  overflow-x: auto;
  font-size: 12px;
}
:deep(.xy-pre code) { font-family: ui-monospace, Consolas, monospace; white-space: pre; }

.xy-quick {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 8px 12px 0;
}
.xy-q {
  background: rgba(76, 141, 255, 0.08);
  border: 1px solid rgba(76, 141, 255, 0.3);
  color: #9db9f5;
  border-radius: 14px;
  font-size: 11.5px;
  padding: 4px 10px;
  cursor: pointer;
}
.xy-q:hover { background: rgba(76, 141, 255, 0.18); color: #cfe0ff; }

.xy-inputrow {
  display: flex;
  gap: 8px;
  padding: 10px 12px;
  border-top: 1px solid var(--border, #232833);
}
.xy-input {
  flex: 1;
  min-width: 0;
  background: var(--bg, #0b0e13);
  border: 1px solid var(--border, #232833);
  border-radius: 8px;
  color: var(--text, #d7dbe0);
  font-size: 13px;
  padding: 8px 10px;
  outline: none;
}
.xy-input:focus { border-color: #4c8dff; }
.xy-input:disabled { opacity: 0.6; }
.xy-send {
  flex: none;
  background: #4c8dff;
  border: 0;
  border-radius: 8px;
  color: #fff;
  font-size: 13px;
  padding: 8px 14px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
}
.xy-send:disabled { opacity: 0.5; cursor: default; }
</style>
