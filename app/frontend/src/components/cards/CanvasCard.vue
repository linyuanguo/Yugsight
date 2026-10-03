<template>
  <!-- 通用 3D 立体卡片(2026-09-27 安全大屏 Pro 卡片体系):
       正反面翻转 + 自由拖拽 + 四角无级缩放 + 层级调整 + 右键菜单。
       几何(x/y/w/h/z/flipped)由父页(画布)持有, 本组件只渲染外壳与交互;
       正/背内容经 #front / #back 插槽注入(按卡片类型渲染对应内容组件)。 -->
  <!-- data-cid: 供画布层框选/批量操作按 DOM 反查卡片 id(编辑模式的框选在父组件实现,
       需要知道指针落在哪张卡上; 用属性而非索引, 避免顺序变化时错位) -->
  <div class="cc" :data-cid="card.id" :class="[mode, { sel: selected, flipped: card.flipped }]"
       :style="cardStyle" @pointerdown="onDown" @click="onClick" @contextmenu.prevent="onContext">
    <!-- 3D 翻转内层(手柄/菜单在卡片坐标系内, 不参与翻转) -->
    <div class="cc-inner" :class="{ flip: card.flipped }">
      <div class="cc-face cc-front"><slot name="front"></slot></div>
      <div class="cc-face cc-back"><slot name="back"></slot></div>
    </div>

    <!-- 编辑态: 四角缩放手柄 + 顶部拖拽锚点(浏览态全部隐藏) -->
    <template v-if="mode === 'edit'">
      <span class="cc-handle nw" @pointerdown.stop="onResizeStart('nw', $event)"></span>
      <span class="cc-handle ne" @pointerdown.stop="onResizeStart('ne', $event)"></span>
      <span class="cc-handle sw" @pointerdown.stop="onResizeStart('sw', $event)"></span>
      <span class="cc-handle se" @pointerdown.stop="onResizeStart('se', $event)"></span>
      <span class="cc-anchor">⠿</span>
    </template>

    <!-- 右键菜单: Teleport 到 body, 避免被画布 transform 影响 fixed 定位 -->
    <Teleport to="body">
      <div v-if="menuOpen" class="cc-menu" :style="menuStyle" @pointerdown.stop @click.stop>
        <button @click="act('edit')">{{ t('screen.cEdit') }}</button>
        <button @click="act('flip')">{{ t('screen.cFlip') }}</button>
        <button @click="act('front')">{{ t('screen.cFront') }}</button>
        <button @click="act('back')">{{ t('screen.cBack') }}</button>
        <button class="danger" @click="act('remove')">{{ t('screen.cRemove') }}</button>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, inject, computed, onBeforeUnmount } from 'vue'
import { t } from '../../i18n'

const props = defineProps({
  card: { type: Object, required: true },
  mode: { type: String, default: 'browse' },   // browse / edit
  selected: { type: Boolean, default: false },
})
const emit = defineEmits(['select', 'patch', 'flip', 'remove', 'bring-front', 'send-back', 'edit'])

// 画布缩放比(来自 FreeCanvas), 屏幕位移 ÷ scale = 设计坐标系位移
const scale = inject('canvasScale', ref(1))

const cardStyle = computed(() => ({
  left: props.card.x + 'px',
  top: props.card.y + 'px',
  width: props.card.w + 'px',
  height: props.card.h + 'px',
  zIndex: props.card.z,
}))

// ===== 拖拽(仅编辑模式): 屏幕位移换算回设计 px, 阈值 4px 判定为拖拽 =====
let drag = null
function onDown(e) {
  if (e.button !== 0) return
  emit('select')
  if (props.mode !== 'edit') return
  drag = { sx: e.clientX, sy: e.clientY, ox: props.card.x, oy: props.card.y, moved: false }
  window.addEventListener('pointermove', onMove)
  window.addEventListener('pointerup', onUp)
}
function onMove(e) {
  if (!drag) return
  if (!drag.moved && Math.abs(e.clientX - drag.sx) + Math.abs(e.clientY - drag.sy) < 4) return
  drag.moved = true
  const dx = (e.clientX - drag.sx) / scale.value
  const dy = (e.clientY - drag.sy) / scale.value
  emit('patch', { x: Math.round(drag.ox + dx), y: Math.round(drag.oy + dy) })
}
function onUp() {
  drag = null
  window.removeEventListener('pointermove', onMove)
  window.removeEventListener('pointerup', onUp)
}

// 浏览模式: 点击卡片翻转(查看正反面); 编辑模式点击不翻转(翻转走右键菜单)
function onClick() {
  if (props.mode !== 'browse') return
  emit('flip')
}

// ===== 四角无级缩放(仅编辑模式): 维持对角锚点不动 =====
function onResizeStart(corner, e) {
  e.stopPropagation()
  emit('select')
  const sx = e.clientX, sy = e.clientY
  const o = { x: props.card.x, y: props.card.y, w: props.card.w, h: props.card.h }
  function mv(ev) {
    const dx = (ev.clientX - sx) / scale.value
    const dy = (ev.clientY - sy) / scale.value
    const p = { w: o.w, h: o.h, x: o.x, y: o.y }
    if (corner.includes('e')) p.w = Math.max(160, o.w + dx)
    if (corner.includes('s')) p.h = Math.max(100, o.h + dy)
    if (corner.includes('w')) { p.w = Math.max(160, o.w - dx); p.x = o.x + (o.w - p.w) }
    if (corner.includes('n')) { p.h = Math.max(100, o.h - dy); p.y = o.y + (o.h - p.h) }
    emit('patch', p)
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}

// ===== 右键菜单(仅编辑模式) =====
const menuOpen = ref(false)
const menuStyle = ref({})
function onContext(e) {
  if (props.mode !== 'edit') return
  menuStyle.value = { left: e.clientX + 'px', top: e.clientY + 'px' }
  menuOpen.value = true
  emit('select')
  window.addEventListener('pointerdown', closeMenu, { once: true })
}
function closeMenu() { menuOpen.value = false }
function act(name) {
  menuOpen.value = false
  if (name === 'edit') emit('edit')
  else if (name === 'flip') emit('flip')
  else if (name === 'front') emit('bring-front')
  else if (name === 'back') emit('send-back')
  else if (name === 'remove') emit('remove')
}
onBeforeUnmount(() => { window.removeEventListener('pointerdown', closeMenu); onUp() })
</script>

<style scoped>
/* 卡片定位(设计坐标系, 由 stage 整体缩放); perspective 给内层 3D 翻转 */
.cc { position: absolute; perspective: 1200px; }
.cc-inner {
  position: absolute; inset: 0; transform-style: preserve-3d;
  transition: transform .5s cubic-bezier(.4, .2, .2, 1);
}
.cc-inner.flip { transform: rotateY(180deg); }
.cc-face {
  position: absolute; inset: 0; backface-visibility: hidden; -webkit-backface-visibility: hidden;
  border-radius: 12px; overflow: hidden;
  background: linear-gradient(160deg, rgba(20, 30, 52, .94), rgba(10, 16, 30, .94));
  border: 1px solid rgba(56, 132, 255, .28);
  box-shadow: 0 12px 32px rgba(0, 0, 0, .5), inset 0 1px 0 rgba(255, 255, 255, .06);
  color: #cdd6e4;
}
.cc-back { transform: rotateY(180deg); }

/* 选中高亮(编辑态) */
.cc.sel .cc-inner { box-shadow: 0 0 0 2px var(--accent), 0 14px 36px rgba(0, 0, 0, .55); }

/* 缩放手柄 + 拖拽锚点 */
.cc-handle {
  position: absolute; width: 14px; height: 14px; border-radius: 50%;
  background: var(--accent); border: 2px solid #0a1020; z-index: 6;
}
.cc-handle.nw { left: -7px; top: -7px; cursor: nwse-resize; }
.cc-handle.ne { right: -7px; top: -7px; cursor: nesw-resize; }
.cc-handle.sw { left: -7px; bottom: -7px; cursor: nesw-resize; }
.cc-handle.se { right: -7px; bottom: -7px; cursor: nwse-resize; }
.cc-anchor {
  position: absolute; left: 50%; top: -11px; transform: translateX(-50%);
  font-size: 12px; color: var(--accent); opacity: .6; pointer-events: none; user-select: none;
}

/* 右键菜单(已 Teleport 到 body) */
.cc-menu {
  position: fixed; z-index: 9999; min-width: 132px;
  background: rgba(12, 20, 36, .97); border: 1px solid rgba(56, 132, 255, .4);
  border-radius: 8px; padding: 4px; box-shadow: 0 12px 34px rgba(0, 0, 0, .6);
}
.cc-menu button {
  display: block; width: 100%; text-align: left; padding: 7px 12px;
  font-size: 12.5px; color: #cdd6e4; background: transparent; border: none;
  cursor: pointer; border-radius: 5px;
}
.cc-menu button:hover { background: rgba(56, 132, 255, .22); color: #fff; }
.cc-menu button.danger { color: #f87171; }
.cc-menu button.danger:hover { background: rgba(248, 113, 113, .18); }
</style>
