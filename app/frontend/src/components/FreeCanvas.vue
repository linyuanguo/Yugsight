<template>
  <!-- 自由画布容器(2026-09-27 安全大屏 Pro 基础框架):
       全屏铺满父级, 内部 1920×1080 设计坐标系, translate+scale 等比适配
       (letterbox 居中, 1080P~4K 一份布局通用, 无需重排)。
       后续所有可视化元素(卡片/3D 拓扑/图表)挂载到 slot, 坐标用设计 px。 -->
  <div class="fc" :class="{ edit: mode === 'edit' }">
    <!-- 画布视口: 深色底 + 科技网格(编辑模式网格增强 + 十字光标) -->
    <div class="fc-vp" ref="vpEl">
      <div class="fc-stage" :style="stageStyle">
        <!-- 内容挂载点: 后续步骤在此放置可视化元素(设计坐标系) -->
        <slot></slot>
        <!-- 空态提示(外层据卡片数传 empty 控制) -->
        <div class="fc-empty" v-if="empty">
          <span class="fc-empty-tag">自由画布</span>
          <span>可视化内容将在后续步骤挂载</span>
        </div>
      </div>
    </div>
    <!-- 编辑模式角标(浏览模式不显示) -->
    <div class="fc-badge" v-if="mode === 'edit'">编辑模式 · 画布已解锁</div>
  </div>
</template>

<script setup>
import { ref, computed, provide, onMounted, onBeforeUnmount } from 'vue'

// 设计坐标系: 纯全屏页(无内嵌顶栏), 取 1920×1080 满幅 16:9
const STAGE_W = 1920
const STAGE_H = 1080

// mode: browse=浏览模式 / edit=编辑模式; empty: 画布是否空(外层据卡片数传入, 控制空态提示)
defineProps({
  mode: { type: String, default: 'browse' },
  empty: { type: Boolean, default: false }
})

const vpEl = ref(null)
const vpW = ref(0)
const vpH = ref(0)
let ro = null

function fit() {
  if (!vpEl.value) return
  vpW.value = vpEl.value.clientWidth
  vpH.value = vpEl.value.clientHeight
}

// 等比适配: 设计坐标系放进视口(letterbox 居中), ResizeObserver 跟踪窗口/全屏变化
const scale = computed(() => {
  if (!vpW.value || !vpH.value) return 1
  return Math.min(vpW.value / STAGE_W, vpH.value / STAGE_H)
})
// 向画布内卡片提供缩放比(设计坐标系→屏幕), 卡片拖拽/缩放时把屏幕位移换算回设计 px
provide('canvasScale', scale)
const stageStyle = computed(() => {
  const offX = Math.max(0, (vpW.value - STAGE_W * scale.value) / 2)
  const offY = Math.max(0, (vpH.value - STAGE_H * scale.value) / 2)
  return {
    width: STAGE_W + 'px',
    height: STAGE_H + 'px',
    transform: `translate(${offX}px, ${offY}px) scale(${scale.value})`
  }
})

onMounted(() => {
  fit()
  ro = new ResizeObserver(fit)
  if (vpEl.value) ro.observe(vpEl.value)
})
onBeforeUnmount(() => {
  if (ro) ro.disconnect()
})
</script>

<style scoped>
/* 画布根: 铺满父级(父级 = 全屏页 .bpro) */
.fc { position: absolute; inset: 0; overflow: hidden; }

/* 网格强度: 浏览=弱, 编辑=增强(模式差异一目了然) */
.fc { --grid-c: rgba(56, 132, 255, .07); }
.fc.edit { --grid-c: rgba(56, 132, 255, .16); }

/* 视口: 深色底 + 48px 网格 + 上/下双色辉光(深色科技风, 与系统整体视觉统一) */
.fc-vp {
  position: absolute; inset: 0; overflow: hidden;
  background:
    radial-gradient(1100px 520px at 50% -6%, rgba(56, 132, 255, .13), transparent 70%),
    linear-gradient(var(--grid-c) 1px, transparent 1px),
    linear-gradient(90deg, var(--grid-c) 1px, transparent 1px),
    radial-gradient(1400px 900px at 50% 118%, rgba(99, 102, 241, .10), transparent 62%),
    #070d18;
  background-size: auto, 48px 48px, 48px 48px, auto, auto;
}
/* 编辑模式: 十字光标(可编辑暗示) */
.fc.edit .fc-vp { cursor: crosshair; }

/* 设计坐标系舞台(内容载体; transform-origin 左上, 由 stageStyle 定位) */
.fc-stage { position: absolute; top: 0; left: 0; transform-origin: 0 0; }

/* 空态提示(随舞台等比缩放, slot 有内容后消失) */
.fc-empty {
  position: absolute; inset: 0; display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 12px;
  color: rgba(160, 180, 210, .55); font-size: 16px; letter-spacing: 2px;
}
.fc-empty-tag {
  font-size: 13px; color: var(--accent); letter-spacing: 3px;
  border: 1px solid rgba(56, 189, 248, .4); border-radius: 999px;
  padding: 4px 18px; background: rgba(56, 189, 248, .08);
}

/* 编辑模式角标(左上; 右上留给页面悬浮控制栏) */
.fc-badge {
  position: absolute; top: 16px; left: 20px; z-index: 5;
  font-size: 12px; color: #38bdf8; white-space: nowrap;
  border: 1px solid rgba(56, 189, 248, .5); border-radius: 999px;
  padding: 4px 14px; background: rgba(56, 189, 248, .12);
  backdrop-filter: blur(6px);
}
</style>
