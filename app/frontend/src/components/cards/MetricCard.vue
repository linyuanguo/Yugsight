<template>
  <!-- 数字指标卡(2026-09-27): 主指标数字 + 同比/环比标签 + 底部迷你趋势折线图。
       数据源、字段、颜色主题、趋势点数全部可在编辑模式右侧属性面板配置。 -->
  <div class="mc">
    <template v-if="side === 'front'">
      <div class="mc-top">
        <span class="mc-title">{{ card.title }}</span>
        <span v-if="!compact" class="mc-chip" :class="chipCls">{{ chipText }}</span>
      </div>
      <div class="mc-val" :style="{ color }">
        <b>{{ shown }}</b><i v-if="m.unit">{{ m.unit }}</i>
      </div>
      <svg v-if="!compact" class="mc-spark" viewBox="0 0 100 30" preserveAspectRatio="none">
        <path :d="sp.area" class="mc-area" :style="{ fill: grad }" />
        <path :d="sp.line" class="mc-line" :style="{ stroke: color }" />
      </svg>
      <div v-if="!compact" class="mc-foot">{{ foot }}</div>
    </template>
    <template v-else>
      <div class="mc-back">
        <div><span>数据源</span><b>/api/v2/screen/overview</b></div>
        <div><span>字段</span><b>{{ m.label }}</b></div>
        <div><span>环比口径</span><b>近7天新增 vs 前7天</b></div>
        <div><span>趋势点数</span><b>{{ span }} 点</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, onBeforeUnmount } from 'vue'
import { COLOR, fmt, linePath, animateNum } from './chartkit.js'
import { useShared, pickMetric, trendSlice, mom7 } from './dashData.js'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const S = useShared()
const m = computed(() => pickMetric(props.card.metric))
const val = computed(() => { void S.updatedAt; return m.value.get() })
const color = computed(() => COLOR[props.card.color] || COLOR.accent)
const grad = computed(() => `linear-gradient(180deg, ${color.value}55, ${color.value}00)`)
const span = computed(() => props.card.span || 14)

// 浏览模式数字带补间动画(浏览要有动效); 编辑模式直接落值, 免得改属性时数字乱跳
const shown = ref(0)
let cancel = null
function paint(v) {
  const abs = Math.abs(v)
  shown.value = abs >= 1000 ? fmt(v) : (Number.isInteger(v) ? String(v) : v.toFixed(1))
}
watch(val, (nv, ov) => {
  if (props.mode !== 'browse') { paint(nv); return }
  if (cancel) cancel()
  cancel = animateNum(ov || 0, nv || 0, 700, (x) => paint(x))
}, { immediate: true })
// m.unit 变化说明切换了指标字段, 立即重置补间避免从旧量级的数字回滚
watch(() => props.card.metric, () => { if (cancel) cancel(); paint(val.value) })
onBeforeUnmount(() => { if (cancel) cancel() })

const mm = computed(() => { void S.updatedAt; return mom7() })
const chipText = computed(() => {
  if (props.card.compare) return props.card.compare
  const v = mm.value
  if (v === null) return '环比 —'
  return '环比 ' + (v > 0 ? '+' : '') + v + '%'
})
const chipCls = computed(() => {
  const v = mm.value
  return v === null ? '' : v > 0 ? 'up' : v < 0 ? 'down' : ''
})

const sp = computed(() => {
  void S.updatedAt
  const pts = trendSlice(span.value).map(p => p.new || 0)
  return linePath(pts, 100, 30, 3)
})
const foot = computed(() => props.card.note || m.value.label)
</script>

<style scoped>
.mc { height: 100%; box-sizing: border-box; padding: 12px 16px; display: flex; flex-direction: column; gap: 4px; }
.mc-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.mc-title { font-size: 12.5px; color: #8295b0; letter-spacing: .5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.mc-chip { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: rgba(255, 255, 255, .06); color: #94a3b8; }
.mc-chip.up { background: rgba(248, 113, 113, .16); color: #fca5a5; }
.mc-chip.down { background: rgba(52, 211, 153, .16); color: #6ee7b7; }
.mc-val { display: flex; align-items: baseline; gap: 4px; margin-top: 2px; }
.mc-val b { font-size: 34px; font-weight: 700; line-height: 1.1; text-shadow: 0 0 18px currentColor; }
.mc-val i { font-size: 14px; font-style: normal; opacity: .75; }
.mc-spark { width: 100%; flex: 1; min-height: 30px; }
.mc-line { fill: none; stroke-width: 1.6; filter: drop-shadow(0 0 4px currentColor); }
.mc-foot { font-size: 11px; color: #64748b; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.mc-back { display: flex; flex-direction: column; gap: 8px; font-size: 12px; padding: 4px; }
.mc-back div { display: flex; justify-content: space-between; gap: 8px; }
.mc-back span { color: #8295b0; }
.mc-back b { color: #eaf1fb; font-weight: 600; }
</style>
