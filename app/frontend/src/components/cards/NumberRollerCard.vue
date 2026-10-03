<template>
  <!-- 数字滚动画板(2026-09-27): 通栏大数字轮播。
       指标序列可配(card.keys 逗号分隔, 取 index 字典), 每 4s 切换;
       编辑模式停播并可直接点右侧箭头试掷, 方便确认绑定是否生效。 -->
  <div class="nr" :class="{ compact }">
    <template v-if="side === 'front'">
      <div class="nr-stage">
        <div class="nr-item" :key="cur.key">
          <span class="nr-label">{{ cur.label }}</span>
          <b class="nr-val" :style="{ color }">{{ shown }}<i v-if="cur.unit">{{ cur.unit }}</i></b>
        </div>
      </div>
      <div class="nr-side">
        <div v-for="(k, i) in list" :key="k.key" class="nr-dot-row" :class="{ on: idx === i }">
          <i :style="{ background: k.color }"></i><span>{{ k.label }}</span>
        </div>
      </div>
      <div class="nr-btns" v-if="mode === 'edit'">
        <button type="button" @pointerdown.stop @click.stop="prev">‹</button>
        <button type="button" @pointerdown.stop @click.stop="next">›</button>
      </div>
    </template>
    <template v-else>
      <div class="nr-back">
        <div><span>轮播序列</span><b>{{ list.length }} 项</b></div>
        <div v-for="k in list" :key="k.key"><span>{{ k.label }}</span><b :style="{ color: k.color }">{{ k.get() }}</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { COLOR, fmt, animateNum } from './chartkit.js'
import { useShared, pickMetric } from './dashData.js'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const S = useShared()
const list = computed(() => {
  const raw = (props.card.keys || 'vulnTotal,assetAlive,probeOnline,vulnHigh').split(',')
  return raw.map(s => s.trim()).filter(Boolean).map((k, i) => {
    const m = pickMetric(k)
    return { key: m.key, label: m.label, unit: m.unit, get: m.get, color: [COLOR.accent, COLOR.ok, COLOR.warn, COLOR.danger, COLOR.info, COLOR.purple][i % 6] }
  })
})
const idx = ref(0)
const cur = computed(() => list.value[Math.min(idx.value, list.value.length - 1)] || { key: 'x', label: '—', get: () => 0 })
const color = computed(() => (cur.value && cur.value.color) || COLOR.accent)
const val = computed(() => { void S.updatedAt; return cur.value.get() })

const shown = ref(0)
let cancel = null
watch([val, () => props.card.keys], () => {
  if (cancel) cancel()
  cancel = animateNum(typeof shown.value === 'number' ? 0 : 0, val.value || 0, 700, (x) => {
    shown.value = Math.abs(x) >= 10000 ? fmt(x) : Math.round(x)
  })
}, { immediate: true })

let timer = null
function start() {
  stop()
  if (props.mode !== 'browse') return       // 编辑模式停播: 动画会干扰布局微调
  if (list.value.length < 2) return
  timer = setInterval(next, 4000)
}
function stop() { if (timer) { clearInterval(timer); timer = null } }
function next() { idx.value = (idx.value + 1) % Math.max(1, list.value.length) }
function prev() { idx.value = (idx.value - 1 + list.value.length) % Math.max(1, list.value.length) }

watch(() => props.mode, start)
onMounted(start)
onBeforeUnmount(() => { stop(); if (cancel) cancel() })
</script>

<style scoped>
.nr { height: 100%; box-sizing: border-box; padding: 6px 18px; display: flex; align-items: center; gap: 18px; }
.nr-stage { flex: 1; min-width: 0; }
.nr-item { display: flex; align-items: baseline; gap: 18px; animation: nrIn .5s ease; }
.nr-label { font-size: 15px; color: #9fb0c8; letter-spacing: 1px; white-space: nowrap; }
.nr-val { font-size: 46px; font-weight: 800; line-height: 1; text-shadow: 0 0 26px currentColor; font-variant-numeric: tabular-nums; }
.nr-val i { font-size: 20px; font-style: normal; opacity: .75; }
.nr-side { display: flex; gap: 14px; flex: 0 0 auto; }
.nr-dot-row { display: flex; align-items: center; gap: 5px; font-size: 11.5px; color: #64748b; opacity: .55; transition: opacity .3s; }
.nr-dot-row.on { opacity: 1; color: #cdd6e4; }
.nr-dot-row i { width: 7px; height: 7px; border-radius: 50%; }
.nr-btns { display: flex; gap: 6px; flex: 0 0 auto; }
.nr-btns button { width: 26px; height: 26px; border-radius: 6px; background: rgba(56, 132, 255, .16); border: 1px solid rgba(56, 132, 255, .4); color: #cdd6e4; cursor: pointer; }
.nr.compact .nr-val { font-size: 30px; }
.nr.compact .nr-side { display: none; }
.nr-back { width: 100%; display: flex; flex-direction: column; gap: 6px; font-size: 12px; }
.nr-back div { display: flex; justify-content: space-between; gap: 8px; }
.nr-back span { color: #8295b0; }
.nr-back b { font-weight: 600; }
@keyframes nrIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
</style>
