<template>
  <!-- 扫描任务趋势(2026-09-27): 折线图, 近 7/30 日"新发现漏洞 vs 修复漏洞"双序列。
       为什么不是"扫描任务量 + 漏洞发现量": 后端 trend 点只有 new/fixed/opened 三个量,
       没有按天的任务量; 硬凑任务量只能前端拿总量摊到每天, 那会造出假趋势。
       因此这里如实呈现后端真实有的两个序列, 任务量逐年细化需后端补 -》。 -->
  <div class="tc">
    <template v-if="side === 'front'">
      <div class="tc-head">
        <span class="tc-title">{{ card.title }}</span>
        <span class="tc-range">近 {{ days }} 日</span>
      </div>
      <div class="tc-legend">
        <span><i style="background:#38bdf8"></i>新发现</span>
        <span><i style="background:#34d399"></i>已修复</span>
      </div>
      <svg class="tc-chart" :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none">
        <line v-for="g in grid" :key="'g' + g" :x1="0" :x2="W" :y1="g" :y2="g" class="tc-grid" />
        <path :d="pNew.area" class="tc-area" fill="url(#tcA)" />
        <path :d="pFix.area" class="tc-area2" fill="url(#tcB)" />
        <path :d="pNew.line" class="tc-line" stroke="#38bdf8" />
        <path :d="pFix.line" class="tc-line" stroke="#34d399" />
      </svg>
      <div class="tc-axis">
        <span v-for="(l, i) in labels" :key="i">{{ l }}</span>
      </div>
    </template>
    <template v-else>
      <div class="tc-back">
        <div><span>数据源</span><b>/api/v2/screen/overview</b></div>
        <div><span>时间窗</span><b>近 {{ days }} 日</b></div>
        <div><span>序列</span><b>new(新发现) / fixed(修复)</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { linePath } from './chartkit.js'
import { useShared, trendSlice } from './dashData.js'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const W = 300, H = 120
const S = useShared()
const days = computed(() => props.card.days || 7)
const pts = computed(() => { void S.updatedAt; return trendSlice(days.value) })
const labels = computed(() => pts.value.filter((_, i) => i % Math.ceil((pts.value.length || 1) / 5) === 0).map(p => p.label))
const pNew = computed(() => linePath(pts.value.map(p => p.new || 0), W, H, 8))
const pFix = computed(() => linePath(pts.value.map(p => p.fixed || 0), W, H, 8))
const grid = [8, 38, 68, 98, 112]
</script>

<style scoped>
.tc { height: 100%; box-sizing: border-box; padding: 12px 14px; display: flex; flex-direction: column; gap: 6px; }
.tc-head { display: flex; align-items: center; justify-content: space-between; }
.tc-title { font-size: 12.5px; color: #8295b0; }
.tc-range { font-size: 11px; color: var(--accent); background: rgba(56, 189, 248, .1); border: 1px solid rgba(56, 189, 248, .35); border-radius: 999px; padding: 1px 8px; }
.tc-legend { display: flex; gap: 12px; font-size: 11px; color: #94a3b8; }
.tc-legend span { display: flex; align-items: center; gap: 4px; }
.tc-legend i { width: 8px; height: 2px; border-radius: 1px; }
.tc-chart { flex: 1; width: 100%; min-height: 60px; }
.tc-grid { stroke: rgba(255, 255, 255, .06); stroke-width: 1; }
.tc-line { fill: none; stroke-width: 1.8; filter: drop-shadow(0 0 5px currentColor); stroke-linejoin: round; }
.tc-area { opacity: .18; }
.tc-area2 { opacity: .12; }
.tc-axis { display: flex; justify-content: space-between; font-size: 10px; color: #64748b; }
.tc-back { display: flex; flex-direction: column; gap: 8px; font-size: 12px; }
.tc-back div { display: flex; justify-content: space-between; gap: 8px; }
.tc-back span { color: #8295b0; }
.tc-back b { color: #eaf1fb; font-weight: 600; }
</style>
