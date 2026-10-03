<template>
  <!-- 资产类型分布(2026-09-27): 饼图(交换机/路由器/服务器/终端)。
       数据来源说明: 后端 db.Assets 没有"设备类型"字段(资产表混主机与 SCA 工件),
       原口径是聚合画布内拓扑卡的设备节点(真实录入数据)。2026-09-28 旧拓扑模块
       删除后该数据源下线, 本卡降级为 0 并提示; 第三阶段新拓扑对接时恢复数据源。 -->
  <div class="ap">
    <template v-if="side === 'front'">
      <div class="ap-title">{{ card.title }}</div>
      <div class="ap-body">
        <svg class="ap-pie" viewBox="0 0 100 100">
          <path v-for="s in segs" :key="s.k" :d="s.d" class="ap-slice" :style="{ fill: s.c }" />
          <circle v-if="!segs.length" cx="50" cy="50" r="34" class="ap-empty" />
        </svg>
        <div class="ap-center"><b>{{ total }}</b><span v-if="!compact">{{ t('screen.cDevice') }}</span></div>
      </div>
      <div class="ap-legend">
        <div v-for="s in segs" :key="s.k" class="ap-row">
          <i :style="{ background: s.c }"></i><span>{{ s.t }}</span><b>{{ s.n }}</b>
        </div>
        <div v-if="!segs.length" class="ap-hint">{{ t('screen.noAsset') }}</div>
      </div>
    </template>
    <template v-else>
      <div class="ap-back">
        <div><span>{{ t('screen.cSrc') }}</span><b>{{ t('screen.devType') }}</b></div>
        <div v-for="s in segs" :key="s.k"><span>{{ s.t }}</span><b :style="{ color: s.c }">{{ s.n }}</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, inject, ref } from 'vue'
import { pieSlice } from './chartkit.js'
import { t } from '../../i18n'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const cards = inject('bproCards', ref([]))
const KIND_KEY = { router: 'typeRouter', switch: 'typeSwitch', server: 'typeServer', terminal: 'typeTerminal' }
const KIND_COLOR = { router: '#a78bfa', switch: '#38bdf8', server: '#34d399', terminal: '#fbbf24' }

const kindCount = computed(() => {
  // 原口径: 聚合画布内拓扑卡(c.type==='topo')的设备节点。旧拓扑模块删除后画布不再有
  // 该类型卡片, 聚合恒为空(前端降级为 0 + 提示); 保留此结构, 第三阶段新拓扑卡片
  // 接入时只需让节点数据回到 c.nodes 即可, 无需再改本卡。
  const m = {}
  for (const c of cards.value || []) {
    if (c.type !== 'topo') continue
    for (const n of (c.nodes || [])) {
      const k = n.kind || 'switch'
      m[k] = (m[k] || 0) + 1
    }
  }
  return m
})
const rows = computed(() => Object.keys(kindCount.value).map(k => ({
  k, t: t('screen.' + (KIND_KEY[k] || 'typeSwitch')), c: KIND_COLOR[k] || '#94a3b8', n: kindCount.value[k],
})).sort((a, b) => b.n - a.n))
const total = computed(() => rows.value.reduce((a, b) => a + b.n, 0))
const segs = computed(() => {
  const tot = total.value   // 2026-10-03: 原局部名 t 遮蔽 i18n 的 t(), 改 tot
  if (!tot) return []
  let acc = 0
  return rows.value.map(r => {
    const sweep = r.n * 360 / tot
    const d = pieSlice(50, 50, 38, acc, acc + sweep)
    acc += sweep
    return { k: r.k, t: r.t, c: r.c, n: r.n, d }
  })
})
</script>

<style scoped>
.ap { height: 100%; box-sizing: border-box; padding: 12px 14px; display: flex; flex-direction: column; gap: 6px; }
.ap-title { font-size: 12.5px; color: #8295b0; }
.ap-body { position: relative; flex: 1; min-height: 0; display: flex; align-items: center; justify-content: center; }
.ap-pie { width: 100%; height: 100%; animation: apPop .6s ease; }
.ap-slice { filter: drop-shadow(0 0 6px currentColor); opacity: .92; stroke: rgba(10, 16, 30, .8); stroke-width: .6; }
.ap-empty { fill: rgba(255, 255, 255, .05); stroke: rgba(255, 255, 255, .12); stroke-dasharray: 3 3; }
.ap-center { position: absolute; display: flex; flex-direction: column; align-items: center; }
.ap-center b { font-size: 22px; font-weight: 800; color: #eaf1fb; }
.ap-center span { font-size: 10.5px; color: #8295b0; }
.ap-legend { display: flex; flex-wrap: wrap; gap: 4px 10px; }
.ap-row { display: flex; align-items: center; gap: 4px; font-size: 11px; color: #94a3b8; }
.ap-row i { width: 7px; height: 7px; border-radius: 2px; }
.ap-row b { color: #eaf1fb; }
.ap-hint { font-size: 11px; color: #64748b; }
.ap-back { display: flex; flex-direction: column; gap: 6px; font-size: 12px; }
.ap-back div { display: flex; justify-content: space-between; gap: 8px; }
.ap-back span { color: #8295b0; }
.ap-back b { font-weight: 600; }
@keyframes apPop { from { opacity: 0; } to { opacity: 1; } }
</style>
