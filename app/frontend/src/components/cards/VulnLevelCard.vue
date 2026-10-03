<template>
  <!-- 漏洞分级统计(2026-09-27): 环形占比图 —— 严重/高危/中危/低危/信息。
       口径复用 bigscreen.SevCount: risk = 四类风险之和(不含 info), info 单独计数,
       避免"缺失安全头"这类加固建议把风险占比稀释到看不出重点。 -->
  <div class="vl">
    <template v-if="side === 'front'">
      <div class="vl-title">{{ t(card.title) }}</div>
      <div class="vl-body">
        <svg class="vl-donut" viewBox="0 0 100 100">
          <path v-for="s in segs" :key="s.k" :d="s.d" class="vl-seg" :style="{ fill: s.c }" />
        </svg>
        <div class="vl-center">
          <b>{{ fmt(total) }}</b>
          <span v-if="!compact">{{ t('screen.unfixedRisk') }}</span>
        </div>
      </div>
      <div v-if="!compact" class="vl-legend">
        <div v-for="s in segs" :key="s.k" class="vl-row">
          <i :style="{ background: s.c }"></i><span>{{ s.t }}</span><b>{{ fmt(s.n) }}</b><em>{{ s.p }}%</em>
        </div>
      </div>
    </template>
    <template v-else>
      <div class="vl-back">
        <div v-for="s in segs" :key="s.k"><span>{{ s.t }}</span><b :style="{ color: s.c }">{{ fmt(s.n) }}</b></div>
        <div class="vl-back-note">{{ t('screen.infoNote') }}</div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmt, arcRing, SEV, SEV_ORDER } from './chartkit.js'
import { useShared, sev } from './dashData.js'
import { t } from '../../i18n'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const S = useShared()
const risk = computed(() => {
  void S.updatedAt
  const v = sev()
  // 是否含 info 可在属性面板配置(card.infoIncl): 默认不含, 与大屏/报告口径一致
  return props.card.infoIncl
    ? SEV_ORDER.map(k => ({ k, n: v[k] || 0 }))
    : SEV_ORDER.filter(k => k !== 'info').map(k => ({ k, n: v[k] || 0 }))
})
const total = computed(() => risk.value.reduce((a, b) => a + b.n, 0))
const segs = computed(() => {
  let acc = 0
  const tot = total.value || 1   // 2026-10-03: 原局部名 t 遮蔽 i18n 的 t(), 改 tot
  return risk.value.map(r => {
    const sweep = r.n * 360 / tot
    const s = arcRing(50, 50, 42, 30, acc, acc + sweep)
    acc += sweep
    return { k: r.k, t: t('sev.' + r.k), c: SEV[r.k], n: r.n, p: Math.round(r.n * 1000 / tot) / 10, d: s }
  })
})
</script>

<style scoped>
.vl { height: 100%; box-sizing: border-box; padding: 12px 14px; display: flex; flex-direction: column; gap: 6px; }
.vl-title { font-size: 12.5px; color: #8295b0; }
.vl-body { position: relative; flex: 1; min-height: 0; display: flex; align-items: center; justify-content: center; }
.vl-donut { width: 100%; height: 100%; animation: vlFade .6s ease; }
.vl-seg { filter: drop-shadow(0 0 6px currentColor); opacity: .92; }
.vl-center { position: absolute; display: flex; flex-direction: column; align-items: center; }
.vl-center b { font-size: 24px; font-weight: 800; color: #eaf1fb; }
.vl-center span { font-size: 10.5px; color: #8295b0; }
.vl-legend { display: flex; flex-wrap: wrap; gap: 4px 10px; }
.vl-row { display: flex; align-items: center; gap: 4px; font-size: 11px; color: #94a3b8; }
.vl-row i { width: 7px; height: 7px; border-radius: 2px; }
.vl-row b { color: #eaf1fb; }
.vl-row em { font-style: normal; color: #64748b; }
.vl-back { display: flex; flex-direction: column; gap: 6px; font-size: 12px; }
.vl-back div { display: flex; justify-content: space-between; gap: 8px; }
.vl-back span { color: #8295b0; }
.vl-back b { font-weight: 700; }
.vl-back-note { font-size: 11px; color: #64748b; }
@keyframes vlFade { from { opacity: 0; transform: scale(.9); } to { opacity: 1; transform: scale(1); } }
</style>
