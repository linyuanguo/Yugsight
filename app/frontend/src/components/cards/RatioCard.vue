<template>
  <!-- 占比统计卡(2026-09-27): 环形进度图 + 中心数值 + 分类说明。
       分子/分母各自绑定指标字典里的字段, 可配颜色主题。 -->
  <div class="rc">
    <template v-if="side === 'front'">
      <div class="rc-title">{{ t(card.title) }}</div>
      <div class="rc-body">
        <svg class="rc-ring" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="40" class="rc-track" />
          <path :d="seg" class="rc-seg" :style="{ fill: color }" />
        </svg>
        <div class="rc-center" :style="{ color }">
          <b>{{ pct }}<i>%</i></b>
          <span class="rc-sub" v-if="!compact">{{ fmt(num) }} / {{ fmt(den) }}</span>
        </div>
      </div>
      <div v-if="!compact" class="rc-note">{{ card.note || t('screen.ratioOf', { a: metricLabel(mA.key), b: metricLabel(mB.key) }) }}</div>
    </template>
    <template v-else>
      <div class="rc-back">
        <div><span>{{ t('screen.numer') }}</span><b>{{ metricLabel(mA.key) }}</b></div>
        <div><span>{{ t('screen.denom') }}</span><b>{{ metricLabel(mB.key) }}</b></div>
        <div><span>{{ t('screen.cSrc') }}</span><b>/api/v2/screen/overview</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { COLOR, fmt, arcRing } from './chartkit.js'
import { useShared, pickMetric, metricLabel } from './dashData.js'
import { t } from '../../i18n'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const S = useShared()
const mA = computed(() => pickMetric(props.card.metric))
const mB = computed(() => pickMetric(props.card.total))
const num = computed(() => { void S.updatedAt; return mA.value.get() })
const den = computed(() => { void S.updatedAt; return mB.value.get() })
const pct = computed(() => (den.value ? Math.round(num.value * 1000 / den.value) / 10 : 0))
const color = computed(() => COLOR[props.card.color] || COLOR.accent)
const seg = computed(() => arcRing(50, 50, 40, 30, 0, Math.max(0, Math.min(359.99, pct.value * 3.6))))
</script>

<style scoped>
.rc { height: 100%; box-sizing: border-box; padding: 12px 14px; display: flex; flex-direction: column; gap: 6px; align-items: center; }
.rc-title { font-size: 12.5px; color: #8295b0; align-self: flex-start; }
.rc-body { position: relative; flex: 1; width: 100%; display: flex; align-items: center; justify-content: center; min-height: 0; }
.rc-ring { width: 100%; height: 100%; }
.rc-track { fill: none; stroke: rgba(255, 255, 255, .07); stroke-width: 12; }
.rc-seg { filter: drop-shadow(0 0 8px currentColor); }
.rc-center { position: absolute; display: flex; flex-direction: column; align-items: center; }
.rc-center b { font-size: 26px; font-weight: 700; }
.rc-center i { font-size: 13px; font-style: normal; opacity: .7; }
.rc-sub { font-size: 11.5px; color: #94a3b8; margin-top: 2px; }
.rc-note { font-size: 11.5px; color: #64748b; text-align: center; }
.rc-back { width: 100%; display: flex; flex-direction: column; gap: 8px; font-size: 12px; }
.rc-back div { display: flex; justify-content: space-between; gap: 8px; }
.rc-back span { color: #8295b0; }
.rc-back b { color: #eaf1fb; font-weight: 600; }
</style>
