<template>
  <!-- 告警 Top5(2026-09-27): 按风险排序的滚动列表。
       排序口径: 等级(严重>高危>中危>低危>信息)优先, 同级看 CVSS —— 若按数量排序
       TOP 榜会被"刷屏的低危"占满, 失去告警意义。
       浏览模式自动滚动; 编辑模式停滚便于布局微调(动画在编辑态纯属干扰)。 -->
  <div class="at">
    <template v-if="side === 'front'">
      <div class="at-head">
        <span class="at-title">{{ card.title }}</span>
        <span class="at-count">Top {{ Math.min(limit, rows.length) }}</span>
      </div>
      <div class="at-view">
        <div class="at-track" :class="{ roll: rolling && canRoll }" :style="{ '--shift': shift + 'px' }">
          <div v-for="(r, i) in (canRoll ? rows.concat(rows) : rows)" :key="i" class="at-item">
            <i :style="{ background: r.c, boxShadow: '0 0 8px ' + r.c }"></i>
            <div class="at-main">
              <b :title="r.title">{{ r.title }}</b>
              <span>{{ r.target }}</span>
            </div>
            <em :style="{ color: r.c }">{{ r.t }}</em>
          </div>
          <div v-if="!rows.length" class="at-empty">暂无告警数据</div>
        </div>
      </div>
    </template>
    <template v-else>
      <div class="at-back">
        <div><span>数据源</span><b>overview.topVulns</b></div>
        <div><span>排序</span><b>等级 → CVSS</b></div>
        <div><span>展示条数</span><b>{{ limit }}</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { SEV, SEV_CN, SEV_ORDER } from './chartkit.js'
import { useShared, alertRows } from './dashData.js'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const S = useShared()
const limit = computed(() => props.card.limit || 5)
const rows = computed(() => {
  void S.updatedAt
  const rank = (s) => { const i = SEV_ORDER.indexOf((s || '').toLowerCase()); return i < 0 ? 9 : i }
  return alertRows()
    .slice()
    .sort((a, b) => (rank(a.severity) - rank(b.severity)) || ((b.cvss || 0) - (a.cvss || 0)))
    .slice(0, limit.value)
    .map(v => ({
      title: v.title || v.cve || '未命名风险',
      target: (v.assetIp || '') + (v.port ? ':' + v.port : ''),
      severity: v.severity,
      t: SEV_CN[(v.severity || '').toLowerCase()] || v.severity || '—',
      c: SEV[(v.severity || '').toLowerCase()] || '#94a3b8',
    }))
})
// 滚动: 列表超过可视区才滚动(少数据时滚动会漏像: 看着像坏了)
const shift = computed(() => rows.value.length * 40)
const canRoll = computed(() => rows.value.length > 3)
const rolling = computed(() => props.mode === 'browse' && !props.compact)
</script>

<style scoped>
.at { height: 100%; box-sizing: border-box; padding: 10px 12px; display: flex; flex-direction: column; gap: 6px; }
.at-head { display: flex; align-items: center; justify-content: space-between; }
.at-title { font-size: 12.5px; color: #8295b0; }
.at-count { font-size: 11px; color: var(--accent); }
.at-view { position: relative; flex: 1; min-height: 0; overflow: hidden; }
.at-track { display: flex; flex-direction: column; }
.at-track.roll { animation: atRoll 12s linear infinite; }
.at-item { display: flex; align-items: center; gap: 8px; height: 40px; flex: 0 0 auto; border-bottom: 1px dashed rgba(255, 255, 255, .06); }
.at-item i { width: 6px; height: 6px; border-radius: 50%; flex: 0 0 auto; }
.at-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.at-main b { font-size: 11.5px; color: #eaf1fb; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.at-main span { font-size: 10.5px; color: #64748b; }
.at-item em { font-style: normal; font-size: 11px; font-weight: 700; flex: 0 0 auto; }
.at-empty { font-size: 12px; color: #64748b; padding: 12px 0; }
.at-back { display: flex; flex-direction: column; gap: 8px; font-size: 12px; }
.at-back div { display: flex; justify-content: space-between; gap: 8px; }
.at-back span { color: #8295b0; }
.at-back b { color: #eaf1fb; font-weight: 600; }
@keyframes atRoll { from { transform: translateY(0); } to { transform: translateY(calc(-1 * var(--shift))); } }
</style>
