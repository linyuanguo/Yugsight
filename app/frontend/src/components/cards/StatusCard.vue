<template>
  <!-- 状态汇总卡(2026-09-27): 多状态色块分布 + 数量统计 + 状态说明。
       绑定任务是"同源真实字段口径": 今日新建/进行中/已完成/失败
       (后端 overview 未拆分 pending, 见 dashData.taskBars 注释)。 -->
  <div class="sc">
    <template v-if="side === 'front'">
      <div class="sc-title">{{ card.title }}</div>
      <div class="sc-list">
        <div v-for="r in rows" :key="r.k" class="sc-row">
          <i class="sc-dot" :style="{ background: r.c, boxShadow: '0 0 8px ' + r.c }"></i>
          <span class="sc-label">{{ r.l }}</span>
          <span class="sc-bar"><b :style="{ width: barW(r.n) + '%', background: r.c }"></b></span>
          <span class="sc-num" :style="{ color: r.c }">{{ fmt(r.n) }}</span>
        </div>
      </div>
      <div v-if="!compact" class="sc-note">{{ card.note || '任务状态分布(实时)' }}</div>
    </template>
    <template v-else>
      <div class="sc-back">
        <div v-for="r in rows" :key="r.k"><span>{{ r.l }}</span><b :style="{ color: r.c }">{{ fmt(r.n) }}</b></div>
        <div><span>数据源</span><b>/api/v2/screen/overview</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmt } from './chartkit.js'
import { useShared, taskBars } from './dashData.js'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const S = useShared()
const rows = computed(() => { void S.updatedAt; return taskBars() })
function barW(n) {
  const mx = Math.max(1, ...rows.value.map(r => r.n))
  return Math.round(n * 100 / mx)
}
</script>

<style scoped>
.sc { height: 100%; box-sizing: border-box; padding: 12px 14px; display: flex; flex-direction: column; gap: 6px; }
.sc-title { font-size: 12.5px; color: #8295b0; }
.sc-list { flex: 1; display: flex; flex-direction: column; justify-content: space-around; gap: 6px; min-height: 0; }
.sc-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.sc-dot { width: 8px; height: 8px; border-radius: 2px; flex: 0 0 auto; }
.sc-label { width: 56px; color: #94a3b8; flex: 0 0 auto; }
.sc-bar { flex: 1; height: 7px; border-radius: 999px; background: rgba(255, 255, 255, .07); overflow: hidden; }
.sc-bar b { display: block; height: 100%; border-radius: 999px; transition: width .5s ease; }
.sc-num { width: 46px; text-align: right; font-weight: 700; font-variant-numeric: tabular-nums; }
.sc-note { font-size: 11px; color: #64748b; }
.sc-back { display: flex; flex-direction: column; gap: 8px; font-size: 12px; }
.sc-back div { display: flex; justify-content: space-between; gap: 8px; }
.sc-back span { color: #8295b0; }
.sc-back b { font-weight: 600; }
</style>
