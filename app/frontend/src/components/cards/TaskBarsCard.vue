<template>
  <!-- 任务状态分布(2026-09-27): 横向柱状图。
       四项全部取自 overview 真实字段; 后端把 pending 合并进 tasksRunning,
       所以这里用"今日新建"代替无法拆出的"待执行", 见 dashData.taskBars 注释。 -->
  <div class="tb">
    <template v-if="side === 'front'">
      <div class="tb-title">{{ t(card.title) }}</div>
      <div class="tb-list">
        <div v-for="r in rows" :key="r.k" class="tb-item">
          <span class="tb-label">{{ r.l }}</span>
          <span class="tb-track">
            <b :style="{ width: w(r.n) + '%', background: barFill(r.c) }">
              <em v-if="!compact">{{ r.n }}</em>
            </b>
          </span>
        </div>
      </div>
    </template>
    <template v-else>
      <div class="tb-back">
        <div v-for="r in rows" :key="r.k"><span>{{ r.l }}</span><b :style="{ color: r.c }">{{ r.n }}</b></div>
        <div><span>{{ t('screen.cSrc') }}</span><b>/api/v2/screen/overview</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useShared, taskBars } from './dashData.js'
import { t } from '../../i18n'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const S = useShared()
const rows = computed(() => { void S.updatedAt; return taskBars() })
function w(n) {
  const mx = Math.max(1, ...rows.value.map(r => r.n))
  return Math.round(n * 100 / mx)
}
// 渐变必须带单位('%' 而非纯数字): Vue 的 style 绑定会把裸数字当 px
function barFill(c) { return `linear-gradient(90deg, ${c}55, ${c})` }
</script>

<style scoped>
.tb { height: 100%; box-sizing: border-box; padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; }
.tb-title { font-size: 12.5px; color: #8295b0; }
.tb-list { flex: 1; display: flex; flex-direction: column; justify-content: space-around; gap: 8px; min-height: 0; }
.tb-item { display: flex; align-items: center; gap: 8px; }
.tb-label { width: 56px; flex: 0 0 auto; font-size: 12px; color: #94a3b8; }
.tb-track { flex: 1; height: 18px; border-radius: 4px; background: rgba(255, 255, 255, .06); overflow: hidden; }
.tb-track b {
  display: flex; align-items: center; justify-content: flex-end; height: 100%;
  border-radius: 4px; padding-right: 6px; min-width: 2px;
  box-shadow: 0 0 10px currentColor; transition: width .6s ease;
}
.tb-track em { font-style: normal; font-size: 11px; font-weight: 700; color: #06121f; }
.tb-back { display: flex; flex-direction: column; gap: 8px; font-size: 12px; }
.tb-back div { display: flex; justify-content: space-between; gap: 8px; }
.tb-back span { color: #8295b0; }
.tb-back b { font-weight: 700; }
</style>
