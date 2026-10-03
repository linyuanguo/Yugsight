<template>
  <!-- 多行任务列表卡(2026-09-28): 一张卡内展示 3-5 条任务, 解决"单卡 1 条、底部任务组占空间大"。
       数据源与仪表盘同源: overview.recentTasks(真实最近任务); 为空时回落卡片自带的静态任务。
       支持按状态筛选、按时间/进度排序、显示条数配置(均在属性面板)。 -->
  <div class="tl">
    <template v-if="side === 'front'">
      <div class="tl-head">
        <span class="tl-title">{{ t(card.title) }}</span>
        <!-- 2026-10-02 用户口径: 状态筛选选项=卡内任务列表里真实存在的状态(只含存在的) -->
        <select class="tl-filter" :value="card.filterStatus || 'all'" @change="setCfg('filterStatus', $event.target.value)">
          <option value="all">{{ t('screen.cAll') }}</option>
          <option v-for="s in statusOpts" :key="s" :value="s">{{ statusName(s) }}</option>
        </select>
      </div>
      <div class="tl-list">
        <div v-for="tk in rows" :key="tk.id" class="tl-row" :class="'s-' + tk.status">
          <i class="tl-dot"></i>
          <span class="tl-name" :title="tk.title">{{ tk.title }}</span>
          <span class="tl-badge">{{ statusName(tk.status) }}</span>
          <span class="tl-bar"><b :style="{ width: tk.progress + '%' }"></b></span>
          <span class="tl-v"><em class="crit">{{ tk.critical }}</em>/<em class="high">{{ tk.high }}</em></span>
        </div>
        <div v-if="!rows.length" class="tl-none">{{ t('screen.noTask') }}</div>
      </div>
    </template>
    <template v-else>
      <div class="tl-back">
        <div>{{ t('screen.cSrc') }} <b>overview.recentTasks</b></div>
        <div>{{ t('screen.cShowCount') }} <b>{{ limit }}</b></div>
        <div>{{ t('screen.cSort') }} <b>{{ sortText }}</b></div>
        <div>{{ t('screen.filter') }} <b>{{ (card.filterStatus || 'all') === 'all' ? t('screen.cAll') : statusName(card.filterStatus) }}</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, watch } from 'vue'
import { useShared } from './dashData.js'
import { t } from '../../i18n'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const S = useShared()
// 状态名本地化(响应式)
const STATUS_KEY = { pending: 'cfgPending', running: 'cfgRunning', done: 'cfgDone', error: 'cfgError' }
function statusName(s) { const k = STATUS_KEY[s]; return k ? t('screen.' + k) : s }
// 后端 ScanTask 状态 → 卡片四态(与漏扫任务卡同口径)
const MAP = { success: 'done', done: 'done', failed: 'error', error: 'error', running: 'running', sent: 'running', pending: 'pending', cancelled: 'error' }

const limit = computed(() => props.card.limit || 5)
const sortText = computed(() => {
  const k = ({ time: 'cfgSortTime', progress: 'cfgSortProgress' }[props.card.sortBy] || 'cfgSortTime')
  return t('screen.' + k)
})

const source = computed(() => {
  void S.updatedAt
  const list = (S.ov && S.ov.recentTasks) || []
  if (!list.length) return (props.card.tasks || []).map((t, i) => Object.assign({ id: 'st' + i }, t))
  return list.map(t => ({
    id: t.id,
    title: (t.target || t.type || t('screen.taskTitle')),
    status: MAP[t.status] || 'pending',
    // recentTasks 不带漏洞计数/进度, 如实留 0 —— 不编造数字
    critical: 0, high: 0,
    progress: t.status === 'success' || t.status === 'done' ? 100 : (t.status === 'running' ? 50 : 0),
    at: t.createdAt || '',
  }))
})
const rows = computed(() => {
  let arr = source.value.slice()
  const f = props.card.filterStatus || 'all'
  if (f !== 'all') arr = arr.filter(t => t.status === f)
  if ((props.card.sortBy || 'time') === 'progress') arr.sort((a, b) => b.progress - a.progress)
  else arr.sort((a, b) => String(b.at || '').localeCompare(String(a.at || '')))
  return arr.slice(0, limit.value)
})
// 2026-10-02: 状态筛选选项 = 卡内任务列表里真实存在的状态(只含存在的)
const statusOpts = computed(() => ['pending', 'running', 'done', 'error'].filter(s => source.value.some(t => t.status === s)))
watch(source, () => {
  const f = props.card.filterStatus || 'all'
  if (f !== 'all' && !statusOpts.value.includes(f)) props.card.filterStatus = 'all'
})
function setCfg(k, v) { props.card[k] = v }
</script>

<style scoped>
.tl { height: 100%; box-sizing: border-box; padding: 10px 12px; display: flex; flex-direction: column; gap: 6px; }
.tl-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.tl-title { font-size: 12.5px; color: #eaf1fb; font-weight: 600; }
.tl-filter { font-size: 11px; padding: 2px 6px; border-radius: 5px; color: #cdd6e4; background: rgba(255, 255, 255, .06); border: 1px solid rgba(56, 132, 255, .3); }
.tl-list { flex: 1; min-height: 0; display: flex; flex-direction: column; gap: 4px; overflow: hidden; }
.tl-row { display: flex; align-items: center; gap: 7px; font-size: 11.5px; color: #cdd6e4; padding: 3px 4px; border-radius: 5px; }
.tl-row:hover { background: rgba(56, 132, 255, .1); }
.tl-dot { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto; background: #94a3b8; box-shadow: 0 0 6px currentColor; }
.tl-row.s-running .tl-dot { background: #3884ff; }
.tl-row.s-done .tl-dot { background: #34d399; }
.tl-row.s-error .tl-dot { background: #f87171; animation: tlBlink 1s steps(2, start) infinite; }
.tl-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tl-badge { font-size: 10px; color: #8295b0; flex: 0 0 auto; }
.tl-bar { width: 54px; height: 5px; border-radius: 999px; background: rgba(255, 255, 255, .08); overflow: hidden; flex: 0 0 auto; }
.tl-bar b { display: block; height: 100%; background: var(--accent); }
.tl-row.s-done .tl-bar b { background: #34d399; }
.tl-row.s-error .tl-bar b { background: #f87171; }
.tl-v { font-size: 10px; color: #64748b; flex: 0 0 auto; font-variant-numeric: tabular-nums; }
.tl-v em { font-style: normal; }
.tl-v em.crit { color: #fca5a5; } .tl-v em.high { color: #fcd34d; }
.tl-none { font-size: 11.5px; color: #475569; padding: 6px 0; }
.tl-back { padding: 10px; display: flex; flex-direction: column; gap: 6px; font-size: 12px; color: #b9c6db; }
.tl-back b { color: #eaf1fb; }
@keyframes tlBlink { 0% { opacity: 1; } 50% { opacity: .35; } 100% { opacity: 1; } }
</style>
