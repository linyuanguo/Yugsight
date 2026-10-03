<template>
  <!-- 漏扫任务卡内容(2026-09-27): 正面=核心指标, 背面=详情。
       compact(卡片被缩小时)仅显示标题+状态徽章, 放大自动展开全字段。 -->
  <div class="st" :class="['st-' + card.status, { compact }]">
    <!-- 正面 -->
    <template v-if="side === 'front'">
      <div class="st-head">
        <span class="st-title">{{ t(card.title) }}</span>
        <span class="st-badge" :title="statusText">{{ statusText }}</span>
      </div>
      <template v-if="!compact">
        <div class="st-body">
          <div class="st-ring" :style="{ '--p': card.progress }"><span>{{ card.progress }}%</span></div>
          <div class="st-vulns">
            <b class="crit">{{ t('screen.sevCrit') }} {{ card.vulns.critical }}</b>
            <b class="high">{{ t('screen.sevHigh') }} {{ card.vulns.high }}</b>
            <b class="med">{{ t('screen.sevMid') }} {{ card.vulns.medium }}</b>
          </div>
        </div>
        <div class="st-scope">{{ t('screen.scanRange') }}{{ card.scope }}</div>
      </template>
    </template>
    <!-- 背面 -->
    <template v-else>
      <div class="st-back-title">{{ t('screen.taskDetail') }}</div>
      <ul class="st-list">
        <li><span>{{ t('screen.cfgStrategy') }}</span><b>{{ t(card.policy) }}</b></li>
        <li><span>{{ t('screen.cfgPorts') }}</span><b>{{ card.ports }}</b></li>
        <li><span>{{ t('screen.cfgDuration') }}</span><b>{{ card.duration }}</b></li>
        <li><span>{{ t('screen.cfgHistory') }}</span><b>{{ t(card.history) }}</b></li>
      </ul>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../../i18n'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
})

// 状态名本地化(响应式: computed 里调 t 随 locale 重算)
const STATUS_KEY = { pending: 'cfgPending', running: 'cfgRunning', done: 'cfgDone', error: 'cfgError' }
const statusText = computed(() => {
  const k = STATUS_KEY[props.card.status]
  return k ? t('screen.' + k) : props.card.status
})
</script>

<style scoped>
.st { height: 100%; box-sizing: border-box; padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; }
.st-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.st-title { font-size: 15px; font-weight: 600; color: #eaf1fb; letter-spacing: .5px; }
/* 3D 状态徽章: 立体高光 + 状态差异化 */
.st-badge {
  flex: 0 0 auto; width: 52px; height: 52px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; color: #fff;
  box-shadow: inset 0 2px 3px rgba(255, 255, 255, .25), inset 0 -4px 8px rgba(0, 0, 0, .45);
}
.st-running .st-badge { background: linear-gradient(145deg, #2f7bff, #0a3aa8); position: relative; overflow: hidden; }
.st-running .st-badge::after {
  content: ''; position: absolute; inset: 0;
  background: linear-gradient(110deg, transparent 30%, rgba(255, 255, 255, .5) 50%, transparent 70%);
  transform: translateX(-120%); animation: stSheen 1.8s linear infinite;
}
.st-done .st-badge { background: linear-gradient(145deg, #22c77e, #0c7a45); box-shadow: 0 5px 14px rgba(34, 199, 126, .45), inset 0 1px 2px rgba(255, 255, 255, .35); }
.st-error .st-badge { background: linear-gradient(145deg, #ff5a5c, #a3161b); animation: stBlink 1s steps(2, start) infinite; }
.st-pending .st-badge { background: linear-gradient(145deg, #3c4658, #222a38); color: #a9b8cf; box-shadow: inset 0 2px 3px rgba(255, 255, 255, .06), inset 0 -4px 8px rgba(0, 0, 0, .5); }
@keyframes stSheen { 0% { transform: translateX(-120%); } 100% { transform: translateX(120%); } }
@keyframes stBlink { 0% { opacity: 1; } 50% { opacity: .4; } 100% { opacity: 1; } }

.st-body { display: flex; align-items: center; gap: 16px; }
.st-ring {
  position: relative; width: 66px; height: 66px; border-radius: 50%; flex: 0 0 auto;
  background: conic-gradient(var(--accent) calc(var(--p, 0) * 1%), rgba(255, 255, 255, .08) 0);
  display: flex; align-items: center; justify-content: center;
}
.st-ring::before { content: ''; position: absolute; width: 50px; height: 50px; border-radius: 50%; background: #0c1424; }
.st-ring span { position: relative; font-size: 13px; font-weight: 700; color: #dbe6f5; }
.st-vulns { display: flex; flex-direction: column; gap: 6px; }
.st-vulns b { padding: 3px 10px; border-radius: 999px; font-size: 11.5px; font-weight: 600; }
.crit { background: rgba(248, 113, 113, .18); color: #fca5a5; }
.high { background: rgba(251, 191, 36, .18); color: #fcd34d; }
.med { background: rgba(56, 189, 248, .18); color: #7dd3fc; }
.st-scope { font-size: 12px; color: #93a4bd; border-top: 1px solid rgba(255, 255, 255, .06); padding-top: 8px; }

/* 背面 */
.st-back-title { font-size: 13px; color: var(--muted); letter-spacing: 1px; margin-bottom: 4px; }
.st-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
.st-list li { display: flex; justify-content: space-between; font-size: 13px; color: #b9c6db; border-bottom: 1px dashed rgba(255, 255, 255, .08); padding-bottom: 8px; }
.st-list li span { color: #8295b0; }
.st-list li b { color: #eaf1fb; font-weight: 600; }

/* 缩小精简态: 仅标题 + 状态徽章 */
.st.compact { flex-direction: row; align-items: center; justify-content: center; gap: 14px; padding: 10px; }
.st.compact .st-head { flex-direction: column; gap: 8px; }
.st.compact .st-title { font-size: 14px; }
.st.compact .st-scope, .st.compact .st-body { display: none; }
</style>
