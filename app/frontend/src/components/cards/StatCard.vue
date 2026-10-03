<template>
  <!-- 统计汇总卡(2026-09-27): 实时聚合画布内所有漏扫任务卡的真实状态计数。 -->
  <div class="sc">
    <div class="sc-title">{{ card.title }}</div>
    <div class="sc-total">{{ s.total }}<small>个任务</small></div>
    <div class="sc-rows">
      <span class="r running">执行中 {{ s.running }}</span>
      <span class="r done">已完成 {{ s.done }}</span>
      <span class="r error">异常 {{ s.error }}</span>
      <span class="r pending">待执行 {{ s.pending }}</span>
    </div>
    <div class="sc-vuln">高危漏洞合计：<b class="crit">{{ s.crit }}</b> / <b class="high">{{ s.high }}</b></div>
  </div>
</template>

<script setup>
import { inject, ref, computed } from 'vue'

defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
})

// 聚合画布内漏扫任务卡(由 BigScreenPro 经 provide 注入)
const cards = inject('bproCards', ref([]))
const s = computed(() => {
  const scans = cards.value.filter(c => c.type === 'scan')
  return {
    total: scans.length,
    running: scans.filter(c => c.status === 'running').length,
    done: scans.filter(c => c.status === 'done').length,
    error: scans.filter(c => c.status === 'error').length,
    pending: scans.filter(c => c.status === 'pending').length,
    crit: scans.reduce((a, c) => a + (c.vulns?.critical || 0), 0),
    high: scans.reduce((a, c) => a + (c.vulns?.high || 0), 0),
  }
})
</script>

<style scoped>
.sc { height: 100%; box-sizing: border-box; padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; justify-content: center; }
.sc-title { font-size: 14px; color: #9fb0c8; letter-spacing: 1px; }
.sc-total { font-size: 40px; font-weight: 800; color: #eaf1fb; line-height: 1; }
.sc-total small { font-size: 13px; font-weight: 500; color: #8295b0; margin-left: 6px; }
.sc-rows { display: flex; flex-wrap: wrap; gap: 8px; }
.sc-rows .r { font-size: 12px; padding: 3px 10px; border-radius: 999px; background: rgba(255, 255, 255, .05); color: #cdd6e4; }
.sc-rows .running { color: #7dd3fc; } .sc-rows .done { color: #6ee7b7; }
.sc-rows .error { color: #fca5a5; } .sc-rows .pending { color: #cbd5e1; }
.sc-vuln { font-size: 12.5px; color: #93a4bd; }
.sc-vuln .crit { color: #fca5a5; } .sc-vuln .high { color: #fcd34d; }
</style>
