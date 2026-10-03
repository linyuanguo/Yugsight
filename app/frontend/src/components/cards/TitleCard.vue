<template>
  <!-- 标题卡(2026-09-27): 分区标注用途, 正面大标题 + 装饰条, 背面为说明。 -->
  <div class="tc">
    <template v-if="side === 'front'">
      <span class="tc-bar"></span>
      <span class="tc-text">{{ t(card.title) }}</span>
    </template>
    <div v-else class="tc-note">{{ t('screen.titleNote') }}</div>
  </div>
</template>

<script setup>
import { t } from '../../i18n'
defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
})
</script>

<style scoped>
.tc { height: 100%; box-sizing: border-box; display: flex; align-items: center; gap: 14px; padding: 0 20px; }
.tc-bar { width: 6px; height: 58%; border-radius: 3px; background: linear-gradient(var(--accent), transparent); box-shadow: 0 0 12px var(--accent); }
.tc-text { font-size: 26px; font-weight: 800; letter-spacing: 2px; color: #eaf1fb; text-shadow: 0 2px 10px rgba(56, 132, 255, .4); }
.tc-note { color: #8295b0; font-size: 13px; padding: 14px; }
</style>
