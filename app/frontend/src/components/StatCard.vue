<template>
  <div class="card stat-card" :class="'tone-' + tone">
    <div class="stat-label">{{ label }}</div>
    <div class="stat-value">{{ value }}</div>
    <div class="stat-sub" v-if="sub">{{ sub }}</div>
  </div>
</template>

<script setup>
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], default: '-' },
  sub: { type: String, default: '' },
  tone: { type: String, default: 'blue' } // blue|green|red|orange|purple|yellow
})
</script>
