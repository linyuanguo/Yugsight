<template>
  <div class="toolbar">
    <div style="font-size: 16px; font-weight: 700;">{{ title }}</div>
    <div class="muted small" v-if="desc">{{ desc }}</div>
    <div class="spacer"></div>
    <slot />
  </div>
</template>

<script setup>
defineProps({
  title: { type: String, required: true },
  desc: { type: String, default: '' }
})
</script>
