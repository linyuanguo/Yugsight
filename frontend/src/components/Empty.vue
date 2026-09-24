<template>
  <div class="empty">
    <div class="big">{{ icon || '∅' }}</div>
    <div>{{ text }}</div>
  </div>
</template>

<script setup>
defineProps({
  text: { type: String, default: '暂无数据' },
  icon: { type: String, default: '∅' }
})
</script>
