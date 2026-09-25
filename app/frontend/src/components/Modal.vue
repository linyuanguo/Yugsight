<template>
  <!-- show 默认 true: 既有调用方全部用 v-if 控制显隐(不传 show), 补上属性后行为不变;
       AiAnalyzeButton 用 :show="!!result" 依赖此属性, 缺失时弹窗一挂载就弹出(空框) -->
  <div v-if="show" class="modal-mask" @click.self="$emit('close')">
    <div class="modal" :style="{ width: width }">
      <div class="modal-head">
        <span>{{ title }}</span>
        <button class="x" @click="$emit('close')">×</button>
      </div>
      <div class="modal-body"><slot /></div>
      <div class="modal-foot" v-if="$slots.footer"><slot name="footer" /></div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  title: { type: String, required: true },
  width: { type: String, default: '520px' },
  show: { type: Boolean, default: true }
})
defineEmits(['close'])
</script>
