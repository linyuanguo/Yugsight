<template>
  <span class="badge" :class="'st-' + status">{{ label }}</span>
</template>

<script setup>
import { computed } from 'vue'
import { STATUS_NAME } from '../utils'

const props = defineProps({ status: { type: String, default: 'pending' } })
const label = computed(() => STATUS_NAME[props.status] || props.status)
</script>
