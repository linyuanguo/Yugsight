<template>
  <span class="badge" :class="cls">{{ name }}</span>
</template>

<script setup>
import { computed } from 'vue'
import { SEV_NAME, SEV_CLASS } from '../utils'

const props = defineProps({ sev: { type: String, default: 'info' } })
const cls = computed(() => SEV_CLASS[String(props.sev).toLowerCase()] || 'sev-info')
const name = computed(() => SEV_NAME[String(props.sev).toLowerCase()] || props.sev || '信息')
</script>
