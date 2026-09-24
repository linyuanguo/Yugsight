<template>
  <!-- 登录页不套主布局; 阶段 4 起安全大屏已并入首页仪表盘 Tab2(不再有独立 full 页),
       meta.full 判断保留以兼容未来的全屏路由 -->
  <router-view v-if="isFull" />
  <Layout v-else><router-view /></Layout>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import Layout from './components/Layout.vue'

const route = useRoute()
const isFull = computed(() => route.meta.full === true || route.path === '/login')
</script>
