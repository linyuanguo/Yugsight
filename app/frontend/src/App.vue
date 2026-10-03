<template>
  <!-- 不套主布局的页: /login 与 meta.full 全屏路由(下方 isFull 判定)。
       注: /bigscreen-pro 已于 2026-09-27 改为套 Layout 外壳的站内页(保留菜单/顶栏),
       其真正浏览器全屏由页内「一键全屏」按钮触发; 仪表盘内嵌的安全大屏 Tab2 不受影响。 -->
  <router-view v-if="isFull" />
  <Layout v-else><router-view /></Layout>
</template>

<script setup>
import { computed, onMounted, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import Layout from './components/Layout.vue'
import { setFsIntent } from './fullscreen.js'

const route = useRoute()
const isFull = computed(() => route.meta.full === true || route.path === '/login')

// 全局全屏监听(2026-09-29): 文档级全屏跨站内页保持, 沉浸式类名(隐藏侧栏/顶栏)
// 与"全屏意图"在这里全局维护 —— 即使切到没有全屏按钮的页面, 按 ESC 退出时
// 类名还原与意图清除都不丢(页内监听随卸载而失效, 全局监听终身有效)。
const onFsChange = () => {
  const on = !!document.fullscreenElement
  try { document.body.classList.toggle('bpro-immersive', on) } catch (e) { /* 忽略 */ }
  if (!on) setFsIntent(false)   // 文档级全屏: 站内切页不会触发退出, 到这里必是用户主动退出
}
onMounted(() => {
  document.addEventListener('fullscreenchange', onFsChange)
  onFsChange()   // 首帧同步(如带全屏态进入应用)
})
onBeforeUnmount(() => document.removeEventListener('fullscreenchange', onFsChange))
</script>
