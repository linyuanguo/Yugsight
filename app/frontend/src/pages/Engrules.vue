<template>
  <div>
    <!-- 合并页 tab(UX 审计 §5.2: 引擎状态 + 规则库管理 -> 引擎与规则)。
         tab 状态放在 URL query 上而不是组件内变量: 刷新/书签/手工输入 URL 都能停在同一个 tab,
         不会因为回到浏览器 tab 就跳回引擎页。 -->
    <div class="tabs">
      <div class="tab" :class="{ active: tab === 'engine' }" @click="setTab('engine')">引擎</div>
      <div class="tab" :class="{ active: tab === 'rules' }" @click="setTab('rules')">规则</div>
    </div>
    <!-- 不用 keep-alive: 切 tab 重新挂载会从服务端重拉最新状态。
         EnvStatus/Rules 两个页面都实现了"服务端仍有任务在跑时自动接续轮询",
         所以中途切走再切回来, 进度不会断。 -->
    <EnvStatus v-if="tab === 'engine'" />
    <Rules v-else />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import EnvStatus from './EnvStatus.vue'
import Rules from './Rules.vue'

const route = useRoute()
const router = useRouter()

// 只有 'rules' 是规则 tab, 其它取值(含空)一律落到引擎 tab —— 旧书签 /env 不会失效
const tab = computed(() => (route.query.tab === 'rules' ? 'rules' : 'engine'))

// replace 而非 push: 切 tab 不该往历史栈里堆记录(浏览器后退应是"离开本页", 不是"回到上一个 tab")
function setTab(t) {
  if (t === tab.value) return
  router.replace({ path: '/env', query: t === 'rules' ? { tab: 'rules' } : {} })
}
</script>
