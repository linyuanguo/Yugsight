<script setup>
// AiAnalyzeButton 业务页"AI 分析"按钮(阶段 3 全链路分析的触发入口)。
//
// 职责边界(用户口径): AI 分析按钮**只出现在业务页面**(实时抓包/扫描
// 作业/弱口令检测/节点监控告警), 不在 AI 配置页触发 —— 配置页只管
// 参数/模板/文档库/记忆库。本组件是四个业务页共用的触发器:
//
//   1. 读 /api/ai 的 enabled + modules 决定置灰(模块开关关闭 = 按钮
//      disabled + 悬浮提示, 与"关闭开关按钮置灰"的口径一致);
//   2. 点击 → POST /api/ai/analyze {reportId?} / {module?};
//   3. 研判结果回写报告中心(raw_reports 的 ai 三字段), 弹窗展示并
//      提供"报告中心查看"入口。
//
// props:
//   module    业务模块: capture / scan / weakpass / monitor / collect
//   reportId  可选, 指定报告则分析该报告(不传 = 后端按模块取现场/最近)
//   before    可选, 分析前钩子(如抓包页"先停止抓包再分析"), 抛错则中止
import { ref, onMounted, computed } from 'vue'
import { api } from '../api/http'
import Modal from './Modal.vue'

const props = defineProps({
  module: { type: String, required: true },
  reportId: { type: String, default: '' },
  label: { type: String, default: 'AI 分析' },
  before: { type: Function, default: null }
})

// 模块 → 开关键(弱口令复用 scan 开关; 节点采集复用 monitor 开关)
const switchKey = computed(() => {
  if (props.module === 'capture') return 'capture'
  if (props.module === 'monitor' || props.module === 'collect') return 'monitor'
  return 'scan'
})

const st = ref(null)
const busy = ref(false)
const result = ref(null)
const err = ref('')

async function loadStatus() {
  try {
    st.value = await api('/api/ai')
  } catch {
    st.value = null // 读不到状态按"不可用"处理(按钮置灰), 不弹窗打扰
  }
}
onMounted(loadStatus)

// 可用 = 全局开启 且 对应模块开关开启
const usable = computed(() =>
  !!(st.value && st.value.enabled && st.value.modules && st.value.modules[switchKey.value])
)
const disabledTip = computed(() => {
  if (!st.value) return 'AI 状态读取失败'
  if (!st.value.enabled) return 'AI 未启用(系统配置 → AI 配置 → 测试并保存)'
  return '该模块的 AI 分析已被管理员关闭(系统配置 → AI 配置 → 模块总开关)'
})

function stopEvent(e) { e.stopPropagation() }

async function analyze() {
  if (busy.value || !usable.value) return
  busy.value = true
  err.value = ''
  result.value = null
  const t0 = Date.now()
  try {
    if (props.before) {
      await props.before() // 前置动作失败(抛错)则不发起分析
    }
    const body = props.reportId ? { reportId: props.reportId } : { module: props.module }
    const d = await api('/api/ai/analyze', { method: 'POST', body: JSON.stringify(body) })
    d.elapsed = Date.now() - t0
    result.value = d
  } catch (e) {
    err.value = e.message || 'AI 分析失败'
  } finally {
    busy.value = false
    loadStatus() // 分析不改变开关, 但状态缓存无成本, 保持一致
  }
}
defineExpose({ analyze, usable, busy, st })

function fmtAI(d) {
  if (!d) return {}
  try {
    return typeof d === 'string' ? JSON.parse(d) : d
  } catch {
    return {}
  }
}
</script>

<template>
  <span>
    <button class="btn sm" :title="usable ? '' : disabledTip" :disabled="busy || !usable" @click="analyze" @mousedown.stop="stopEvent">
      <span class="spinner" v-if="busy"></span>
      {{ busy ? 'AI 分析中…' : label }}
    </button>
    <div class="ai-err" v-if="err">{{ err }}</div>

    <Modal :show="!!result" title="AI 分析结果" width="720px" @close="result = null">
      <template v-if="result">
        <div class="ai-meta">
          <span class="chip on">分析完成</span>
          <span class="muted small mono">
            {{ result.template || '' }} · {{ result.model || '' }} · 耗时 {{ Math.round((result.elapsed || 0) / 1000) }}s
          </span>
          <span class="muted small" v-if="result.ragHits">RAG 参考 {{ result.ragHits }} 条</span>
          <span class="muted small" v-if="result.memoryItems">历史记忆 {{ result.memoryItems }} 条</span>
          <div class="spacer"></div>
          <span class="muted small mono" v-if="result.reportId">报告: {{ result.reportId }}</span>
        </div>
        <pre class="ai-note">{{ result.aiNote }}</pre>
        <details class="ai-data" v-if="result.aiData">
          <summary class="muted small">分析元数据(模型/模板/RAG/记忆, 存报告中心)</summary>
          <pre class="mono small">{{ JSON.stringify(fmtAI(result.aiData), null, 2) }}</pre>
        </details>
        <div class="muted small">研判结果已存入报告中心对应报告(原始数据 + AI 研判可同时查看)。</div>
      </template>
      <template #footer>
        <button class="btn" @click="result = null">关闭</button>
        <router-link class="btn primary" to="/reports">去报告中心查看</router-link>
      </template>
    </Modal>
  </span>
</template>

<style scoped>
.ai-err {
  color: var(--danger, #e5484d);
  font-size: 12px;
  margin-top: 4px;
}
.ai-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}
.ai-note {
  background: var(--bg2, #101318);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 13px;
  line-height: 1.75;
  max-height: 420px;
  overflow: auto;
}
.ai-data {
  margin-top: 8px;
}
.ai-data summary {
  cursor: pointer;
  user-select: none;
}
.ai-data pre {
  margin-top: 6px;
  background: var(--bg2, #101318);
  border-radius: 6px;
  padding: 8px;
  max-height: 200px;
  overflow: auto;
}
</style>
