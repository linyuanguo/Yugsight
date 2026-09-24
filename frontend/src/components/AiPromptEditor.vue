<script setup>
// AiPromptEditor Prompt 模板编辑器: 透明 textarea 叠在高亮 pre 之上,
// {{变量}} 以彩色 token 呈现(语法高亮的最小实现, 零依赖)。
//
// 为什么不用 contenteditable/第三方编辑器: 模板是纯文本数据, 只需要
// "变量一眼可辨"; 双层同步方案(textarea 负责输入, pre 负责着色)是最
// 小可靠实现 —— 输入永远落在 textarea, 不丢焦点、无 HTML 注入面。
import { computed, ref } from 'vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  height: { type: String, default: '300px' },
  vars: { type: Array, default: () => [] } // 内置变量名(着色 + 悬停提示)
})
const emit = defineEmits(['update:modelValue'])

// 转义后把 {{var}} 包进 span —— 注意先转义再匹配, 防止用户输入 HTML
// 标签被浏览器当结构解析(内容进 DOM 的路径只有 v-html 这一条)。
const highlighted = computed(() => {
  let h = props.modelValue
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
  h = h.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (m, name) => {
    const known = props.vars.includes(name)
    return `<span class="phe-var${known ? '' : ' unknown'}">${m}</span>`
  })
  return h
})

const taEl = ref(null)
const hlEl = ref(null)

function onInput(e) {
  emit('update:modelValue', e.target.value)
}
// 滚动同步: 用户滚 textarea 时高亮层跟着滚(内容逐字一致, 偏移对齐)
function syncScroll(e) {
  if (hlEl.value) {
    hlEl.value.scrollTop = e.target.scrollTop
    hlEl.value.scrollLeft = e.target.scrollLeft
  }
}
</script>

<template>
  <div class="phe" :style="{ height }">
    <pre ref="hlEl" class="phe-hl" v-html="highlighted"></pre>
    <textarea
      ref="taEl"
      class="phe-ta"
      :value="modelValue"
      spellcheck="false"
      wrap="off"
      @input="onInput"
      @scroll="syncScroll"
    ></textarea>
  </div>
</template>

<style scoped>
.phe {
  position: relative;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg2, #101318);
  overflow: hidden;
}
.phe-hl,
.phe-ta {
  margin: 0;
  padding: 10px 12px;
  font-family: ui-monospace, Consolas, 'Courier New', monospace;
  font-size: 12.5px;
  line-height: 1.7;
  white-space: pre;
  overflow: auto;
  tab-size: 4;
}
.phe-hl {
  position: absolute;
  inset: 0;
  pointer-events: none;
  color: var(--text, #d7dbe0);
}
.phe-ta {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  background: transparent;
  color: transparent;
  caret-color: #7aa2f7;
  border: none;
  resize: none;
  outline: none;
}
.phe-ta::selection {
  background: rgba(122, 162, 247, 0.25);
}
.phe-var {
  color: #7aa2f7;
  background: rgba(122, 162, 247, 0.12);
  border-radius: 3px;
  padding: 0 2px;
}
.phe-var.unknown {
  color: var(--warning, #f0b429);
  background: rgba(240, 180, 41, 0.1);
}
</style>
