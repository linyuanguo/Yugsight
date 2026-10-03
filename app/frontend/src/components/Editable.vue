<script setup>
// 就地编辑块(2026-09-26 用户要求: 模板编辑要"像 WPS 一样"直接在版面上改, 而不是
// 左侧一堆输入框)。与 RichText 的区别: 本组件**不带自己的工具条**, 外观完全交给
// 父级(透明融入 A4 页面), 由页面顶部统一的工具条对当前焦点元素下命令。
//
// 实现口径与 RichText 一致(避免踩过的坑):
//   - DOM 是编辑源, input/blur 时把 innerHTML emit 出去; 不绑 Vue 文本插值 ——
//     状态变化会重写文本节点把光标冲掉。
//   - 初始内容: 含标签用 innerHTML(值来自服务端清洗过的白名单片段), 纯文本用
//     textContent。
//   - 外部值变化(加载模板/重置)时才回写 DOM, 且先比对 —— 否则自己 emit 的值
//     回流会触发回写, 把光标顶到末尾。
import { ref, watch, nextTick } from 'vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  placeholder: { type: String, default: '' }
})
const emit = defineEmits(['update:modelValue'])
const box = ref(null)

function write(v) {
  if (!box.value) return
  if (box.value.innerHTML === (v || '')) return
  if (/<[a-z][^>]*>/i.test(v || '')) box.value.innerHTML = v
  else box.value.textContent = v || ''
}

watch(() => props.modelValue, (v) => write(v), { immediate: true })
nextTick(() => write(props.modelValue))

function sync() {
  if (box.value) emit('update:modelValue', box.value.innerHTML)
}
defineExpose({ focus: () => box.value?.focus() })
</script>

<template>
  <div
    class="ed"
    ref="box"
    contenteditable="true"
    spellcheck="false"
    :data-ph="placeholder"
    @input="sync"
    @blur="sync"
  ></div>
</template>

<style scoped>
.ed {
  outline: none;
  border-radius: 3px;
  /* 空值时保留占位高度, 否则页面会因为空块塌下去, 看不出那里能编辑 */
  min-height: 1em;
  cursor: text;
  transition: box-shadow .12s;
}
.ed:hover { box-shadow: 0 0 0 1px rgba(148, 163, 184, .5); }
.ed:focus { box-shadow: 0 0 0 2px rgba(56, 189, 248, .55); }
/* 空块显示灰色占位提示(父级传 data-ph); 有内容时不显示 */
.ed:empty::before {
  content: attr(data-ph);
  color: #9ca3af;
  pointer-events: none;
}
</style>
