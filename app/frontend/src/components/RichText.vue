<script setup>
// 迷你富文本编辑器(2026-09-25 用户: 报告模板字段要"像 Word 一样"编辑字体
// 颜色/底色/格式)。零依赖: contenteditable + document.execCommand 小白名单。
//
// 数据流与 WYSIWYG 白纸区同口径: DOM 是编辑源, input/blur 时 emit innerHTML;
// 不绑 Vue 文本插值(状态变化会重写文本节点冲掉光标)。初始内容在挂载时写入:
// 纯文本用 textContent, 富文本(含标签)用 innerHTML(值来自服务端已清洗的
// 白名单片段, 无注入面)。
import { ref, nextTick } from 'vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  placeholder: { type: String, default: '' },
  disabled: { type: Boolean, default: false }
})
const emit = defineEmits(['input'])

const box = ref(null)
const colorInput = ref(null)
const bgInput = ref(null)

function mount() {
  nextTick(() => {
    if (!box.value) return
    const v = props.modelValue || ''
    if (/<[a-z][^>]*>/i.test(v)) {
      box.value.innerHTML = v // 富文本回显(服务端已清洗)
    } else {
      box.value.textContent = v
    }
  })
}
function sync() {
  if (box.value) emit('input', box.value.innerHTML)
}
function cmd(name, val) {
  box.value?.focus()
  try { document.execCommand(name, false, val) } catch (e) { /* 个别命令不可用不阻断 */ }
  sync()
}
function pickColor() {
  if (colorInput.value) colorInput.value.click()
}
function pickBg() {
  if (bgInput.value) bgInput.value.click()
}
function onColor(e) {
  const v = e.target.value
  if (v) cmd('foreColor', v)
}
function onBg(e) {
  const v = e.target.value
  if (v) {
    // 背景色: Chrome 用 hiliteColor, 老浏览器 backColor
    if (!document.execCommand('hiliteColor', false, v)) {
      document.execCommand('backColor', false, v)
    }
    sync()
  }
}
function onSize(e) {
  const v = e.target.value
  if (v) cmd('fontSize', v)
  e.target.value = ''
}
mount()
</script>

<template>
  <div class="rt" :class="{ dis: disabled }">
    <div class="rt-bar" v-if="!disabled">
      <button type="button" title="加粗" @mousedown.prevent @click="cmd('bold')"><b>B</b></button>
      <button type="button" title="斜体" @mousedown.prevent @click="cmd('italic')"><i>I</i></button>
      <button type="button" title="下划线" @mousedown.prevent @click="cmd('underline')"><u>U</u></button>
      <button type="button" class="rt-color" title="字体颜色" @mousedown.prevent @click="pickColor">
        <span class="rt-color-sw"></span>字色
      </button>
      <button type="button" class="rt-bg" title="背景色" @mousedown.prevent @click="pickBg">
        <span class="rt-bg-sw"></span>底色
      </button>
      <select class="rt-size" title="字号" @change="onSize">
        <option value="">字号</option>
        <option value="2">小</option>
        <option value="3">中</option>
        <option value="4">大</option>
        <option value="5">特大</option>
      </select>
      <input type="color" ref="colorInput" value="#c00000" @input="onColor" tabindex="-1" aria-hidden="true">
      <input type="color" ref="bgInput" value="#ffff00" @input="onBg" tabindex="-1" aria-hidden="true">
    </div>
    <div
      class="rt-box"
      :contenteditable="!disabled"
      :data-ph="placeholder"
      ref="box"
      @input="sync"
      @blur="sync"
    ></div>
  </div>
</template>

<style scoped>
.rt { border: 1px solid var(--line, #e5e7eb); border-radius: 8px; background: #fff; overflow: hidden; }
.rt.dis { opacity: .6; }
.rt-bar {
  display: flex; align-items: center; gap: 2px; padding: 3px 6px;
  background: #f8fafc; border-bottom: 1px solid var(--line, #e5e7eb);
}
.rt-bar button {
  border: 1px solid transparent; background: transparent; border-radius: 4px;
  min-width: 26px; height: 24px; cursor: pointer; font-size: 12.5px; color: #374151;
  display: inline-flex; align-items: center; justify-content: center; gap: 3px;
  padding: 0 5px;
}
.rt-bar button:hover { border-color: var(--line, #d1d5db); background: #eef2ff; }
.rt-size {
  border: 1px solid var(--line, #d1d5db); border-radius: 4px; height: 24px;
  font-size: 12px; color: #374151; background: #fff; cursor: pointer;
}
input[type="color"] { position: absolute; width: 0; height: 0; opacity: 0; pointer-events: none; }
.rt-color-sw, .rt-bg-sw { width: 12px; height: 12px; border-radius: 3px; border: 1px solid #d1d5db; display: inline-block; }
.rt-color-sw { background: linear-gradient(90deg, #c00000, #0000ff, #008000); }
.rt-bg-sw { background: linear-gradient(90deg, #ffff00, #c0c0c0); }
.rt-box {
  padding: 7px 10px; min-height: 34px; outline: none; font-size: 13.5px;
  color: #1f2937; line-height: 1.6; word-break: break-all;
}
.rt-box:empty::before { content: attr(data-ph); color: #9ca3af; }
.rt-box:focus { box-shadow: inset 0 0 0 2px rgba(56, 189, 248, .3); }
</style>
