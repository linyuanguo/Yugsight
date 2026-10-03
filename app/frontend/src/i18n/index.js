// i18n 核心(2026-10-03): 零依赖中英切换, 不用 vue-i18n(项目前端运行时只有
// vue + vue-router, 不引新依赖)。
//
// 机制:
// - locale 是响应式 ref, t() 在渲染期读取 → 切语言时所有用到 t() 的组件自动重渲染;
// - 选择持久化 localStorage(yugsight_lang), 默认 zh(存量用户零影响);
// - 三级回落: 当前语言缺失 → zh → 键本身(漏词条不出现空白);
// - {name} 占位符插值。
//
// 用法: import { t, locale, toggleLocale } from '../i18n'
//       模板: {{ t('menu.dashboard') }} 或 {{ t('login.faRemain', { sec: remain }) }}
import { ref } from 'vue'
import zh from './zh.js'
import en from './en.js'

const LS_KEY = 'yugsight_lang'
const dicts = { zh, en }

function initLocale() {
  try {
    const s = localStorage.getItem(LS_KEY)
    if (s === 'zh' || s === 'en') return s
  } catch { /* 隐私模式等: 走默认 */ }
  return 'zh'
}

export const locale = ref(initLocale())

export function setLocale(l) {
  if (l !== 'zh' && l !== 'en') return
  locale.value = l
  try { localStorage.setItem(LS_KEY, l) } catch { /* 存储不可用不影响切换 */ }
}

export function toggleLocale() {
  setLocale(locale.value === 'zh' ? 'en' : 'zh')
}

function lookup(dict, key) {
  const parts = String(key).split('.')
  let cur = dict
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return undefined
    cur = cur[p]
  }
  return typeof cur === 'string' ? cur : undefined
}

export function t(key, params) {
  let s = lookup(dicts[locale.value], key)
  if (s == null) s = lookup(dicts.zh, key)
  if (s == null) s = String(key)
  if (params) {
    for (const k of Object.keys(params)) {
      s = s.split('{' + k + '}').join(String(params[k]))
    }
  }
  return s
}

export default { locale, setLocale, toggleLocale, t }
