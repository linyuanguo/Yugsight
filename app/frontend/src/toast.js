// 全局轻量 toast(2026-09-28 节点监控推送配置引入): 按需创建挂载点,
// 不在 main.js 注册全局组件 —— 前端是单文件 exe 嵌入部署形态, 侵入 main.js
// 只会增加无谓的耦合。多个 toast 纵向堆叠, 超时自动消失, 点击立即关闭。
// type: ok(绿) | err(红) | info(蓝)
import { t } from './i18n'

let wrap = null

function ensureWrap() {
  if (wrap && document.body.contains(wrap)) return wrap
  wrap = document.createElement('div')
  wrap.className = 'ys-toast-wrap'
  document.body.appendChild(wrap)
  return wrap
}

export function toast(msg, type = 'ok', ms = 2600) {
  try {
    const el = document.createElement('div')
    el.className = 'ys-toast' + (type === 'err' ? ' ys-toast-err' : type === 'info' ? ' ys-toast-info' : '')
    el.textContent = msg
    el.title = t('common.clickClose')
    el.addEventListener('click', () => el.remove())
    ensureWrap().appendChild(el)
    setTimeout(() => {
      el.classList.add('ys-toast-out')
      setTimeout(() => el.remove(), 220)
    }, ms)
  } catch (e) { /* 展示失败不影响业务 */ }
}
