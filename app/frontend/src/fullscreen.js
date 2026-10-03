// ===== 全屏意图持久化(2026-09-29 用户要求) =====
//
// 旧口径(废): 各页「一键全屏」用元素级(rootEl.requestFullscreen), 且页面
// onBeforeUnmount 强制 exitFullscreen() —— 站内切页(大屏 ↔ 拓扑页)或刷新
// 全屏全丢, 退回"浏览器里的小屏"。用户明确要求: 没主动退出全屏, 切页/刷新
// /切卡片模板都要保持全屏。
//
// 新口径:
//  1. 文档级全屏(document.documentElement): SPA 站内导航时 <html> 不卸载,
//     全屏天然跨页保持 —— 大屏 ↔ 拓扑页互切不退出。
//  2. localStorage 记住"全屏意图"(yugsight_fullscreen_intent): 刷新会清空
//     浏览器全屏状态, 而浏览器安全策略要求进入全屏必须有用户手势(无法在
//     onMounted 静默进入) → 页面挂载时挂一次性手势监听, 刷新后首次点击/
//     按键即自动恢复全屏。
//  3. fullscreenchange 到"无全屏元素"= 用户主动退出(ESC / 退出按钮; 文档级
//     全屏下站内切页不会再触发退出) → App.vue 全局监听清除意图, 之后刷新
//     不再自动进入。
//
// body.bpro-immersive 类(隐藏侧栏/顶栏的沉浸式外观)由 App.vue 全局监听维护 ——
// 全屏跨页后无论停在哪个页面, 外观与意图都一致; 页面只管自己按钮的 isFs 状态。

const LS_FS = 'yugsight_fullscreen_intent'

export function fsIntent() {
  try { return localStorage.getItem(LS_FS) === '1' } catch (e) { return false }
}

export function setFsIntent(on) {
  try { localStorage.setItem(LS_FS, on ? '1' : '0') } catch (e) { /* 忽略: 隐私模式等 */ }
}

// 文档级进入全屏(元素级会在切页 unmount 时随元素销毁被浏览器强制退出)
export function enterFullscreen() {
  const el = document.documentElement
  if (!el || !el.requestFullscreen) return Promise.reject(new Error('不支持全屏'))
  return el.requestFullscreen()
}

// 页面 onMounted 调用: 若"上次没退出全屏"(意图在)且当前不在全屏(典型=刚刷新),
// 等第一个用户交互(点击/按键)立即恢复全屏。返回清理函数(页面卸载时移除监听)。
// 已在全屏或无意图 → 返回 null(不挂监听)。
export function scheduleFullscreenRestore() {
  if (document.fullscreenElement || !fsIntent()) return null
  let done = false
  const go = () => {
    if (done) return
    done = true
    cleanup()
    enterFullscreen().catch(() => { /* 手势上下文被拒时静默: 用户可再点「一键全屏」 */ })
  }
  const cleanup = () => {
    window.removeEventListener('pointerdown', go)
    window.removeEventListener('keydown', go)
  }
  window.addEventListener('pointerdown', go, { once: true })
  window.addEventListener('keydown', go, { once: true })
  return cleanup
}
