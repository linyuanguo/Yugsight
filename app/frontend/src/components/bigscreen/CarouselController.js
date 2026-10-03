// 模板自动轮播控制(2026-09-28)。
//
// 设计要点:
//  - 轮播的是"模板", 不是卡片内容 —— 与模板只管布局的定位一致;
//  - 三处必须暂停: ① 编辑模式(你在摆位置, 画面自己跳走没法干活) ② 用户刚操作过画布
//    (操作后延时恢复, 免得刚拖好的卡被切走) ③ 出现高危告警(要停下来让人看清楚);
//  - 暂停用"计数式"而不是布尔: 多处原因可能同时要求暂停, 任一原因解除就恢复会误播。
//    这里用 reasons Set + 延时恢复计时器组合。

// 2026-10-04 i18n: 档位文案键值化, BigScreenPro 渲染期 t() 解析
export const INTERVALS = [
  { v: 30, t: 'bpro.iv30' }, { v: 60, t: 'bpro.iv60' },
  { v: 180, t: 'bpro.iv180' }, { v: 300, t: 'bpro.iv300' },
]

export function createCarousel(opts) {
  const { getList, onSwitch, getInterval, canPlay, onState } = opts
  let timer = null
  let idx = 0
  let playing = false
  const reasons = new Set()
  let resumeT = null
  let state = { playing: false, idx: 0, reason: '' }

  function emit() {
    state = { playing, idx, reason: Array.from(reasons).join(',') }
    if (onState) onState(state)
  }
  function list() { return (getList && getList()) || [] }

  function tick() {
    const l = list()
    if (l.length < 2) return
    idx = (idx + 1) % l.length
    if (onSwitch) onSwitch(l[idx].id)
    emit()
  }
  function restart() {
    stopTimer()
    if (!playing || reasons.size || !canPlay || !canPlay()) { emit(); return }
    const l = list()
    if (l.length < 2) { emit(); return }
    timer = setInterval(tick, Math.max(5, getInterval() || 60) * 1000)
    emit()
  }
  function stopTimer() { if (timer) { clearInterval(timer); timer = null } }

  return {
    start() { playing = true; restart() },
    stop() { playing = false; stopTimer(); emit() },
    // 立即暂停(编辑模式/高危告警), 不带延时恢复
    hold(reason) { reasons.add(reason || 'hold'); stopTimer(); emit() },
    release(reason) {
      reasons.delete(reason || 'hold')
      if (!reasons.size) restart()
      else emit()
    },
    // 交互暂停: 操作结束后 delayMs 自动恢复(默认 30s, 够看完又不至于一直停)
    touch(delayMs = 30000) {
      reasons.add('interact')
      stopTimer()
      emit()
      if (resumeT) clearTimeout(resumeT)
      resumeT = setTimeout(() => { reasons.delete('interact'); resumeT = null; restart() }, delayMs)
    },
    next() {
      const l = list()
      if (l.length < 2) return
      idx = (idx + 1) % l.length
      if (onSwitch) onSwitch(l[idx].id)
      restart()
    },
    prev() {
      const l = list()
      if (l.length < 2) return
      idx = (idx - 1 + l.length) % l.length
      if (onSwitch) onSwitch(l[idx].id)
      restart()
    },
    setIndex(i) { idx = i; restart() },
    dispose() { stopTimer(); if (resumeT) clearTimeout(resumeT) },
    get state() { return state },
  }
}

// ===== 轮播配置持久化(参与轮播的模板ID列表 + 间隔秒) =====
// 由 BigScreenPro 读写; 抽到这里集中管理 key/结构, 便于一处维护。
export const CAR_KEY = 'yugsight_bpro_carousel'
export function loadCarCfg() {
  try {
    const o = JSON.parse(localStorage.getItem(CAR_KEY) || 'null')
    return (o && typeof o === 'object') ? o : null
  } catch (e) { return null }
}
export function saveCarCfg(cfg) {
  try { localStorage.setItem(CAR_KEY, JSON.stringify(cfg)) } catch (e) { /* 忽略 */ }
  return cfg
}
