// 原生 SVG 图表工具(2026-09-27 安全大屏 Pro 组件库)。
//
// 为什么手写而不引图表库: 本项目前端运行时只保留 vue + vue-router(单二进制 +
// 全资源本地化硬约束), 图表库一旦引入就会把 dist 吹大并带来 CDN/许可证风险。
// 环形/饼图/折线/柱状所需的几何其实只有几十行三角函数, 自己实现更可控也更贴合
// 深色科技风的视觉口径(渐变填充/发光描边都直接用 CSS filter + SVG gradient)。
//
// 约定: 角度制, 0° 指向正上方(12 点), 顺时针增大 —— 与人对时钟的直觉一致,
// 省掉调用点反复做 -90° 修正。
import { locale } from '../../i18n'

export const C = {
  accent: '#3884ff', ok: '#34d399', warn: '#fbbf24', danger: '#f87171',
  info: '#38bdf8', purple: '#a78bfa', muted: '#64748b',
}
export const COLOR = {
  accent: C.accent, ok: C.ok, warn: C.warn, danger: C.danger, info: C.info, purple: C.purple,
}
export const COLOR_OPTS = [
  { v: 'accent', t: '科技蓝' }, { v: 'ok', t: '安全绿' }, { v: 'warn', t: '告警橙' },
  { v: 'danger', t: '危险红' }, { v: 'info', t: '信息青' }, { v: 'purple', t: '幻紫' },
]
export const SEV = { critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8', info: '#94a3b8' }
export const SEV_CN = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export function color(v) { return COLOR[v] || C.accent }
export function fmt(n) {
  if (n === null || n === undefined || isNaN(n)) return '—'
  const v = Math.round(n)
  // 2026-10-03 i18n: 英文用 K/M/B 记数法, 中文保留 万/亿
  if (locale.value === 'en') {
    if (Math.abs(v) >= 1e9) return (v / 1e9).toFixed(1) + 'B'
    if (Math.abs(v) >= 1e6) return (v / 1e6).toFixed(1) + 'M'
    if (Math.abs(v) >= 1e3) return (v / 1e3).toFixed(1) + 'K'
    return String(v)
  }
  if (Math.abs(v) >= 1e8) return (v / 1e8).toFixed(1) + '亿'
  if (Math.abs(v) >= 1e4) return (v / 1e4).toFixed(1) + '万'
  return String(v)
}
// 负载/占比 → 颜色(与拓扑节点同一套语义: 绿→黄→红)
export function heatColor(v) { return v >= 80 ? C.danger : v >= 50 ? C.warn : C.ok }

// 极坐标: 0° 在正上方, 顺时针
function polar(cx, cy, r, deg) {
  const a = (deg - 90) * Math.PI / 180
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)]
}

// 环形扇段(外圆 rO, 内圆 rI)
export function arcRing(cx, cy, rO, rI, a0, a1) {
  const end = Math.min(a1, a0 + 359.99)
  const [x0, y0] = polar(cx, cy, rO, a0), [x1, y1] = polar(cx, cy, rO, end)
  const [x2, y2] = polar(cx, cy, rI, end), [x3, y3] = polar(cx, cy, rI, a0)
  const lg = end - a0 > 180 ? 1 : 0
  return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${rO} ${rO} 0 ${lg} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}` +
         ` L ${x2.toFixed(2)} ${y2.toFixed(2)} A ${rI} ${rI} 0 ${lg} 0 ${x3.toFixed(2)} ${y3.toFixed(2)} Z`
}

// 实心扇形(饼图)
export function pieSlice(cx, cy, r, a0, a1) {
  if (a1 - a0 >= 359.99) {
    // 单项占满时 A 命令起终点重合会画不出图, 用两段半圆代替
    return `M ${cx} ${cy - r} A ${r} ${r} 0 1 1 ${cx} ${cy + r} A ${r} ${r} 0 1 1 ${cx} ${cy - r} Z`
  }
  const [x0, y0] = polar(cx, cy, r, a0), [x1, y1] = polar(cx, cy, r, a1)
  const lg = a1 - a0 > 180 ? 1 : 0
  return `M ${cx} ${cy} L ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${lg} 1 ${x1.toFixed(2)} ${y1.toFixed(2)} Z`
}

// 迷你折线/折线图: 返回 { line, area }
export function linePath(vals, w, h, pad = 2) {
  const v = (vals && vals.length) ? vals : [0]
  const mx = Math.max.apply(null, v.concat([1]))
  const mn = Math.min.apply(null, v.concat([0]))
  const n = v.length
  const step = n === 1 ? 0 : (w - pad * 2) / (n - 1)
  const pt = v.map((d, i) => {
    const x = n === 1 ? w / 2 : pad + step * i
    const y = pad + (h - pad * 2) * (1 - (d - mn) / (mx - mn || 1))
    return [Number(x.toFixed(2)), Number(y.toFixed(2))]
  })
  const line = pt.map((p, i) => (i ? 'L' : 'M') + p[0] + ' ' + p[1]).join(' ')
  const area = line + ` L ${pt[pt.length - 1][0]} ${h} L ${pt[0][0]} ${h} Z`
  return { line, area, pts: pt }
}

// 数值滚动补间(浏览模式图表带动画; 返回取消函数)
export function animateNum(from, to, ms, cb) {
  const t0 = performance.now()
  let raf = 0
  function frame(t) {
    const p = Math.min(1, (t - t0) / ms)
    // easeOutCubic: 数字跳动先看增减方向, 再稳定, 观感比线性自然
    const e = 1 - Math.pow(1 - p, 3)
    cb(from + (to - from) * e)
    if (p < 1) raf = requestAnimationFrame(frame)
  }
  raf = requestAnimationFrame(frame)
  return () => cancelAnimationFrame(raf)
}

// 等距-重采样: 点数超限时按"取前 N 名 + 均匀分布"降级, 防止图上糊成一团
export function downsample(arr, max) {
  if (!arr || arr.length <= max) return arr || []
  const sorted = arr.slice().sort((a, b) => (b.v || 0) - (a.v || 0))
  return sorted.slice(0, max)
}
