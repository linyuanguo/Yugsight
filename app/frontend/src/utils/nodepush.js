// 节点监控「告警推送」共享状态与常量(2026-09-28)。
//
// 数据归属(与 api/nodepush.js 分工):
//   - 目标 / 规则 / 日志 / 告警: 全部由后端持久化(/api/node/push/*),
//     前端不存副本 —— 告警记录不再有 localStorage 本地层(原 Mock 已移除)。
//   - pushStore: 仅在内存共享"已加载的目标列表", 供 AlertLog 页的
//     "推送日志" 目标筛选下拉与 PushRuleConfig 的复选框共用(避免两组件重复请求)。
//   - uid: 轻量唯一 id 生成器(ConnectivityTest 页面内部状态用, 与后端无关)。

// ===== 轻量唯一 id(ConnectivityTest 用)=====
let _seq = 0
export function uid(prefix = 'id') {
  _seq += 1
  return prefix + '-' + Date.now().toString(36) + '-' + _seq.toString(36)
}

// ===== 告警级别(与漏洞五级口径区分: 节点告警是三级) =====
// key 与后端 node_alerts 表 level 字段一一对应(critical/warning/info)。
export const LEVELS = [
  { key: 'critical', label: '紧急', color: 'var(--red)', cls: 'sev-critical' },
  { key: 'warning', label: '重要', color: 'var(--amber)', cls: 'sev-medium' },
  { key: 'info', label: '提示', color: 'var(--blue)', cls: 'sev-info' }
]
export const LEVEL_LABEL = Object.fromEntries(LEVELS.map(l => [l.key, l.label]))

// 告警来源(与后端 node_alerts.source 一一对应: device/link/probe)
export const SOURCE_LABEL = {
  device: '设备',
  link: '链路',
  probe: '探针'
}

// 推送状态(与后端 node_alerts.pushStatus 一一对应)
export const PUSH_STATUS = [
  { key: 'unpushed', label: '未推送' },
  { key: 'pushed', label: '推送成功' },
  { key: 'failed', label: '推送失败' }
]
export const PUSH_STATUS_LABEL = Object.fromEntries(PUSH_STATUS.map(s => [s.key, s.label]))

// ===== 推送目标类型(与企业微信/钉钉/飞书 Webhook 平台对应) =====
export const TARGET_TYPES = [
  { key: 'wecom', label: '企业微信', icon: '💬' },
  { key: 'dingtalk', label: '钉钉', icon: '🔔' },
  { key: 'feishu', label: '飞书', icon: '🪁' }
]
export const TARGET_TYPE_LABEL = Object.fromEntries(TARGET_TYPES.map(t => [t.key, t.label]))
// PUSH_TYPES: PushTargetList 的模板按此名引用(兼容别名, 与 TARGET_TYPES 同一来源)
export const PUSH_TYPES = TARGET_TYPES
// typeLabel: 类型 key → 中文名(未知 key 原样返回, 不丢信息)
export function typeLabel(key) {
  return TARGET_TYPE_LABEL[key] || key || '未知'
}
// isWebhookURL: 与后端 validPushTarget 同口径(必须 http/https 且带 host)
export function isWebhookURL(u) {
  if (typeof u !== 'string') return false
  try {
    const p = new URL(u.trim())
    return (p.protocol === 'http:' || p.protocol === 'https:') && !!p.host
  } catch (e) {
    return false
  }
}
// maskWebhook: 列表脱敏(保留协议与 host, 中段打码; 完整地址靠 title 悬浮看)
export function maskWebhook(u) {
  if (typeof u !== 'string' || !u) return '—'
  try {
    const p = new URL(u)
    const tail = (p.search + (p.hash || ''))
    const mid = (p.pathname + tail).slice(0, 6)
    return p.protocol + '//' + p.host + (mid ? mid + '…' : '')
  } catch (e) {
    return u.slice(0, 12) + '…'
  }
}

// ===== 共享状态: 已加载的目标列表(内存, 不落盘) =====
// 由 PushTargetList 页首次拉取后写入, AlertLog / PushRuleConfig 直接读取。
export const pushStore = {
  targets: []
}

// ===== 推送规则默认值与归一化 =====
// 后端可只返回部分字段, 这里补默认值并固定键序。
// 键序固定是因为 PushRuleConfig 用 JSON.stringify 快照判"已修改"(见该文件 initRules)。
export function defaultRules() {
  return {
    levels: ['critical', 'warning', 'info'],
    delaySec: 30,
    window: 'all',
    workStart: '09:00',
    workEnd: '18:00',
    customStart: '09:00',
    customEnd: '18:00',
    dnd: false,
    dndStart: '22:00',
    dndEnd: '08:00',
    targetIds: []
  }
}

export function normalizeRules(raw) {
  const d = defaultRules()
  const r = { ...d, ...(raw || {}) }
  // 固定键序(判脏快照用)
  const order = ['levels', 'delaySec', 'window', 'workStart', 'workEnd',
    'customStart', 'customEnd', 'dnd', 'dndStart', 'dndEnd', 'targetIds']
  const out = {}
  for (const k of order) out[k] = r[k] ?? d[k]
  if (!Array.isArray(out.levels)) out.levels = d.levels
  if (!Array.isArray(out.targetIds)) out.targetIds = []
  return out
}
