// 节点监控「告警推送」后端接口层(2026-09-28: 替换 localStorage 本地存储)。
//
// 职责边界(与 utils/nodepush.js 分工):
//   - 本文件: 所有与后端 /api/node/push/* 的交互(目标/规则/测试/日志/告警/重推),
//     配置、测试、日志、告警数据全部由后端持久化; 前端只调用这些管理接口,
//     绝不直接请求任何企业微信/钉钉/飞书 Webhook。
//   - utils/nodepush.js: 展示常量(级别/类型/状态文案) + pushStore 共享目标列表
//     + 推送规则默认值/归一化。
//
// ===== 接口契约与字段映射 =====
//
//   统一信封 Resp{code, message, data}(同 /api/dashboard/flows), 经 v2dash 拆包;
//   code!=0 或 HTTP 非 2xx 时抛 Error(message), 由调用方 toast 提示。
//
//   目标 Target(表单字段与接口字段一一对应):
//     { id, name, type: 'wecom'|'dingtalk'|'feishu', webhook, note, enabled, createdAt? }
//       GET    /api/node/push/targets               → { list: Target[] }(兼容裸数组)
//       POST   /api/node/push/target        body Target → Target(id 由后端生成)
//       PUT    /api/node/push/target/{id}  body Target → Target
//       DELETE /api/node/push/target/{id}           → {}
//
//   规则 Rules(字段与 PushRuleConfig 表单一一对应; 后端可只返回部分字段,
//   由 normalizeRules 补默认值并固定键序 —— 前端 JSON 快照判脏依赖键序稳定):
//     { levels[], delaySec, window: 'all'|'work'|'custom',
//       workStart, workEnd, customStart, customEnd,
//       dnd, dndStart, dndEnd, targetIds[] }
//       GET /api/node/push/rules          → Rules
//       PUT /api/node/push/rules   body Rules → {}
//
//   推送总开关 + 状态概览(2026-09-28: 3D 拓扑页「告警设置」轻量入口用,
//   消费方 = topo3d/PushStatusPanel, 现随旧拓扑模块封存, 第三阶段对接时恢复;
//   完整配置在 节点监控→告警日志管理→推送配置):
//     PUT /api/node/push/switch  body { enabled } → { enabled }
//       只改 nodepush 节 enabled, 目标/规则不动; 未写 enabled 的存量配置 = 开。
//     GET /api/node/push/stat → { enabled, todayPushed, todayFailed }
//       今日(本地 0 点起)推送日志按状态计数: success 计推送数, failed 计失败数,
//       skipped 与跨天记录不计。
//
//   测试推送(前端触发, 后端真实发送一条测试告警并回执, 同时写一条无主推送日志):
//     POST /api/node/push/test body { targetId } → { success: boolean, message }
//       success=false 时 message 即失败原因(如 webhook 拒绝), 展示给用户。
//
//   推送日志 Log(后端 push_logs 表, 与告警记录一一对应):
//     { id, alertId, at, level, content, target, status, reason }
//       alertId 空 = 无主记录(测试推送); reason 仅 failed 有意义(悬浮提示用)
//       status: 'success' | 'failed' | 'skipped'
//       GET /api/node/push/logs
//         ?page&size&start&end&status&level&target → { list: Log[], total }
//
//   告警记录 Alert(后端 node_alerts 表: 采集引擎异常事件自动生成,
//   推送触发/规则匹配/消息发送全部由后端执行, 前端只展示 + 手动重推):
//     { id, level: 'critical'|'warning'|'info', source: 'device'|'link'|'probe',
//       device, ip, content, at,
//       pushStatus: 'unpushed'|'pushed'|'failed', pushedAt?,
//       handled: ''|'confirmed'|'ignored' }
//       GET  /api/node/push/alerts?limit=200        → { list: Alert[], total }(新在前)
//       POST /api/node/push/retry   body { alertId } → { alertId, status }(手动重推)
//       POST /api/node/push/alerts/{id}/handled body { handled } → { id, handled }
//
// 注意: 路由挂在根 mux 的 /api/node/push/*(不在 /api/v2/ 子树, 同 /api/dashboard/flows
// 口径), 必须用 v2dash 裸路径, 不要套 /api/v2 前缀(会双重前缀恒 404, 见 http.js)。

import { v2dash } from './http'

const P = '/api/node/push'

function asList(d, key) {
  if (Array.isArray(d)) return d
  const v = (d && d[key]) || (d && d.items)
  return Array.isArray(v) ? v : []
}

// ===== 目标 =====
// GET → { list, total }
export async function fetchTargets() {
  const d = await v2dash(P + '/targets')
  return { list: asList(d, 'list'), total: (d && Number.isFinite(d.total)) ? d.total : 0 }
}
// POST body Target → Target(id 后端生成)
export async function createTarget(t) {
  return await v2dash(P + '/target', { method: 'POST', body: t })
}
// PUT body Target → Target
export async function updateTarget(id, t) {
  return await v2dash(P + '/target/' + encodeURIComponent(id), { method: 'PUT', body: t })
}
// DELETE → {}
export async function deleteTarget(id) {
  return await v2dash(P + '/target/' + encodeURIComponent(id), { method: 'DELETE' })
}

// ===== 规则 =====
// GET → Rules(未保存 = 默认值)
export async function fetchRules() {
  return await v2dash(P + '/rules')
}
// PUT body Rules → {}
export async function saveRules(rules) {
  return await v2dash(P + '/rules', { method: 'PUT', body: rules })
}

// ===== 推送总开关 + 状态概览(大屏轻量入口) =====
// PUT { enabled } → { enabled }
export async function setPushSwitch(enabled) {
  return await v2dash(P + '/switch', { method: 'PUT', body: { enabled: !!enabled } })
}
// GET → { enabled, todayPushed, todayFailed }
export async function fetchPushStat() {
  return await v2dash(P + '/stat')
}

// ===== 测试推送 =====
// POST { targetId } → { success, message }
export async function testPush(targetId) {
  return await v2dash(P + '/test', { method: 'POST', body: { targetId } })
}

// ===== 推送日志 =====
// GET 分页 + 时间/状态/级别/目标 筛选 → { list, total }
export async function fetchLogs({ page = 1, size = 20, start = '', end = '', status = '', level = '', target = '' } = {}) {
  const p = new URLSearchParams()
  p.set('page', page)
  p.set('size', size)
  if (start) p.set('start', start)
  if (end) p.set('end', end)
  if (status) p.set('status', status)
  if (level) p.set('level', level)
  if (target) p.set('target', target)
  const d = await v2dash(P + '/logs?' + p.toString())
  return {
    list: asList(d, 'list'),
    total: (d && Number.isFinite(d.total)) ? d.total : 0
  }
}

// ===== 告警记录(后端真实告警, 5s 轮询保持实时) =====
// GET → { list, total }
export async function fetchAlerts(limit = 200) {
  const d = await v2dash(P + '/alerts?limit=' + limit)
  return {
    list: asList(d, 'list'),
    total: (d && Number.isFinite(d.total)) ? d.total : 0
  }
}
// POST { alertId } → { alertId, status }(对推送失败的告警手动重推)
export async function retryPush(alertId) {
  return await v2dash(P + '/retry', { method: 'POST', body: { alertId } })
}
// POST { handled: ''|'confirmed'|'ignored' } → { id, handled }
export async function setAlertHandled(id, handled) {
  return await v2dash(P + '/alerts/' + encodeURIComponent(id) + '/handled', { method: 'POST', body: { handled } })
}
