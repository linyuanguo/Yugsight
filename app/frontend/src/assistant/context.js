// context.js 小 Y 页面上下文采集工具(2026-09-27)。
//
// 两个职责:
//  1. collectContext() —— 从路由提取页面类型/名称/筛选条件(query)/详情参数
//     (params), 并合并各页面通过 setPageData 注册的"页面关键数据"
//     (列表字段/正在查看的详情项等)。零侵入: 页面不注册时只有通用信息,
//     注册后小 Y 能答"当前列表"类问题。
//  2. quickQuestions() —— 按页面类型给 2-3 个高频快捷提问。
//
// 上报时机由 AssistantWidget 统一控制(路由变化时 POST /api/v1/ai/context,
// 提问时随请求覆盖传参), 本模块只做"采集"。
import router from '../router'

// ===== 页面类型识别(path → type) =====
// 与 router.js 的路由表对齐; 未列出的路径落到 'other'(通用快捷提问)。
function pageTypeOf(r) {
  const p = r.path
  if (p === '/vulns') return 'vulns'
  if (/^\/vulns\/[^/]+$/.test(p)) return 'vulndetail'
  if (p === '/nodemonitor') return 'nodemonitor'
  if (p === '/console') return 'console'
  if (p === '/assets') return 'assets'
  if (p === '/capture') return 'capture'
  if (p === '/weakpass') return 'weakpass'
  if (p === '/reports') return 'reports'
  if (p === '/license') return 'license'
  if (p === '/env') return 'env'
  if (p === '/') return 'dashboard'
  return 'other'
}

const PAGE_NAMES = {
  vulns: '漏洞管理', vulndetail: '漏洞详情', nodemonitor: '节点监控',
  console: '扫描控制台', assets: '资产管理', capture: '实时抓包分析',
  weakpass: '弱口令检测', reports: '报告中心', license: '授权与模型',
  env: '引擎与规则', dashboard: '首页仪表盘'
}

// ===== 页面关键数据注册(各页面 add 式接入, 不改既有逻辑) =====
//
// setPageData(key, getter): key = 页面类型, 或 "页面类型:tab"(节点监控两
// Tab 数据不同, 按 query.tab 区分)。getter 返回该页面当前关键数据
// (纯数据对象, 敏感字段由后端注入 LLM 前统一脱敏)。
const registry = new Map()
export function setPageData(key, getter) {
  registry.set(key, getter)
}

function currentKey(r) {
  const base = pageTypeOf(r)
  return r.query && r.query.tab ? base + ':' + String(r.query.tab) : base
}

// collectContext 采集当前页面上下文(用户无感知, 发送问答/路由变化时调用)。
export function collectContext() {
  const r = router.currentRoute.value
  const type = pageTypeOf(r)
  let data = null
  // 先查 "type:tab" 精确键, 再回退 "type"(Tab 页未注册时拿主数据)
  for (const key of [currentKey(r), type]) {
    const g = registry.get(key)
    if (g) {
      try { data = g() || null } catch (e) { data = null } // getter 异常不阻断问答
      if (data) break
    }
  }
  return {
    pageType: type,
    pageName: (r.meta && r.meta.title) || PAGE_NAMES[type] || type,
    // query = 已选筛选条件(漏洞列表等页面的筛选就持久化在 query 上)
    query: { ...(r.query || {}) },
    // params = 正在查看的详情项(如漏洞详情 /vulns/:id)
    params: { ...(r.params || {}) },
    data
  }
}

// ===== 场景化快捷提问(按页面类型推荐 2-3 个高频问题) =====
const QUICKS = {
  vulns: [
    '统计当前页面高危及以上漏洞, 列出清单',
    '哪些漏洞应优先修复? 给出理由',
    '总结当前筛选条件与结果数量'
  ],
  vulndetail: [
    '分析这个漏洞的影响范围',
    '给出这个漏洞的修复方案',
    '这个漏洞为什么是这个风险等级?'
  ],
  'nodemonitor:probe': [
    '哪些探针离线了? 分析可能原因',
    '总结当前探针节点在线情况'
  ],
  'nodemonitor:net': [
    '列出当前离线(告警)的网络设备',
    '总结当前监控设备的在线状态'
  ],
  nodemonitor: ['哪些节点当前告警?', '总结当前节点监控整体状态'],
  console: [
    '当前有多少任务在运行/排队?',
    '当前扫描的类型、目标与任务名是什么?'
  ],
  assets: ['总结当前资产列表概况', '哪些资产风险最高?'],
  capture: ['总结当前抓包页面看到的数据'],
  weakpass: ['总结当前弱口令检测结果'],
  reports: ['总结当前报告列表'],
  dashboard: ['总结当前仪表盘的关键指标']
}
const DEFAULT_QUICKS = ['总结当前页面的内容', '当前页面有什么需要关注的?']

export function quickQuestions() {
  const r = router.currentRoute.value
  const type = pageTypeOf(r)
  const key = r.query && r.query.tab ? type + ':' + String(r.query.tab) : type
  return QUICKS[key] || QUICKS[type] || DEFAULT_QUICKS
}
