// treeStore.js —— 资产管理「二级混合树」状态层(2026-09-28)
//
// 定位: 台账资产表(/api/v2/assets)仍是唯一事实来源, 本模块只是"视图 + 归属"层。
// 只把树结构(目录/顺序/展开态/扫描快照条目)持久化到 localStorage, 绝不持久化
// 资产数据本身 —— 资产字段(存活/端口/标签)永远以 API 为准, 树里只做展示。
//
// 四类一级节点(entry 键前缀):
//   f:<nodeId>    自定义目录(folder)     二级 = assetId 数组, 可编辑/可拖拽
//   t:<nodeId>    扫描任务快照(scan_task) 二级 = 该次扫描报告的资产快照, 只读
//   mprobe:<id>   监控设备(探针)          叶子, 实时同步 /api/v2/probe/list
//   msnmp:<id>    监控设备(SNMP 目标)     叶子, 实时同步 /api/v2/monitor/status
//   a:<assetId>   独立资产(single_asset)  叶子 = 未归入任何目录的台账资产
//
// 全局 assetId 口径: 后端 Asset.ID(IP 的 SHA1 前 16 位, StableID)天然全局唯一,
// 移动资产只改归属条目, 不复制副本; 同一资产可同时出现在多个"扫描快照"里
// (历史只读维度), 但在"可编辑维度"(目录 + 独立资产)里恒只出现一次。
//
// 扫描快照 children 里允许 'absent:<ip>' 形式: 该 IP 曾被扫到但已不在台账
// (被删除/清理), 快照按历史原样保留, 界面标"已移除"灰显 —— 快照只读不可改。
// 目录 children 不允许 absent(目录是活分组, 资产删了就该消失)。

import { reactive, computed } from 'vue'
import { v2 } from '../../api/http'
import { t } from '../../i18n'

const KEY = 'yugsight_asset_tree'
const VERSION = 1
const FETCH_SIZE = 1000
const FETCH_MAX_PAGES = 10 // 台账上限 1 万条兜底(超了截断并提示)

const state = reactive({
  // ---- 持久化部分(写 localStorage) ----
  migratedAt: 0,        // 首次迁移时间戳(0 = 尚未迁移)
  nodes: {},            // nodeId -> folderNode | scanNode
  order: [],            // 一级展示顺序: ['f:x','t:y','mprobe:z','msnmp:w','a:aid', ...]
  expanded: {},         // nodeId -> bool(目录默认展开, 快照默认收起)
  refIps: {},           // 快照 children 里 ref -> IP 的持久缓存: 资产从台账删除后,
                        //   快照仍要能显示当时的 IP(ghost 灰显), 靠这里找回
  // ---- 内存数据(每次 loadAll 重取, 不持久化) ----
  assets: {},           // assetId -> asset
  ipToId: {},           // ip -> assetId
  reports: {},          // reportId -> raw report(module=scan)
  reportsOk: false,     // 原始报告接口是否可用(503 时快照只做保留不新增/不判失)
  probes: {},           // probeId -> probe
  snmp: {},             // targetId -> monitor target view
  truncated: false,     // 资产拉取超上限截断
  loaded: false,
  loadError: '',
})

// ===== 持久化 =====

function loadRaw() {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return null
    const d = JSON.parse(raw)
    if (!d || d.version !== VERSION) return null // 旧版/未知结构: 丢弃重建(新功能首版)
    return {
      migratedAt: d.migratedAt || 0,
      nodes: d.nodes || {},
      order: Array.isArray(d.order) ? d.order : [],
      expanded: d.expanded || {},
      refIps: d.refIps || {},
    }
  } catch (e) {
    console.warn('资产树本地存储解析失败, 重建:', e)
    return null
  }
}

function persist() {
  try {
    localStorage.setItem(KEY, JSON.stringify({
      version: VERSION,
      migratedAt: state.migratedAt,
      nodes: state.nodes,
      order: state.order,
      expanded: state.expanded,
      refIps: state.refIps,
    }))
  } catch (e) {
    // 配额/隐私模式写失败不阻断: 树仍是内存可用的, 只是刷新不保留
    console.warn('资产树本地存储写入失败:', e)
  }
}

function initState() {
  const d = loadRaw()
  if (d) {
    state.migratedAt = d.migratedAt
    state.nodes = d.nodes
    state.order = d.order
    state.expanded = d.expanded
  }
}
initState()

// ===== 数据拉取(全部复用现有接口, 降级不报错) =====

async function fetchAssets() {
  const out = {}
  const ipToId = {}
  let page = 1
  let total = 0
  while (page <= FETCH_MAX_PAGES) {
    const d = await v2('/assets?page=' + page + '&size=' + FETCH_SIZE)
    const list = (d && d.list) || []
    total = (d && d.total) || 0
    for (const a of list) {
      if (!a || !a.id) continue
      out[a.id] = a
      if (a.ip) ipToId[a.ip] = a.id
    }
    if (list.length < FETCH_SIZE || page * FETCH_SIZE >= total) break
    page++
  }
  if (total > FETCH_MAX_PAGES * FETCH_SIZE) state.truncated = true
  state.assets = out
  state.ipToId = ipToId
}

async function fetchScanReports() {
  try {
    const d = await v2('/raw/list?module=scan&page=1&size=' + FETCH_SIZE)
    const out = {}
    for (const r of (d && d.list) || []) {
      if (r && r.id) out[r.id] = r
    }
    state.reports = out
    state.reportsOk = true
  } catch (e) {
    // 报告中心未启用(503)等情况: 快照节点保留存量, 不新增不判失
    state.reports = {}
    state.reportsOk = false
  }
}

async function fetchProbes() {
  try {
    const d = await v2('/probe/list')
    const out = {}
    for (const p of (d && d.list) || []) {
      if (p && p.id) out[p.id] = p
    }
    state.probes = out
  } catch (e) {
    state.probes = {} // 探针中心未启用时静默降级
  }
}

async function fetchSnmp() {
  try {
    const d = await v2('/monitor/status')
    const out = {}
    for (const t of (d && d.targets) || []) {
      if (t && t.id) out[t.id] = t
    }
    state.snmp = out
  } catch (e) {
    state.snmp = {} // 监控未启用时静默降级
  }
}

export async function loadAll() {
  state.loadError = ''
  try {
    await fetchAssets() // 台账是树的地基, 失败要上抛让页面提示
  } catch (e) {
    state.loadError = e.message
    throw e
  }
  await Promise.all([fetchScanReports(), fetchProbes(), fetchSnmp()])
  syncTree()
}

// ===== 同步/迁移(幂等, 每次 loadAll 后跑) =====
//
// 规则:
//  1) 扫描快照: 存量节点对应的报告没了 → 标 reportGone(历史保留);
//     报告表里还没有对应节点的 → 自动生成快照节点(新扫描自动出现 = 平滑迁移)
//  2) 目录: children 里不在台账的 id 剔除(活分组跟随台账)
//  3) order: 失效条目剔除(节点删了/资产删了/移进目录了)
//  4) 追加: 新台账资产(未归目录)、新探针、新 SNMP 目标 补到顺序尾部

function resolveAssetRef(ip) {
  return state.ipToId[ip] || ('absent:' + ip)
}

// 快照 children 的 ref 统一登记 IP(创建/同步时): 资产日后从台账删除,
// ghost 行仍用这里的 IP 显示, 而不是露出 assetId
function registerRefIps(refs) {
  for (const ref of refs || []) {
    if (state.refIps[ref]) continue
    if (ref.startsWith('absent:')) state.refIps[ref] = ref.slice('absent:'.length)
    else if (state.assets[ref]) state.refIps[ref] = state.assets[ref].ip
  }
  // 只保留当前快照仍引用的 ref, 防止缓存无限膨胀
  const live = new Set()
  for (const n of Object.values(state.nodes)) {
    if (n.type === 'scan_task') (n.children || []).forEach(r => live.add(r))
  }
  for (const k of Object.keys(state.refIps)) {
    if (!live.has(k)) delete state.refIps[k]
  }
}

function inFolder(assetId) {
  for (const n of Object.values(state.nodes)) {
    if (n.type === 'folder' && (n.children || []).includes(assetId)) return true
  }
  return false
}

function orderEntryExists(k) {
  const i = k.indexOf(':')
  if (i < 0) return false
  const p = k.slice(0, i)
  const id = k.slice(i + 1)
  switch (p) {
    case 'f': return state.nodes[id] && state.nodes[id].type === 'folder'
    case 't': return state.nodes[id] && state.nodes[id].type === 'scan_task'
    case 'mprobe': return !!state.probes[id]
    case 'msnmp': return !!state.snmp[id]
    case 'a': return !!state.assets[id] && !inFolder(id)
    default: return false
  }
}

export function syncTree() {
  if (!state.migratedAt) state.migratedAt = Date.now()

  // 1) 扫描快照节点
  const covered = new Set()
  for (const n of Object.values(state.nodes)) {
    if (n.type !== 'scan_task') continue
    covered.add(n.reportId)
    if (state.reportsOk) n.reportGone = !state.reports[n.reportId]
  }
  if (state.reportsOk) {
    for (const r of Object.values(state.reports)) {
      if (covered.has(r.id)) continue
      const nodeId = 'scan_' + r.id
      if (state.nodes[nodeId]) continue
      const kids = (r.assets || []).map(resolveAssetRef)
      state.nodes[nodeId] = {
        nodeId,
        type: 'scan_task',
        name: r.title || t('at.scanName', { x: r.target || r.id }),
        scanTime: r.createdAt,
        reportId: r.id,
        children: kids,
      }
      registerRefIps(kids)
      state.order.push('t:' + nodeId)
      state.expanded[nodeId] = false // 快照默认收起(二级可能很长)
    }
  }

  // 2) 目录 children 跟随台账
  for (const n of Object.values(state.nodes)) {
    if (n.type !== 'folder') continue
    n.children = (n.children || []).filter(cid => state.assets[cid])
  }

  // 3) order 剔除失效条目
  state.order = state.order.filter(orderEntryExists)

  // 4) 新资产/探针/目标 补尾部
  const inOrder = new Set(state.order)
  for (const id of Object.keys(state.assets)) {
    if (!inFolder(id) && !inOrder.has('a:' + id)) state.order.push('a:' + id)
  }
  for (const id of Object.keys(state.probes)) {
    if (!inOrder.has('mprobe:' + id)) state.order.push('mprobe:' + id)
  }
  for (const id of Object.keys(state.snmp)) {
    if (!inOrder.has('msnmp:' + id)) state.order.push('msnmp:' + id)
  }

  state.loaded = true
  persist()
}

// ===== 一级节点解析(渲染视图) =====

function splitKey(k) {
  const i = k.indexOf(':')
  return [k.slice(0, i), k.slice(i + 1)]
}

function childViews(ids) {
  return (ids || []).map(ref => {
    const asset = ref.startsWith('absent:') ? null : state.assets[ref]
    const ip = asset ? asset.ip
      : (ref.startsWith('absent:') ? ref.slice('absent:'.length) : state.refIps[ref] || '')
    return {
      ref,
      asset,
      ip,
      ghost: !asset, // 快照里"已不在台账"的历史资产
    }
  })
}

export const entries = computed(() => {
  const out = []
  for (const k of state.order) {
    const e = resolveEntry(k)
    if (e) out.push(e)
  }
  return out
})

function resolveEntry(k) {
  const [p, id] = splitKey(k)
  switch (p) {
    case 'f': {
      const n = state.nodes[id]
      if (!n || n.type !== 'folder') return null
      return { key: k, kind: 'folder', node: n, children: childViews(n.children) }
    }
    case 't': {
      const n = state.nodes[id]
      if (!n || n.type !== 'scan_task') return null
      return { key: k, kind: 'scan', node: n, children: childViews(n.children) }
    }
    case 'mprobe': {
      const pr = state.probes[id]
      if (!pr) return null
      return {
        key: k, kind: 'monitor', children: [],
        name: pr.name || id,
        ip: pr.addr || '',
        status: pr.online ? 'online' : 'offline',
        meta: pr.status || '',
        link: '/nodemonitor',
      }
    }
    case 'msnmp': {
      const t = state.snmp[id]
      if (!t) return null
      return {
        key: k, kind: 'monitor', children: [],
        name: t.name || t.addr || id,
        ip: t.addr || '',
        // Online = 最近两轮内有成功采样; Collected 但离线 = warning(配置存在但采不到)
        status: t.online ? 'online' : (t.collected ? 'warning' : 'offline'),
        meta: (t.sysDescr || t.version || '').toString().slice(0, 40),
        link: '/nodemonitor?tab=net',
      }
    }
    case 'a': {
      const a = state.assets[id]
      if (!a || inFolder(id)) return null
      return { key: k, kind: 'single', asset: a, name: a.hostname || a.ip, children: [] }
    }
    default:
      return null
  }
}

// ===== 动作(全部落 persist; 返回 false = 非法操作被拒) =====

function genId(prefix) {
  return prefix + '_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7)
}

export function addFolder(name, remark) {
  const id = genId('f')
  state.nodes[id] = { nodeId: id, type: 'folder', name: name || t('at.untitled'), remark: remark || '', children: [] }
  state.order.push('f:' + id)
  state.expanded[id] = true
  persist()
  return id
}

export function updateFolder(id, patch) {
  const n = state.nodes[id]
  if (!n || n.type !== 'folder') return false
  if (patch.name != null && String(patch.name).trim()) n.name = String(patch.name).trim()
  if (patch.remark != null) n.remark = String(patch.remark)
  persist()
  return true
}

export function removeFolder(id) {
  const n = state.nodes[id]
  if (!n || n.type !== 'folder') return false
  const kids = (n.children || []).slice()
  const idx = state.order.indexOf('f:' + id)
  delete state.nodes[id]
  delete state.expanded[id]
  if (idx >= 0) {
    state.order.splice(idx, 1)
    // 原成员退回独立资产, 插在原目录位置(不消失不复制)
    state.order.splice(idx, 0, ...kids.map(k => 'a:' + k))
  }
  persist()
  return true
}

export function removeScanNode(id) {
  const n = state.nodes[id]
  if (!n || n.type !== 'scan_task') return false
  delete state.nodes[id]
  const i = state.order.indexOf('t:' + id)
  if (i >= 0) state.order.splice(i, 1)
  persist()
  return true
}

function removeFromAnywhere(assetId) {
  for (const n of Object.values(state.nodes)) {
    if (n.type !== 'folder') continue
    const i = (n.children || []).indexOf(assetId)
    if (i >= 0) n.children.splice(i, 1)
  }
  const i = state.order.indexOf('a:' + assetId)
  if (i >= 0) state.order.splice(i, 1)
}

// moveAsset: 把资产移到目标位置(只改归属, 不复制)
//   toKey = 'f:<folderId>' 进目录(index 缺省=末尾, -1 同缺省)
//   toKey = 'a:<assetId>'  退回独立资产(插在该条目前)
export function moveAsset(assetId, toKey, index) {
  if (!assetId || assetId.startsWith('absent:')) return false
  if (!state.assets[assetId]) return false // 不在台账的(快照 ghost)不允许进可编辑维度
  if (toKey.startsWith('f:')) {
    const fid = toKey.slice(2)
    const f = state.nodes[fid]
    if (!f || f.type !== 'folder') return false
    if (!f.children.includes(assetId)) removeFromAnywhere(assetId)
    let i = (index == null || index < 0) ? f.children.length : index
    i = Math.max(0, Math.min(i, f.children.length))
    f.children.splice(i, 0, assetId)
  } else if (toKey.startsWith('a:')) {
    const target = toKey.slice(2)
    if (target === assetId) return false
    removeFromAnywhere(assetId)
    const i = state.order.indexOf(toKey)
    if (i < 0) state.order.push('a:' + assetId)
    else state.order.splice(i, 0, 'a:' + assetId)
  } else {
    return false
  }
  persist()
  return true
}

// 同目录内重排(拖拽二级行): 计算好插入下标后走 moveAsset
export function reorderChild(folderKey, assetId, insertIdx) {
  return moveAsset(assetId, folderKey, insertIdx)
}

// 一级顺序调整(拖一级行): key 移到 targetKey 前/后
export function reorderEntry(key, targetKey, before) {
  if (!key || !targetKey || key === targetKey) return false
  const from = state.order.indexOf(key)
  if (from < 0) return false
  state.order.splice(from, 1)
  let ti = state.order.indexOf(targetKey)
  if (ti < 0) return false
  if (!before) ti += 1
  state.order.splice(ti, 0, key)
  persist()
  return true
}

export function toggleExpand(id) {
  state.expanded[id] = !state.expanded[id]
  persist()
}

// 重置树: 清掉所有本地分组/顺序/快照条目, 按当前台账+快照重建
// (资产本身、扫描报告存档完全不动)
export function resetTree() {
  state.nodes = {}
  state.order = []
  state.expanded = {}
  state.migratedAt = Date.now()
  syncTree()
}

// ===== 查询辅助(组件用) =====

export function isExpanded(nodeId) {
  const n = state.nodes[nodeId]
  if (!n) return false
  // 目录默认展开 / 快照默认收起
  return state.expanded[nodeId] !== undefined ? state.expanded[nodeId] : n.type === 'folder'
}

export function isAbsent(ref) {
  return typeof ref === 'string' && ref.startsWith('absent:')
}

// 资产在树里的可编辑归属: 'f:<id>' | 'a:<id>' | null(只存在于只读快照里)
export function locationOf(assetId) {
  if (!state.assets[assetId]) return null
  for (const [id, n] of Object.entries(state.nodes)) {
    if (n.type === 'folder' && (n.children || []).includes(assetId)) return 'f:' + id
  }
  return 'a:' + assetId
}

// focus 定位: 返回应展开并滚动到的一级 key(目录 > 独立)
export function focusKeyOf(assetId) {
  const loc = locationOf(assetId)
  if (!loc) return null
  if (loc.startsWith('f:')) {
    state.expanded[loc.slice(2)] = true
    persist()
  }
  return loc
}

export const assetTree = { state, entries }
