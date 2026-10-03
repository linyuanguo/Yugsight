// 布局模板管理(2026-09-28 安全大屏 Pro 终版)。
//
// 【核心约束】模板**只存元素的 key → 几何(x/y/w/h) + 显隐(hidden) + 少量组件配置(cfg)**,
// 不存业务数据、不创建/销毁组件实例。带来的好处: 切模板只是改一堆数字, 不重建组件、
// 不重新拉数据、不打断轮询, 切换开销接近零; 坏处是不能凭空变出一张卡 —— 所以内置模板
// 只在"默认 19 卡"的范围内重排, 需要新卡(如趋势折线)得先由用户拖一个进来再存模板。
//
// key 是默认布局里给每张卡打的稳定标识(见 types.js defaultCards), 用户后加的卡没有 key,
// 切模板时保持原样不动 —— 不认识就别动它, 比误移位置安全。
//
// 2026-09-29: 拓扑卡(key=topo)回归 —— 2026-09-28 曾随旧 2D 拓扑模块删除, 现以新卡片
// (TopoCard, 复用 topo3d 场景)回到默认布局, 内置模板重新覆盖该 key。
// 用户旧布局里残留的 topo 条目仍会被 applyLayout 忽略(找不到对应卡片), 无副作用。

export const TPL_KEY = 'yugsight_bpro_tpls'
export const CUR_KEY = 'yugsight_bpro_tpl_current'

const M = (title, metric) => ({ title, metric })

// ===== 内置模板(2026-09-28: 原第三套"网络专项"为拓扑全屏布局, 随旧拓扑模块删除) =====
// 严格基于 1920×1080 基准画布, 外边距 16px / 间距 16px,
// 每套覆盖默认 19 卡的全部 key(几何或 hidden), 无溢出、无重叠、间距统一。
export const BUILTIN = [
  {
    id: 'tpl_overview', name: '综合总览', scene: '日常值守', builtin: true,
    layout: {
      m1: { x: 16, y: 16, w: 460, h: 104, cfg: M('累计漏洞总数', 'vulnRisk') },
      m2: { x: 492, y: 16, w: 460, h: 104, cfg: M('今日新增漏洞', 'findingToday') },
      m3: { x: 968, y: 16, w: 460, h: 104, cfg: M('已完成扫描任务', 'taskSuccess') },
      m4: { x: 1444, y: 16, w: 460, h: 104, cfg: M('任务成功率', 'successRate') },
      globe: { x: 16, y: 136, w: 688, h: 400 },
      topo: { x: 720, y: 136, w: 480, h: 400 },
      vl: { x: 1216, y: 136, w: 336, h: 192 },
      tb: { x: 1568, y: 136, w: 336, h: 192 },
      at: { x: 1216, y: 344, w: 336, h: 192 },
      ap: { x: 1568, y: 344, w: 336, h: 192 },
      gt1: { x: 16, y: 552, w: 618, h: 48 },
      s1: { x: 16, y: 612, w: 618, h: 220 },
      s2: { x: 16, y: 844, w: 618, h: 220 },
      gt2: { x: 650, y: 552, w: 618, h: 48 },
      s3: { x: 650, y: 612, w: 618, h: 220 },
      s4: { x: 650, y: 844, w: 618, h: 220 },
      gt3: { x: 1284, y: 552, w: 618, h: 48 },
      s5: { x: 1284, y: 612, w: 618, h: 220 },
      s6: { x: 1284, y: 844, w: 618, h: 220 },
    },
  },
  {
    id: 'tpl_attack', name: '攻击态势', scene: '宏观威胁', builtin: true,
    // 说明: 后端暂无"攻击量/拦截数/攻击源国家数"指标, 顶部四个槽位沿用同源可得的
    // 风险/新增/任务/成功率, 不编造攻击数字(标题如实反映指标含义)。
    layout: {
      globe: { x: 16, y: 16, w: 1372, h: 852 },
      vl: { x: 1404, y: 16, w: 500, h: 273 },
      at: { x: 1404, y: 305, w: 500, h: 273 },
      tb: { x: 1404, y: 594, w: 500, h: 273 },
      m1: { x: 16, y: 884, w: 460, h: 180, cfg: M('风险总量', 'vulnRisk') },
      m2: { x: 492, y: 884, w: 460, h: 180, cfg: M('今日新增', 'findingToday') },
      m3: { x: 968, y: 884, w: 460, h: 180, cfg: M('已完成任务', 'taskSuccess') },
      m4: { x: 1444, y: 884, w: 460, h: 180, cfg: M('任务成功率', 'successRate') },
      // 攻击态势把地球放大到 1372 宽(覆盖原拓扑卡位置), 拓扑卡隐藏避免重叠
      topo: { hidden: true },
      ap: { hidden: true },
      gt1: { hidden: true }, gt2: { hidden: true }, gt3: { hidden: true },
      s1: { hidden: true }, s2: { hidden: true }, s3: { hidden: true },
      s4: { hidden: true }, s5: { hidden: true }, s6: { hidden: true },
    },
  },
  {
    id: 'tpl_topo', name: '网络拓扑', scene: '拓扑值守', builtin: true,
    // 2026-09-29: 用户要求新增"网络拓扑"默认模板 —— 把拓扑卡放大为主视觉(与攻击态势把
    // 地球放大到 1372 宽同口径, 拓扑卡用相同的大画布占比), 右侧挂漏洞分级/告警/任务柱状,
    // 底部四指标兜底整体态势。其余图表卡隐藏避免重叠。
    layout: {
      topo: { x: 16, y: 16, w: 1372, h: 852 },
      vl: { x: 1404, y: 16, w: 500, h: 273 },
      at: { x: 1404, y: 305, w: 500, h: 273 },
      tb: { x: 1404, y: 594, w: 500, h: 273 },
      m1: { x: 16, y: 884, w: 460, h: 180, cfg: M('风险总量', 'vulnRisk') },
      m2: { x: 492, y: 884, w: 460, h: 180, cfg: M('今日新增', 'findingToday') },
      m3: { x: 968, y: 884, w: 460, h: 180, cfg: M('已完成任务', 'taskSuccess') },
      m4: { x: 1444, y: 884, w: 460, h: 180, cfg: M('任务成功率', 'successRate') },
      globe: { hidden: true },
      ap: { hidden: true },
      gt1: { hidden: true }, gt2: { hidden: true }, gt3: { hidden: true },
      s1: { hidden: true }, s2: { hidden: true }, s3: { hidden: true },
      s4: { hidden: true }, s5: { hidden: true }, s6: { hidden: true },
    },
  },
]

// ===== 持久化 =====
export function loadTpls() {
  try {
    const a = JSON.parse(localStorage.getItem(TPL_KEY) || '[]')
    return Array.isArray(a) ? a : []
  } catch (e) { return [] }
}
function persist(list) {
  try { localStorage.setItem(TPL_KEY, JSON.stringify(list)) } catch (e) { /* 忽略 */ }
  return list
}
export function saveTpl(name, scene, layout) {
  const list = loadTpls().filter(t => t.name !== name)
  return persist(list.concat([{ id: 'ut_' + Date.now().toString(36), name: name || '未命名模板', scene: scene || '自定义', builtin: false, layout }]))
}
export function renameTpl(id, name) {
  return persist(loadTpls().map(t => (t.id === id ? Object.assign({}, t, { name: name || t.name }) : t)))
}
export function delTpl(id) { return persist(loadTpls().filter(t => t.id !== id)) }
export function allTpls() { return BUILTIN.concat(loadTpls()) }
export function findTpl(id) { return allTpls().find(t => t.id === id) || null }

// 当前模板(供拓扑页"返回安全大屏"时还原)
export function setCur(id) { try { localStorage.setItem(CUR_KEY, id || '') } catch (e) { /* 忽略 */ } }
export function getCur() { try { return localStorage.getItem(CUR_KEY) || '' } catch (e) { return '' } }

// ===== 应用 / 快照 =====
// 只处理有 key 的元素; 未知 key 的卡片原样保留(用户自己加的卡不该被模板搬走)
export function applyLayout(cards, layout) {
  if (!layout) return
  for (const c of cards) {
    const hit = c.key && layout[c.key]
    if (!hit) continue
    // 先重置后应用: 目标模板**显式决定**显隐(缺省=可见), 几何/配置随之落地。
    // 旧逻辑只在 hit.hidden 有值时才改, 导致从"隐藏了某卡"的模板切回"应显示该卡"的
    // 模板时, 卡片残留 hidden:true(表现为反复切换后卡片莫名消失 = 布局错乱)。
    c.hidden = !!hit.hidden
    if (!c.hidden) {
      if (hit.x != null) c.x = hit.x
      if (hit.y != null) c.y = hit.y
      if (hit.w != null) c.w = hit.w
      if (hit.h != null) c.h = hit.h
    }
    if (hit.cfg) Object.assign(c, hit.cfg)
  }
}
export function snapshotLayout(cards) {
  const out = {}
  for (const c of cards) {
    if (!c.key) continue
    out[c.key] = { x: c.x, y: c.y, w: c.w, h: c.h, hidden: !!c.hidden }
  }
  return out
}

// ===== 导出 / 导入(跨环境迁移) =====
export function exportTpl(t) {
  return JSON.stringify({ name: t.name, scene: t.scene, layout: snapshotLayoutOf(t.layout) }, null, 2)
}
function snapshotLayoutOf(l) { return l }
export function importTpl(text) {
  const o = JSON.parse(text)
  if (!o || !o.layout) throw new Error('模板 JSON 缺少 layout 字段')
  return saveTpl(o.name || '导入模板', o.scene || '导入', o.layout)
}
