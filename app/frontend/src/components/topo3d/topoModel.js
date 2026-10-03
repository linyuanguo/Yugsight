// 独立 3D 拓扑页的模型层(2026-09-28)。
//
// 放这里而不是塞进页面: 布局算法 / 状态映射 / Mock 数据与渲染解耦, 页面三套视图
// (逻辑 / 机房 / 力导向)只是换一个 layout 函数, 渲染层完全不用改。
//
// 【3D 实现方式说明】本页"3D"是 CSS 3D(perspective + rotateX/rotateY) + 原生 SVG,
// 不加载 WebGL: 仓库里的 three 只以 globe.gl 内嵌形式存在(build/globe/globe.gl.min.js),
// UMD 既不导出 window.THREE 也不含 OrbitControls, 无法拿来自定义节点/链路场景;
// 强行引 three 需要新增 npm 依赖或本地 ESM 文件, 违反"零第三方依赖 + 单二进制"约束。
// 平移/缩放/旋转/复位/自动巡检这些 OrbitControls 能力在 CSS 3D 下同样能实现。

// 分组盒(2026-09-29 用户要求"框框自定义"): 物理分层盒(核心/汇聚/接入)与逻辑业务组
// 都是用户数据 —— 可改名/增删/调高度, localStorage 持久化。这里是**默认值**,
// 页面 loadGroups() 无本地数据时以它为初始; 运行期以页面传入的 bands/clusters 为准。
export const DEFAULT_BANDS = [
  { key: 'b1', name: '核心层', h: 200 },
  { key: 'b2', name: '汇聚层', h: 220 },
  { key: 'b3', name: '接入层', h: 200 },
]
export const DEFAULT_CLUSTERS = [
  { key: 'network', name: '网络设备' },
  { key: 'service', name: '业务服务' },
  { key: 'other', name: '其它' },
]
// 自定义层列表 → 逐层累计 top(层高可拖拽/输入调整, 盒高即节点排布带的上下界)
export function bandTops(bands) {
  const list = (bands && bands.length) ? bands : DEFAULT_BANDS
  let y = 0
  return list.map(b => {
    const h = Math.max(60, Math.min(320, Number(b.h) || 160))
    const t = { key: b.key, name: b.name, h, top: y }
    y += h
    return t
  })
}
// 兼容旧引用(3D 视图 layoutRack 等按 layer 1|2|3 编号): 编号=默认层序
export const LAYERS = DEFAULT_BANDS.map((b, i) => ({ layer: i + 1, label: b.name, top: 0, h: b.h }))

// 资产类型(2026-09-29 第四阶段扩展): 网络设备 + 业务服务 两组, 对齐资产库分类与 Zabbix 图标口径。
// group=network|service 供设备库分组与逻辑拓扑聚类; layer=物理分层(核心1/汇聚2/接入3)供物理拓扑排布。
// 图标用辨识度高的几何字形(零第三方依赖, 不引图标库), 各类型互不重复。
export const TYPES = {
  // 网络设备
  router:     { t: '路由器',     g: '⇄', layer: 1, group: 'network' },
  coresw:     { t: '核心交换机', g: '▤', layer: 1, group: 'network' },
  l3sw:       { t: '三层交换机', g: '⋔', layer: 2, group: 'network' },
  l2sw:       { t: '二层交换机', g: '⊞', layer: 2, group: 'network' },
  aggsw:      { t: '汇聚交换机', g: '▦', layer: 2, group: 'network' },
  firewall:   { t: '防火墙',     g: '⛨', layer: 2, group: 'network' },
  // 业务服务
  database:   { t: '数据库',     g: '⛁', layer: 3, group: 'service' },
  middleware: { t: '中间件',     g: '⧉', layer: 3, group: 'service' },
  web:        { t: 'Web 服务',   g: '◈', layer: 3, group: 'service' },
  server:     { t: '服务器',     g: '▥', layer: 3, group: 'service' },
  probe:      { t: '探针终端',   g: '◎', layer: 3, group: 'service' },
}
export const TYPE_GROUPS = [
  { key: 'network', label: '网络设备' },
  { key: 'service', label: '业务服务' },
]
// 平铺(按组序)供"添加设备"菜单/设备库使用, 网络在前、业务在后
export const TYPE_OPTIONS = TYPE_GROUPS.flatMap(g =>
  Object.keys(TYPES).filter(v => TYPES[v].group === g.key).map(v => ({ v, t: TYPES[v].t })))
export function typeText(t) { return (TYPES[t] && TYPES[t].t) || t || '未识别' }
export function typeGlyph(t) { return (TYPES[t] && TYPES[t].g) || '▣' }
export function layerForType(t) { return (TYPES[t] && TYPES[t].layer) || 3 }
export function bizGroup(t) { return (TYPES[t] && TYPES[t].group) || 'other' }

export const STATUS_CN = { normal: '正常', warn: '告警', error: '异常', down: '断开' }
export const STATUS_COLOR = { normal: '#34d399', warn: '#fbbf24', error: '#f87171', down: '#94a3b8' }
// 链路颜色按"连通状态"三色口径(2026-09-29 新拓扑架构): 绿=正常 / 黄=告警 / 红=中断,
// 与节点安全状态四色同源, 便于整屏一眼对齐。旧版青/橙已改绿/黄。
export const LINK_COLOR = { normal: '#34d399', warn: '#fbbf24', down: '#f87171' }

// ===== 安全状态四色映射(2026-09-29 新拓扑架构) =====
// 规格口径: 绿=在线/低风险, 黄=告警/中风险, 红=离线/高危, 灰=未监控。
// 颜色同时编码"连通性 + 风险等级 + 是否纳管"三个维度, 不是 status 的直译:
//   未纳管(isMonitor=false)   → gray  (数据不可信, 不纳入风险配色)
//   离线(down) 或 高危(error) → red   (需要立即关注, 离线与高危同级)
//   告警/中危(warn)           → yellow
//   在线且低风险(normal)      → green
export const SAFE_COLOR = { green: '#34d399', yellow: '#fbbf24', red: '#f87171', gray: '#64748b' }
export const SAFE_CN = { green: '在线/低风险', yellow: '告警/中风险', red: '离线/高危', gray: '未监控' }
export function safeStatus(n) {
  if (!n || !n.isMonitor) return 'gray'
  if (n.status === 'down' || n.status === 'error') return 'red'
  if (n.status === 'warn') return 'yellow'
  return 'green'
}
export function safeColor(n) { return SAFE_COLOR[safeStatus(n)] || SAFE_COLOR.gray }

// 告警级别三色(规格: 提示=蓝 / 一般=黄 / 严重=红)
export const ALERT_LEVEL_COLOR = { info: '#38bdf8', warning: '#fbbf24', critical: '#f87171' }
export const ALERT_LEVEL_CN = { info: '提示', warning: '一般', critical: '严重' }
// 后端有两套级别词: collect.Event 用 info|warn|critical, node_alerts 用 info|warning|critical
// → 统一归一到 info|warning|critical 三档, 避免前端按词面判断漏档。
export function normAlertLevel(lv) {
  const s = String(lv == null ? '' : lv).toLowerCase()
  if (s === 'warn' || s === 'warning' || s === 'medium') return 'warning'
  if (s === 'critical' || s === 'error' || s === 'high') return 'critical'
  return 'info'
}

// ===== 状态防抖(2026-09-29 新拓扑架构) =====
// 规格: 连续 N 次检测到异常才真正变更显示状态, 避免网络抖动导致节点颜色频繁跳变。
// 纯函数 + 外部维护的 streak 状态({pending, n}): 异常"起"需连续 3 次; 恢复(normal)立即生效
// (快速回绿, 避免"实际已恢复却仍显示告警")。prev=当前显示态, raw=本次观测态。
export const DEBOUNCE_N = 3
export function stepDebounce(prev, raw, streak) {
  if (raw === prev) { streak.pending = ''; streak.n = 0; return prev }
  if (raw === 'normal') { streak.pending = ''; streak.n = 0; return 'normal' }
  if (streak.pending === raw) {
    streak.n++
    if (streak.n >= DEBOUNCE_N) { streak.pending = ''; streak.n = 0; return raw }
  } else {
    streak.pending = raw; streak.n = 1
  }
  return prev
}

export function uid(p = 'x') { return p + '_' + Math.random().toString(36).slice(2, 9) }

// 设备库拖拽的 dataTransfer 类型标识(设备树 → 2D 画布, 借鉴 Zabbix 元素库拖拽)。
// 独立 MIME 而非 'text/plain': 避免与浏览器自带的文本拖拽混淆。
export const TOPO_TYPE_MIME = 'text/topo-type'

// 负载 → 色(绿→黄→红), 与卡片/大屏同一映射口径
export function loadColor(cpu, mem) {
  const v = Math.max(0, Math.min(100, Math.max(cpu || 0, mem || 0)))
  return `hsl(${Math.round(140 * (1 - v / 100))} 80% 55%)`
}
export function loadPct(cpu, mem) { return Math.max(0, Math.min(100, Math.max(cpu || 0, mem || 0))) }

// ===== 由 dashData 设备构造拓扑节点实例(deviceId 是全局主键) =====
export function nodeFromDevice(d, seq = 0) {
  const layer = Number(d.layer) || layerForType(d.type)
  return {
    nodeId: uid('nd'), deviceId: d.deviceId, name: d.name, type: d.type || 'server', layer,
    x: 0, y: 0, z: 0,                       // 由 layout 填充
    ip: d.ip || '', mac: d.mac || '',
    cpu: d.cpu || 0, memory: d.memory || 0, status: d.status || 'normal',
    isMonitor: !!d.isMonitor, seq,
  }
}
// 速率按 IP 补全(2026-10-01 真机): 从资产台账手动拖进画布的节点是 A_*(isMonitor=false),
// 同步循环只更新纳管节点 → 该 IP 明明有 SNMP 真实速率却不显示(用户: "上下带宽没显示")。
// 同 IP = 同一台设备(与设备列表"同 IP 去重"同口径), 因此按 IP 命中纳管设备的真实速率
// 补全; 只补速率 —— 状态/CPU 仍只认纳管节点(不顺便把资产节点判成在线)。
export function fillRatesByIP(nodes, devices) {
  const byIp = new Map()
  for (const d of (devices || [])) {
    if (d.isMonitor && d.ip) byIp.set(d.ip, d)
  }
  if (!byIp.size) return
  for (const n of (nodes || [])) {
    if (n.isMonitor) continue
    const d = byIp.get(n.ip)
    if (!d) continue
    n.inBps = d.inRateBps || 0
    n.outBps = d.outRateBps || 0
  }
}
export function newNode(type, x, y) {
  return {
    nodeId: uid('nd'), deviceId: 'U_' + Math.random().toString(36).slice(2, 9),
    name: typeText(type), type, layer: layerForType(type), x, y, z: 0,
    ip: '', mac: '', cpu: 0, memory: 0, status: 'normal', isMonitor: false,
  }
}
export function newLink(a, b) {
  return {
    linkId: uid('lk'), fromDeviceId: a.deviceId, toDeviceId: b.deviceId,
    bandwidth: 1000, packetLoss: 0, delay: 2, status: 'normal', pps: 0,
    kind: 'primary',   // primary=主用(实线) / backup=备用(虚线), 由用户右键"设置备用链路"标记
    // 连通性口径(2026-09-29 用户要求): 手动连线只是"画了线", 不算"通" ——
    // tested=false 时画布灰虚线"未测", 必须点"测试连通"(中心端真实探测两端 IP)
    // 才翻成 绿=已连通 / 红=未连通。pps=0: 未测链路没有真实流量, 不套 Mock 系数。
    tested: false, checkedAt: 0,
    // 2026-10-01: 用户实画标记 —— 区分"实画线"(走真实连通测试/绿红)与"推测边"
    // (后端按网段猜的 _real 边, 未经实测显示"推测"细虚线, 见 TopoScene2D isInferred)
    userDrawn: true,
  }
}

// ===== 布局算法(三套视图各自一个) =====
export const W = 1200, H = 720

// ① 逻辑分层: 按层级分带, 带内等距排开。bands=用户自定义层列表(可改名/增删/调高);
// 缺省走 DEFAULT_BANDS(与旧 LAYERS 同几何, 零行为变化)。节点 layer 号=层序(1 基),
// 层被删导致越界时钳到最后一层(兜底, 不丢节点)。
export function layoutLayered(nodes, bands) {
  const list = (bands && bands.length) ? bands : DEFAULT_BANDS
  const tops = bandTops(list)
  const byLayer = {}
  for (const n of nodes) {
    const k = Math.min(Math.max(1, Number(n.layer) || 1), list.length)
    ;(byLayer[k] || (byLayer[k] = [])).push(n)
  }
  tops.forEach((band, i) => {
    const arr = byLayer[i + 1] || []
    const cy = band.top + band.h / 2
    arr.forEach((n, j) => {
      n.x = Math.round(W * (j + 1) / (arr.length + 1))
      n.y = Math.round(cy + (j % 2 ? 26 : -26))
      n.z = 0
    })
  })
}

// ② 机房机柜: 每层一列机柜, 设备在柜内按 U 位堆叠(z 为进深)
export function layoutRack(nodes) {
  const byLayer = { 1: [], 2: [], 3: [] }
  for (const n of nodes) (byLayer[n.layer] || byLayer[3]).push(n)
  const cols = [190, 600, 1010]
  for (const k of [1, 2, 3]) {
    const arr = byLayer[k]
    const col = cols[k - 1]
    arr.forEach((n, i) => {
      const per = 5
      n.x = Math.round(col + Math.floor(i / per) * 130)
      n.y = Math.round(160 + (i % per) * 110)
      n.z = Math.round((i % per) * 20)
    })
  }
}

// ③ 2D 力导向: 斥力 + 弹簧 + 向心力, 迭代收敛(纯函数式, 不引入图布局库)
export function layoutForce(nodes, links, iters = 220) {
  const n = nodes.length
  if (!n) return
  const idx = new Map(nodes.map((d, i) => [d.deviceId, i]))
  const px = new Float64Array(n), py = new Float64Array(n)
  nodes.forEach((d, i) => {
    px[i] = d.x || (W / 2 + (Math.random() - 0.5) * 300)
    py[i] = d.y || (H / 2 + (Math.random() - 0.5) * 200)
  })
  const edges = (links || []).map(l => [idx.get(l.fromDeviceId), idx.get(l.toDeviceId)])
    .filter(e => e[0] !== undefined && e[1] !== undefined)
  for (let it = 0; it < iters; it++) {
    const k = 16000 / (it + 40)   // 斥力随迭代衰减, 避免末段抖动
    const fx = new Float64Array(n), fy = new Float64Array(n)
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let dx = px[i] - px[j], dy = py[i] - py[j]
        let d2 = dx * dx + dy * dy
        if (d2 < 1) { d2 = 1; dx = Math.random() - 0.5; dy = Math.random() - 0.5 }
        const d = Math.sqrt(d2)
        const f = k / d2
        const ux = dx / d * f, uy = dy / d * f
        fx[i] += ux; fy[i] += uy; fx[j] -= ux; fy[j] -= uy
      }
    }
    for (const [a, b] of edges) {
      const dx = px[b] - px[a], dy = py[b] - py[a]
      const d = Math.max(1, Math.hypot(dx, dy))
      const f = (d - 190) * 0.02
      const ux = dx / d * f, uy = dy / d * f
      fx[a] += ux; fy[a] += uy; fx[b] -= ux; fy[b] -= uy
    }
    for (let i = 0; i < n; i++) {
      fx[i] += (W / 2 - px[i]) * 0.004
      fy[i] += (H / 2 - py[i]) * 0.004
      px[i] += Math.max(-30, Math.min(30, fx[i]))
      py[i] += Math.max(-30, Math.min(30, fy[i]))
      px[i] = Math.max(60, Math.min(W - 60, px[i]))
      py[i] = Math.max(60, Math.min(H - 60, py[i]))
    }
  }
  nodes.forEach((d, i) => { d.x = Math.round(px[i]); d.y = Math.round(py[i]); d.z = 0 })
}

// ===== 网段分组与逻辑聚类(2026-09-29 第四阶段: 子网折叠/钻取 + 物理/逻辑视图) =====
// 网段 = 按 IP 前 3 段(/24)归组; 无合法 IPv4 的归入"未分组"。前缀作稳定分组键。
export function subnetKey(ip) {
  const p = String(ip || '').split('.')
  if (p.length < 4 || !/^\d+$/.test(p[0])) return '_ungrouped'
  return p.slice(0, 3).join('.')
}
export function subnetLabel(ip) {
  const k = subnetKey(ip)
  return k === '_ungrouped' ? '未分组网段' : k + '.0/24'
}
// 子网整体状态 = 成员中最差的安全状态(red>yellow>green>gray), 供折叠汇总节点着色
export function subnetStatus(members) {
  const rank = { gray: 0, green: 1, yellow: 2, red: 3 }
  let worst = 'green'
  for (const n of members || []) {
    const s = safeStatus(n)
    if (rank[s] > rank[worst]) worst = s
  }
  return worst
}
// 按网段把节点分组: [{key, label, members[]}] ; 已分组在前(按 IP 数值序), 未分组殿后
export function groupBySubnet(nodes) {
  const map = new Map()
  for (const n of nodes) {
    const k = subnetKey(n.ip)
    if (!map.has(k)) map.set(k, { key: k, label: subnetLabel(n.ip), members: [] })
    map.get(k).members.push(n)
  }
  const groups = [...map.values()]
  groups.sort((a, b) => (a.key === '_ungrouped' ? 1 : b.key === '_ungrouped' ? -1
    : String(a.key).localeCompare(String(b.key), undefined, { numeric: true })))
  return groups
}
// 逻辑视图布局: 按业务组(用户自定义, 可增删改名)分簇, 簇=等宽竖列, 簇内网格排布。
// 节点归属 = n.biz(用户在属性面板指定, 可覆盖类型默认); 未指定时按类型 group 落默认组,
// 该组已被删则落第一组(兜底, 不丢节点)。
export function layoutLogical(nodes, clusters) {
  const list = (clusters && clusters.length) ? clusters : DEFAULT_CLUSTERS
  const byGroup = {}
  for (const c of list) byGroup[c.key] = []
  for (const n of nodes) {
    const g = n.biz || bizGroup(n.type)
    const k = byGroup[g] ? g : list[0].key
    byGroup[k].push(n)
  }
  const colW = W / list.length
  list.forEach((c, i) => {
    const arr = byGroup[c.key]
    if (!arr.length) return
    arr.sort((a, b) => layerForType(a.type) - layerForType(b.type) || (a.type || '').localeCompare(b.type || ''))
    const per = Math.max(1, Math.ceil(Math.sqrt(arr.length)))
    const gap = Math.min(120, (colW * 0.8) / Math.max(1, per))
    const cx = colW * (i + 0.5)
    arr.forEach((n, j) => {
      const col = j % per, row = Math.floor(j / per)
      n.x = Math.round(cx + (col - per / 2 + 0.5) * gap)
      n.y = Math.round(130 + row * Math.min(110, gap))
      n.z = 0
    })
  })
}
// 钻取单网段时: 把该网段成员铺满整个画布(居中网格), 内部完整拓扑展示
export function layoutSubnetFill(members) {
  if (!members.length) return
  const per = Math.max(1, Math.ceil(Math.sqrt(members.length)))
  const gapX = Math.min(180, (W * 0.82) / Math.max(1, per))
  const gapY = Math.min(150, (H * 0.74) / Math.max(1, Math.ceil(members.length / per)))
  members.forEach((n, i) => {
    const col = i % per, row = Math.floor(i / per)
    n.x = Math.round(W / 2 + (col - per / 2 + 0.5) * gapX)
    n.y = Math.round(H / 2 + (row - Math.ceil(members.length / per) / 2 + 0.5) * gapY)
    n.z = 0
  })
}

// ===== Mock: 链路 / 端口 / 24 小时时序 =====
//
// 后端当前没有网络拓扑链路接口, 这里给出**与后端待实现字段一一对应**的 Mock,
// 接口就绪后只需把 dashData.loadNetworkLinks() 的 URL 打开即可替换(见 dashData 注释)。
export function mockLinks(nodes) {
  const out = []
  const byLayer = { 1: [], 2: [], 3: [] }
  for (const n of nodes) (byLayer[n.layer] || byLayer[3]).push(n)
  // 核心→汇聚全互联
  for (const a of byLayer[1]) for (const b of byLayer[2]) out.push(link(a, b))
  // 汇聚→接入按序挂接
  byLayer[3].forEach((c, i) => {
    const up = byLayer[2][i % Math.max(1, byLayer[2].length)]
    if (up) out.push(link(up, c))
  })
  // 汇聚层横向堆叠链路
  for (let i = 0; i + 1 < byLayer[2].length; i++) out.push(link(byLayer[2][i], byLayer[2][i + 1]))
  return out
}
function link(a, b) {
  return {
    linkId: uid('lk'), fromDeviceId: a.deviceId, toDeviceId: b.deviceId,
    bandwidth: [10000, 40000, 1000][Math.floor(Math.random() * 3)],
    packetLoss: 0, delay: Math.round((Math.random() * 4 + 0.5) * 10) / 10,
    status: 'normal', pps: Math.round(800 + Math.random() * 9000),
    kind: 'primary',
  }
}
// 2026-09-29 移除两个 Mock 生成器(用户要求"没测过不算通 / 数据必须是真的"):
// - applyHour(Mock 链路 24h 流量系数): 手动链路未测通前不套假流量, 后端真实链路
//   (_real) 自带真实 pps/utilPct, 时间轴失去作用对象 → 函数删除, 时间轴禁用。
// - mockPorts(假端口表 Gig0/1…): 端口详情改走 /api/v2/monitor/samples 真实 SNMP
//   接口表(两帧差分出速率), 主机类设备不显示端口表, 无监控目标时明示"未纳管"。
export function mockSeries24() {
  const out = []
  for (let h = 0; h < 24; h++) {
    const wave = 0.5 + 0.5 * Math.sin((h / 24) * Math.PI * 2 - 1.2)
    out.push({
      h,
      throughput: Math.round(40 + wave * 55),      // 带宽均值 %
      loss: Math.round((0.2 + Math.random() * 1.4) * 10) / 10,
      latency: Math.round((2 + wave * 8) * 10) / 10,
      alerts: Math.floor(Math.random() * 3),
    })
  }
  return out
}
