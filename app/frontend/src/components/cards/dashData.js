// 大屏组件库共享数据层(2026-09-27)。
//
// 为什么必须是共享单例: 画布上一屏可能有十几张图表卡, 若每张卡各自轮询
// /api/v2/screen/overview, 15 秒一轮很快就变成十几路并发请求, 而且各卡拿到的数据
// 不是同一时刻的快照 —— 同一屏上"漏洞总数"和"分级占比"对不上是最难解释的 bug。
// 这里用引用计数保证: 首张卡挂载即起一个 15s 轮询, 全部卸载才停, 所有卡共用同一份
// reactive 快照, 整屏数据天然同源同时刻。
//
// 数据源口径(与首页仪表盘 / 安全大屏 Tab2 完全一致, 不是另起炉灶):
//   - /api/v2/screen/overview  → 漏洞分级/趋势/任务/probe/榜单/最近任务
//   - /api/dashboard/flows     → IP 流向(3D 地球的轨迹与事件点)
// 任一路失败只降级该路(保留上一次快照), 不整屏报错 —— 项目规则 3: 失败降级不崩。
import { reactive, onBeforeUnmount } from 'vue'
import { v2, v2dash } from '../../api/http.js'
import { mockLinks } from '../topo3d/topoModel.js'

const S = reactive({
  ov: null, flows: null, frames: [], err: '', errFlow: '',
  updatedAt: '',
  // 纳管设备(探针/合法监控对象) + 未纳管候选(扫描发现的资产), 统一 deviceId 主键
  devices: [], errDev: '', devUpdatedAt: '',
  // 链路统计(告警链路数/离线链路数/带宽利用率)的挂载点: 后端当前没有链路接口,
  // 保持 null 让上层显示"—"而不是编一个数字出来; 接口上线后在这里填即可。
  netSummary: null,
  // 网络拓扑链路(独立 3D 拓扑页用)。linkSource: 'api' | 'mock'
  networkLinks: [], linkSource: '', linkUpdatedAt: '', errLink: '',
  // 拓扑页本地"自定义节点"计数(独立于纳管设备; 由 /topology/3d 增删时同步)。
  // 2026-09-29: 大屏网络拓扑卡(TopoCard)直接读同一份 localStorage 布局(yugsight_topo3d_layout)
  // 自行计数, 不走此计数器; 此值现仅 /topology/3d 独立页展示用。
  topoCustomCount: readTopoCustom(),
})

let timer = null
let refs = 0
let beat = 0 // 轮询拍数: 资产列表较重, 按拍降频

async function loadOverview() {
  try {
    // 一次取 30 天趋势: 卡片需要 7 天窗口时在本地切片即可, 不必为不同组件重复请求
    S.ov = await v2('/screen/overview?days=30&top=10&recent=30')
    S.err = ''
    S.updatedAt = new Date().toISOString()
  } catch (e) {
    S.err = (e && e.message) || '概览数据获取失败'
  }
}
async function loadFlows() {
  try { S.flows = await v2dash('/api/dashboard/flows'); S.errFlow = '' } catch (e) {
    S.errFlow = (e && e.message) || '流向数据获取失败'
  }
  try {
    const d = await v2dash('/api/dashboard/flows?timeline=1')
    S.frames = (d && d.frames) || []
  } catch (e) { /* 回放帧失败不影响总览 */ }
}

// ===== 网络设备列表(拓扑「设备实例化」的唯一数据源) =====
//
// 为什么分多路合成, 而不是要求后端新加一个"设备列表接口":
//   ① 纳管设备的实时指标(cpu/内存/在线)本来就在 overview.probes 里, 且是同一份 15s
//      轮询快照 —— 再开一个接口只会让"卡片上的 CPU"和"拓扑里的 CPU"又对不上;
//   ② 但 overview.probes 只有"IP 列表", 没有 MAC / 网卡信息, 而拓扑需要 MAC,
//      所以再从 /api/v2/probe/list 取一次静态档案(NodeInfo.NetIfaces)补齐;
//   ③ 未纳管候选用已发现的资产(/api/v2/assets), 供"标注还没纳管的设备"。
// 各路由失败只降级该路, 不让整张拓扑变空白(项目规则 3)。
//
// 2026-09-30 用户要求: 拓扑「绑定节点」应绑"协议配置里的监控目标"(主机 ssh/winrm/
// snmp、网络侧采集、SNMP 网络监控目标、探针), 而不是扫描发现的资产。
//   ④ SNMP 网络监控目标 /api/v2/monitor/status.targets(M_ 前缀, isMonitor=true)
//   ⑤ 采集任务(主机侧/网络侧) /api/v2/node/tasks(C_ 前缀, isMonitor=true;
//      netflow 是监听器不是设备, 不入设备清单)
// 绑定弹窗/属性面板按 isMonitor 过滤候选; 资产(A_)保留在台账供展示与去重。

// 类型 → 层级(2026-09-28 口径: 路由器/核心交换机→核心层, 汇聚交换机/防火墙→汇聚层,
// 探针/终端服务器/其它发现设备→接入层)
export const LAYER_BY_TYPE = {
  router: 1, coresw: 1, firewall: 2, aggsw: 2,
  probe: 3, server: 3, terminal: 3, unknowndevice: 3,
}
export const TYPE_CN = {
  router: '路由器', coresw: '核心交换机', aggsw: '汇聚交换机', firewall: '防火墙',
  probe: '探针', server: '服务器', terminal: '终端', unknowndevice: '未识别设备',
}
export const TYPE_OPTIONS = Object.keys(TYPE_CN).map(v => ({ v, t: TYPE_CN[v] }))
export function layerForType(t) { return LAYER_BY_TYPE[t] || 3 }

function statusOfProbe(online, cpu, mem) {
  if (!online) return 'down'
  const m = Math.max(cpu || 0, mem || 0)
  if (m >= 90) return 'error'
  if (m >= 75) return 'warn'
  return 'normal'
}

async function loadNetworkDevices() {
  const out = []
  // ---- ① 纳管设备: 探针档案(MAC/网卡) ----
  let probeRows = []
  try {
    const r = await v2('/probe/list')
    probeRows = (r && r.list) || []
  } catch (e) {
    probeRows = null // 档案取不到不致命: 仍可用 overview 的运行时指标
  }
  // ---- ② 纳管设备运行时指标(overview.probes, 同源同时刻) ----
  const runtime = {}
  for (const p of ((S.ov && S.ov.probes) || [])) runtime[p.id] = p
  // ---- ②b 探针网卡端口明细(2026-10-02: 探针上报的 load.ifaces, 拓扑"端口详情"用) ----
  // 走 /probe/status 的 online(带 load), overview.probes 只有汇总指标没有端口清单;
  // 取不到不影响其它设备(降级为空清单)。
  const probeIfaces = {}
  try {
    const ps = await v2('/probe/status')
    for (const o of ((ps && ps.online) || [])) {
      const ld = o.load || {}
      if (Array.isArray(ld.ifaces) && ld.ifaces.length) probeIfaces[o.probeId] = ld.ifaces
    }
  } catch (e) { /* 中心端未启用/接口失败: 无端口清单, 不致命 */ }
  if (probeRows) {
    for (const row of probeRows) {
      const info = (row.nodeInfo) || {}
      const rt = runtime[row.id] || {}
      const ips = (info.localIps && info.localIps.length) ? info.localIps : String(row.addr || '').split(',')
      const face = (info.netIfaces || [])[0] || {}
      out.push({
        deviceId: 'P_' + row.id,           // 主键: P_ 前缀=探针来源, A_ =资产来源, 全局唯一
        source: 'probe', isMonitor: true,
        name: row.name || info.hostname || row.id,
        type: 'probe', ip: (ips[0] || '').trim(), ips: ips,
        mac: face.mac || '', cpu: Math.round(rt.cpuPercent || 0),
        memory: Math.round(rt.memPercent || 0),
        // 网卡端口清单(探针上报; 老版本探针没有该字段 → 空数组, 端口详情给"待升级"提示)
        ifaces: probeIfaces[row.id] || [],
        status: statusOfProbe(rt.online !== false && row.online !== false, rt.cpuPercent, rt.memPercent),
        layer: 3,
      })
    }
  } else {
    // 降级: 只有运行时数据时也能出设备(IP/MAC 缺失由上层置灰处理)
    for (const p of Object.values(runtime)) {
      out.push({
        deviceId: 'P_' + p.id, source: 'probe', isMonitor: true,
        name: p.name || p.hostname || p.id, type: 'probe',
        ip: String(p.addr || '').split(',')[0], ips: String(p.addr || '').split(','),
        mac: '', cpu: Math.round(p.cpuPercent || 0), memory: Math.round(p.memPercent || 0),
        ifaces: probeIfaces[p.id] || [],
        status: statusOfProbe(p.online, p.cpuPercent, p.memPercent), layer: 3,
      })
    }
  }
  // 同 IP 去重集: 探针之后持续累积(同一台机器被多路纳管时只出一次)
  const existingIp0 = new Set(out.map(d => d.ip))
  // ---- ④ SNMP 网络监控目标(2026-09-30: 绑定节点=协议配置监控目标, 如 172.16.199.1) ----
  let monTargets = []
  try {
    const r = await v2('/monitor/status')
    monTargets = (r && r.targets) || []
  } catch (e) { monTargets = [] } // 该路失败只降级
  for (const t of monTargets) {
    const ip = t.addr ? String(t.addr).split(':')[0] : ''
    if (ip && existingIp0.has(ip)) continue // 与探针同 IP 不重复(装机即纳管)
    existingIp0.add(ip)
    const memPct = t.memTotal ? Math.round((t.memUsed / t.memTotal) * 100) : 0
    // 2026-10-01: 内置"中心端(本机)"(source=center)是主机不是交换机 —— 类型/层
    // 按主机算, 否则拓扑把它画成核心交换机(图标与层级都错)。
    const isCenter = t.source === 'center'
    out.push({
      deviceId: 'M_' + t.id, source: 'monitor', isMonitor: true,
      name: t.name || t.addr, type: isCenter ? 'server' : 'coresw', ip, ips: ip ? [ip] : [],
      mac: t.mac || '', cpu: Math.round(t.cpuLoad || 0), memory: memPct,
      // 2026-09-30: 该端接口真实上下行速率(SNMP 两帧差分, 后端 monitor/status 回带)——
      // 拓扑手动链路(端点常是 M_* 监控设备)的线上速率展示靠它, 无数据为 0=不画光点
      inRateBps: t.inRateBps || 0, outRateBps: t.outRateBps || 0,
      // 2026-10-02: 中心端(本机)网卡端口清单(后端 centerMonitorView 按探针同一实现
      // 回带, 全量无 top5 截断)——拓扑"中心端节点选网口"靠它。普通 SNMP 目标 status
      // 里的 ifaces 只有 TOP5(全量走 /samples 的 snmpPorts 路径), 不能塞这里, 否则
      // 交换机端口下拉会从 113 口缩水成 5 口。
      ifaces: isCenter
        ? (t.ifaces || []).map(f => ({ name: f.name, state: f.up ? 'up' : '', inBps: f.inRate || 0, outBps: f.outRate || 0, speed: f.speed || 0 }))
        : [],
      status: statusOfProbe(!!t.online, Math.round(t.cpuLoad || 0), memPct),
      layer: isCenter ? 3 : 1,   // 中心端=主机层(3), SNMP 网络设备=核心层(1)
    })
  }
  // ---- ⑤ 采集任务(主机侧 winrm/ssh/snmp + 网络侧 icmp/netflow/netconf/restconf) ----
  let collectTasks = []
  try {
    const r = await v2('/node/tasks')
    collectTasks = (r && r.tasks) || []
  } catch (e) { collectTasks = [] } // 该路失败只降级
  for (const t of collectTasks) {
    if (t.protocol === 'netflow') continue // netflow 是监听器(0.0.0.0:2000), 不是设备
    const ip = t.target ? String(t.target).split(':')[0] : ''
    if (ip && existingIp0.has(ip)) continue // 同 IP 已纳管(探针/SNMP 目标)不重复
    if (ip) existingIp0.add(ip)
    const cpu = metricVal(t, 'cpu')
    const mem = metricVal(t, 'mem_used_pct')
    out.push({
      deviceId: 'C_' + t.id, source: 'collect', isMonitor: true,
      name: t.name || t.target,
      type: t.side === 'net' ? 'coresw' : 'server', // 网络侧协议=网络设备, 主机侧协议=主机
      ip, ips: ip ? [ip] : [],
      mac: '', cpu: cpu != null ? Math.round(cpu) : 0, memory: mem != null ? Math.round(mem) : 0,
      // 网卡端口清单(nic 指标, SSH/WinRM/主机SNMP 采集上报; 速率由端口详情对两轮样本差分)
      ifaces: nicList(t.metrics),
      status: statusOfProbe(!!t.online, cpu != null ? Math.round(cpu) : 0, mem != null ? Math.round(mem) : 0),
      layer: t.side === 'net' ? 1 : 3,
    })
  }
  // ---- ⑥ 未纳管候选: 已发现资产(较重, 由调用方按拍降频) ----
  for (const a of assetCache) {
    if (existingIp0.has(a.ip)) continue // 该 IP 已是纳管设备(探针/SNMP 目标/采集任务)
    out.push({
      deviceId: 'A_' + (a.id || a.ip), source: 'asset', isMonitor: false,
      name: a.hostname || a.ip, type: guessType(a), ip: a.ip, ips: [a.ip],
      mac: a.mac || '', cpu: 0, memory: 0, status: a.alive ? 'normal' : 'down',
      layer: layerForType(guessType(a)),
    })
  }
  S.devices = out
  S.devUpdatedAt = new Date().toISOString()
}
// 采集任务指标取值(metrics 数组 [{name,value,unit}], 取不到返回 null)
function metricVal(t, name) {
  const m = (t.metrics || []).find(x => x && x.name === name)
  return m && typeof m.value === 'number' ? m.value : null
}

// nicList 采集指标里的网卡端口清单(2026-10-02): 主机侧(SSH/WinRM/主机SNMP)采集
// 把每个网卡报成一条 name='nic' 的指标, 属性(名称/状态/MAC/IP/带宽/累计收发字节)
// 全在 labels 里(后端 Metric.Value 是数字, 字符串只能放 labels)。
// 这里只做"清单 + 静态属性", 速率留给端口详情对两轮样本差分(与交换机同口径)。
function nicList(metrics) {
  const out = []
  for (const m of (metrics || [])) {
    if (!m || m.name !== 'nic' || !m.labels) continue
    const l = m.labels
    if (!l.iface) continue
    out.push({
      name: l.iface, state: l.state || '', mac: l.mac || '', ip: l.ip || '',
      speed: parseFloat(l.speed || 0) || 0, inBps: 0, outBps: 0,
    })
  }
  return out.sort((a, b) => String(a.name).localeCompare(String(b.name)))
}

// 资产列表降频后的本地缓存(不进 reactive, 只在合成设备时被读取)
let assetCache = []
async function loadAssets() {
  try {
    const r = await v2('/assets?size=200&host=1')
    assetCache = (r && (r.list || r.items)) || []
  } catch (e) {
    S.errDev = (e && e.message) || '资产列表获取失败'
  }
}
// 资产没有"设备类型"字段, 只能靠证据猜: 有明确 OS→服务器/终端, 常见交换端口→交换机,
// 其余标 unknowndevice(猜错比留空更糟: 用户会拿着错类型去排障)
function guessType(a) {
  const os = String(a.os || '').toLowerCase()
  const ports = (a.ports || []).map(Number)
  if (ports.includes(161) || ports.includes(830) || ports.includes(22) && /cisco|huawei|ruijie|h3c|junos/.test(os)) return 'coresw'
  if (/windows|linux|ubuntu|centos|debian|server/.test(os)) return 'server'
  if (ports.length && ports.some(p => [22, 3389, 5900].includes(p))) return 'terminal'
  return 'unknowndevice'
}

export function deviceById(id) { return S.devices.find(d => d.deviceId === id) || null }

// ===== 拓扑自定义节点计数(本地持久化, 与节点坐标/数据分离) =====
// 独立于 nodes 结构: 大屏(另一页)只需知道"有几张自定义节点", 不必读整个拓扑结构。
const TOPO_CUSTOM_KEY = 'yugsight_topo_custom'
function readTopoCustom() {
  try { return Number(localStorage.getItem(TOPO_CUSTOM_KEY)) || 0 } catch (e) { return 0 }
}
export function setTopoCustomCount(n) {
  const v = Math.max(0, Number(n) || 0)
  S.topoCustomCount = v
  try { localStorage.setItem(TOPO_CUSTOM_KEY, String(v)) } catch (e) { /* 忽略 */ }
}

// ===== 网络拓扑链路 =====
//
// 后端当前**没有**链路接口, 所以这里默认不发起请求(对不存在的端点每 15s 打一次
// 404 只会污染日志, 且排查时会被误导成"接口坏了")。链路先用 topoModel 的 Mock,
// 字段与后端待实现契约完全一致(见下), 后端就绪后把 LINK_API_ENABLED 置 true 即可,
// 页面代码一行都不用改。
//
// 后端契约(GET /api/v2/topology/links, 2026-09-29 阶段 B 已实现, 见 app/topology_links_api.go):
//   { list: [ { linkId, fromDeviceId, toDeviceId,
//               bandwidth(Mbps), bandwidthUsed, utilPct,
//               packetLoss(%), delay(ms), status: 'normal'|'warn'|'down', pps } ] }
// 口径: 接口只提供"字段覆盖"(流量/状态按 from+to 匹配到页面已有链路),
// 链路集合的增删仍由页面掌控(Mock 初值 + 用户手增删 + localStorage 持久化) ——
// 避免轮询重生成边集合把用户删掉的链路"救回来"。
export const LINKS_ENDPOINT = '/api/v2/topology/links'
export const LINK_API_ENABLED = true
export async function loadNetworkLinks(nodes) {
  if (LINK_API_ENABLED) {
    try {
      const r = await v2('/topology/links')
      S.networkLinks = (r && (r.list || r.items)) || []
      S.linkSource = 'api'
      S.errLink = ''
      S.linkUpdatedAt = new Date().toISOString()
      return S.networkLinks
    } catch (e) {
      // 接口不可用时保留上一帧数据并标错误(页面条上显示), 不退回 Mock:
      // 真数据与 Mock 混用会让用户误以为"这条链路是真的"
      S.errLink = (e && e.message) || '链路接口获取失败'
      S.linkUpdatedAt = new Date().toISOString()
      return S.networkLinks
    }
  }
  // Mock: 只在为空时生成一次 —— 链路是用户可编辑并持久化的, 每次轮询重生成会把
  // 用户手工增删的链路冲掉(表现为"我刚删的链路又回来了")。
  if (!S.networkLinks.length) {
    S.networkLinks = mockLinks(nodes || [])
    S.linkSource = 'mock'
    S.linkUpdatedAt = new Date().toISOString()
  }
  return S.networkLinks
}

// 组件挂载时调用: 引用计数起轮询
export function useShared() {
  refs++
  if (!timer) {
    loadOverview(); loadFlows(); loadNetworkDevices(); loadAssets()
    if (LINK_API_ENABLED) loadNetworkLinks()   // 链路真实数据随主轮询走(15s; SSE topolink 负责秒级翻转)
    timer = setInterval(() => {
      beat++
      loadOverview(); loadFlows()
      loadNetworkDevices()
      // 链路流量来自 SNMP 差分(采样间隔 60s), 15s 拉一次足够, 与设备同源同拍
      if (LINK_API_ENABLED) loadNetworkLinks()
      // 资产列表比探针档案重得多, 每 4 拍(约 60s)拉一次即可: 资产发现本身是慢变量
      if (beat % 4 === 0) loadAssets()
    }, 15000)
  }
  onBeforeUnmount(() => {
    refs--
    if (refs <= 0 && timer) { clearInterval(timer); timer = null }
  })
  return S
}
export const shared = S

// ===== 派生口径(所有卡片统一从这里取, 保证口径一致) =====
export function overview() { return (S.ov && S.ov.overview) || {} }
export function sev() {
  const v = overview().vulns
  return v || { critical: 0, high: 0, medium: 0, low: 0, info: 0, risk: 0, total: 0 }
}
export function trend() { return (S.ov && S.ov.trend) || { days: 30, points: [], newTotal: 0, fixedTotal: 0 } }
export function trendSlice(days) {
  const p = trend().points || []
  return days > 0 ? p.slice(-days) : p
}
// 任务成功率: 以"已完成 / (已完成 + 失败)"为口径, 进行中的任务不计入分母
// (把未决任务算进分母会让成功率随并发量忽高忽低, 失去参考价值)
export function successRate() {
  const o = overview()
  const t = (o.tasksSuccess || 0) + (o.tasksFailed || 0)
  return t ? Math.round((o.tasksSuccess || 0) * 1000 / t) / 10 : 0
}
// 环比: 近 7 天新增 vs 前 7 天新增(同源趋势点本地计算, 无需后端额外字段)
export function mom7() {
  const p = trend().points || []
  const sum = (a) => a.reduce((x, y) => x + (y.new || 0), 0)
  const last = sum(p.slice(-7)), prev = sum(p.slice(-14, -7))
  if (!prev) return null
  return Math.round((last - prev) * 1000 / prev) / 10
}
export function taskBars() {
  const o = overview()
  // 后端 overview 把 pending 合并进 tasksRunning, 没有独立的"待执行"计数。
  // 这里不硬造 pending, 而是改用同样是真实字段的"今日新建", 避免数字无法溯源。
  return [
    { k: 'today', l: '今日新建', n: o.tasksToday || 0, c: '#38bdf8' },
    { k: 'running', l: '进行中', n: o.tasksRunning || 0, c: '#3884ff' },
    { k: 'done', l: '已完成', n: o.tasksSuccess || 0, c: '#34d399' },
    { k: 'failed', l: '失败', n: o.tasksFailed || 0, c: '#f87171' },
  ]
}
export function alertRows() { return (S.ov && S.ov.topVulns) || [] }
export function updatedAtText() { return S.updatedAt || '—' }

// ===== 指标字典(属性面板"数据源字段"下拉的唯一事实来源) =====
export const METRICS = [
  { key: 'vulnRisk', label: '未修复漏洞(风险)', unit: '', get: () => sev().risk || 0 },
  { key: 'vulnTotal', label: '漏洞总数(含已修复)', unit: '', get: () => overview().vulnTotal || 0 },
  { key: 'vulnCrit', label: '严重漏洞', unit: '', get: () => sev().critical || 0 },
  { key: 'vulnHigh', label: '高危漏洞', unit: '', get: () => sev().high || 0 },
  { key: 'findingToday', label: '今日新增漏洞', unit: '', get: () => overview().findingsToday || 0 },
  { key: 'findingWeek', label: '近7天新增漏洞', unit: '', get: () => overview().findingsWeek || 0 },
  { key: 'fixedWeek', label: '近7天修复漏洞', unit: '', get: () => overview().fixedWeek || 0 },
  { key: 'taskToday', label: '今日新建任务', unit: '', get: () => overview().tasksToday || 0 },
  { key: 'taskRunning', label: '进行中任务', unit: '', get: () => overview().tasksRunning || 0 },
  { key: 'taskSuccess', label: '已完成任务', unit: '', get: () => overview().tasksSuccess || 0 },
  { key: 'taskFailed', label: '失败任务', unit: '', get: () => overview().tasksFailed || 0 },
  { key: 'successRate', label: '任务成功率', unit: '%', get: () => successRate() },
  { key: 'assetTotal', label: '资产总数', unit: '', get: () => overview().assets || 0 },
  { key: 'assetAlive', label: '在线资产', unit: '', get: () => overview().assetsAlive || 0 },
  { key: 'probeTotal', label: '探针总数', unit: '', get: () => overview().probes || 0 },
  { key: 'probeOnline', label: '在线探针', unit: '', get: () => overview().probesOnline || 0 },
]
export const METRIC_OPTIONS = METRICS.map(m => ({ v: m.key, t: m.label }))
export function pickMetric(key) {
  return METRICS.find(m => m.key === key) || METRICS[0]
}
