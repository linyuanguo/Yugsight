// topoPorts.js —— 设备端口清单 + 按端口速率的共享取数(2026-10-02 排期需求 2: 链路
// 按端口绑定; 此前逻辑只在 NetworkTopology3d.vue 的 onDrill 里, 画线选端口要复用)。
//
// 数据源分支(与 v245"端口详情"三源口径完全一致, 单一实现防漂移):
//   ① 探针 P_*: load.ifaces(探针端已算好速率, 随心跳上报);
//   ② 主机采集 C_*: /api/v2/node/metrics?task=&limit=2 nic 累计字节两轮差分
//     (采集端只报累计, 速率必须两帧差分才成立);
//   ③ SNMP 目标: /api/v2/monitor/status 按 IP 找目标 → /api/v2/monitor/samples?target=
//     &limit=2 两轮接口样本差分(与后端 monitor.IfaceRate 同口径);
//   ④ 同 IP 兜底(本模块新增): 节点自身不纳管(资产 A_ / 未绑定设备)但与某纳管设备同 IP
//     = 同一台设备(与 topoModel.fillRatesByIP"同 IP=同设备"同口径) → 复用那台设备的数据源。
// 返回 Promise<{ports:[{port,up,state,rxBps,txBps,speed,util}], note}>; 按 deviceId 做
// 30s 内存缓存(属性面板下拉 + 画布悬浮卡共用; 高频打开不叠加轮询)。
// 无数据一律带 note 说明原因(用户口径: 不编造, 但必须说清为什么没有)。

import { v2 as apiV2 } from '../../api/http.js'

// 有交换机端口表语义的网络设备类型(其余类型的主机类设备没有 ifTable)
export const NET_PORT_TYPES = ['router', 'coresw', 'l3sw', 'l2sw', 'aggsw', 'firewall']

// 利用率文本: 千兆口跑几 Kb/s 时 round() 恒 0%, 分不清"有流量"和"没流量" —— <0.1 显式
// 标 <0.1, 10% 以下保留两位小数; 没有带宽数据(网卡未上报)显示 '—' 而不是按 1G 假算。
export function utilText(totalBps, speed) {
  if (!speed || speed <= 0) return '—'
  const pct = Math.min(100, totalBps * 100 / speed)
  if (pct > 0 && pct < 0.1) return '<0.1'
  if (pct >= 10) return String(Math.round(pct))
  if (pct > 0) return pct.toFixed(2)
  return '0'
}

// Mbps 短文本(下拉选项/悬浮卡用): 12.3M / 456K / 0
export function rateShort(bps) {
  const m = ((Number(bps) || 0) * 8) / 1e6
  if (m >= 100) return Math.round(m) + 'M'
  if (m >= 1) return (Math.round(m * 10) / 10) + 'M'
  if (m > 0) return Math.max(1, Math.round(m * 1000)) + 'K'
  return '0'
}

const cache = new Map()   // deviceId -> { at, data }
const TTL_MS = 30000

export function invalidatePortCache(deviceId) {
  if (deviceId) cache.delete(deviceId)
}

// node: 视图中节点对象(需 deviceId/ip); devices: dashData 设备台账(S.devices)
export async function fetchNodePorts(node, devices) {
  if (!node) return { ports: [], note: '节点不存在' }
  const key = node.deviceId
  const c = cache.get(key)
  if (c && Date.now() - c.at < TTL_MS) return c.data
  let data
  try {
    data = await resolveNodePorts(node, devices)
  } catch (e) {
    data = { ports: [], note: '端口数据读取失败: ' + ((e && e.message) || e) }
  }
  cache.set(key, { at: Date.now(), data })
  return data
}

async function resolveNodePorts(n, devices) {
  const dev = (devices || []).find(d => d.deviceId === n.deviceId)
  // ① 设备自带网卡清单优先(探针心跳上报 / 主机侧采集任务)
  if (dev && dev.source === 'probe' && Array.isArray(dev.ifaces) && dev.ifaces.length) {
    return { ports: probePorts(dev.ifaces), note: '数据源: 探针上报的网卡端口(速率为采样窗口均值)' }
  }
  if (dev && dev.source === 'collect') {
    return await collectPorts(dev.deviceId)
  }
  // ①b 中心端(本机)自带网卡采样(2026-10-02: 内置 center-self 目标此前只报整机总
  //     上下行不报接口表, 中心端节点永远"无网口"; 后端 centerMonitorView 现按探针
  //     同一实现(probe.SampleIfaces)回带逐口明细, 走此分支直接复用)
  if (dev && dev.source === 'monitor' && Array.isArray(dev.ifaces) && dev.ifaces.length) {
    return { ports: probePorts(dev.ifaces), note: '数据源: 中心端本机网卡采样(速率窗口随监控轮询间隔)' }
  }
  const ip = (n.ip || (dev && dev.ip) || '').trim()
  // ② 网络设备类型 → SNMP 接口表(监控目标按 IP 匹配)
  if (NET_PORT_TYPES.includes(n.type) && ip) {
    return await snmpPorts(ip, n)
  }
  // ③ 同 IP 兜底: 节点自身不纳管, 但同 IP 有纳管设备 = 同一台设备, 复用其数据源。
  //    扫全部同 IP 设备而非只取首个(2026-10-02 修: 同一台机器被多路纳管时——如
  //    探针 + SNMP 目标同 IP——旧逻辑 find() 命中谁全看台账顺序, 顺序不巧就漏端口)
  if (ip) {
    const others = (devices || []).filter(d => d.ip === ip && d.deviceId !== n.deviceId)
    const pb = others.find(d => d.source === 'probe' && Array.isArray(d.ifaces) && d.ifaces.length)
    if (pb) {
      return { ports: probePorts(pb.ifaces), note: '数据源: 同 IP 探针 ' + ip + ' 上报的网卡端口' }
    }
    const col = others.find(d => d.source === 'collect')
    if (col) {
      return await collectPorts(col.deviceId)
    }
    const mon = others.find(d => d.source === 'monitor' && Array.isArray(d.ifaces) && d.ifaces.length)
    if (mon) {
      return { ports: probePorts(mon.ifaces), note: '数据源: 同 IP 中心端 ' + ip + ' 本机网卡采样' }
    }
    if (others.some(d => NET_PORT_TYPES.includes(d.type))) {
      return await snmpPorts(ip, n)
    }
  }
  // ④ 无数据: 说明原因(不编造)
  if (NET_PORT_TYPES.includes(n.type)) {
    return { ports: [], note: '该设备未纳入 SNMP 监控目标, 取不到端口数据。请到「节点监控 → 监控目标」为 ' + (ip || '该设备') + ' 添加 SNMP 监控后重试。' }
  }
  // 探针节点却没 ifaces = 探针版本旧(v243 之前不报网卡), 明示升级路径
  const probeHint = (dev && dev.source === 'probe') ? '(当前探针版本较旧, 升级到 v243+ 后自动上报网卡端口)' : ''
  return { ports: [], note: '该设备暂无端口数据: 交换机走 SNMP 接口表(需先加为监控目标); 主机/探针的网卡端口由探针上报' + probeHint }
}

// 探针 ifaces → 统一端口行(探针端已算好速率, 直接映射)
function probePorts(ifaces) {
  return ifaces.map(f => ({
    port: f.name,
    up: f.state === 'up',
    state: f.state || '',
    rxBps: Math.round(f.inBps || 0),
    txBps: Math.round(f.outBps || 0),
    speed: f.speed || 0,
    util: utilText(Math.round(f.inBps || 0) + Math.round(f.outBps || 0), f.speed || 0),
  }))
}

// 主机侧采集(SSH/WinRM/主机SNMP): nic 指标只报累计字节(labels.rx/tx), 两轮样本差分
async function collectPorts(deviceId) {
  const taskId = String(deviceId || '').replace(/^C_/, '')
  const m = await apiV2('/node/metrics?task=' + encodeURIComponent(taskId) + '&limit=2')
  const pts = (m && m.points) || []
  const newest = pts[pts.length - 1]
  const prev = pts.length > 1 ? pts[pts.length - 2] : null
  const secs = prev && newest ? Math.max(1, (Date.parse(newest.at) - Date.parse(prev.at)) / 1000) : 0
  const pmap = new Map()
  if (prev) {
    for (const p of (prev.metrics || [])) {
      if (p && p.name === 'nic' && p.labels && p.labels.iface) pmap.set(p.labels.iface, p)
    }
  }
  const ports = []
  for (const p of ((newest && newest.metrics) || [])) {
    if (!p || p.name !== 'nic' || !p.labels || !p.labels.iface) continue
    const l = p.labels
    const q = pmap.get(l.iface)
    const rx = parseFloat(l.rx || 0), tx = parseFloat(l.tx || 0)
    let rxBps = 0, txBps = 0
    if (q && secs) {
      const prx = parseFloat(q.labels.rx || 0), ptx = parseFloat(q.labels.tx || 0)
      if (rx >= prx) rxBps = Math.round((rx - prx) / secs)
      if (tx >= ptx) txBps = Math.round((tx - ptx) / secs)
    }
    const speed = parseFloat(l.speed || 0) || 0
    const st = l.state === 'unknown' ? '' : (l.state || '')
    ports.push({ port: l.iface, up: st === 'up', state: st, rxBps, txBps, speed, util: utilText(rxBps + txBps, speed) })
  }
  ports.sort((a, b) => String(a.port).localeCompare(String(b.port)))
  if (!ports.length) {
    return { ports: [], note: '该采集任务尚未上报网卡端口(nic 指标)。请确认采集协议为 SSH/WinRM/主机SNMP 且已完成至少一轮采集。' }
  }
  return {
    ports,
    note: '数据源: 主机采集(最近两轮样本差分速率)' + (prev ? '' : ' · 目前仅 1 轮样本, 速率待下一轮出现'),
  }
}

// 交换机/路由器 SNMP 接口表: 按 IP 找监控目标, 两轮样本差分出每口真实速率
async function snmpPorts(ip, n) {
  const st = await apiV2('/monitor/status')
  // 注意: /status 目标视图的 ID 字段是小写 json:"id" (monitorTargetView), 不是 t.ID
  const t = (st.targets || []).find(x => String(x.addr || '').split(':')[0] === ip)
  if (!t) {
    return { ports: [], note: '该设备未纳入 SNMP 监控目标, 取不到端口数据。请到「节点监控 → 监控目标」为 ' + (ip || (n && n.name) || '该设备') + ' 添加 SNMP 监控后重试。' }
  }
  const sm = await apiV2('/monitor/samples?target=' + encodeURIComponent(t.id) + '&limit=2')
  const list = (sm.samples || []).slice()
  if (!list.length) {
    return { ports: [], note: '该监控目标尚无接口样本(等待第一轮采集完成后自动出现)。' }
  }
  const newest = list[list.length - 1]
  const prev = list.length > 1 ? list[list.length - 2] : null
  const secs = prev ? Math.max(1, (Date.parse(newest.at) - Date.parse(prev.at)) / 1000) : 0
  const pmap = new Map((prev && prev.ifaces || []).map(f => [f.name, f]))
  const ports = (newest.ifaces || []).map(f => {
    const p = pmap.get(f.name)
    const rxBps = p && secs && p.in <= f.in ? Math.round((f.in - p.in) / secs) : 0
    const txBps = p && secs && p.out <= f.out ? Math.round((f.out - p.out) / secs) : 0
    return {
      port: f.name,
      up: f.oper === 1,
      state: f.oper === 1 ? 'up' : 'down',
      rxBps, txBps, speed: f.speed,
      util: utilText(rxBps + txBps, f.speed),
    }
  })
  return {
    ports,
    note: prev
      ? '数据源: SNMP 监控(最近两轮接口样本差分速率, ' + new Date(newest.at).toLocaleTimeString() + ')'
      : '数据源: SNMP 监控(目前仅 1 轮样本, 速率待下一轮差分后出现)',
  }
}
