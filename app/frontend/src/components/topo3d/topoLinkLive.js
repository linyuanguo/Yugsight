// 链路"活数据"同步共享逻辑(2026-10-01 用户反馈: 大屏拓扑卡里 WSL 探针上线了,
// 连线还是红的/没有上下行速率和光点特效)。
// 根因: 大屏卡 TopoCard 挂载时只初始化一次链路, 之后只跟随节点状态同步;
// /topology/links 的 15s 轮询覆盖、手动线自动连通测试
// 全在独立页 /topology/3d(NetworkTopology3d.vue) —— 大屏卡从未跟随, 线色永远是
// 视图文档里上次持久化的状态。
// 独立页与大屏卡共用同一套(防两份实现漂移):
//   ① applyApiLinks       _real 链路按 (from,to) pair 字段覆盖(状态/利用率/流量)
//   ② autoCheckManualLinks 两端在线的实画链路自动发起中心端实测(节流/复验间隔可按
//      链路自定义: 连线属性面板 retrySec/recheckSec, 默认 30s/300s)
// 【2026-10-01 用户口径"速率要真实的, 不要编造的, 没有就不显示"】线上速率补全
// (syncManualLinkRates) 整体删除: 线上显示的速率是"端点设备的总上下行", 不是这条
// 链路的流量(交换机~路由器线上显示交换机速率=误导归因)。速率只挂在设备节点上
// (SNMP 实测, 真实归属); 链路只表达连通状态(实测/未测/推测), 不表达流量。
// 探测执行本身(API 调用 + 结果写回)由调用方以 check(l) 传入:
//   独立页 = onCheckLink(l, silent)(手动按钮仍弹提示, 自动发起静默);
//   大屏卡 = 全静默(值守画面不弹提示)。

import { stepDebounce } from './topoModel.js'

const linkStreak = new Map()   // linkId -> {pending, n} 状态防抖(异常连 3 次才翻红, 回绿立即)
const autoCheckAt = new Map()  // linkId -> 上次自动发起时间(独立页 + 大屏卡共享节流)
// 在途标记(纯内存, 绝不放链路对象上): 链路对象的 _checking 字段会被页面/大屏卡的
// 持久化写进 LS, 测试在途时恰好 save → 下次加载后该链路"永久测试中", 自动测试被
// 守卫跳过, 线一直红不恢复(2026-10-01 真机事故)。UI 按钮态仍读对象上的 _checking。
const checkingNow = new Set()
export function markChecking(l, on) {
  if (!l) return
  if (on) checkingNow.add(l.linkId)
  else checkingNow.delete(l.linkId)
}
export function isChecking(l) { return !!l && checkingNow.has(l.linkId) }

// 重试间隔秒值规范化(2026-10-02 连线属性可自定义): 非数/≤0 → 默认值, 越界钳制
function clampSec(v, lo, hi, dft) {
  const n = Math.round(Number(v))
  if (!Number.isFinite(n) || n <= 0) return dft
  return Math.max(lo, Math.min(hi, n))
}

// ① _real 链路字段覆盖: 后端只提供按 (from,to) 匹配的字段, 这里"只覆盖不增删" ——
// 否则每次轮询重生成边集合, 用户删掉的链路会"又回来了"(口径与独立页 2026-09-29 一致)。
// 只覆盖连通状态/利用率/流量统计(底部指标与属性面板用); 速率不再写链路(移到设备节点)。
export function applyApiLinks(links, api) {
  if (!Array.isArray(api) || !api.length) return
  const idx = new Map()
  for (const a of api) {
    if (!a || !a.fromDeviceId || !a.toDeviceId) continue
    idx.set(a.fromDeviceId + '~' + a.toDeviceId, a)
    idx.set(a.toDeviceId + '~' + a.fromDeviceId, a)   // 后端端点按字典序, 视图方向不定, 双向都试
  }
  for (const l of links || []) {
    const a = idx.get(l.fromDeviceId + '~' + l.toDeviceId)
    if (!a) continue
    l._real = true
    if (a.utilPct != null && a.utilPct !== l.utilPct) l.utilPct = a.utilPct
    if (a.bandwidth) l.bandwidth = a.bandwidth
    if (a.bandwidthUsed != null) l.bandwidthUsed = a.bandwidthUsed
    if (a.pps) l.pps = a.pps
    if (a.rttMs != null) l.rttMs = a.rttMs
    if (a.status && a.status !== l.status) {
      const st = linkStreak.get(l.linkId) || { pending: '', n: 0 }
      const next = stepDebounce(l.status, a.status, st)
      if (next !== l.status) l.status = next
      linkStreak.set(l.linkId, st)
    }
  }
}

// ③ 手动链路自动连通测试(2026-09-30 用户要求: "设备上线了, 连接就要发起测试, 通过了就显示绿线"):
// 画了线不算通(2026-09-29 口径)依然成立, 但两端都已在线(上线检测)的手动链路不该一直
// 挂着"未测/未连通"等用户手点 —— 设备状态轮询拍里自动发起中心端实测:
//   未测 + 两端在线 → 测; 曾失败 + 两端在线(红线重试间隔, 默认 30s) → 重试(设备可能恢复);
//   已通过 → 绿线复验间隔(默认 5 分钟)复验一次(防绿线过期: 对端后来真断了, 线应保持红)。
// 【2026-10-01 推测线口径】_real 且未经实测且非用户实画的线 = 系统按网段推测的边
// (展示为"推测"灰虚线): 不自动发起连通测试 —— 实测结果(中心端能到两端)不代表两端
// 直连, 自动把它测绿会误导(用户反馈"路由器~远端交换机为什么是绿的")。用户可手动
// 实测任意线(测过=实测, 显示真实结果并参与复验)。
export function autoCheckManualLinks(nodes, links, check) {
  const now = Date.now()
  for (const l of links || []) {
    if ((l._real && !l.tested && !l.userDrawn) || isChecking(l)) continue
    const a = (nodes || []).find(n => n.deviceId === l.fromDeviceId)
    const b = (nodes || []).find(n => n.deviceId === l.toDeviceId)
    if (!a || !b) continue
    if (a.status === 'down' || b.status === 'down') continue   // 端点不在线不发起(等上线)
    const ips = [a.ip, b.ip].filter(x => x && /^\d{1,3}(\.\d{1,3}){3}$/.test(x))
    if (ips.length < 2) continue
    const last = autoCheckAt.get(l.linkId) || 0
    // 间隔取链路对象上的用户自定义值(连线属性面板可配, 随视图文档持久化), 未设/非法 → 默认
    if (l.tested && l.status !== 'down' && now - last < clampSec(l.recheckSec, 10, 86400, 300) * 1000) continue // 已通过: 复验
    if (now - last < clampSec(l.retrySec, 5, 3600, 30) * 1000) continue                                          // 节流
    autoCheckAt.set(l.linkId, now)
    check && check(l)
  }
}
