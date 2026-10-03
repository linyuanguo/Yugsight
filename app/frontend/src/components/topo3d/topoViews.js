// topoViews.js —— 多套拓扑视图仓库(2026-09-30 用户要求: 物理/逻辑双子视图取消,
// 改为多套独立视图: 每套视图是一份完整拓扑文档(节点/链路/框), 互相不影响。
//
// 数据布局 localStorage[yugsight_topo_views_v2]:
//   { active: '视图名', views: [ { name, nodes: [], links: [], boxes: [] } ] }
// 节点 2D 位置 = n.px/n.py(世界坐标, 画布拖拽/落点写入); 未设置时场景按 autoPos
// 自动网格排布(视图内顺序确定, 刷新稳定)。
// boxes = 自由框(画布右键"在此添加框"/按钮下拉新增; 可拖拽移动/拉角缩放/双击改名/右键删除):
//   [{ id, name, x, y, w, h }]
//
// v1→v2 迁移: 首次加载若存在旧全局布局(yugsight_topo3d_layout)则迁入"默认视图"
// (位置优先旧手动摆位 yugsight_topo_manualpos_v1, 否则自动网格); 旧物理分层盒/
// 逻辑业务组盒不迁移(概念随物理/逻辑视图取消, 框由画布右键重建)。
// 旧 key 只读不删(安全起见), 迁移后不再被任何代码引用。

import { reactive } from 'vue'
import { v2 as apiV2 } from '../../api/http.js'

const LS_VIEWS = 'yugsight_topo_views_v2'
const LS_LEGACY = 'yugsight_topo3d_layout'
const LS_LEGACY_POS = 'yugsight_topo_manualpos_v1'
const DEFAULT_NAME = '默认视图'

// 自动排布网格: 按视图内节点顺序确定位置(6 列 × 170/150 步进), 无 px 的节点落这里
export function autoPos(i) {
  const col = i % 6
  const row = Math.floor(i / 6)
  return { x: 150 + col * 170, y: 150 + row * 150 }
}

// 显示元素开关(2026-10-02 用户要求: 顶部按钮+勾选控制名字/速率/网口信息显隐):
// 独立页与大屏拓扑卡共用同一份(各自浏览器 LS 各自记, 跨浏览器不做同步 —— 显示偏好
// 是纯个人设置, 不像视图文档需要多端一致)。默认全开=零行为变化。
// 2026-10-02 v255: flow(连线光效)从 rate(设备速率+流量环)拆出独立开关 —— 此前光效
// 挂在"速率"勾选上, 用户为关光效勾掉它 → 设备名字下方的速率标签一起消失(用户报
// "设备上的速率不显示了")。
const LS_DISPLAY = 'yugsight_topo_display'
export const displayCfg = reactive({ name: true, rate: true, port: true, flow: true })
try {
  const raw = localStorage.getItem(LS_DISPLAY)
  if (raw) {
    const o = JSON.parse(raw)
    if (o && typeof o === 'object') {
      for (const k of ['name', 'rate', 'port', 'flow']) if (typeof o[k] === 'boolean') displayCfg[k] = o[k]
    }
  }
} catch (e) { /* 损坏: 全开 */ }
export function setDisplayCfg(k, v) {
  displayCfg[k] = !!v
  try { localStorage.setItem(LS_DISPLAY, JSON.stringify({ ...displayCfg })) } catch (e) { /* 忽略 */ }
}

function emptyView(name) {
  return { name, nodes: [], links: [], boxes: [] }
}

const store = reactive({ active: '', views: [] })
let loaded = false

// 视图集合序列化(剔除瞬时在途标记):
// _checking=true 只在一次连通测试进行中的几秒内有效, 若测试在途时恰好持久化, 该标记
// 随视图文档落盘 —— 下次加载后被误认为"正在测试中", 自动连通测试的 l._checking 守卫
// 永远跳过该链路, 线一直红不恢复(2026-10-01 真机事故)。UI 按钮态不受影响(读内存对象)。
function viewsPayload() {
  return store.views.map(v => ({
    ...v,
    nodes: (v.nodes || []).map(n => { const c = { ...n }; delete c._checking; return c }),
    links: (v.links || []).map(l => { const c = { ...l }; delete c._checking; return c }),
  }))
}

// silent=true: 只写 LS 不推服务端(采用服务器版本时调用 —— 版本就是服务器自己的,
// 再推上去只会白白更新时间戳)。
function save(silent) {
  try { localStorage.setItem(LS_VIEWS, JSON.stringify({ active: store.active, views: viewsPayload() })) } catch (e) { /* 存储满/隐私模式: 忽略, 会话内仍有效 */ }
  if (silent) return
  localUpd = Date.now()
  saveUpdMeta()
  schedulePush()
}

function migrateLegacy() {
  const v = emptyView(DEFAULT_NAME)
  try {
    const raw = localStorage.getItem(LS_LEGACY)
    if (raw) {
      const o = JSON.parse(raw)
      if (o && Array.isArray(o.nodes) && o.nodes.length) {
        v.nodes = o.nodes
        v.links = Array.isArray(o.links) ? o.links : []
        // 旧手动摆位坐标 → px/py(2D 视图位置); 没有的留给 autoPos 网格
        const posRaw = localStorage.getItem(LS_LEGACY_POS)
        if (posRaw) {
          const pos = JSON.parse(posRaw)
          for (const n of v.nodes) {
            const p = pos[n.deviceId]
            if (p && (p.x || p.y)) { n.px = +p.x || 0; n.py = +p.y || 0 }
          }
        }
      }
    }
  } catch (e) { /* 旧数据损坏: 从空视图开始 */ }
  return v
}

// 悬空链路清洗(2026-10-01 真机事故): 旧版曾把后端按网段推测的链路集自动灌进视图,
// 后来导入口径改成"只导入纳管设备"/用户删过节点, 残留链路的端点在当前视图里已不
// 存在 —— 场景 posOf 对未知 ID 落 (0,0), 线被画到画布原点且终点没有任何设备
// (用户: "192.168.1.1 和 172.16.199.1 连的终点是空的")。每个浏览器的 localStorage
// 各自独立、残留时机不同, 所以同一个地址在不同浏览器看到的连线不一样。
// 加载即清洗(一次性自愈, 各浏览器打开后口径一致), 删除数 >0 时落盘。
function sanitizeLinks(v) {
  const ids = new Set((v.nodes || []).map(n => n.deviceId))
  const before = (v.links || []).length
  v.links = (v.links || []).filter(l => ids.has(l.fromDeviceId) && ids.has(l.toDeviceId))
  return before - v.links.length
}

// 载入(幂等): 已有 v2 数据直接用; 没有则从 v1 旧布局迁移(或建空默认视图)。
// 两条路径收尾都启动服务端同步(跨浏览器共享, 见下方"服务端持久化"节)。
function loadStore() {
  if (loaded) return
  loaded = true
  loadUpdMeta()
  let o = null
  try { o = JSON.parse(localStorage.getItem(LS_VIEWS) || 'null') } catch (e) { o = null }
  if (o && Array.isArray(o.views) && o.views.length) {
    for (const v of o.views) {
      v.nodes = Array.isArray(v.nodes) ? v.nodes : []
      v.links = Array.isArray(v.links) ? v.links : []
      v.boxes = Array.isArray(v.boxes) ? v.boxes : []
      // 存量污染清洗(2026-10-01): 旧版 save 未剔除 _checking, 测试在途时落盘会把
      // "测试中"标记永久固化 —— 加载时统一剔除, 防 UI 按钮卡"测试中…"禁用态
      for (const n of v.nodes) delete n._checking
      for (const l of v.links) delete l._checking
    }
    if (!o.views.some(v => v.name === o.active)) o.active = o.views[0].name
    store.active = o.active
    store.views = o.views
    let dropped = 0
    for (const v of store.views) dropped += sanitizeLinks(v)
    if (dropped) save()   // 清洗结果落盘, 下次打开不再出现悬空线
    startServerSync()
    return
  }
  store.views = [migrateLegacy()]
  store.active = store.views[0].name
  save()
  startServerSync()
}

// 取得仓库(幂等加载)。页面/大屏卡共用同一模块级 reactive 仓库:
// 站内从大屏卡进拓扑页(SPA 路由切换)时两边看到的是同一份数据。
export function ensureStore() {
  loadStore()
  return store
}

export function activeView() {
  return store.views.find(v => v.name === store.active) || store.views[0] || null
}

export function setActive(name) {
  if (!store.views.some(v => v.name === name)) return
  store.active = name
  switchFlag = true   // 切视图=只动 active 指针: curView 变化会触发页面 watch → 其 persist* 消费标记跳过打戳
  save()
}

// 新建视图: src 传源视图=复制一份(深拷贝, 节点/链路/框全部独立, 互不影响)
export function createView(name, src) {
  if (store.views.some(v => v.name === name)) return null
  let v
  if (src) {
    v = JSON.parse(JSON.stringify({ name, nodes: src.nodes, links: src.links, boxes: src.boxes }))
    // 运行态字段不随复制带过去(在线起始时间/测试中标记等, 由新视图会话重新建立)
    for (const n of v.nodes) { delete n._onlineSince; delete n._checking }
    for (const l of v.links) { delete l._checking; delete l._check }
  } else {
    v = emptyView(name)
  }
  v.upd = Date.now()   // 新建=内容变更, 打戳(按视图合并基准)
  store.views.push(v)
  switchFlag = true    // 建视图同时切 active(同切视图, 不让 watch 再误打一次戳)
  store.active = name
  save()
  return v
}

export function renameView(oldName, newName) {
  const v = store.views.find(x => x.name === oldName)
  if (!v || !newName || v.name === newName) return false
  if (store.views.some(x => x.name === newName)) return false
  v.name = newName
  if (store.active === oldName) store.active = newName
  v.upd = Date.now()   // 改名=视图身份变更, 打戳
  save()
  return true
}

// 删除视图: 至少保留一套(删光后卡片/页面无从读起)
export function deleteView(name) {
  if (store.views.length <= 1) return false
  const i = store.views.findIndex(v => v.name === name)
  if (i < 0) return false
  store.views.splice(i, 1)
  if (store.active === name) store.active = store.views[0].name
  save()
  return true
}

// ===== 每视图版本(2026-10-02 真机事故: "之前我的连线了为什么现在没有了?") =====
// 根因: 跨浏览器同步是"整包 last-write-wins" —— 两个浏览器(Chrome/Edge)内容分叉后,
// 后推的一方整包覆盖服务器, 另一方 30s 轮询采纳"更新"的文档 → 手绘连线被不含连线的
// 文档整包冲掉(谁"刚打开过页面"谁的 localUpd=now 最新, 谁的旧内容就把对方的新内容盖掉)。
// 修复(三件套, 后端 views 为 []map[string]any 透传, 无需改 Go):
// ① 每视图带独立时间戳 v.upd(内容变更时由 persistContent() 打; 切视图/改 active 不打 ——
//    switchFlag 标记, 由下一次 persist* 消费, 防轮播切视图让所有视图都"变新");
// ② 采用服务器文档(409 冲突 / 轮询判新)从整包替换改为按视图合并(mergeViews):
//    同名视图取 v.upd 新的一方, 单边存在的视图保留 —— 按视图 LWW 是确定性单调的,
//    不会两浏览器互盖循环(旧注释顾虑的是"字段级合并", 与按视图 LWW 是两回事);
// ③ 空壳文档(任何视图都无节点/链路/框, 如全新 profile 首开)禁止推送 ——
//    2026-10-02 E2E 测试事故正是此路径: 新 profile LS 空 → localUpd=now > 服务器 →
//    空壳把用户真实文档整包覆盖(已记档, 组 15)。
function hasLocalContent() {
  return store.views.some(v => (v.nodes && v.nodes.length) || (v.links && v.links.length) || (v.boxes && v.boxes.length))
}
// 按视图合并(采用服务器文档时): 同名 → v.upd 新者胜(无戳按 0, 平手服务器胜);
// 单边存在 → 保留。已知代价(均可人工补救, 远好于丢手绘拓扑):
// ① 一侧删除的视图可能在冲突时于另一侧"复活"(再删一次);
// ② 视图改名后, 旧名/新名可能在另一浏览器短暂并存(删掉多余那份)。
function mergeViews(srvViews, localViews) {
  const lm = new Map()
  for (const v of localViews) lm.set(v.name, v)
  const out = []
  for (const s of srvViews) {
    const l = lm.get(s.name)
    out.push(l && (Number(l.upd) || 0) > (Number(s.upd) || 0) ? l : s)
  }
  const names = new Set(srvViews.map(v => v.name))
  for (const l of localViews) if (!names.has(l.name)) out.push(l)
  return out
}
let switchFlag = false   // 刚切过视图/改过 active(非内容变更); 由下一次 persist* 消费
// 落盘(状态同步/轮询写入等纯落盘, 不打视图戳)
export function persist() {
  if (switchFlag) switchFlag = false
  save()
}
// 内容变更落盘: 打当前视图 v.upd(按视图合并的新旧基准)
export function persistContent() {
  if (switchFlag) switchFlag = false
  else {
    const v = activeView()
    if (v) v.upd = Date.now()
  }
  save()
}

// ===== 服务端持久化(2026-10-02 用户要求: "chrome和edge显示网络拓扑不一样, edge老是
// 显示老缓存不会自动更新") =====
//
// 根因: 视图文档此前只存各浏览器 localStorage —— 同一地址不同浏览器各自一份(Edge 里
// 画过路由器, Chrome 里没有), 一边编辑另一边永远看不到; 浏览器里的旧视图又表现为
// "老缓存不更新"。改: 中心端 /api/v2/topo/views(data/topo_views.json)成为跨浏览器
// 唯一事实来源, localStorage 只留两个用途: 首帧立即渲染 + 离线兜底。
// 同步模型(last-write-wins + 冲突检测, 后端口径见 app/topo_view_api.go):
//   ① 加载: LS 先渲染, 再异步拉取 —— 服务器比本地新 → 采用(覆盖 LS); 本地比服务器
//      新(离线时没推成功) → 补推;
//   ② 保存: LS 写完后 800ms 防抖推服务端; 409 冲突(另一浏览器已写更新版本) → 采用
//      服务器版本, 本地旧快照丢弃(视图是手绘文档, 无字段级合并价值, 整包取舍最简单
//      可预期 —— 字段合并会让两浏览器互相覆盖成死循环);
//   ③ 30s 轮询: 服务器有新版本 → 采用(跨浏览器自动刷新, 无需手动刷新页面)。
// 离线/未登录/5xx: 静默降级纯 LS(降级不崩, 规则 3/4), 不阻塞主流程。
const LS_SRV = 'yugsight_topo_views_srv'   // { upd: 最近看到的服务器版本, local: 本地版本 }
const POLL_MS = 30000
const PUSH_DEBOUNCE_MS = 800

let srvUpd = 0      // 最近看到的服务器 updatedAt(ms) —— PUT 的 base + 轮询比较基准
let localUpd = 0    // 本地 updatedAt(ms)
let syncBusy = false
let pushT = null
let pollT = null

function loadUpdMeta() {
  try {
    const o = JSON.parse(localStorage.getItem(LS_SRV) || 'null')
    if (o && typeof o === 'object') { srvUpd = Number(o.upd) || 0; localUpd = Number(o.local) || 0 }
  } catch (e) { /* 元信息损坏: 当无, 首拉以服务器为准 */ }
}
function saveUpdMeta() {
  try { localStorage.setItem(LS_SRV, JSON.stringify({ upd: srvUpd, local: localUpd })) } catch (e) { /* 忽略 */ }
}

// ===== 新窗口分显钉住(2026-10-02 用户要求: 视图下拉旁加"新窗口"按钮, 多屏各显一套视图) =====
// ?view=<名称> 打开的窗口把 active "钉住"在该视图, 两个方向都拦:
//   ① 远程采用(applyServerDoc)只换 views 内容, 不改本窗口 active —— 否则本窗口 30s 轮询
//      采纳服务器文档时会跳到别人切到的视图, 多屏分显失效;
//   ② 推送(doPush)带"最近看到的服务器 active"(srvActive)而非本窗口 store.active ——
//      否则本窗口切视图会改写"全局 active", 另一窗口 30s 内被轮询带跑, 同样分显失效。
// 本窗口内用户自己切视图照常有效(钉住只拦远程影响, 不拦本窗意图); 钉住随窗口存活,
// 刷新/重开(不带 ?view)即解除。视图文档内容(节点/链路/框)仍是跨窗口共享, 编辑互见。
let pinnedActive = ''
let pendingDeepLink = ''   // 打开时视图还没载入(纯本地空 + 服务器文档未拉回)→ 等 applyServerDoc
let srvActive = ''         // 最近一次看到的服务器"全局 active"(钉住窗口推送时的 active 口径)

// 页面 onMounted 按 ?view= 调用: 激活并钉住指定视图; 视图不存在(可能已删)返回 false
export function applyViewDeepLink(name) {
  if (!name) return false
  if (store.views.some(v => v.name === name)) {
    pendingDeepLink = ''
    pinnedActive = name
    if (store.active !== name) { store.active = name; switchFlag = true; save() }
    return true
  }
  pendingDeepLink = name   // 视图未载入: 留给服务器文档回落后补激活
  return false
}

// 采用服务器版本(整包替换 + 悬空链路清洗与本地加载同口径 + LS 落盘不重推)
function applyServerDoc(d) {
  let views = Array.isArray(d.views) ? d.views : []
  if (!views.length) return
  for (const v of views) {
    v.nodes = Array.isArray(v.nodes) ? v.nodes : []
    v.links = Array.isArray(v.links) ? v.links : []
    v.boxes = Array.isArray(v.boxes) ? v.boxes : []
    for (const n of v.nodes) delete n._checking
    for (const l of v.links) delete l._checking
  }
  // 深链补激活: 打开时视图未载入, 服务器文档回来了再钉住
  if (pendingDeepLink) {
    if (views.some(v => v.name === pendingDeepLink)) pinnedActive = pendingDeepLink
    pendingDeepLink = ''
  }
  srvActive = String(d.active || '')
  // 2026-10-02: 按视图合并替代整包替换(见"每视图版本"节②) ——
  // 本地 v.upd 更新的视图保留, "旧浏览器的新推送"再也冲不掉本机的新画内容
  const merged = mergeViews(views, store.views)
  const active = views.some(v => v.name === d.active) ? d.active : views[0].name
  for (const v of merged) sanitizeLinks(v)
  // 钉住窗口只采纳内容不跟别人切视图; 钉住的视图已被删 → 回落普通口径
  store.active = (pinnedActive && merged.some(v => v.name === pinnedActive)) ? pinnedActive : active
  switchFlag = true   // 整包换 views 会让 curView 变化触发页面 watch → 该次 persist* 跳过打戳
  store.views = merged
  localUpd = d.updatedAt
  save(true)
}

// 真正执行推送(调用方保证无并发: pullFromServer 与 schedulePush 都持有 syncBusy)
async function doPush() {
  if (!(localUpd > 0)) return
  if (!hasLocalContent()) return   // 空壳禁止推送(见"每视图版本"节③): 全新 profile/清过 LS 的浏览器不得覆盖服务器真实文档
  try {
    await apiV2('/topo/views', {
      method: 'PUT',
      body: {
        updatedAt: localUpd,
        baseUpdatedAt: srvUpd,
        // 钉住窗口(新窗口分显): 不带本窗口的视图去改"全局 active"(见 pinnedActive 注释)
        active: pinnedActive ? (srvActive || store.active) : store.active,
        views: viewsPayload(),
      },
    })
    srvUpd = localUpd
  } catch (e) {
    if (e && e.status === 409 && e.body && e.body.data) {
      applyServerDoc(e.body.data)   // 冲突: 另一浏览器写入了更新版本 → 采用服务器版本
    }
    // 其余错误(离线/5xx): 本地保留, 下次保存/轮询自然补推
  }
}

async function pullFromServer() {
  if (syncBusy || !loaded) return
  syncBusy = true
  try {
    const d = await apiV2('/topo/views')
    if (!d || !(d.updatedAt > 0)) {
      // 服务器还没有视图(首次部署/纯本地阶段): 本地有内容且从未推成功过 → 推上去
      // (第一个打开的浏览器把本地视图变成共享基线, 后开的浏览器自然拉到同一份)
      if (localUpd > 0 && localUpd > srvUpd) await doPush()
    } else {
      srvUpd = d.updatedAt
      if (d.updatedAt > localUpd) {
        applyServerDoc(d)          // 服务器更新 → 采用(跨浏览器"自动更新"的主体)
      } else if (localUpd > d.updatedAt) {
        await doPush()             // 本地更新(离线期间编辑) → 补推
      }
    }
  } catch (e) { /* 离线/未登录/5xx: 降级纯 LS, 静默 */ }
  syncBusy = false
  saveUpdMeta()
}

function schedulePush() {
  if (pushT) clearTimeout(pushT)
  pushT = setTimeout(() => {
    pushT = null
    if (syncBusy) return
    syncBusy = true
    doPush().finally(() => { syncBusy = false; saveUpdMeta() })
  }, PUSH_DEBOUNCE_MS)
}

// 启动同步(幂等, loadStore 收尾调用; 独立页/大屏卡共用模块只启动一次)
function startServerSync() {
  if (pollT) return
  pullFromServer()
  pollT = setInterval(pullFromServer, POLL_MS)
}

// ===== 视图轮播(2026-09-30 用户要求: 视图多了可以轮播) =====
// 配置 localStorage[yugsight_topo_view_carousel] = { on, interval(秒) }, 默认关闭(规则5)。
// 全局单计时器(模块级): 大屏卡(TopoCard, 仅浏览态)与独立页(仅浏览态)按同一配置
// 自动切换全局激活视图; 视图 <2 时不转。开关/间隔由独立页"视图工具栏"管理。
const LS_CAR = 'yugsight_topo_view_carousel'
export function loadViewCarCfg() {
  try {
    const o = JSON.parse(localStorage.getItem(LS_CAR) || 'null')
    return { on: !!(o && o.on), interval: (o && o.interval >= 5) ? o.interval : 15 }
  } catch (e) { return { on: false, interval: 15 } }
}
export function saveViewCarCfg(cfg) {
  try { localStorage.setItem(LS_CAR, JSON.stringify({ on: !!cfg.on, interval: cfg.interval || 15 })) } catch (e) { /* 忽略 */ }
}
let carTimer = null
export function viewCarRunning() { return carTimer != null }
export function stopViewCarousel() {
  if (carTimer) { clearInterval(carTimer); carTimer = null }
}
// 每拍取"当前激活"的下一套视图(视图增删后自动跟随, 无需重启计时器)
export function startViewCarousel(intervalSec) {
  stopViewCarousel()
  const cfg = loadViewCarCfg()
  if (!cfg.on) return
  if (store.views.length < 2) return
  const ms = Math.max(5, intervalSec || cfg.interval) * 1000
  carTimer = setInterval(() => {
    if (store.views.length < 2) { stopViewCarousel(); return }
    const i = store.views.findIndex(v => v.name === store.active)
    const next = store.views[(i + 1) % store.views.length]
    setActive(next.name)
  }, ms)
}
