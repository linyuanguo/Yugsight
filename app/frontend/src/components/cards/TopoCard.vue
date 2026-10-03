<template>
  <!-- TopoCard: 安全大屏 Pro「网络拓扑卡」(2026-09-29 用户要求: 移除一级菜单/节点监控入口,
       大屏卡片成为拓扑唯一入口)。
       2026-09-30: 数据源 = 多套独立视图仓库(topoViews.js, yugsight_topo_views_v2),
       与 /topology/3d 独立页同源; 物理/逻辑子视图取消, 卡头改"视图列表"下拉
       (每套视图独立, 互不影响; card.view 按卡记忆, 未选=跟随全局激活视图)。
       纳管设备状态随 dashData 15s 轮询同步。
       场景复用 TopoScene2D(browse 只读: 平移/缩放/子网折叠可用, 无节点编辑),
       点「⤢ 全屏」进独立页做全功能管理。

       为什么场景区 @click.stop/@pointerdown.stop: 卡片体系浏览态"点击翻转"、
       编辑态"拖卡片"由 CanvasCard 外壳捕获, 不拦截的话操作拓扑(选节点/平移/缩放)
       会先触发卡片翻转或整卡拖动。卡片只能从顶部标题条拖拽/翻转(与 Globe3DCard 同口径)。 -->
  <!-- 2026-09-29 用户反馈: 大屏卡双击应进编辑画布 —— 整卡(含标题条)双击直达
       /topology/3d 独立页; 单击仍是翻转/场景交互, 互不冲突 -->
  <div class="tc" @dblclick.stop="goFull" title="双击进入全功能拓扑页(设备库 / 连线 / 编辑)">
    <!-- 正面 -->
    <template v-if="side === 'front'">
      <div class="tc-head">
        <span class="tc-title">{{ card.title || '网络拓扑' }}</span>
        <!-- 视图列表(2026-09-30 用户要求: 物理/逻辑取消, 多套独立视图, 每个视图互不影响) -->
        <div class="tc-hbtns" v-if="!compact">
          <select class="tc-view" :value="curViewName" @click.stop @change.stop="pickView($event.target.value)"
                  :disabled="!store.views.length" title="拓扑视图列表(每套视图独立, 互不影响)">
            <option v-for="v in store.views" :key="v.name" :value="v.name">{{ v.name }}</option>
          </select>
        </div>
        <button type="button" class="tc-fs" title="进入全功能拓扑页(双击卡片同样进入)" @click.stop="goFull">⤢ 全屏</button>
      </div>
      <div class="tc-body" @click.stop @pointerdown.stop>
        <!-- 无节点时不渲染场景(空场景只有分层带, 值守者会误以为"拓扑是空的"而非"还没数据"), 走空态提示 -->
        <TopoScene2D v-if="!compact && ready && nodes.length" :nodes="nodes" :links="links" :boxes="boxes"
                     :devices="S.devices" mode="browse" :show-mini="false" :low-zoom-scale="0.3" />
        <!-- 四色状态图例(2026-09-29 对照 Zabbix 图标映射口径: 图标固定、状态用颜色表达):
             大屏值守者无需进全屏页即可看懂绿/黄/红/灰分别代表什么, 点卡片背面也有完整统计 -->
        <div v-if="!compact && ready && nodes.length" class="tc-legend" @click.stop @pointerdown.stop>
          <span v-for="g in LEGEND" :key="g.k"><i :style="{ background: g.c }"></i>{{ g.t }}<b>{{ countOf(g.k) }}</b></span>
        </div>
        <!-- 缩略态: 卡被缩到阈值以下(卡片体系 compact 口径) → 标题 + 一行统计 -->
        <div v-else-if="compact" class="tc-mini">
          <b>{{ nodes.length }}</b> 台设备 · 在线 <em>{{ onlineRate }}%</em>
          <span class="tc-dots">
            <i v-for="g in LEGEND" :key="g.k" :style="{ background: g.c, color: g.c }" :title="g.t + ' ' + countOf(g.k)"></i>
          </span>
        </div>
        <div v-else-if="ready && !nodes.length" class="tc-empty">
          <span>暂无拓扑数据</span>
          <em>请进全屏页(编辑模式)添加设备/框, 或在「节点监控」添加采集任务</em>
        </div>
        <div v-else class="tc-empty"><span>正在加载拓扑数据…</span></div>
      </div>
    </template>
    <!-- 背面: 汇总概览(点卡片翻转回拓扑) -->
    <template v-else>
      <div class="tb">
        <div class="tb-title">{{ card.title || '网络拓扑' }}</div>
        <div class="tb-row"><span>设备总数</span><b>{{ nodes.length }}</b></div>
        <div class="tb-row"><span>在线率</span><b>{{ onlineRate }}%</b></div>
        <div class="tb-row"><span>链路数</span><b>{{ links.length }}</b></div>
        <div class="tb-legend">
          <span v-for="g in LEGEND" :key="g.k"><i :style="{ background: g.c }"></i>{{ g.t }}<b>{{ countOf(g.k) }}</b></span>
        </div>
        <div class="tb-src">数据源: {{ srcText }} · 点击返回拓扑</div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import TopoScene2D from '../topo3d/TopoScene2D.vue'
import { nodeFromDevice, safeStatus, fillRatesByIP } from '../topo3d/topoModel.js'
import { ensureStore, setActive, persist as persistViews, persistContent as persistContentViews, startViewCarousel, stopViewCarousel } from '../topo3d/topoViews.js'
import { useShared, shared, loadNetworkLinks } from './dashData.js'
// 2026-10-01 用户反馈"大屏拓扑: 探针上线了连线还是红的/没有速率光点": 大屏卡此前只
// 挂载时初始化一次链路, 不跟随 15s 轮询 —— 接入共享模块 topoLinkLive(与独立拓扑页同源):
// ① _real 链路状态/利用率随 S.linkUpdatedAt 覆盖(只覆盖不增删, 速率已移到设备节点);
// ② 实画线两端在线自动发起实测(推测边不自动测, 见 topoLinkLive.js 口径)。
import { applyApiLinks, autoCheckManualLinks, markChecking, isChecking } from '../topo3d/topoLinkLive.js'
import { v2 } from '../../api/http.js'

// 2026-09-30 修复"大屏拓扑卡整卡黑/空白"根因: 此前 defineProps 未接返回值,
// script 里 curViewName/pickView 直接引用 prop 名 `card` → 每次计算都抛
// ReferenceError: card is not defined → 组件渲染失败 → 卡面只剩空 div(一片黑)。
// <script setup> 中 prop 只能经 props 对象访问(模板里才能直接写 card.xxx)。
const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  mode: { type: String, default: 'browse' },
  side: { type: String, default: 'front' },
})

const S = useShared()
const router = useRouter()

// 2026-09-30: 数据源 = 多套独立视图仓库(topoViews.js), 与 /topology/3d 独立页同源。
// 卡片展示 card.view 选中的视图(按卡记忆, 随大屏卡片配置保存); 未选/已删 → 跟随全局激活视图。
// 刻意不用演示节点: 大屏出现假节点会让值守者误以为有真实数据。
const store = ensureStore()
const curViewName = computed(() =>
  store.views.some(v => v.name === props.card.view) ? props.card.view : store.active)
const curView = computed(() => store.views.find(v => v.name === curViewName.value) || store.views[0] || null)
// 当前视图文档的节点/链路/框(= 视图对象里的数组, 状态同步直接改视图, 页面同步可见)
const nodes = computed(() => (curView.value ? curView.value.nodes : []))
const links = computed(() => (curView.value ? curView.value.links : []))
const boxes = computed(() => (curView.value ? curView.value.boxes : []))
const ready = ref(false)

// 卡内切视图: 按卡记忆 + 同步全局激活(双击进独立页落在同一视图)
function pickView(name) {
  if (!store.views.some(v => v.name === name)) return
  props.card.view = name
  setActive(name)
}

// ===== 视图轮播(2026-09-30 用户要求: 视图多了可轮播) =====
// 配置(yugsight_topo_view_carousel)由独立页"视图工具栏"管理; 卡只负责跟随:
// 浏览态启用了轮播且视图 ≥2 时, 全局激活视图按间隔自动切换, 卡(未固定 card.view)
// 随 store.active 联动。大屏处于编辑态(用户在摆卡片)时暂停, 回浏览态恢复。
function syncCar() {
  if (props.mode === 'browse' && store.views.length >= 2) startViewCarousel()
  else stopViewCarousel()
}
watch(() => props.mode, syncCar)

onMounted(async () => {
  const v = curView.value
  // 当前视图为空且有纳管设备 → 引导填充(落盘, 独立页看到同样内容)
  // 2026-10-01: 只填纳管设备(探针/节点监控/采集任务), 不再全量灌资产台账
  // (与独立页 importDevices 同口径, 见该函数注释)
  const monDevs = (S.devices || []).filter(d => d.isMonitor)
  if (v && !v.nodes.length && monDevs.length) {
    v.nodes = monDevs.map((d, i) => nodeFromDevice(d, i))
    persistContentViews()   // 内容变更(导入纳管设备) → 打视图戳
  }
  await loadNetworkLinks(nodes.value)
  // 2026-10-01: 不再自动灌入后端按网段推测的链路集(与独立页同口径) —— 卡与页共用
  // 同一份视图文档, 卡里一灌, 独立页和另外的浏览器就冒出用户没画过的线(其中端点
  // 不在视图里的会画成"终点为空"的悬空线); 后端链路只用于覆盖已有链路的字段。
  ready.value = true
  syncCar()   // 视图轮播: 浏览态 + 已启用 + ≥2 视图 才跑
})
onBeforeUnmount(stopViewCarousel)

// 手动链路自动连通测试(大屏全静默: 值守画面不弹提示, 结果写回视图文档, 独立页同步可见)
// 2026-10-01: 与独立页同口径, 放开 _real 限制(用户手动实测过的推测线参与复验)
async function cardCheckLink(l) {
  if (!l || isChecking(l)) return
  const a = nodes.value.find(n => n.deviceId === l.fromDeviceId)
  const b = nodes.value.find(n => n.deviceId === l.toDeviceId)
  const ips = [a && a.ip, b && b.ip].filter(x => x && /^\d{1,3}(\.\d{1,3}){3}$/.test(x))
  if (ips.length < 2) return
  l._checking = true            // UI"测试中…"态
  markChecking(l, true)         // 调度器在途标记(纯内存, 不进 LS —— 防"永久测试中"卡死自动测试)
  try {
    const d = await v2('/topology/links/check', { method: 'POST', body: { ips } })
    l.tested = true
    l.checkedAt = Date.now()
    l.status = d.ok ? 'normal' : 'down'
    l._check = d
    persistContentViews()   // 内容变更(连通测试结果) → 打视图戳
  } catch (e) { /* 静默: 30s 节流后下一拍自然重试 */ }
  finally {
    l._checking = false
    markChecking(l, false)
  }
}

// 纳管设备状态随 15s 轮询同步(小图概览直取值、不做防抖 ——
// "连续 3 次异常才翻态"的防抖口径在独立页工作视图, 大屏概览直取更实时)
// 兜底: 卡片挂载时设备列表可能还没轮询回来(异步竞态, 曾导致有设备却显示空场景),
// 首帧为空则等第一份设备数据回来时补导入
watch(() => S.devUpdatedAt, () => {
  const v = curView.value
  if (!v) return
  // 首帧设备未回来时的补导入: 同样只填纳管设备(见 onMounted 注释)
  if (!v.nodes.length) {
    const monDevs = (S.devices || []).filter(d => d.isMonitor)
    if (monDevs.length) { v.nodes = monDevs.map((d, i) => nodeFromDevice(d, i)); persistContentViews() }   // 内容变更(补导入) → 打视图戳
  }
  for (const n of v.nodes) {
    if (!n.isMonitor) continue
    const d = (S.devices || []).find(x => x.deviceId === n.deviceId)
    if (!d) continue
    n.cpu = d.cpu
    n.memory = d.memory
    // 设备真实上下行 → 节点速率标签 + 流量环(2026-10-01, 与独立页同口径)
    n.inBps = d.inRateBps || 0
    n.outBps = d.outRateBps || 0
    n.status = d.status || n.status
    if (d.ip) n.ip = d.ip
    if (d.mac) n.mac = d.mac
  }
  fillRatesByIP(v.nodes || [], S.devices)   // 资产节点按 IP 补全真实速率(与独立页同口径)
  // 2026-10-01: 链路活数据(与独立拓扑页同源) —— 覆盖 + 补全 + 自动测试走固定序
  syncCardLinkLive()
  persistViews()
})

// 链路活数据统一入口(与独立拓扑页同口径): 后端覆盖(状态/利用率, 只覆盖不增删) +
// 实画线自动连通测试。2026-10-01: 线上速率补全已删(速率只挂在设备节点, 见
// topoLinkLive.js 头注释"速率要真实的"口径)。
function syncCardLinkLive() {
  const v = curView.value
  if (!v) return
  applyApiLinks(v.links || [], S.networkLinks)
  autoCheckManualLinks(v.nodes || [], v.links || [], cardCheckLink)
}

watch(() => S.linkUpdatedAt, () => syncCardLinkLive())
// 2026-10-01: 视图轮播/卡内切视图 → 新视图链路速率要等下一轮 15s 拍才补全
// ("光点有了又没了"), 切换后立即同步(幂等)
watch(curView, () => syncCardLinkLive())

const onlineRate = computed(() => nodes.value.length
  ? Math.round(nodes.value.filter(n => n.status !== 'down').length * 100 / nodes.value.length)
  : 0)
// 安全状态四色(与 topoModel 同口径): 绿=在线/低风险 黄=告警/中危 红=离线/高危 灰=未纳管
const LEGEND = [
  { k: 'green', t: '在线/低风险', c: '#34d399' },
  { k: 'yellow', t: '告警/中风险', c: '#fbbf24' },
  { k: 'red', t: '离线/高危', c: '#f87171' },
  { k: 'gray', t: '未监控', c: '#64748b' },
]
function countOf(k) { return nodes.value.filter(n => safeStatus(n) === k).length }
const srcText = computed(() => (shared.linkSource === 'api' ? '后端链路接口' : 'Mock(链路接口未接入)'))

function goFull() { router.push('/topology/3d') }
</script>

<style scoped>
.tc { position: relative; width: 100%; height: 100%; overflow: hidden; display: flex; flex-direction: column; }
/* 顶栏: 点击翻转卡片(卡片体系行为); 栏内按钮各自 stop, 不误触发翻转 */
.tc-head {
  display: flex; align-items: center; gap: 8px; flex: 0 0 auto;
  padding: 8px 12px; border-bottom: 1px solid rgba(56, 132, 255, .22); cursor: pointer;
}
.tc-title {
  flex: 1; min-width: 0; font-size: 13px; font-weight: 600; letter-spacing: 1px; color: #eaf1fb;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.tc-hbtns { display: flex; gap: 4px; flex: 0 0 auto; }
/* 视图列表下拉(2026-09-30: 替代物理/逻辑切换按钮) */
.tc-view {
  font-size: 11px; padding: 1px 4px; border-radius: 5px; cursor: pointer; max-width: 110px;
  color: #cdd6e4; background: rgba(12, 20, 36, .8); border: 1px solid rgba(56, 132, 255, .3);
}
.tc-fs {
  font-size: 11px; padding: 2px 8px; border-radius: 5px; cursor: pointer;
  color: #9fb0c8; background: transparent; border: 1px solid rgba(56, 132, 255, .3);
}
.tc-fs { flex: 0 0 auto; color: #cdd6e4; }
.tc-fs:hover { background: rgba(56, 132, 255, .24); color: #fff; }
.tc-body { flex: 1; min-height: 0; position: relative; }
/* 缩略态: 一行统计 + 四色圆点 */
.tc-mini {
  position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; gap: 10px;
  font-size: 12px; color: #9fb0c8;
}
.tc-mini b { font-size: 16px; color: #eaf1fb; }
.tc-mini em { font-style: normal; color: #34d399; }
.tc-dots { display: inline-flex; gap: 5px; align-items: center; }
.tc-dots i { width: 8px; height: 8px; border-radius: 50%; display: inline-block; box-shadow: 0 0 6px currentColor; }
.tc-empty {
  position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px;
  font-size: 12.5px; color: #9fb0c8;
}
.tc-empty em { font-style: normal; font-size: 11px; color: #64748b; }
/* 四色状态图例(2026-09-29): 不拦截指针, 拓扑仍可平移/缩放 */
.tc-legend {
  position: absolute; left: 50%; transform: translateX(-50%); bottom: 8px; z-index: 6;
  display: flex; align-items: center; gap: 14px; pointer-events: none;
  padding: 3px 10px; background: rgba(10, 18, 32, .72); border: 1px solid rgba(56, 132, 255, .28);
  border-radius: 8px; backdrop-filter: blur(4px); white-space: nowrap;
}
.tc-legend span { display: flex; align-items: center; gap: 5px; font-size: 10.5px; color: #9fb0c8; }
.tc-legend i { width: 8px; height: 8px; border-radius: 50%; flex: 0 0 auto; }
.tc-legend b { color: #eaf1fb; font-variant-numeric: tabular-nums; margin-left: 2px; }
/* 背面: 汇总概览 */
.tb { position: absolute; inset: 0; display: flex; flex-direction: column; gap: 8px; padding: 14px 16px; }
.tb-title { font-size: 13px; font-weight: 600; color: #eaf1fb; letter-spacing: 1px; }
.tb-row { display: flex; align-items: center; justify-content: space-between; font-size: 12.5px; color: #9fb0c8; }
.tb-row b { font-size: 15px; color: #eaf1fb; }
.tb-legend { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 12px; margin-top: 4px; }
.tb-legend span { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: #9fb0c8; }
.tb-legend i { width: 8px; height: 8px; border-radius: 50%; flex: 0 0 auto; }
.tb-legend b { margin-left: auto; color: #eaf1fb; }
.tb-src { margin-top: auto; font-size: 10.5px; color: #64748b; }
</style>
