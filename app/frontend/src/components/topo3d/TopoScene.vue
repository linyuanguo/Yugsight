<template>
  <!-- TopoScene: 3D 拓扑画布(CSS 3D + 原生 SVG, 不加载 WebGL)。
       三套视图共用同一渲染, 只换布局坐标(见 topoModel 的 layout* 函数)。
       场景控制等价于 OrbitControls 的四件套: 拖拽平移 / 滚轮缩放(锚定鼠标) / Shift+拖拽旋转 / 一键复位;
       浏览模式额外开启"自动巡检"(视角缓慢摆动), 编辑模式暂停(省电, 也免得拖节点时视角乱动)。

       2026-09-28 全量优化:
         - 滚轮缩放中心跟随鼠标位置(锚点公式, 与平移同一近似口径)
         - 双击节点居中放大; 端口下钻移入右键菜单
         - 连线贝塞尔平滑曲线 + 断开红虚线 + 线宽随带宽利用率
         - 节点: 类型差异化配色 + 名称 + 右下角状态指示灯(在线绿/离线灰+红框/告警橙脉冲)
         - 悬浮详情卡(名称/IP/状态/带宽利用率/告警数)
         - 右键菜单: 查看资产详情 / 跳转节点监控 / 全屏查看(浏览+编辑) + 编辑动作
         - 右上角快捷控件: 复位/放大/缩小/全屏 + 编辑模式 自动布局/网格吸附
         - 左下角小地图: 全图预览 + 红色视口框 + 拖拽移动视口 + 框选放大
       left-inset / right-inset: 页面悬浮面板(设备树/属性告警)的开合宽度,
       场景内的左下角小地图与右上角快捷控件随其让位, 避免被面板遮挡 -->
  <div class="ts" :class="[mode, 'v-' + view]" :style="insetStyle" @contextmenu.prevent.stop="openMenu($event, null)">
    <div ref="stageEl" class="ts-stage"
         :title="mode === 'edit' ? '编辑: 拖节点=三维摆位 · Shift+左键拖=旋转视角 · 左键拖空白=平移 · 滚轮=缩放 · 右键=菜单' : '左键拖=平移 · Shift+左键拖=旋转视角 · 滚轮=缩放'"
         @pointerdown="onSceneDown" @wheel.prevent="onWheel"
         @pointerenter="patrolOn = false" @pointerleave="patrolOn = true">
      <div class="ts-fit" :style="fitStyle">
        <div class="ts-world" :style="worldStyle">
          <!-- 分层带(仅逻辑视图) -->
          <template v-if="view === 'logic'">
            <div v-for="b in LAYERS" :key="b.layer" class="ts-band" :style="bandStyle(b)">
              <span class="ts-band-label">{{ b.label }}</span>
            </div>
          </template>
          <!-- 机柜(仅机房视图) -->
          <template v-else-if="view === 'rack'">
            <div v-for="(r, i) in racks" :key="i" class="ts-rack" :style="rackStyle(r)">
              <span class="ts-rack-label">{{ r.label }}</span>
            </div>
          </template>

          <!-- 链路(贝塞尔曲线): 主用=实线 / 备用=虚线 / 中断=红虚线; 颜色=连通状态(绿黄红), 线宽=实时流量占比 -->
          <svg class="ts-links" :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none">
            <path v-for="l in viewLinks" :key="'p' + l.linkId" :id="pathId(l)" :d="pathOf(l)"
                  :class="['ts-link', l.status, (l.kind === 'backup' ? 'backup' : '')]" :style="linkStyle(l)" fill="none" />
            <path v-for="l in viewLinks" :key="'h' + l.linkId" :d="pathOf(l)" class="ts-hit"
                  @click.stop="onLinkClick(l)" @pointerdown.stop @contextmenu.stop.prevent="openMenu($event, null, l)" />
            <template v-for="l in viewLinks" :key="'f' + l.linkId">
              <template v-if="l.status !== 'down'">
                <circle :r="dotR(l)" class="ts-dot" :class="l.status">
                  <animateMotion :dur="flowDur(l)" repeatCount="indefinite">
                    <mpath :href="'#' + pathId(l)" />
                  </animateMotion>
                </circle>
                <circle :r="dotR(l)" class="ts-dot" :class="l.status">
                  <animateMotion :dur="flowDur(l)" repeatCount="indefinite" keyPoints="1;0" keyTimes="0;1" calcMode="linear">
                    <mpath :href="'#' + pathId(l)" />
                  </animateMotion>
                </circle>
              </template>
            </template>
          </svg>

          <!-- 节点实例: 图标填充=设备类型识别色(保留), 边框+状态灯=安全状态四色(绿/黄/红/灰);
               核心/关键节点外圈金色高亮环。见 topoModel.safeStatus/safeColor。 -->
          <div v-for="n in nodes" :key="n.nodeId" class="ts-node"
               :class="[n.status, 'safe-' + safeStatus(n), { core: !!n.isCore, sel: selNode === n.nodeId, linking: linkFrom === n.nodeId }]"
               :style="nodeStyle(n)"
               @pointerdown="onNodeDown($event, n)" @click.stop="onNodeClick(n)"
               @dblclick.stop="onNodeDblClick(n)"
               @mouseenter="onNodeHover($event, n)" @mouseleave="onNodeLeave"
               @contextmenu.stop.prevent="openMenu($event, n)">
            <i v-if="n.isCore" class="ts-core" title="核心/关键节点"></i>
            <span class="ts-ico" :class="'t-' + n.type" :style="{ borderColor: safeColor(n), boxShadow: glow(n) }">
              <i>{{ typeGlyph(n.type) }}</i>
              <em class="ts-led" :style="{ background: safeColor(n), boxShadow: '0 0 6px ' + safeColor(n) }"></em>
            </span>
            <span class="ts-name" :class="{ dim: safeStatus(n) === 'gray' }">{{ n.name }}</span>
            <span class="ts-load"><b :style="{ width: loadPct(n.cpu, n.memory) + '%', background: loadColor(n.cpu, n.memory) }"></b></span>
            <i v-if="n.isCore" class="ts-core-badge" title="核心节点">★</i>
            <i v-if="n.isMonitor" class="ts-mon" title="纳管设备(监控同步)">M</i>
          </div>
        </div>
      </div>
    </div>

    <!-- 悬浮详情卡(节点: 名称/IP/状态/带宽利用率/告警数) -->
    <div v-if="hover" class="ts-hover" :style="hoverStyle">
      <div class="th-h">
        <b>{{ hover.name }}</b>
        <span class="th-st" :class="'st-' + hover.status">{{ STATUS_CN[hover.status] || hover.status }}</span>
      </div>
      <div class="th-row"><span>IP</span><i class="th-ip">{{ hover.ip || '—' }}</i></div>
      <div class="th-row"><span>带宽利用率</span><i>{{ hover.utilText }}</i></div>
      <div class="th-row"><span>关联告警</span><i :class="{ bad: hover.alerts > 0 }">{{ hover.alerts }} 处</i></div>
      <div class="th-tip">双击居中放大 · 右键更多操作</div>
    </div>

    <!-- 右上角快捷控件: 复位/放大/缩小/全屏(常驻) + 自动布局/网格吸附(仅编辑) -->
    <div class="ts-ctrl">
      <button type="button" title="复位视图" @click="resetView">⌂</button>
      <button type="button" title="放大" @click="zoomBy(1.25)">＋</button>
      <button type="button" title="缩小" @click="zoomBy(0.8)">－</button>
      <button type="button" title="全屏查看" @click="emit('fullscreen')">⛶</button>
      <template v-if="mode === 'edit'">
        <span class="ts-ctrl-sep"></span>
        <button type="button" title="一键自动布局(重置为最优分层排布)" @click="emit('reset-layout')">▦</button>
        <button type="button" :class="{ on: snap }" title="网格吸附(拖拽节点时吸附到 20px 网格)" @click="snap = !snap">⌗</button>
      </template>
    </div>

    <!-- 左下角小地图: 全图预览 + 红色视口框; 拖拽=移动视口, 空白处拖框=框选放大 -->
    <div class="ts-mm">
      <svg ref="mmSvg" :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" @pointerdown="onMMDown" @contextmenu.prevent>
        <rect :x="0" :y="0" :width="W" :height="H" class="mm-bg" />
        <line v-for="l in viewLinks" :key="'ml' + l.linkId" class="mm-line"
              :x1="mmEnd(l, 1)" :y1="mmEnd(l, 'y1')" :x2="mmEnd(l, 2)" :y2="mmEnd(l, 'y2')" />
        <circle v-for="n in nodes" :key="'md' + n.nodeId" class="mm-dot" :class="'led-' + n.status"
                :cx="n.x" :cy="n.y" r="26" />
        <rect v-if="mmVp" class="mm-vp" :x="mmVp.x" :y="mmVp.y" :width="mmVp.w" :height="mmVp.h" />
        <rect v-if="mmBox" class="mm-box" :x="mmBox.x" :y="mmBox.y" :width="mmBox.w" :height="mmBox.h" />
      </svg>
    </div>

    <!-- 提示条(放置节点 / 连线 / 删除反馈) -->
    <div v-if="tip" class="ts-tip">{{ tip }}</div>

    <!-- 右键菜单: 节点 / 链路 / 空白处 三类。
         双模式边界(沿用既有"浏览=只读"口径): 查看/配置类双模式可用, 变更类(标记核心/换绑/备用/删除/布局/清空)仅编辑。 -->
    <Teleport to="body">
      <div v-if="menuOpen" class="ts-menu" :style="menuStyle" @pointerdown.stop @click.stop>
        <!-- 链路右键: 查看详情 + 设主用/备用 + 删除 -->
        <template v-if="menuLink">
          <div class="ts-menu-h">链路 · {{ linkMenuTitle }}</div>
          <button type="button" @click="linkAction('detail')">查看详情</button>
          <template v-if="mode === 'edit'">
            <div class="ts-menu-h">编辑</div>
            <button type="button" @click="linkAction('backup')">{{ menuLink.kind === 'backup' ? '设为主用链路(实线)' : '设为备用链路(虚线)' }}</button>
            <button type="button" class="danger" @click="linkAction('delete')">删除链路</button>
          </template>
        </template>
        <!-- 节点右键: 查看详情/配置告警/跳转监控/端口详情 + 标记核心/换绑/连线/删除 -->
        <template v-else-if="menuNode">
          <div class="ts-menu-h">{{ menuNode.name }}</div>
          <button type="button" @click="nodeAction('detail')">查看详情</button>
          <button type="button" @click="nodeAction('alert')">配置告警</button>
          <button type="button" @click="nodeAction('nodemon')">跳转节点监控</button>
          <button type="button" @click="nodeAction('drill')">端口详情</button>
          <template v-if="mode === 'edit'">
            <div class="ts-menu-h">编辑</div>
            <button type="button" @click="nodeAction('core')">{{ menuNode.isCore ? '取消核心标记' : '标记核心节点' }}</button>
            <button type="button" @click="nodeAction('rebind')">更换绑定资产</button>
            <button type="button" @click="pickLink">{{ linkFrom === menuNode.deviceId ? '取消连线' : '从此节点添加链路' }}</button>
            <button type="button" class="danger" @click="nodeAction('delete')">删除该节点</button>
          </template>
        </template>
        <!-- 空白处右键: 导出图片(双模式) + 自动布局/清空画布/网格/添加设备(仅编辑) -->
        <template v-else>
          <div class="ts-menu-h">画布</div>
          <button type="button" @click="canvasAction('export')">导出图片</button>
          <button type="button" @click="canvasAction('resetview')">复位视角</button>
          <template v-if="mode === 'edit'">
            <div class="ts-menu-h">添加设备</div>
            <button v-for="t in TYPE_OPTIONS" :key="t.v" type="button" @click="pickAdd(t.v)">{{ t.t }}</button>
            <div class="ts-menu-h">操作</div>
            <button type="button" @click="canvasAction('layout')">一键自动布局</button>
            <button type="button" class="danger" @click="canvasAction('clear')">清空画布</button>
            <button type="button" @click="canvasAction('grid')">网格吸附: {{ snap ? '开' : '关' }}</button>
          </template>
        </template>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRouter } from 'vue-router'
import {
  LAYERS, TYPE_OPTIONS, W, H, typeGlyph, loadColor, loadPct, LINK_COLOR, STATUS_CN,
  safeStatus, safeColor,
} from './topoModel.js'

const props = defineProps({
  nodes: { type: Array, default: () => [] },
  links: { type: Array, default: () => [] },
  view: { type: String, default: 'logic' },   // logic | rack | force
  mode: { type: String, default: 'browse' },  // browse | edit
  selNode: { type: String, default: '' },
  selLink: { type: String, default: '' },
  // 页面悬浮面板开合宽度: 小地图/快捷控件让位用(0 = 面板收起)
  leftInset: { type: Number, default: 0 },
  rightInset: { type: Number, default: 0 },
})
const emit = defineEmits(['select', 'add-node', 'add-link', 'delete', 'drill', 'move', 'reset-layout', 'fullscreen',
  'config-alert', 'toggle-core', 'rebind', 'toggle-backup', 'export', 'clear-canvas', 'blank-click'])
const router = useRouter()
const insetStyle = computed(() => ({
  '--li': (props.leftInset || 0) + 'px',
  '--ri': (props.rightInset || 0) + 'px',
}))

const stageEl = ref(null)
const tip = ref('')
let tipT = null
function flash(s) {
  tip.value = s
  if (tipT) clearTimeout(tipT)
  tipT = setTimeout(() => { tip.value = '' }, 2400)
}

// ===== 视图变换(对应 OrbitControls 的 target/zoom/rotate + reset) =====
// 坐标口径: .ts-fit 的 1200×720 局部原点在其左上角, 舞台中心对应局部 (W/2, H/2);
// 世界→局部 q = p * scale + t。平移/缩放/定位全部在这一套口径下推导。
const viewState = ref({ rx: 0, ry: 0, tx: 0, ty: 0, scale: 1 })
const SCALE_MIN = 0.35, SCALE_MAX = 2.6
const DEFAULTS = { logic: { rx: 46, ry: 0 }, rack: { rx: 18, ry: -12 }, force: { rx: 0, ry: 0 } }
function resetView() {
  const d = DEFAULTS[props.view] || DEFAULTS.logic
  viewState.value = { rx: d.rx, ry: d.ry, tx: 0, ty: 0, scale: 1 }
}
watch(() => props.view, resetView, { immediate: true })

const fit = ref(1)
const fitStyle = computed(() => ({ transform: `scale(${fit.value})`, transformOrigin: 'top left' }))
const worldStyle = computed(() => {
  const v = viewState.value
  return { transform: `rotateX(${v.rx}deg) rotateY(${v.ry}deg) translate(${v.tx}px, ${v.ty}px) scale(${v.scale})` }
})

// 舞台像素 → fit 局部坐标(缩放锚点/小地图共用)
function toFitLocal(e) {
  const el = stageEl.value
  const r = el.getBoundingClientRect()
  return {
    x: (e.clientX - r.left - r.width / 2) / fit.value + W / 2,
    y: (e.clientY - r.top - r.height / 2) / fit.value + H / 2,
  }
}
// 滚轮缩放: 锚定鼠标 —— 鼠标下的世界点保持不动(与平移同一近似口径: 忽略旋转分量)
function onWheel(e) {
  hover.value = null
  const v = viewState.value
  const f = e.deltaY < 0 ? 1.12 : 0.9
  const ns = Math.min(SCALE_MAX, Math.max(SCALE_MIN, v.scale * f))
  if (ns === v.scale) return
  const m = toFitLocal(e)
  v.tx = m.x - (m.x - v.tx) * (ns / v.scale)
  v.ty = m.y - (m.y - v.ty) * (ns / v.scale)
  v.scale = ns
}
// 快捷缩放(锚定舞台中心)
function zoomBy(f) {
  const v = viewState.value
  const ns = Math.min(SCALE_MAX, Math.max(SCALE_MIN, v.scale * f))
  if (ns === v.scale) return
  v.tx = W / 2 - (W / 2 - v.tx) * (ns / v.scale)
  v.ty = H / 2 - (H / 2 - v.ty) * (ns / v.scale)
  v.scale = ns
}
let cleanup = null
function onSceneDown(e) {
  hover.value = null
  if (e.button !== 0) return
  if (props.mode === 'edit' && addType.value) { placeNode(e); return }
  gesture.value = true
  const v = viewState.value
  const sx = e.clientX, sy = e.clientY
  const o = { tx: v.tx, ty: v.ty, rx: v.rx, ry: v.ry }
  const rot = e.shiftKey
  let moved = false
  function mv(ev) {
    const dx = ev.clientX - sx, dy = ev.clientY - sy
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) moved = true
    if (rot) { v.ry = o.ry + dx / 3; v.rx = Math.min(86, Math.max(0, o.rx - dy / 3)) }
    else { const k = fit.value * v.scale; v.tx = o.tx + dx / k; v.ty = o.ty + dy / k }
  }
  function up() {
    window.removeEventListener('pointermove', mv); window.removeEventListener('pointerup', up); cleanup = null
    gesture.value = false
    // 无位移的点击落在空白(节点/链路已 stopPropagation 不会走到这里) → 收起右侧属性面板
    if (!moved) emit('blank-click')
  }
  cleanup = up
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
// 自适应: 舞台尺寸变化时重算缩放(容器由父页/模板决定, 窗口缩放时自动等比适配)
// stageSize 用响应式状态记录 —— 小地图视口框的计算依赖它(clientWidth 本身不触发 computed)
let ro = null
const stageSize = ref({ w: 0, h: 0 })
function measure() {
  const el = stageEl.value
  if (!el) return
  fit.value = Math.min(el.clientWidth / W, el.clientHeight / H) || 1
  stageSize.value = { w: el.clientWidth, h: el.clientHeight }
}

// ===== 自动巡检(浏览模式): 视角缓慢摆动, 编辑模式暂停 =====
// 2026-09-30 用户反馈: 3D 鼠标放设备上提示"一直闪"(2D 正常) —— 巡检每帧旋转视角,
// 节点在光标下持续滑动, mouseenter/mouseleave 反复触发 → 悬浮卡反复出现消失。
// 修复: ①指针进入舞台期间暂停巡检(移开恢复, 值守视角仍在动); ②悬浮卡 200ms 防抖。
const patrolOn = ref(true)
let raf = 0
function loop(t) {
  if (props.mode === 'browse' && patrolOn.value) {
    const base = (DEFAULTS[props.view] || DEFAULTS.logic).ry
    viewState.value.ry = base + Math.sin(t / 14000) * 16
  }
  raf = requestAnimationFrame(loop)
}

// ===== 渲染 =====
const viewLinks = computed(() => props.links)
function nodeById(deviceId) { return props.nodes.find(n => n.deviceId === deviceId) }
function linkEnds(l) { return [nodeById(l.fromDeviceId), nodeById(l.toDeviceId)] }
// 贝塞尔平滑曲线: 控制点取两端点的垂直中点 → 跨层连线呈 S 形自然过渡,
// 比直线减少同层横向连线与跨层连线的视觉交叉
function pathOf(l) {
  const [a, b] = linkEnds(l)
  if (!a || !b) return ''
  const my = (a.y + b.y) / 2
  return `M ${a.x} ${a.y} C ${a.x} ${my}, ${b.x} ${my}, ${b.x} ${b.y}`
}
function pathId(l) { return 'ts_' + l.linkId }
// 线宽随带宽利用率动态变化(1.6 → 6px); 异常链路再加粗保证全局视角优先可见
function linkStyle(l) {
  const util = l.utilPct != null ? l.utilPct : Math.min(100, Math.round((l.pps || 0) / 60))
  let w = 1.6 + (Math.min(100, util) / 100) * 4.4
  if (l.status !== 'normal') w += 1.5
  return { strokeWidth: w + 'px', stroke: LINK_COLOR[l.status] || LINK_COLOR.normal, opacity: l.status === 'normal' ? 0.8 : 1 }
}
function dotR(l) { return l.status === 'warn' ? 4 : 3 }
// 流量越大光点越快(告警链路再提速)
function flowDur(l) {
  const util = Math.min(100, (l.utilPct != null ? l.utilPct : Math.round((l.pps || 0) / 60)))
  const base = l.status === 'warn' ? 1.1 : 2.6
  return Math.max(0.35, base - util / 100 * 0.9).toFixed(2) + 's'
}
function nodeStyle(n) {
  return { left: n.x + 'px', top: n.y + 'px', transform: `translate(-50%, -50%) translateZ(${n.z || 0}px)` }
}
// 发光: 告警=橙脉冲(颜色由 CSS 动画叠加), 异常=红, 离线=灰+红框(描边环)
function glow(n) {
  // 发光色跟随安全状态四色: 红(离线/高危)最强、黄(告警)次之、绿(在线低风险)弱光、灰(未监控)仅立体阴影
  const base = '0 6px 14px rgba(0,0,0,.55), inset 0 2px 3px rgba(255,255,255,.6)'
  const s = safeStatus(n)
  if (s === 'red') return '0 0 16px 4px rgba(248,113,113,.9), ' + base
  if (s === 'yellow') return '0 0 14px 3px rgba(251,191,36,.85), ' + base
  if (s === 'green') return '0 0 9px 1px rgba(52,211,153,.5), ' + base
  return base
}
function bandStyle(b) { return { top: b.top + 'px', height: b.h + 'px' } }
const racks = computed(() => ([
  { label: '核心机柜 A', x: 140 }, { label: '汇聚机柜 B', x: 560 }, { label: '接入机柜 C', x: 980 },
]))
function rackStyle(r) { return { left: (r.x - 90) + 'px', top: '90px' } }

// ===== 选中 =====
function onNodeClick(n) {
  if (props.mode === 'edit' && linkFrom.value && linkFrom.value !== n.deviceId) {
    const a = nodeById(linkFrom.value)
    if (a) emit('add-link', { fromDeviceId: a.deviceId, toDeviceId: n.deviceId })
    linkFrom.value = ''
    flash('已生成链路')
    return
  }
  emit('select', { kind: 'node', id: n.nodeId })
}
function onLinkClick(l) { emit('select', { kind: 'link', id: l.linkId }) }
// 双击节点: 居中放大显示(原"双击下钻端口"移入右键菜单「端口详情」)
function onNodeDblClick(n) {
  focusDevice(n.deviceId)
}

// ===== 悬浮详情卡 =====
const hover = ref(null)
const hoverStyle = computed(() => {
  const h = hover.value
  if (!h) return {}
  return { left: h.x + 'px', top: h.y + 'px', transform: 'translateX(-50%)' }
})
// 拖拽手势(平移/拖节点)进行中标记: 手势中不弹悬浮卡, 避免卡住拖拽路径
const gesture = ref(false)
// 2026-09-30: 防抖 —— 快速划过节点不弹卡(也兜住巡检滑动下的 enter/leave 抖动)
let hoverT = null
function onNodeHover(e, n) {
  if (gesture.value || e.buttons) return   // 平移/拖节点等手势进行中不弹卡
  if (hoverT) clearTimeout(hoverT)
  hoverT = setTimeout(() => { hoverT = null; showHoverCard(e, n) }, 200)
}
function onNodeLeave() {
  if (hoverT) { clearTimeout(hoverT); hoverT = null }
  hover = null
}
function showHoverCard(e, n) {
  const ico = e.currentTarget && e.currentTarget.querySelector ? e.currentTarget.querySelector('.ts-ico') : null
  const el = stageEl.value
  if (!ico || !el) return
  const ir = ico.getBoundingClientRect()
  const r = el.getBoundingClientRect()
  const cx = ir.left + ir.width / 2 - r.left
  const topY = ir.top - r.top
  const flip = topY < 150   // 靠近顶边时翻到节点下方
  // 带宽利用率 = 相邻链路均值(无链路 —); 告警数 = 自身异常 + 相邻异常链路
  const ls = props.links.filter(l => l.fromDeviceId === n.deviceId || l.toDeviceId === n.deviceId)
  let utilText = '—', alerts = 0
  if (ls.length) {
    const us = ls.map(l => (l.utilPct != null ? l.utilPct : Math.min(100, Math.round((l.pps || 0) / 60))))
    utilText = Math.round(us.reduce((a, b) => a + b, 0) / us.length) + '%'
  }
  if (n.status !== 'normal') alerts++
  alerts += ls.filter(l => l.status !== 'normal').length
  hover.value = {
    name: n.name, ip: n.ip, status: n.status,
    utilText, alerts,
    x: Math.max(110, Math.min(r.width - 110, cx)),
    y: flip ? topY + ir.height + 10 : topY - 122,
    flip,
  }
}

// ===== 小地图(全图预览 + 红色视口框 + 拖拽移动 + 框选放大) =====
const mmSvg = ref(null)
const mmBox = ref(null)
// 视口 = 当前可见的世界区域(舞台尺寸/fit → fit 局部 → 世界; 钳到世界边界)
const mmVp = computed(() => {
  if (!fit.value || !stageSize.value.w) return null
  const v = viewState.value
  const sw = stageSize.value.w / fit.value, sh = stageSize.value.h / fit.value
  const x1 = (-v.tx) / v.scale, x2 = (sw - v.tx) / v.scale
  const y1 = (-v.ty) / v.scale, y2 = (sh - v.ty) / v.scale
  const x = Math.max(0, x1), y = Math.max(0, y1)
  const x2c = Math.min(W, x2), y2c = Math.min(H, y2)
  if (x2c - x < 1 || y2c - y < 1) return null
  return { x, y, w: x2c - x, h: y2c - y }
})
function mmEnd(l, which) {
  const [a, b] = linkEnds(l)
  if (!a || !b) return 0
  return which === 1 ? a.x : which === 2 ? b.x : which === 'y1' ? a.y : b.y
}
// 小地图像素 → 世界坐标(小地图按 viewBox 0 0 W H 等比映射, 直接取)
function mmWorld(e) {
  const r = mmSvg.value.getBoundingClientRect()
  return {
    x: (e.clientX - r.left) / r.width * W,
    y: (e.clientY - r.top) / r.height * H,
  }
}
function onMMDown(e) {
  if (e.button !== 0) return
  const p = mmWorld(e)
  const vp = mmVp.value
  const inVp = vp && p.x >= vp.x && p.x <= vp.x + vp.w && p.y >= vp.y && p.y <= vp.y + vp.h
  if (!e.shiftKey && inVp) {
    // 拖拽红框(视口内): 移动视口 —— 世界位移反作用于 tx/ty
    const v = viewState.value
    const t0 = { tx: v.tx, ty: v.ty }
    function mv(ev) {
      const q = mmWorld(ev)
      v.tx = t0.tx - (q.x - p.x) * v.scale
      v.ty = t0.ty - (q.y - p.y) * v.scale
    }
    function up() {
      window.removeEventListener('pointermove', mv)
      window.removeEventListener('pointerup', up)
    }
    window.addEventListener('pointermove', mv)
    window.addEventListener('pointerup', up)
    return
  }
  // 空白处拖框: 框选放大(松手把框内区域放大到充满舞台; 小于阈值当点击=居中该点)
  const box0 = { x: p.x, y: p.y }
  mmBox.value = { x: p.x, y: p.y, w: 0, h: 0 }
  function mv(ev) {
    const q = mmWorld(ev)
    mmBox.value = {
      x: Math.min(box0.x, q.x), y: Math.min(box0.y, q.y),
      w: Math.abs(q.x - box0.x), h: Math.abs(q.y - box0.y),
    }
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    const b = mmBox.value
    mmBox.value = null
    if (!b || !stageSize.value.w) return
    if (b.w < 40 || b.h < 24) {   // 太小 = 点击: 视口居中到该点
      const v = viewState.value
      v.tx = W / 2 - b.x * v.scale
      v.ty = H / 2 - b.y * v.scale
      return
    }
    const sw = stageSize.value.w / fit.value, sh = stageSize.value.h / fit.value
    const ns = Math.min(SCALE_MAX, Math.max(SCALE_MIN, Math.min(sw / b.w, sh / b.h)))
    const v = viewState.value
    v.scale = ns
    v.tx = W / 2 - (b.x + b.w / 2) * ns
    v.ty = H / 2 - (b.y + b.h / 2) * ns
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}

// ===== 右键菜单(浏览+编辑; 节点动作双模式可用, 编辑动作仅编辑态) =====
const menuOpen = ref(false)
const menuStyle = ref({})
const menuNode = ref(null)
const menuLink = ref(null)
const linkMenuTitle = computed(() => {
  const l = menuLink.value
  if (!l) return ''
  const a = nodeById(l.fromDeviceId), b = nodeById(l.toDeviceId)
  return (a ? a.name : '?') + ' ↔ ' + (b ? b.name : '?')
})
function openMenu(e, node, link) {
  menuNode.value = node || null
  menuLink.value = link || null
  // 浏览模式: 空白处无动作; 节点/链路菜单仍可用(只读动作), 变更项在模板里按 mode 隐藏
  if (!menuNode.value && !menuLink.value && props.mode !== 'edit') return
  menuStyle.value = {
    left: Math.min(e.clientX, window.innerWidth - 210) + 'px',
    top: Math.min(e.clientY, window.innerHeight - 360) + 'px',
  }
  menuOpen.value = true
  window.addEventListener('pointerdown', closeMenu, { once: true })
}
function closeMenu() { menuOpen.value = false }
// 节点右键: 查看详情/配置告警/跳转监控/端口详情(双模式) + 标记核心/换绑/删除(仅编辑)
function nodeAction(kind) {
  const n = menuNode.value
  closeMenu()
  if (!n) return
  if (kind === 'detail') emit('select', { kind: 'node', id: n.nodeId })
  else if (kind === 'alert') emit('config-alert', n)
  else if (kind === 'nodemon') router.push('/nodemonitor')
  else if (kind === 'drill') emit('drill', n)
  else if (kind === 'core') emit('toggle-core', n)
  else if (kind === 'rebind') emit('rebind', n)
  else if (kind === 'delete') emit('delete', { nodeId: n.nodeId })
}
// 链路右键: 查看详情(双模式) + 设主用/备用 + 删除(仅编辑)
function linkAction(kind) {
  const l = menuLink.value
  closeMenu()
  if (!l) return
  if (kind === 'detail') emit('select', { kind: 'link', id: l.linkId })
  else if (kind === 'backup') emit('toggle-backup', l)
  else if (kind === 'delete') emit('delete', { linkId: l.linkId })
}
// 空白处右键: 导出图片/复位(双模式) + 自动布局/清空画布/网格(仅编辑)
function canvasAction(kind) {
  closeMenu()
  if (kind === 'resetview') { resetView(); return }
  if (kind === 'export') emit('export')
  else if (kind === 'layout') emit('reset-layout')
  else if (kind === 'clear') emit('clear-canvas')
  else if (kind === 'grid') snap.value = !snap.value
}

// ===== 编辑: 拖拽 / 放置 / 连线 / 删除 =====
const snap = ref(false)   // 网格吸附开关(编辑模式快捷控件)
function onNodeDown(e, n) {
  e.stopPropagation()
  hover.value = null
  if (props.mode !== 'edit') return
  gesture.value = true
  const v = viewState.value
  const k = fit.value * v.scale
  const sx = e.clientX, sy = e.clientY, ox = n.x, oy = n.y
  function mv(ev) {
    let nx = ox + (ev.clientX - sx) / k
    let ny = oy + (ev.clientY - sy) / k
    if (snap.value) { nx = Math.round(nx / 20) * 20; ny = Math.round(ny / 20) * 20 }
    n.x = Math.round(nx)
    n.y = Math.round(ny)
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    gesture.value = false
    if (snap.value) { n.x = Math.round(n.x / 20) * 20; n.y = Math.round(n.y / 20) * 20 }
    emit('move', n)
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
const addType = ref('')
function pickAdd(t) {
  closeMenu()
  addType.value = t
  flash(`点击画布空白处放置「${TYPE_OPTIONS.find(x => x.v === t).t}」`)
}
function placeNode(e) {
  const rect = stageEl.value.getBoundingClientRect()
  const v = viewState.value
  const px = (e.clientX - rect.left) / fit.value
  const py = (e.clientY - rect.top) / fit.value
  const x = Math.round((px - v.tx) / v.scale)
  const y = Math.round((py - v.ty) / v.scale)
  emit('add-node', { type: addType.value, x, y })
  addType.value = ''
}
const linkFrom = ref('')
function pickLink() {
  closeMenu()
  if (linkFrom.value) { linkFrom.value = ''; flash('已取消连线'); return }
  const n = menuNode.value || props.nodes.find(x => x.nodeId === props.selNode)
  linkFrom.value = n ? n.deviceId : ''
  flash(linkFrom.value ? '再点击另一个节点完成连线' : '请先选中起点节点')
}
function delSel() {
  closeMenu()
  if (props.selNode || props.selLink) emit('delete', { nodeId: props.selNode, linkId: props.selLink })
}
// 重置节点位置: 由父页清掉本地坐标缓存并回到默认分层排布
function resetLayoutPositions() {
  closeMenu()
  emit('reset-layout')
}
function onKey(e) {
  if (props.mode !== 'edit') return
  if (e.key !== 'Delete' && e.key !== 'Backspace') return
  const t = e.target
  if (t && ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName)) return
  if (props.selNode || props.selLink) { e.preventDefault(); delSel() }
}

// ===== 外部可调用(搜索定位 / 复位 / 双击居中) =====
function focusDevice(deviceId) {
  const n = nodeById(deviceId)
  if (!n) return false
  const v = viewState.value
  v.rx = (DEFAULTS[props.view] || DEFAULTS.logic).rx
  v.ry = 0
  // 节点居中: 局部 (W/2, H/2) 是舞台中心 → t = 中心 - 节点 * 缩放
  v.scale = Math.min(SCALE_MAX, Math.max(1.2, v.scale * 1.2))
  v.tx = Math.round(W / 2 - n.x * v.scale)
  v.ty = Math.round(H / 2 - n.y * v.scale)
  emit('select', { kind: 'node', id: n.nodeId })
  return true
}
defineExpose({ focusDevice, resetView })

watch(() => props.mode, (m) => { if (m !== 'edit') { addType.value = ''; linkFrom.value = ''; menuOpen.value = false; snap.value = false } })

onMounted(() => {
  measure()
  if (window.ResizeObserver) { ro = new ResizeObserver(measure); ro.observe(stageEl.value) }
  window.addEventListener('keydown', onKey)
  raf = requestAnimationFrame(loop)
})
onBeforeUnmount(() => {
  cancelAnimationFrame(raf)
  window.removeEventListener('keydown', onKey)
  window.removeEventListener('pointerdown', closeMenu)
  if (ro) ro.disconnect()
  if (cleanup) cleanup()
  if (tipT) clearTimeout(tipT)
})
</script>

<style scoped>
.ts { position: relative; width: 100%; height: 100%; overflow: hidden; background: radial-gradient(120% 90% at 50% 0%, #0d1730 0%, #070d18 70%); }
.ts-stage { position: absolute; inset: 0; perspective: 1500px; perspective-origin: 50% 44%; overflow: hidden; cursor: grab; }
.ts-stage:active { cursor: grabbing; }
.ts-fit { position: absolute; left: 50%; top: 50%; width: 1200px; height: 720px; margin-left: -600px; margin-top: -360px; }
.ts-world { position: absolute; inset: 0; transform-style: preserve-3d; }

.ts-band { position: absolute; left: 0; width: 1200px; border-bottom: 1px dashed rgba(56, 132, 255, .35); }
.ts-band:nth-child(1) { background: linear-gradient(180deg, rgba(56, 132, 255, .1), rgba(56, 132, 255, .02)); }
.ts-band:nth-child(2) { background: linear-gradient(180deg, rgba(56, 132, 255, .05), rgba(56, 132, 255, .01)); }
.ts-band:nth-child(3) { background: linear-gradient(180deg, rgba(56, 132, 255, .02), rgba(56, 132, 255, .06)); }
.ts-band-label { position: absolute; right: 14px; top: 6px; font-size: 13px; color: rgba(159, 176, 200, .75); letter-spacing: 2px; }
.ts-rack {
  position: absolute; width: 200px; height: 520px; border: 1px solid rgba(56, 132, 255, .35);
  border-radius: 8px; background: linear-gradient(180deg, rgba(56, 132, 255, .08), rgba(56, 132, 255, .02));
  box-shadow: inset 0 0 30px rgba(56, 132, 255, .08);
}
.ts-rack-label { position: absolute; left: 8px; top: -20px; font-size: 12px; color: rgba(159, 176, 200, .8); }

/* ===== 链路 ===== */
.ts-links { position: absolute; left: 0; top: 0; width: 1200px; height: 720px; overflow: visible; pointer-events: none; }
.ts-link { filter: drop-shadow(0 0 4px currentColor); transition: stroke .4s ease, stroke-width .4s ease; }
.ts-link.warn { animation: tsBreath 1.4s ease-in-out infinite; }
/* 断开链路: 红色虚线(呼吸保留, 让人一眼看到"断了") */
.ts-link.down { stroke-dasharray: 9 7; animation: tsBlink 1s steps(2, start) infinite; }
/* 备用链路: 虚线(与中断同为虚线, 靠颜色区分——备用=对应连通色, 中断=红) */
.ts-link.backup { stroke-dasharray: 9 7; }
.ts-hit { stroke: transparent; stroke-width: 16; fill: none; pointer-events: stroke; cursor: pointer; }
/* 流动光点颜色跟随链路连通状态(绿正常/黄告警/红中断) */
.ts-dot { fill: #d6fff2; filter: drop-shadow(0 0 6px #34d399); }
.ts-dot.warn { fill: #ffe1b0; filter: drop-shadow(0 0 6px #fbbf24); }
.ts-dot.down { fill: #ffd0d0; filter: drop-shadow(0 0 7px #f87171); }
@keyframes tsBreath { 0%, 100% { opacity: .9; } 50% { opacity: .35; } }
@keyframes tsBlink { 0% { opacity: 1; } 50% { opacity: .3; } 100% { opacity: 1; } }

/* ===== 节点(类型差异化配色 + 名称 + 右下角状态灯) ===== */
.ts-node { position: absolute; display: flex; flex-direction: column; align-items: center; gap: 3px; cursor: pointer; user-select: none; }
.ts-ico {
  position: relative;
  width: 38px; height: 38px; border-radius: 9px; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(145deg, #e8eefc, #b9c6e0); color: #06121f; font-size: 18px; font-weight: 700;
  border: 1.5px solid rgba(56, 132, 255, .55);
  transition: border-color .4s ease, box-shadow .4s ease;   /* 安全状态变化平滑过渡(防抖翻态时颜色渐变而非生硬跳变) */
}
.ts-ico i { font-style: normal; }
/* 类型差异化: 每台设备一个识别色(边框+图标色), 远距离也能分辨层级角色 */
.ts-ico.t-router { border-color: #38bdf8; color: #075985; background: linear-gradient(145deg, #e0f2fe, #bae6fd); }
.ts-ico.t-coresw { border-color: #818cf8; color: #3730a3; background: linear-gradient(145deg, #e0e7ff, #c7d2fe); }
.ts-ico.t-aggsw { border-color: #c084fc; color: #6b21a8; background: linear-gradient(145deg, #f3e8ff, #e9d5ff); }
.ts-ico.t-firewall { border-color: #fb7185; color: #9f1239; background: linear-gradient(145deg, #ffe4e6, #fecdd3); }
.ts-ico.t-server { border-color: #34d399; color: #065f46; background: linear-gradient(145deg, #d1fae5, #a7f3d0); }
.ts-ico.t-probe { border-color: #fbbf24; color: #92400e; background: linear-gradient(145deg, #fef3c7, #fde68a); }
/* 第四阶段扩展类型(网络设备/业务服务) */
.ts-ico.t-l3sw { border-color: #60a5fa; color: #1e3a8a; background: linear-gradient(145deg, #dbeafe, #bfdbfe); }
.ts-ico.t-l2sw { border-color: #a78bfa; color: #5b21b6; background: linear-gradient(145deg, #ede9fe, #ddd6fe); }
.ts-ico.t-database { border-color: #2dd4bf; color: #134e4a; background: linear-gradient(145deg, #ccfbf1, #99f6e4); }
.ts-ico.t-middleware { border-color: #fb923c; color: #9a3412; background: linear-gradient(145deg, #ffedd5, #fed7aa); }
.ts-ico.t-web { border-color: #38bdf8; color: #0c4a6e; background: linear-gradient(145deg, #e0f2fe, #bae6fd); }
/* 右下角状态指示灯: 在线绿 / 离线灰 / 告警橙 / 异常红 */
.ts-led {
  position: absolute; right: -3px; bottom: -3px; width: 10px; height: 10px; border-radius: 50%;
  border: 2px solid #0a1220; font-style: normal;
}
.led-normal { background: #34d399; box-shadow: 0 0 6px #34d399; }
.led-warn { background: #fbbf24; box-shadow: 0 0 7px #fbbf24; }
.led-error { background: #f87171; box-shadow: 0 0 7px #f87171; }
.led-down { background: #64748b; }
/* 离线: 灰化 + 红框(图标本身的红框由 glow 的 inset 环给出) */
.ts-node.down .ts-ico { filter: grayscale(.65); opacity: .8; }
.ts-node.error .ts-name { color: #fca5a5; }
/* 告警/异常: 图标外圈脉冲发光(颜色脉冲, 不闪烁) */
.ts-node.warn .ts-ico::after, .ts-node.error .ts-ico::after {
  content: ''; position: absolute; inset: -5px; border-radius: 13px; pointer-events: none;
}
.ts-node.warn .ts-ico::after { animation: icoPulseWarn 1.4s ease-in-out infinite; }
.ts-node.error .ts-ico::after { animation: icoPulseErr 1.4s ease-in-out infinite; }
@keyframes icoPulseWarn {
  0% { box-shadow: 0 0 0 0 rgba(251, 191, 36, .65); }
  70% { box-shadow: 0 0 0 10px rgba(251, 191, 36, 0); }
  100% { box-shadow: 0 0 0 0 rgba(251, 191, 36, 0); }
}
@keyframes icoPulseErr {
  0% { box-shadow: 0 0 0 0 rgba(248, 113, 113, .65); }
  70% { box-shadow: 0 0 0 10px rgba(248, 113, 113, 0); }
  100% { box-shadow: 0 0 0 0 rgba(248, 113, 113, 0); }
}
.ts-name { font-size: 12px; color: #dbe6f5; white-space: nowrap; text-shadow: 0 1px 3px #000; }
.ts-load { width: 30px; height: 3px; border-radius: 2px; background: rgba(255, 255, 255, .12); overflow: hidden; }
.ts-load b { display: block; height: 100%; }
.ts-mon {
  position: absolute; top: -6px; right: -10px; width: 14px; height: 14px; border-radius: 50%;
  font-size: 8px; font-style: normal; line-height: 14px; text-align: center;
  background: #38bdf8; color: #06121f; box-shadow: 0 0 6px #38bdf8;
}
/* 未监控节点: 名称置灰(安全状态=gray, 数据不可信, 弱化显示) */
.ts-node.safe-gray .ts-name.dim { color: #64748b; opacity: .72; }
/* 核心/关键节点: 外圈金色高亮环(比选中态更醒目, 独立于状态色, 一眼锁定关键资产) */
.ts-core {
  position: absolute; width: 50px; height: 50px; left: 50%; top: 19px; transform: translate(-50%, -50%);
  border: 2px solid #f5c542; border-radius: 15px; pointer-events: none;
  box-shadow: 0 0 12px rgba(245, 197, 66, .7), inset 0 0 8px rgba(245, 197, 66, .3);
}
/* 核心节点 ★ 徽标(左上角, 与纳管 M 徽章错开) */
.ts-core-badge {
  position: absolute; top: -7px; left: -9px; width: 15px; height: 15px; border-radius: 50%;
  font-size: 9px; font-style: normal; line-height: 15px; text-align: center;
  background: #f5c542; color: #3a2a05; box-shadow: 0 0 7px rgba(245, 197, 66, .8);
}
/* 离线/高危(安全红): 状态灯闪烁提示(告警脉冲由 icoPulse 承担, 这里补离线/高危的呼吸) */
.ts-node.safe-red .ts-led { animation: tsBlink 1.2s ease-in-out infinite; }
.ts-node.sel .ts-ico, .ts-node.linking .ts-ico { outline: 2px solid #fbbf24; outline-offset: 2px; }
.ts.edit .ts-node:hover .ts-ico { outline: 1px solid rgba(56, 132, 255, .85); outline-offset: 2px; }

/* ===== 悬浮详情卡 ===== */
.ts-hover {
  position: absolute; z-index: 25; width: 190px; pointer-events: none;
  background: rgba(10, 18, 32, .94); border: 1px solid rgba(56, 132, 255, .45);
  border-radius: 8px; padding: 8px 10px; box-shadow: 0 10px 28px rgba(0, 0, 0, .55);
  backdrop-filter: blur(6px);
}
.th-h { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 5px; }
.th-h b { font-size: 12.5px; color: #eaf1fb; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.th-st { flex: 0 0 auto; font-size: 10px; border-radius: 4px; padding: 1px 6px; }
.th-st.st-normal { color: #34d399; background: rgba(52, 211, 153, .14); }
.th-st.st-warn { color: #fbbf24; background: rgba(251, 191, 36, .14); }
.th-st.st-error { color: #f87171; background: rgba(248, 113, 113, .16); }
.th-st.st-down { color: #94a3b8; background: rgba(148, 163, 184, .14); }
.th-row { display: flex; justify-content: space-between; font-size: 11.5px; color: #8295b0; padding: 2px 0; }
.th-row i { font-style: normal; color: #dbe6f5; font-variant-numeric: tabular-nums; }
.th-row i.bad { color: #fbbf24; }
.th-ip { font-family: var(--mono, monospace); }
.th-tip { margin-top: 5px; padding-top: 4px; border-top: 1px solid rgba(255, 255, 255, .08); font-size: 10px; color: #64748b; }

/* ===== 右上角快捷控件 ===== */
.ts-ctrl {
  position: absolute; top: 12px; right: calc(12px + var(--ri, 0px)); z-index: 24;
  display: flex; align-items: center; gap: 4px; padding: 4px 6px;
  background: rgba(10, 18, 32, .72); border: 1px solid rgba(56, 132, 255, .35);
  border-radius: 8px; backdrop-filter: blur(8px); box-shadow: 0 4px 18px rgba(0, 0, 0, .4);
}
.ts-ctrl button {
  width: 26px; height: 24px; border-radius: 5px; cursor: pointer;
  color: #9fb0c8; background: transparent; border: 1px solid transparent;
  font-size: 13px; line-height: 1;
}
.ts-ctrl button:hover { color: #fff; background: rgba(56, 132, 255, .24); }
.ts-ctrl button.on { color: #38bdf8; border-color: rgba(56, 189, 248, .5); background: rgba(56, 189, 248, .14); }
.ts-ctrl-sep { width: 1px; height: 16px; background: rgba(255, 255, 255, .14); margin: 0 2px; }

/* ===== 左下角小地图 ===== */
.ts-mm {
  position: absolute; left: calc(12px + var(--li, 0px)); bottom: 12px; z-index: 24; width: 176px; height: 106px;
  background: rgba(10, 18, 32, .78); border: 1px solid rgba(56, 132, 255, .35);
  border-radius: 8px; overflow: hidden; backdrop-filter: blur(8px);
  box-shadow: 0 4px 18px rgba(0, 0, 0, .4); cursor: crosshair;
}
.ts-mm svg { display: block; width: 100%; height: 100%; }
.mm-bg { fill: rgba(56, 132, 255, .05); }
.mm-line { stroke: rgba(52, 214, 200, .28); stroke-width: 3; }
.mm-dot { stroke: none; }
.mm-dot.led-normal { fill: #34d399; }
.mm-dot.led-warn { fill: #fbbf24; }
.mm-dot.led-error { fill: #f87171; }
.mm-dot.led-down { fill: #64748b; }
/* 红色视口框(任务口径) */
.mm-vp {
  fill: rgba(248, 113, 113, .12); stroke: #f87171; stroke-width: 2;
  vector-effect: non-scaling-stroke;
}
.mm-box { fill: rgba(56, 189, 248, .16); stroke: #38bdf8; stroke-width: 2; stroke-dasharray: 6 4; vector-effect: non-scaling-stroke; }

.ts-tip {
  position: absolute; left: 50%; transform: translateX(-50%); bottom: 12px; z-index: 26;
  font-size: 12px; color: #fbbf24; background: rgba(10, 18, 32, .92);
  border: 1px solid rgba(251, 191, 36, .35); border-radius: 6px; padding: 3px 12px;
}
.ts-menu {
  position: fixed; z-index: 9999; min-width: 156px;
  background: rgba(12, 20, 36, .97); border: 1px solid rgba(56, 132, 255, .4);
  border-radius: 8px; padding: 4px; box-shadow: 0 12px 34px rgba(0, 0, 0, .6);
}
.ts-menu-h { padding: 5px 12px 2px; font-size: 10.5px; color: #64748b; letter-spacing: 1px; border-top: 1px solid rgba(255, 255, 255, .06); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ts-menu-h:first-child { border-top: none; }
.ts-menu button { display: block; width: 100%; text-align: left; padding: 6px 12px; font-size: 12px; color: #cdd6e4; background: transparent; border: none; border-radius: 5px; cursor: pointer; }
.ts-menu button:hover { background: rgba(56, 132, 255, .22); color: #fff; }
.ts-menu button:disabled { opacity: .4; cursor: default; }
.ts-menu button.danger { color: #f87171; }
.ts-menu button.danger:hover { background: rgba(248, 113, 113, .18); }
</style>
