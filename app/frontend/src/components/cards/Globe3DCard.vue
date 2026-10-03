<template>
  <!-- 3D 地球安全态势卡(2026-09-27)。

       【为什么不用 CSS 伪三维】与卡片/拓扑不同, 地球需要真实的球面贴图、大气散射、
        透视深度与上千个数据点, CSS 做不到; 仓库在 build/globe/ 已内置 globe.gl
        (UMD, 内嵌 three ≥ r165), 运行时经 Go 端 /vendor/globe/ 直读, 属于本地资源,
        不需要新增 npm 依赖也不需要任何 CDN —— 满足"全资源本地化、禁在线依赖"。

       【必须记住的坑(历史实测)】
        ① 不要单独预载 three.min.js: globe.gl 内部优先复用 window.THREE, 预载旧版
           (r15x 无 THREE.Timer) 会直接崩溃 "s3.Timer is not a constructor";
           资源里留 three.min.js 只作占位, 只用 globe 自带的那份 three;
        ② 线宽属性是 arcStroke(不是 arcStrokeWidth), 链式调用名写错整条链会崩;
        ③ 每个实例占用一个 WebGL context, 浏览器有上限且丢失后不可恢复 —— 因此
           画布级硬限「最多 1 个地球卡」, 卸载时必须 destructor + 清空 DOM 释放。

       【数据绑定】默认 /api/dashboard/flows(points 事件点 / arcs 攻击轨迹);
        属性面板 custom 字段可贴自定义 JSON:[{name,lat,lon,value,level,type}]。
        points 同时派生 rings(流量热点圆环, 半径映射数值)。 -->
  <div class="g3" @pointerdown.stop @click.stop>
    <template v-if="side === 'front'">
      <div v-if="blocked" class="g3-mask">
        <span class="g3-tag">受限</span>画布已有地球卡<br />
        <span class="muted">每个地球占用一个 WebGL 上下文, 同一页最多 1 个</span>
      </div>
      <template v-else>
        <div ref="wrapEl" class="g3-canvas"></div>
        <div v-if="state === 'loading'" class="g3-mask"><span class="g3-tag">加载中</span>正在加载 3D 地球资源</div>
        <div v-else-if="state === 'error'" class="g3-mask"><span class="g3-tag">不可用</span>{{ errorMsg }}</div>
        <div v-else-if="!ptCount" class="g3-mask"><span class="g3-tag">无数据</span>{{ emptyMsg }}</div>
        <div class="g3-hud">
          <span><i class="d" style="background:#f87171"></i>高危</span>
          <span><i class="d" style="background:#fb923c"></i>中危</span>
          <span><i class="d" style="background:#38bdf8"></i>低危</span>
          <span class="g3-hud-num">节点 {{ ptCount }} · 轨迹 {{ arcCount }}</span>
        </div>
      </template>
    </template>
    <template v-else>
      <div class="g3-back">
        <div><span>数据源</span><b>{{ card.custom ? '自定义 JSON' : '/api/dashboard/flows' }}</b></div>
        <div><span>事件点</span><b>{{ ptCount }}</b></div>
        <div><span>攻击轨迹</span><b>{{ arcCount }}</b></div>
        <div><span>热点圆环</span><b>{{ ringCount }}</b></div>
        <div><span>点上限</span><b>{{ max }}</b></div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, inject, watch, onMounted, onBeforeUnmount } from 'vue'
import { useShared } from './dashData.js'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

// 单实例限制:只认画布上 id 最小(最先创建的)那张地球卡
const cards = inject('bproCards', ref([]))
const blocked = computed(() => {
  const gl = (cards.value || []).filter(c => c.type === 'globe')
  return gl.length > 1 && gl[0].id !== props.card.id
})

// 保证本卡片挂载后 shared 轮询一定在跑(画面只剩下地球卡时也要有数据)
const shared = useShared()

const wrapEl = ref(null)
const state = ref('loading')     // loading | ready | error
const errorMsg = ref('')
const emptyMsg = ref('暂无可定位的地理位置数据(多为内网段或 geoip 未开启)')

const max = computed(() => props.card.maxPoints || 120)

// ===== 数据解析( points / arcs / rings ) =====
const LV_COLOR = { high: '#f87171', mid: '#fb923c', low: '#38bdf8' }
// 等级名归一: 自定义数据里可能写 medium/middle/严重 之类, 统一收敛到三档配色
function normLevel(v) {
  const s = String(v || '').toLowerCase()
  if (s === 'high' || s === 'critical' || s === '严重' || s === 'critical' || s === 'high') return 'high'
  if (s === 'mid' || s === 'medium' || s === 'middle' || s === '中危' || s === 'medium') return 'mid'
  return 'low'
}
function levelOf(v) {
  const hi = props.card.hiAt || 50, mi = props.card.midAt || 10
  if (v >= hi) return 'high'
  if (v >= mi) return 'mid'
  return 'low'
}
function parseCustom() {
  try {
    const arr = JSON.parse(props.card.custom || '')
    return Array.isArray(arr) ? arr : []
  } catch (e) { return [] }
}
const points = computed(() => {
  void shared.updatedAt
  const raw = props.card.custom ? parseCustom() : ((shared.flows && shared.flows.points) || [])
  const mapped = raw.map((d, i) => ({
    id: d.id || String(i), name: d.name || d.ip || '未知', ip: d.ip || '',
    lat: Number(d.lat), lng: Number(d.lon || d.lng),
    value: Number(d.value || d.count || 0),
    lv: normLevel(d.level || levelOf(Number(d.value || d.count || 0))),
  })).filter(d => !isNaN(d.lat) && !isNaN(d.lng))
  // 降采样: 先按数值取前 N(保住重点), 超限时不再往下喂给 WebGL
  return mapped.sort((a, b) => b.value - a.value).slice(0, max.value)
})
const arcs = computed(() => {
  void shared.updatedAt
  if (props.card.custom) return []
  const raw = (shared.flows && shared.flows.arcs) || []
  const mx = Math.max(1, ...raw.map(a => a.count || 1))
  return raw.slice(0, max.value).map((a, i) => ({
    id: String(i), count: a.count || 1,
    startLat: a.from && a.from.lat, startLng: a.from && a.from.lon,
    endLat: a.to && a.to.lat, endLng: a.to && a.to.lon,
    lv: levelOf(Math.round((a.count || 1) * 100 / mx)),
  })).filter(a => !isNaN(a.startLat) && !isNaN(a.endLat))
})
const rings = computed(() => {
  const mx = Math.max(1, ...points.value.map(p => p.value))
  return points.value.slice(0, Math.min(30, max.value)).map(p => ({
    lat: p.lat, lng: p.lng, maxR: 1.5 + 4.5 * (p.value / mx), lv: p.lv, id: p.id,
  }))
})
const ptCount = computed(() => points.value.length)
const arcCount = computed(() => arcs.value.length)
const ringCount = computed(() => rings.value.length)

// ===== globe.gl 懒加载(模块级 Promise: 只加载一次) =====
let loadPromise = null
function loadScript() {
  if (loadPromise) return loadPromise
  loadPromise = new Promise((resolve, reject) => {
    if (window.Globe) { resolve(); return }
    const s = document.createElement('script')
    s.src = '/vendor/globe/globe.gl.min.js'
    s.onload = () => (window.Globe ? resolve() : reject(new Error('globe.gl 未导出 Globe 全局')))
    s.onerror = () => reject(new Error('加载失败: /vendor/globe/globe.gl.min.js'))
    document.head.appendChild(s)
  })
  loadPromise.catch(() => { loadPromise = null })
  return loadPromise
}

// ===== 实例 =====
let globe = null
let ro = null
function applyData() {
  if (!globe) return
  globe
    .pointsData(points.value)
    .pointLat('lat').pointLng('lng')
    .pointAltitude(0.01)
    .pointRadius((d) => (d.lv === 'high' ? 0.5 : d.lv === 'mid' ? 0.4 : 0.28))
    .pointColor((d) => LV_COLOR[d.lv] || LV_COLOR.low)
    .pointLabel((d) => `<div style="background:rgba(10,15,25,.92);padding:6px 10px;border-radius:6px;font-size:12px;border:1px solid rgba(56,189,248,.4)"><b>${d.name}</b><br/>数量 ${d.value}</div>`)
    .ringsData(rings.value)
    .ringLat('lat').ringLng('lng')
    .ringMaxRadius('maxR')
    .ringColor((d) => (t) => {
      const c = LV_COLOR[d.lv] || LV_COLOR.low
      return `${c}${Math.round((1 - t) * 200 + 20).toString(16).padStart(2, '0')}`
    })
    .ringAltitude(0.02)
    .ringRepeatPeriod(1200)
    .arcsData(arcs.value)
    .arcStartLat('startLat').arcStartLng('startLng')
    .arcEndLat('endLat').arcEndLng('endLng')
    .arcAltitude((a) => 0.12 + 0.3 * (a.count / Math.max(1, Math.max.apply(null, arcs.value.map(x => x.count).concat([1])))))
    .arcColor((a) => LV_COLOR[a.lv] || LV_COLOR.low)
    .arcStroke(0.6)
    .arcDashLength(0.4).arcDashGap(2.2).arcDashAnimateTime(3500)
}
function build() {
  if (!wrapEl.value || window.Globe === undefined) return
  const w = wrapEl.value.clientWidth || 520
  const h = Math.max(240, wrapEl.value.clientHeight || 320)
  globe = new window.Globe(wrapEl.value)
    .globeImageUrl(props.card.baseImage || '/vendor/globe/earth-blue-marble.jpg')
    .bumpImageUrl('/vendor/globe/earth-topology.png')
    .backgroundImageUrl('/vendor/globe/night-sky.png')
    .showAtmosphere(true)
    .atmosphereColor('#38bdf8')
    .atmosphereAltitude(0.2)
    .width(w).height(h)
  applyData()
  setRotate()
  if (window.ResizeObserver) {
    ro = new ResizeObserver(() => {
      if (!globe || !wrapEl.value) return
      globe.width(wrapEl.value.clientWidth || 520)
      globe.height(Math.max(240, wrapEl.value.clientHeight || 320))
    })
    ro.observe(wrapEl.value)
  }
  bindCtxEvents()
}

// ===== WebGL 上下文丢失兜底(2026-09-28) =====
// 浏览器在 GPU 切换/显存紧张/标签页久置后台时会主动丢弃上下文。默认行为是"丢弃后不恢复",
// 页面永久黑屏 —— 必须对 webglcontextlost 调 preventDefault(), 浏览器才会走恢复流程。
// 选中卡片不会触发重建(init 只在挂载/blocked 变化时调用), 这里只补"丢失→恢复"这一段。
let ctxEl = null
function onCtxLost(e) {
  e.preventDefault()               // 关键: 不阻止默认行为就永远等不到 restored
  state.value = 'error'
  errorMsg.value = 'WebGL 上下文丢失, 正在自动恢复…'
}
function onCtxRestored() {
  // three 的 WebGLRenderer 内部 onContextRestore 会重建 GL 状态, 这里只需收起提示并重喂数据
  state.value = 'ready'
  applyData()
}
function bindCtxEvents() {
  const el = (globe && globe.renderer && globe.renderer())
    ? globe.renderer().domElement
    : (wrapEl.value && wrapEl.value.querySelector('canvas'))
  if (!el) return
  ctxEl = el
  el.addEventListener('webglcontextlost', onCtxLost)
  el.addEventListener('webglcontextrestored', onCtxRestored)
}
function unbindCtxEvents() {
  if (!ctxEl) return
  ctxEl.removeEventListener('webglcontextlost', onCtxLost)
  ctxEl.removeEventListener('webglcontextrestored', onCtxRestored)
  ctxEl = null
}

// 编辑模式停自转: WebGL 常驻动画在编辑态纯属耗电, 也防止拖卡片时视角跟着转
function setRotate() {
  if (!globe || !globe.controls) return
  try {
    globe.controls().autoRotate = props.mode === 'browse'
    globe.controls().autoRotateSpeed = 0.45
  } catch (e) { /* 控件不可用时忽略 */ }
}

async function init() {
  if (blocked.value || props.side !== 'front') return
  try {
    await loadScript()
    build()
    state.value = 'ready'
  } catch (e) {
    state.value = 'error'
    errorMsg.value = (e && e.message) || '3D 资源加载失败'
  }
}
watch([points, arcs, rings], () => { if (state.value === 'ready') applyData() })
watch(() => props.mode, setRotate)
watch(blocked, (b) => { if (!b && state.value === 'loading') init() })

onMounted(init)
onBeforeUnmount(() => {
  if (ro) { ro.disconnect(); ro = null }
  unbindCtxEvents()
  if (globe) {
    try { globe.pointsData([]); globe.arcsData([]); globe.ringsData([]) } catch (e) { /* 忽略 */ }
    // globe.gl 的销毁是内部 API: 存在才调, 失败也必须继续清 DOM 释放 WebGL 上下文
    if (typeof globe._destructor === 'function') { try { globe._destructor() } catch (e) { /* 忽略 */ } }
    globe = null
  }
  if (wrapEl.value) wrapEl.value.innerHTML = ''
})
</script>

<style scoped>
.g3 { position: relative; width: 100%; height: 100%; overflow: hidden; }
.g3-canvas { position: absolute; inset: 0; }
.g3-canvas :deep(canvas) { display: block; }
.g3-mask {
  position: absolute; inset: 0; display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 6px; text-align: center;
  background: rgba(8, 12, 22, .6); color: #9fb0c8; font-size: 12.5px; padding: 12px;
}
.g3-tag { font-size: 11px; color: #38bdf8; border: 1px solid rgba(56, 189, 248, .4); padding: 2px 10px; border-radius: 999px; background: rgba(56, 189, 248, .08); }
.g3-hud {
  position: absolute; left: 10px; bottom: 8px; display: flex; align-items: center; gap: 10px;
  font-size: 11px; color: #9fb0c8; background: rgba(8, 12, 22, .6);
  border: 1px solid rgba(56, 189, 248, .22); border-radius: 8px; padding: 4px 10px;
}
.g3-hud span { display: flex; align-items: center; gap: 4px; }
.g3-hud i.d { width: 7px; height: 7px; border-radius: 50%; box-shadow: 0 0 6px currentColor; }
.g3-hud-num { color: #64748b; }
.g3-back { padding: 14px; display: flex; flex-direction: column; gap: 8px; font-size: 12px; }
.g3-back div { display: flex; justify-content: space-between; gap: 8px; }
.g3-back span { color: #8295b0; }
.g3-back b { color: #eaf1fb; font-weight: 600; }
</style>
