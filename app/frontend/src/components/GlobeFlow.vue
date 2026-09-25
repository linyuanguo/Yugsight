<!--
  GlobeFlow.vue 3D 地球 IP 流向(任务 10d 前端)。

  技术约束(任务书): Globe.gl + Three.js, 资源放 build/ 不打包进 Go 二进制。
  - 运行时经 /vendor/globe/*.js 动态加载(由 Go 端 handleGlobeFile 从 exe 同目录
    res/globe/ 直读), 不引入 npm 依赖 —— 守住"前端运行时仅 vue+vue-router"的零依赖约束;
  - 【只加载 globe.gl.min.js, 不单独加载 three.min.js】globe.gl 2.46.2 的 UMD
    是 self-contained 打包(内嵌 three ≥r165, 含 THREE.Timer), 且内部优先复用
    window.THREE —— 预载旧版 three(r15x 无 Timer)会让 new THREE.Timer 直接崩溃
    (真机冒烟实测 "s3.Timer is not a constructor"), 故 three.min.js 只留作
    资源位不加载, 用 globe 自带 three 即可;
  - 资源缺失/加载失败 → 降级为占位提示, 不报错不白屏(项目规则 3: 外部资源可选降级)。

  数据: props.flows = { center, arcs[], points[], stats, geoip } 来自 /api/dashboard/flows。
  弧线聚合到城市层级(后端已聚合), 前端只负责渲染。
-->
<template>
  <div class="globe-flow">
    <div ref="wrapEl" class="globe-canvas"></div>
    <!-- 资源加载中 -->
    <div v-if="state === 'loading'" class="globe-overlay">
      <span class="ph-tag">加载中</span>正在加载 3D 地球资源
    </div>
    <!-- 资源不可用(降级, 不报错) -->
    <div v-else-if="state === 'error'" class="globe-overlay">
      <span class="ph-tag">不可用</span>{{ errorMsg }}
      <span class="muted small">可在 settings.json 开启 geoip.enabled / dashboard.enabled 并重启</span>
    </div>
    <!-- 无数据(地球仍在自转作底, 上面盖占位) -->
    <div v-else-if="!hasData" class="globe-overlay">
      <span class="ph-tag">无数据</span>{{ emptyMsg }}
      <span class="muted small" v-if="geoipDisabled">IP 地理映射未开启(geoip.enabled=false)</span>
    </div>
    <!-- 时序回放(二期 14): 按天分帧播放, 看清流向随时间的变化 -->
    <div v-if="frames.length > 1" class="globe-playbar">
      <button class="pb-btn" @click="togglePlay">{{ playing ? '暂停' : '播放' }}</button>
      <input class="pb-range" type="range" min="0" :max="frames.length - 1" v-model.number="frameIdx" />
      <span class="pb-day mono">{{ curFrame ? curFrame.day : '' }}</span>
      <span class="pb-idx small muted">{{ frameIdx + 1 }}/{{ frames.length }}</span>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'

const props = defineProps({
  flows: { type: Object, default: () => null }, // {center,arcs,points,stats,geoip}
  // frames: 时序回放数据源(来自 /api/dashboard/flows?timeline=1), 可为空
  frames: { type: Array, default: () => [] }
})

// ===== 时序回放 =====
const frameIdx = ref(0)
const playing = ref(false)
let playTimer = null
const curFrame = computed(() => (props.frames.length ? props.frames[Math.min(frameIdx.value, props.frames.length - 1)] : null))

function stopPlay() {
  playing.value = false
  if (playTimer) { clearInterval(playTimer); playTimer = null }
}
function togglePlay() {
  if (playing.value) { stopPlay(); return }
  if (!props.frames.length) return
  playing.value = true
  if (frameIdx.value >= props.frames.length - 1) frameIdx.value = 0
  playTimer = setInterval(() => {
    if (frameIdx.value >= props.frames.length - 1) { stopPlay(); return } // 播到最后一帧停(不循环: 循环播放会让人以为数据在动)
    frameIdx.value++
  }, 1200)
}

const wrapEl = ref(null)
const state = ref('loading') // loading | ready | error
const errorMsg = ref('')
const emptyMsg = ref('暂无可定位的 IP 流向(扫描目标多为内网段或地理库未收录)')

const hasData = computed(() => {
  // 回放模式: 任意一帧有数据即算有(否则首帧为空会误盖"无数据"遮罩)
  if (props.frames && props.frames.length) {
    return props.frames.some(fr => (fr.arcs && fr.arcs.length) || (fr.points && fr.points.length))
  }
  const f = props.flows
  return !!(f && ((f.arcs && f.arcs.length) || (f.points && f.points.length)))
})
const geoipDisabled = computed(() => {
  const f = props.flows
  return !!(f && f.geoip && f.geoip.enabled === false)
})

// ===== 动态加载 globe.gl(self-contained, 内嵌 three) =====
// 模块级 promise: 多实例/重挂载只加载一次; 失败不缓存, 允许重试。
let loadPromise = null
function loadScripts() {
  if (loadPromise) return loadPromise
  loadPromise = new Promise((resolve, reject) => {
    const s = document.createElement('script')
    s.src = '/vendor/globe/globe.gl.min.js'
    s.onload = () => {
      if (!window.Globe) reject(new Error('globe.gl 未定义 Globe 全局'))
      else resolve()
    }
    s.onerror = () => reject(new Error('加载失败: /vendor/globe/globe.gl.min.js'))
    document.head.appendChild(s)
  })
  loadPromise.catch(() => { loadPromise = null })
  return loadPromise
}

// ===== Globe 实例 =====
let globe = null
let ro = null // ResizeObserver

function maxCount(arcs) {
  return Math.max(1, ...(arcs || []).map(a => a.count || 1))
}

// viewOf 当前应渲染的数据: 回放模式下取当前帧, 否则取总量聚合。
// 两种模式共用 center(总览的 center 由后端算出, 回放也用同一个视角, 避免播放时地球乱飞)。
function viewOf() {
  const f = props.flows || {}
  const fr = curFrame.value
  if (fr) {
    return { center: f.center, arcs: fr.arcs || [], points: fr.points || [] }
  }
  return { center: f.center, arcs: f.arcs || [], points: f.points || [] }
}

function applyData() {
  if (!globe) return
  const f = viewOf()
  globe
    .pointsData(f.points || [])
    .pointLat((d) => d.lat)
    .pointLng((d) => d.lon)
    .arcsData(f.arcs || [])
    .arcStartLat((a) => a.from.lat)
    .arcStartLng((a) => a.from.lon)
    .arcEndLat((a) => a.to.lat)
    .arcEndLng((a) => a.to.lon)
    .arcAltitude((a) => 0.15 + 0.35 * Math.min(1, (a.count || 1) / maxCount(f.arcs)))
  // 有中心则把视角飞过去, 无中心用默认
  const c = f.center
  if (c && (c.lat || c.lon)) {
    globe.pointOfView({ lat: c.lat, lng: c.lon, altitude: 1.6 }, 0)
  }
}

function buildGlobe() {
  if (!wrapEl.value || window.Globe === undefined) return
  const w = wrapEl.value.clientWidth || 600
  const h = Math.max(280, wrapEl.value.clientHeight || 340)
  globe = new window.Globe(wrapEl.value)
    .globeImageUrl('/vendor/globe/earth-blue-marble.jpg')
    .bumpImageUrl('/vendor/globe/earth-topology.png')
    .backgroundImageUrl('/vendor/globe/night-sky.png')
    .showAtmosphere(true)
    .atmosphereColor('#38bdf8')
    .atmosphereAltitude(0.18)
    .width(w)
    .height(h)
    .pointAltitude(0.02)
    .pointRadius(0.42)
    .pointColor(() => '#38bdf8')
    .pointLabel((d) => `<div style="background:rgba(10,15,25,.92);padding:6px 10px;border-radius:6px;font-size:12px;border:1px solid rgba(56,189,248,.4)"><b>${d.name || ''}</b><br/>流向 ${d.count || 0} 次</div>`)
    .arcColor(() => 'rgba(56,189,248,0.85)')
    .arcStroke(0.7) // 2.46.x 里线宽属性是 arcStroke(非 arcStrokeWidth, 链式调错会整条链崩)
    .arcDashLength(0.6)
    .arcDashGap(2.5)
    .arcDashAnimateTime(4000)
  applyData()
  // 缓慢自转: 大屏常驻展示感; 交互后 globe.gl 默认会暂停
  if (globe.controls) {
    globe.controls().autoRotate = true
    globe.controls().autoRotateSpeed = 0.4
  }
  if (window.ResizeObserver) {
    ro = new ResizeObserver(() => {
      if (!globe || !wrapEl.value) return
      globe.width(wrapEl.value.clientWidth || 600)
      globe.height(Math.max(280, wrapEl.value.clientHeight || 340))
    })
    ro.observe(wrapEl.value)
  }
}

async function init() {
  try {
    await loadScripts()
    buildGlobe()
    state.value = 'ready'
  } catch (e) {
    state.value = 'error'
    errorMsg.value = (e && e.message) || '3D 资源加载失败'
  }
}

// 数据变化: 资源已就绪则即时刷新; 空态与有态的切换由 hasData 计算属性驱动(无需改 state)
watch(() => props.flows, () => {
  if (state.value === 'ready' && globe && !curFrame.value) applyData()
})
// 回放: 帧变化即重绘(拖动进度条与自动播放走同一条路径)
watch(frameIdx, () => {
  if (state.value === 'ready' && globe) applyData()
})
watch(() => props.frames, (v) => {
  stopPlay()
  frameIdx.value = v && v.length ? v.length - 1 : 0 // 默认停在最新一天, 点播放才从头开始
})

onMounted(() => { init() })

onBeforeUnmount(() => {
  stopPlay()
  if (ro) { ro.disconnect(); ro = null }
  globe = null
})
</script>

<style scoped>
.globe-flow { position: relative; width: 100%; height: 100%; min-height: 300px; }
.globe-canvas { width: 100%; height: 100%; min-height: 300px; }
.globe-canvas :deep(canvas) { display: block; border-radius: 8px; }
.globe-overlay {
  position: absolute; inset: 0; display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 8px;
  background: rgba(8, 12, 22, .55); border-radius: 8px;
  color: var(--muted); font-size: 13px; text-align: center; padding: 16px;
}
.globe-overlay .ph-tag {
  font-size: 11px; color: var(--accent); border: 1px solid rgba(56, 189, 248, .4);
  padding: 2px 10px; border-radius: 999px; background: rgba(56, 189, 248, .08);
}
.globe-overlay .small { font-size: 11px; }
/* 时序回放控制条 */
.globe-playbar {
  position: absolute; left: 8px; right: 8px; bottom: 8px;
  display: flex; align-items: center; gap: 8px;
  background: rgba(8, 12, 22, .72); border: 1px solid rgba(56, 189, 248, .25);
  border-radius: 8px; padding: 6px 10px; font-size: 12px;
}
.pb-btn {
  background: rgba(56, 189, 248, .16); border: 1px solid rgba(56, 189, 248, .45);
  color: var(--accent); border-radius: 6px; padding: 3px 12px; cursor: pointer; font-size: 12px;
}
.pb-range { flex: 1; accent-color: #38bdf8; }
.pb-day { color: var(--text); }
.pb-idx { white-space: nowrap; }
</style>
