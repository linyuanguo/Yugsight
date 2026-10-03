<template>
  <!-- 安全大屏 Pro(2026-09-27): 套 Layout 外壳的站内页(保留左菜单/顶栏),
       画布占满内容区; 真正浏览器全屏由「一键全屏」按钮触发(投屏场景)。
       与仪表盘内嵌的「安全大屏」Tab2 是两回事: 这里是独立一级菜单入口。
       本步在画布上接入通用 3D 卡片体系(漏扫任务卡/统计汇总卡/标题卡),
       支持双模式 · 拖拽缩放 · 右键菜单 · 层级调整 · 布局持久化。 -->
  <div class="bpro" ref="rootEl">
    <!-- 画布底层: 全屏自由画布(卡片载体, 设计坐标系 1920×1080) -->
    <!-- 框选/批量的事件放在**捕获阶段**: 需要在卡片自己的 onDown 之前决定是"框选/批量拖"
         还是"单卡拖拽"; 捕获期 stopPropagation 就能让卡片完全收不到这次事件 -->
    <div class="bpro-stage" ref="stageElRef" :class="{ fadein: tplFade }"
         @pointerdown.capture="onStageDownCapture" @contextmenu.capture="onStageCtxCapture">
    <FreeCanvas :mode="mode" :empty="cards.length === 0">
      <!-- 框选框(在画布内部, 直接吃 FreeCanvas 的 translate+scale, 坐标即设计坐标) -->
      <div v-if="marquee" class="bpro-marquee" :style="marqueeStyle"></div>
      <CanvasCard v-for="c in visibleCards" :key="c.id" :card="c" :mode="mode"
        :selected="selId === c.id || selIds.includes(c.id)"
        @select="onCardSelect(c.id)" @patch="patchCard(c.id, $event)" @flip="flipCard(c.id)"
        @remove="removeCard(c.id)" @bring-front="bringFront(c.id)" @send-back="sendBack(c.id)" @edit="editCard(c.id)">
        <template #front>
          <component :is="comp(c.type)" :card="c" :compact="compactOf(c)" :mode="mode" side="front" />
        </template>
        <template #back>
          <component :is="comp(c.type)" :card="c" :compact="compactOf(c)" :mode="mode" side="back" />
        </template>
      </CanvasCard>
    </FreeCanvas>
    </div>

    <!-- 右上角悬浮控制栏: 双模式开关 / 一键全屏 / 布局模板切换 / 新建卡片(编辑态) -->
    <div class="bpro-ctrl" :class="{ hidden: ctrlHidden }">
      <div class="bpro-mode" :title="mode === 'browse' ? t('bpro.modeEditTitle') : t('bpro.modeBrowseTitle')">
        <button type="button" :class="{ on: mode === 'browse' }" @click="setMode('browse')">{{ t('bpro.modeBrowse') }}</button>
        <button type="button" :class="{ on: mode === 'edit' }" @click="setMode('edit')">{{ t('bpro.modeEdit') }}</button>
      </div>
      <button type="button" class="bpro-btn" :title="isFullscreen ? t('bpro.exitFullscreen') : t('bpro.fullscreenHint')" @click="toggleFullscreen">
        {{ isFullscreen ? t('bpro.exitFullscreen') : t('bpro.fullscreen') }}
      </button>
      <!-- 模板下拉: 内置模板 / 我的自定义模板(只改几何与显隐, 不重建组件实例) -->
      <div class="bpro-new">
        <button type="button" class="bpro-btn" @click.stop="tplOpen = !tplOpen">{{ t('bpro.tplLabel') }}: {{ curTplName }}</button>
        <div class="bpro-new-menu" v-if="tplOpen" @click.stop>
          <div class="ni-group">{{ t('bpro.builtinTpls') }}</div>
          <button v-for="tpl in BUILTIN" :key="tpl.id" type="button" @click="applyTpl(tpl.id)">
            <span class="ni">▤</span><span class="ni-t">{{ t(tpl.name) }}</span>
            <span class="ni-tag">{{ t(tpl.scene) }}</span>
          </button>
          <template v-if="userTpls.length">
            <div class="ni-group">{{ t('bpro.myTpls') }}</div>
            <button v-for="tpl in userTpls" :key="tpl.id" type="button" @click="applyTpl(tpl.id)">
              <span class="ni">★</span><span class="ni-t">{{ tpl.name }}</span>
              <span class="ni-del" @click.stop="renameTplOf(tpl)">{{ t('bpro.rename') }}</span>
              <span class="ni-del" @click.stop="delTplOf(tpl)">×</span>
            </button>
          </template>
          <div class="ni-group">{{ t('bpro.manage') }}</div>
          <button type="button" @click="saveAsTpl"><span class="ni">＋</span>{{ t('bpro.saveAsLayout') }}</button>
          <button type="button" @click="exportTplOf"><span class="ni">⤓</span>{{ t('bpro.exportTpl') }}</button>
          <button type="button" @click="importTplOf"><span class="ni">⤒</span>{{ t('bpro.importTpl') }}</button>
          <button type="button" @click="applyTpl('tpl_overview')"><span class="ni">↺</span>{{ t('bpro.resetOverview') }}</button>
        </div>
      </div>
      <!-- 保存布局(2026-09-29 用户要求: 布局保存按钮要显眼、一点就存) -->
      <button type="button" class="bpro-btn" :title="t('bpro.saveLayoutTitle')" @click="saveAsTpl">{{ t('bpro.saveLayout') }}</button>
      <!-- 新建组件(仅编辑态): 按 基础/统计/图表/高级 分组 + 我的模板 -->
      <div class="bpro-new" v-if="mode === 'edit'">
        <button type="button" class="bpro-btn" @click.stop="newOpen = !newOpen">+ {{ t('bpro.newCard') }}</button>
        <div class="bpro-new-menu" v-if="newOpen" @click.stop>
          <template v-for="g in TYPE_GROUPS" :key="g.k">
            <div class="ni-group">{{ t(g.t) }}</div>
            <button v-for="k in typesOf(g.k)" :key="k" type="button" @click="addCard(k)">
              <span class="ni">{{ CARD_TYPES[k].icon }}</span>{{ t(CARD_TYPES[k].label) }}
            </button>
          </template>
          <template v-if="tpls.length">
            <div class="ni-group">{{ t('bpro.myTpls') }}</div>
            <button v-for="tp in tpls" :key="tp.id" type="button" @click.stop="addFromTpl(tp)">
              <span class="ni">★</span><span class="ni-t">{{ tp.name }}</span>
              <span class="ni-del" @click.stop="delTpl(tp)">×</span>
            </button>
          </template>
        </div>
      </div>
    </div>

    <!-- 右侧属性面板(编辑态选中组件时弹出): 数据源字段 / 图表类型 / 颜色 / 显示范围 / 几何 -->
    <!-- 2026-09-28: 面板只编辑卡片级对象 —— 旧拓扑模块的节点/链路选中通道(topoSel)
         已随"彻底删除原有网络拓扑模块"一并移除, 3D 拓扑第三阶段重新对接时再扩展。 -->
    <div class="bpro-panel" v-if="mode === 'edit' && panelTarget" @pointerdown.stop @click.stop>
      <div class="bp-head">
        <span>{{ panelTitle }}</span>
        <button type="button" class="bp-x" @click="clearSelAll">×</button>
      </div>
      <div class="bp-body">
        <label v-for="f in panelFields" :key="f.k">
          <span>{{ t(f.l) }}<i v-if="isRo(f)" class="bp-ro">{{ t('bpro.monitorSync') }}</i></span>
          <input v-if="f.t === 'text'" :disabled="isRo(f)" :value="panelTarget[f.k]" @input="setField(f, $event.target.value)" />
          <input v-else-if="f.t === 'number'" type="number" :disabled="isRo(f)" :value="panelTarget[f.k]" @input="setField(f, Number($event.target.value))" />
          <select v-else-if="f.t === 'select'" :disabled="isRo(f)" :value="String(panelTarget[f.k])" @change="setField(f, castSel(f, $event.target.value))">
            <option v-for="o in optsFor(f)" :key="String(o.v)" :value="String(o.v)">{{ t(o.t) }}</option>
          </select>
          <textarea v-else-if="f.t === 'textarea'" rows="3" :value="panelTarget[f.k]" @input="setField(f, $event.target.value)"></textarea>
        </label>
        <div v-if="!panelFields.length" class="bp-none">{{ t('bpro.noFields') }}</div>
        <!-- 旧拓扑模块的"告警设置"分组(PushStatusPanel)与拓扑对象选中分支已一并删除:
             面板现在只编辑卡片, 不再有 selObj 互斥分支(3D 拓扑第三阶段对接时再扩展)。 -->
        <div class="bp-sep">{{ t('bpro.geoSep') }}</div>
        <label v-for="g in GEO" :key="g.k" class="bp-geo">
          <span>{{ t(g.l) }}</span>
          <input type="number" :value="panelTarget[g.k]" @input="setField(g, Number($event.target.value))" />
        </label>
      </div>
      <div class="bp-foot">
        <input class="bp-tplname" v-model="tplName" :placeholder="t('bpro.tplNamePh')" />
        <!-- 2026-09-29: 此按钮存的是"选中的这张卡"为可复用组件模板, 不是整屏布局 —— 改名避免与
             控制栏「保存布局」混淆(布局模板走 saveAsTpl, 组件模板走 saveTpl) -->
        <button type="button" @click="saveTpl">{{ t('bpro.saveAsCardTpl') }}</button>
        <button type="button" class="danger" @click="removeCard(sel.id)">{{ t('bpro.del') }}</button>
      </div>
    </div>

    <!-- 批量右键菜单(选中 2 个以上时出现; 单项仍用卡片自带菜单) -->
    <Teleport to="body">
      <div v-if="batchMenu" class="bpro-batch" :style="batchMenuStyle" @pointerdown.stop @click.stop>
        <div class="bb-h">{{ t('bpro.batchOps', { n: selIds.length }) }}</div>
        <button v-for="a in BATCH_ACTIONS" :key="a.k" type="button" :class="{ danger: a.danger }" @click="applyBatch(a.k)">{{ t(a.t) }}</button>
      </div>
    </Teleport>

    <!-- 轮播控制条(浏览模式): 上下切 + 播放/暂停 + 间隔档位 + 轮播设置 -->
    <div class="bpro-carousel" v-if="mode === 'browse'">
      <button type="button" @click="carousel && carousel.prev()">‹</button>
      <button type="button" @click="togglePlay">{{ playing ? t('bpro.pause') : t('bpro.play') }}</button>
      <button type="button" @click="carousel && carousel.next()">›</button>
      <select :value="carIntervalSel" @change="onIntervalChange" :title="t('bpro.carIntervalTitle')">
        <option v-for="i in INTERVALS" :key="i.v" :value="i.v">{{ t(i.t) }}</option>
        <option value="custom">{{ t('bpro.custom') }}</option>
      </select>
      <button type="button" @click="carOpen = !carOpen">{{ t('bpro.carSettings') }}</button>
      <span class="bc-idx">{{ carouselIdx + 1 }}/{{ carouselList.length }}</span>
      <span class="bc-state" v-if="!playing">{{ t('bpro.paused') }}</span>
    </div>
    <!-- 轮播设置面板(浏览模式): 勾选参与轮播的模板 + 自定义间隔 -->
    <div class="bpro-carousel-set" v-if="mode === 'browse' && carOpen">
      <div class="bcs-h">{{ t('bpro.carTplLabel') }} <span class="bcs-hint">{{ t('bpro.carMinHint') }}</span></div>
      <label v-for="cp in carCandidates" :key="cp.id" class="bcs-item">
        <input type="checkbox" :checked="isCarChecked(cp.id)" @change="toggleCarCheck(cp.id, $event.target.checked)" />
        <span class="bcs-name">{{ cp.name }}</span>
        <span class="bcs-tag">{{ cp.builtin ? t('bpro.builtin') : t('bpro.custom') }}</span>
      </label>
      <div v-if="!carCandidates.length" class="bcs-empty">{{ t('bpro.noLayoutTpl') }}</div>
      <div class="bcs-foot">
        <label class="bcs-int">{{ t('bpro.interval') }}
          <input type="number" min="5" max="3600" :value="carInterval" @change="onCustomInterval" /> {{ t('bpro.sec') }}
        </label>
        <span class="bcs-count">{{ t('bpro.carCount', { n: carouselList.length }) }}</span>
        <button type="button" @click="carOpen = false">{{ t('bpro.done') }}</button>
      </div>
    </div>

    <!-- 编辑辅助(2026-09-29: 可拖动 + 可显隐): 网格吸附 + 撤销/恢复。
         拖动把手(⠿)改位置, ✕ 隐藏(左下角"工具"按钮呼回), 位置/显隐持久化到 localStorage -->
    <div class="bpro-tools" v-if="mode === 'edit' && !toolsHidden" ref="toolsEl" :style="toolsStyle">
      <span class="bpro-tools-handle" title="拖动调整工具栏位置" @pointerdown.stop="startToolsDrag">⠿</span>
      <label>{{ t('bpro.grid') }}
        <select :value="grid" @change="grid = Number($event.target.value)">
          <option :value="1">{{ t('bpro.gridOff') }}</option><option :value="8">8px</option>
          <option :value="16">16px</option><option :value="24">24px</option>
        </select>
      </label>
      <button type="button" :disabled="!canUndo" @click="undo">{{ t('bpro.undo') }}</button>
      <button type="button" :disabled="!canRedo" @click="redo">{{ t('bpro.redo') }}</button>
      <button type="button" class="bpro-tools-hide" :title="t('bpro.hideTools')" @click="toggleToolsHidden">✕</button>
    </div>
    <!-- 工具栏被隐藏时的呼出入口(左下角) -->
    <button v-if="mode === 'edit' && toolsHidden" type="button" class="bpro-tools-restore" :title="t('bpro.showTools')" @click="toggleToolsHidden">{{ t('bpro.tools') }}</button>

    <!-- 底部悬浮: 恢复默认布局 -->
    <div class="bpro-foot">
      <button type="button" class="bpro-reset" @click="resetLayout">{{ t('bpro.resetLayout') }}</button>
      <span class="bpro-done" v-if="resetTip">{{ t('bpro.resetDone') }}</span>
      <span class="bpro-warn" v-if="warn">{{ warn }}</span>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, provide, inject, watch, onMounted, onBeforeUnmount } from 'vue'
import FreeCanvas from '../components/FreeCanvas.vue'
import CanvasCard from '../components/cards/CanvasCard.vue'
import { t } from '../i18n'
import {
  CARD_TYPES, TYPE_GROUPS, CONTENT_COMP, CFG, defaultCards, uid, BATCH_ACTIONS,
  makeScan, makeStat, makeTitle, makeNode, makeTaskList,
  makeMetric, makeRatio, makeStatusCard, makeVulnLevel, makeTrend,
  makeTaskBars, makeAssetPie, makeAlertTop, makeRoller, makeGlobe,
} from '../components/cards/types.js'

// 2026-09-27 安全大屏 Pro 卡片体系接入: 画布内卡片数组 + 双模式 + 布局持久化。
// 后续步骤: 卡片属性编辑面板、更多卡片类型、轮播/告警等。

const rootEl = ref(null)
const isFullscreen = ref(false)
let fsHandler = null

// ===== 画布卡片数据(持久化到 localStorage; 首次用默认布局) =====
const cards = ref(loadCards())
function loadCards() {
  try {
    const raw = localStorage.getItem('yugsight_bpro_cards')
    if (raw) { const a = JSON.parse(raw); if (Array.isArray(a) && a.length) return a }
  } catch (e) { /* 解析失败回退默认 */ }
  return defaultCards()
}
// 供内容组件(如统计汇总卡)实时聚合画布内卡片
provide('bproCards', cards)
// 2026-09-28: 旧网络拓扑模块已整体删除 —— 卡片内 3D 拓扑、拓扑缩略入口卡、
// topoFocus / topoActive / bproTopoSel 三条通道全部移除, 不留悬空订阅者。
// 2026-09-29: 拓扑以"卡片"形态回归 —— TopoCard(components/cards, 复用 components/topo3d
// 场景组件 + 独立页 /topology/3d)进默认布局, 一级菜单/节点监控入口移除, 大屏卡为唯一入口。
// 防抖落盘, 避免拖拽过程频繁写
let saveT = null
watch(cards, () => {
  if (saveT) clearTimeout(saveT)
  saveT = setTimeout(() => {
    try { localStorage.setItem('yugsight_bpro_cards', JSON.stringify(cards.value)) } catch (e) { /* 忽略 */ }
  }, 300)
}, { deep: true })

const selId = ref(null)
// 模板的"显隐"只影响渲染, 实例与数据保留在 cards 里(切回模板立刻复原)
const visibleCards = computed(() => cards.value.filter(c => !c.hidden))

// 缩略态: 卡片被缩到阈值以下 → 仅显示标题+状态(放大自动展开)
function compactOf(c) { return c.w < 300 || c.h < 170 }
function comp(type) { return CONTENT_COMP[type] || CONTENT_COMP.scan }
function typesOf(g) { return Object.keys(CARD_TYPES).filter(k => CARD_TYPES[k].group === g) }

// ===== 属性面板(编辑态): 字段表来自 CFG, 新增组件类型不必改本页 =====
const sel = computed(() => cards.value.find(c => c.id === selId.value) || null)
const fields = computed(() => (sel.value && CFG[sel.value.type]) ? CFG[sel.value.type] : [])
// l 是词条键(X/Y 语言无关, 面板渲染期 t() 回退原样)
const GEO = [{ k: 'x', l: 'X' }, { k: 'y', l: 'Y' }, { k: 'w', l: 'bpro.geoW' }, { k: 'h', l: 'bpro.geoH' }]
function setField(f, v) { if (sel.value) patchCard(sel.value.id, { [f.k]: v }) }
// 下拉 option 的 value 一律转字符串(避开 Vue 数字/布尔绑定差异), 回写时按原值还原
function castSel(f, val) {
  const o = (f.o || []).find(x => String(x.v) === val)
  return o ? o.v : val
}
function optsFor(f) { return f.o || [] }
// 只读字段判定(2026-09-28 修复): 模板第 93-96 行依赖本函数, 但它随"卡片内拓扑"一起被删除后
// 一直没补回来 —— 编辑模式点卡片 → 面板渲染 → 调用未定义的 isRo → 抛 ReferenceError,
// Vue 把整个页面组件的渲染结果替换成空注释节点(只剩深色画布底, 观感"一片黑")。
// 判定规则保持原语义: 字段表(CFG)里显式标 ro:true 的字段才置灰并显示「监控同步」。
// 当前面板只编辑卡片级对象, 没有任何字段标 ro, 故恒 false。
function isRo(f) { return !!(f && f.ro) }
// 面板只编辑"卡片级"对象(旧拓扑模块的节点/链路选中通道已整体删除)
const panelTarget = computed(() => sel.value)
const panelFields = computed(() => (sel.value ? (CFG[sel.value.type] || []) : []))
const panelTitle = computed(() => (sel.value ? t((CARD_TYPES[sel.value.type] && CARD_TYPES[sel.value.type].label) || 'bpro.newCard') : t('bpro.newCard')))
function clearSelAll() { selId.value = null }
// ===== 组件模板: 把配置好的卡片存起来复用 =====
const TPL_KEY = 'yugsight_bpro_tpls'
const tpls = ref(loadTpls())
const tplName = ref('')
function loadTpls() {
  try { const a = JSON.parse(localStorage.getItem(TPL_KEY) || '[]'); return Array.isArray(a) ? a : [] } catch (e) { return [] }
}
function persistTpls() { try { localStorage.setItem(TPL_KEY, JSON.stringify(tpls.value)) } catch (e) { /* 忽略 */ } }
function saveTpl() {
  const c = sel.value
  if (!c) return
  const name = (tplName.value || '').trim() || (CARD_TYPES[c.type] && CARD_TYPES[c.type].label) || '模板'
  const cfg = JSON.parse(JSON.stringify(c))
  delete cfg.id
  tpls.value = tpls.value.concat([{ id: uid('t'), name, type: c.type, cfg }])
  persistTpls()
  tplName.value = ''
}
function delTpl(t) { tpls.value = tpls.value.filter(x => x.id !== t.id); persistTpls() }
function addFromTpl(t) {
  newOpen.value = false
  const c = JSON.parse(JSON.stringify(t.cfg || {}))
  c.id = uid('c'); c.z = maxZ() + 1
  c.x = (c.x || 120) + 24; c.y = (c.y || 120) + 24
  cards.value.push(c)
  selId.value = c.id
}

const warn = ref('')
let warnT = null
function flashWarn(s) {
  warn.value = s
  if (warnT) clearTimeout(warnT)
  warnT = setTimeout(() => { warn.value = '' }, 2600)
}

// ===== 双模式 =====
const mode = ref(readModeLS())
function readModeLS() {
  try { return localStorage.getItem('yugsight_bpro_mode') === 'edit' ? 'edit' : 'browse' } catch (e) { return 'browse' }
}
function setMode(m) {
  mode.value = m
  try { localStorage.setItem('yugsight_bpro_mode', m) } catch (e) { /* 忽略 */ }
  if (m === 'browse') newOpen.value = false
}

// ===== 布局模板体系(只改几何/显隐/少量配置, 不重建组件实例) =====
// 注意: 本页已有"组件模板"(saveTpl/delTpl/renameTpl)与"布局模板"两套概念,
// 因此布局模板的函数一律带 Layout 前缀别名, 避免同名覆盖掉组件模板那套。
import {
  BUILTIN, findTpl, applyLayout, snapshotLayout,
  saveTpl as saveLayoutTpl, renameTpl as renameLayoutTpl, delTpl as delLayoutTpl,
  setCur, getCur, exportTpl, importTpl,
} from '../components/bigscreen/TemplateManager.js'
import { createCarousel, INTERVALS, loadCarCfg, saveCarCfg } from '../components/bigscreen/CarouselController.js'
import { useShared, shared } from '../components/cards/dashData.js'
import { enterFullscreen, setFsIntent, scheduleFullscreenRestore } from '../fullscreen.js'
useShared() // 本页也挂上共享轮询(告警联动需要 overview)

const tplOpen = ref(false)
const curTpl = ref(getCur() || 'tpl_overview')
const userTpls = ref(loadUserTpls())
const tplFade = ref(false)   // 切换后短挂一次"淡入"(只过渡 opacity, 不做位移过渡)
let fadeT = null
function loadUserTpls() {
  try {
    const a = JSON.parse(localStorage.getItem('yugsight_bpro_tpls') || '[]')
    return Array.isArray(a) ? a : []
  } catch (e) { return [] }
}
const curTplName = computed(() => {
  // 内置模板 name 是词条键, t() 解析; 用户模板自由名非键 → 原样返回
  const tpl = findTpl(curTpl.value)
  return tpl ? t(tpl.name) : t('bpro.tplOverview')
})

// 切换: 先重置后应用 —— 撤过渡类让所有卡**瞬时**落到目标几何/显隐(无位移插值,
// 不会飞行/相撞), 落位完成后再挂 fadein 类播一次淡入(只过渡 opacity), 结束即撤。
// 不再用 0.9s 位移过渡: 快速切换时卡片会"飞行中再被改目标" → 布局错乱。
function applyTpl(id, quiet) {
  const tpl = findTpl(id)
  if (!tpl) return
  pushHistory()
  curTpl.value = id
  setCur(id)
  clearSelection()   // 切模板即清空选中(模板换了布局, 旧选中集合已无意义)
  tplFade.value = false
  applyLayout(cards.value, tpl.layout)
  requestAnimationFrame(() => {
    tplFade.value = true
    if (fadeT) clearTimeout(fadeT)
    fadeT = setTimeout(() => { tplFade.value = false }, 520)
  })
  tplOpen.value = false
  if (!quiet) flashWarn(t('bpro.switchedTpl', { name: t(tpl.name) }))
}
function saveAsTpl() {
  const name = (tplName.value || '').trim() || window.prompt(t('bpro.tplNamePrompt'), t('bpro.myTpls'))
  if (!name) return
  const list = saveLayoutTpl(name, t('bpro.custom'), snapshotLayout(cards.value))
  userTpls.value = list
  const nt = list[list.length - 1]
  if (nt) carAddTpl(nt.id)   // 新模板默认参与轮播
  tplName.value = ''
  tplOpen.value = false
  flashWarn(t('bpro.savedTpl', { name }))
}
function renameTplOf(tp) {
  const name = window.prompt(t('bpro.renamePrompt'), tp.name)
  if (!name) return
  userTpls.value = renameLayoutTpl(tp.id, name)
  syncTpl()
}
function delTplOf(tp) { userTpls.value = delLayoutTpl(tp.id); carRemoveTpl(tp.id); syncTpl() }
function syncTpl() {
  userTpls.value = loadUserTpls()
  if (carousel) carousel.setIndex(indexOfTpl(curTpl.value))
}
function exportTplOf() {
  const tpl = findTpl(curTpl.value)
  if (!tpl) return
  const blob = new Blob([exportTpl(tpl)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  // 文件名用解析后的显示名(内置模板 name 是词条键, 不能直接进文件名)
  a.download = (t(tpl.name) || 'template') + '.json'
  a.click()
  URL.revokeObjectURL(a.href)
}
function importTplOf() {
  const text = window.prompt(t('bpro.pasteTplJson'))
  if (!text) return
  try {
    const list = importTpl(text)
    userTpls.value = list
    const nt = list[list.length - 1]
    if (nt) carAddTpl(nt.id)
    flashWarn(t('bpro.tplImported')); syncTpl()
  }
  catch (e) { flashWarn(t('bpro.importFail', { err: e.message || t('bpro.jsonParseErr') })) }
}

// ===== 轮播(候选池 = "勾选参与轮播"的布局模板; 至少 2 个才能自动播放) =====
// 配置持久化 key yugsight_bpro_carousel = { ids: [参与轮播的模板ID], interval: 秒 }
const carChecked = ref(loadCarChecked())   // { [id]: true }; null=未配置(默认全部参与)
const carInterval = ref(loadCarInterval())
const carOpen = ref(false)                // "轮播设置"面板开关
const playing = ref(false)
const carouselIdx = ref(0)
// 内置 + 自定义(reactive: userTpls 变化即重算, 增删模板后候选池自动更新)
const allTplList = computed(() => BUILTIN.concat(userTpls.value))
// 只含"布局模板"(组件模板无 layout 字段, 排除, 避免轮播切到无布局的卡模板)
const carCandidates = computed(() => allTplList.value.filter(t => t && t.layout))
function isCarChecked(id) { return !carChecked.value || !!carChecked.value[id] }
const carouselList = computed(() => carCandidates.value.filter(t => isCarChecked(t.id)))
function loadCarChecked() {
  const c = loadCarCfg()
  if (c && Array.isArray(c.ids)) return Object.fromEntries(c.ids.map(id => [id, true]))
  return null
}
function loadCarInterval() {
  const c = loadCarCfg()
  return (c && Number(c.interval) > 0) ? Number(c.interval) : 60
}
function persistCar() {
  saveCarCfg({ ids: carCandidates.value.filter(t => isCarChecked(t.id)).map(t => t.id), interval: carInterval.value })
}
function toggleCarCheck(id, checked) {
  if (!carChecked.value) carChecked.value = {}
  carChecked.value[id] = checked
  persistCar()
  if (carouselList.value.length < 2) carousel.hold('pool')
  else carousel.release('pool')
}
function onIntervalChange(e) {
  const v = e.target.value
  if (v === 'custom') { carOpen.value = true; return }   // 自定义 → 打开面板输入秒数
  carInterval.value = Number(v)
  persistCar()
  carousel.release('manual'); carousel.start()
}
function onCustomInterval(v) {
  let n = Math.round(Number(v))
  if (!isFinite(n) || n < 5) n = 5
  if (n > 3600) n = 3600
  carInterval.value = n
  persistCar()
  carousel.release('manual'); carousel.start()
}
const carIntervalSel = computed(() => INTERVALS.some(i => i.v === carInterval.value) ? carInterval.value : 'custom')
function indexOfTpl(id) { const i = carouselList.value.findIndex(t => t.id === id); return i < 0 ? 0 : i }
const carousel = createCarousel({
  getList: () => carouselList.value,
  onSwitch: (id) => applyTpl(id, true),
  getInterval: () => carInterval.value,
  canPlay: () => mode.value === 'browse',
  onState: (s) => {
    playing.value = !!s.playing && !s.reason
    carouselIdx.value = s.idx
  },
})
function togglePlay() {
  if (playing.value) { carousel.hold('manual'); return }
  if (carouselList.value.length < 2) { flashWarn(t('bpro.need2Tpl')); carOpen.value = true; return }
  carousel.release('manual'); carousel.start()
}
// 增删模板后: 同步轮播勾选(新增默认参与, 删除移除), 候选池随之更新
function carAddTpl(id) {
  if (!carChecked.value) carChecked.value = {}
  carChecked.value[id] = true
  persistCar()
}
function carRemoveTpl(id) {
  if (carChecked.value) {
    const m = { ...carChecked.value }; delete m[id]; carChecked.value = m; persistCar()
  }
}
// 候选池变化时: 少于 2 个必须停(校验), 恢复后放行
watch(carouselList, (l) => { if (l.length < 2) carousel.hold('pool'); else carousel.release('pool') })
function onStageTouch() { if (mode.value === 'browse') carousel.touch(30000) }

// 高危告警联动: 出现严重漏洞 → 切到攻击态势模板并暂停轮播(停下来让人看清楚)
watch(() => shared.updatedAt, () => {
  const c = (shared.ov && shared.ov.overview && shared.ov.overview.vulns && shared.ov.overview.vulns.critical) || 0
  if (c > 0) {
    carousel.hold('alert')
    if (curTpl.value !== 'tpl_attack') { applyTpl('tpl_attack', true); flashWarn(t('bpro.alertSwitch')) }
  } else {
    carousel.release('alert')
  }
})

// ===== 卡片操作 =====
// ===== 框选 / 批量操作(仅编辑模式) =====
// 画布缩放比(来自 FreeCanvas): 屏幕位移 ÷ scale = 设计坐标系位移
const canvasScale = inject('canvasScale', ref(1))
const stageElRef = ref(null)
const selIds = ref([])                 // 批量选中集合(与单选 selId 并存, 单选优先用于属性面板)
const marquee = ref(null)              // {x,y,w,h} 设计坐标
const batchMenu = ref(null)            // {x,y} 屏幕坐标
const CANVAS_W = 1920, CANVAS_H = 1080

function toDesign(e) {
  const el = stageElRef.value
  if (!el) return { x: 0, y: 0 }
  const r = el.getBoundingClientRect()
  const s = canvasScale.value || 1
  // rect 已包含 FreeCanvas 的 letterbox 平移, 除以缩放即得到设计坐标
  return { x: (e.clientX - r.left) / s, y: (e.clientY - r.top) / s }
}
function cardIdAt(e) {
  const el = e.target && e.target.closest ? e.target.closest('[data-cid]') : null
  return el ? el.getAttribute('data-cid') : null
}
function toggleSel(id) {
  selIds.value = selIds.value.includes(id) ? selIds.value.filter(x => x !== id) : selIds.value.concat([id])
}
function clearSelection() { selIds.value = []; selId.value = null; batchMenu.value = null }
// 单卡选中: 点未参与多选的卡时清掉批量集合, 避免"多选残留 + 单选"两套高亮同时亮
function onCardSelect(id) {
  selId.value = id
  if (!selIds.value.includes(id)) selIds.value = []
}

// 捕获阶段: 决定这次按下是 ①Shift 加减选 ②批量拖拽 ③空白处框选 ④交给单卡自己处理
function onStageDownCapture(e) {
  if (mode.value !== 'edit') return
  if (e.button !== 0) return
  const id = cardIdAt(e)
  if (id && e.shiftKey) { toggleSel(id); e.stopPropagation(); return }
  if (id && selIds.value.length > 1 && selIds.value.includes(id)) { startBatchDrag(e, id); e.stopPropagation(); return }
  if (!id) { clearSelection(); startMarquee(e) }
}
const marqueeStyle = computed(() => {
  const m = marquee.value
  return m ? { left: m.x + 'px', top: m.y + 'px', width: m.w + 'px', height: m.h + 'px' } : {}
})
const batchMenuStyle = computed(() => (batchMenu.value
  ? { left: batchMenu.value.x + 'px', top: batchMenu.value.y + 'px' } : {}))

function startMarquee(e) {
  const p = toDesign(e)
  marquee.value = { x: p.x, y: p.y, w: 0, h: 0 }
  function mv(ev) {
    const q = toDesign(ev)
    marquee.value = { x: Math.min(p.x, q.x), y: Math.min(p.y, q.y), w: Math.abs(q.x - p.x), h: Math.abs(q.y - p.y) }
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    const m = marquee.value
    marquee.value = null
    if (!m || m.w < 6 || m.h < 6) return   // 只是点一下, 不算框选
    // 规则: **完全包含**才选中(相交即选会在拖动大框时误选一堆无关元素)
    selIds.value = visibleCards.value
      .filter(c => c.x >= m.x && c.y >= m.y && c.x + c.w <= m.x + m.w && c.y + c.h <= m.y + m.h)
      .map(c => c.id)
    if (selIds.value.length) selId.value = null
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}

// 批量拖拽: 整体同步移动 + 整体网格吸附 + 整体边界校验(不允许把任一张拖出画布)
function startBatchDrag(e, primaryId) {
  const s = canvasScale.value || 1
  const sx = e.clientX, sy = e.clientY
  const origin = new Map(cards.value.filter(c => selIds.value.includes(c.id)).map(c => [c.id, { x: c.x, y: c.y }]))
  const prim = origin.get(primaryId) || { x: 0, y: 0 }
  pushHistory()  // 批量操作统一走撤销栈
  const box = {
    minX: Math.min(...Array.from(origin.values()).map(o => o.x)),
    minY: Math.min(...Array.from(origin.values()).map(o => o.y)),
    maxX: Math.max(...cards.value.filter(c => origin.has(c.id)).map(c => c.x + c.w)),
    maxY: Math.max(...cards.value.filter(c => origin.has(c.id)).map(c => c.y + c.h)),
  }
  function mv(ev) {
    const dx = (ev.clientX - sx) / s
    const dy = (ev.clientY - sy) / s
    // 以"手抓的那张"为基准做网格吸附, 其余元素跟随同一个位移 → 相对位置不变
    let deltaX = snap(prim.x + dx) - prim.x
    let deltaY = snap(prim.y + dy) - prim.y
    deltaX = Math.max(-box.minX, Math.min(CANVAS_W - box.maxX, deltaX))
    deltaY = Math.max(-box.minY, Math.min(CANVAS_H - box.maxY, deltaY))
    for (const c of cards.value) {
      const o = origin.get(c.id)
      if (!o) continue
      c.x = Math.round(o.x + deltaX)
      c.y = Math.round(o.y + deltaY)
    }
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}

// 批量右键: 选中 2 个以上时接管, 单项仍走卡片自带菜单
function onStageCtxCapture(e) {
  if (mode.value !== 'edit' || selIds.value.length < 2) return
  const id = cardIdAt(e)
  if (id && !selIds.value.includes(id)) return   // 右键在未选中的卡上 → 交给该卡自己的菜单
  e.stopPropagation(); e.preventDefault()
  batchMenu.value = { x: e.clientX, y: e.clientY }
  window.addEventListener('pointerdown', closeBatchMenu, { once: true })
}
function closeBatchMenu() { batchMenu.value = null }

// ===== 批量对齐 / 尺寸 / 层级 / 删除 =====
function applyBatch(kind) {
  const list = cards.value.filter(c => selIds.value.includes(c.id))
  if (!list.length) return
  batchMenu.value = null
  if (kind === 'del') {
    pushHistory()
    cards.value = cards.value.filter(c => !selIds.value.includes(c.id))
    clearSelection()
    return
  }
  if (kind === 'front' || kind === 'back') {
    pushHistory()
    const mz = kind === 'front' ? maxZ() + 1 : minZ() - 1
    for (const c of list) c.z = mz
    return
  }
  pushHistory()
  const minX = Math.min.apply(null, list.map(c => c.x))
  const minY = Math.min.apply(null, list.map(c => c.y))
  const maxX = Math.max.apply(null, list.map(c => c.x + c.w))
  const maxY = Math.max.apply(null, list.map(c => c.y + c.h))
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2
  const maxW = Math.max.apply(null, list.map(c => c.w))
  const maxH = Math.max.apply(null, list.map(c => c.h))
  for (const c of list) {
    if (kind === 'left') c.x = minX
    else if (kind === 'right') c.x = maxX - c.w
    else if (kind === 'top') c.y = minY
    else if (kind === 'bottom') c.y = maxY - c.h
    else if (kind === 'hcenter') c.x = Math.round(cx - c.w / 2)
    else if (kind === 'vcenter') c.y = Math.round(cy - c.h / 2)
    else if (kind === 'eqw') c.w = maxW
    else if (kind === 'eqh') c.h = maxH
  }
  // 对齐后可能越界(如右对齐把超宽元素推出画布), 统一夹回
  for (const c of list) {
    c.x = Math.max(0, Math.min(CANVAS_W - c.w, c.x))
    c.y = Math.max(0, Math.min(CANVAS_H - c.h, c.y))
  }
}

// ===== 撤销/恢复 + 网格吸附 =====
const grid = ref(8)
let gestureSnap = null

// ===== 编辑工具栏(2026-09-29: 可拖动 + 可显隐, 位置/显隐持久化) =====
const toolsEl = ref(null)
const TOOLS_LS = 'yugsight_bpro_tools'
const toolsPos = ref(null)      // {x,y} 相对画布容器的像素坐标; null=用 CSS 默认(右下角)
const toolsHidden = ref(false)
function loadToolsState() {
  try {
    const o = JSON.parse(localStorage.getItem(TOOLS_LS) || '{}')
    if (o && typeof o.x === 'number') toolsPos.value = { x: o.x, y: o.y }
    if (o && typeof o.hidden === 'boolean') toolsHidden.value = o.hidden
  } catch (e) { /* 忽略 */ }
}
let toolsSaveT = null
function persistTools() {
  if (toolsSaveT) clearTimeout(toolsSaveT)
  toolsSaveT = setTimeout(() => {
    try {
      localStorage.setItem(TOOLS_LS, JSON.stringify({
        x: toolsPos.value ? toolsPos.value.x : null,
        y: toolsPos.value ? toolsPos.value.y : null,
        hidden: toolsHidden.value,
      }))
    } catch (e) { /* 忽略 */ }
  }, 200)
}
loadToolsState()
// 有显式坐标时用 left/top, 否则交给 CSS 默认(right/bottom)
const toolsStyle = computed(() => toolsPos.value
  ? { left: toolsPos.value.x + 'px', top: toolsPos.value.y + 'px', right: 'auto', bottom: 'auto' }
  : {})
function startToolsDrag(e) {
  if (e.button !== 0) return
  e.preventDefault()
  const el = toolsEl.value, host = rootEl.value
  if (!el || !host) return
  const hr = host.getBoundingClientRect()
  const er = el.getBoundingClientRect()
  const ox = er.left - hr.left, oy = er.top - hr.top
  const sx = e.clientX, sy = e.clientY
  function mv(ev) {
    const x = Math.max(0, Math.min(hr.width - er.width, ox + (ev.clientX - sx)))
    const y = Math.max(0, Math.min(hr.height - er.height, oy + (ev.clientY - sy)))
    toolsPos.value = { x: Math.round(x), y: Math.round(y) }
    persistTools()
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
function toggleToolsHidden() { toolsHidden.value = !toolsHidden.value; persistTools() }
const undoStack = ref([])
const redoStack = ref([])
const canUndo = computed(() => undoStack.value.length > 0)
const canRedo = computed(() => redoStack.value.length > 0)
function snapshot() { return JSON.stringify(cards.value.map(c => ({ id: c.id, x: c.x, y: c.y, w: c.w, h: c.h, hidden: !!c.hidden }))) }
function pushHistory() {
  undoStack.value = undoStack.value.concat([snapshot()]).slice(-30)
  redoStack.value = []
}
function restore(snap) {
  const arr = JSON.parse(snap)
  for (const s of arr) {
    const c = cards.value.find(x => x.id === s.id)
    if (c) Object.assign(c, { x: s.x, y: s.y, w: s.w, h: s.h, hidden: s.hidden })
  }
}
function undo() {
  if (!undoStack.value.length) return
  const cur = snapshot()
  const prev = undoStack.value[undoStack.value.length - 1]
  undoStack.value = undoStack.value.slice(0, -1)
  redoStack.value = redoStack.value.concat([cur])
  restore(prev)
}
function redo() {
  if (!redoStack.value.length) return
  const cur = snapshot()
  const next = redoStack.value[redoStack.value.length - 1]
  redoStack.value = redoStack.value.slice(0, -1)
  undoStack.value = undoStack.value.concat([cur])
  restore(next)
}
function snap(v) {
  const g = Number(grid.value) || 1
  return g > 1 ? Math.round(v / g) * g : Math.round(v)
}
// 拖拽/缩放的一次手势只记一份历史: 首次 patch 前拍快照, pointerup 时入栈
function endGesture() {
  if (gestureSnap) { undoStack.value = undoStack.value.concat([gestureSnap]).slice(-30); redoStack.value = []; gestureSnap = null }
}
function patchCard(id, patch) {
  if (patch.x != null || patch.y != null || patch.w != null || patch.h != null) {
    if (!gestureSnap) gestureSnap = snapshot()
    const p = Object.assign({}, patch)
    if (p.x != null) p.x = snap(p.x)
    if (p.y != null) p.y = snap(p.y)
    if (p.w != null) p.w = Math.max(160, snap(p.w))
    if (p.h != null) p.h = Math.max(100, snap(p.h))
    patch = p
  }
  const c = cards.value.find(x => x.id === id)
  if (c) Object.assign(c, patch)
}
function flipCard(id) {
  const c = cards.value.find(x => x.id === id)
  if (c) c.flipped = !c.flipped
}
function removeCard(id) {
  cards.value = cards.value.filter(x => x.id !== id)
  if (selId.value === id) selId.value = null
}
function maxZ() { return cards.value.reduce((m, c) => Math.max(m, c.z || 0), 0) }
function minZ() { return cards.value.reduce((m, c) => Math.min(m, c.z || 0), 0) }
function bringFront(id) { const c = cards.value.find(x => x.id === id); if (c) c.z = maxZ() + 1 }
function sendBack(id) { const c = cards.value.find(x => x.id === id); if (c) c.z = minZ() - 1 }
// 编辑: 本步仅选中卡片(属性编辑面板为后续步骤); 预留入口
function editCard(id) { selId.value = id }

// ===== 新建组件(编辑态下拉) =====
const newOpen = ref(false)
const FACTORY = {
  scan: makeScan, stat: makeStat, title: makeTitle, node: makeNode,
  taskList: makeTaskList,
  metric: makeMetric, ratio: makeRatio, status: makeStatusCard,
  vlevel: makeVulnLevel, trend: makeTrend, tbars: makeTaskBars,
  apie: makeAssetPie, atop: makeAlertTop, roller: makeRoller, globe: makeGlobe,
}
function addCard(type) {
  newOpen.value = false
  // 3D 地球每个实例独占一个 WebGL 上下文, 超限后浏览器会丢上下文且不可恢复, 这里硬拦
  if (type === 'globe' && cards.value.some(c => c.type === 'globe')) {
    flashWarn(t('bpro.globeLimit'))
    return
  }
  const factory = FACTORY[type] || makeScan
  const n = cards.value.length
  const c = factory({ x: 120 + (n % 6) * 36, y: 120 + (n % 6) * 36 })
  c.z = maxZ() + 1
  cards.value.push(c)
  selId.value = c.id
}

// ===== 恢复默认布局 =====
const resetTip = ref(false)
let tipTimer = null
function resetLayout() {
  cards.value = defaultCards()
  selId.value = null
  resetTip.value = true
  if (tipTimer) clearTimeout(tipTimer)
  tipTimer = setTimeout(() => { resetTip.value = false }, 2000)
}

// ===== 一键全屏(2026-09-29 改文档级 + 意图持久化, 见 fullscreen.js) =====
// 文档级: 站内切页(如双击拓扑卡去 /topology/3d)不退出全屏; 退出只认用户
// ESC/按钮。刷新后由 scheduleFullscreenRestore 在首次交互时恢复。
let fsRestoreCleanup = null
async function toggleFullscreen() {
  try {
    if (document.fullscreenElement) await document.exitFullscreen()
    else { await enterFullscreen(); setFsIntent(true) }
  } catch (e) { /* 不支持全屏的环境静默失败 */ }
}
// 沉浸式类名(body.bpro-immersive)改由 App.vue 全局监听维护(全屏跨页后
// 页内监听已卸载, 全局才能覆盖); 这里只管控制栏自动隐藏逻辑
function syncImmersive() {
  if (!document.fullscreenElement) ctrlHidden.value = false
}
// 全屏下控制栏自动隐藏: 鼠标移到顶部 60px 内呼出, 离开 2s 后收起
const ctrlHidden = ref(false)
let hideT = null
function onEdgeMove(e) {
  if (!document.fullscreenElement) return
  if (e.clientY <= 60) {
    ctrlHidden.value = false
    if (hideT) { clearTimeout(hideT); hideT = null }
  } else if (!ctrlHidden.value && !hideT) {
    hideT = setTimeout(() => { ctrlHidden.value = true; hideT = null }, 2000)
  }
}

// 新建卡片下拉: 点击画布其它处关闭
function onDocClick() { newOpen.value = false }
// 编辑模式暂停轮播(你在摆位置, 画面自己跳走没法干活); 回浏览模式恢复
watch(mode, (m) => {
  // 浏览模式必须彻底隐藏框选/批量能力: 清选中、关菜单、不进捕获逻辑
  if (m === 'edit') carousel.hold('edit')
  else { carousel.release('edit'); carousel.start(); clearSelection() }
})
function onGlobalKey(e) {
  const t = e.target
  if (t && ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName)) return
  // Delete 批量删除(多选优先; 单选删除由各组件自己处理)
  if ((e.key === 'Delete' || e.key === 'Backspace') && mode.value === 'edit' && selIds.value.length > 1) {
    e.preventDefault(); applyBatch('del'); return
  }
  if (!(e.ctrlKey || e.metaKey)) return
  const k = String(e.key || '').toLowerCase()
  if (k === 'z') { e.preventDefault(); undo() }
  else if (k === 'y') { e.preventDefault(); redo() }
}
onMounted(() => {
  isFullscreen.value = !!document.fullscreenElement
  fsHandler = () => { isFullscreen.value = !!document.fullscreenElement; syncImmersive() }
  document.addEventListener('fullscreenchange', fsHandler)
  document.addEventListener('click', onDocClick)
  window.addEventListener('pointerup', endGesture)
  window.addEventListener('keydown', onGlobalKey)
  window.addEventListener('mousemove', onEdgeMove)
  // 刷新后恢复全屏: 意图在(上次没退出)且当前不在全屏 → 首个交互即重新进入
  fsRestoreCleanup = scheduleFullscreenRestore()
  carousel.setIndex(indexOfTpl(curTpl.value))
  if (mode.value === 'browse') carousel.start()
  else carousel.hold('edit')
})
onBeforeUnmount(() => {
  if (fsHandler) document.removeEventListener('fullscreenchange', fsHandler)
  document.removeEventListener('click', onDocClick)
  window.removeEventListener('pointerup', endGesture)
  window.removeEventListener('keydown', onGlobalKey)
  window.removeEventListener('mousemove', onEdgeMove)
  if (fsRestoreCleanup) { fsRestoreCleanup(); fsRestoreCleanup = null }
  if (hideT) clearTimeout(hideT)
  carousel.dispose()
  if (tipTimer) clearTimeout(tipTimer)
  if (warnT) clearTimeout(warnT)
  if (saveT) clearTimeout(saveT)
  // 注意: 不再强制退出全屏/清沉浸式类 —— 文档级全屏跨页保持(用户没退出就保持),
  // 类名由 App.vue 全局监听维护
})
</script>

<style scoped>
/* 站内页(2026-09-27 改): 套 Layout 外壳, 占满内容区(非 fixed 脱离外壳);
   真正的浏览器全屏仍由「一键全屏」按钮触发(投屏场景)。
   height:100% 依赖 .page-main 的 flex:1 确定高度, FreeCanvas 自适应缩放。 */
.bpro { position: relative; width: 100%; height: 100%; overflow: hidden; background: #070d18; border-radius: 10px; }

/* 模板切换(2026-09-28 修复): 不再用位移过渡 —— 快速切换时卡片会"飞行中再被改目标"
   造成布局错乱。改为"先瞬时落位(无过渡), 落位完成后再挂 fadein 类只过渡 opacity(淡入),
   ~520ms 撤掉"。平时(非切换)无过渡, 拖拽不"追手"。 */
.bpro-stage { position: absolute; inset: 0; }
@keyframes bproCardIn { from { opacity: 0; } to { opacity: 1; } }
.bpro-stage.fadein :deep(.cc-inner) { animation: bproCardIn .48s ease; }

/* 沉浸式: 全屏下控制栏可自动隐藏(鼠标移到顶部 60px 内呼出) */
.bpro-ctrl.hidden { opacity: 0; pointer-events: none; transform: translateY(-12px); transition: opacity .4s, transform .4s; }

/* 框选框: 半透明蓝色, 设计坐标系(在 FreeCanvas 内, 自动跟着缩放) */
.bpro-marquee {
  position: absolute; z-index: 5; pointer-events: none;
  background: rgba(56, 132, 255, .16); border: 1px solid rgba(56, 132, 255, .85);
  box-shadow: 0 0 12px rgba(56, 132, 255, .35) inset;
}
/* 批量右键菜单 */
.bpro-batch {
  position: fixed; z-index: 9999; min-width: 158px;
  background: rgba(12, 20, 36, .97); border: 1px solid rgba(56, 132, 255, .4);
  border-radius: 8px; padding: 4px; box-shadow: 0 12px 34px rgba(0, 0, 0, .6);
}
.bb-h { padding: 5px 12px 3px; font-size: 10.5px; color: #64748b; letter-spacing: 1px; }
.bpro-batch button {
  display: block; width: 100%; text-align: left; padding: 6px 12px; font-size: 12px;
  color: #cdd6e4; background: transparent; border: none; border-radius: 5px; cursor: pointer;
}
.bpro-batch button:hover { background: rgba(56, 132, 255, .22); color: #fff; }
.bpro-batch button.danger { color: #f87171; }
.bpro-batch button.danger:hover { background: rgba(248, 113, 113, .18); }

/* 轮播控制条 / 编辑辅助条 */
.bpro-carousel, .bpro-tools {
  position: absolute; left: 50%; transform: translateX(-50%); z-index: 10;
  display: flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 10px;
  background: rgba(10, 18, 32, .72); border: 1px solid rgba(56, 132, 255, .35);
  backdrop-filter: blur(8px); box-shadow: 0 4px 24px rgba(0, 0, 0, .45);
}
.bpro-carousel { bottom: 62px; }
.bpro-tools { bottom: 62px; left: auto; right: 20px; transform: none; }
/* 拖动把手 / 隐藏按钮 / 恢复入口(2026-09-29 工具框可拖动+可显隐) */
.bpro-tools-handle { cursor: grab; color: #64748b; font-size: 14px; line-height: 1; padding: 0 2px; user-select: none; }
.bpro-tools-handle:hover { color: #fff; }
.bpro-tools:active .bpro-tools-handle { cursor: grabbing; }
.bpro-tools-hide { padding: 2px 6px !important; line-height: 1; }
.bpro-tools-restore {
  position: absolute; left: 20px; bottom: 62px; z-index: 10;
  padding: 4px 12px; font-size: 12px; cursor: pointer;
  color: #cdd6e4; background: rgba(10, 18, 32, .72); border: 1px solid rgba(56, 132, 255, .4);
  border-radius: 8px; backdrop-filter: blur(8px); box-shadow: 0 4px 24px rgba(0, 0, 0, .45);
}
.bpro-tools-restore:hover { background: rgba(56, 132, 255, .3); color: #fff; }
.bpro-carousel button, .bpro-tools button {
  font-size: 12px; padding: 3px 12px; cursor: pointer; white-space: nowrap;
  color: #cdd6e4; background: rgba(56, 132, 255, .14);
  border: 1px solid rgba(56, 132, 255, .4); border-radius: 6px;
}
.bpro-carousel button:hover, .bpro-tools button:hover { background: rgba(56, 132, 255, .3); color: #fff; }
.bpro-carousel button:disabled, .bpro-tools button:disabled { opacity: .4; cursor: default; }
.bpro-carousel select, .bpro-tools select {
  font-size: 12px; padding: 3px 6px; color: #cdd6e4; background: rgba(10, 18, 32, .9);
  border: 1px solid var(--border); border-radius: 6px;
}
.bpro-tools label { display: flex; align-items: center; gap: 6px; font-size: 12px; color: #9fb0c8; }
.bc-idx, .bc-state { font-size: 11.5px; color: #8295b0; }
.bc-state { color: #fbbf24; }
/* 轮播设置面板: 勾选参与轮播的模板 + 自定义间隔 */
.bpro-carousel-set {
  position: absolute; left: 50%; transform: translateX(-50%); bottom: 96px; z-index: 11;
  width: 300px; max-height: 340px; overflow-y: auto; padding: 10px 12px;
  background: rgba(12, 20, 36, .97); border: 1px solid rgba(56, 132, 255, .4);
  border-radius: 10px; box-shadow: 0 12px 34px rgba(0, 0, 0, .6);
}
.bcs-h { font-size: 12.5px; color: #eaf1fb; margin-bottom: 8px; }
.bcs-hint { font-size: 10.5px; color: #64748b; }
.bcs-item { display: flex; align-items: center; gap: 8px; padding: 5px 6px; border-radius: 6px; cursor: pointer; font-size: 12px; color: #cdd6e4; }
.bcs-item:hover { background: rgba(56, 132, 255, .14); }
.bcs-item input { accent-color: #3884ff; }
.bcs-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bcs-tag { font-size: 10px; color: #64748b; }
.bcs-empty { font-size: 11.5px; color: #64748b; padding: 8px 0; }
.bcs-foot { display: flex; align-items: center; gap: 10px; margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(255, 255, 255, .08); font-size: 11.5px; color: #9fb0c8; }
.bcs-int { display: flex; align-items: center; gap: 6px; }
.bcs-int input { width: 56px; background: rgba(255, 255, 255, .06); border: 1px solid rgba(56, 132, 255, .3); border-radius: 5px; color: #eaf1fb; padding: 2px 6px; font-size: 11.5px; }
.bcs-count { margin-left: auto; color: #34d399; }
.bcs-foot button { padding: 3px 12px; font-size: 11.5px; cursor: pointer; color: #cdd6e4; background: rgba(56, 132, 255, .16); border: 1px solid rgba(56, 132, 255, .4); border-radius: 6px; }
.bcs-foot button:hover { background: rgba(56, 132, 255, .3); color: #fff; }
.ni-tag { margin-left: auto; font-size: 10px; color: #64748b; }

/* 右上角悬浮控制栏(毛玻璃底, 不占画布空间) */
.bpro-ctrl {
  position: absolute; top: 16px; right: 20px; z-index: 10;
  display: flex; align-items: center; gap: 10px;
  padding: 8px 12px; border-radius: 10px;
  background: rgba(10, 18, 32, .72);
  border: 1px solid rgba(56, 132, 255, .35);
  backdrop-filter: blur(8px);
  box-shadow: 0 4px 24px rgba(0, 0, 0, .45);
}
/* 双模式开关(分段控件) */
.bpro-mode {
  display: inline-flex; align-items: center;
  border: 1px solid var(--border); border-radius: 6px; overflow: hidden;
  background: rgba(255, 255, 255, .02);
}
.bpro-mode button {
  padding: 4px 12px; font-size: 12.5px; line-height: 18px;
  color: var(--muted); cursor: pointer; user-select: none;
  background: transparent; border: none;
}
.bpro-mode button + button { border-left: 1px solid var(--border); }
.bpro-mode button:hover { color: #fff; }
.bpro-mode button.on { color: #fff; background: rgba(56, 132, 255, .22); }
.bpro-btn {
  padding: 4px 12px; font-size: 12.5px; cursor: pointer; white-space: nowrap;
  color: #cdd6e4; background: rgba(56, 132, 255, .14);
  border: 1px solid rgba(56, 132, 255, .4); border-radius: 6px;
}
.bpro-btn:hover { background: rgba(56, 132, 255, .3); color: #fff; }
.bpro-select {
  padding: 4px 8px; font-size: 12.5px; cursor: pointer;
  color: #cdd6e4; background: rgba(10, 18, 32, .9);
  border: 1px solid var(--border); border-radius: 6px;
}
/* 新建卡片下拉 */
.bpro-new { position: relative; }
.bpro-new-menu {
  position: absolute; top: calc(100% + 8px); right: 0; z-index: 20; min-width: 152px;
  background: rgba(12, 20, 36, .97); border: 1px solid rgba(56, 132, 255, .4);
  border-radius: 8px; padding: 4px; box-shadow: 0 10px 30px rgba(0, 0, 0, .6);
}
.bpro-new-menu button {
  display: block; width: 100%; text-align: left; padding: 8px 12px;
  font-size: 12.5px; color: #cdd6e4; background: transparent; border: none; border-radius: 5px; cursor: pointer;
}
.bpro-new-menu button:hover { background: rgba(56, 132, 255, .22); color: #fff; }
.bpro-new-menu .ni { display: inline-block; width: 22px; color: var(--accent); }

/* 底部悬浮(居中): 恢复默认布局 + 反馈提示 */
.bpro-foot {
  position: absolute; bottom: 18px; left: 50%; transform: translateX(-50%); z-index: 10;
  display: flex; align-items: center; gap: 12px;
  padding: 8px 14px; border-radius: 10px;
  background: rgba(10, 18, 32, .72);
  border: 1px solid rgba(56, 132, 255, .35);
  backdrop-filter: blur(8px);
  box-shadow: 0 4px 24px rgba(0, 0, 0, .45);
}
.bpro-reset {
  padding: 4px 16px; font-size: 12.5px; cursor: pointer; white-space: nowrap;
  color: #cdd6e4; background: rgba(56, 132, 255, .14);
  border: 1px solid rgba(56, 132, 255, .4); border-radius: 6px;
}
.bpro-reset:hover { background: rgba(56, 132, 255, .3); color: #fff; }
.bpro-done { color: #34d399; font-size: 12px; white-space: nowrap; }
.bpro-warn { color: #fbbf24; font-size: 12px; white-space: nowrap; }

/* 新建组件下拉: 分组标题 + 模板条目(删除按钮) */
.ni-group {
  padding: 6px 12px 2px; font-size: 11px; color: #64748b; letter-spacing: 1px;
  border-top: 1px solid rgba(255, 255, 255, .06);
}
.bpro-new-menu .ni-group:first-child { border-top: none; }
.bpro-new-menu button { display: flex; align-items: center; gap: 2px; }
.ni-t { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ni-del { color: #64748b; padding: 0 4px; border-radius: 4px; }
.ni-del:hover { color: #f87171; background: rgba(248, 113, 113, .14); }

/* 右侧属性面板: 选中组件后弹出, 编辑数据源/字段/样式/显示范围 */
.bpro-panel {
  position: absolute; top: 70px; right: 20px; bottom: 70px; width: 258px; z-index: 12;
  display: flex; flex-direction: column; gap: 8px; padding: 10px 12px;
  background: rgba(10, 18, 32, .88); border: 1px solid rgba(56, 132, 255, .4);
  border-radius: 10px; backdrop-filter: blur(8px); box-shadow: 0 12px 34px rgba(0, 0, 0, .55);
}
.bp-head { display: flex; align-items: center; justify-content: space-between; font-size: 13px; color: #eaf1fb; }
.bp-x { background: none; border: none; color: #8295b0; font-size: 16px; cursor: pointer; line-height: 1; }
.bp-x:hover { color: #fff; }
.bp-body { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; padding-right: 2px; }
.bp-body label { display: flex; align-items: center; gap: 8px; font-size: 11.5px; color: #8295b0; }
.bp-body label span { width: 82px; flex: 0 0 auto; }
.bp-body input, .bp-body select, .bp-body textarea {
  flex: 1; min-width: 0; background: rgba(255, 255, 255, .05); color: #eaf1fb;
  border: 1px solid rgba(56, 132, 255, .3); border-radius: 5px; padding: 4px 6px; font-size: 11.5px;
}
/* 2026-09-30 用户反馈"下拉选择背景白的看不到文字": 下拉展开列表走系统主题(白底),
   option 却继承了面板的浅色文字 → 白底浅字不可读。显式给 option 深色底+浅色字
   (与 TopoInspector 同口径); 轮播/工具栏下拉一并覆盖防同类问题。 */
.bp-body select option, .bpro-select option, .bpro-carousel select option, .bpro-tools select option {
  background: #0e1826; color: #eaf1fb; padding: 4px 6px;
}
.bp-body select option:hover, .bpro-select option:hover,
.bpro-carousel select option:hover, .bpro-tools select option:hover {
  background: #1e3a5f; color: #fff;
}
.bp-body textarea { resize: vertical; }
.bp-none { font-size: 11.5px; color: #64748b; }
/* 属性面板内的功能分组(告警设置等): 标题 + 内嵌组件 */
.bp-sec { margin-top: 2px; padding-top: 8px; border-top: 1px solid rgba(255, 255, 255, .08); display: flex; flex-direction: column; gap: 8px; }
.bp-sec-h { font-size: 11px; color: #64748b; letter-spacing: 1px; display: flex; align-items: baseline; gap: 6px; }
.bp-sec-note { font-size: 9.5px; color: #475569; letter-spacing: 0; }
.bp-ro { margin-left: 4px; font-style: normal; font-size: 9.5px; color: #38bdf8; border: 1px solid rgba(56, 189, 248, .35); border-radius: 3px; padding: 0 3px; }
.bp-body input:disabled, .bp-body select:disabled { opacity: .5; cursor: default; }
.bp-hint { font-size: 11px; color: #64748b; }
.bp-sep { margin-top: 4px; padding-top: 6px; border-top: 1px solid rgba(255, 255, 255, .08); font-size: 11px; color: #64748b; }
.bp-geo span { width: 40px; }
.bp-foot { display: flex; align-items: center; gap: 6px; }
.bp-tplname {
  flex: 1; min-width: 0; background: rgba(255, 255, 255, .05); color: #eaf1fb;
  border: 1px solid rgba(56, 132, 255, .3); border-radius: 5px; padding: 4px 6px; font-size: 11.5px;
}
.bp-foot button {
  padding: 4px 10px; font-size: 11.5px; cursor: pointer; white-space: nowrap;
  color: #cdd6e4; background: rgba(56, 132, 255, .16);
  border: 1px solid rgba(56, 132, 255, .4); border-radius: 5px;
}
.bp-foot button:hover { background: rgba(56, 132, 255, .3); color: #fff; }
.bp-foot button.danger { color: #f87171; background: rgba(248, 113, 113, .12); border-color: rgba(248, 113, 113, .4); }
.bp-foot button.danger:hover { background: rgba(248, 113, 113, .24); }
</style>
