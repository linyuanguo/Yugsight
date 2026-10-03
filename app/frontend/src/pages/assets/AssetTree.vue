<!--
  AssetTree.vue —— 资产管理二级混合树(2026-09-28)

  结构: 一级 = 目录 / 扫描任务快照 / 监控设备 / 独立资产 四类节点混排;
        二级 = 仅目录与扫描快照下的资产条目(assetId 数组)。
  交互: HTML5 原生拖拽(一级重排 / 二级跨目录移动 / 独立资产拖入目录),
        连接线用原生 SVG 层按元素实际位置重算(展开/筛选/尺寸变化时)。
  约束: 扫描快照二级只读(不可拖入/拖出); 监控设备只可重排, 点行跳节点监控页;
        资产数据一律以 /api/v2/assets 为准, 本组件只做展示与归属操作。
-->
<template>
  <div>
    <div class="card">
      <div class="toolbar">
        <input class="input" v-model.trim="q" placeholder="搜索 IP / 主机名 / 目录名 / 任务名" style="max-width:260px">
        <!-- 2026-10-02 用户口径: 类型筛选选项=当前树里真实存在的类型(某类节点全没了选项消失) -->
        <select class="input" v-model="typeF" style="max-width:140px">
          <option value="">全部类型</option>
          <option v-for="k in typeOpts" :key="k" :value="k">{{ TYPE_CN[k] }}</option>
        </select>
        <button class="btn sm" @click="openFolder">新增目录</button>
        <button class="btn sm" :disabled="busy" @click="resync">{{ busy ? '同步中...' : '同步扫描快照' }}</button>
        <button class="btn sm danger" @click="doReset">重置树</button>
        <div class="spacer"></div>
        <span class="muted small">{{ statText }}</span>
        <span class="muted small" v-if="state.truncated">(台账超 1 万条已截断, 请到台账表分页查看)</span>
      </div>

      <Empty v-if="loadError" :text="'资产树加载失败: ' + loadError" />

      <div class="atree" ref="wrapRef" v-else>
        <!-- 原生 SVG 连接线层: 位置随节点行实测重算, 纯装饰不拦事件 -->
        <svg class="atree-lines" v-if="linePaths.length" :width="box.w" :height="box.h"
             :viewBox="`0 0 ${box.w} ${box.h}`" aria-hidden="true">
          <path v-for="(d, i) in linePaths" :key="i" :d="d" />
        </svg>

        <template v-for="e in visibleEntries" :key="e.key">
          <div class="atree-item">
            <!-- ===== 一级行 ===== -->
            <div class="atree-row l1"
                 :class="[rowDropClass(e.key), { 'atree-focus': focusKey === e.key }]"
                 :ref="el => setRowRef(e.key, el)"
                 :draggable="true"
                 @dragstart="onEntryDragStart(e, $event)"
                 @dragover="onDragOver(e, $event, null)"
                 @drop="onDropOnEntry(e, $event)">
              <span class="caret" v-if="e.kind === 'folder' || e.kind === 'scan'"
                    @click.stop="toggleExpand(e.node.nodeId)">{{ isExpanded(e.node.nodeId) ? '▾' : '▸' }}</span>
              <span class="caret ghost" v-else>&nbsp;</span>
              <span class="tp" :class="'tp-' + e.kind">{{ tpLabel(e.kind) }}</span>
              <b class="atree-name">{{ e.kind === 'folder' || e.kind === 'scan' ? e.node.name : e.name }}</b>
              <span class="muted small mono" v-if="e.kind === 'single' && e.asset.hostname">{{ e.asset.ip }}</span>
              <!-- 元信息: 目录备注 / 快照时间 / 设备 IP -->
              <span class="muted small" v-if="e.kind === 'folder' && e.node.remark" :title="e.node.remark">· {{ e.node.remark }}</span>
              <span class="muted small mono" v-else-if="e.kind === 'scan'">{{ fmtDT(e.node.scanTime) }}</span>
              <span class="muted small mono" v-else-if="e.kind === 'monitor' && e.ip">{{ e.ip }}</span>
              <span class="badge" :class="'cnt-' + e.kind" v-if="e.kind === 'folder' || e.kind === 'scan'">{{ e.children.length }}</span>
              <span class="badge" :class="'st-' + statusClass(e)" v-else-if="e.kind === 'monitor'">{{ statusLabel(e) }}</span>
              <span class="badge st-failed" v-if="e.kind === 'scan' && e.node.reportGone">报告已删除</span>
              <!-- 操作 -->
              <div class="row-actions">
                <template v-if="e.kind === 'folder'">
                  <button class="btn xs" @click.stop="openRename(e.node)">重命名</button>
                  <button class="btn xs danger" @click.stop="delFolder(e.node)">删除</button>
                </template>
                <template v-else-if="e.kind === 'scan'">
                  <button class="btn xs" :disabled="!!e.node.reportGone" @click.stop="openReport(e.node)">查看报告</button>
                  <button class="btn xs danger" @click.stop="delScan(e.node)">移除快照</button>
                </template>
                <button class="btn xs" v-else-if="e.kind === 'monitor'" @click.stop="gotoMonitor(e)">节点监控</button>
                <template v-else>
                  <!-- 独立资产: 与二级资产行同操作 -->
                  <button class="btn xs" @click.stop="$emit('edit', e.asset)">编辑</button>
                  <button class="btn xs" @click.stop="gotoReportByAsset(e.asset)">原始报告</button>
                  <button class="btn xs" @click.stop="$emit('locate', e.asset)">定位</button>
                  <button class="btn xs danger" @click.stop="delAsset(e.asset)">删除</button>
                </template>
              </div>
            </div>

            <!-- ===== 二级行(目录/快照下的资产条目) ===== -->
            <div class="atree-children"
                 v-if="(e.kind === 'folder' || e.kind === 'scan') && isExpanded(e.node.nodeId) && visibleChildren(e).length">
              <div class="atree-row l2" v-for="c in visibleChildren(e)" :key="c.ref"
                   :class="[rowDropClass(e.key + '#' + e.children.indexOf(c)), { 'atree-focus': focusKey === (e.key + '#' + e.children.indexOf(c)) }]"
                   :ref="el => setRowRef(e.key + '#' + e.children.indexOf(c), el)"
                   :draggable="e.kind === 'folder'"
                   :title="e.kind === 'scan' ? '扫描快照只读, 不可移动' : '拖到其它目录 / 独立资产行可移动归属'"
                   @dragstart="onAssetDragStart(e, c, $event)"
                   @dragover="onDragOver(e, $event, e.children.indexOf(c))"
                   @drop="onDropOnChild(e, c, e.children.indexOf(c), $event)">
                <span class="muted small" style="width:14px;flex:none">·</span>
                <span class="mono">{{ c.ip }}</span>
                <span class="small" v-if="c.asset && c.asset.hostname">{{ c.asset.hostname }}</span>
                <span class="badge" :class="c.asset && c.asset.alive ? 'st-success' : 'st-failed'" v-if="c.asset">
                  {{ c.asset.alive ? '存活' : '未存活' }}
                </span>
                <span class="muted small" v-if="c.ghost">已不在台账(历史保留)</span>
                <span class="tag" v-for="t in (c.asset && c.asset.tags) || []" :key="t">{{ t }}</span>
                <div class="row-actions" v-if="c.asset && e.kind === 'folder'">
                  <button class="btn xs" @click.stop="$emit('edit', c.asset)">编辑</button>
                  <button class="btn xs" @click.stop="gotoReportByAsset(c.asset)">原始报告</button>
                  <button class="btn xs" @click.stop="$emit('locate', c.asset)">定位</button>
                  <button class="btn xs danger" @click.stop="delAsset(c.asset)">删除</button>
                </div>
              </div>
            </div>
          </div>
        </template>

        <Empty v-if="!visibleEntries.length" text="没有匹配的节点(试试清空搜索/类型筛选, 或点「新增目录」「同步扫描快照」)" />
      </div>
    </div>

    <!-- 新增/重命名目录 -->
    <Modal v-if="showFolder" :title="renaming ? '重命名目录' : '新增目录'" width="420px" @close="showFolder = false">
      <div class="field"><label class="label">目录名 *</label>
        <input class="input" v-model="folderName" placeholder="如 核心机房 / 财务区" @keyup.enter="saveFolder"></div>
      <div class="field"><label class="label">备注</label>
        <input class="input" v-model="folderRemark" placeholder="可选"></div>
      <div class="login-err" style="text-align:left">{{ folderErr }}</div>
      <template #footer>
        <button class="btn" @click="showFolder = false">取消</button>
        <button class="btn primary" @click="saveFolder">保存</button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import Modal from '../../components/Modal.vue'
import Empty from '../../components/Empty.vue'
import { v2 } from '../../api/http'
import { fmtDT } from '../../utils'
import {
  assetTree, entries, loadAll, isExpanded, addFolder, updateFolder, removeFolder,
  removeScanNode, moveAsset, reorderEntry, toggleExpand, resetTree, focusKeyOf
} from './treeStore'

const { state } = assetTree
const emit = defineEmits(['edit', 'locate', 'changed'])
const router = useRouter()
const route = useRoute()

// ===== 数据装载 =====
const loadError = ref('')
const busy = ref(false)

async function init() {
  loadError.value = ''
  busy.value = true
  try {
    await loadAll()
  } catch (e) {
    loadError.value = e.message
  } finally {
    busy.value = false
  }
}
init()

async function resync() {
  busy.value = true
  try { await loadAll() } catch (e) { alert('同步失败: ' + e.message) } finally { busy.value = false }
}

function doReset() {
  if (!confirm('重置资产树?\n\n将清空所有目录分组、顺序与快照条目(资产本身、扫描报告存档完全不受影响),\n随后按当前台账与扫描快照重建视图。')) return
  resetTree()
  drawLines()
}

// ===== 搜索/类型筛选(纯展示层过滤, 不改归属) =====
const q = ref('')
const typeF = ref('')

function matchText(e) {
  const s = q.value.toLowerCase()
  if (!s) return true
  const nodeText = (e.kind === 'folder' || e.kind === 'scan')
    ? (e.node.name + ' ' + (e.node.remark || ''))
    : (e.name + ' ' + (e.ip || ''))
  if (nodeText.toLowerCase().includes(s)) return true
  // 目录/快照: 任一二级成员命中即显示该节点
  for (const c2 of e.children) {
    if ((c2.ip + ' ' + ((c2.asset && c2.asset.hostname) || '')).toLowerCase().includes(s)) return true
  }
  return false
}

// 2026-10-02: 类型筛选选项 = 当前树里真实存在的类型(只含存在的)
const TYPE_CN = { folder: '自定义目录', scan: '扫描任务快照', monitor: '监控设备', single: '独立资产' }
const typeOpts = computed(() => ['folder', 'scan', 'monitor', 'single'].filter(k => entries.value.some(e => e.kind === k)))
watch(entries, () => {
  if (typeF.value && !typeOpts.value.includes(typeF.value)) typeF.value = ''
})

const visibleEntries = computed(() => {
  return entries.value.filter(e => {
    if (typeF.value && e.kind !== typeF.value) return false
    return matchText(e)
  })
})

// 二级成员过滤: 搜索词命中节点名时全显, 否则只显命中的成员
function visibleChildren(e) {
  if (!q.value) return e.children
  const s = q.value.toLowerCase()
  const nameHit = ((e.node && e.node.name) || '').toLowerCase().includes(s)
    || ((e.node && e.node.remark) || '').toLowerCase().includes(s)
  if (nameHit) return e.children
  return e.children.filter(c => ((c.ip + ' ' + ((c.asset && c.asset.hostname) || '')).toLowerCase().includes(s)))
}

const statText = computed(() => {
  const c = { folder: 0, scan: 0, monitor: 0, single: 0 }
  for (const e of entries.value) c[e.kind] = (c[e.kind] || 0) + 1
  return `目录 ${c.folder} · 快照 ${c.scan} · 监控设备 ${c.monitor} · 独立资产 ${c.single}`
})

function tpLabel(k) {
  return { folder: '目录', scan: '扫描快照', monitor: '监控设备', single: '独立资产' }[k] || k
}
function statusClass(e) {
  return { online: 'st-success', warning: 'st-running', offline: 'st-failed' }[e.status] || 'st-pending'
}
function statusLabel(e) {
  return { online: '在线', warning: '预警', offline: '离线' }[e.status] || e.status
}

// ===== 节点/资产业务动作 =====
const showFolder = ref(false)
const renaming = ref(null)
const folderName = ref('')
const folderRemark = ref('')
const folderErr = ref('')

function openFolder() {
  renaming.value = null
  folderName.value = ''
  folderRemark.value = ''
  folderErr.value = ''
  showFolder.value = true
}
function openRename(node) {
  renaming.value = node
  folderName.value = node.name
  folderRemark.value = node.remark || ''
  folderErr.value = ''
  showFolder.value = true
}
function saveFolder() {
  const name = folderName.value.trim()
  if (!name) { folderErr.value = '目录名不能为空'; return }
  if (renaming.value) updateFolder(renaming.value.nodeId, { name, remark: folderRemark.value.trim() })
  else addFolder(name, folderRemark.value.trim())
  showFolder.value = false
  drawLines()
}
function delFolder(node) {
  const n = (node.children || []).length
  if (!confirm(`删除目录「${node.name}」?\n\n目录内的 ${n} 台资产不会删除, 全部退回「独立资产」一级。`)) return
  removeFolder(node.nodeId)
  emit('changed')
  drawLines()
}
function delScan(node) {
  if (!confirm(`从资产树移除扫描快照「${node.name}」?\n\n只移除本树的快照条目, 报告中心的原始报告存档不受影响(删错了可点「同步扫描快照」找回来)。`)) return
  removeScanNode(node.nodeId)
  drawLines()
}
function openReport(node) {
  // 联动深链: 报告中心原始报告 tab 直接打开该报告详情(Reports.vue 读 rawId)
  router.push({ path: '/reports', query: { tab: 'raw', rawId: node.reportId } })
}
function gotoMonitor(e) {
  router.push(e.link)
}
function gotoReportByAsset(a) {
  // 联动: 报告中心按资产 IP 过滤原始报告(Reports.vue 读 asset)
  router.push({ path: '/reports', query: { tab: 'raw', asset: a.ip } })
}
async function delAsset(a) {
  if (!confirm('确认删除资产 ' + a.ip + ' ?\n\n删除后不可恢复, 扫描快照里的历史记录仍保留(灰显)。')) return
  try {
    await v2('/assets/' + a.id, { method: 'DELETE' })
    await loadAll() // 台账删了, 整体重同步(目录/独立条目自动摘除, 快照 absent 化)
    emit('changed')
    drawLines()
  } catch (e) {
    alert(e.message)
  }
}

// ===== 拖拽(HTML5 DnD) =====
//
// 载荷两类:
//   {kind:'entry', key}              一级节点(仅重排; 独立资产一级行拖入目录=归属变更)
//   {kind:'asset', ref, fromKey}     二级资产(跨目录移动/目录内重排/退回独立)
// 落点: 一级行(上/下 30%=重排前/后, 中段 40%=移入目录), 二级行(前/后=插入该位置)
// 红线: 扫描快照二级不可拖入/拖出; 目录不可拖入目录; 监控设备不可进目录。

const drop = reactive({ key: '', zone: '', valid: false })
let dragging = null

function rowDropClass(key) {
  if (drop.key !== key) return {}
  if (!drop.zone) return {}
  if (!drop.valid) return { 'atree-nodrop': true }
  return { ['atree-drop-' + drop.zone]: true }
}

function setPayload(ev, payload) {
  dragging = payload
  ev.dataTransfer.effectAllowed = 'move'
  ev.dataTransfer.setData('text/plain', JSON.stringify(payload))
}

function onEntryDragStart(e, ev) {
  setPayload(ev, { kind: 'entry', key: e.key })
}
function onAssetDragStart(e, c, ev) {
  setPayload(ev, { kind: 'asset', ref: c.ref, fromKey: e.key })
}

function zoneOf(ev, rect) {
  // 垂直三分: 上 30% = before, 下 30% = after, 中段 40% = inside(仅一级行有意义)
  const r = (ev.clientY - rect.top) / rect.height
  if (r < 0.3) return 'before'
  if (r > 0.7) return 'after'
  return 'inside'
}

// 合法性判定(与执行分离: dragover 时即给视觉反馈)
// 注意: p 必须作参数传入 —— drop 处理里会先 clearDrop() 置空 dragging,
// 若内部再读 dragging 就会永远拿到 null 恒判非法(浏览器 E2E 实测抓出的真 bug)
function evalDrop(e, zone, isChild, p) {
  if (!p || !zone) return { zone: '', valid: false }
  if (p.kind === 'asset') {
    if (p.ref.startsWith('absent:')) return { zone: '', valid: false } // 快照 ghost 不进可编辑维度
    if (isChild) return { zone, valid: e.kind === 'folder' } // 二级行只接受目录
    if (zone === 'inside') return { zone: 'inside', valid: e.kind === 'folder' } // 移入目录
    return { zone, valid: e.kind === 'single' } // 前/后: 目标是独立资产行 = 退回独立
  }
  // p.kind === 'entry'
  if (isChild) return { zone: '', valid: false } // 一级节点不能插进二级
  if (zone === 'inside') {
    // 只有"独立资产一级行 拖进 目录"是归属变更
    return { zone: 'inside', valid: e.kind === 'folder' && p.key.startsWith('a:') }
  }
  return { zone, valid: p.key !== e.key } // 一级重排
}

function onDragOver(e, ev, childIndex) {
  ev.preventDefault()
  const rect = ev.currentTarget.getBoundingClientRect()
  const zone = zoneOf(ev, rect)
  const res = evalDrop(e, zone, childIndex != null, dragging)
  drop.key = childIndex != null ? e.key + '#' + childIndex : e.key
  drop.zone = res.zone
  drop.valid = res.valid
  ev.dataTransfer.dropEffect = res.valid ? 'move' : 'none'
}

function onDropOnEntry(e, ev) {
  ev.preventDefault()
  const p = dragging
  clearDrop()
  if (!p) return
  const rect = ev.currentTarget.getBoundingClientRect()
  const zone = zoneOf(ev, rect)
  const res = evalDrop(e, zone, false, p)
  if (!res.valid) { flash(dropMsg(e, p)); return }

  if (p.kind === 'entry') {
    if (res.zone === 'inside') {
      moveAsset(p.key.slice(2), e.key, -1) // 独立资产一级行 拖入 目录
    } else {
      reorderEntry(p.key, e.key, res.zone === 'before')
    }
  } else {
    if (res.zone === 'inside') {
      moveAsset(p.ref, e.key, -1) // 移入目录末尾
    } else {
      moveAssetToSingle(p.ref, e.key, res.zone === 'before')
    }
  }
  emit('changed')
  drawLines()
}

// 二级行落点: 插入到目录 children 的 childIndex 前/后(childIndex 为真实下标)
function onDropOnChild(e, c, childIndex, ev) {
  ev.preventDefault()
  const p = dragging
  const after = drop.zone === 'after' // 必须在 clearDrop() 前读, 否则恒为假
  clearDrop()
  if (!p) return
  if (e.kind !== 'folder') { flash('扫描快照是只读历史, 不能往里放资产'); return }
  if (p.kind === 'asset') {
    if (p.ref.startsWith('absent:')) { flash('快照中的历史资产不能拖入目录'); return }
    let idx = childIndex + (after ? 1 : 0)
    if (p.fromKey === e.key) {
      const fromIdx = (e.node.children || []).indexOf(p.ref)
      if (fromIdx >= 0 && fromIdx < idx) idx-- // 同目录内下移: 先剔除再插入, 下标前移
    }
    if (!moveAsset(p.ref, e.key, idx)) flash('移动失败')
  } else if (p.kind === 'entry' && p.key.startsWith('a:')) {
    // 独立资产一级行拖进目录二级位置
    if (!moveAsset(p.key.slice(2), e.key, childIndex + (after ? 1 : 0))) flash('移动失败')
  } else {
    flash('目录不能放进另一个目录')
    return
  }
  emit('changed')
  drawLines()
}

function clearDrop() {
  drop.key = ''
  drop.zone = ''
  drop.valid = false
  dragging = null
}

// 独立资产行拖到另一独立资产行前/后 = 保持独立, 换位置
function moveAssetToSingle(assetId, targetKey, before) {
  if (before) {
    moveAsset(assetId, targetKey)
    return
  }
  const i = state.order.indexOf(targetKey)
  let j = i + 1
  while (j < state.order.length && !state.order[j].startsWith('a:')) j++
  if (j < state.order.length) moveAsset(assetId, state.order[j])
  else moveAsset(assetId, 'a:' + assetId) // 没有更后的独立行: 落到末尾
}

function dropMsg(e, p) {
  if (p.kind === 'entry' && e.kind !== 'single') return '该位置不能放置此类节点'
  if (e.kind === 'scan') return '扫描快照是只读历史'
  return '该位置不能放置此类节点'
}
function flash(msg) { alert(msg) }

// ===== SVG 连接线(原生) =====
//
// 纵向文件树布局: 每个有可见子节点的父行画"父行 → 子行"肘形线:
//   父行左缘中部 → 水平到 midX → 垂直干到每个子行 → 水平接到子行左缘
// 位置全部按 DOM 实测(相对容器), 数据/展开/筛选/窗口尺寸变化时重算。

const wrapRef = ref(null)
const rowRefs = new Map()
const linePaths = ref([])
const box = reactive({ w: 0, h: 0 })

function setRowRef(key, el) {
  if (el) rowRefs.set(key, el)
  else rowRefs.delete(key)
}

function drawLines() {
  nextTick(() => {
    const wrap = wrapRef.value
    if (!wrap) return
    const wr = wrap.getBoundingClientRect()
    const paths = []
    for (const e of visibleEntries.value) {
      if (e.kind !== 'folder' && e.kind !== 'scan') continue
      if (!isExpanded(e.node.nodeId)) continue
      const kids = visibleChildren(e)
      if (!kids.length) continue
      const pEl = rowRefs.get(e.key)
      if (!pEl) continue
      const pr = pEl.getBoundingClientRect()
      const px = pr.left - wr.left + 16 // 父行 caret 列右缘
      const py = pr.top - wr.top + pr.height / 2
      const segs = []
      for (const c of kids) {
        const cEl = rowRefs.get(e.key + '#' + e.children.indexOf(c))
        if (!cEl) continue
        const cr = cEl.getBoundingClientRect()
        segs.push({ cx: cr.left - wr.left + 22, cy: cr.top - wr.top + cr.height / 2 })
      }
      if (!segs.length) continue
      const midX = px + 8
      let d = `M ${px} ${py} L ${midX} ${py}`
      d += ` M ${midX} ${py} L ${midX} ${segs[segs.length - 1].cy}`
      for (const s of segs) d += ` M ${midX} ${s.cy} L ${s.cx} ${s.cy}`
      paths.push(d)
    }
    linePaths.value = paths
    box.w = Math.max(1, Math.ceil(wr.width))
    box.h = Math.max(1, Math.ceil(wr.height))
  })
}

let ro = null
function onResize() { drawLines() }
onMounted(() => {
  drawLines()
  window.addEventListener('resize', onResize)
  if (typeof ResizeObserver !== 'undefined' && wrapRef.value) {
    ro = new ResizeObserver(() => drawLines())
    ro.observe(wrapRef.value)
  }
  // 深链: /assets?tab=tree&focus=<assetId> → 展开归属目录并滚动高亮
  if (route.query.focus) locateAsset(String(route.query.focus))
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  if (ro) ro.disconnect()
})

watch([visibleEntries, q, typeF], () => drawLines())
watch(() => state.expanded, () => drawLines(), { deep: true })

// focus 定位(台账表"定位到树" / 深链共用)
const focusKey = ref('')
function locateAsset(assetId) {
  const key = focusKeyOf(assetId)
  if (!key) return
  nextTick(() => {
    const el = rowRefs.get(key)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' })
      focusKey.value = key
      setTimeout(() => { if (focusKey.value === key) focusKey.value = '' }, 2500)
    }
  })
}

defineExpose({ locateAsset })
</script>

<style scoped>
.atree {
  position: relative;
  padding: 6px 10px 12px;
  min-height: 60px;
}
.atree-lines {
  position: absolute;
  left: 0;
  top: 0;
  pointer-events: none;
  z-index: 0;
}
.atree-lines path {
  fill: none;
  stroke: var(--border2, #2a3548);
  stroke-width: 1.5;
}
.atree-item { position: relative; z-index: 1; }
.atree-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  border: 1px solid var(--border2, #2a3548);
  border-radius: 8px;
  margin: 4px 0;
  background: var(--bg2, rgba(255, 255, 255, .02));
  cursor: default;
  transition: border-color .12s, background .12s;
  min-height: 34px;
}
.atree-row.l1 { cursor: grab; }
.atree-row.l1:hover { border-color: var(--blue, #60a5fa); }
.atree-row.l2 {
  margin-left: 26px;
  padding: 5px 10px;
  font-size: 13px;
  background: transparent;
  min-height: 30px;
}
.atree-row.l2[draggable="true"] { cursor: grab; }
.atree-row.l2:hover { border-color: var(--blue, #60a5fa); }
.atree-row .atree-name { font-weight: 600; }
.atree-row .mono { font-size: 12.5px; }
.caret {
  width: 16px;
  text-align: center;
  cursor: pointer;
  color: var(--muted);
  flex: none;
  user-select: none;
}
.caret.ghost { cursor: default; }
.tp {
  flex: none;
  font-size: 11px;
  font-weight: 700;
  padding: 1px 8px;
  border-radius: 999px;
  border: 1px solid;
}
.tp-folder { color: var(--yellow, #facc15); border-color: rgba(250, 204, 21, .5); background: rgba(250, 204, 21, .08); }
.tp-scan { color: var(--blue, #60a5fa); border-color: rgba(96, 165, 250, .5); background: rgba(96, 165, 250, .08); }
.tp-monitor { color: var(--green, #34d399); border-color: rgba(52, 211, 153, .5); background: rgba(52, 211, 153, .08); }
.tp-single { color: var(--muted, #8b98ad); border-color: var(--border2, #2a3548); background: transparent; }
.cnt-folder { color: var(--yellow, #facc15); }
.cnt-scan { color: var(--blue, #60a5fa); }
/* 拖拽落点指示 */
.atree-drop-before { border-top: 2px solid var(--green, #34d399); }
.atree-drop-after { border-bottom: 2px solid var(--green, #34d399); }
.atree-drop-inside {
  background: rgba(52, 211, 153, .08);
  border-color: var(--green, #34d399);
  box-shadow: inset 0 0 0 1px rgba(52, 211, 153, .35);
}
.atree-nodrop {
  opacity: .55;
  border-color: var(--red, #f87171);
}
/* focus 定位高亮(2.5s 自动消退) */
.atree-focus {
  outline: 2px solid var(--green, #34d399);
  outline-offset: 1px;
}
.row-actions { margin-left: auto; flex: none; }
.atree-children { padding-bottom: 2px; }
</style>
