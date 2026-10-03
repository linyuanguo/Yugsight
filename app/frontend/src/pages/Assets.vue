<template>
  <div>
    <PageHeader title="资产管理" desc="统一资产台账: 二级混合树(扫描快照 / 自定义目录 / 监控设备 / 独立资产) + 台账明细表">
      <button class="btn sm primary" @click="openAdd">新增资产</button>
    </PageHeader>

    <!-- 双 tab(2026-09-28 资产树重构): tab 状态放 URL query(先例 /env?tab=rules),
         刷新/书签/深链(/assets?tab=tree&focus=<id>)都能停在同一视图 -->
    <div class="tabs">
      <div class="tab" :class="{ active: tab === 'tree' }" @click="setTab('tree')">资产树</div>
      <div class="tab" :class="{ active: tab === 'list' }" @click="setTab('list')">台账表</div>
    </div>

    <!-- ===== Tab1: 二级混合树 ===== -->
    <AssetTree v-if="tab === 'tree'" @edit="openEdit" @locate="locateInTree" @changed="load" />

    <!-- ===== Tab2: 台账明细表(原有功能原样保留) ===== -->
    <div v-else>
      <div class="card">
        <div class="toolbar">
          <input class="input" v-model.trim="filter.ip" placeholder="按 IP 过滤" @keyup.enter="reload">
          <input class="input" v-model.trim="filter.tag" placeholder="按标签过滤" @keyup.enter="reload">
          <button class="btn sm" @click="reload">查询</button>
          <button class="btn sm" @click="resetFilter">清空</button>
          <label style="display:inline-flex;align-items:center;gap:5px;font-size:13px;cursor:pointer;user-select:none"><input type="checkbox" v-model="onlyAlive" @change="reload"> 只看存活</label>
          <button class="btn sm danger" @click="cleanDead">清理未存活</button>
          <button class="btn sm danger" @click="cleanArpGhosts">清理幽灵资产</button>
          <!-- 删除选中(批量): 表格 checkbox 勾选, 走 /assets/batch-delete -->
          <button class="btn sm danger" :disabled="!sel.length || busy" @click="batchDel">
            删除选中{{ sel.length ? ' (' + sel.length + ')' : '' }}
          </button>
          <div class="spacer"></div>
          <span class="muted small">共 {{ total }} 台主机</span>
        </div>

        <div class="table-wrap" v-if="list.length">
          <table class="table">
            <thead>
              <tr>
                <th style="width:30px"><input type="checkbox" :checked="allSel" @change="toggleAll" :disabled="!list.length" title="全选/取消本页"></th>
                <th>IP</th><th>存活</th><th>主机名</th><th>操作系统</th><th>主服务</th>
                <th>开放端口</th><th>探针节点</th><th>标签</th><th>发现时间</th><th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="a in list" :key="a.id">
                <td><input type="checkbox" :checked="sel.includes(a.id)" @change="toggleSel(a.id)"></td>
                <td class="mono">{{ a.ip }}</td>
                <!-- 存活: 最近一轮扫描的判定(Alive 由存活扫描回写, 见 scan_persist.go) -->
                <td>
                  <span class="badge" :class="a.alive ? 'st-success' : 'st-failed'">{{ a.alive ? '存活' : '未存活' }}</span>
                </td>
                <td>{{ a.hostname || '-' }}</td>
                <td>{{ a.os || '-' }}</td>
                <td>{{ a.service ? a.service + (a.version ? ' ' + a.version : '') : '-' }}</td>
                <td class="mono small" :title="(a.ports || []).join(', ')">
                  {{ (a.ports || []).length ? (a.ports || []).slice(0, 6).join(', ') + ((a.ports || []).length > 6 ? ' …' : '') : '-' }}
                </td>
                <td v-if="a.probeNode">{{ a.probeNode }}</td>
                <td v-else class="muted">本地</td>
                <td>
                  <span class="tag" v-for="t in a.tags" :key="t">{{ t }}
                    <button title="移除标签" @click="removeTag(a, t)">×</button>
                  </span>
                  <span class="muted small" v-if="!a.tags || !a.tags.length">-</span>
                </td>
                <td class="muted small mono">{{ fmtDT(a.foundAt) }}</td>
                <td>
                  <div class="row-actions">
                    <button class="btn xs" @click="openEdit(a)">编辑</button>
                    <button class="btn xs" @click="openTag(a)">加标签</button>
                    <button class="btn xs" @click="locateInTree(a)" title="到资产树中定位这台资产">树</button>
                    <button class="btn xs danger" @click="del(a)">删除</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="filter.ip || filter.tag ? '无匹配资产' : '暂无资产, 可手动新增或等待扫描管线回传'" />

        <div class="pager" v-if="total > page * size">
          <span>第 {{ page }} 页</span>
          <div class="spacer"></div>
          <button class="btn xs" :disabled="page <= 1" @click="page--; load()">上一页</button>
          <button class="btn xs" :disabled="page * size >= total" @click="page++; load()">下一页</button>
        </div>
      </div>
    </div>

    <!-- 新增/编辑(树/表两 tab 共用; 新增时可选归属目录) -->
    <Modal v-if="showForm" :title="editing ? '编辑资产' : '新增资产'" @close="showForm = false">
      <div class="field"><label class="label">IP *</label>
        <input class="input mono" v-model.trim="form.ip" :disabled="!!editing" placeholder="如 192.168.1.10"></div>
      <div class="form-row">
        <div class="field"><label class="label">MAC</label>
          <input class="input mono" v-model.trim="form.mac" placeholder="可选"></div>
        <div class="field"><label class="label">主机名</label>
          <input class="input" v-model.trim="form.hostname" placeholder="可选"></div>
      </div>
      <div class="form-row">
        <div class="field"><label class="label">操作系统</label>
          <input class="input" v-model.trim="form.os" placeholder="如 Windows Server 2019"></div>
        <div class="field"><label class="label">探针节点</label>
          <input class="input" v-model.trim="form.probeNode" placeholder="空 = 本地"></div>
      </div>
      <div class="form-row">
        <div class="field"><label class="label">主服务</label>
          <input class="input" v-model.trim="form.service" placeholder="如 http / ssh"></div>
        <div class="field"><label class="label">服务版本</label>
          <input class="input" v-model.trim="form.version" placeholder="如 nginx 1.24.0"></div>
      </div>
      <div class="field"><label class="label">Banner</label>
        <input class="input mono" v-model.trim="form.banner" placeholder="服务横幅(可选)"></div>
      <div class="form-row">
        <div class="field"><label class="label">开放端口(逗号分隔)</label>
          <input class="input mono" v-model="form.portsStr" placeholder="如 22,80,443,3389"></div>
        <div class="field"><label class="label">标签(逗号分隔)</label>
          <input class="input" v-model="form.tagsStr" placeholder="如 core,finance"></div>
      </div>
      <!-- 2026-09-28 资产树: 新增资产可选归属目录(留空 = 独立资产一级节点);
           编辑不改归属(归属调整走资产树拖拽), 所以只在新增时显示 -->
      <div class="field" v-if="!editing"><label class="label">归属目录(资产树)</label>
        <select class="input" v-model="form.folder">
          <option value="">独立资产(树顶层)</option>
          <option v-for="f in folderOptions" :key="f.nodeId" :value="f.nodeId">{{ f.name }}</option>
        </select>
      </div>
      <div class="login-err" style="text-align:left">{{ formErr }}</div>
      <template #footer>
        <button class="btn" @click="showForm = false">取消</button>
        <button class="btn primary" :disabled="busy" @click="save">{{ busy ? '保存中...' : '保存' }}</button>
      </template>
    </Modal>

    <!-- 加标签 -->
    <Modal v-if="showTag" title="添加标签" width="420px" @close="showTag = false">
      <div class="field"><label class="label">标签(逗号分隔可多个)</label>
        <input class="input" v-model="tagInput" placeholder="如 test,web" @keyup.enter="addTag"></div>
      <div class="login-err" style="text-align:left">{{ formErr }}</div>
      <template #footer>
        <button class="btn" @click="showTag = false">取消</button>
        <button class="btn primary" :disabled="busy" @click="addTag">添加</button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import Modal from '../components/Modal.vue'
import Empty from '../components/Empty.vue'
import AssetTree from './assets/AssetTree.vue'
import { entries as treeEntries, moveAsset } from './assets/treeStore'
import { v2 } from '../api/http'
import { fmtDT } from '../utils'

// ===== tab 状态(URL query 驱动, 与 /env?tab=rules 同口径) =====
const route = useRoute()
const router = useRouter()
const tab = computed(() => (route.query.tab === 'list' ? 'list' : 'tree'))
function setTab(t) {
  if (t === tab.value) return
  router.replace({ query: t === 'list' ? { tab: 'list' } : {} })
}

// ===== 台账表(原有功能) =====
const list = ref([])
const total = ref(0)
const page = ref(1)
const size = 20
const busy = ref(false)
const filter = reactive({ ip: '', tag: '' })
const onlyAlive = ref(true) // 只看存活(默认开: 隐藏从未存活过的探测噪声)
// 选中态(删除选中): 存 id 数组, 跨页保留, 翻页后过滤掉不在列表的
const sel = ref([])
const allSel = computed(() => list.value.length > 0 && list.value.every(a => sel.value.includes(a.id)))
function toggleSel(id) {
  const i = sel.value.indexOf(id)
  if (i >= 0) sel.value.splice(i, 1)
  else sel.value.push(id)
}
function toggleAll() {
  sel.value = allSel.value ? [] : list.value.map(a => a.id)
}

const showForm = ref(false)
const editing = ref(null)
const showTag = ref(false)
const tagTarget = ref(null)
const tagInput = ref('')
const formErr = ref('')
const form = reactive({
  ip: '', mac: '', hostname: '', os: '', service: '', version: '',
  banner: '', probeNode: '', portsStr: '', tagsStr: '', folder: ''
})

// 新增资产的归属目录选项(来自资产树 store 的目录节点)
const folderOptions = computed(() =>
  treeEntries.value.filter(e => e.kind === 'folder'))

function resetForm() {
  Object.assign(form, {
    ip: '', mac: '', hostname: '', os: '', service: '', version: '',
    banner: '', probeNode: '', portsStr: '', tagsStr: '', folder: ''
  })
  formErr.value = ''
}

async function load() {
  const p = new URLSearchParams({ page: String(page.value), size: String(size) })
  if (filter.ip) p.set('ip', filter.ip)
  if (filter.tag) p.set('tag', filter.tag)
  if (onlyAlive.value) p.set('alive', '1')
  const d = await v2('/assets?' + p.toString())
  list.value = d.list || []
  total.value = d.total || 0
  // 选中项只保留当前仍存在的(删掉/筛选变化的 id 不再可操作)
  sel.value = sel.value.filter(id => list.value.some(a => a.id === id))
}

function reload() { page.value = 1; load().catch(e => (formErr.value = e.message)) }
function resetFilter() { filter.ip = ''; filter.tag = ''; reload() }

function openAdd() { resetForm(); editing.value = null; showForm.value = true }
function openEdit(a) {
  editing.value = a
  Object.assign(form, {
    ip: a.ip, mac: a.mac || '', hostname: a.hostname || '', os: a.os || '',
    service: a.service || '', version: a.version || '', banner: a.banner || '',
    probeNode: a.probeNode || '',
    portsStr: (a.ports || []).join(','), tagsStr: (a.tags || []).join(','), folder: ''
  })
  formErr.value = ''
  showForm.value = true
}

async function save() {
  formErr.value = ''
  busy.value = true
  try {
    const body = {
      ip: form.ip, mac: form.mac, hostname: form.hostname, os: form.os,
      service: form.service, version: form.version, banner: form.banner,
      probeNode: form.probeNode,
      ports: form.portsStr.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n)),
      tags: form.tagsStr.split(',').map(s => s.trim()).filter(Boolean)
    }
    if (editing.value) {
      await v2('/assets/' + editing.value.id, { method: 'PUT', body })
    } else {
      const r = await v2('/assets', { method: 'POST', body })
      // 新增 + 选了归属目录: 把新资产挂进目录(树侧动作, 失败不阻断台账写入)
      if (form.folder && r && r.asset && r.asset.id) {
        try {
          moveAsset(r.asset.id, 'f:' + form.folder, -1)
        } catch (e) { console.warn('归属目录写入失败:', e) }
      }
    }
    showForm.value = false
    await load()
  } catch (e) { formErr.value = e.message } finally { busy.value = false }
}

async function del(a) {
  if (!confirm('确认删除资产 ' + a.ip + ' ?')) return
  try { await v2('/assets/' + a.id, { method: 'DELETE' }); await load() }
  catch (e) { alert(e.message) }
}

// 批量删除选中(走 /assets/batch-delete, 后端上限 500/次)
async function batchDel() {
  const n = sel.value.length
  if (!n) return
  if (n > 500) { alert('单次最多删除 500 条'); return }
  const ips = list.value.filter(a => sel.value.includes(a.id)).map(a => a.ip)
  const preview = ips.slice(0, 10).join(', ') + (ips.length > 10 ? ' 等 ' + ips.length + ' 台' : '')
  if (!confirm('确认删除选中的 ' + n + ' 台资产?\n' + preview + '\n\n删除后不可恢复, 继续?')) return
  busy.value = true
  try {
    const r = await v2('/assets/batch-delete', { method: 'POST', body: { ids: sel.value } })
    alert('已删除 ' + (r.deleted || 0) + ' 台资产')
    sel.value = []
    await load()
  } catch (e) {
    alert(e.message)
  } finally { busy.value = false }
}

// 清理所有未存活(Alive=false)资产: 先查未存活数量, 确认框展示将删 N 台,
// 再批量删(曾上线后下线的资产 Alive=true, 不受影响)。
async function cleanDead() {
  try {
    const d = await v2('/assets?alive=0&page=1&size=1')
    const n = d.total || 0
    if (n === 0) { alert('没有未存活资产可清理'); return }
    if (!confirm(`确认清理所有「未存活」资产？\n将删除 ${n} 台(删除后不可恢复)。\n\n曾上线后下线的资产不受影响(它们始终显示存活)。`)) return
    const r = await v2('/assets/dead', { method: 'DELETE' })
    alert('已清理 ' + (r.deleted || 0) + ' 台未存活资产')
    await load()
  } catch (e) { alert(e.message) }
}

// 清理代理 ARP 幽灵资产: 先预览(同 MAC 分组/真身/将删清单), 确认后再删。
async function cleanArpGhosts() {
  try {
    const p = await v2('/assets/arp-ghosts')
    if (!p.count) { alert('未检测到代理 ARP 幽灵资产'); return }
    let msg = `检测到 ${p.count} 个幽灵资产将删除:\n`
    for (const g of (p.groups || [])) {
      if (g.unresolved) {
        msg += `\nMAC ${g.mac}: ${g.ips.length} 台同 MAC 但无真身证据, 不删(需人工复核)`
      } else if (g.ghosts && g.ghosts.length) {
        msg += `\nMAC ${g.mac}: 真身 ${(g.real || []).join(', ')} 保留, 删 ${g.ghosts.length} 个`
      }
    }
    if (!confirm(msg + '\n\n删除后不可恢复, 继续?')) return
    const r = await v2('/assets/arp-ghosts/cleanup', { method: 'POST' })
    alert('已删除 ' + (r.deleted || 0) + ' 个幽灵资产')
    await load()
  } catch (e) { alert(e.message) }
}

function openTag(a) { tagTarget.value = a; tagInput.value = ''; formErr.value = ''; showTag.value = true }

async function addTag() {
  const tags = tagInput.value.split(',').map(s => s.trim()).filter(Boolean)
  if (!tags.length) return
  formErr.value = ''
  busy.value = true
  try {
    await v2('/assets/' + tagTarget.value.id + '/tags', { method: 'POST', body: { tags } })
    showTag.value = false
    await load()
  } catch (e) { formErr.value = e.message } finally { busy.value = false }
}

async function removeTag(a, tag) {
  try {
    await v2('/assets/' + a.id + '/tags', { method: 'DELETE', body: { tags: [tag] } })
    await load()
  } catch (e) { alert(e.message) }
}

// 台账表 → 资产树 联动: 切到树 tab 并定位高亮该资产(AssetTree 读 focus 深链)
function locateInTree(a) {
  router.replace({ query: { focus: a.id } })
}

load().catch(e => (formErr.value = e.message))
</script>
