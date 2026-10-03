<template>
  <div>
    <PageHeader :title="t('as.title')" :desc="t('as.desc')">
      <button class="btn sm primary" @click="openAdd">{{ t('as.add') }}</button>
    </PageHeader>

    <!-- 双 tab(2026-09-28 资产树重构): tab 状态放 URL query(先例 /env?tab=rules),
         刷新/书签/深链(/assets?tab=tree&focus=<id>)都能停在同一视图 -->
    <div class="tabs">
      <div class="tab" :class="{ active: tab === 'tree' }" @click="setTab('tree')">{{ t('as.tabTree') }}</div>
      <div class="tab" :class="{ active: tab === 'list' }" @click="setTab('list')">{{ t('as.tabList') }}</div>
    </div>

    <!-- ===== Tab1: 二级混合树 ===== -->
    <AssetTree v-if="tab === 'tree'" @edit="openEdit" @locate="locateInTree" @changed="load" />

    <!-- ===== Tab2: 台账明细表(原有功能原样保留) ===== -->
    <div v-else>
      <div class="card">
        <div class="toolbar">
          <input class="input" v-model.trim="filter.ip" :placeholder="t('as.fIp')" @keyup.enter="reload">
          <input class="input" v-model.trim="filter.tag" :placeholder="t('as.fTag')" @keyup.enter="reload">
          <button class="btn sm" @click="reload">{{ t('as.query') }}</button>
          <button class="btn sm" @click="resetFilter">{{ t('as.reset') }}</button>
          <label style="display:inline-flex;align-items:center;gap:5px;font-size:13px;cursor:pointer;user-select:none"><input type="checkbox" v-model="onlyAlive" @change="reload"> {{ t('as.onlyAlive') }}</label>
          <button class="btn sm danger" @click="cleanDead">{{ t('as.cleanDead') }}</button>
          <button class="btn sm danger" @click="cleanArpGhosts">{{ t('as.cleanGhosts') }}</button>
          <!-- 删除选中(批量): 表格 checkbox 勾选, 走 /assets/batch-delete -->
          <button class="btn sm danger" :disabled="!sel.length || busy" @click="batchDel">
            {{ t('as.delSel') }}{{ sel.length ? ' (' + sel.length + ')' : '' }}
          </button>
          <div class="spacer"></div>
          <span class="muted small">{{ t('as.totalHosts', { n: total }) }}</span>
        </div>

        <div class="table-wrap" v-if="list.length">
          <table class="table">
            <thead>
              <tr>
                <th style="width:30px"><input type="checkbox" :checked="allSel" @change="toggleAll" :disabled="!list.length" :title="t('as.selAll')"></th>
                <th>IP</th><th>{{ t('as.cAlive') }}</th><th>{{ t('as.cHost') }}</th><th>{{ t('as.cOs') }}</th><th>{{ t('as.cService') }}</th>
                <th>{{ t('as.cPorts') }}</th><th>{{ t('as.cProbe') }}</th><th>{{ t('as.cTags') }}</th><th>{{ t('as.cFound') }}</th><th>{{ t('pb.cOp') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="a in list" :key="a.id">
                <td><input type="checkbox" :checked="sel.includes(a.id)" @change="toggleSel(a.id)"></td>
                <td class="mono">{{ a.ip }}</td>
                <!-- 存活: 最近一轮扫描的判定(Alive 由存活扫描回写, 见 scan_persist.go) -->
                <td>
                  <span class="badge" :class="a.alive ? 'st-success' : 'st-failed'">{{ a.alive ? t('as.alive') : t('as.dead') }}</span>
                </td>
                <td>{{ a.hostname || '-' }}</td>
                <td>{{ a.os || '-' }}</td>
                <td>{{ a.service ? a.service + (a.version ? ' ' + a.version : '') : '-' }}</td>
                <td class="mono small" :title="(a.ports || []).join(', ')">
                  {{ (a.ports || []).length ? (a.ports || []).slice(0, 6).join(', ') + ((a.ports || []).length > 6 ? ' …' : '') : '-' }}
                </td>
                <td v-if="a.probeNode">{{ a.probeNode }}</td>
                <td v-else class="muted">{{ t('as.local') }}</td>
                <td>
                  <span class="tag" v-for="t in a.tags" :key="t">{{ t }}
                    <button :title="t('as.rmTag')" @click="removeTag(a, t)">×</button>
                  </span>
                  <span class="muted small" v-if="!a.tags || !a.tags.length">-</span>
                </td>
                <td class="muted small mono">{{ fmtDT(a.foundAt) }}</td>
                <td>
                  <div class="row-actions">
                    <button class="btn xs" @click="openEdit(a)">{{ t('common.edit') }}</button>
                    <button class="btn xs" @click="openTag(a)">{{ t('as.addTag') }}</button>
                    <button class="btn xs" @click="locateInTree(a)" :title="t('as.locateTree')">{{ t('as.tree') }}</button>
                    <button class="btn xs danger" @click="del(a)">{{ t('common.del') }}</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="filter.ip || filter.tag ? t('as.noMatch') : t('as.noAssets')" />

        <div class="pager" v-if="total > page * size">
          <span>{{ t('as.pageOf', { p: page }) }}</span>
          <div class="spacer"></div>
          <button class="btn xs" :disabled="page <= 1" @click="page--; load()">{{ t('al.prev') }}</button>
          <button class="btn xs" :disabled="page * size >= total" @click="page++; load()">{{ t('al.next') }}</button>
        </div>
      </div>
    </div>

    <!-- 新增/编辑(树/表两 tab 共用; 新增时可选归属目录) -->
    <Modal v-if="showForm" :title="editing ? t('as.edit') : t('as.add')" @close="showForm = false">
      <div class="field"><label class="label">IP *</label>
        <input class="input mono" v-model.trim="form.ip" :disabled="!!editing" :placeholder="t('as.phIp')"></div>
      <div class="form-row">
        <div class="field"><label class="label">MAC</label>
          <input class="input mono" v-model.trim="form.mac" :placeholder="t('as.phOpt')"></div>
        <div class="field"><label class="label">{{ t('as.cHost') }}</label>
          <input class="input" v-model.trim="form.hostname" :placeholder="t('as.phOpt')"></div>
      </div>
      <div class="form-row">
        <div class="field"><label class="label">{{ t('as.cOs') }}</label>
          <input class="input" v-model.trim="form.os" :placeholder="t('as.phOs')"></div>
        <div class="field"><label class="label">{{ t('as.cProbe') }}</label>
          <input class="input" v-model.trim="form.probeNode" :placeholder="t('as.phProbe')"></div>
      </div>
      <div class="form-row">
        <div class="field"><label class="label">{{ t('as.cService') }}</label>
          <input class="input" v-model.trim="form.service" :placeholder="t('as.phService')"></div>
        <div class="field"><label class="label">{{ t('as.cVer') }}</label>
          <input class="input" v-model.trim="form.version" :placeholder="t('as.phVer')"></div>
      </div>
      <div class="field"><label class="label">Banner</label>
        <input class="input mono" v-model.trim="form.banner" :placeholder="t('as.phBanner')"></div>
      <div class="form-row">
        <div class="field"><label class="label">{{ t('as.fPorts') }}</label>
          <input class="input mono" v-model="form.portsStr" :placeholder="t('as.phPorts')"></div>
        <div class="field"><label class="label">{{ t('as.fTags') }}</label>
          <input class="input" v-model="form.tagsStr" :placeholder="t('as.phTags')"></div>
      </div>
      <!-- 2026-09-28 资产树: 新增资产可选归属目录(留空 = 独立资产一级节点);
           编辑不改归属(归属调整走资产树拖拽), 所以只在新增时显示 -->
      <div class="field" v-if="!editing"><label class="label">{{ t('as.folder') }}</label>
        <select class="input" v-model="form.folder">
          <option value="">{{ t('as.standalone') }}</option>
          <option v-for="f in folderOptions" :key="f.nodeId" :value="f.nodeId">{{ f.name }}</option>
        </select>
      </div>
      <div class="login-err" style="text-align:left">{{ formErr }}</div>
      <template #footer>
        <button class="btn" @click="showForm = false">{{ t('common.cancel') }}</button>
        <button class="btn primary" :disabled="busy" @click="save">{{ busy ? t('pb.saving') : t('common.save') }}</button>
      </template>
    </Modal>

    <!-- 加标签 -->
    <Modal v-if="showTag" :title="t('as.addTag')" width="420px" @close="showTag = false">
      <div class="field"><label class="label">{{ t('as.fTagsMulti') }}</label>
        <input class="input" v-model="tagInput" :placeholder="t('as.phTags2')" @keyup.enter="addTag"></div>
      <div class="login-err" style="text-align:left">{{ formErr }}</div>
      <template #footer>
        <button class="btn" @click="showTag = false">{{ t('common.cancel') }}</button>
        <button class="btn primary" :disabled="busy" @click="addTag">{{ t('as.addTagBtn') }}</button>
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
import { t } from '../i18n'

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
  if (!confirm(t('as.delConfirm', { ip: a.ip }))) return
  try { await v2('/assets/' + a.id, { method: 'DELETE' }); await load() }
  catch (e) { alert(e.message) }
}

// 批量删除选中(走 /assets/batch-delete, 后端上限 500/次)
async function batchDel() {
  const n = sel.value.length
  if (!n) return
  if (n > 500) { alert(t('as.batchMax')); return }
  const ips = list.value.filter(a => sel.value.includes(a.id)).map(a => a.ip)
  const preview = ips.slice(0, 10).join(', ') + (ips.length > 10 ? t('as.etC', { n: ips.length }) : '')
  if (!confirm(t('as.batchConfirm', { n, preview }) + '\n\n' + t('as.irreversible'))) return
  busy.value = true
  try {
    const r = await v2('/assets/batch-delete', { method: 'POST', body: { ids: sel.value } })
    alert(t('as.deletedN', { n: r.deleted || 0 }))
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
    if (n === 0) { alert(t('as.noDead')); return }
    if (!confirm(t('as.cleanDeadConfirm', { n }) + '\n\n' + t('as.cleanDeadNote'))) return
    const r = await v2('/assets/dead', { method: 'DELETE' })
    alert(t('as.deadCleaned', { n: r.deleted || 0 }))
    await load()
  } catch (e) { alert(e.message) }
}

// 清理代理 ARP 幽灵资产: 先预览(同 MAC 分组/真身/将删清单), 确认后再删。
async function cleanArpGhosts() {
  try {
    const p = await v2('/assets/arp-ghosts')
    if (!p.count) { alert(t('as.noGhosts')); return }
    let msg = t('as.ghostWillDel', { n: p.count }) + '\n'
    for (const g of (p.groups || [])) {
      if (g.unresolved) {
        msg += `\nMAC ${g.mac}: ` + t('as.ghostUnresolved', { n: g.ips.length })
      } else if (g.ghosts && g.ghosts.length) {
        msg += `\nMAC ${g.mac}: ` + t('as.ghostGroup', { real: (g.real || []).join(', '), n: g.ghosts.length })
      }
    }
    if (!confirm(msg + '\n\n' + t('as.irreversible'))) return
    const r = await v2('/assets/arp-ghosts/cleanup', { method: 'POST' })
    alert(t('as.ghostDeleted', { n: r.deleted || 0 }))
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
