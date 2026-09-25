<template>
  <div>
    <PageHeader title="资产管理" desc="主机资产台账">
      <button class="btn sm primary" @click="openAdd">新增资产</button>
    </PageHeader>

    <div class="card">
      <div class="toolbar">
        <input class="input" v-model.trim="filter.ip" placeholder="按 IP 过滤" @keyup.enter="reload">
        <input class="input" v-model.trim="filter.tag" placeholder="按标签过滤" @keyup.enter="reload">
        <button class="btn sm" @click="reload">查询</button>
        <button class="btn sm" @click="resetFilter">清空</button>
        <div class="spacer"></div>
        <span class="muted small">共 {{ total }} 台主机</span>
      </div>

      <div class="table-wrap" v-if="list.length">
        <table class="table">
          <thead>
            <tr>
              <th>IP</th><th>存活</th><th>主机名</th><th>操作系统</th><th>主服务</th>
              <th>开放端口</th><th>探针节点</th><th>标签</th><th>发现时间</th><th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in list" :key="a.id">
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
              <td>{{ a.probeNode || '<span class="muted">本地</span>' }}</td>
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

    <!-- 新增/编辑 -->
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
import { ref, reactive } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import Modal from '../components/Modal.vue'
import Empty from '../components/Empty.vue'
import { v2 } from '../api/http'
import { fmtDT } from '../utils'

const list = ref([])
const total = ref(0)
const page = ref(1)
const size = 20
const busy = ref(false)
const filter = reactive({ ip: '', tag: '' })

const showForm = ref(false)
const editing = ref(null)
const showTag = ref(false)
const tagTarget = ref(null)
const tagInput = ref('')
const formErr = ref('')
const form = reactive({
  ip: '', mac: '', hostname: '', os: '', service: '', version: '',
  banner: '', probeNode: '', portsStr: '', tagsStr: ''
})

function resetForm() {
  Object.assign(form, {
    ip: '', mac: '', hostname: '', os: '', service: '', version: '',
    banner: '', probeNode: '', portsStr: '', tagsStr: ''
  })
  formErr.value = ''
}

async function load() {
  const p = new URLSearchParams({ page: String(page.value), size: String(size) })
  if (filter.ip) p.set('ip', filter.ip)
  if (filter.tag) p.set('tag', filter.tag)
  const d = await v2('/assets?' + p.toString())
  list.value = d.list || []
  total.value = d.total || 0
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
    portsStr: (a.ports || []).join(','), tagsStr: (a.tags || []).join(',')
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
      await v2('/assets', { method: 'POST', body })
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

load().catch(e => (formErr.value = e.message))
</script>
