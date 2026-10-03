<!--
  CollectSection.vue 节点监控"采集底座"任务区(按 side 复用, 阶段 1)。

  side=host: 主机侧扩展采集(WinRM / SSH / 主机SNMP) —— 与 yugsight-agent 探针互补:
            探针是自研二进制(需部署), 这里是"无代理"协议, 目标机上装不了探针时用。
  side=net:  网络侧扩展采集(ICMP 链路 / NetFlow·IPFIX / NETCONF / RESTCONF) ——
            与上方 SNMP(monitor 包)互补, SNMP 之外的协议都走这里。

  数据源 /api/v2/node/*(node_api.go 装配层 → collect 包)。口令只回 has* 布尔,
  编辑留空 = 不修改, 与 monitor 目标同一口径。
-->
<template>
  <div class="card">
    <div class="card-title">
      {{ title || t('cs.dftTitle') }}
      <span class="sub">{{ t('cs.taskCnt', { n: tasks.length }) }}</span>
      <div class="spacer"></div>
      <button class="btn xs" @click="collectAll" :disabled="busy || !enabled">{{ t('cs.collectAll') }}</button>
      <button class="btn primary xs" @click="openAdd">＋ {{ t('cs.addTask') }}</button>
    </div>

    <div v-if="!tasks.length" class="empty-box">
      <span class="ph-tag">{{ t('cs.noTasks') }}</span>
      {{ t('cs.noTasksHint') }}
    </div>

    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('nm.colStatus') }}</th><th>{{ t('nm.colName') }}</th><th>{{ t('cs.colProto') }}</th><th>{{ t('cs.colTarget') }}</th>
            <th>{{ t('cs.lastMetrics') }}</th><th>{{ t('nm.colLastCollected') }}</th><th class="a-r">{{ t('nm.colOp') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="tk in tasks" :key="tk.id">
            <td><span class="dot" :class="tk.online ? 'on' : (tk.collected ? 'off' : 'idle')"></span></td>
            <td>
              <div>{{ tk.name || tk.target }}</div>
              <div class="muted small mono" v-if="tk.lastErr">{{ tk.lastErr }}</div>
            </td>
            <td><span class="chip proto">{{ protoLabel(tk.protocol) }}</span></td>
            <td class="mono muted small">{{ tk.target }}</td>
            <td>
              <div class="muted small" v-if="!tk.metrics || !tk.metrics.length">—</div>
              <div v-else class="kv-mini">
                <span v-for="m in topMetrics(tk)" :key="m.name" class="kv-mini-item" :title="metricTitle(m)">
                  {{ m.name }} <b>{{ fmtVal(m) }}</b>
                </span>
              </div>
            </td>
            <td class="mono small muted">{{ fmtDT(t.lastAt) }}<span v-if="t.elapsedMs"> · {{ t.elapsedMs }}ms</span></td>
            <td class="a-r">
              <div class="row-actions">
                <button class="btn xs" @click="collectOne(tk)" :disabled="busy || !enabled">{{ t('cs.collect') }}</button>
                <button class="btn xs" @click="openHistory(tk)">{{ t('cs.history') }}</button>
                <button class="btn xs" @click="openEdit(tk)">{{ t('common.edit') }}</button>
                <button class="btn xs danger" @click="del(tk)">{{ t('common.del') }}</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 添加/编辑任务 -->
    <Modal v-if="showForm" :title="formTitle" @close="closeForm">
      <!-- 快捷模板(2026-09-29 阶段 C, 仅新建): 选模板自动带入协议/参数,
           保存时传 templateId → 后端继承模板默认阈值到该任务(可后改) -->
      <div class="field" v-if="!form.id && sideTemplates.length">
        <label class="lbl">{{ t('cs.quickTpl') }} <span class="muted small">{{ t('cs.quickTplHint') }}</span></label>
        <select class="input" v-model="form.templateId" @change="onTplChange">
          <option value="">{{ t('cs.noTpl') }}</option>
          <option v-for="tp in sideTemplates" :key="tp.id" :value="tp.id">
            {{ tp.name }}（{{ protoLabel(tp.protocol) }}）
          </option>
        </select>
      </div>
      <div class="field">
        <label class="lbl">{{ t('cs.protocol') }} <span class="req">*</span></label>
        <select class="input" v-model="form.protocol" :disabled="!!form.id" @change="onProtoChange">
          <option v-for="p in sideProtocols" :key="p.name" :value="p.name">{{ p.label }}</option>
        </select>
        <div class="muted small" v-if="curProto">{{ curProto.desc }}</div>
      </div>
      <div class="field">
        <label class="lbl">{{ t('cs.target') }} <span class="req">*</span> <span class="muted small" v-if="form.protocol==='netflow'">{{ t('cs.listenAddr') }}</span></label>
        <input class="input" v-model="form.target" :placeholder="targetPlaceholder" />
      </div>
      <div class="field">
        <label class="lbl">{{ t('nm.name') }}</label>
        <input class="input" v-model="form.name" :placeholder="t('cs.namePh')" />
      </div>
      <div class="form-row">
        <div class="field">
          <label class="lbl">{{ t('cs.interval') }}</label>
          <input class="input" type="number" min="0" v-model.number="form.intervalSec" />
        </div>
        <div class="field">
          <label class="lbl">{{ t('cs.timeout') }}</label>
          <input class="input" type="number" min="0" v-model.number="form.timeoutMs" />
        </div>
      </div>
      <template v-if="needCommunity">
        <div class="field">
          <label class="lbl">{{ t('cs.snmpCommunity') }}</label>
          <input class="input" v-model="form.community" placeholder="public" />
        </div>
      </template>
      <template v-if="needUser">
        <div class="form-row">
          <div class="field">
            <label class="lbl">{{ t('nm.username') }}</label>
            <input class="input" v-model="form.user" />
          </div>
          <div class="field">
            <label class="lbl">{{ t('cs.password') }} <span class="muted small" v-if="form.hasAuthPass">{{ t('cs.passSet') }}</span></label>
            <input class="input" type="password" v-model="form.authPass" autocomplete="off" />
          </div>
        </div>
      </template>
      <template v-if="form.protocol==='snmp'">
        <div class="form-row">
          <div class="field">
            <label class="lbl">{{ t('cs.v3Auth') }}</label>
            <select class="input" v-model="form.authProto">
              <option value="">(v2c)</option>
              <option value="md5">MD5</option>
              <option value="sha">SHA</option>
            </select>
          </div>
          <div class="field">
            <label class="lbl">{{ t('cs.v3Priv') }}</label>
            <select class="input" v-model="form.privProto">
              <option value="">{{ t('cs.none') }}</option>
              <option value="des">DES</option>
              <option value="aes">AES</option>
            </select>
          </div>
        </div>
      </template>
      <template v-if="form.protocol==='icmp'">
        <div class="field">
          <label class="lbl">{{ t('cs.probeCount') }}</label>
          <input class="input" type="number" min="1" max="20" v-model.number="form.count" />
        </div>
      </template>
      <template v-if="form.protocol==='restconf'">
        <div class="field">
          <label class="lbl">{{ t('cs.dataPath') }}</label>
          <input class="input" v-model="form.path" placeholder="if:interfaces" />
        </div>
      </template>
      <div class="muted small" v-if="form.protocol==='ssh'">
        {{ t('cs.sshNote') }}
      </div>
      <div class="muted small" v-if="form.protocol==='netconf'">
        {{ t('cs.netconfNote') }}
      </div>
      <div class="form-actions">
        <button class="btn" @click="closeForm">{{ t('common.cancel') }}</button>
        <button class="btn primary" @click="save" :disabled="saving">{{ t('common.save') }}</button>
      </div>
    </Modal>

    <!-- 历史时序 -->
    <Modal v-if="showHistory" :title="t('cs.histTitle', { name: histTask ? (histTask.name || histTask.target) : '' })" @close="showHistory=false" style="max-width:720px">
      <div v-if="histLoading" class="muted">{{ t('push.loading') }}</div>
      <div v-else-if="!histPoints.length" class="empty-box">{{ t('cs.noHist') }}</div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead><tr><th>{{ t('cs.colTime') }}</th><th>{{ t('cs.colResult') }}</th><th>{{ t('cs.colMetrics') }}</th></tr></thead>
          <tbody>
            <tr v-for="(p, i) in histPoints" :key="i">
              <td class="mono small">{{ fmtDT(p.at) }}</td>
              <td><span class="chip" :class="p.ok ? 'on' : 'off'">{{ p.ok ? t('cs.ok') : t('cs.fail') }}</span>
                <div class="muted small" v-if="p.err">{{ p.err }}</div></td>
              <td class="small">
                <div v-for="m in p.metrics" :key="m.name + JSON.stringify(m.labels||{})" class="mono">
                  {{ m.name }}<span v-if="m.labels && m.labels.iface">[{{ m.labels.iface }}]</span>
                  <span v-if="m.labels && m.labels.counter">.{{ m.labels.counter }}</span>: <b>{{ fmtVal(m) }}</b>
                  <span class="muted"> {{ m.unit || '' }}</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </Modal>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import Modal from './Modal.vue'
import { v2 } from '../api/http'
import { t } from '../i18n'

const props = defineProps({
  side: { type: String, required: true }, // host | net
  title: { type: String, default: '' },
})

const tasks = ref([])
const protocols = ref([])
const status = ref({})
const enabled = ref(false)
const busy = ref(false)
const saving = ref(false)

const showForm = ref(false)
const form = ref(emptyForm())
const showHistory = ref(false)
const histTask = ref(null)
const histPoints = ref([])
const histLoading = ref(false)

const formTitle = computed(() => (form.value.id ? t('cs.editTask') : t('cs.addTask')))

function emptyForm() {
  return {
    id: '', name: '', protocol: '', target: '',
    intervalSec: 0, timeoutMs: 0,
    community: '', user: '', authPass: '',
    authProto: '', privProto: '',
    count: 4, path: 'if:interfaces',
    hasAuthPass: false, params: {},
    templateId: '',   // 快捷模板(仅新建; 保存时传给后端继承参数+默认阈值)
  }
}

const sideProtocols = computed(() =>
  protocols.value.filter(p => p.side === props.side && !p.notInScheduler))
const curProto = computed(() => protocols.value.find(p => p.name === form.value.protocol))
// 快捷模板: 只列"协议 side 与当前页一致"的模板(snmp 模板不会出现在主机侧页)
const sideTemplates = computed(() =>
  (status.value.templates || []).filter(tp => {
    const p = protocols.value.find(x => x.name === tp.protocol)
    return p && p.side === props.side
  }))
// 选模板: 自动带入协议 + 参数预设(icmp count / restconf path)
function onTplChange() {
  const tp = sideTemplates.value.find(x => x.id === form.value.templateId)
  if (!tp) return
  form.value.protocol = tp.protocol
  onProtoChange()
  if (tp.params) {
    if (tp.params.count) form.value.count = Number(tp.params.count) || 4
    if (tp.params.path) form.value.path = tp.params.path
  }
}

const needCommunity = computed(() =>
  form.value.protocol === 'snmp' && form.value.authProto !== 'md5' && form.value.authProto !== 'sha')
const needUser = computed(() => ['winrm', 'ssh', 'netconf', 'restconf'].includes(form.value.protocol))

const targetPlaceholder = computed(() => {
  switch (form.value.protocol) {
    case 'netflow': return '0.0.0.0:2000'
    case 'icmp': return '192.168.1.1'
    case 'winrm': return '192.168.1.10:5985'
    case 'ssh': return '192.168.1.11:22'
    case 'snmp': return '192.168.1.12:161'
    case 'restconf': return '192.168.1.13:443'
    case 'netconf': return '192.168.1.14:8300'
    default: return t('cs.targetAddr')
  }
})

function protoLabel(name) {
  const p = protocols.value.find(x => x.name === name)
  return p ? p.label : name
}

// 展示用的"关键指标": 只挑最常用的 4 个, 全量进"历史"
function topMetrics(task) {
  const keys = ['cpu', 'mem_used_pct', 'rtt_avg_ms', 'loss_pct', 'in_rate_bps', 'if_up']
  return (task.metrics || []).filter(m => keys.includes(m.name)).slice(0, 4)
}
function fmtVal(m) {
  const v = m.value
  if (typeof v !== 'number') return v
  if (m.unit === 'B' || m.unit === 'bps') return fmtSpeed(m)
  if (m.unit === 'MB') return v.toFixed(1) + 'MB'
  if (Math.abs(v) >= 100) return v.toFixed(0)
  return v.toFixed(1)
}
function fmtSpeed(m) {
  if (m.unit === 'bps') {
    if (m.value >= 1e9) return (m.value / 1e9).toFixed(1) + 'Gbps'
    if (m.value >= 1e6) return (m.value / 1e6).toFixed(1) + 'Mbps'
    if (m.value >= 1e3) return (m.value / 1e3).toFixed(0) + 'Kbps'
    return m.value.toFixed(0) + 'bps'
  }
  if (m.unit === 'B') {
    if (m.value >= 1e12) return (m.value / 1e12).toFixed(1) + 'TB'
    if (m.value >= 1e9) return (m.value / 1e9).toFixed(1) + 'GB'
    if (m.value >= 1e6) return (m.value / 1e6).toFixed(1) + 'MB'
    if (m.value >= 1e3) return (m.value / 1e3).toFixed(0) + 'KB'
    return m.value.toFixed(0) + 'B'
  }
  return m.value.toFixed(1) + (m.unit || '')
}
function metricTitle(m) {
  let s = m.name + ': ' + fmtVal(m)
  if (m.labels) s += '  ' + Object.entries(m.labels).map(([k, v]) => `${k}=${v}`).join(' ')
  return s
}
function fmtDT(s) {
  if (!s) return '—'
  const d = new Date(s)
  if (isNaN(d)) return s
  const p = n => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

async function load() {
  try {
    const [st, ts] = await Promise.all([
      v2('/node/status'),
      v2('/node/tasks?side=' + props.side),
    ])
    status.value = st
    protocols.value = st.protocols || []
    enabled.value = !!(st.enabled && st.running)
    tasks.value = ts.tasks || []
  } catch (e) {
    console.warn('load collect tasks failed', e)
  }
}

function openAdd() {
  const first = sideProtocols.value[0]
  form.value = emptyForm()
  form.value.protocol = first ? first.name : ''
  showForm.value = true
}
function openEdit(task) {
  form.value = {
    id: task.id, name: task.name || '', protocol: task.protocol, target: task.target,
    intervalSec: task.intervalSec || 0, timeoutMs: task.timeoutMs || 0,
    community: task.community || '', user: task.user || '', authPass: '',
    authProto: task.authProto || '', privProto: task.privProto || '',
    count: (task.params && task.params.count) || 4,
    path: (task.params && task.params.path) || 'if:interfaces',
    hasAuthPass: !!task.hasAuthPass, params: task.params || {},
  }
  showForm.value = true
}
function closeForm() { showForm.value = false }
function onProtoChange() {
  form.value.count = 4
  form.value.path = 'if:interfaces'
  form.value.authProto = ''
  form.value.privProto = ''
  // 手动换协议 = 模板不再适用, 清掉(否则后端按旧模板继承参数)
  if (!form.value.templateId || !sideTemplates.value.some(t => t.id === form.value.templateId && t.protocol === form.value.protocol)) {
    form.value.templateId = ''
  }
}

async function save() {
  if (!form.value.protocol || !form.value.target) return
  saving.value = true
  try {
    const body = {
      id: form.value.id || undefined,
      name: form.value.name,
      side: props.side,
      protocol: form.value.protocol,
      target: form.value.target.trim(),
      intervalSec: form.value.intervalSec,
      timeoutMs: form.value.timeoutMs,
      community: form.value.community || undefined,
      user: form.value.user || undefined,
      authPass: form.value.authPass || undefined,
      authProto: form.value.authProto || undefined,
      privProto: form.value.privProto || undefined,
      templateId: (form.value.id ? undefined : (form.value.templateId || undefined)),
    }
    if (form.value.protocol === 'icmp') body.params = { count: String(form.value.count || 4) }
    if (form.value.protocol === 'restconf' && form.value.path) body.params = { path: form.value.path }
    await v2('/node/tasks', { method: 'POST', body })
    showForm.value = false
    await load()
  } catch (e) {
    alert(t('cs.saveFail', { err: e.message }))
  } finally {
    saving.value = false
  }
}

async function del(task) {
  if (!confirm(t('cs.delTaskConfirm', { name: task.name || task.target }))) return
  try {
    await v2('/node/tasks/' + encodeURIComponent(task.id), { method: 'DELETE' })
    await load()
  } catch (e) {
    alert(t('cs.delFail', { err: e.message }))
  }
}

async function collectOne(task) {
  busy.value = true
  try {
    await v2('/node/collect', { method: 'POST', body: { taskID: task.id } })
    await load()
  } catch (e) {
    alert(t('cs.collectFail', { err: e.message }))
  } finally {
    busy.value = false
  }
}
async function collectAll() {
  busy.value = true
  try {
    await v2('/node/collect', { method: 'POST', body: {} })
    await load()
  } catch (e) {
    alert(t('cs.collectFail', { err: e.message }))
  } finally {
    busy.value = false
  }
}

async function openHistory(task) {
  histTask.value = task
  showHistory.value = true
  histLoading.value = true
  histPoints.value = []
  try {
    const d = await v2('/node/metrics?task=' + encodeURIComponent(task.id) + '&limit=30')
    histPoints.value = (d.points || []).slice().reverse() // 新在前
  } catch (e) {
    console.warn(e)
  } finally {
    histLoading.value = false
  }
}

let timer = null
onMounted(() => {
  load()
  timer = setInterval(load, 10000) // 10s 轮询最新状态
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.kv-mini { display: flex; flex-wrap: wrap; gap: 4px 10px; }
.kv-mini-item { white-space: nowrap; }
.kv-mini-item b { color: var(--accent); }
.chip.proto { background: rgba(77, 163, 255, .12); color: var(--blue); }
.form-row { display: flex; gap: 12px; }
.form-row .field { flex: 1; }
.form-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px; }
</style>
