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
      {{ title }}
      <span class="sub">{{ tasks.length }} 个采集任务</span>
      <div class="spacer"></div>
      <button class="btn xs" @click="collectAll" :disabled="busy || !enabled">全部立即采集</button>
      <button class="btn primary xs" @click="openAdd">＋ 添加任务</button>
    </div>

    <div v-if="!tasks.length" class="empty-box">
      <span class="ph-tag">无任务</span>
      尚未配置采集任务。点击「添加任务」选择协议并填入目标地址。
    </div>

    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>状态</th><th>名称</th><th>协议</th><th>目标</th>
            <th>最新指标</th><th>最近采集</th><th class="a-r">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="t in tasks" :key="t.id">
            <td><span class="dot" :class="t.online ? 'on' : (t.collected ? 'off' : 'idle')"></span></td>
            <td>
              <div>{{ t.name || t.target }}</div>
              <div class="muted small mono" v-if="t.lastErr">{{ t.lastErr }}</div>
            </td>
            <td><span class="chip proto">{{ protoLabel(t.protocol) }}</span></td>
            <td class="mono muted small">{{ t.target }}</td>
            <td>
              <div class="muted small" v-if="!t.metrics || !t.metrics.length">—</div>
              <div v-else class="kv-mini">
                <span v-for="m in topMetrics(t)" :key="m.name" class="kv-mini-item" :title="metricTitle(m)">
                  {{ m.name }} <b>{{ fmtVal(m) }}</b>
                </span>
              </div>
            </td>
            <td class="mono small muted">{{ fmtDT(t.lastAt) }}<span v-if="t.elapsedMs"> · {{ t.elapsedMs }}ms</span></td>
            <td class="a-r">
              <div class="row-actions">
                <button class="btn xs" @click="collectOne(t)" :disabled="busy || !enabled">采集</button>
                <button class="btn xs" @click="openHistory(t)">历史</button>
                <button class="btn xs" @click="openEdit(t)">编辑</button>
                <button class="btn xs danger" @click="del(t)">删除</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 添加/编辑任务 -->
    <Modal v-if="showForm" :title="formTitle" @close="closeForm">
      <div class="field">
        <label class="lbl">协议 <span class="req">*</span></label>
        <select class="input" v-model="form.protocol" :disabled="!!form.id" @change="onProtoChange">
          <option v-for="p in sideProtocols" :key="p.name" :value="p.name">{{ p.label }}</option>
        </select>
        <div class="muted small" v-if="curProto">{{ curProto.desc }}</div>
      </div>
      <div class="field">
        <label class="lbl">目标 <span class="req">*</span> <span class="muted small" v-if="form.protocol==='netflow'">(监听地址)</span></label>
        <input class="input" v-model="form.target" :placeholder="targetPlaceholder" />
      </div>
      <div class="field">
        <label class="lbl">名称</label>
        <input class="input" v-model="form.name" placeholder="可选, 便于识别" />
      </div>
      <div class="form-row">
        <div class="field">
          <label class="lbl">间隔(秒, 0=用全局)</label>
          <input class="input" type="number" min="0" v-model.number="form.intervalSec" />
        </div>
        <div class="field">
          <label class="lbl">超时(ms, 0=默认)</label>
          <input class="input" type="number" min="0" v-model.number="form.timeoutMs" />
        </div>
      </div>
      <template v-if="needCommunity">
        <div class="field">
          <label class="lbl">SNMP 社区串(v2c)</label>
          <input class="input" v-model="form.community" placeholder="public" />
        </div>
      </template>
      <template v-if="needUser">
        <div class="form-row">
          <div class="field">
            <label class="lbl">用户名</label>
            <input class="input" v-model="form.user" />
          </div>
          <div class="field">
            <label class="lbl">口令 <span class="muted small" v-if="form.hasAuthPass">(已配置, 留空不改)</span></label>
            <input class="input" type="password" v-model="form.authPass" autocomplete="off" />
          </div>
        </div>
      </template>
      <template v-if="form.protocol==='snmp'">
        <div class="form-row">
          <div class="field">
            <label class="lbl">v3 认证协议</label>
            <select class="input" v-model="form.authProto">
              <option value="">(v2c)</option>
              <option value="md5">MD5</option>
              <option value="sha">SHA</option>
            </select>
          </div>
          <div class="field">
            <label class="lbl">v3 加密协议</label>
            <select class="input" v-model="form.privProto">
              <option value="">无</option>
              <option value="des">DES</option>
              <option value="aes">AES</option>
            </select>
          </div>
        </div>
      </template>
      <template v-if="form.protocol==='icmp'">
        <div class="field">
          <label class="lbl">探测次数(1-20)</label>
          <input class="input" type="number" min="1" max="20" v-model.number="form.count" />
        </div>
      </template>
      <template v-if="form.protocol==='restconf'">
        <div class="field">
          <label class="lbl">数据路径(默认 if:interfaces)</label>
          <input class="input" v-model="form.path" placeholder="if:interfaces" />
        </div>
      </template>
      <div class="muted small" v-if="form.protocol==='ssh'">
        仅支持密钥登录(BatchMode); 需在中心端配置好到目标的 SSH 密钥。
      </div>
      <div class="muted small" v-if="form.protocol==='netconf'">
        走 NETCONF over TLS(RFC 8012); 目标需支持 TLS 通道, 仅 SSH 通道的设备暂不支持。
      </div>
      <div class="form-actions">
        <button class="btn" @click="closeForm">取消</button>
        <button class="btn primary" @click="save" :disabled="saving">保存</button>
      </div>
    </Modal>

    <!-- 历史时序 -->
    <Modal v-if="showHistory" :title="'采集历史 · ' + (histTask ? (histTask.name || histTask.target) : '')" @close="showHistory=false" style="max-width:720px">
      <div v-if="histLoading" class="muted">加载中…</div>
      <div v-else-if="!histPoints.length" class="empty-box">暂无历史数据</div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead><tr><th>时间</th><th>结果</th><th>指标</th></tr></thead>
          <tbody>
            <tr v-for="(p, i) in histPoints" :key="i">
              <td class="mono small">{{ fmtDT(p.at) }}</td>
              <td><span class="chip" :class="p.ok ? 'on' : 'off'">{{ p.ok ? '成功' : '失败' }}</span>
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

const props = defineProps({
  side: { type: String, required: true }, // host | net
  title: { type: String, default: '采集任务' },
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

const formTitle = computed(() => (form.value.id ? '编辑任务' : '添加任务'))

function emptyForm() {
  return {
    id: '', name: '', protocol: '', target: '',
    intervalSec: 0, timeoutMs: 0,
    community: '', user: '', authPass: '',
    authProto: '', privProto: '',
    count: 4, path: 'if:interfaces',
    hasAuthPass: false, params: {},
  }
}

const sideProtocols = computed(() =>
  protocols.value.filter(p => p.side === props.side && !p.notInScheduler))
const curProto = computed(() => protocols.value.find(p => p.name === form.value.protocol))

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
    default: return '目标地址'
  }
})

function protoLabel(name) {
  const p = protocols.value.find(x => x.name === name)
  return p ? p.label : name
}

// 展示用的"关键指标": 只挑最常用的 4 个, 全量进"历史"
function topMetrics(t) {
  const keys = ['cpu', 'mem_used_pct', 'rtt_avg_ms', 'loss_pct', 'in_rate_bps', 'if_up']
  return (t.metrics || []).filter(m => keys.includes(m.name)).slice(0, 4)
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
function openEdit(t) {
  form.value = {
    id: t.id, name: t.name || '', protocol: t.protocol, target: t.target,
    intervalSec: t.intervalSec || 0, timeoutMs: t.timeoutMs || 0,
    community: t.community || '', user: t.user || '', authPass: '',
    authProto: t.authProto || '', privProto: t.privProto || '',
    count: (t.params && t.params.count) || 4,
    path: (t.params && t.params.path) || 'if:interfaces',
    hasAuthPass: !!t.hasAuthPass, params: t.params || {},
  }
  showForm.value = true
}
function closeForm() { showForm.value = false }
function onProtoChange() {
  form.value.count = 4
  form.value.path = 'if:interfaces'
  form.value.authProto = ''
  form.value.privProto = ''
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
    }
    if (form.value.protocol === 'icmp') body.params = { count: String(form.value.count || 4) }
    if (form.value.protocol === 'restconf' && form.value.path) body.params = { path: form.value.path }
    await v2('/node/tasks', { method: 'POST', body })
    showForm.value = false
    await load()
  } catch (e) {
    alert('保存失败: ' + e.message)
  } finally {
    saving.value = false
  }
}

async function del(t) {
  if (!confirm(`删除采集任务「${t.name || t.target}」?`)) return
  try {
    await v2('/node/tasks/' + encodeURIComponent(t.id), { method: 'DELETE' })
    await load()
  } catch (e) {
    alert('删除失败: ' + e.message)
  }
}

async function collectOne(t) {
  busy.value = true
  try {
    await v2('/node/collect', { method: 'POST', body: { taskID: t.id } })
    await load()
  } catch (e) {
    alert('采集失败: ' + e.message)
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
    alert('采集失败: ' + e.message)
  } finally {
    busy.value = false
  }
}

async function openHistory(t) {
  histTask.value = t
  showHistory.value = true
  histLoading.value = true
  histPoints.value = []
  try {
    const d = await v2('/node/metrics?task=' + encodeURIComponent(t.id) + '&limit=30')
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
