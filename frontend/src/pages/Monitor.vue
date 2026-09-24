<!--
  Monitor.vue SNMP 网络监控管理页(任务 10a 前端)。
  目标增删改 + 轮询配置 + 实时状态(在线/CPU/内存/流量速率) + 手动采集。
  数据源 /api/v2/monitor/*(monitor_api.go 装配层)。大屏(3D 地球)复用同一数据源。
-->
<template>
  <div class="page">
    <PageHeader title="网络监控 (SNMP)" desc="只读 GET/GETBULK 周期采集交换机/路由器/服务器指标, 对设备零影响">
      <button class="btn sm" @click="collectNow" :disabled="collecting">
        {{ collecting ? '采集中…' : '立即采集一轮' }}
      </button>
      <button class="btn primary sm" @click="openAdd">＋ 添加目标</button>
    </PageHeader>

    <!-- 轮询配置 -->
    <div class="card">
      <div class="card-title">轮询配置</div>
      <div class="form-row cfg-row">
        <div class="field cfg-field">
          <label class="lbl">启用监控</label>
          <div class="cfg-toggle">
            <span class="chip" :class="status.enabled ? 'on' : 'off'">{{ status.enabled ? '已启用' : '已停用' }}</span>
            <button class="btn xs" @click="toggleEnabled">{{ status.enabled ? '停用' : '启用' }}</button>
          </div>
        </div>
        <div class="field cfg-field">
          <label class="lbl">轮询间隔(秒, 最小 5)</label>
          <input class="input cfg-input" type="number" min="5" v-model.number="cfgInterval" />
        </div>
        <div class="field cfg-field" style="justify-content:flex-end">
          <button class="btn primary sm" @click="saveConfig" :disabled="savingConfig">保存配置</button>
        </div>
      </div>
      <div class="muted small" v-if="status.lastRound">
        最近一轮 {{ fmtDT(status.lastRound.at) }} · {{ status.lastRound.ok }}/{{ status.lastRound.total }} 成功 · {{ status.lastRound.durationMs }}ms
        <span v-if="status.lastRound.errors && status.lastRound.errors.length" style="color:var(--orange)">（有错误）</span>
      </div>
    </div>

    <!-- 目标列表 -->
    <div class="card">
      <div class="card-title">监控目标 <span class="sub">{{ onlineCount }} 在线 / {{ targets.length }} 个</span></div>
      <div v-if="!targets.length" class="empty-box">
        <span class="ph-tag">无目标</span>
        尚未配置 SNMP 监控目标。点击右上「添加目标」, 填入设备 IP / 社区串后开始采集。
      </div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>状态</th><th>名称</th><th>地址</th><th>凭据</th>
              <th>CPU</th><th>内存</th><th>流量(每周期)</th><th>接口 up/总</th><th>最近采集</th><th class="a-r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in targets" :key="t.id">
              <td><span class="dot" :class="t.online ? 'on' : 'off'"></span></td>
              <td><div>{{ t.name || t.addr }}</div><div class="muted small mono" v-if="t.lastErr">{{ t.lastErr }}</div></td>
              <td class="mono muted">{{ t.version }}<span v-if="t.v3User"> · {{ t.v3User }}</span></td>
              <td class="mono">{{ t.cpuLoad ? t.cpuLoad + '%' : '-' }}</td>
              <td class="mono">{{ memUsedPct(t) }}</td>
              <td class="mono small">{{ fmtSpeed(t.inRateBps) }}↓ / {{ fmtSpeed(t.outRateBps) }}↑</td>
              <td class="mono">{{ t.ifUp }}/{{ t.ifaceCount }}</td>
              <td class="mono small muted">{{ fmtDT(t.lastAt) }}</td>
              <td class="a-r">
                <div class="row-actions">
                  <button class="btn xs" @click="openEdit(t)">编辑</button>
                  <button class="btn xs danger" @click="del(t)">删除</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 添加/编辑目标 -->
    <Modal v-if="showModal" :title="modalTitle" @close="closeModal">
      <div class="field">
        <label class="lbl">名称 <span class="req">*</span></label>
        <input class="input" v-model="form.name" placeholder="核心交换机-A" />
      </div>
      <div class="field">
        <label class="lbl">地址 (IP 或 IP:端口) <span class="req">*</span></label>
        <input class="input" v-model="form.addr" placeholder="192.168.1.1 或 192.168.1.1:161" />
      </div>
      <div class="field">
        <label class="lbl">SNMP 版本</label>
        <select class="input" v-model="form.version">
          <option value="v2c">v2c(社区串)</option>
          <option value="v3">v3(USM 鉴权/加密)</option>
        </select>
      </div>
      <div class="form-row" v-if="form.version === 'v2c'">
        <div class="field">
          <label class="lbl">社区串 (只读) <span class="req">*</span></label>
          <input class="input" v-model="form.community" placeholder="public" />
        </div>
        <div class="field">
          <label class="lbl">超时 (ms)</label>
          <input class="input" type="number" min="0" v-model.number="form.timeoutMs" />
        </div>
      </div>
      <template v-else>
        <div class="form-row">
          <div class="field">
            <label class="lbl">用户名 <span class="req">*</span></label>
            <input class="input" v-model="form.user" placeholder="monitor" />
          </div>
          <div class="field">
            <label class="lbl">超时 (ms)</label>
            <input class="input" type="number" min="0" v-model.number="form.timeoutMs" />
          </div>
        </div>
        <div class="form-row">
          <div class="field">
            <label class="lbl">鉴权协议</label>
            <select class="input" v-model="form.authProto">
              <option value="">不鉴权</option>
              <option value="md5">MD5</option>
              <option value="sha">SHA1</option>
            </select>
          </div>
          <div class="field">
            <label class="lbl">鉴权口令</label>
            <input class="input" type="password" v-model="form.authPass" :placeholder="editingId ? '留空=不修改' : ''" />
          </div>
        </div>
        <div class="form-row">
          <div class="field">
            <label class="lbl">加密协议</label>
            <select class="input" v-model="form.privProto">
              <option value="">不加密</option>
              <option value="des">DES</option>
              <option value="aes">AES-128</option>
            </select>
          </div>
          <div class="field">
            <label class="lbl">加密口令</label>
            <input class="input" type="password" v-model="form.privPass" :placeholder="editingId ? '留空=不修改' : ''" />
          </div>
        </div>
        <p class="muted small">口令加密存储(密钥取自环境变量 YUGSIGHT_MONITOR_KEY), 列表接口不回传口令。</p>
      </template>
      <div class="form-actions">
        <button class="btn" @click="closeModal">取消</button>
        <button class="btn primary" @click="saveTarget" :disabled="saving">{{ saving ? '保存中…' : '保存' }}</button>
      </div>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import Modal from '../components/Modal.vue'
import { v2 } from '../api/http'
import { fmtDT, fmtSpeed } from '../utils'

const status = ref({ enabled: false, running: false, intervalSec: 60, lastRound: null })
const targets = ref([])
const collecting = ref(false)
const savingConfig = ref(false)
const cfgInterval = ref(60)

// ===== 目标表单 =====
const showModal = ref(false)
const editingId = ref('')
const saving = ref(false)
const form = reactive({
  id: '', name: '', addr: '', community: 'public', timeoutMs: 3000,
  // v3(USM): version 只用于表单显隐, 后端以 user 是否非空判定 v2c/v3
  version: 'v2c', user: '', authProto: 'md5', authPass: '', privProto: '', privPass: '', context: ''
})
const modalTitle = computed(() => (editingId.value ? '编辑目标' : '添加目标'))

const onlineCount = computed(() => targets.value.filter(t => t.online).length)

function memUsedPct(t) {
  if (!t || !t.memTotal) return '-'
  return Math.round((t.memUsed / t.memTotal) * 100) + '%'
}

// ===== 数据加载 =====
async function load() {
  try {
    const s = await v2('/monitor/status')
    if (s) {
      status.value = s
      targets.value = s.targets || []
      if (s.intervalSec) cfgInterval.value = s.intervalSec
    }
  } catch (e) { /* 保留上一帧 */ }
}

async function toggleEnabled() {
  await saveConfig(!status.value.enabled)
}

async function saveConfig(forceEnabled) {
  savingConfig.value = true
  try {
    const body = {}
    if (typeof forceEnabled === 'boolean') body.enabled = forceEnabled
    if (cfgInterval.value) body.intervalSec = cfgInterval.value
    await v2('/monitor/config', { method: 'POST', body })
    await load()
  } catch (e) {
    alert('保存失败: ' + (e && e.message || e))
  } finally {
    savingConfig.value = false
  }
}

async function collectNow() {
  collecting.value = true
  try {
    await v2('/monitor/collect', { method: 'POST', body: {} })
    await load()
  } catch (e) {
    alert('采集失败: ' + (e && e.message || e))
  } finally {
    collecting.value = false
  }
}

// ===== 目标 CRUD =====
const emptyForm = () => ({
  id: '', name: '', addr: '', community: 'public', timeoutMs: 3000,
  version: 'v2c', user: '', authProto: 'md5', authPass: '', privProto: '', privPass: '', context: ''
})
function openAdd() {
  editingId.value = ''
  Object.assign(form, emptyForm())
  showModal.value = true
}
function openEdit(t) {
  editingId.value = t.id
  Object.assign(form, emptyForm(), {
    id: t.id, name: t.name || '', addr: t.addr, timeoutMs: t.timeoutMs || 3000,
    // 口令服务端不回传: 留空即"不修改"(hasAuthPass 只用于提示是否已配置)
    version: (t.version || '').startsWith('v3') ? 'v3' : 'v2c',
    user: t.v3User || '', authProto: t.authProto || 'md5', privProto: t.privProto || ''
  })
  showModal.value = true
}
function closeModal() { showModal.value = false }

async function saveTarget() {
  if (!form.name.trim() || !form.addr.trim()) {
    alert('名称 / 地址 必填')
    return
  }
  if (form.version === 'v2c' && !form.community.trim()) {
    alert('v2c 目标必须填社区串')
    return
  }
  if (form.version === 'v3') {
    if (!form.user.trim()) { alert('v3 目标必须填用户名'); return }
    if (form.authProto && !editingId.value && !form.authPass) { alert('v3 指定鉴权协议时必须填鉴权口令'); return }
  }
  saving.value = true
  try {
    const body = { id: form.id, name: form.name, addr: form.addr, timeoutMs: form.timeoutMs }
    if (form.version === 'v3') {
      Object.assign(body, {
        // 留空 community: 后端据此判定为 v3 模式(以 user 非空为准)
        user: form.user, authProto: form.authProto, authPass: form.authPass,
        privProto: form.privProto, privPass: form.privPass, context: form.context
      })
    } else {
      body.community = form.community
    }
    await v2('/monitor/targets', { method: 'POST', body })
    closeModal()
    await load()
  } catch (e) {
    alert('保存失败: ' + (e && e.message || e))
  } finally {
    saving.value = false
  }
}

async function del(t) {
  if (!confirm(`确认删除目标「${t.name || t.addr}」?`)) return
  try {
    await v2('/monitor/targets/' + t.id, { method: 'DELETE' })
    await load()
  } catch (e) {
    alert('删除失败: ' + (e && e.message || e))
  }
}

let timer = null
onMounted(() => {
  load()
  timer = setInterval(load, 10000) // 10s 轮询状态(采集轮次 60s, 10s 足够感知在线变化)
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.cfg-row { align-items: flex-end; }
.cfg-field { display: flex; flex-direction: column; gap: 6px; }
.cfg-field .lbl { font-size: 12px; color: var(--muted); }
.cfg-input { width: 120px; }
.cfg-toggle { display: flex; align-items: center; gap: 10px; }
.empty-box {
  border: 1px dashed var(--border2); border-radius: 10px;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  min-height: 140px; color: var(--muted); font-size: 13px; gap: 8px; text-align: center; padding: 16px;
}
.empty-box .ph-tag {
  font-size: 11px; color: var(--accent); border: 1px solid rgba(56,189,248,.4);
  padding: 2px 10px; border-radius: 999px; background: rgba(56,189,248,.08);
}
.dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; background: var(--muted); }
.dot.on { background: var(--green); box-shadow: 0 0 0 3px rgba(52,211,153,.18); }
.dot.off { background: var(--red); }
.a-r { text-align: right; }
.req { color: var(--red); }
</style>
