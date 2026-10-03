<!--
  Monitor.vue SNMP 网络监控管理页(任务 10a 前端)。
  目标增删改 + 轮询配置 + 实时状态(在线/CPU/内存/流量速率) + 手动采集。
  数据源 /api/v2/monitor/*(monitor_api.go 装配层)。大屏(3D 地球)复用同一数据源。
-->
<template>
  <div class="page">
    <PageHeader :title="t('nm.monTitle')" :desc="t('nm.monDesc')">
      <button class="btn sm" @click="collectNow" :disabled="collecting">
        {{ collecting ? t('nm.collecting') : t('nm.collectNow') }}
      </button>
      <button class="btn primary sm" @click="openAdd">＋ {{ t('nm.addTarget') }}</button>
    </PageHeader>

    <!-- 轮询配置 -->
    <div class="card">
      <div class="card-title">{{ t('nm.pollCfg') }}</div>
      <div class="form-row cfg-row">
        <div class="field cfg-field">
          <label class="lbl">{{ t('nm.enableMon') }}</label>
          <div class="cfg-toggle">
            <span class="chip" :class="status.enabled ? 'on' : 'off'">{{ status.enabled ? t('nm.enabled') : t('nm.disabled') }}</span>
            <button class="btn xs" @click="toggleEnabled">{{ status.enabled ? t('nm.stop') : t('nm.enable') }}</button>
          </div>
        </div>
        <div class="field cfg-field">
          <label class="lbl">{{ t('nm.pollInterval') }}</label>
          <input class="input cfg-input" type="number" min="5" v-model.number="cfgInterval" />
        </div>
        <div class="field cfg-field" style="justify-content:flex-end">
          <button class="btn primary sm" @click="saveConfig" :disabled="savingConfig">{{ t('nm.saveCfg') }}</button>
        </div>
      </div>
      <div class="muted small" v-if="status.lastRound">
        {{ t('nm.lastRound', { at: fmtDT(status.lastRound.at), ok: status.lastRound.ok, total: status.lastRound.total, ms: status.lastRound.durationMs }) }}
        <span v-if="status.lastRound.errors && status.lastRound.errors.length" style="color:var(--orange)">{{ t('nm.hasErr') }}</span>
      </div>
    </div>

    <!-- 目标列表 -->
    <div class="card">
      <div class="card-title">{{ t('nm.monTargets') }} <span class="sub">{{ t('nm.onlineCnt', { n: onlineCount, m: targets.length }) }}</span></div>
      <div v-if="!targets.length" class="empty-box">
        <span class="ph-tag">{{ t('nm.noTargets') }}</span>
        {{ t('nm.noTargetsHint') }}
      </div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <!-- 2026-09-27: 新增 IP 地址/MAC 地址列(与设备名称/状态并列);
                   同时修正原"地址"列表头错位(该列实际内容是 SNMP 版本, 改名为"版本",
                   表头与单元格一一对齐) -->
              <th>{{ t('nm.colStatus') }}</th><th>{{ t('nm.colName') }}</th><th>{{ t('nm.colIp') }}</th><th>MAC</th><th>{{ t('nm.colVer') }}</th>
              <th>CPU</th><th>{{ t('nm.colMem') }}</th><th>{{ t('nm.colTraffic') }}</th><th>{{ t('nm.colIfs') }}</th><th>{{ t('nm.colLastCollected') }}</th><th class="a-r">{{ t('nm.colOp') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="tg in targets" :key="tg.id">
              <td><span class="dot" :class="tg.online ? 'on' : 'off'"></span></td>
              <td><div>{{ tg.name || tg.addr }}</div><div class="muted small mono" v-if="tg.lastErr">{{ tg.lastErr }}</div></td>
              <td class="mono small">{{ tg.addr || '-' }}</td>
              <!-- MAC 来自 SNMP ifPhysAddress(首个 up 接口); 设备不支持时显示 '-' -->
              <td class="mono small">{{ tg.mac || '-' }}</td>
              <!-- 2026-10-01: 内置"中心端(本机)"(source=center)不是 SNMP 目标, 版本列显示"本机" -->
              <td class="mono muted"><span v-if="tg.source === 'center'">{{ t('nm.local') }}</span><span v-else>{{ tg.version }}<span v-if="tg.v3User"> · {{ tg.v3User }}</span></span></td>
              <td class="mono">{{ tg.cpuLoad ? tg.cpuLoad + '%' : '-' }}</td>
              <td class="mono">{{ memUsedPct(tg) }}</td>
              <td class="mono small">{{ fmtSpeed(tg.inRateBps) }}↓ / {{ fmtSpeed(tg.outRateBps) }}↑</td>
              <!-- 内置中心端没有 SNMP 接口表(接口数指标不适用于主机) -->
              <td class="mono"><span v-if="tg.source === 'center'">—</span><span v-else>{{ tg.ifUp }}/{{ tg.ifaceCount }}</span></td>
              <td class="mono small muted">{{ fmtDT(tg.lastAt) }}</td>
              <td class="a-r">
                <!-- 内置中心端: 不落配置, 编辑/删除在后端无对应目标(会报"目标不存在"), 故不给出入口 -->
                <div class="row-actions">
                  <span v-if="tg.source === 'center'" class="muted small">{{ t('nm.builtin') }}</span>
                  <template v-else>
                    <button class="btn xs" @click="openEdit(tg)">{{ t('common.edit') }}</button>
                    <button class="btn xs danger" @click="del(tg)">{{ t('common.del') }}</button>
                  </template>
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
        <label class="lbl">{{ t('nm.name') }} <span class="req">*</span></label>
        <input class="input" v-model="form.name" :placeholder="t('nm.namePh')" />
      </div>
      <div class="field">
        <label class="lbl">{{ t('nm.addr') }} <span class="req">*</span></label>
        <input class="input" v-model="form.addr" placeholder="192.168.1.1 或 192.168.1.1:161" />
      </div>
      <div class="field">
        <label class="lbl">{{ t('nm.snmpVer') }}</label>
        <select class="input" v-model="form.version">
          <option value="v2c">{{ t('nm.v2c') }}</option>
          <option value="v3">{{ t('nm.v3') }}</option>
        </select>
      </div>
      <div class="form-row" v-if="form.version === 'v2c'">
        <div class="field">
          <label class="lbl">{{ t('nm.community') }} <span class="req">*</span></label>
          <input class="input" v-model="form.community" placeholder="public" />
        </div>
        <div class="field">
          <label class="lbl">{{ t('nm.timeout') }}</label>
          <input class="input" type="number" min="0" v-model.number="form.timeoutMs" />
        </div>
      </div>
      <template v-else>
        <div class="form-row">
          <div class="field">
            <label class="lbl">{{ t('nm.username') }} <span class="req">*</span></label>
            <input class="input" v-model="form.user" placeholder="monitor" />
          </div>
          <div class="field">
            <label class="lbl">{{ t('nm.timeout') }}</label>
            <input class="input" type="number" min="0" v-model.number="form.timeoutMs" />
          </div>
        </div>
        <div class="form-row">
          <div class="field">
            <label class="lbl">{{ t('nm.authProto') }}</label>
            <select class="input" v-model="form.authProto">
              <option value="">{{ t('nm.noAuth') }}</option>
              <option value="md5">MD5</option>
              <option value="sha">SHA1</option>
            </select>
          </div>
          <div class="field">
            <label class="lbl">{{ t('nm.authPass') }}</label>
            <input class="input" type="password" v-model="form.authPass" :placeholder="editingId ? t('nm.keepEmpty') : ''" />
          </div>
        </div>
        <div class="form-row">
          <div class="field">
            <label class="lbl">{{ t('nm.privProto') }}</label>
            <select class="input" v-model="form.privProto">
              <option value="">{{ t('nm.noPriv') }}</option>
              <option value="des">DES</option>
              <option value="aes">AES-128</option>
            </select>
          </div>
          <div class="field">
            <label class="lbl">{{ t('nm.privPass') }}</label>
            <input class="input" type="password" v-model="form.privPass" :placeholder="editingId ? t('nm.keepEmpty') : ''" />
          </div>
        </div>
        <p class="muted small">{{ t('nm.passNote') }}</p>
      </template>
      <div class="form-actions">
        <button class="btn" @click="closeModal">{{ t('common.cancel') }}</button>
        <button class="btn primary" @click="saveTarget" :disabled="saving">{{ saving ? t('nm.saving') : t('common.save') }}</button>
      </div>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import { t } from '../i18n'
import PageHeader from '../components/PageHeader.vue'
import Modal from '../components/Modal.vue'
import { v2 } from '../api/http'
import { fmtDT, fmtSpeed } from '../utils'
import { setPageData } from '../assistant/context'

const status = ref({ enabled: false, running: false, intervalSec: 60, lastRound: null })
const targets = ref([])
// 小 Y 助手(2026-09-27): 节点监控"网络设备"Tab 的关键数据(设备在线状态/告警)
setPageData('nodemonitor:net', () => ({
  enabled: !!status.value.enabled,
  intervalSec: status.value.intervalSec || 0,
  devices: targets.value.slice(0, 50).map(t => ({
    name: t.name || t.addr,
    addr: t.addr || '',
    online: !!t.online,
    cpu: t.cpuLoad != null ? t.cpuLoad + '%' : '',
    mem: t.memPct != null ? t.memPct + '%' : '',
    lastErr: t.lastErr || ''
  }))
}))
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
const modalTitle = computed(() => (editingId.value ? t('nm.editTarget') : t('nm.addTarget')))

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
    alert(t('nm.saveFail', { err: (e && e.message || e) }))
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
    alert(t('nm.collectFail', { err: (e && e.message || e) }))
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
    alert(t('nm.nameAddrRequired'))
    return
  }
  if (form.version === 'v2c' && !form.community.trim()) {
    alert(t('nm.v2cNeedCommunity'))
    return
  }
  if (form.version === 'v3') {
    if (!form.user.trim()) { alert(t('nm.v3NeedUser')); return }
    if (form.authProto && !editingId.value && !form.authPass) { alert(t('nm.v3NeedAuthPass')); return }
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
    alert(t('nm.saveFail', { err: (e && e.message || e) }))
  } finally {
    saving.value = false
  }
}

async function del(task) {
  if (!confirm(t('nm.delTargetConfirm', { name: task.name || task.addr }))) return
  try {
    await v2('/monitor/targets/' + task.id, { method: 'DELETE' })
    await load()
  } catch (e) {
    alert(t('nm.delFail', { err: (e && e.message || e) }))
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
