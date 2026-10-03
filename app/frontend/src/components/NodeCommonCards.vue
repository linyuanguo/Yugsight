<!--
  NodeCommonCards.vue 节点监控「协议配置」公共区: 采集全局配置。

  配置: 总开关 / 默认间隔 / 并发 / 全局限速 / 保留时长 / IP 白名单 / NetFlow 接收 /
        告警阈值 —— 对应 /api/v2/node/config(写 settings.json 的 collect 节)。

  2026-09-30 用户要求: 异常事件与「告警日志管理 → 告警记录」同源(都是采集引擎
  异常事件自动生成), 两处显示重复 —— 异常事件卡整体移入告警日志页(新"异常事件"
  Tab, 含 AI 分析按钮), 本组件不再展示。
-->
<template>
  <div>
    <!-- 采集配置 -->
    <div class="card">
      <div class="card-title">{{ t('nc.cfgTitle') }} <span class="sub">{{ t('nc.cfgSub') }}</span></div>
      <div class="form-row cfg-row">
        <div class="field cfg-field">
          <label class="lbl">{{ t('nc.enable') }}</label>
          <div class="cfg-toggle">
            <span class="chip" :class="cfg.enabled ? 'on' : 'off'">{{ cfg.enabled ? t('nc.onText') : t('nc.offText') }}</span>
            <button class="btn xs" @click="toggleEnabled">{{ cfg.enabled ? t('nc.btnOff') : t('nc.btnOn') }}</button>
          </div>
        </div>
        <div class="field cfg-field">
          <label class="lbl">{{ t('nc.interval') }}</label>
          <input class="input cfg-input" type="number" min="5" v-model.number="cfg.intervalSec" />
        </div>
        <div class="field cfg-field">
          <label class="lbl">{{ t('nc.concurrent') }}</label>
          <input class="input cfg-input" type="number" min="1" v-model.number="cfg.concurrent" />
        </div>
        <div class="field cfg-field">
          <label class="lbl">{{ t('nc.rate') }}</label>
          <input class="input cfg-input" type="number" min="1" v-model.number="cfg.globalRate" />
        </div>
        <div class="field cfg-field">
          <label class="lbl">{{ t('nc.retention') }}</label>
          <input class="input cfg-input" type="number" min="1" v-model.number="cfg.retentionHours" />
        </div>
        <div class="field cfg-field" style="justify-content:flex-end">
          <button class="btn primary sm" @click="saveConfig" :disabled="saving">{{ t('nc.saveCfg') }}</button>
        </div>
      </div>

      <div class="muted small" v-if="status.netflowActive && status.netflowActive.length">
        {{ t('nc.netflowActive') }}: {{ status.netflowActive.join(', ') }}
      </div>
      <div class="muted small" v-if="!status.secretKeySet">
        {{ t('nc.noKey') }}
      </div>
    </div>

    <!-- 2026-10-02 用户口径: 节点监控不生成原始报告(报告中心被刷屏) ——
         原"报告中心/存快照"卡片与"立即采集自动存档"一并移除, 采集结果只记日志;
         存量历史报告仍在「报告中心 → 原始报告」可查/可删 -->

    <!-- 告警阈值 + NetFlow + 白名单(折叠区, 避免首屏过长) -->
    <div class="card">
      <div class="card-title" style="cursor:pointer" @click="advOpen = !advOpen">
        {{ t('nc.advTitle') }}
        <span class="sub">{{ advOpen ? t('nc.collapse') : t('nc.expand') }}</span>
      </div>
      <template v-if="advOpen">
        <div class="form-row cfg-row">
          <div class="field cfg-field">
            <label class="lbl">{{ t('nc.cpuAlert') }}</label>
            <input class="input cfg-input" type="number" min="0" v-model.number="cfg.alerts.cpuPct" />
          </div>
          <div class="field cfg-field">
            <label class="lbl">{{ t('nc.memAlert') }}</label>
            <input class="input cfg-input" type="number" min="0" v-model.number="cfg.alerts.memPct" />
          </div>
          <div class="field cfg-field">
            <label class="lbl">{{ t('nc.rttAlert') }}</label>
            <input class="input cfg-input" type="number" min="0" v-model.number="cfg.alerts.rttMs" />
          </div>
          <div class="field cfg-field">
            <label class="lbl">{{ t('nc.lossAlert') }}</label>
            <input class="input cfg-input" type="number" min="0" v-model.number="cfg.alerts.lossPct" />
          </div>
          <div class="field cfg-field">
            <label class="lbl">{{ t('nc.failStreak') }}</label>
            <input class="input cfg-input" type="number" min="1" v-model.number="cfg.alerts.failStreak" />
          </div>
        </div>
        <div class="form-row cfg-row">
          <div class="field cfg-field">
            <label class="lbl">{{ t('nc.netflow') }}</label>
            <div class="cfg-toggle">
              <span class="chip" :class="cfg.netflow.enabled ? 'on' : 'off'">{{ cfg.netflow.enabled ? t('nc.onText') : t('nc.offText') }}</span>
              <button class="btn xs" @click="cfg.netflow.enabled = !cfg.netflow.enabled">{{ cfg.netflow.enabled ? t('nc.btnOff') : t('nc.btnOn') }}</button>
            </div>
          </div>
          <div class="field cfg-field">
            <label class="lbl">{{ t('nc.netflowListen') }}</label>
            <input class="input cfg-input" v-model="cfg.netflow.listen" placeholder="0.0.0.0:2000" />
          </div>
        </div>
        <div class="field">
          <label class="lbl">{{ t('nc.whitelist') }} <span class="muted small">{{ t('nc.whitelistHint') }}</span></label>
          <textarea class="input" rows="3" v-model="whitelistText" placeholder="192.168.1.0/24, 10.0.0.0/8"></textarea>
        </div>
      </template>
    </div>

    <!-- 每节点告警阈值(Zabbix 式"全局默认 + 节点覆盖": 留空=跟全局, 填了=该节点独立阈值) -->
    <div class="card">
      <div class="card-title">{{ t('nc.perNodeTitle') }}
        <span class="sub">{{ t('nc.perNodeSub') }}</span>
      </div>
      <div v-if="!status.tasks || !status.tasks.length" class="empty-box">
        <span class="ph-tag">{{ t('nc.noTasks') }}</span> {{ t('nc.noTasksHint') }}
      </div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead><tr><th>{{ t('nc.cNode') }}</th><th>{{ t('nc.cCpu') }}</th><th>{{ t('nc.cMem') }}</th><th>{{ t('nc.cRtt') }}</th><th>{{ t('nc.cLoss') }}</th><th>{{ t('nc.cStreak') }}</th><th></th></tr></thead>
          <tbody>
            <tr v-for="tk in status.tasks" :key="tk.id">
              <td>
                <div class="small">{{ tk.name || tk.target }}</div>
                <div class="mono small muted">{{ tk.protocol }} · {{ tk.target }}</div>
              </td>
              <td><input class="input cfg-input" type="number" min="0" max="100" v-model="perNode[tk.id].cpuPct" :placeholder="t('nc.globalPh')" @input="onPerNodeInput" /></td>
              <td><input class="input cfg-input" type="number" min="0" max="100" v-model="perNode[tk.id].memPct" :placeholder="t('nc.globalPh')" @input="onPerNodeInput" /></td>
              <td><input class="input cfg-input" type="number" min="0" v-model="perNode[tk.id].rttMs" :placeholder="t('nc.globalPh')" @input="onPerNodeInput" /></td>
              <td><input class="input cfg-input" type="number" min="0" max="100" v-model="perNode[tk.id].lossPct" :placeholder="t('nc.globalPh')" @input="onPerNodeInput" /></td>
              <td><input class="input cfg-input" type="number" min="1" v-model="perNode[tk.id].failStreak" :placeholder="t('nc.globalPh')" @input="onPerNodeInput" /></td>
              <td><button class="btn xs" @click="resetPerNode(tk.id)" :disabled="!hasPerNode(tk.id)">{{ t('nc.reset') }}</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="form-row cfg-row" v-if="status.tasks && status.tasks.length">
        <div class="field" style="flex:1; align-self:center">
          <span class="muted small">{{ t('nc.globalNote', { cpu: cfg.alerts.cpuPct, mem: cfg.alerts.memPct, rtt: cfg.alerts.rttMs || t('nc.offWord'), loss: cfg.alerts.lossPct, n: cfg.alerts.failStreak }) }}</span>
        </div>
        <div class="field cfg-field" style="justify-content:flex-end">
          <button class="btn primary sm" @click="savePerNode" :disabled="perNodeSaving">{{ t('nc.savePerNode') }}</button>
        </div>
      </div>
    </div>

    <!-- 采集模板(2026-09-29 阶段 C, 借鉴 Zabbix 监控模板: 命名预设=协议+参数+默认阈值。
         建任务时选模板自动继承; 继承是一次性起点, 之后改模板不影响已建任务) -->
    <div class="card">
      <div class="card-title">{{ t('nc.tplTitle') }}
        <span class="sub">{{ t('nc.tplSub') }}</span>
      </div>
      <div v-if="!tplList.length" class="empty-box">
        <span class="ph-tag">{{ t('nc.noTpl') }}</span> {{ t('nc.noTplHint') }}
      </div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead><tr><th>{{ t('nc.cName') }}</th><th>{{ t('nc.cProto') }}</th><th>{{ t('nc.cAlerts') }}</th><th>{{ t('nc.cNote') }}</th><th class="a-r">{{ t('nc.cOp') }}</th></tr></thead>
          <tbody>
            <tr v-for="tp in tplList" :key="tp.id">
              <td class="small">{{ tp.name }}</td>
              <td><span class="chip proto">{{ protoLabel(tp.protocol) }}</span></td>
              <td class="mono small">{{ tplAlertsText(tp) }}</td>
              <td class="small muted">{{ tp.note || '—' }}</td>
              <td class="a-r"><button class="btn xs danger" @click="delTpl(tp)">{{ t('rp.del') }}</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="form-row cfg-row">
        <div class="field cfg-field"><label class="lbl">{{ t('nc.tName') }}</label>
          <input class="input cfg-input" v-model="tplForm.name" :placeholder="t('nc.tplNamePh')" /></div>
        <div class="field cfg-field"><label class="lbl">{{ t('nc.tProto') }}</label>
          <select class="input cfg-input" v-model="tplForm.protocol">
            <option v-for="p in tplProtocols" :key="p.name" :value="p.name">{{ p.label }}</option>
          </select></div>
        <div class="field cfg-field"><label class="lbl">{{ t('nc.cCpu') }}</label>
          <input class="input cfg-input" type="number" min="0" max="100" v-model="tplForm.cpuPct" :placeholder="t('nc.globalPh')" /></div>
        <div class="field cfg-field"><label class="lbl">{{ t('nc.cMem') }}</label>
          <input class="input cfg-input" type="number" min="0" max="100" v-model="tplForm.memPct" :placeholder="t('nc.globalPh')" /></div>
        <div class="field cfg-field"><label class="lbl">{{ t('nc.cRtt') }}</label>
          <input class="input cfg-input" type="number" min="0" v-model="tplForm.rttMs" :placeholder="t('nc.globalPh')" /></div>
        <div class="field cfg-field"><label class="lbl">{{ t('nc.cLoss') }}</label>
          <input class="input cfg-input" type="number" min="0" max="100" v-model="tplForm.lossPct" :placeholder="t('nc.globalPh')" /></div>
        <div class="field cfg-field"><label class="lbl">{{ t('nc.tNote') }}</label>
          <input class="input cfg-input" v-model="tplForm.note" :placeholder="t('nc.tplNotePh')" /></div>
        <div class="field" style="align-self:flex-end; justify-content:flex-end">
          <button class="btn primary sm" @click="saveTpl" :disabled="tplSaving">{{ t('nc.saveTpl') }}</button>
        </div>
      </div>
    </div>

    <!-- 异常事件已并入「告警日志管理 → 异常事件」Tab(2026-09-30 用户要求, 见文件头) -->
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { v2 } from '../api/http'
import { t } from '../i18n'

const status = ref({})
const cfg = reactive({
  enabled: false,
  intervalSec: 60,
  concurrent: 4,
  globalRate: 10,
  retentionHours: 24,
  whitelist: '',
  netflow: { enabled: false, listen: '0.0.0.0:2000' },
  alerts: { cpuPct: 90, memPct: 90, rttMs: 0, lossPct: 30, failStreak: 3 },
})
const saving = ref(false)
const advOpen = ref(false)
const whitelistText = ref('')

// ===== 每节点阈值覆盖(留空字符串 = 跟随全局; 提交时只带非空字段) =====
const perNode = ref({})
const perNodeSaving = ref(false)
const EMPTY_T = { cpuPct: '', memPct: '', rttMs: '', lossPct: '', failStreak: '' }
function syncPerNode(tasks, saved) {
  const out = {}
  for (const t of (tasks || [])) {
    const s = (saved && saved[t.id]) || {}
    out[t.id] = {
      cpuPct: s.cpuPct || '', memPct: s.memPct || '', rttMs: s.rttMs || '',
      lossPct: s.lossPct || '', failStreak: s.failStreak || '',
    }
  }
  perNode.value = out
}
function hasPerNode(id) {
  const v = perNode.value[id]
  return !!(v && (v.cpuPct || v.memPct || v.rttMs || v.lossPct || v.failStreak))
}
function resetPerNode(id) {
  perNode.value[id] = { ...EMPTY_T }
}

// ===== 采集模板(阶段 C, 借鉴 Zabbix 监控模板) =====
// 模板 = 命名预设(协议 + 默认阈值 + 说明)。建任务时选模板一次性继承。
// 整体替换语义: 增删都提交完整列表(与 perNode/authcheck 同口径)。
const tplList = ref([])
const tplSaving = ref(false)
const tplForm = ref(emptyTpl())
function emptyTpl() {
  return { name: '', protocol: '', cpuPct: '', memPct: '', rttMs: '', lossPct: '', note: '' }
}
const tplProtocols = computed(() =>
  (status.value.protocols || []).filter(p => p && !p.notInScheduler))
function protoLabel(name) {
  const p = (status.value.protocols || []).find(x => x.name === name)
  return p ? p.label : name
}
function tplAlertsText(tp) {
  const a = (tp && tp.alerts) || {}
  const parts = []
  if (a.cpuPct) parts.push(t('nc.tplCpu', { v: a.cpuPct }))
  if (a.memPct) parts.push(t('nc.tplMem', { v: a.memPct }))
  if (a.rttMs) parts.push(t('nc.tplRtt', { v: a.rttMs }))
  if (a.lossPct) parts.push(t('nc.tplLoss', { v: a.lossPct }))
  return parts.length ? parts.join(' · ') : t('nc.followGlobal')
}
function syncTpl(list) {
  tplList.value = (list || []).map(t => ({ ...t }))
}
function addTpl() {
  const name = (tplForm.value.name || '').trim()
  if (!name) { alert(t('nc.tplNameReq')); return }
  if (!tplForm.value.protocol) { alert(t('nc.tplProtoReq')); return }
  const alerts = {}
  if (tplForm.value.cpuPct) alerts.cpuPct = Number(tplForm.value.cpuPct)
  if (tplForm.value.memPct) alerts.memPct = Number(tplForm.value.memPct)
  if (tplForm.value.rttMs) alerts.rttMs = Number(tplForm.value.rttMs)
  if (tplForm.value.lossPct) alerts.lossPct = Number(tplForm.value.lossPct)
  const tpl = {
    id: 'tpl_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    name, protocol: tplForm.value.protocol,
    alerts: Object.keys(alerts).length ? alerts : {},
    note: (tplForm.value.note || '').trim(),
  }
  saveTplList([...tplList.value, tpl])
}
function delTpl(tp) {
  if (!confirm(t('nc.tplDelConfirm', { name: tp.name }))) return
  saveTplList(tplList.value.filter(x => x.id !== tp.id))
}
async function saveTplList(list) {
  tplSaving.value = true
  try {
    await v2('/node/templates', { method: 'PUT', body: { templates: list } })
    syncTpl(list)
    tplForm.value = emptyTpl()
  } catch (e) {
    alert(t('nc.tplSaveFail', { err: e.message }))
  } finally {
    tplSaving.value = false
  }
}
// 保存模板 = 追加当前表单
function saveTpl() { addTpl() }

async function loadStatus() {
  try {
    const st = await v2('/node/status')
    status.value = st
    cfg.enabled = !!st.enabled
    cfg.intervalSec = st.intervalSec || 60
    cfg.concurrent = st.concurrent || 4
    cfg.globalRate = st.globalRate || 10
    cfg.retentionHours = st.retentionHours || 24
    whitelistText.value = (st.whitelist || []).join(', ')
    if (st.netflowEnabled !== undefined) cfg.netflow.enabled = !!st.netflowEnabled
    if (st.netflowListen) cfg.netflow.listen = st.netflowListen
    if (st.alerts) {
      cfg.alerts.cpuPct = st.alerts.cpuPct ?? 90
      cfg.alerts.memPct = st.alerts.memPct ?? 90
      cfg.alerts.rttMs = st.alerts.rttMs ?? 0
      cfg.alerts.lossPct = st.alerts.lossPct ?? 30
      cfg.alerts.failStreak = st.alerts.failStreak ?? 3
    }
    // 只有"用户改过节点阈值"时才覆盖本地编辑中的值 —— 15s 轮询不能把
    // 表格里正在输入的数字冲掉(与推送配置表单同一竞态口径)。
    if (!perNodeEditing) syncPerNode(st.tasks, st.perNode)
    syncTpl(st.templates)
  } catch (e) {
    console.warn('load node status failed', e)
  }
}
let perNodeEditing = false
// 输入事件置位(任意节点阈值输入框 @input): 轮询暂停覆盖, 保存后恢复
function onPerNodeInput() { perNodeEditing = true }
// 提交: 只带非空字段(0 语义=跟随全局, 与后端 AlertsFor 的覆盖口径一致)
async function savePerNode() {
  perNodeSaving.value = true
  try {
    const out = {}
    for (const t of (status.value.tasks || [])) {
      const v = perNode.value[t.id]
      if (!v) continue
      const item = {}
      if (v.cpuPct) item.cpuPct = Number(v.cpuPct)
      if (v.memPct) item.memPct = Number(v.memPct)
      if (v.rttMs) item.rttMs = Number(v.rttMs)
      if (v.lossPct) item.lossPct = Number(v.lossPct)
      if (v.failStreak) item.failStreak = Number(v.failStreak)
      if (Object.keys(item).length) out[t.id] = item
    }
    await v2('/node/alert/thresholds', { method: 'PUT', body: { perNode: out } })
    await loadStatus()
  } catch (e) {
    alert(t('nc.saveFail', { err: e.message }))
  } finally {
    perNodeSaving.value = false
    perNodeEditing = false
  }
}

async function saveConfig() {
  saving.value = true
  try {
    const whitelist = whitelistText.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
    await v2('/node/config', {
      method: 'POST',
      body: {
        enabled: cfg.enabled,
        intervalSec: cfg.intervalSec,
        concurrent: cfg.concurrent,
        globalRate: cfg.globalRate,
        retentionHours: cfg.retentionHours,
        whitelist,
        netflow: cfg.netflow,
        alerts: cfg.alerts,
      },
    })
    await loadStatus()
  } catch (e) {
    alert(t('nc.saveFail', { err: e.message }))
  } finally {
    saving.value = false
  }
}

async function toggleEnabled() {
  cfg.enabled = !cfg.enabled
  saving.value = true
  try {
    await v2('/node/config', { method: 'POST', body: { enabled: cfg.enabled } })
    await loadStatus()
  } catch (e) {
    alert(t('nc.toggleFail', { err: e.message }))
  } finally {
    saving.value = false
  }
}

let timer = null
onMounted(() => {
  loadStatus()
  timer = setInterval(loadStatus, 15000)
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.cfg-row { flex-wrap: wrap; }
.cfg-field { min-width: 130px; }
.cfg-input { width: 100%; }
.cfg-toggle { display: flex; align-items: center; gap: 6px; }
.chip.warn { background: rgba(255, 176, 32, .14); color: var(--orange); }
/* 采集模板卡: 协议 chip + 右对齐操作列(与 CollectSection 同口径) */
.chip.proto { background: rgba(77, 163, 255, .12); color: var(--blue, #4da3ff); }
.a-r { text-align: right; }
</style>
