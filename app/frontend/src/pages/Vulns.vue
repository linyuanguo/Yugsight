<template>
  <div>
    <PageHeader :title="t('vn.title')" :desc="t('vn.desc')"></PageHeader>

    <div class="tabs" style="margin-bottom:14px">
      <div class="tab" :class="{ active: tab === 'list' }" @click="setTab('list')">{{ t('vn.tabList') }} ({{ total }})</div>
      <div class="tab" :class="{ active: tab === 'control' }" @click="setTab('control')">{{ t('vn.tabControl') }}</div>
    </div>

    <div class="card" v-if="tab === 'list'">
      <div class="toolbar">
        <!-- 2026-10-02 用户口径: 筛选选项基于当前数据里存在的 —— 等级/状态选项由
             /vulns/options 按全量漏洞库聚合(列表是分页接口, 当前页取不全); 删光
             某类数据后选项消失, 后期有了再出现 -->
        <select class="select" v-model="f.severity">
          <option value="">{{ t('vn.allSev') }}</option>
          <option v-for="s in vulnOpts.severities" :key="s" :value="s">{{ sevName(s) }}</option>
        </select>
        <!-- 两态口径: 开放(含历史 new/duplicate) / 已修复; 重复命中见"最后命中"列 -->
        <select class="select" v-model="f.status">
          <option value="">{{ t('vn.allStatus') }}</option>
          <option v-for="s in vulnOpts.statuses" :key="s.id" :value="s.id">{{ s.id === 'fixed' ? t('vn.stFixed') : t('vn.stOpen') }} ({{ s.count }})</option>
        </select>
        <input class="input mono" v-model.trim="f.cve" :placeholder="t('vn.cvePh')" @keyup.enter="reload">
        <input class="input mono" v-model.trim="f.ip" :placeholder="t('vn.ipPh')" @keyup.enter="reload">
        <input class="input" v-model.trim="f.title" :placeholder="t('vn.titlePh')" @keyup.enter="reload">
        <button class="btn sm" @click="reload">{{ t('common.query') }}</button>
        <!-- 旧按钮名叫"清空", 与下面的"清空全部漏洞"混在一起被当成"清库没反应" -->
        <button class="btn sm" @click="resetF" :title="t('vn.resetFilterTitle')">{{ t('vn.resetFilter') }}</button>
        <div class="spacer"></div>
        <span class="muted small">{{ t('vn.total', { n: total }) }}</span>
        <!-- 阶段 5 联动: 选中漏洞 -> 渗透工作台做验证渗透(仅管理员)。
             operator/auditor 不给入口: 渗透是攻击性能力, 权限边界比本页写操作更严 -->
        <span class="chip warn" v-if="selCount">{{ t('vn.selCount', { n: selCount }) }}</span>
        <button class="btn sm primary" v-if="admin && selCount" @click="sendToPenta"
                :title="t('vn.sendPentaTitle')">{{ t('vn.sendPenta') }}</button>
        <button class="btn sm danger" v-if="canWrite" :disabled="total === 0" :title="t('vn.clearAllTitle')"
                @click="openClear">{{ t('vn.clearAll') }}</button>
      </div>

      <!-- 发送失败留在当前页, 提示必须可见(跳转成功则整页切走, 用不到) -->
      <div class="err-line" v-if="sendMsg" style="margin-bottom:8px; color:var(--danger,#e5484d)">{{ sendMsg }}</div>

      <div class="table-wrap" v-if="list.length">
        <table class="table">
          <thead>
            <tr>
              <th style="width:36px"><input type="checkbox" :checked="allChecked" @change="toggleAll"></th>
              <th>{{ t('vn.thSev') }}</th><th>{{ t('vn.thTitle') }}</th><th>CVE</th><th>{{ t('vn.thAsset') }}</th><th>{{ t('vn.thPort') }}</th>
              <th>{{ t('vn.thConf') }}</th><th>{{ t('vn.thStatus') }}</th><th>{{ t('vn.thSource') }}</th><th>{{ t('vn.thFound') }}</th><th>{{ t('vn.thLastHit') }}</th><th style="width:96px">{{ t('vn.thPenta') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr class="clickable" v-for="v in list" :key="v.id" @click="$router.push('/vulns/' + v.id)">
              <!-- @click.stop: 复选框不能触发整行的详情跳转 -->
              <td @click.stop><input type="checkbox" v-model="sel[v.id]"></td>
              <td><SevTag :sev="v.severity" /></td>
              <td>
                <b style="font-size:12.5px">{{ v.title }}</b>
                <span class="badge" v-if="v.falsePositive" style="color:var(--muted); border-style:dashed; margin-left:6px" :title="v.fpNote || t('vn.fpManual')">{{ t('vn.fp') }}</span>
              </td>
              <td class="mono small">{{ v.cve || '-' }}</td>
              <td class="mono small">{{ v.assetIp }}</td>
              <td class="mono small">{{ v.port || '-' }}</td>
              <td class="mono small">{{ v.confidence != null ? v.confidence : '-' }}</td>
              <td>
                <StatusTag :status="vulnStatus(v.status)" />
                <span class="muted small" v-if="v.lastSeenAt && v.foundAt && v.lastSeenAt !== v.foundAt"
                      :title="t('vn.dup', { time: fmtDT(v.lastSeenAt) })">{{ t('vn.dupMark') }}</span>
              </td>
              <td class="small muted">{{ v.source || '-' }}</td>
              <td class="muted small mono">{{ fmtDT(v.foundAt) }}</td>
              <td class="muted small mono" :title="v.lastSeenAt && v.lastSeenAt !== v.foundAt ? t('vn.dupShort') : ''">{{ fmtDT(v.lastSeenAt) }}</td>
              <td>
                <span class="badge" v-if="v.pentaResult" :style="expStyle(v.pentaResult)"
                      :title="t('vn.pentaTaskTitle', { id: v.pentaTaskId || '-' })">{{ expName(v.pentaResult) }}</span>
                <span class="muted small" v-else>{{ t('vn.unverified') }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else :text="hasFilter ? t('vn.noMatch') : t('vn.none')" />

      <div class="pager" v-if="total > page * size">
        <span>{{ t('vn.page', { n: page }) }}</span>
        <div class="spacer"></div>
        <button class="btn xs" :disabled="page <= 1" @click="page--; load()">{{ t('al.prev') }}</button>
        <button class="btn xs" :disabled="page * size >= total" @click="page++; load()">{{ t('al.next') }}</button>
      </div>
    </div>

    <!-- 漏扫管控并入(2026-09-26): 白名单/误报/置信度, 内嵌 Whitelist 组件(embedded 隐藏其自身 PageHeader) -->
    <Whitelist v-if="tab === 'control'" embedded />

    <!-- 清空全部漏洞: 不可逆, 要求输入确认词(与"删一条"的 confirm 区分开) -->
    <Modal v-if="showClear" :title="t('vn.clearTitle')" width="460px" @close="closeClear">
      <div class="alert warn" style="margin-bottom:12px">
        {{ t('vn.clearHint1', { n: total }) }}
        {{ t('vn.clearHint2') }}
      </div>
      <div class="field">
        <label class="label">{{ t('vn.clearInput') }}</label>
        <input class="input" v-model.trim="clearWord" :placeholder="t('vn.clearWord')" @keyup.enter="doClear">
      </div>
      <div class="login-err" style="text-align:left">{{ clearErr }}</div>
      <template #footer>
        <button class="btn" @click="closeClear">{{ t('common.cancel') }}</button>
        <button class="btn danger" :disabled="clearWord !== t('vn.clearWord') || clearing" @click="doClear">{{ t('vn.clearConfirm') }}</button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { setPageData } from '../assistant/context'
import PageHeader from '../components/PageHeader.vue'
import Whitelist from './Whitelist.vue'
import SevTag from '../components/SevTag.vue'
import StatusTag from '../components/StatusTag.vue'
import Modal from '../components/Modal.vue'
import Empty from '../components/Empty.vue'
import { v2, api } from '../api/http'
import { fmtDT, vulnStatus } from '../utils'
import { isAdmin } from '../auth'
import { t } from '../i18n'

const router = useRouter()
const route = useRoute()
// 漏扫管控并入漏洞管理(2026-09-26): URL query 驱动 tab; 旧 /whitelist 重定向到 ?tab=control
const tab = computed(() => (route.query.tab === 'control' ? 'control' : 'list'))
// 2026-09-27: 列表状态(筛选/分页)URL 持久化 —— 详情页"返回"用 router.back()
// 回到带 query 的精确列表 URL, 原筛选条件/分页/排序全部保留; 刷新/书签也不丢。
// 键名用短形式: sev/status/cve/ip/title/page。
function listQuery() {
  const q = {}
  if (f.severity) q.sev = f.severity
  if (f.status) q.status = f.status
  if (f.cve) q.cve = f.cve
  if (f.ip) q.ip = f.ip
  if (f.title) q.title = f.title
  if (page.value > 1) q.page = String(page.value)
  return q
}
function queryEq(a, b) {
  const ka = Object.keys(a).sort(), kb = Object.keys(b).sort()
  if (ka.length !== kb.length) return false
  return ka.every(k => a[k] === b[k])
}
function syncQuery() {
  const q = listQuery()
  if (route.query.tab === 'control') q.tab = 'control'
  if (!queryEq(route.query, q)) router.replace({ query: q }) // replace 不堆历史(后退应离开本页)
}
function initFromQuery() {
  const q = route.query
  if (q.sev) f.severity = String(q.sev)
  if (q.status === 'open' || q.status === 'fixed') f.status = String(q.status)
  if (q.cve) f.cve = String(q.cve)
  if (q.ip) f.ip = String(q.ip)
  if (q.title) f.title = String(q.title)
  if (q.page) {
    const n = parseInt(String(q.page), 10)
    if (n > 0) page.value = n
  }
}
function setTab(t) {
  if (t === tab.value) return
  const q = listQuery() // 切 tab 不清空列表状态(切回列表 tab 时还在)
  if (t === 'control') q.tab = 'control'
  else delete q.tab
  router.replace({ path: '/vulns', query: q })
}
// admin 必须 computed 跟随 auth.js 的响应式角色: 整页刷新时本组件可能在
// whoami 返回前挂载, 快照式 ref(isAdmin()) 会永远拿到 false(阶段 4 已踩过)
const admin = computed(() => isAdmin())
// 多选 -> 「发送到渗透工作台」(阶段 5 联动入口)
const sel = reactive({})
const sendMsg = ref('')
const selCount = computed(() => Object.values(sel).filter(Boolean).length)
const allChecked = computed(() => list.value.length > 0 && list.value.every((v) => sel[v.id]))
function toggleAll(e) {
  const on = e.target.checked
  for (const v of list.value) sel[v.id] = on
}
// 渗透验证结论文案与配色(与渗透工作台同口径, 便于用户跨页对齐认知)
const EXP_KEY = { exploitable: 'vn.expExploitable', partial: 'vn.expPartial', not_exploitable: 'vn.expNot' }
function expName(s) {
  return EXP_KEY[s] ? t(EXP_KEY[s]) : (s || '-')
}
function expStyle(s) {
  if (s === 'exploitable') return { color: '#fff', background: 'var(--danger,#e5484d)', borderColor: 'transparent' }
  if (s === 'partial') return { color: '#fff', background: 'var(--warning,#f0b429)', borderColor: 'transparent' }
  return { color: 'var(--muted,#8b93a7)' }
}
async function sendToPenta() {
  const ids = Object.keys(sel).filter((k) => sel[k])
  if (!ids.length) return
  try {
    const d = await v2('/penta/tasks/import', { method: 'POST', body: { vulnIds: ids } })
    sendMsg.value = ''
    for (const k of Object.keys(sel)) sel[k] = false
    // 跳转后再提示: 目标页面会自动带上这批任务, 提示只是补一句"已导入"
    router.push('/penta')
    if (d && (d.skipped || d.missing)) {
      sendMsg.value = t('vn.imported', { created: d.created, skipped: d.skipped, missing: d.missing })
    }
  } catch (e) {
    sendMsg.value = t('vn.sendFail', { err: e.message })
  }
}

const list = ref([])
const total = ref(0)
const page = ref(1)
const size = 20
const f = reactive({ severity: '', status: '', cve: '', ip: '', title: '' })
// canWrite: admin/operator 才显示"清空全部漏洞"(auditor 是只读角色);
// 真正边界在后端 adminOrOperator 中间件, 这里只是不给只读角色一个必然 403 的按钮
const canWrite = ref(false)

// 2026-10-02: 等级/状态筛选选项 = 全量漏洞库聚合(后端 /vulns/options), 只含存在的值
const SEV_KEY = { critical: 'sev.critical', high: 'sev.high', medium: 'sev.medium', low: 'sev.low', info: 'sev.info' }
function sevName(s) { return SEV_KEY[s] ? t(SEV_KEY[s]) : (s || '') }
const vulnOpts = ref({ severities: [], statuses: [] })
async function loadVulnOpts() {
  try {
    const d = await v2('/vulns/options')
    if (d) {
      vulnOpts.value = { severities: d.severities || [], statuses: d.statuses || [] }
      // 已选的等级/状态对应数据被删光 → 选项消失, 筛选要自清, 否则列表卡死为空
      let reset = false
      if (f.severity && !vulnOpts.value.severities.includes(f.severity)) { f.severity = ''; reset = true }
      if (f.status && !vulnOpts.value.statuses.some(s => s.id === f.status)) { f.status = ''; reset = true }
      if (reset) load()
    }
  } catch (e) { /* 选项失败不影响列表 */ }
}

const hasFilter = computed(() => !!(f.severity || f.status || f.cve || f.ip || f.title))

const showClear = ref(false)
const clearWord = ref('')
const clearErr = ref('')
const clearing = ref(false)

async function load() {
  const p = new URLSearchParams({ page: String(page.value), size: String(size) })
  for (const k of ['severity', 'status', 'cve', 'ip', 'title']) {
    if (f[k]) p.set(k, f[k])
  }
  const d = await v2('/vulns?' + p.toString())
  list.value = d.list || []
  total.value = d.total || 0
}

function reload() { page.value = 1; load().catch(e => alert(e.message)) }

// 小 Y 助手(2026-09-27): 向助手注册本页关键数据(getter 惰性求值, 提问/上报时
// 读到的是当前列表+筛选状态)。纯 add 式接入, 不改既有逻辑。
setPageData('vulns', () => ({
  total: total.value,
  page: page.value,
  filters: { severity: f.severity, status: f.status, cve: f.cve, ip: f.ip, title: f.title },
  list: list.value.slice(0, 50).map(v => ({
    title: v.title, severity: v.severity, status: v.status, cve: v.cve || '', ip: v.ip || ''
  }))
}))
function resetF() {
  Object.assign(f, { severity: '', status: '', cve: '', ip: '', title: '' })
  reload()
}

function openClear() {
  clearWord.value = ''
  clearErr.value = ''
  showClear.value = true
}
function closeClear() { showClear.value = false }

async function doClear() {
  if (clearWord.value !== t('vn.clearWord') || clearing.value) return
  clearing.value = true
  clearErr.value = ''
  try {
    const d = await v2('/vulns', { method: 'DELETE' })
    showClear.value = false
    page.value = 1
    await load()
    loadVulnOpts()   // 清库后刷新筛选选项(等级/状态全没了要同步消失)
    alert(t('vn.cleared', { n: (d && d.deleted != null) ? d.deleted : 0 }))
  } catch (e) {
    clearErr.value = e.message
  } finally { clearing.value = false }
}

async function loadRole() {
  try {
    const me = await api('/api/whoami')
    canWrite.value = me.role === 'admin' || me.role === 'operator'
  } catch (e) {
    canWrite.value = false // 取不到角色就不显示写入口
  }
}

// 2026-09-27: 挂载时先从 URL 还原列表状态(必须在首次 load 之前)
initFromQuery()
// 筛选/分页变化 → 同步到 URL(详情页"返回"时据此还原, 见 syncQuery 注释)
watch([() => f.severity, () => f.status, () => f.cve, () => f.ip, () => f.title, page], syncQuery)

onMounted(loadRole)
load().catch(e => alert(e.message))
loadVulnOpts()
</script>
