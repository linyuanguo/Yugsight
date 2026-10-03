<template>
  <div>
    <PageHeader title="漏洞管理" desc="全部漏洞记录 · 漏扫管控(白名单/误报/置信度)"></PageHeader>

    <div class="tabs" style="margin-bottom:14px">
      <div class="tab" :class="{ active: tab === 'list' }" @click="setTab('list')">漏洞列表 ({{ total }})</div>
      <div class="tab" :class="{ active: tab === 'control' }" @click="setTab('control')">漏扫管控</div>
    </div>

    <div class="card" v-if="tab === 'list'">
      <div class="toolbar">
        <!-- 2026-10-02 用户口径: 筛选选项基于当前数据里存在的 —— 等级/状态选项由
             /vulns/options 按全量漏洞库聚合(列表是分页接口, 当前页取不全); 删光
             某类数据后选项消失, 后期有了再出现 -->
        <select class="select" v-model="f.severity">
          <option value="">全部等级</option>
          <option v-for="s in vulnOpts.severities" :key="s" :value="s">{{ SEV_CN[s] || s }}</option>
        </select>
        <!-- 两态口径: 开放(含历史 new/duplicate) / 已修复; 重复命中见"最后命中"列 -->
        <select class="select" v-model="f.status">
          <option value="">全部状态</option>
          <option v-for="s in vulnOpts.statuses" :key="s.id" :value="s.id">{{ s.id === 'fixed' ? '已修复' : '开放' }} ({{ s.count }})</option>
        </select>
        <input class="input mono" v-model.trim="f.cve" placeholder="CVE 编号" @keyup.enter="reload">
        <input class="input mono" v-model.trim="f.ip" placeholder="资产 IP" @keyup.enter="reload">
        <input class="input" v-model.trim="f.title" placeholder="标题关键字" @keyup.enter="reload">
        <button class="btn sm" @click="reload">查询</button>
        <!-- 旧按钮名叫"清空", 与下面的"清空全部漏洞"混在一起被当成"清库没反应" -->
        <button class="btn sm" @click="resetF" title="清空筛选条件并回到第 1 页">重置筛选</button>
        <div class="spacer"></div>
        <span class="muted small">共 {{ total }} 条</span>
        <!-- 阶段 5 联动: 选中漏洞 -> 渗透工作台做验证渗透(仅管理员)。
             operator/auditor 不给入口: 渗透是攻击性能力, 权限边界比本页写操作更严 -->
        <span class="chip warn" v-if="selCount">已选 {{ selCount }} 条</span>
        <button class="btn sm primary" v-if="admin && selCount" @click="sendToPenta"
                title="把选中的漏洞作为已知漏洞导入渗透工作台执行验证(全程审计)">发送到渗透工作台</button>
        <button class="btn sm danger" v-if="canWrite" :disabled="total === 0" title="删除本库全部漏洞记录(资产/任务/白名单不受影响, 操作记审计)"
                @click="openClear">清空全部漏洞</button>
      </div>

      <!-- 发送失败留在当前页, 提示必须可见(跳转成功则整页切走, 用不到) -->
      <div class="err-line" v-if="sendMsg" style="margin-bottom:8px; color:var(--danger,#e5484d)">{{ sendMsg }}</div>

      <div class="table-wrap" v-if="list.length">
        <table class="table">
          <thead>
            <tr>
              <th style="width:36px"><input type="checkbox" :checked="allChecked" @change="toggleAll"></th>
              <th>等级</th><th>标题</th><th>CVE</th><th>资产</th><th>端口</th>
              <th>置信度</th><th>状态</th><th>来源</th><th>发现时间</th><th>最后命中</th><th style="width:96px">渗透验证</th>
            </tr>
          </thead>
          <tbody>
            <tr class="clickable" v-for="v in list" :key="v.id" @click="$router.push('/vulns/' + v.id)">
              <!-- @click.stop: 复选框不能触发整行的详情跳转 -->
              <td @click.stop><input type="checkbox" v-model="sel[v.id]"></td>
              <td><SevTag :sev="v.severity" /></td>
              <td>
                <b style="font-size:12.5px">{{ v.title }}</b>
                <span class="badge" v-if="v.falsePositive" style="color:var(--muted); border-style:dashed; margin-left:6px" :title="v.fpNote || '人工标记误报'">误报</span>
              </td>
              <td class="mono small">{{ v.cve || '-' }}</td>
              <td class="mono small">{{ v.assetIp }}</td>
              <td class="mono small">{{ v.port || '-' }}</td>
              <td class="mono small">{{ v.confidence != null ? v.confidence : '-' }}</td>
              <td>
                <StatusTag :status="vulnStatus(v.status)" />
                <span class="muted small" v-if="v.lastSeenAt && v.foundAt && v.lastSeenAt !== v.foundAt"
                      :title="'重复命中, 最近一次: ' + fmtDT(v.lastSeenAt)">· 重</span>
              </td>
              <td class="small muted">{{ v.source || '-' }}</td>
              <td class="muted small mono">{{ fmtDT(v.foundAt) }}</td>
              <td class="muted small mono" :title="v.lastSeenAt && v.lastSeenAt !== v.foundAt ? '重复命中' : ''">{{ fmtDT(v.lastSeenAt) }}</td>
              <td>
                <span class="badge" v-if="v.pentaResult" :style="expStyle(v.pentaResult)"
                      :title="'渗透任务 ' + (v.pentaTaskId || '-') + ' 已回传'">{{ expName(v.pentaResult) }}</span>
                <span class="muted small" v-else>未验证</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else :text="hasFilter ? '无匹配漏洞' : '暂无漏洞记录(扫描结果经回传通道写入本库)'" />

      <div class="pager" v-if="total > page * size">
        <span>第 {{ page }} 页</span>
        <div class="spacer"></div>
        <button class="btn xs" :disabled="page <= 1" @click="page--; load()">上一页</button>
        <button class="btn xs" :disabled="page * size >= total" @click="page++; load()">下一页</button>
      </div>
    </div>

    <!-- 漏扫管控并入(2026-09-26): 白名单/误报/置信度, 内嵌 Whitelist 组件(embedded 隐藏其自身 PageHeader) -->
    <Whitelist v-if="tab === 'control'" embedded />

    <!-- 清空全部漏洞: 不可逆, 要求输入确认词(与"删一条"的 confirm 区分开) -->
    <Modal v-if="showClear" title="清空全部漏洞" width="460px" @close="closeClear">
      <div class="alert warn" style="margin-bottom:12px">
        将删除本库全部 <b>{{ total }}</b> 条漏洞记录, 不可恢复。
        资产台账、扫描任务、白名单与误报规则都不受影响; 本次操作会写入审计日志。
      </div>
      <div class="field">
        <label class="label">请输入"清空"以确认</label>
        <input class="input" v-model.trim="clearWord" placeholder="清空" @keyup.enter="doClear">
      </div>
      <div class="login-err" style="text-align:left">{{ clearErr }}</div>
      <template #footer>
        <button class="btn" @click="closeClear">取消</button>
        <button class="btn danger" :disabled="clearWord !== '清空' || clearing" @click="doClear">确认清空</button>
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
function expName(s) {
  return { exploitable: '可利用', partial: '部分利用', not_exploitable: '不可利用' }[s] || s || '-'
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
      sendMsg.value = `已导入 ${d.created} 条，跳过旧任务 ${d.skipped} 条，不存在 ${d.missing} 条`
    }
  } catch (e) {
    sendMsg.value = '发送到渗透工作台失败: ' + e.message
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
const SEV_CN = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
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
  if (clearWord.value !== '清空' || clearing.value) return
  clearing.value = true
  clearErr.value = ''
  try {
    const d = await v2('/vulns', { method: 'DELETE' })
    showClear.value = false
    page.value = 1
    await load()
    loadVulnOpts()   // 清库后刷新筛选选项(等级/状态全没了要同步消失)
    alert('已清空 ' + ((d && d.deleted != null) ? d.deleted : 0) + ' 条漏洞记录')
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
