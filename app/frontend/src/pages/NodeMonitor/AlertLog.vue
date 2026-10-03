<!--
  AlertLog.vue 节点监控「告警」页(2026-09-28; 2026-09-30 增"异常事件"Tab)
  四个 tab:
    1. 告警记录: 后端真实告警(采集引擎异常事件自动生成, node_alerts 表),
       含推送状态列(未推送/推送成功/推送失败), 5s 轮询实时刷新,
       推送失败行标红 + 操作列"重推"按钮(POST /api/node/push/retry)。
       推送触发/规则匹配/消息发送全部由后端执行, 前端只展示 + 手动重推。
    2. 推送日志: 后端 push_logs 表(每次"告警 × 目标"的发送结果),
       关联告警 ID 列(点击跳转定位到对应告警记录), 失败行标红 + 悬浮失败原因,
       支持按告警级别 / 推送目标 / 状态 / 时间筛选。
    3. 推送配置(2026-09-28 补齐): 推送目标管理(PushTargetList) + 规则与推送窗口
       (PushRuleConfig), 深链 ?tab=push —— 3D 拓扑页「告警设置」的「完整配置」
       按钮跳到这里(分层边界: 拓扑侧只给总开关/概览, 完整配置在节点管理侧;
       该组件现封存, 第三阶段对接时恢复)。
       规则表单有未保存修改时经 setGuard 拦截菜单切换(父页 NodeMonitor 在
       setView 路由变化【前】询问, 见该页注释)。
    4. 异常事件(2026-09-30 用户要求合并): 采集底座原始事件流(/api/v2/node/events,
       collect_events 表, 保留 30 天)—— 此前在「协议配置 → 采集配置」的"异常事件"
       卡单独显示, 与告警记录同源重复, 整体并入本页; "AI 分析(告警)"按钮
       (AiAnalyzeButton module=collect)随卡一并迁移到这里。
  数据: 来自后端 /api/node/push/*(api/nodepush.js) 与 /api/v2/node/events, 无本地存储。
-->
<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHeader from '../../components/PageHeader.vue'
import PushTargetList from '../../components/node/PushTargetList.vue'
import PushRuleConfig from '../../components/node/PushRuleConfig.vue'
import { toast } from '../../toast'
import { fmtDT } from '../../utils'
import { v2 } from '../../api/http'
import { LEVELS, LEVEL_LABEL, SOURCE_LABEL, PUSH_STATUS_LABEL, pushStore } from '../../utils/nodepush'
import { fetchAlerts, retryPush, setAlertHandled, fetchLogs } from '../../api/nodepush'
import AiAnalyzeButton from '../../components/AiAnalyzeButton.vue'
import { t } from '../../i18n'

const props = defineProps({
  // 父页(NodeMonitor)注入的离开守卫注册口: 传 fn(返回 false 拦截) 或 null 注销
  setGuard: { type: Function, default: null },
})

const route = useRoute()
const router = useRouter()

// tab: records=告警记录 / plog=推送日志 / push=推送配置 / events=异常事件
// (路由 ?tab= 持久化, 默认 records)
const tab = computed(() => ['plog', 'push', 'events'].includes(route.query.tab) ? route.query.tab : 'records')
function switchTab(t) {
  router.replace({ path: '/nodemonitor', query: { view: 'alerts', tab: t } })
}

// ===== 推送配置未保存守卫 =====
// PushRuleConfig 的 dirty(表单 vs 已保存快照)上抛到这里; 未保存时拦截:
//   ① 菜单切走(父页 setView 在路由变化前调用本 fn) ② 浏览器刷新/关闭(beforeunload)。
const pushDirty = ref(false)
function onPushDirty(d) { pushDirty.value = !!d }
function leaveGuard() {
  if (!pushDirty.value) return true
  return window.confirm(t('al.leaveConfirm'))
}
onMounted(() => { if (props.setGuard) props.setGuard(leaveGuard) })
onBeforeUnmount(() => {
  if (props.setGuard) props.setGuard(null)
  if (onBeforeUnload) window.removeEventListener('beforeunload', onBeforeUnload)
})
let onBeforeUnload = null
watch(pushDirty, (d) => {
  if (d) {
    onBeforeUnload = (e) => { e.preventDefault(); e.returnValue = '' }
    window.addEventListener('beforeunload', onBeforeUnload)
  } else if (onBeforeUnload) {
    window.removeEventListener('beforeunload', onBeforeUnload)
    onBeforeUnload = null
  }
})

// ===== tab 1: 告警记录(后端 node_alerts 表, 5s 轮询实时刷新推送状态) =====
const ALERT_POLL_MS = 5000
const alerts = ref([])
const alertsTotal = ref(0)
const alertsErr = ref('')
let pollTimer = null

async function loadAlerts(silent = false) {
  try {
    const d = await fetchAlerts(200)
    alerts.value = d.list
    alertsTotal.value = d.total
    alertsErr.value = ''
  } catch (e) {
    if (!silent) alertsErr.value = e.message // 保留上一轮列表, 不整体清空
  }
}
function startPoll() {
  stopPoll()
  loadAlerts()
  loadLogs(true)   // 2026-09-30 用户反馈: 进页面时"推送日志"徽章显示 0(原设计切到该 tab 才拉) —— 进页即初始化计数
  pollTimer = setInterval(() => {
    loadAlerts(true)
    loadLogs(true)  // 推送日志由告警推送产生, 随告警同拍静默刷新, 徽章常驻准确
  }, ALERT_POLL_MS)
}
function stopPoll() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null } }
onMounted(startPoll)
onBeforeUnmount(stopPoll)

// 筛选(客户端作用于最近 200 条)
const fLevel = ref('')
const fFrom = ref('')
const fTo = ref('')
// 2026-10-02: 级别选项 = 当前告警列表里真实出现的级别(全被裁剪后选项消失)
const levelOpts = computed(() => LEVELS.filter(l => alerts.value.some(a => a.level === l.key)))
watch(alerts, () => {
  if (fLevel.value && !levelOpts.value.some(l => l.key === fLevel.value)) fLevel.value = ''
})
const filtered = computed(() => {
  let list = alerts.value
  if (fLevel.value) list = list.filter(a => a.level === fLevel.value)
  if (fFrom.value) list = list.filter(a => new Date(a.at) >= new Date(fFrom.value))
  if (fTo.value) list = list.filter(a => new Date(a.at) <= new Date(fTo.value + 'T23:59:59'))
  return list
})

// 处理标记(确认/忽略, 存后端; 再次点击撤销)
async function setHandled(a, v) {
  const prev = a.handled
  const next = (a.handled === v) ? '' : v
  a.handled = next
  try {
    await setAlertHandled(a.id, next)
  } catch (e) {
    a.handled = prev
    toast(t('al.opFail', { err: e.message }), 'err')
  }
}

// 手动重推(仅推送失败的告警显示; 后端同步执行, 返回终态)
const retryingId = ref('')
async function doRetry(a) {
  if (retryingId.value) return
  retryingId.value = a.id
  try {
    const d = await retryPush(a.id)
    const ok = d && d.status === 'pushed'
    toast(ok ? t('al.retryOk') : t('al.retryFail'), ok ? 'ok' : 'err')
    await loadAlerts(true) // 刷新推送状态
    loadLogs(true)         // 刷新推送日志(新产生的日志立即可见)
  } catch (e) {
    toast(t('al.retryErr', { err: e.message }), 'err')
  } finally {
    retryingId.value = ''
  }
}

// 关联告警深链(推送日志行点击 → ?alertId=<id>): 等列表就绪后滚动定位 + 高亮闪烁。
// 定位成功后清掉 alertId, 保留 tab=records(view=alerts 是本页默认态)。
watch(() => route.query.alertId, (id) => {
  if (!id) return
  let tries = 0
  const attempt = () => {
    const row = document.querySelector('tr[data-alert-id="' + id + '"]')
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' })
      row.classList.add('row-flash')
      setTimeout(() => row.classList.remove('row-flash'), 2800)
    } else if (tries === 3) {
      // 列表已就绪但行不在: 可能被级别/时间筛选挡掉 → 清筛选再试
      fLevel.value = ''; fFrom.value = ''; fTo.value = ''
    } else if (tries >= 15) {
      toast(t('al.notFound'), 'info')
    }
    tries++
    if (tries < 15) setTimeout(attempt, 300) // 等 5s 轮询的首次拉取
  }
  attempt()
  router.replace({ path: '/nodemonitor', query: { view: 'alerts', tab: 'records' } })
})

// ===== tab 2: 推送日志(后端 push_logs 表, 与告警记录一一对应) =====
const logs = ref([])
const logTotal = ref(0)
const logPage = ref(1)
const logErr = ref('')
const logFrom = ref('')
const logTo = ref('')
const logStatus = ref('')
const logLevel = ref('')   // 按告警级别筛选
const logTarget = ref('')  // 按推送目标(名称)筛选
// 2026-10-02: 状态/级别/目标筛选选项 = 后端按全量日志聚合回带(只含真实存在的值)
const logStatusOpts = ref([])
const logLevelOpts = ref([])
const logTargetOpts = ref([])

async function loadLogs(silent = false) {
  try {
    const d = await fetchLogs({
      page: logPage.value, size: 20,
      start: logFrom.value, end: logTo.value,
      status: logStatus.value, level: logLevel.value, target: logTarget.value
    })
    logs.value = d.list
    logTotal.value = d.total
    logStatusOpts.value = d.statuses || []
    logLevelOpts.value = d.levels || []
    logTargetOpts.value = d.targets || []
    // 已选筛选值对应日志全删 → 选项消失, 筛选自清(防列表卡死为空)
    if (logStatus.value && !logStatusOpts.value.some(s => s.id === logStatus.value)) logStatus.value = ''
    if (logLevel.value && !logLevelOpts.value.some(s => s.id === logLevel.value)) logLevel.value = ''
    if (logTarget.value && !logTargetOpts.value.includes(logTarget.value)) logTarget.value = ''
    logErr.value = ''
  } catch (e) {
    if (!silent) logErr.value = e.message
  }
}
watch(() => [logFrom.value, logTo.value, logStatus.value, logLevel.value, logTarget.value], () => {
  logPage.value = 1
  loadLogs()
})

// 进入推送日志 tab 才拉取(含深链直达 ?tab=plog 的场景)
watch(tab, (t) => { if (t === 'plog') loadLogs() })
if (tab.value === 'plog') loadLogs()

// ===== tab 4: 异常事件(2026-09-30 从「协议配置 → 异常事件」卡并入) =====
// /api/v2/node/events(collect_events 表, 保留 30 天) = 采集底座原始事件流,
// 与告警记录(node_alerts)同源; 15s 全局轮询(2026-09-30 起, 徽章计数进页即准确)。
const events = ref([])
const eventsTotal = ref(0)
const eventsErr = ref('')
const EVENTS_POLL_MS = 15000
let evtTimer = null

async function loadEvents(silent = false) {
  try {
    const d = await v2('/node/events?limit=200')
    events.value = d.events || []
    eventsTotal.value = events.value.length   // 接口只回最近 N 条(Tail), 无 total 字段
    eventsErr.value = ''
  } catch (e) {
    if (!silent) eventsErr.value = e.message
  }
}
function startEvtPoll() {
  stopEvtPoll()
  loadEvents()
  evtTimer = setInterval(() => loadEvents(true), EVENTS_POLL_MS)
}
function stopEvtPoll() { if (evtTimer) { clearInterval(evtTimer); evtTimer = null } }
// 2026-09-30 用户反馈: 进页面时"异常事件"徽章显示 0(原设计仅在激活该 tab 时轮询) ——
// 改为全局 15s 轮询, 徽章计数进页即准确(每次拉最近 200 条, 开销 ≈1 请求/15s, 可接受)。
onMounted(startEvtPoll)
onBeforeUnmount(stopEvtPoll)
// 事件类型词条键(原 NodeCommonCards 口径; 未知类型原样返回)
function evtLabel(tp) {
  const map = { offline: 'al.evOffline', recover: 'al.evRecover', high_cpu: 'al.evCpu', high_mem: 'al.evMem', high_rtt: 'al.evRtt', high_loss: 'al.evLoss' }
  const k = map[tp]
  return k ? t(k) : tp
}
function evtLvlClass(l) {
  return l === 'critical' ? 'off' : (l === 'warn' ? 'warn' : 'on')
}

// 日志行点击"关联告警" → 跳到告警记录 tab 并定位(深链见上方 watcher)
function gotoAlert(alertId) {
  if (!alertId) return
  router.replace({ path: '/nodemonitor', query: { view: 'alerts', tab: 'records', alertId } })
}
</script>

<template>
  <div class="page">
    <PageHeader
      :title="t('al.title')"
      :sub="t('al.sub')"
      :count="alertsTotal"
      :span="t('al.span')"
    >
      <template #actions>
        <button class="btn" :disabled="alertsErr !== ''" @click="loadAlerts(false)">{{ t('al.refresh') }}</button>
      </template>
    </PageHeader>

    <!-- 工具栏: tab 切换 + 各 tab 筛选 -->
    <div class="toolbar">
      <div class="tabs">
        <button class="tab" :class="{ active: tab === 'records' }" @click="switchTab('records')">
          {{ t('al.tabRecords') }}<span class="cnt">{{ alertsTotal }}</span>
        </button>
        <button class="tab" :class="{ active: tab === 'plog' }" @click="switchTab('plog')">
          {{ t('al.tabPlog') }}<span class="cnt">{{ logTotal }}</span>
        </button>
        <!-- 推送配置: 推送目标 + 规则(深链 ?tab=push, 大屏拓扑卡「完整配置」跳到这里) -->
        <button class="tab" :class="{ active: tab === 'push' }" @click="switchTab('push')">{{ t('al.tabPush') }}</button>
        <!-- 异常事件: 2026-09-30 用户要求从协议配置并入(与告警记录同源, 不再两处显示) -->
        <button class="tab" :class="{ active: tab === 'events' }" @click="switchTab('events')">
          {{ t('al.tabEvents') }}<span class="cnt">{{ eventsTotal }}</span>
        </button>
      </div>

      <!-- 2026-10-02 用户口径: 筛选选项基于当前数据里存在的 —— 级别选项=当前告警
           列表里真实出现的级别; 推送日志的状态/级别/目标选项=后端按全量日志聚合
           回带(无数据的选项不出现, 后期有了再出现; 目标不再用"推送目标配置"全量,
           只列日志里真实出现过的目标) -->
      <div class="fgroup" v-if="tab === 'records'">
        <select class="select" v-model="fLevel">
          <option value="">{{ t('al.allLevels') }}</option>
          <option v-for="l in levelOpts" :key="l.key" :value="l.key">{{ t(l.label) }}</option>
        </select>
        <input type="date" class="input" v-model="fFrom" :title="t('al.dFrom')">
        <span class="dash">—</span>
        <input type="date" class="input" v-model="fTo" :title="t('al.dTo')">
      </div>

      <div class="fgroup" v-if="tab === 'plog'">
        <input type="date" class="input" v-model="logFrom" :title="t('al.dFrom')">
        <span class="dash">—</span>
        <input type="date" class="input" v-model="logTo" :title="t('al.dTo')">
        <select class="select" v-model="logStatus">
          <option value="">{{ t('al.allStatus') }}</option>
          <option v-for="s in logStatusOpts" :key="s.id" :value="s.id">{{ t(PUSH_STATUS_LABEL[s.id] || s.id) }} ({{ s.count }})</option>
        </select>
        <select class="select" v-model="logLevel">
          <option value="">{{ t('al.allLevels') }}</option>
          <option v-for="l in logLevelOpts" :key="l.id" :value="l.id">{{ t(LEVEL_LABEL[l.id] || l.id) }} ({{ l.count }})</option>
        </select>
        <select class="select" v-model="logTarget">
          <option value="">{{ t('al.allTargets') }}</option>
          <option v-for="tg in logTargetOpts" :key="tg" :value="tg">{{ tg }}</option>
        </select>
      </div>
    </div>

    <!-- tab 1: 告警记录 -->
    <div v-if="tab === 'records'" class="card">
      <table class="tbl">
        <thead>
          <tr>
            <th>{{ t('al.cLevel') }}</th>
            <th>{{ t('al.cContent') }}</th>
            <th style="width:170px">{{ t('al.cTime') }}</th>
            <th style="width:104px">{{ t('al.cPush') }}</th>
            <th style="width:104px">{{ t('al.cHandled') }}</th>
            <th style="width:168px">{{ t('al.cOp') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="a in filtered" :key="a.id" :data-alert-id="a.id"
              :class="{ 'row-push-failed': a.pushStatus === 'failed' }">
            <td><span class="sev" :class="LEVELS.find(l => l.key === a.level)?.cls || 'sev-info'">{{ t(LEVELS.find(l => l.key === a.level)?.label || a.level) }}</span></td>
            <td>
              <div class="alert-main">
                <span class="mono ip">{{ a.device || a.ip || '-' }}</span>
                <span class="muted small" v-if="a.ip && a.device && a.ip !== a.device">{{ a.ip }}</span>
                <span class="muted small" v-if="a.source">· {{ t(SOURCE_LABEL[a.source] || a.source) }}</span>
              </div>
              <div class="alert-msg">{{ a.content }}</div>
            </td>
            <td class="muted small">{{ fmtDT(a.at) }}</td>
            <td>
              <span class="chip" :class="a.pushStatus === 'pushed' ? 'on' : a.pushStatus === 'failed' ? 'off' : 'idle'">
                {{ t(PUSH_STATUS_LABEL[a.pushStatus] || a.pushStatus) }}
              </span>
            </td>
            <td>
              <span class="chip" v-if="a.handled === 'confirmed'" style="border-color:var(--green);color:var(--green)">{{ t('al.confirmed') }}</span>
              <span class="chip" v-else-if="a.handled === 'ignored'" style="border-color:var(--dim);color:var(--dim)">{{ t('al.ignored') }}</span>
              <span class="muted small" v-else>{{ t('al.pending') }}</span>
            </td>
            <td class="ops">
              <button class="btn xs danger" v-if="a.pushStatus === 'failed'"
                      :disabled="retryingId !== ''" @click="doRetry(a)">
                {{ retryingId === a.id ? t('al.retrying') : t('al.retry') }}
              </button>
              <button class="btn xs" :class="{ active: a.handled === 'confirmed' }" @click="setHandled(a, 'confirmed')">{{ t('al.confirm') }}</button>
              <button class="btn xs" :class="{ active: a.handled === 'ignored' }" @click="setHandled(a, 'ignored')">{{ t('al.ignore') }}</button>
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="6" class="empty">
              {{ alertsErr ? t('al.loadFail', { err: alertsErr }) : t('al.noAlerts') }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- tab 2: 推送日志 -->
    <div v-else-if="tab === 'plog'" class="card">
      <table class="tbl">
        <thead>
          <tr>
            <th style="width:170px">{{ t('al.cTime') }}</th>
            <th style="width:150px">{{ t('al.lAlert') }}</th>
            <th style="width:80px">{{ t('al.lLevel') }}</th>
            <th>{{ t('al.cContent') }}</th>
            <th style="width:130px">{{ t('al.lTarget') }}</th>
            <th style="width:104px">{{ t('al.lStatus') }}</th>
            <th style="width:180px">{{ t('al.lReason') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in logs" :key="p.id" :class="{ 'row-log-fail': p.status === 'failed' }">
            <td class="muted small">{{ fmtDT(p.at) }}</td>
            <td>
              <a class="mono small link" v-if="p.alertId" href="javascript:void(0)" @click="gotoAlert(p.alertId)"
                 :title="t('al.clickLocate')">{{ p.alertId }}</a>
              <span class="muted small" v-else>—</span>
            </td>
            <td><span class="sev" :class="LEVELS.find(l => l.key === p.level)?.cls || 'sev-info'">{{ t(LEVELS.find(l => l.key === p.level)?.label || (p.level || '-')) }}</span></td>
            <td class="log-content" :title="p.content">{{ p.content || '-' }}</td>
            <td class="muted small">{{ p.target || '—' }}</td>
            <td>
              <span class="chip" :class="p.status === 'success' ? 'on' : p.status === 'failed' ? 'off' : 'idle'">
                {{ p.status === 'success' ? t('push.stPushed') : p.status === 'failed' ? t('push.stFailed') : p.status === 'skipped' ? t('al.skipped') : p.status }}
              </span>
            </td>
            <td class="reason" :class="{ fail: p.status === 'failed' }" :title="p.status === 'failed' ? p.reason : ''">
              {{ p.status === 'failed' ? (p.reason || t('al.unknownReason')) : '—' }}
            </td>
          </tr>
          <tr v-if="!logs.length">
            <td colspan="7" class="empty">{{ logErr ? t('al.loadFail', { err: logErr }) : t('al.noLogs') }}</td>
          </tr>
        </tbody>
      </table>
      <div class="pager" v-if="logTotal > 0">
        <button class="btn xs" :disabled="logPage <= 1" @click="logPage--; loadLogs()">{{ t('al.prev') }}</button>
        <span class="muted small">{{ t('al.pageInfo', { p: logPage, m: Math.ceil(logTotal / 20), n: logTotal }) }}</span>
        <button class="btn xs" :disabled="logPage >= Math.ceil(logTotal / 20)" @click="logPage++; loadLogs()">{{ t('al.next') }}</button>
      </div>
    </div>

    <!-- tab 3: 推送配置(目标 + 规则; v-if 每次切 tab 重新挂载, 与上方两 tab 同口径) -->
    <div v-if="tab === 'push'" class="push-cfg">
      <PushTargetList />
      <PushRuleConfig @dirty="onPushDirty" />
    </div>

    <!-- tab 4: 异常事件(原「协议配置 → 采集配置 → 异常事件」卡整体迁移, 口径不变) -->
    <div v-if="tab === 'events'" class="card">
      <div class="evt-head">
        <span class="muted small">{{ t('al.eventsDesc') }}</span>
        <div class="spacer"></div>
        <button class="btn xs" :disabled="eventsErr !== ''" @click="loadEvents(false)">{{ t('al.refresh') }}</button>
        <!-- AI 分析随卡从协议配置迁入: 后端按 module=collect 现场生成采集快照并
             内存分析(2026-10-02 用户口径: 节点监控不生成原始报告, 不存 raw_reports) -->
        <AiAnalyzeButton module="collect" :label="t('al.aiAnalyze')" />
      </div>
      <table class="tbl">
        <thead>
          <tr>
            <th style="width:80px">{{ t('al.cLevel') }}</th>
            <th style="width:110px">{{ t('al.cType') }}</th>
            <th style="width:170px">{{ t('al.cTarget') }}</th>
            <th>{{ t('al.cDesc') }}</th>
            <th style="width:170px">{{ t('al.cTime') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in events" :key="e.id">
            <td><span class="chip" :class="evtLvlClass(e.level)">{{ e.level }}</span></td>
            <td class="muted small">{{ evtLabel(e.type) }}</td>
            <td class="muted small mono">{{ e.target }}</td>
            <td class="small">{{ e.msg }}</td>
            <td class="muted small">{{ fmtDT(e.at) }}</td>
          </tr>
          <tr v-if="!events.length">
            <td colspan="5" class="empty">
              {{ eventsErr ? t('al.loadFail', { err: eventsErr }) : t('al.noEvents') }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
export default { name: 'AlertLog' }
</script>

<style scoped>
.page { display: flex; flex-direction: column; gap: 14px; }
/* 推送配置 tab: 目标卡 + 规则卡纵向排列 */
.push-cfg { display: flex; flex-direction: column; gap: 16px; }
.toolbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
.tabs { display: flex; gap: 6px; }
.tab {
  padding: 7px 16px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--panel); color: var(--text-dim); font-size: 13px; cursor: pointer;
}
.tab:hover { border-color: var(--border-hi); }
.tab.active { background: rgba(34,197,94,.12); border-color: var(--green); color: var(--green); }
.tab .cnt { margin-left: 6px; opacity: .7; font-family: var(--mono); font-size: 11px; }

.fgroup { display: flex; align-items: center; gap: 8px; }
.dash { color: var(--dim); }

.card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.tbl th {
  text-align: left; padding: 10px 14px; background: var(--panel2);
  color: var(--dim); font-size: 12px; font-weight: 600; border-bottom: 1px solid var(--border);
}
.tbl td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
.tbl tr:last-child td { border-bottom: none; }

/* 级别徽章 */
.sev {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 700; border: 1px solid transparent;
}
.sev-critical { background: rgba(239,68,68,.14); color: var(--red); border-color: rgba(239,68,68,.3); }
.sev-medium   { background: rgba(245,158,11,.14); color: var(--amber); border-color: rgba(245,158,11,.3); }
.sev-info     { background: rgba(59,130,246,.14); color: var(--blue); border-color: rgba(59,130,246,.3); }

/* 告警内容单元格 */
.alert-main { display: flex; align-items: center; gap: 8px; margin-bottom: 3px; }
.ip { color: var(--text); font-size: 13px; }
.alert-msg { color: var(--text-dim); font-size: 12px; line-height: 1.5; }

/* 推送状态徽章 */
.chip {
  display: inline-block; padding: 2px 8px; border-radius: 999px;
  font-size: 11px; border: 1px solid var(--border); color: var(--text-dim);
}
.chip.on   { border-color: var(--green); color: var(--green); background: rgba(34,197,94,.1); }
.chip.off  { border-color: var(--red); color: var(--red); background: rgba(239,68,68,.1); }
.chip.idle { border-color: var(--border); color: var(--dim); }
/* 异常事件级别徽章(warn=越限预警, 同原 NodeCommonCards 口径) */
.chip.warn { border-color: var(--amber, #f59e0b); color: var(--amber, #f59e0b); background: rgba(245,158,11,.1); }

/* 异常事件 tab 头部(说明 + 刷新 + AI 分析) */
.evt-head {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 14px; border-bottom: 1px solid var(--border);
}

/* 推送失败的告警行: 整行标红突出 */
tr.row-push-failed { background: rgba(239,68,68,.08); }
tr.row-push-failed td { border-bottom-color: rgba(239,68,68,.16); }

/* 关联告警深链定位: 高亮闪烁 */
tr.row-flash { animation: rowFlash 1.4s ease 2; }
@keyframes rowFlash {
  0%, 100% { background: transparent; }
  50% { background: rgba(34,197,94,.22); }
}

/* 操作按钮 */
.ops { display: flex; gap: 6px; }
.btn.xs { padding: 3px 9px; font-size: 11px; border-radius: 5px; }
.btn.active { border-color: var(--green); color: var(--green); }
.btn.danger { border-color: rgba(239,68,68,.4); color: var(--red); }
.btn.danger:hover { background: rgba(239,68,68,.12); }

/* 推送日志 */
.log-content {
  max-width: 420px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: var(--text-dim); font-size: 12px;
}
.reason {
  font-size: 12px; color: var(--dim);
  max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.reason.fail { color: var(--red); cursor: help; }
/* 失败的日志行: 标红展示(悬浮失败原因由 .reason.fail 的 title 提示) */
tr.row-log-fail { background: rgba(239,68,68,.06); }
tr.row-log-fail td { border-bottom-color: rgba(239,68,68,.14); }
tr.row-log-fail .log-content { color: var(--red); }
tr.row-log-fail .muted { color: rgba(239,68,68,.75); }

/* 关联告警 ID 链接 */
.link { color: var(--blue); text-decoration: none; }
.link:hover { text-decoration: underline; }

.empty { text-align: center; padding: 42px 14px !important; color: var(--dim); font-size: 13px; }

.pager {
  display: flex; justify-content: center; align-items: center; gap: 14px;
  padding: 10px 14px; border-top: 1px solid var(--border);
}
</style>
