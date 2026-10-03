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
  return window.confirm('推送配置有未保存的修改, 离开将丢失。确定离开吗?')
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
    toast('操作失败: ' + e.message, 'err')
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
    toast(ok ? '重推成功' : '重推失败, 失败原因见推送日志', ok ? 'ok' : 'err')
    await loadAlerts(true) // 刷新推送状态
    loadLogs(true)         // 刷新推送日志(新产生的日志立即可见)
  } catch (e) {
    toast('重推失败: ' + e.message, 'err')
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
      toast('未在最近告警中找到该记录(可能已被裁剪)', 'info')
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
// 事件类型中文(原 NodeCommonCards 口径)
function evtLabel(t) {
  const map = { offline: '离线', recover: '恢复', high_cpu: 'CPU 越限', high_mem: '内存越限', high_rtt: '时延越限', high_loss: '丢包越限' }
  return map[t] || t
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
      title="告警"
      sub="节点采集异常自动生成告警, 推送状态与后端实时同步(5s 轮询)"
      :count="alertsTotal"
      :span="'推送配置 / 测试 / 推送日志 / 告警记录 均由后端持久化'"
    >
      <template #actions>
        <button class="btn" :disabled="alertsErr !== ''" @click="loadAlerts(false)">刷新告警</button>
      </template>
    </PageHeader>

    <!-- 工具栏: tab 切换 + 各 tab 筛选 -->
    <div class="toolbar">
      <div class="tabs">
        <button class="tab" :class="{ active: tab === 'records' }" @click="switchTab('records')">
          告警记录<span class="cnt">{{ alertsTotal }}</span>
        </button>
        <button class="tab" :class="{ active: tab === 'plog' }" @click="switchTab('plog')">
          推送日志<span class="cnt">{{ logTotal }}</span>
        </button>
        <!-- 推送配置: 推送目标 + 规则(深链 ?tab=push, 大屏拓扑卡「完整配置」跳到这里) -->
        <button class="tab" :class="{ active: tab === 'push' }" @click="switchTab('push')">推送配置</button>
        <!-- 异常事件: 2026-09-30 用户要求从协议配置并入(与告警记录同源, 不再两处显示) -->
        <button class="tab" :class="{ active: tab === 'events' }" @click="switchTab('events')">
          异常事件<span class="cnt">{{ eventsTotal }}</span>
        </button>
      </div>

      <!-- 2026-10-02 用户口径: 筛选选项基于当前数据里存在的 —— 级别选项=当前告警
           列表里真实出现的级别; 推送日志的状态/级别/目标选项=后端按全量日志聚合
           回带(无数据的选项不出现, 后期有了再出现; 目标不再用"推送目标配置"全量,
           只列日志里真实出现过的目标) -->
      <div class="fgroup" v-if="tab === 'records'">
        <select class="select" v-model="fLevel">
          <option value="">全部级别</option>
          <option v-for="l in levelOpts" :key="l.key" :value="l.key">{{ l.label }}</option>
        </select>
        <input type="date" class="input" v-model="fFrom" title="起始日期">
        <span class="dash">—</span>
        <input type="date" class="input" v-model="fTo" title="结束日期">
      </div>

      <div class="fgroup" v-if="tab === 'plog'">
        <input type="date" class="input" v-model="logFrom" title="起始日期">
        <span class="dash">—</span>
        <input type="date" class="input" v-model="logTo" title="结束日期">
        <select class="select" v-model="logStatus">
          <option value="">全部状态</option>
          <option v-for="s in logStatusOpts" :key="s.id" :value="s.id">{{ PUSH_STATUS_LABEL[s.id] || s.id }} ({{ s.count }})</option>
        </select>
        <select class="select" v-model="logLevel">
          <option value="">全部级别</option>
          <option v-for="l in logLevelOpts" :key="l.id" :value="l.id">{{ LEVEL_LABEL[l.id] || l.id }} ({{ l.count }})</option>
        </select>
        <select class="select" v-model="logTarget">
          <option value="">全部目标</option>
          <option v-for="t in logTargetOpts" :key="t" :value="t">{{ t }}</option>
        </select>
      </div>
    </div>

    <!-- tab 1: 告警记录 -->
    <div v-if="tab === 'records'" class="card">
      <table class="tbl">
        <thead>
          <tr>
            <th>级别</th>
            <th>告警内容</th>
            <th style="width:170px">时间</th>
            <th style="width:104px">推送状态</th>
            <th style="width:104px">处理</th>
            <th style="width:168px">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="a in filtered" :key="a.id" :data-alert-id="a.id"
              :class="{ 'row-push-failed': a.pushStatus === 'failed' }">
            <td><span class="sev" :class="LEVELS.find(l => l.key === a.level)?.cls || 'sev-info'">{{ LEVELS.find(l => l.key === a.level)?.label || a.level }}</span></td>
            <td>
              <div class="alert-main">
                <span class="mono ip">{{ a.device || a.ip || '-' }}</span>
                <span class="muted small" v-if="a.ip && a.device && a.ip !== a.device">{{ a.ip }}</span>
                <span class="muted small" v-if="a.source">· {{ SOURCE_LABEL[a.source] || a.source }}</span>
              </div>
              <div class="alert-msg">{{ a.content }}</div>
            </td>
            <td class="muted small">{{ fmtDT(a.at) }}</td>
            <td>
              <span class="chip" :class="a.pushStatus === 'pushed' ? 'on' : a.pushStatus === 'failed' ? 'off' : 'idle'">
                {{ PUSH_STATUS_LABEL[a.pushStatus] || a.pushStatus }}
              </span>
            </td>
            <td>
              <span class="chip" v-if="a.handled === 'confirmed'" style="border-color:var(--green);color:var(--green)">已确认</span>
              <span class="chip" v-else-if="a.handled === 'ignored'" style="border-color:var(--dim);color:var(--dim)">已忽略</span>
              <span class="muted small" v-else>未处理</span>
            </td>
            <td class="ops">
              <button class="btn xs danger" v-if="a.pushStatus === 'failed'"
                      :disabled="retryingId !== ''" @click="doRetry(a)">
                {{ retryingId === a.id ? '重推中…' : '重推' }}
              </button>
              <button class="btn xs" :class="{ active: a.handled === 'confirmed' }" @click="setHandled(a, 'confirmed')">确认</button>
              <button class="btn xs" :class="{ active: a.handled === 'ignored' }" @click="setHandled(a, 'ignored')">忽略</button>
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="6" class="empty">
              {{ alertsErr ? '加载失败: ' + alertsErr : '暂无告警记录(节点采集未产生异常事件)' }}
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
            <th style="width:170px">时间</th>
            <th style="width:150px">关联告警</th>
            <th style="width:80px">告警级别</th>
            <th>告警内容</th>
            <th style="width:130px">推送目标</th>
            <th style="width:104px">状态</th>
            <th style="width:180px">失败原因</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in logs" :key="p.id" :class="{ 'row-log-fail': p.status === 'failed' }">
            <td class="muted small">{{ fmtDT(p.at) }}</td>
            <td>
              <a class="mono small link" v-if="p.alertId" href="javascript:void(0)" @click="gotoAlert(p.alertId)"
                 title="点击定位到对应告警记录">{{ p.alertId }}</a>
              <span class="muted small" v-else>—</span>
            </td>
            <td><span class="sev" :class="LEVELS.find(l => l.key === p.level)?.cls || 'sev-info'">{{ LEVELS.find(l => l.key === p.level)?.label || (p.level || '-') }}</span></td>
            <td class="log-content" :title="p.content">{{ p.content || '-' }}</td>
            <td class="muted small">{{ p.target || '—' }}</td>
            <td>
              <span class="chip" :class="p.status === 'success' ? 'on' : p.status === 'failed' ? 'off' : 'idle'">
                {{ p.status === 'success' ? '推送成功' : p.status === 'failed' ? '推送失败' : p.status === 'skipped' ? '已跳过' : p.status }}
              </span>
            </td>
            <td class="reason" :class="{ fail: p.status === 'failed' }" :title="p.status === 'failed' ? p.reason : ''">
              {{ p.status === 'failed' ? (p.reason || '未知原因') : '—' }}
            </td>
          </tr>
          <tr v-if="!logs.length">
            <td colspan="7" class="empty">{{ logErr ? '加载失败: ' + logErr : '暂无推送日志' }}</td>
          </tr>
        </tbody>
      </table>
      <div class="pager" v-if="logTotal > 0">
        <button class="btn xs" :disabled="logPage <= 1" @click="logPage--; loadLogs()">上一页</button>
        <span class="muted small">第 {{ logPage }} 页 / 共 {{ Math.ceil(logTotal / 20) }} 页 ({{ logTotal }} 条)</span>
        <button class="btn xs" :disabled="logPage >= Math.ceil(logTotal / 20)" @click="logPage++; loadLogs()">下一页</button>
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
        <span class="muted small">采集底座异常事件(离线/恢复/指标越限) · 保留 30 天 · 15s 刷新</span>
        <div class="spacer"></div>
        <button class="btn xs" :disabled="eventsErr !== ''" @click="loadEvents(false)">刷新</button>
        <!-- AI 分析随卡从协议配置迁入: 后端按 module=collect 现场生成采集快照并
             内存分析(2026-10-02 用户口径: 节点监控不生成原始报告, 不存 raw_reports) -->
        <AiAnalyzeButton module="collect" label="AI 分析(告警)" />
      </div>
      <table class="tbl">
        <thead>
          <tr>
            <th style="width:80px">级别</th>
            <th style="width:110px">类型</th>
            <th style="width:170px">目标</th>
            <th>说明</th>
            <th style="width:170px">时间</th>
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
              {{ eventsErr ? '加载失败: ' + eventsErr : '暂无异常事件。连续失败达阈值会报离线, 恢复报上线, 指标越限报告警。' }}
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
