<template>
  <div>
    <!-- 2026-09-28: 已移除内置 Tab2「安全大屏」—— 该能力全量迁到独立一级菜单
         /bigscreen-pro(v138 起), Tab2 与旧 /bigscreen 重定向一并删除(见 router.js)。
         页面只保留概览仪表盘, 不再有 tab 切换与 URL query 驱动。 -->
    <!-- 2026-10-03: 文案接入 i18n(t('dash.*')), 中英切换即时生效 -->
      <PageHeader :title="t('dash.header')">
        <button class="btn sm" @click="loadAll"><span class="spinner" v-if="loading"></span>{{ t('common.refresh') }}</button>
      </PageHeader>

      <!-- 概览卡片 -->
      <div class="grid cols-5">
        <!-- 2026-09-27: sub 显示"存活/总计"(主机口径 host=1, 排除镜像工件),
             与资产页"只看存活"默认视图的数字对得上, 差异一眼可见 -->
        <StatCard :label="t('dash.assets')" :value="assetsTotal" :sub="t('dash.assetsSub', { alive: assetsAliveTotal, total: assetsTotal })" tone="blue" />
        <StatCard :label="t('dash.vulns')" :value="vulnsTotal" :sub="t('dash.vulnsSub', { high: highCount, critical: criticalCount })" tone="red" />
        <StatCard :label="t('dash.scans')" :value="scansTotal" :sub="t('dash.scansSub', { running: runningCount, pending: pendingCount, hist: histScansTotal })" tone="orange" />
        <StatCard :label="t('dash.engines')" :value="engineOk ? t('common.normal') : t('common.degraded')" :sub="engineSub" :tone="engineOk ? 'green' : 'orange'" />
        <StatCard :label="t('dash.npcap')" :value="npcapText" :sub="t('dash.npcapCap')" :tone="npcapOk ? 'green' : 'yellow'" />
      </div>

      <!-- 中心端运行状态(阶段 4): 中心主机动态实时指标, 5 秒轮询。
           与"系统信息"卡的分工: 系统信息 = 静态构建/配置信息(版本由顶栏展示),
           这里 = 动态负载/任务队列/数据链路, 解决版本与系统信息重复展示。 -->
      <div class="card" style="margin-top:14px">
        <div class="card-title">
          {{ t('dash.csTitle') }}
          <span class="sub">{{ t('dash.csSub') }}</span>
          <span class="chip" :class="csErr ? 'off' : 'on'" style="margin-left:auto">
            {{ csErr ? t('dash.csErr') : (cs ? t('dash.csLive') : t('dash.csLoading')) }}
          </span>
        </div>
        <div class="grid cols-3">
          <!-- 中心主机负载 -->
          <div>
            <div class="cs-title">{{ t('dash.csHostLoad') }}</div>
            <div class="load-cell" style="width:100%; margin-bottom:10px">
              <span class="load-label" style="width:52px">CPU</span>
              <span class="mini-track"><span class="mini-fill" :style="{ width: barW(cs && cs.cpu && cs.cpu.percent), background: loadColor(cs && cs.cpu && cs.cpu.percent) }"></span></span>
              <span class="mono small" style="width:52px; text-align:right">{{ pct(cs && cs.cpu && cs.cpu.percent) }}</span>
            </div>
            <div class="load-cell" style="width:100%; margin-bottom:10px">
              <span class="load-label" style="width:52px">{{ t('dash.mem') }}</span>
              <span class="mini-track"><span class="mini-fill" :style="{ width: barW(csMemPct), background: loadColor(csMemPct) }"></span></span>
              <span class="mono small" style="width:52px; text-align:right">{{ pct(csMemPct) }}</span>
            </div>
            <div class="load-cell" style="width:100%; margin-bottom:10px">
              <span class="load-label" style="width:52px">{{ t('dash.disk') }}</span>
              <span class="mini-track"><span class="mini-fill" :style="{ width: barW(csDiskPct), background: loadColor(csDiskPct) }"></span></span>
              <span class="mono small" style="width:52px; text-align:right">{{ pct(csDiskPct) }}</span>
            </div>
            <div class="kv">
              <div class="k">{{ t('dash.cpuCores') }}</div><div class="v mono">{{ (cs && cs.cpu && cs.cpu.cores) || '-' }}</div>
              <div class="k">{{ t('dash.memUsed') }}</div><div class="v mono">{{ cs && cs.mem && cs.mem.ok ? fmtBytes(cs.mem.used) + ' / ' + fmtBytes(cs.mem.total) : '-' }}</div>
              <div class="k">{{ t('dash.diskFree') }}</div><div class="v mono" :title="(cs && cs.disk && cs.disk.path) || ''">{{ cs && cs.disk && cs.disk.ok ? fmtBytes(cs.disk.free) + ' / ' + fmtBytes(cs.disk.total) : '-' }}</div>
              <div class="k">{{ t('dash.startedAt') }}</div><div class="v mono small">{{ timeFull(cs && cs.startedAt) }}</div>
              <div class="k">{{ t('dash.uptime') }}</div><div class="v mono">{{ fmtDuration((cs && cs.uptimeSec) || 0) }}</div>
            </div>
          </div>

          <!-- 任务队列(扫描任务 + 节点采集) -->
          <div>
            <div class="cs-title">{{ t('dash.taskQueue') }}</div>
            <div class="kv" style="margin-bottom:10px">
              <div class="k">{{ t('dash.queued') }}</div><div class="v mono">{{ (cs && cs.tasks && cs.tasks.queued) || 0 }}</div>
              <div class="k">{{ t('dash.runningTask') }}</div><div class="v mono">{{ (cs && cs.tasks && cs.tasks.running) || 0 }} / {{ (cs && cs.tasks && cs.tasks.maxSlots) || '-' }} {{ t('dash.slots') }}</div>
              <div class="k">{{ t('dash.paused') }}</div><div class="v mono">{{ (cs && cs.tasks && cs.tasks.paused) || 0 }}</div>
              <div class="k">{{ t('dash.collect') }}</div><div class="v">{{ (cs && cs.tasks && cs.tasks.collect && cs.tasks.collect.running) ? t('dash.collecting', { n: cs.tasks.collect.taskCount || 0 }) : t('dash.notCollecting') }}</div>
            </div>
            <div class="cs-sub">{{ t('dash.liveProgress') }}</div>
            <div v-if="!csTasks.length" class="muted small" style="margin-top:6px">{{ t('dash.noRunningTasks') }}</div>
            <div v-else class="scroll-list" style="max-height:170px">
              <div class="top-item" v-for="t in csTasks" :key="t.id">
                <span class="chip on" style="min-width:52px; justify-content:center">{{ t.kind }}</span>
                <span class="t-title mono" :title="t.target">{{ t.target }}</span>
                <span class="mono small muted" v-if="t.node">@{{ t.node }}</span>
                <span class="muted small" :title="t.progress || ''">{{ t.progress || t2('dash.running') }}</span>
              </div>
            </div>
          </div>

          <!-- 数据链路(探针连接 / 数据库 / 消息队列) -->
          <div>
            <div class="cs-title">{{ t('dash.linksTitle') }}</div>
            <div class="kv" style="margin-bottom:10px">
              <div class="k">{{ t('dash.probeConn') }}</div>
              <div class="v">
                <template v-if="cs && cs.links && cs.links.probeCenterEnabled">
                  <span class="dot on" style="margin-right:5px"></span>{{ t('dash.probesOnline', { online: cs.links.probesOnline, total: cs.links.probesTotal }) }}
                </template>
                <template v-else>{{ t('dash.centerDisabled') }}</template>
              </div>
              <div class="k">{{ t('dash.dbRW') }}</div>
              <div class="v">
                <template v-if="cs && cs.links && cs.links.db && cs.links.db.ok">
                  <span class="dot on" style="margin-right:5px"></span>{{ cs.links.db.type }}
                  <span class="muted small" v-if="cs.links.db.stats">{{ dbSummary }}</span>
                </template>
                <template v-else><span class="dot off" style="margin-right:5px"></span>{{ t('dash.dbUnavailable') }}</template>
              </div>
              <div class="k">{{ t('dash.msgQueue') }}</div>
              <div class="v">
                <template v-if="cs && cs.links && cs.links.sse">
                  <span class="dot on" style="margin-right:5px"></span>
                  {{ t('dash.subscribers', { n: cs.links.sse.subscribers, used: cs.links.sse.ringUsed, cap: cs.links.sse.ringCap }) }}
                </template>
                <template v-else>-</template>
              </div>
              <div class="k">{{ t('dash.centerHost') }}</div><div class="v">{{ (cs && cs.hostname) || '-' }} <span class="muted small mono" v-if="cs && cs.os">{{ cs.os }}/{{ cs.arch }}</span></div>
              <div class="k">{{ t('dash.listenPort') }}</div><div class="v mono">{{ info.port || '-' }}</div>
            </div>
            <div class="muted small">{{ t('dash.linksNote') }}</div>
          </div>
        </div>
      </div>

      <!-- 任务历史清理: 累计数是历史记录(含已完成), 与上面"运行中/待执行"不是一回事,
           堆积久了会让人误以为有一堆任务卡着, 给用户一条清理入口 -->
      <div class="toolbar" style="margin-top:8px">
        <span class="muted small">{{ t('dash.histNote', { n: histScansTotal }) }}</span>
        <button class="btn xs danger" :disabled="!histScansTotal || clearing" @click="clearScans">
          {{ clearing ? t('dash.clearing') : t('dash.clearHist') }}
        </button>
        <div class="spacer" style="flex:1"></div>
        <router-link class="muted small" to="/console?tab=queue">{{ t('dash.toConsole') }}</router-link>
      </div>

      <div class="grid cols-3" style="margin-top:14px">
        <!-- 漏洞等级分布 -->
        <div class="card">
          <div class="card-title">{{ t('dash.sevDist') }} <span class="sub" v-if="vulnsTotal">{{ t('dash.sevTotal', { n: vulnsTotal }) }}</span></div>
          <div v-if="vulnsTotal === 0"><Empty :text="t('dash.noVulns')" /></div>
          <div v-else>
            <div class="bar-row" v-for="s in sevBars" :key="s.key">
              <div class="bar-label">{{ s.name }}</div>
              <div class="bar-track"><div class="bar-fill" :style="{ width: s.pct + '%', background: s.color }"></div></div>
              <div class="bar-val">{{ s.count }}</div>
            </div>
          </div>
        </div>

        <!-- 引擎状态 -->
        <div class="card">
          <div class="card-title">{{ t('dash.engineStatus') }} <span class="sub">{{ t('dash.engineSub') }}</span></div>
          <div v-if="!env"><Empty :text="t('dash.envChecking')" /></div>
          <div v-else>
            <div class="top-item" v-for="e in env.engines" :key="e.name">
              <span class="chip" :class="e.state === 'ok' ? 'on' : (e.fallback ? 'warn' : 'off')" style="min-width:64px; justify-content:center; text-align:center">
                {{ e.state === 'ok' ? t('dash.ready') : (e.state === 'detecting' ? t('dash.detecting') : (e.fallback ? t('common.degraded') : t('dash.abnormal'))) }}
              </span>
              <span class="t-title mono">{{ e.name }}</span>
              <span class="muted small mono">{{ e.version || '-' }}</span>
            </div>
            <div class="muted small" style="margin-top:10px">
              {{ t('dash.degradedNote') }}
              <router-link to="/env">{{ t('common.detail') }}</router-link>
            </div>
          </div>
        </div>

        <!-- 系统信息(静态构建/配置信息; 版本号由顶栏右上角唯一展示, 阶段 4 去重) -->
        <div class="card">
          <div class="card-title">{{ t('dash.sysInfo') }}</div>
          <div class="kv">
            <div class="k">{{ t('dash.localIP') }}</div><div class="v mono">{{ info.localIP || '-' }}</div>
            <div class="k">{{ t('dash.hostname') }}</div><div class="v">{{ info.hostname || '-' }}</div>
            <div class="k">{{ t('dash.servicePort') }}</div><div class="v mono">{{ info.port || '-' }}</div>
            <div class="k">{{ t('dash.builtinRules') }}</div><div class="v">{{ t('dash.rulesUnit', { n: info.vulnRules || 0 }) }}</div>
            <div class="k">{{ t('dash.nucleiTpl') }}</div><div class="v">{{ t('dash.nucleiTplV', { b: info.nucleiTemplatesBuilt || 0, e: info.nucleiTemplates || 0 }) }}</div>
            <div class="k">{{ t('dash.aiPost') }}</div><div class="v">{{ info.aiEnabled ? t('common.enabled') : t('common.disabled') }}</div>
            <div class="k">{{ t('dash.dataLayer') }}</div><div class="v mono small">{{ dbType }} {{ dbStats }}</div>
          </div>
        </div>
      </div>

      <!-- 快捷入口 -->
      <div class="card" style="margin-top:14px">
        <div class="card-title">{{ t('dash.quick') }}</div>
        <div class="grid cols-4">
          <router-link class="btn" to="/console">{{ t('dash.quickScan') }}</router-link>
          <router-link class="btn" to="/console?tab=queue">{{ t('dash.quickSched') }}</router-link>
          <router-link class="btn" to="/vulns">{{ t('dash.quickVulns') }}</router-link>
          <router-link class="btn" to="/bigscreen-pro">{{ t('dash.quickScreen') }}</router-link>
        </div>
      </div>

      <!-- 功能开关(默认全开, 关掉即停; 参数保存在 settings.json, 不需要手改文件) -->
      <div class="card" style="margin-top:14px">
        <div class="card-title">
          {{ t('dash.switches') }}
          <span class="sub">{{ t('dash.switchesSub') }}</span>
        </div>
        <div v-if="!switches" class="muted small">{{ t('common.loading') }}</div>
        <div v-else class="sw-grid">
          <label class="sw">
            <input type="checkbox" v-model="switches.geoip.enabled" @change="saveSwitches" />
            <span>{{ t('dash.swGeoip') }}</span>
            <span class="muted small">{{ switches.geoip.loaded ? t('dash.swGeoipCidr', { n: switches.geoip.v4Count }) : (switches.geoip.note || '') }}</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="switches.dashboard.enabled" @change="saveSwitches" />
            <span>{{ t('dash.swGlobe') }}</span>
            <span class="muted small">{{ t('dash.swGlobeDays', { n: switches.dashboard.days }) }}</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="switches.report.enabled" @change="saveReport" />
            <span>{{ t('dash.swReport') }}</span>
            <span class="muted small">{{ t('dash.swReportSub') }}</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="switches.report.autoGenerate" @change="saveReport" />
            <span>{{ t('dash.swAutoReport') }}</span>
            <span class="muted small">{{ t('dash.swAutoReportSub') }}</span>
          </label>
        </div>
        <div class="muted small" style="margin-top:8px">{{ t('dash.switchesNote') }}</div>
      </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import StatCard from '../components/StatCard.vue'
import Empty from '../components/Empty.vue'
import { api } from '../api/http'
import { v2 } from '../api/http'
import { t } from '../i18n'

// 模板里任务循环的 item 也叫 t(与 i18n 的 t 撞名), 这里给 i18n 起个别名
const t2 = t

const router = useRouter()

// ===== Tab1 概览数据(手动刷新) =====
const loading = ref(false)
const info = ref({})
const env = ref(null)
const assetsTotal = ref(0)
const assetsAliveTotal = ref(0) // 存活主机数(资产卡 sub 用, 与"总计"同口径 host=1)
const vulnsTotal = ref(0)
const vulnsList = ref([])
const scansTotal = ref(0)
const runningCount = ref(0)
const pendingCount = ref(0)
// histScansTotal v2 任务表里的历史累计条数(含已完成的旧任务)。
// 与上面的"运行中/待执行"分开显示: 只给一个总数会让人以为"现在有 7 个任务在跑",
// 而任务列表页(扫描作业)显示的其实是调度器当前队列 —— 两个口径混在一个数字里
// 就是"页面没有任务、首页却显示 7"的来源。
const histScansTotal = ref(0)
const dbType = ref('-')
const dbStats = ref('')

const criticalCount = computed(() => vulnsList.value.filter(v => v.severity === 'critical').length)
const highCount = computed(() => vulnsList.value.filter(v => v.severity === 'high').length)

// 等级名走 i18n(sev.*): 切语言时 computed 重算, 柱状图标签同步换
const SEV_META = [
  { key: 'critical', color: '#ff6b6b' },
  { key: 'high', color: '#f87171' },
  { key: 'medium', color: '#fb923c' },
  { key: 'low', color: '#facc15' },
  { key: 'info', color: '#60a5fa' }
]

const sevBars = computed(() => {
  const max = Math.max(1, ...SEV_META.map(s => vulnsList.value.filter(v => v.severity === s.key).length))
  return SEV_META.map(s => {
    const count = vulnsList.value.filter(v => v.severity === s.key).length
    return { ...s, name: t('sev.' + s.key), count, pct: count ? Math.max(4, Math.round(count / max * 100)) : 0 }
  })
})

const engineOk = computed(() => {
  if (!env.value) return false
  return !(env.value.degraded && env.value.degraded.length) && !env.value.detecting
})
const engineSub = computed(() => {
  if (!env.value) return t('dash.detecting')
  const d = env.value.degraded || []
  return d.length ? t('dash.engineSubDeg', { list: d.join(', ') }) : t('dash.engineSubReady', { n: (env.value.engines || []).filter(e => e.state === 'ok').length })
})
const npcapText = computed(() => {
  if (!env.value) return '-'
  if (!env.value.npcap.supported) return t('dash.npcapNA')
  return env.value.npcap.installed ? t('dash.npcapInstalled') : t('dash.npcapMissing')
})
const npcapOk = computed(() => !!env.value && (!env.value.npcap.supported || env.value.npcap.installed))

async function loadAll() {
  loading.value = true
  try {
    const [i, e, a, aAlive, v, s, d, sc] = await Promise.allSettled([
      api('/api/info'),
      api('/api/env'),
      v2('/assets?size=1&host=1'),
      v2('/assets?size=1&host=1&alive=1'),
      v2('/vulns?size=200'),
      v2('/scans?size=200'),
      v2('/db/status'),
      v2('/scheduler/status')
    ])
    if (i.status === 'fulfilled') info.value = i.value
    if (e.status === 'fulfilled') env.value = e.value
    // 主机口径(host=1): 排除 Trivy 镜像工件等非 IP 资产, 与资产页"共 N 台主机"对齐
    if (a.status === 'fulfilled') assetsTotal.value = a.value.total
    if (aAlive.status === 'fulfilled') assetsAliveTotal.value = aAlive.value.total
    if (v.status === 'fulfilled') {
      vulnsTotal.value = v.value.total
      vulnsList.value = v.value.list || []
    }
    if (s.status === 'fulfilled') {
      histScansTotal.value = s.value.total || 0
      // 当前任务数优先取调度器(与「扫描作业」页同一口径): 任务表里"运行中"可能
      // 是上次服务重启前留下的旧记录, 用它会把历史状态当成此刻在跑。
      const st = (sc.status === 'fulfilled' && sc.value && sc.value.enabled)
        ? (sc.value.stats || {}) : null
      if (st) {
        runningCount.value = st.running || 0
        pendingCount.value = st.queued || 0
      } else {
        const L = s.value.list || []
        runningCount.value = L.filter(t => t.status === 'running').length
        pendingCount.value = L.filter(t => t.status === 'pending').length
      }
      scansTotal.value = runningCount.value + pendingCount.value
    }
    if (d.status === 'fulfilled') {
      dbType.value = d.value.type + ' (' + (d.value.dir || '') + ')'
      const st = d.value.stats || {}
      dbStats.value = Object.keys(st).map(k => k + ':' + st[k]).join(' ')
    }
  } finally { loading.value = false }
  loadCenterStatus()
}

// ===== 中心端运行状态(5 秒轮询, 独立于手动刷新) =====
// 拉取失败保留上一帧 + 顶部异常提示(与大屏同一口径: 空屏比"稍旧的数据"更让人恐慌)
const cs = ref(null)
const csErr = ref('')
let csTimer = null
const CS_INTERVAL = 5000

async function loadCenterStatus() {
  try {
    const d = await v2('/center/status')
    if (d) { cs.value = d; csErr.value = '' }
  } catch (e) {
    csErr.value = (e && e.message) ? e.message : t('dash.csErr')
  }
}

const csTasks = computed(() => (cs.value && cs.value.tasks && cs.value.tasks.items) || [])
const csMemPct = computed(() => (cs.value && cs.value.mem && cs.value.mem.ok) ? cs.value.mem.percent : null)
const csDiskPct = computed(() => (cs.value && cs.value.disk && cs.value.disk.ok) ? cs.value.disk.percentUsed : null)
const dbSummary = computed(() => {
  const st = (cs.value && cs.value.links && cs.value.links.db && cs.value.links.db.stats) || {}
  return Object.keys(st).map(k => k + ':' + st[k]).join(' ')
})

// barW / pct 对 null 的显式处理: 后端用 null 表示"尚无基线/未上报",
// 与 0% 是两种含义(还没算出来 vs 真的空闲), 不能混为一谈 —— 首屏 CPU 显示 "-"
function barW(v) { return v == null ? '0%' : Math.max(2, Math.min(100, v)) + '%' }
function pct(v) { return v == null ? '-' : Math.round(v) + '%' }
function loadColor(v) {
  if (v == null) return 'var(--border2)'
  if (v >= 85) return '#f87171'
  if (v >= 60) return '#fb923c'
  return '#34d399'
}
function fmtBytes(n) {
  const b = Number(n) || 0
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + 'GB'
  if (b >= 1048576) return (b / 1048576).toFixed(1) + 'MB'
  if (b >= 1024) return (b / 1024).toFixed(0) + 'KB'
  return b + 'B'
}
function fmtDuration(sec) {
  const s = Math.max(0, Math.floor(Number(sec) || 0))
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  const ss = s % 60
  const p = (n) => String(n).padStart(2, '0')
  return (d ? d + t('dash.day') : '') + p(h) + ':' + p(m) + ':' + p(ss)
}
function timeFull(s) {
  if (!s) return '-'
  const d = new Date(s)
  if (isNaN(d.getTime())) return '-'
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

// ===== 扫描任务历史清理 =====
const clearing = ref(false)

async function clearScans() {
  if (!histScansTotal.value) return
  if (!confirm(t('dash.clearConfirm', { n: histScansTotal.value }))) return
  clearing.value = true
  try {
    const d = await v2('/scans', { method: 'DELETE' })
    await loadAll()
    alert(t('dash.clearDone', { n: (d && d.deleted != null ? d.deleted : 0) }))
  } catch (e) {
    alert(t('dash.clearFail') + (e.message || e))
  } finally {
    clearing.value = false
  }
}

// ===== 功能开关 =====
const switches = ref(null)

async function loadSwitches() {
  try {
    switches.value = await v2('/config/features')
  } catch (e) {
    switches.value = null // 读不到就不显示开关, 不影响首页其它卡片
  }
}

// 大屏/地理映射开关: 一个接口两个节(dashboard + geoip)
async function saveSwitches() {
  if (!switches.value) return
  try {
    await v2('/config/dashboard', {
      method: 'POST',
      body: {
        enabled: switches.value.dashboard.enabled,
        geoipEnabled: switches.value.geoip.enabled,
        days: switches.value.dashboard.days,
        topCities: switches.value.dashboard.topCities
      }
    })
  } catch (e) {
    alert(t('dash.saveFail') + (e && e.message || e))
    loadSwitches()
  }
}

async function saveReport() {
  if (!switches.value) return
  try {
    await v2('/config/report', {
      method: 'POST',
      body: {
        enabled: switches.value.report.enabled,
        autoGenerate: switches.value.report.autoGenerate
      }
    })
  } catch (e) {
    alert(t('dash.saveFail') + (e && e.message || e))
    loadSwitches()
  }
}

onMounted(() => {
  loadAll()
  loadSwitches()
  // 中心端运行状态: 5 秒轮询(比大屏 15s 更贴近"实时负载"); 离开页面即停
  csTimer = setInterval(loadCenterStatus, CS_INTERVAL)
})

onBeforeUnmount(() => { if (csTimer) clearInterval(csTimer) })
</script>

<style scoped>
/* 中心端运行状态面板内部的小标题(面板专属, 不进全局主题) */
.cs-title {
  font-size: 12px; font-weight: 600; color: var(--text);
  margin-bottom: 10px; padding-left: 8px; border-left: 3px solid var(--accent);
}
.cs-sub { font-size: 12px; color: var(--muted); margin-top: 4px; }
</style>
