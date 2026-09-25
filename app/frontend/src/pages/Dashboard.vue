<template>
  <div>
    <!-- 阶段 4: 首页仪表盘内置 2 个 Tab ——
         Tab1 概览仪表盘(资产/风险/任务/引擎 + 中心端运行状态)
         Tab2 安全大屏(原独立 /bigscreen 全屏页能力全量迁入, 数据源不变)。
         tab 状态放 URL query(与 Engrules 同一口径): 刷新/书签/旧 /bigscreen
         重定向都能停在同一个 tab。 -->
    <div class="tabs">
      <div class="tab" :class="{ active: tab === 'overview' }" @click="setTab('overview')">概览仪表盘</div>
      <div class="tab" :class="{ active: tab === 'screen' }" @click="setTab('screen')">安全大屏</div>
    </div>

    <BigScreen v-if="tab === 'screen'" />

    <template v-else>
      <PageHeader title="首页仪表盘" desc="资产 / 风险 / 任务 / 引擎 / 中心端运行状态 一屏概览">
        <button class="btn sm" @click="loadAll"><span class="spinner" v-if="loading"></span>刷新</button>
      </PageHeader>

      <!-- 概览卡片 -->
      <div class="grid cols-5">
        <StatCard label="资产总数" :value="assetsTotal" sub="主机维度(去重)" tone="blue" />
        <StatCard label="漏洞总数" :value="vulnsTotal" :sub="`高危 ${highCount} / 严重 ${criticalCount}`" tone="red" />
        <StatCard label="扫描任务" :value="scansTotal" :sub="`运行中 ${runningCount} / 待执行 ${pendingCount} · 累计 ${histScansTotal}`" tone="orange" />
        <StatCard label="扫描引擎" :value="engineOk ? '正常' : '降级'" :sub="engineSub" :tone="engineOk ? 'green' : 'orange'" />
        <StatCard label="Npcap 驱动" :value="npcapText" sub="抓包能力" :tone="npcapOk ? 'green' : 'yellow'" />
      </div>

      <!-- 中心端运行状态(阶段 4): 中心主机动态实时指标, 5 秒轮询。
           与"系统信息"卡的分工: 系统信息 = 静态构建/配置信息(版本由顶栏展示),
           这里 = 动态负载/任务队列/数据链路, 解决版本与系统信息重复展示。 -->
      <div class="card" style="margin-top:14px">
        <div class="card-title">
          中心端运行状态
          <span class="sub">CPU / 内存 / 磁盘 · 任务队列 · 数据链路 · 5 秒自动刷新</span>
          <span class="chip" :class="csErr ? 'off' : 'on'" style="margin-left:auto">
            {{ csErr ? '数据获取异常' : (cs ? '实时更新中' : '加载中') }}
          </span>
        </div>
        <div class="grid cols-3">
          <!-- 中心主机负载 -->
          <div>
            <div class="cs-title">中心主机负载</div>
            <div class="load-cell" style="width:100%; margin-bottom:10px">
              <span class="load-label" style="width:52px">CPU</span>
              <span class="mini-track"><span class="mini-fill" :style="{ width: barW(cs && cs.cpu && cs.cpu.percent), background: loadColor(cs && cs.cpu && cs.cpu.percent) }"></span></span>
              <span class="mono small" style="width:52px; text-align:right">{{ pct(cs && cs.cpu && cs.cpu.percent) }}</span>
            </div>
            <div class="load-cell" style="width:100%; margin-bottom:10px">
              <span class="load-label" style="width:52px">内存</span>
              <span class="mini-track"><span class="mini-fill" :style="{ width: barW(csMemPct), background: loadColor(csMemPct) }"></span></span>
              <span class="mono small" style="width:52px; text-align:right">{{ pct(csMemPct) }}</span>
            </div>
            <div class="load-cell" style="width:100%; margin-bottom:10px">
              <span class="load-label" style="width:52px">磁盘</span>
              <span class="mini-track"><span class="mini-fill" :style="{ width: barW(csDiskPct), background: loadColor(csDiskPct) }"></span></span>
              <span class="mono small" style="width:52px; text-align:right">{{ pct(csDiskPct) }}</span>
            </div>
            <div class="kv">
              <div class="k">CPU 核数</div><div class="v mono">{{ (cs && cs.cpu && cs.cpu.cores) || '-' }}</div>
              <div class="k">内存占用</div><div class="v mono">{{ cs && cs.mem && cs.mem.ok ? fmtBytes(cs.mem.used) + ' / ' + fmtBytes(cs.mem.total) : '-' }}</div>
              <div class="k">磁盘剩余</div><div class="v mono" :title="(cs && cs.disk && cs.disk.path) || ''">{{ cs && cs.disk && cs.disk.ok ? fmtBytes(cs.disk.free) + ' / ' + fmtBytes(cs.disk.total) : '-' }}</div>
              <div class="k">服务启动于</div><div class="v mono small">{{ timeFull(cs && cs.startedAt) }}</div>
              <div class="k">服务运行时长</div><div class="v mono">{{ fmtDuration((cs && cs.uptimeSec) || 0) }}</div>
            </div>
          </div>

          <!-- 任务队列(扫描任务 + 节点采集) -->
          <div>
            <div class="cs-title">任务队列状态</div>
            <div class="kv" style="margin-bottom:10px">
              <div class="k">等待任务数</div><div class="v mono">{{ (cs && cs.tasks && cs.tasks.queued) || 0 }}</div>
              <div class="k">执行中任务</div><div class="v mono">{{ (cs && cs.tasks && cs.tasks.running) || 0 }} / {{ (cs && cs.tasks && cs.tasks.maxSlots) || '-' }} 槽位</div>
              <div class="k">已暂停</div><div class="v mono">{{ (cs && cs.tasks && cs.tasks.paused) || 0 }}</div>
              <div class="k">节点采集</div><div class="v">{{ (cs && cs.tasks && cs.tasks.collect && cs.tasks.collect.running) ? ('采集中 · ' + (cs.tasks.collect.taskCount || 0) + ' 个任务') : '未采集' }}</div>
            </div>
            <div class="cs-sub">实时进度(运行中的扫描/采集任务)</div>
            <div v-if="!csTasks.length" class="muted small" style="margin-top:6px">当前无运行中的任务</div>
            <div v-else class="scroll-list" style="max-height:170px">
              <div class="top-item" v-for="t in csTasks" :key="t.id">
                <span class="chip on" style="min-width:52px; justify-content:center">{{ t.kind }}</span>
                <span class="t-title mono" :title="t.target">{{ t.target }}</span>
                <span class="mono small muted" v-if="t.node">@{{ t.node }}</span>
                <span class="muted small" :title="t.progress || ''">{{ t.progress || '执行中' }}</span>
              </div>
            </div>
          </div>

          <!-- 数据链路(探针连接 / 数据库 / 消息队列) -->
          <div>
            <div class="cs-title">数据链路状态</div>
            <div class="kv" style="margin-bottom:10px">
              <div class="k">探针连接</div>
              <div class="v">
                <template v-if="cs && cs.links && cs.links.probeCenterEnabled">
                  <span class="dot on" style="margin-right:5px"></span>{{ cs.links.probesOnline }} 在线 / {{ cs.links.probesTotal }} 登记
                </template>
                <template v-else>中心端未启用</template>
              </div>
              <div class="k">数据库读写</div>
              <div class="v">
                <template v-if="cs && cs.links && cs.links.db && cs.links.db.ok">
                  <span class="dot on" style="margin-right:5px"></span>{{ cs.links.db.type }}
                  <span class="muted small" v-if="cs.links.db.stats">{{ dbSummary }}</span>
                </template>
                <template v-else><span class="dot off" style="margin-right:5px"></span>不可用</template>
              </div>
              <div class="k">消息队列</div>
              <div class="v">
                <template v-if="cs && cs.links && cs.links.sse">
                  <span class="dot on" style="margin-right:5px"></span>
                  {{ cs.links.sse.subscribers }} 订阅者 · 补发窗口 {{ cs.links.sse.ringUsed }}/{{ cs.links.sse.ringCap }}
                </template>
                <template v-else>-</template>
              </div>
              <div class="k">中心主机</div><div class="v">{{ (cs && cs.hostname) || '-' }} <span class="muted small mono" v-if="cs && cs.os">{{ cs.os }}/{{ cs.arch }}</span></div>
              <div class="k">监听端口</div><div class="v mono">{{ info.port || '-' }}</div>
            </div>
            <div class="muted small">探针未启用时仅中心本地执行; 数据库与消息队列异常时面板保持上一帧并提示</div>
          </div>
        </div>
      </div>

      <!-- 任务历史清理: 累计数是历史记录(含已完成), 与上面"运行中/待执行"不是一回事,
           堆积久了会让人误以为有一堆任务卡着, 给用户一条清理入口 -->
      <div class="toolbar" style="margin-top:8px">
        <span class="muted small">扫描任务历史累计 {{ histScansTotal }} 条(已完成的历史记录, 不影响资产与漏洞)</span>
        <button class="btn xs danger" :disabled="!histScansTotal || clearing" @click="clearScans">
          {{ clearing ? '清空中...' : '清空历史记录' }}
        </button>
        <div class="spacer" style="flex:1"></div>
        <router-link class="muted small" to="/console?tab=queue">扫描作业 →</router-link>
      </div>

      <div class="grid cols-3" style="margin-top:14px">
        <!-- 漏洞等级分布 -->
        <div class="card">
          <div class="card-title">漏洞等级分布 <span class="sub" v-if="vulnsTotal">共 {{ vulnsTotal }} 条</span></div>
          <div v-if="vulnsTotal === 0"><Empty text="暂无漏洞记录" /></div>
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
          <div class="card-title">引擎状态 <span class="sub">本地引擎 ./bin/ + 内置引擎</span></div>
          <div v-if="!env"><Empty text="环境检测中 / 不可用" /></div>
          <div v-else>
            <div class="top-item" v-for="e in env.engines" :key="e.name">
              <span class="chip" :class="e.state === 'ok' ? 'on' : (e.fallback ? 'warn' : 'off')" style="min-width:64px; justify-content:center; text-align:center">
                {{ e.state === 'ok' ? '就绪' : (e.state === 'detecting' ? '检测中' : (e.fallback ? '降级' : '异常')) }}
              </span>
              <span class="t-title mono">{{ e.name }}</span>
              <span class="muted small mono">{{ e.version || '-' }}</span>
            </div>
            <div class="muted small" style="margin-top:10px">
              降级引擎自动切换内置引擎, 扫描功能不受影响
              <router-link to="/env">详情 →</router-link>
            </div>
          </div>
        </div>

        <!-- 系统信息(静态构建/配置信息; 版本号由顶栏右上角唯一展示, 阶段 4 去重) -->
        <div class="card">
          <div class="card-title">系统信息</div>
          <div class="kv">
            <div class="k">本机 IP</div><div class="v mono">{{ info.localIP || '-' }}</div>
            <div class="k">主机名</div><div class="v">{{ info.hostname || '-' }}</div>
            <div class="k">服务端口</div><div class="v mono">{{ info.port || '-' }}</div>
            <div class="k">内置规则</div><div class="v">{{ info.vulnRules || 0 }} 条</div>
            <div class="k">Nuclei 模板</div><div class="v">{{ (info.nucleiTemplatesBuilt || 0) + ' 内置 / ' + (info.nucleiTemplates || 0) + ' 外部' }}</div>
            <div class="k">AI 后置分析</div><div class="v">{{ info.aiEnabled ? '已启用' : '未启用' }}</div>
            <div class="k">数据层</div><div class="v mono small">{{ dbType }} {{ dbStats }}</div>
          </div>
        </div>
      </div>

      <!-- 快捷入口 -->
      <div class="card" style="margin-top:14px">
        <div class="card-title">快捷入口</div>
        <div class="grid cols-4">
          <router-link class="btn" to="/console">启动实时扫描</router-link>
          <router-link class="btn" to="/console?tab=queue">管理调度任务</router-link>
          <router-link class="btn" to="/vulns">查看漏洞列表</router-link>
          <button class="btn" @click="setTab('screen')">进入安全大屏</button>
        </div>
      </div>

      <!-- 功能开关(默认全开, 关掉即停; 参数保存在 settings.json, 不需要手改文件) -->
      <div class="card" style="margin-top:14px">
        <div class="card-title">
          功能开关
          <span class="sub">默认开启 · 关闭后立即生效(无需重启)</span>
        </div>
        <div v-if="!switches" class="muted small">加载中...</div>
        <div v-else class="sw-grid">
          <label class="sw">
            <input type="checkbox" v-model="switches.geoip.enabled" @change="saveSwitches" />
            <span>IP 地理映射</span>
            <span class="muted small">{{ switches.geoip.loaded ? ('段表 ' + switches.geoip.v4Count + ' 条') : (switches.geoip.note || '') }}</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="switches.dashboard.enabled" @change="saveSwitches" />
            <span>3D 地球大屏</span>
            <span class="muted small">流向窗口 {{ switches.dashboard.days }} 天</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="switches.report.enabled" @change="saveReport" />
            <span>报告引擎</span>
            <span class="muted small">存档与下载</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="switches.report.templateManagement" @change="saveReport" />
            <span>模板管理</span>
            <span class="muted small">自建报告模板</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="switches.report.pdfExternal" @change="saveReport" />
            <span>PDF 外部转换</span>
            <span class="muted small">未装转换器自动回落打印</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="switches.report.autoGenerate" @change="saveReport" />
            <span>扫描后自动生成报告</span>
            <span class="muted small">异步, 失败不影响扫描</span>
          </label>
        </div>
        <div class="muted small" style="margin-top:8px">开关状态写入 exe 同目录 settings.json(该文件只用于保存参数)。</div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import StatCard from '../components/StatCard.vue'
import Empty from '../components/Empty.vue'
import BigScreen from './BigScreen.vue'
import { api } from '../api/http'
import { v2 } from '../api/http'

const route = useRoute()
const router = useRouter()

// ===== Tab 状态(URL query 驱动, 与 Engrules 同一口径) =====
// 只有 'screen' 是安全大屏 tab, 其它取值(含空)一律落到概览 —— 旧书签 / 不会失效
const tab = computed(() => (route.query.tab === 'screen' ? 'screen' : 'overview'))

// replace 而非 push: 切 tab 不该往历史栈里堆记录(浏览器后退应是"离开本页")
function setTab(t) {
  if (t === tab.value) return
  router.replace({ path: '/', query: t === 'screen' ? { tab: 'screen' } : {} })
}

// ===== Tab1 概览数据(手动刷新) =====
const loading = ref(false)
const info = ref({})
const env = ref(null)
const assetsTotal = ref(0)
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

const SEV_META = [
  { key: 'critical', name: '严重', color: '#ff6b6b' },
  { key: 'high', name: '高危', color: '#f87171' },
  { key: 'medium', name: '中危', color: '#fb923c' },
  { key: 'low', name: '低危', color: '#facc15' },
  { key: 'info', name: '信息', color: '#60a5fa' }
]

const sevBars = computed(() => {
  const max = Math.max(1, ...SEV_META.map(s => vulnsList.value.filter(v => v.severity === s.key).length))
  return SEV_META.map(s => {
    const count = vulnsList.value.filter(v => v.severity === s.key).length
    return { ...s, count, pct: count ? Math.max(4, Math.round(count / max * 100)) : 0 }
  })
})

const engineOk = computed(() => {
  if (!env.value) return false
  return !(env.value.degraded && env.value.degraded.length) && !env.value.detecting
})
const engineSub = computed(() => {
  if (!env.value) return '检测中'
  const d = env.value.degraded || []
  return d.length ? '降级: ' + d.join(', ') : (env.value.engines || []).filter(e => e.state === 'ok').length + ' 个就绪'
})
const npcapText = computed(() => {
  if (!env.value) return '-'
  if (!env.value.npcap.supported) return '不适用'
  return env.value.npcap.installed ? '已安装' : '未安装'
})
const npcapOk = computed(() => !!env.value && (!env.value.npcap.supported || env.value.npcap.installed))

async function loadAll() {
  loading.value = true
  try {
    const [i, e, a, v, s, d, sc] = await Promise.allSettled([
      api('/api/info'),
      api('/api/env'),
      v2('/assets?size=1'),
      v2('/vulns?size=200'),
      v2('/scans?size=200'),
      v2('/db/status'),
      v2('/scheduler/status')
    ])
    if (i.status === 'fulfilled') info.value = i.value
    if (e.status === 'fulfilled') env.value = e.value
    if (a.status === 'fulfilled') assetsTotal.value = a.value.total
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
    csErr.value = (e && e.message) ? e.message : '数据获取失败'
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
function barW(v) { return v == null ? 0 : Math.max(2, Math.min(100, v)) }
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
  return (d ? d + '天 ' : '') + p(h) + ':' + p(m) + ':' + p(ss)
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
  if (!confirm(`将清空全部 ${histScansTotal.value} 条扫描任务历史记录, 不可恢复。\n\n只清任务记录, 资产 / 漏洞 / 探针任务明细都不受影响。\n\n确认清空?`)) return
  clearing.value = true
  try {
    const d = await v2('/scans', { method: 'DELETE' })
    await loadAll()
    alert('已清空 ' + (d && d.deleted != null ? d.deleted : 0) + ' 条历史任务记录')
  } catch (e) {
    alert('清空失败: ' + (e.message || e))
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
    alert('保存失败: ' + (e && e.message || e))
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
        templateManagement: switches.value.report.templateManagement,
        pdfExternal: switches.value.report.pdfExternal,
        autoGenerate: switches.value.report.autoGenerate
      }
    })
  } catch (e) {
    alert('保存失败: ' + (e && e.message || e))
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
