<!--
  NodeCommonCards.vue 节点监控公共区: 采集全局配置 + 异常事件(两 Tab 共用)。

  配置: 总开关 / 默认间隔 / 并发 / 全局限速 / 保留时长 / IP 白名单 / NetFlow 接收 /
        告警阈值 —— 对应 /api/v2/node/config(写 settings.json 的 collect 节)。
  事件: 采集底座输出的异常事件(离线/恢复/CPU·内存·时延·丢包越限), 来自
        /api/v2/node/events(落 collect_events 表, 保留 30 天)。
-->
<template>
  <div>
    <!-- 采集配置 -->
    <div class="card">
      <div class="card-title">采集配置 <span class="sub">全局 · 写入 settings.json 的 collect 节</span></div>
      <div class="form-row cfg-row">
        <div class="field cfg-field">
          <label class="lbl">启用采集</label>
          <div class="cfg-toggle">
            <span class="chip" :class="cfg.enabled ? 'on' : 'off'">{{ cfg.enabled ? '已启用' : '已停用' }}</span>
            <button class="btn xs" @click="toggleEnabled">{{ cfg.enabled ? '停用' : '启用' }}</button>
          </div>
        </div>
        <div class="field cfg-field">
          <label class="lbl">默认间隔(秒)</label>
          <input class="input cfg-input" type="number" min="5" v-model.number="cfg.intervalSec" />
        </div>
        <div class="field cfg-field">
          <label class="lbl">并发任务数</label>
          <input class="input cfg-input" type="number" min="1" v-model.number="cfg.concurrent" />
        </div>
        <div class="field cfg-field">
          <label class="lbl">全局限速(次/秒)</label>
          <input class="input cfg-input" type="number" min="1" v-model.number="cfg.globalRate" />
        </div>
        <div class="field cfg-field">
          <label class="lbl">保留(小时)</label>
          <input class="input cfg-input" type="number" min="1" v-model.number="cfg.retentionHours" />
        </div>
        <div class="field cfg-field" style="justify-content:flex-end">
          <button class="btn primary sm" @click="saveConfig" :disabled="saving">保存配置</button>
        </div>
      </div>

      <div class="muted small" v-if="status.netflowActive && status.netflowActive.length">
        NetFlow/IPFIX 监听中: {{ status.netflowActive.join(', ') }}
      </div>
      <div class="muted small" v-if="!status.secretKeySet">
        提示: 未设置加密密钥(环境变量 YUGSIGHT_MONITOR_KEY), 任务口令将以明文存储于 settings.json。
      </div>
    </div>

    <!-- 报告中心(二期): 节点监控是连续采样, 周期轮询不自动存档;
         这里提供手动"存快照"入口(最新状态 + 最近异常事件 → 原始报告) -->
    <div class="card">
      <div class="card-title">报告中心 <span class="sub">把当前节点监控状态存一份原始报告</span></div>
      <div class="form-row cfg-row">
        <div class="field cfg-field">
          <button class="btn sm" @click="saveSnapshot('collect')" :disabled="snapBusy">存节点采集快照</button>
        </div>
        <div class="field cfg-field">
          <button class="btn sm" @click="saveSnapshot('monitor')" :disabled="snapBusy">存设备监控快照(SNMP)</button>
        </div>
        <div class="field" style="flex:1; align-self:center">
          <span class="muted small">"立即采集"完成也会自动存档一份; 存储与查看在「报告中心 → 原始报告」。</span>
        </div>
      </div>
    </div>

    <!-- 告警阈值 + NetFlow + 白名单(折叠区, 避免首屏过长) -->
    <div class="card">
      <div class="card-title" style="cursor:pointer" @click="advOpen = !advOpen">
        高级配置(告警阈值 / NetFlow / IP 白名单)
        <span class="sub">{{ advOpen ? '收起 ▲' : '展开 ▼' }}</span>
      </div>
      <template v-if="advOpen">
        <div class="form-row cfg-row">
          <div class="field cfg-field">
            <label class="lbl">CPU 告警(%)</label>
            <input class="input cfg-input" type="number" min="0" v-model.number="cfg.alerts.cpuPct" />
          </div>
          <div class="field cfg-field">
            <label class="lbl">内存告警(%)</label>
            <input class="input cfg-input" type="number" min="0" v-model.number="cfg.alerts.memPct" />
          </div>
          <div class="field cfg-field">
            <label class="lbl">时延告警(ms)</label>
            <input class="input cfg-input" type="number" min="0" v-model.number="cfg.alerts.rttMs" />
          </div>
          <div class="field cfg-field">
            <label class="lbl">丢包告警(%)</label>
            <input class="input cfg-input" type="number" min="0" v-model.number="cfg.alerts.lossPct" />
          </div>
          <div class="field cfg-field">
            <label class="lbl">连续失败 N 轮判离线</label>
            <input class="input cfg-input" type="number" min="1" v-model.number="cfg.alerts.failStreak" />
          </div>
        </div>
        <div class="form-row cfg-row">
          <div class="field cfg-field">
            <label class="lbl">NetFlow 接收</label>
            <div class="cfg-toggle">
              <span class="chip" :class="cfg.netflow.enabled ? 'on' : 'off'">{{ cfg.netflow.enabled ? '已启用' : '已停用' }}</span>
              <button class="btn xs" @click="cfg.netflow.enabled = !cfg.netflow.enabled">{{ cfg.netflow.enabled ? '停用' : '启用' }}</button>
            </div>
          </div>
          <div class="field cfg-field">
            <label class="lbl">NetFlow 监听地址</label>
            <input class="input cfg-input" v-model="cfg.netflow.listen" placeholder="0.0.0.0:2000" />
          </div>
        </div>
        <div class="field">
          <label class="lbl">IP 白名单 <span class="muted small">(IP 或 CIDR, 逗号/换行分隔; 留空 = 不限制)</span></label>
          <textarea class="input" rows="3" v-model="whitelistText" placeholder="192.168.1.0/24, 10.0.0.0/8"></textarea>
        </div>
      </template>
    </div>

    <!-- 异常事件 -->
    <div class="card">
      <div class="card-title">
        异常事件
        <span class="sub">{{ events.length }} 条(保留 30 天)</span>
        <div class="spacer"></div>
        <button class="btn xs" @click="loadEvents">刷新</button>
        <!-- 阶段 3: 告警 AI 分析 —— 后端按 module=collect 现场生成采集快照报告
             (最新状态 + 最近事件)并分析, 结果存报告中心; 未启用自动置灰 -->
        <AiAnalyzeButton module="collect" label="AI 分析(告警)" />
      </div>
      <div v-if="!events.length" class="empty-box">
        <span class="ph-tag">无事件</span>
        暂无异常事件。连续失败达阈值会报离线, 恢复报上线, 指标越限报告警。
      </div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead><tr><th>级别</th><th>类型</th><th>目标</th><th>说明</th><th>时间</th></tr></thead>
          <tbody>
            <tr v-for="e in events" :key="e.id">
              <td><span class="chip" :class="lvlClass(e.level)">{{ e.level }}</span></td>
              <td class="mono small">{{ evtLabel(e.type) }}</td>
              <td class="mono small">{{ e.target }}</td>
              <td class="small">{{ e.msg }}</td>
              <td class="mono small muted">{{ fmtDT(e.at) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { v2 } from '../api/http'
import AiAnalyzeButton from './AiAnalyzeButton.vue'

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
const events = ref([])
const whitelistText = ref('')

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
  } catch (e) {
    console.warn('load node status failed', e)
  }
}

async function loadEvents() {
  try {
    const d = await v2('/node/events?limit=100')
    events.value = d.events || []
  } catch (e) {
    console.warn('load node events failed', e)
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
    alert('保存失败: ' + e.message)
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
    alert('切换失败: ' + e.message)
  } finally {
    saving.value = false
  }
}

const snapBusy = ref(false)
// 报告中心二期: 手动存快照(module: collect=节点采集 / monitor=SNMP 设备监控)
async function saveSnapshot(module) {
  snapBusy.value = true
  try {
    await v2('/raw/snapshot', { method: 'POST', body: { module } })
    alert('快照已存入报告中心(原始报告)')
  } catch (e) {
    alert(e.message)
  } finally {
    snapBusy.value = false
  }
}

function lvlClass(l) {
  return l === 'critical' ? 'off' : (l === 'warn' ? 'warn' : 'on')
}
function evtLabel(t) {
  const map = { offline: '离线', recover: '恢复', high_cpu: 'CPU 越限', high_mem: '内存越限', high_rtt: '时延越限', high_loss: '丢包越限' }
  return map[t] || t
}
function fmtDT(s) {
  if (!s) return '—'
  const d = new Date(s)
  if (isNaN(d)) return s
  const p = n => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

let timer = null
onMounted(() => {
  loadStatus()
  loadEvents()
  timer = setInterval(() => { loadStatus(); loadEvents() }, 15000)
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.cfg-row { flex-wrap: wrap; }
.cfg-field { min-width: 130px; }
.cfg-input { width: 100%; }
.cfg-toggle { display: flex; align-items: center; gap: 6px; }
.chip.warn { background: rgba(255, 176, 32, .14); color: var(--orange); }
</style>
