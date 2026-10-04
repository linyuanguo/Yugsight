<template>
  <div>
    <PageHeader :title="t('wp.title')" :desc="t('wp.desc')">
      <span class="chip" :class="st && st.enabled ? 'on' : 'off'">
        {{ st && st.enabled ? t('wp.on') : t('wp.off') }}
      </span>
      <button class="btn sm" @click="loadStatus"><span class="spinner" v-if="loading"></span> {{ t('wp.refresh') }}</button>
    </PageHeader>

    <!-- 顶层 Tab: 检测任务(原有功能) + 字典管理(新增) -->
    <!-- 注意: 外层用 view 状态, 内层"结果/审计"仍用 tab —— 二者是不同维度,
         共用一个变量会导致点内层 Tab 时整个任务区被 v-if 隐藏(已踩过的坑)。 -->
    <div class="tabs">
      <div class="tab" :class="{ active: view === 'task' }" @click="view = 'task'">{{ t('wp.tabTask') }}</div>
      <div class="tab" :class="{ active: view === 'dict' }" @click="switchToDict">
        {{ t('wp.tabDict') }}
        <span class="muted small" v-if="dictTotal > 0">{{ t('wp.dictBuiltIn', { n: dictStats.builtin }) }} · {{ t('wp.dictCustom', { n: dictStats.custom }) }}</span>
      </div>
    </div>

    <!-- ===== 顶层 Tab 1: 检测任务(原有内容) ===== -->
    <template v-if="view === 'task'">
      <!-- 未启用: 给出可操作的启用方法, 而不是让用户对空页面猜原因 -->
      <div class="card" v-if="st && !st.enabled">
        <Empty :text="t('wp.notEnabled')" />
        <p class="muted small" style="text-align:center; margin-top:8px">
          {{ t('wp.notEnabledHint') }}
        </p>
      </div>

      <template v-else-if="st">
        <!-- 运行配置 -->
        <div class="card">
          <div class="card-title">
            {{ t('wp.runCfg') }}
            <span class="sub">{{ t('wp.runCfgSub') }}</span>
            <div class="spacer"></div>
            <span class="chip">{{ t('wp.dictSize', { n: st.dictSize }) }}</span>
            <span class="chip" v-if="dictTotal > 0">{{ t('wp.customCount', { n: dictStats.custom }) }}</span>
            <span class="chip">{{ t('wp.rate', { rate: st.rate, max: st.maxTry, ms: st.timeoutMs }) }}</span>
          </div>
          <div class="muted small" style="margin-bottom:6px">{{ t('wp.wlLabel') }}</div>
          <div style="display:flex; flex-wrap:wrap; gap:6px; align-items:center; margin-bottom:8px">
            <span class="badge blue mono" v-for="tg in (st.targets || [])" :key="tg">
              {{ tg }}
              <b v-if="admin" @click="removeTarget(tg)" :title="t('wp.wlRemove')"
                 style="cursor:pointer; margin-left:4px; color:var(--danger,#e5484d)">×</b>
            </span>
            <span class="muted small" v-if="!(st.targets || []).length">{{ t('wp.wlNone') }}</span>
          </div>
          <!-- 白名单增删(仅 admin): 改白名单=改爆破攻击面, 与字典编辑同一权限口径。
               后端整体替换语义: 提交"当前列表 ± 本次改动"的完整列表, 立即写
               settings.json 并热生效(免重启)。 -->
          <div class="form-row" v-if="admin" style="margin-bottom:4px">
            <div class="field" style="max-width:340px; flex:1">
              <input class="input mono" v-model.trim="newTarget"
                     :placeholder="t('wp.wlAddPh')"
                     :disabled="wlBusy" @keyup.enter="addTarget">
            </div>
            <button class="btn sm" :disabled="!newTarget || wlBusy" @click="addTarget">
              <span class="spinner" v-if="wlBusy"></span> {{ t('wp.add') }}
            </button>
            <span class="muted small">{{ t('wp.wlHot') }}</span>
          </div>
          <div class="muted small" v-else style="margin-bottom:4px">{{ t('wp.wlAdminOnly') }}</div>
          <!-- 只列支持的协议。st.unsupported(目前是 mssql)刻意不展示: 用户要求
               "不支持的就不显示" —— 列出来只会让人以为"能填但被拒", 反而要去点。
               用户真的填了不支持的协议时, 结果表里仍会有「协议不支持」的明确反馈,
               提示责任由数据行承担, 不靠这里的清单预告。 -->
          <div class="muted small" style="margin-bottom:6px">{{ t('wp.supported') }}</div>
          <div style="display:flex; flex-wrap:wrap; gap:6px">
            <span class="badge" v-for="p in (st.supported || [])" :key="p">{{ p }}</span>
          </div>
        </div>

        <!-- 发起检测 -->
        <div class="card">
          <div class="card-title">
            {{ t('wp.startTitle') }}
            <span class="sub">{{ t('wp.startSub') }}</span>
          </div>
          <textarea
            class="input mono"
            v-model="targetsText"
            rows="5"
            spellcheck="false"
            :disabled="running"
            placeholder="192.168.1.10:6379&#10;192.168.1.20:3306:mysql&#10;192.168.1.30:21:ftp:admin"
          ></textarea>
          <div class="form-row" style="margin-top:10px">
            <div class="field" style="max-width:220px">
              <label class="label">{{ t('wp.userLabel') }}</label>
              <input class="input mono" v-model.trim="user" :placeholder="t('wp.userPh')" :disabled="running">
            </div>
            <div class="field" style="max-width:280px">
              <label class="label" style="display:flex; align-items:center; gap:6px; cursor:pointer">
                <input type="checkbox" v-model="builtinOnly" :disabled="running" style="width:15px; height:15px">
                {{ t('wp.builtinOnly') }}
                <span class="muted small">{{ t('wp.builtinOnlyHint') }}</span>
              </label>
            </div>
            <div class="spacer"></div>
            <!-- 2026-09-25 命名扫描: 控制台"下一步弱口令"带任务名时显示关联, 本批次
                 结果按它打进原始报告(报告中心按任务名分类) -->
            <span class="chip blue" v-if="jobName" :title="t('wp.jobNameTitle')">{{ t('wp.jobName', { name: jobName }) }}</span>
            <span class="chip" :class="parsed.length ? 'on' : 'warn'">{{ t('wp.parsed', { n: parsed.length }) }}</span>
            <button class="btn primary" v-if="!running" :disabled="!parsed.length" @click="start">{{ t('wp.start') }}</button>
            <button class="btn danger" v-else @click="stop">{{ t('wp.stop') }}</button>
          </div>
          <div class="muted small err-line" style="color:var(--danger,#e5484d)">{{ err }}</div>
        </div>

        <!-- 最近批次 -->
        <div class="card" v-if="run">
          <div class="card-title">
            {{ t('wp.lastBatch') }}
            <span class="chip" v-if="run.finished && run.stopped" style="color:var(--warning,#f0b429)">{{ t('wp.stopped') }}</span>
            <span class="chip" :class="run.finished ? 'on' : 'warn'">{{ run.finished ? t('wp.finished') : t('wp.running') }}</span>
            <div class="spacer"></div>
            <span class="mono small muted">{{ run.id }}</span>
            <span class="muted small">{{ t('wp.startedAt', { time: fmtDT(run.startedAt) }) }}</span>
            <!-- 阶段 3: AI 研判 —— 批次结束后结果自动存档为原始报告,
                 后端按 module=weakpass 取 10 分钟内最新一份分析(复用 scan 模块开关) -->
            <AiAnalyzeButton v-if="run.finished" module="weakpass" :label="t('wp.aiLabel')" />
          </div>
          <div class="muted small" v-if="run.summary" style="margin-bottom:8px">{{ run.summary }}</div>

          <div class="tabs">
            <div class="tab" :class="{ active: tab === 'res' }" @click="tab = 'res'">{{ t('wp.resTab') }} ({{ (run.results || []).length }})</div>
            <div class="tab" :class="{ active: tab === 'aud' }" @click="tab = 'aud'">{{ t('wp.audTab') }} ({{ (run.audit || []).length }})</div>
          </div>

          <div v-if="tab === 'res'">
            <div class="table-wrap" v-if="(run.results || []).length">
              <table class="table">
                <thead>
                  <tr><th>{{ t('wp.thTarget') }}</th><th>{{ t('wp.thService') }}</th><th>{{ t('wp.thConclusion') }}</th><th>{{ t('wp.thPass') }}</th><th>{{ t('wp.thAttempts') }}</th><th>{{ t('wp.thEndReason') }}</th><th>{{ t('wp.thError') }}</th><th style="width:90px">{{ t('wp.thLink') }}</th></tr>
                </thead>
                <tbody>
                  <tr v-for="(r, i) in run.results" :key="i">
                    <td class="mono">{{ r.host }}<span class="muted">:{{ r.port }}</span></td>
                    <td><span class="badge blue">{{ r.service }}</span></td>
                    <td>
                      <span class="badge" style="color:#fff;background:var(--danger,#e5484d);border-color:transparent" v-if="r.ok && r.emptyPass">{{ t('wp.emptyPass') }}</span>
                      <span class="badge" style="color:#fff;background:var(--danger,#e5484d);border-color:transparent" v-else-if="r.ok">{{ t('wp.weak') }}</span>
                      <span class="badge" style="color:var(--muted)" v-else-if="r.unsupported">{{ t('wp.unsupported') }}</span>
                      <span class="badge" style="color:var(--muted)" v-else>{{ t('wp.miss') }}</span>
                    </td>
                    <td class="mono">{{ r.ok ? (r.password || t('wp.emptyPwd')) : '-' }}</td>
                    <td class="mono">{{ r.attempts }}</td>
                    <td class="mono small muted">{{ r.stopped || '-' }}</td>
                    <td class="small muted">{{ r.error || '-' }}</td>
                    <!-- 阶段 5 联动: 把这条服务的目标/端口/服务带去渗透工作台做凭据验证
                         (渗透是攻击性能力, 仅管理员有入口) -->
                    <td>
                      <button class="btn xs" v-if="admin" @click="toPenta(r)">{{ t('wp.verify') }}</button>
                      <span class="muted small" v-else>-</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <Empty v-else :text="t('wp.noResult')" />
          </div>

          <div v-else>
            <div class="table-wrap" v-if="(run.audit || []).length">
              <table class="table">
                <thead>
                  <tr><th>{{ t('wp.thTime') }}</th><th>{{ t('wp.thTarget') }}</th><th>{{ t('wp.thService') }}</th><th>{{ t('wp.thUser') }}</th><th>{{ t('wp.thPass') }}</th><th>{{ t('wp.thResult') }}</th><th>{{ t('wp.thError') }}</th></tr>
                </thead>
                <tbody>
                  <tr v-for="(a, i) in run.audit" :key="i">
                    <td class="mono small muted">{{ fmtDT(a.time) }}</td>
                    <td class="mono">{{ a.target }}</td>
                    <td><span class="badge blue">{{ a.service }}</span></td>
                    <td class="mono">{{ a.user || '-' }}</td>
                    <td class="mono">{{ a.ok ? a.password : '-' }}</td>
                    <td>
                      <span class="badge" style="color:#fff;background:var(--danger,#e5484d);border-color:transparent" v-if="a.ok">{{ t('wp.hit') }}</span>
                      <span class="badge" style="color:var(--muted)" v-else>{{ t('wp.miss') }}</span>
                    </td>
                    <td class="small muted">{{ a.err || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <Empty v-else :text="t('wp.noAudit')" />
          </div>
        </div>
      </template>
    </template>

    <!-- ===== 顶层 Tab 2: 字典管理(新增) ===== -->
    <template v-if="view === 'dict'">
      <!-- 操作栏 -->
      <div class="card">
        <div class="card-title">
          {{ t('wp.dictTitle') }}
          <span class="sub">{{ t('wp.dictSub') }}</span>
          <div class="spacer"></div>
          <span class="chip" :class="dictStats.builtin > 0 ? 'on' : 'warn'">{{ t('wp.dictBuiltIn', { n: dictStats.builtin }) }}</span>
          <span class="chip" :class="dictStats.custom > 0 ? 'blue' : ''">{{ t('wp.dictCustom', { n: dictStats.custom }) }}</span>
        </div>
        <div class="form-row" style="margin-top:4px">
          <div class="field" style="max-width:260px; flex:1">
            <label class="label">{{ t('wp.dictSearch') }}</label>
            <input class="input mono" v-model="dictQ" :placeholder="t('wp.dictSearchPh')" @keyup.enter="dictPage = 1; loadDict()">
          </div>
          <div class="spacer"></div>
          <button class="btn" v-if="admin" @click="openAdd">{{ t('wp.addWeak') }}</button>
          <button class="btn" v-if="admin" :disabled="!dictSelected.length" @click="batchDelete">
            {{ t('wp.batchDel') }}{{ dictSelected.length ? ` (${dictSelected.length})` : '' }}
          </button>
          <button class="btn danger" v-if="admin" @click="openReset">{{ t('wp.resetDict') }}</button>
          <span class="muted small" v-if="!admin">{{ t('wp.dictAdminOnly') }}</span>
        </div>
        <div class="muted small err-line" style="color:var(--danger,#e5484d)">{{ dictErr }}</div>
      </div>

      <!-- 列表 -->
      <div class="card">
        <div class="table-wrap" v-if="dictItems.length">
          <table class="table">
            <thead>
              <tr>
                <th style="width:36px"><input type="checkbox" v-if="admin" :checked="allCustomSelected" :indeterminate.prop="someCustomSelected" @change="toggleAllCustom" :title="t('wp.selAllCustom')"></th>
                <th style="width:56px">{{ t('wp.thSeq') }}</th>
                <th>{{ t('wp.thContent') }}</th>
                <th style="width:90px">{{ t('wp.thType') }}</th>
                <th style="width:160px">{{ t('wp.thCreate') }}</th>
                <th style="width:80px">{{ t('wp.thOp') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(it, i) in dictItems" :key="it.id">
                <td>
                  <input type="checkbox" v-if="admin && it.type === 'custom'" :checked="dictSelected.includes(it.id)" @change="toggleSelect(it.id)" :title="t('wp.customDeletable')">
                </td>
                <td class="mono muted small">{{ (dictPage - 1) * dictSize + i + 1 }}</td>
                <td class="mono">{{ it.password }}</td>
                <td>
                  <span class="badge" :class="it.type === 'custom' ? 'blue' : ''">{{ it.type === 'custom' ? t('wp.custom') : t('wp.builtin') }}</span>
                </td>
                <td class="mono small muted">{{ fmtDT(it.createTime) }}</td>
                <td>
                  <button class="btn xs danger" v-if="admin && it.type === 'custom'" @click="removeOne(it)">{{ t('common.del') }}</button>
                  <span class="muted small" v-else>-</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="dictQ ? t('wp.noMatch') : t('wp.dictEmpty')" />

        <div class="pager" v-if="dictTotal > dictPage * dictSize">
          <span>{{ t('wp.page', { n: dictPage, t: dictTotal }) }}</span>
          <div class="spacer"></div>
          <button class="btn xs" :disabled="dictPage <= 1" @click="dictPage--; loadDict()">{{ t('al.prev') }}</button>
          <button class="btn xs" :disabled="dictPage * dictSize >= dictTotal" @click="dictPage++; loadDict()">{{ t('al.next') }}</button>
        </div>
      </div>
    </template>

    <!-- 新增弱口令弹窗(单条 / 批量, 每行一个) -->
    <Modal v-if="showAdd" :title="t('wp.addTitle')" width="480px" @close="showAdd = false">
      <div class="alert info" style="margin-bottom:12px">
        {{ t('wp.addHint') }}
      </div>
      <div class="field">
        <label class="label">{{ t('wp.addList') }}</label>
        <textarea class="input mono" v-model="addText" rows="8" spellcheck="false" placeholder="mySecret1&#10;P@ssw0rd2024&#10;admin888"></textarea>
      </div>
      <div class="muted small" style="margin-top:6px">{{ t('wp.parsedN', { n: addLines.length }) }}</div>
      <div class="login-err" style="text-align:left">{{ addErr }}</div>
      <template #footer>
        <button class="btn" @click="showAdd = false">{{ t('common.cancel') }}</button>
        <button class="btn primary" :disabled="!addLines.length || adding" @click="doAdd">
          <span class="spinner" v-if="adding"></span> {{ t('wp.add') }}
        </button>
      </template>
    </Modal>

    <!-- 重置确认弹窗(破坏性动作, 要求输入确认词) -->
    <Modal v-if="showReset" :title="t('wp.resetTitle')" width="460px" @close="showReset = false">
      <div class="alert warn" style="margin-bottom:12px">
        {{ t('wp.resetHint', { custom: dictStats.custom }) }}
      </div>
      <div class="field">
        <label class="label">{{ t('wp.resetInput') }}</label>
        <input class="input" v-model.trim="resetWord" :placeholder="t('wp.resetWord')" @keyup.enter="doReset">
      </div>
      <div class="login-err" style="text-align:left">{{ resetErr }}</div>
      <template #footer>
        <button class="btn" @click="showReset = false">{{ t('common.cancel') }}</button>
        <button class="btn danger" :disabled="resetWord !== t('wp.resetWord') || resetting" @click="doReset">
          <span class="spinner" v-if="resetting"></span> {{ t('wp.resetConfirm') }}
        </button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'

import { useRoute } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import Modal from '../components/Modal.vue'
import AiAnalyzeButton from '../components/AiAnalyzeButton.vue'
import { useRouter } from 'vue-router'
import { api, v2 } from '../api/http'
import { fmtDT } from '../utils'
import { isAdmin } from '../auth'
import { t } from '../i18n'

const route = useRoute()
const router = useRouter()
// admin 必须 computed 跟随响应式角色(快照式取值在整页刷新时会漏掉按钮, 阶段 4 已踩过)
const admin = computed(() => isAdmin())

// ===== 顶层 Tab 状态 =====
// view: 'task' = 检测任务(默认), 'dict' = 字典管理。
// 内层"结果/审计"Tab 用独立的 tab 变量(res/aud), 二者不可共用(会互相覆盖)。
const view = ref('task')
const tab = ref('res')
function switchToDict() {
  view.value = 'dict'
  loadDict() // 首次切入才拉字典(避免未切入也发请求)
}

// 「验证」: 深链把 host:port:service:user 带去渗透工作台预填新建任务
function toPenta(r) {
  const parts = [r.host, r.port, r.service || '', r.user || '']
  router.push('/penta?new=' + encodeURIComponent(parts.join(':')))
}

// 端口 -> 服务名(与后端 weakpass 包的支持列表一致; 只在 target 未带 service 时兜底)
const PORT_SERVICE = { 6379: 'redis', 3306: 'mysql', 21: 'ftp', 23: 'telnet' }

// 扫描控制台「弱口令检测」按钮带过来的目标(P1-6):
// targets=IP:端口(多个用逗号或换行分隔), service=服务名。
// 预填成 host:port[:service] 逐行格式, 与下方 parsed 的解析逻辑完全兼容。
function applyQueryTargets() {
  const raw = route.query.targets
  if (!raw) return
  const svc = String(route.query.service || '').trim().toLowerCase()
  const lines = []
  for (const part of String(raw).split(/[,\r\n]/)) {
    const t = part.trim()
    if (!t) continue
    const seg = t.split(':')
    const host = (seg[0] || '').trim()
    const port = parseInt(seg[1], 10)
    if (!host || !port) continue
    const s = (seg[2] && seg[2].trim()) ? seg[2].trim() : (svc || PORT_SERVICE[port] || '')
    lines.push(s ? `${host}:${port}:${s}` : `${host}:${port}`)
  }
  if (lines.length) targetsText.value = lines.join('\n')
  // 2026-09-25 命名扫描: 控制台"下一步弱口令"带任务名(job) —— 本批次结果按任务名
  // 打进原始报告, 报告中心按任务名分类/生成报告时能归到同一任务下
  jobName.value = String(route.query.job || '').trim()
}

// ===== 检测任务(原有逻辑) =====
// 全部走旧版 /api/authcheck/* 接口(原始 JSON, 错误体 {error}), 不经 Resp 拆包
const st = ref(null)
const run = ref(null)
const loading = ref(false)
const err = ref('')
const running = ref(false)
const targetsText = ref('')
const user = ref('')
// 仅使用内置字典开关(默认 false = 全量"内置 + 自定义")
const builtinOnly = ref(false)
// 关联的扫描任务名(控制台"下一步弱口令"带过来; 提交时随批次下发, 原始报告按它分类)
const jobName = ref('')
let pollTimer = null

// 逐行解析 host:port[:service[:user]]。
// 在前端把格式错误挡下来: 后端只校验条数, 单行格式错误会整批 400, 逐行提示更友好。
const parsed = computed(() => {
  const out = []
  for (let raw of (targetsText.value || '').split(/\r?\n/)) {
    const line = raw.trim()
    if (!line) continue
    const seg = line.split(':')
    if (seg.length < 2) continue
    const host = seg[0].trim()
    const port = parseInt(seg[1], 10)
    if (!host || !port || port < 1 || port > 65535) continue
    const t = { host, port }
    if (seg[2] && seg[2].trim()) t.service = seg[2].trim()
    if (seg[3] && seg[3].trim()) t.user = seg[3].trim()
    out.push(t)
  }
  return out
})

async function loadStatus() {
  loading.value = true
  try {
    st.value = await api('/api/authcheck/status')
    run.value = st.value.result || null
    setRunning(!!st.value.running)
    // 状态接口顺带回带字典统计, 同步刷新徽标(避免切 Tab 才加载)
    if (st.value.dictStats) {
      dictStats.value = st.value.dictStats
      dictTotal.value = (st.value.dictStats.builtin || 0) + (st.value.dictStats.custom || 0)
    }
  } catch (e) {
    err.value = t('wp.errStatus', { err: e.message })
  } finally {
    loading.value = false
  }
}

function setRunning(v) {
  running.value = v
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
  if (v) {
    // 执行中轮询(批次可能持续数分钟, 频率不必高)
    pollTimer = setInterval(async () => {
      try {
        const s = await api('/api/authcheck/status')
        st.value = s
        run.value = s.result || null
        if (s.dictStats) {
          dictStats.value = s.dictStats
          dictTotal.value = (s.dictStats.builtin || 0) + (s.dictStats.custom || 0)
        }
        if (!s.running) {
          setRunning(false)
          err.value = ''
        }
      } catch (e) { /* 瞬时抖动, 下一轮重试 */ }
    }, 2000)
  }
}

async function start() {
  err.value = ''
  const targets = parsed.value
  if (!targets.length) { err.value = t('wp.errNoTarget'); return }
  if (targets.length > 200) { err.value = t('wp.errTooMany', { n: targets.length }); return }
  const body = { targets }
  if (user.value) body.user = user.value
  if (builtinOnly.value) body.builtinOnly = true
  if (jobName.value) body.job = jobName.value // 关联扫描任务名(原始报告按任务名分类)
  try {
    await api('/api/authcheck/start', { method: 'POST', body })
    setRunning(true)
    await loadStatus()
  } catch (e) {
    err.value = t('wp.errStart', { err: e.message })
    // 后端返回的运行状态是权威的, 以它为准刷新本地 running
    await loadStatus()
  }
}

async function stop() {
  err.value = ''
  try {
    await api('/api/authcheck/stop', { method: 'POST' })
  } catch (e) {
    err.value = t('wp.errStop', { err: e.message })
  }
  await loadStatus()
}

// ===== 白名单增删(仅 admin) =====
// 后端是整体替换语义: 每次提交"当前列表 ± 本次改动"的完整列表。
// 失败时以 status 接口重新拉取为准(服务端是唯一事实来源)。
const newTarget = ref('')
const wlBusy = ref(false)

async function applyTargets(targets) {
  err.value = ''
  wlBusy.value = true
  try {
    const d = await api('/api/authcheck/config', { method: 'PUT', body: { targets } })
    st.value.targets = d.targets || []
  } catch (e) {
    err.value = e.message
    await loadStatus()
  } finally {
    wlBusy.value = false
  }
}

function addTarget() {
  const t = newTarget.value
  if (!t) return
  newTarget.value = ''
  applyTargets([...(st.value?.targets || []), t])
}

function removeTarget(t) {
  applyTargets((st.value?.targets || []).filter(x => x !== t))
}

// ===== 字典管理(新增) =====
const dictItems = ref([])
const dictStats = ref({ builtin: 0, custom: 0 })
const dictTotal = ref(0)
const dictQ = ref('')
const dictPage = ref(1)
const dictSize = 20
const dictErr = ref('')
const dictSelected = ref([]) // 选中的自定义条目 id

const allCustomSelected = computed(() => {
  const customs = dictItems.value.filter(it => it.type === 'custom')
  return customs.length > 0 && customs.every(it => dictSelected.value.includes(it.id))
})
const someCustomSelected = computed(() => {
  const customs = dictItems.value.filter(it => it.type === 'custom')
  return customs.some(it => dictSelected.value.includes(it.id)) && !allCustomSelected.value
})

async function loadDict() {
  dictErr.value = ''
  try {
    const qs = new URLSearchParams({ page: String(dictPage.value), size: String(dictSize) })
    if (dictQ.value.trim()) qs.set('q', dictQ.value.trim())
    const d = await v2('/weakpass/dict?' + qs.toString())
    dictItems.value = d.items || []
    dictTotal.value = d.total || 0
    dictStats.value = { builtin: d.builtinCount || 0, custom: d.customCount || 0 }
    // 翻页/搜索后, 清理已不在本页的选择(避免删除已不存在的 id)
    dictSelected.value = dictSelected.value.filter(id => dictItems.value.some(it => it.id === id))
  } catch (e) {
    dictErr.value = t('wp.errDict', { err: e.message })
  }
}

// 新增
const showAdd = ref(false)
const addText = ref('')
const addErr = ref('')
const adding = ref(false)
const addLines = computed(() =>
  (addText.value || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean)
)
function openAdd() {
  addText.value = ''
  addErr.value = ''
  showAdd.value = true
}
async function doAdd() {
  addErr.value = ''
  const passwords = addLines.value
  if (!passwords.length) { addErr.value = t('wp.errAddNone'); return }
  if (passwords.length > 500) { addErr.value = t('wp.errAddMax'); return }
  adding.value = true
  try {
    const d = await v2('/weakpass/dict', { method: 'POST', body: { passwords } })
    showAdd.value = false
    // 有跳过项时提示(用户以为加成功实际没进去)
    if (d.skipped && d.skipped.length) {
      addErr.value = t('wp.addSkip', { added: d.added, skipped: d.skipped.length, list: d.skipped.join(', ') })
    }
    await loadDict()
  } catch (e) {
    addErr.value = t('wp.errAdd', { err: e.message })
  } finally {
    adding.value = false
  }
}

// 单条删除
async function removeOne(it) {
  if (!confirm(t('wp.delOne', { p: it.password }))) return
  try {
    await v2(`/weakpass/dict/${it.id}`, { method: 'DELETE' })
    dictSelected.value = dictSelected.value.filter(id => id !== it.id)
    await loadDict()
  } catch (e) {
    dictErr.value = t('wp.errDel', { err: e.message })
  }
}

// 批量删除
async function batchDelete() {
  const ids = dictSelected.value
  if (!ids.length) return
  if (!confirm(t('wp.delBatch', { n: ids.length }))) return
  try {
    const d = await v2('/weakpass/dict/batch-delete', { method: 'POST', body: { ids } })
    dictSelected.value = []
    dictErr.value = d.skippedBuiltin ? t('wp.delBatchMsg', { deleted: d.deleted, skipped: d.skippedBuiltin }) : ''
    await loadDict()
  } catch (e) {
    dictErr.value = t('wp.errBatch', { err: e.message })
  }
}

function toggleSelect(id) {
  const i = dictSelected.value.indexOf(id)
  if (i >= 0) dictSelected.value.splice(i, 1)
  else dictSelected.value.push(id)
}
function toggleAllCustom(checked) {
  const customs = dictItems.value.filter(it => it.type === 'custom').map(it => it.id)
  dictSelected.value = checked ? customs : []
}

// 重置
const showReset = ref(false)
const resetWord = ref('')
const resetErr = ref('')
const resetting = ref(false)
function openReset() {
  resetWord.value = ''
  resetErr.value = ''
  showReset.value = true
}
async function doReset() {
  if (resetWord.value !== t('wp.resetWord')) { resetErr.value = t('wp.resetInputErr'); return }
  resetting.value = true
  try {
    await v2('/weakpass/dict/reset', { method: 'POST' })
    showReset.value = false
    dictSelected.value = []
    dictPage.value = 1
    dictQ.value = ''
    await loadDict()
  } catch (e) {
    resetErr.value = t('wp.errReset', { err: e.message })
  } finally {
    resetting.value = false
  }
}

onMounted(() => {
  loadStatus()
  applyQueryTargets()
})
onBeforeUnmount(() => { if (pollTimer) clearInterval(pollTimer) })
</script>
