<template>
  <div>
    <PageHeader title="弱口令检测" desc="限速认证尝试 redis/mysql/ftp/telnet(全程审计)">
      <span class="chip" :class="st && st.enabled ? 'on' : 'off'">
        {{ st && st.enabled ? '检测已启用' : '检测未启用' }}
      </span>
      <button class="btn sm" @click="loadStatus"><span class="spinner" v-if="loading"></span> 刷新</button>
    </PageHeader>

    <!-- 顶层 Tab: 检测任务(原有功能) + 字典管理(新增) -->
    <!-- 注意: 外层用 view 状态, 内层"结果/审计"仍用 tab —— 二者是不同维度,
         共用一个变量会导致点内层 Tab 时整个任务区被 v-if 隐藏(已踩过的坑)。 -->
    <div class="tabs">
      <div class="tab" :class="{ active: view === 'task' }" @click="view = 'task'">检测任务</div>
      <div class="tab" :class="{ active: view === 'dict' }" @click="switchToDict">
        字典管理
        <span class="muted small" v-if="dictTotal > 0">内置 {{ dictStats.builtin }} · 自定义 {{ dictStats.custom }}</span>
      </div>
    </div>

    <!-- ===== 顶层 Tab 1: 检测任务(原有内容) ===== -->
    <template v-if="view === 'task'">
      <!-- 未启用: 给出可操作的启用方法, 而不是让用户对空页面猜原因 -->
      <div class="card" v-if="st && !st.enabled">
        <Empty text="弱口令检测未启用" />
        <p class="muted small" style="text-align:center; margin-top:8px">
          在 exe 同目录 settings.json 增加 authcheck 节(如 { "enabled": true, "targets": ["192.168.0.0/16"] })后重启服务。
          targets 为 CIDR 白名单, 为空时所有请求都会被拒绝。
        </p>
      </div>

      <template v-else-if="st">
        <!-- 运行配置 -->
        <div class="card">
          <div class="card-title">
            运行配置
            <span class="sub">settings.json 的 authcheck 节, 修改后需重启服务</span>
            <div class="spacer"></div>
            <span class="chip">内置字典 {{ st.dictSize }} 条</span>
            <span class="chip" v-if="dictTotal > 0">自定义 {{ dictStats.custom }} 条</span>
            <span class="chip">限速 {{ st.rate }}/s · 上限 {{ st.maxTry }} · 超时 {{ st.timeoutMs }}ms</span>
          </div>
          <div class="muted small" style="margin-bottom:6px">目标白名单(CIDR):</div>
          <div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:10px">
            <span class="badge blue mono" v-for="t in (st.targets || [])" :key="t">{{ t }}</span>
            <span class="muted small" v-if="!(st.targets || []).length">未配置(接口将拒绝执行)</span>
          </div>
          <!-- 只列支持的协议。st.unsupported(目前是 mssql)刻意不展示: 用户要求
               "不支持的就不显示" —— 列出来只会让人以为"能填但被拒", 反而要去点。
               用户真的填了不支持的协议时, 结果表里仍会有「协议不支持」的明确反馈,
               提示责任由数据行承担, 不靠这里的清单预告。 -->
          <div class="muted small" style="margin-bottom:6px">支持协议:</div>
          <div style="display:flex; flex-wrap:wrap; gap:6px">
            <span class="badge" v-for="p in (st.supported || [])" :key="p">{{ p }}</span>
          </div>
        </div>

        <!-- 发起检测 -->
        <div class="card">
          <div class="card-title">
            发起检测
            <span class="sub">每行一个目标 host:port[:service[:user]] · service 留空按端口推断 · 单次上限 200</span>
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
              <label class="label">覆盖用户名(可选)</label>
              <input class="input mono" v-model.trim="user" placeholder="留空用目标自带的 user" :disabled="running">
            </div>
            <div class="field" style="max-width:280px">
              <label class="label" style="display:flex; align-items:center; gap:6px; cursor:pointer">
                <input type="checkbox" v-model="builtinOnly" :disabled="running" style="width:15px; height:15px">
                仅使用内置字典
                <span class="muted small">(默认用「内置 + 自定义」全量, 勾选后忽略自定义条目)</span>
              </label>
            </div>
            <div class="spacer"></div>
            <span class="chip" :class="parsed.length ? 'on' : 'warn'">解析到 {{ parsed.length }} 个目标</span>
            <button class="btn primary" v-if="!running" :disabled="!parsed.length" @click="start">启动检测</button>
            <button class="btn danger" v-else @click="stop">停止检测</button>
          </div>
          <div class="muted small err-line" style="color:var(--danger,#e5484d)">{{ err }}</div>
        </div>

        <!-- 最近批次 -->
        <div class="card" v-if="run">
          <div class="card-title">
            最近批次
            <span class="chip" v-if="run.finished && run.stopped" style="color:var(--warning,#f0b429)">已中止</span>
            <span class="chip" :class="run.finished ? 'on' : 'warn'">{{ run.finished ? '已结束' : '执行中' }}</span>
            <div class="spacer"></div>
            <span class="mono small muted">{{ run.id }}</span>
            <span class="muted small">· 开始 {{ fmtDT(run.startedAt) }}</span>
            <!-- 阶段 3: AI 研判 —— 批次结束后结果自动存档为原始报告,
                 后端按 module=weakpass 取 10 分钟内最新一份分析(复用 scan 模块开关) -->
            <AiAnalyzeButton v-if="run.finished" module="weakpass" label="AI 研判" />
          </div>
          <div class="muted small" v-if="run.summary" style="margin-bottom:8px">{{ run.summary }}</div>

          <div class="tabs">
            <div class="tab" :class="{ active: tab === 'res' }" @click="tab = 'res'">结果 ({{ (run.results || []).length }})</div>
            <div class="tab" :class="{ active: tab === 'aud' }" @click="tab = 'aud'">审计明细 ({{ (run.audit || []).length }})</div>
          </div>

          <div v-if="tab === 'res'">
            <div class="table-wrap" v-if="(run.results || []).length">
              <table class="table">
                <thead>
                  <tr><th>目标</th><th>服务</th><th>结论</th><th>口令</th><th>尝试次数</th><th>结束原因</th><th>错误</th><th style="width:90px">联动</th></tr>
                </thead>
                <tbody>
                  <tr v-for="(r, i) in run.results" :key="i">
                    <td class="mono">{{ r.host }}<span class="muted">:{{ r.port }}</span></td>
                    <td><span class="badge blue">{{ r.service }}</span></td>
                    <td>
                      <span class="badge" style="color:#fff;background:var(--danger,#e5484d);border-color:transparent" v-if="r.ok && r.emptyPass">空口令/免认证</span>
                      <span class="badge" style="color:#fff;background:var(--danger,#e5484d);border-color:transparent" v-else-if="r.ok">弱口令</span>
                      <span class="badge" style="color:var(--muted)" v-else-if="r.unsupported">协议不支持</span>
                      <span class="badge" style="color:var(--muted)" v-else>未命中</span>
                    </td>
                    <td class="mono">{{ r.ok ? (r.password || '(空)') : '-' }}</td>
                    <td class="mono">{{ r.attempts }}</td>
                    <td class="mono small muted">{{ r.stopped || '-' }}</td>
                    <td class="small muted">{{ r.error || '-' }}</td>
                    <!-- 阶段 5 联动: 把这条服务的目标/端口/服务带去渗透工作台做凭据验证
                         (渗透是攻击性能力, 仅管理员有入口) -->
                    <td>
                      <button class="btn xs" v-if="admin" @click="toPenta(r)">验证</button>
                      <span class="muted small" v-else>-</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <Empty v-else text="本批次暂无结果(执行中或尚未产生)" />
          </div>

          <div v-else>
            <div class="table-wrap" v-if="(run.audit || []).length">
              <table class="table">
                <thead>
                  <tr><th>时间</th><th>目标</th><th>服务</th><th>用户</th><th>口令</th><th>结果</th><th>错误</th></tr>
                </thead>
                <tbody>
                  <tr v-for="(a, i) in run.audit" :key="i">
                    <td class="mono small muted">{{ fmtDT(a.time) }}</td>
                    <td class="mono">{{ a.target }}</td>
                    <td><span class="badge blue">{{ a.service }}</span></td>
                    <td class="mono">{{ a.user || '-' }}</td>
                    <td class="mono">{{ a.ok ? a.password : '-' }}</td>
                    <td>
                      <span class="badge" style="color:#fff;background:var(--danger,#e5484d);border-color:transparent" v-if="a.ok">命中</span>
                      <span class="badge" style="color:var(--muted)" v-else>未命中</span>
                    </td>
                    <td class="small muted">{{ a.err || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <Empty v-else text="本批次暂无审计记录" />
          </div>
        </div>
      </template>
    </template>

    <!-- ===== 顶层 Tab 2: 字典管理(新增) ===== -->
    <template v-if="view === 'dict'">
      <!-- 操作栏 -->
      <div class="card">
        <div class="card-title">
          字典管理
          <span class="sub">弱口令爆破目标库: 内置 349 条常用弱口令 + 页面自定义, 执行任务时自动全量加载</span>
          <div class="spacer"></div>
          <span class="chip" :class="dictStats.builtin > 0 ? 'on' : 'warn'">内置 {{ dictStats.builtin }}</span>
          <span class="chip" :class="dictStats.custom > 0 ? 'blue' : ''">自定义 {{ dictStats.custom }}</span>
        </div>
        <div class="form-row" style="margin-top:4px">
          <div class="field" style="max-width:260px; flex:1">
            <label class="label">搜索口令(模糊)</label>
            <input class="input mono" v-model="dictQ" placeholder="输入关键字过滤" @keyup.enter="dictPage = 1; loadDict()">
          </div>
          <div class="spacer"></div>
          <button class="btn" v-if="admin" @click="openAdd">新增弱口令</button>
          <button class="btn" v-if="admin" :disabled="!dictSelected.length" @click="batchDelete">
            批量删除{{ dictSelected.length ? ` (${dictSelected.length})` : '' }}
          </button>
          <button class="btn danger" v-if="admin" @click="openReset">重置默认字典</button>
          <span class="muted small" v-if="!admin">仅管理员可编辑 / 重置, 当前只读</span>
        </div>
        <div class="muted small err-line" style="color:var(--danger,#e5484d)">{{ dictErr }}</div>
      </div>

      <!-- 列表 -->
      <div class="card">
        <div class="table-wrap" v-if="dictItems.length">
          <table class="table">
            <thead>
              <tr>
                <th style="width:36px"><input type="checkbox" v-if="admin" :checked="allCustomSelected" :indeterminate.prop="someCustomSelected" @change="toggleAllCustom" title="全选自定义条目"></th>
                <th style="width:56px">序号</th>
                <th>弱口令内容</th>
                <th style="width:90px">类型</th>
                <th style="width:160px">创建时间</th>
                <th style="width:80px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(it, i) in dictItems" :key="it.id">
                <td>
                  <input type="checkbox" v-if="admin && it.type === 'custom'" :checked="dictSelected.includes(it.id)" @change="toggleSelect(it.id)" title="自定义条目可删除">
                </td>
                <td class="mono muted small">{{ (dictPage - 1) * dictSize + i + 1 }}</td>
                <td class="mono">{{ it.password }}</td>
                <td>
                  <span class="badge" :class="it.type === 'custom' ? 'blue' : ''">{{ it.type === 'custom' ? '自定义' : '内置' }}</span>
                </td>
                <td class="mono small muted">{{ fmtDT(it.createTime) }}</td>
                <td>
                  <button class="btn xs danger" v-if="admin && it.type === 'custom'" @click="removeOne(it)">删除</button>
                  <span class="muted small" v-else>-</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="dictQ ? '无匹配口令' : '字典为空(重置可恢复内置 349 条)'" />

        <div class="pager" v-if="dictTotal > dictPage * dictSize">
          <span>第 {{ dictPage }} 页 · 共 {{ dictTotal }} 条</span>
          <div class="spacer"></div>
          <button class="btn xs" :disabled="dictPage <= 1" @click="dictPage--; loadDict()">上一页</button>
          <button class="btn xs" :disabled="dictPage * dictSize >= dictTotal" @click="dictPage++; loadDict()">下一页</button>
        </div>
      </div>
    </template>

    <!-- 新增弱口令弹窗(单条 / 批量, 每行一个) -->
    <Modal v-if="showAdd" title="新增弱口令" width="480px" @close="showAdd = false">
      <div class="alert info" style="margin-bottom:12px">
        每行一个口令, 支持一次粘贴多条。已存在的口令会被自动跳过(响应中列明), 新增条目为「自定义」类型, 可随时删除或重置。
      </div>
      <div class="field">
        <label class="label">口令列表(每行一个, 上限 500 条)</label>
        <textarea class="input mono" v-model="addText" rows="8" spellcheck="false" placeholder="mySecret1&#10;P@ssw0rd2024&#10;admin888"></textarea>
      </div>
      <div class="muted small" style="margin-top:6px">解析到 {{ addLines.length }} 条</div>
      <div class="login-err" style="text-align:left">{{ addErr }}</div>
      <template #footer>
        <button class="btn" @click="showAdd = false">取消</button>
        <button class="btn primary" :disabled="!addLines.length || adding" @click="doAdd">
          <span class="spinner" v-if="adding"></span> 添加
        </button>
      </template>
    </Modal>

    <!-- 重置确认弹窗(破坏性动作, 要求输入确认词) -->
    <Modal v-if="showReset" title="重置为默认字典" width="460px" @close="showReset = false">
      <div class="alert warn" style="margin-bottom:12px">
        将删除全部 <b>{{ dictStats.custom }}</b> 条自定义条目, 恢复内置 <b>349</b> 条常用弱口令。
        此操作不可恢复, 且会写入审计日志。
      </div>
      <div class="field">
        <label class="label">请输入"重置"以确认</label>
        <input class="input" v-model.trim="resetWord" placeholder="重置" @keyup.enter="doReset">
      </div>
      <div class="login-err" style="text-align:left">{{ resetErr }}</div>
      <template #footer>
        <button class="btn" @click="showReset = false">取消</button>
        <button class="btn danger" :disabled="resetWord !== '重置' || resetting" @click="doReset">
          <span class="spinner" v-if="resetting"></span> 确认重置
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
    err.value = '状态获取失败: ' + e.message
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
  if (!targets.length) { err.value = '没有可用的目标行(格式: host:port[:service[:user]])'; return }
  if (targets.length > 200) { err.value = '单次目标数上限 200, 当前 ' + targets.length; return }
  const body = { targets }
  if (user.value) body.user = user.value
  if (builtinOnly.value) body.builtinOnly = true
  try {
    await api('/api/authcheck/start', { method: 'POST', body })
    setRunning(true)
    await loadStatus()
  } catch (e) {
    err.value = '启动失败: ' + e.message
    // 后端返回的运行状态是权威的, 以它为准刷新本地 running
    await loadStatus()
  }
}

async function stop() {
  err.value = ''
  try {
    await api('/api/authcheck/stop', { method: 'POST' })
  } catch (e) {
    err.value = '停止失败: ' + e.message
  }
  await loadStatus()
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
    dictErr.value = '字典加载失败: ' + e.message
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
  if (!passwords.length) { addErr.value = '请输入至少一个口令'; return }
  if (passwords.length > 500) { addErr.value = '单次最多 500 条'; return }
  adding.value = true
  try {
    const d = await v2('/weakpass/dict', { method: 'POST', body: { passwords } })
    showAdd.value = false
    // 有跳过项时提示(用户以为加成功实际没进去)
    if (d.skipped && d.skipped.length) {
      addErr.value = `已添加 ${d.added} 条, 跳过重复 ${d.skipped.length} 条: ${d.skipped.join(', ')}`
    }
    await loadDict()
  } catch (e) {
    addErr.value = '添加失败: ' + e.message
  } finally {
    adding.value = false
  }
}

// 单条删除
async function removeOne(it) {
  if (!confirm(`删除弱口令「${it.password}」?`)) return
  try {
    await v2(`/weakpass/dict/${it.id}`, { method: 'DELETE' })
    dictSelected.value = dictSelected.value.filter(id => id !== it.id)
    await loadDict()
  } catch (e) {
    dictErr.value = '删除失败: ' + e.message
  }
}

// 批量删除
async function batchDelete() {
  const ids = dictSelected.value
  if (!ids.length) return
  if (!confirm(`删除选中的 ${ids.length} 条自定义弱口令?`)) return
  try {
    const d = await v2('/weakpass/dict/batch-delete', { method: 'POST', body: { ids } })
    dictSelected.value = []
    dictErr.value = d.skippedBuiltin ? `已删除 ${d.deleted} 条, 内置 ${d.skippedBuiltin} 条不可删已跳过` : ''
    await loadDict()
  } catch (e) {
    dictErr.value = '批量删除失败: ' + e.message
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
  if (resetWord.value !== '重置') { resetErr.value = '请输入"重置"'; return }
  resetting.value = true
  try {
    await v2('/weakpass/dict/reset', { method: 'POST' })
    showReset.value = false
    dictSelected.value = []
    dictPage.value = 1
    dictQ.value = ''
    await loadDict()
  } catch (e) {
    resetErr.value = '重置失败: ' + e.message
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
