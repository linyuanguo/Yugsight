<!--
  ConnectivityTest.vue 连通性测试(2026-09-28, 节点配置 → 三级叶子节点)。

  单目标(TCP/ICMP/HTTP) + 批量(每行一个地址, 可带 :port)。
  2026-09-30 用户反馈后由"前端纯模拟"改为真实探测: 服务端 POST /api/v2/node/connectivity
  实际发包(tcp 建连即断 / icmp 一次回显, 复用存活探测原始套接字 / http 一次 GET),
  状态三态与前端表格口径一致: ok=可达 / timeout=超时 / fail=不可达。
  测试结果仅保留本次会话(不持久化)。
-->
<template>
  <div>
    <PageHeader title="连通性测试" desc="探测节点设备可达性(TCP / ICMP / HTTP)">
      <span class="muted small">服务端真实发包 · ICMP 需服务以管理员运行(与存活探测同口径)</span>
    </PageHeader>

    <div class="grid cols-2">
      <div class="card">
        <div class="card-title">单目标测试</div>
        <div class="field">
          <label class="label">目标地址 (IP / 主机名) <span class="req">*</span></label>
          <input class="input mono" v-model="single.target" placeholder="172.16.199.1" />
          <div class="form-err" v-if="singleErr">{{ singleErr }}</div>
        </div>
        <div class="form-row">
          <div class="field" style="margin-bottom:0">
            <label class="label">协议</label>
            <select class="input" v-model="single.proto">
              <option value="tcp">TCP</option>
              <option value="icmp">ICMP</option>
              <option value="http">HTTP</option>
            </select>
          </div>
          <div class="field" v-if="single.proto !== 'icmp'" style="margin-bottom:0">
            <label class="label">端口</label>
            <input class="input mono" type="number" min="1" max="65535" v-model.number="single.port" />
          </div>
          <div class="field" style="margin-bottom:0">
            <label class="label">超时 (ms)</label>
            <input class="input mono" type="number" min="100" max="10000" step="100" v-model.number="single.timeout" />
          </div>
        </div>
        <div class="form-actions" style="justify-content:flex-start">
          <button class="btn primary" :disabled="single.running" @click="runSingle">
            <span class="spinner" v-if="single.running"></span>
            {{ single.running ? '测试中…' : '开始测试' }}
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">批量测试 <span class="sub">每行一个地址, 可带 :port</span></div>
        <div class="field">
          <textarea class="textarea" v-model="batchText"
            placeholder="172.16.199.1:161&#10;172.16.101.222:3389&#10;core-sw.example.com"></textarea>
        </div>
        <div class="form-actions" style="justify-content:flex-start">
          <button class="btn" :disabled="batchRunning" @click="runBatch">
            <span class="spinner" v-if="batchRunning"></span>
            {{ batchRunning ? '测试中…' : '批量测试' }}
          </button>
          <span class="muted small" v-if="batchRunning">{{ batchDone }} / {{ batchTotal }}</span>
        </div>
      </div>
    </div>

    <!-- 路由跟踪(2026-09-30: tracert/端口跟踪, 服务端真实逐跳; ping 与端口两种) -->
    <div class="card">
      <div class="card-title">
        路由跟踪 (tracert)
        <span class="sub">Ping 模式 = 逐跳跟踪; 端口模式 = 逐跳(ICMP) + 目标端口最小跳数(TCP 探测)</span>
      </div>
      <div class="field">
        <label class="label">目标地址 (IP / 主机名) <span class="req">*</span></label>
        <input class="input mono" v-model="trace.target" placeholder="172.16.199.1" />
      </div>
      <div class="form-row">
        <div class="field" style="margin-bottom:0">
          <label class="label">模式</label>
          <select class="input" v-model="trace.mode">
            <option value="icmp">Ping (ICMP)</option>
            <option value="port">端口 (TCP)</option>
          </select>
        </div>
        <div class="field" v-if="trace.mode === 'port'" style="margin-bottom:0">
          <label class="label">端口</label>
          <input class="input mono" type="number" min="1" max="65535" v-model.number="trace.port" />
        </div>
        <div class="field" style="margin-bottom:0">
          <label class="label">最大跳数</label>
          <input class="input mono" type="number" min="1" max="30" v-model.number="trace.maxHops" />
        </div>
        <div class="field" style="margin-bottom:0">
          <label class="label">每跳超时 (ms)</label>
          <input class="input mono" type="number" min="200" max="3000" step="100" v-model.number="trace.perHopMs" />
        </div>
      </div>
      <div class="form-actions" style="justify-content:flex-start">
        <button class="btn primary" :disabled="trace.running" @click="runTrace">
          <span class="spinner" v-if="trace.running"></span>
          {{ trace.running ? '跟踪中…' : '开始跟踪' }}
        </button>
        <span class="form-err" v-if="traceErr">{{ traceErr }}</span>
      </div>

      <div v-if="trace.result" class="trace-result">
        <div class="trace-summary">
          <span class="mono">{{ trace.result.target }} → {{ trace.result.resolved }}</span>
          <span class="chip" :class="trace.result.reached ? 'on' : 'off'">{{ trace.result.reached ? '可达' : '不可达' }}</span>
          <span class="chip" v-if="trace.result.port"
                :class="trace.result.portState === 'open' ? 'on' : trace.result.portState === 'closed' ? 'warn' : 'off'">
            端口 {{ trace.result.port }}: {{ portStateLabel(trace.result.portState) }}
          </span>
          <span class="chip" v-if="trace.result.port && trace.result.hopsNeeded">{{ trace.result.hopsNeeded }} 跳</span>
          <span class="muted small">{{ trace.result.elapsedMs }}ms</span>
        </div>
        <div class="muted small" v-if="trace.result.note">{{ trace.result.note }}</div>
        <table class="table">
          <thead>
            <tr><th style="width:64px">跳数</th><th>IP</th><th style="width:100px">延迟</th></tr>
          </thead>
          <tbody>
            <tr v-for="h in displayHops" :key="h.hop">
              <td class="mono">{{ h.hop }}</td>
              <td class="mono" :class="{ muted: h.kind !== 'icmp' }">
                <template v-if="h.kind === 'gap'">(未回应)</template>
                <template v-else-if="h.kind === 'probe'">目标端口响应 (TCP 探测)</template>
                <template v-else>{{ h.ip || '*' }}</template>
              </td>
              <td class="mono">{{ h.rttMs >= 0 ? h.rttMs + 'ms' : '*' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="muted small" v-else-if="!trace.running && !traceErr">
        提示: Windows 内核不支持逐跳走端口(tcptraceroute 方式, 原始 TCP 套接字被系统禁止),
        端口模式的逐跳列表按同一路径用 ICMP 实测, "N 跳"由 TCP 端口探测确定; Ping 模式为完整逐跳跟踪。
        ICMP 跟踪需服务以管理员运行(与存活探测同口径)。
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        测试结果
        <span class="sub">{{ results.length }} 条(本次会话)</span>
        <div class="spacer"></div>
        <button class="btn xs" :disabled="!results.length" @click="results = []">清空</button>
      </div>
      <div v-if="!results.length" class="empty">
        暂无测试记录。在上方填入目标后开始测试。
      </div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>目标</th><th>协议</th><th>端口</th><th>状态</th>
              <th>延迟</th><th>详情</th><th>测试时间</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in results" :key="r.id">
              <td class="mono">{{ r.target }}</td>
              <td><span class="chip">{{ r.proto.toUpperCase() }}</span></td>
              <td class="mono">{{ r.port || '-' }}</td>
              <td>
                <span class="chip" :class="r.status === 'ok' ? 'on' : r.status === 'timeout' ? 'warn' : 'off'">
                  {{ r.status === 'ok' ? '可达' : r.status === 'timeout' ? '超时' : '不可达' }}
                </span>
              </td>
              <td class="mono">{{ r.status === 'ok' ? r.latency + 'ms' : '-' }}</td>
              <td class="muted small">{{ r.detail }}</td>
              <td class="mono small muted">{{ fmtDT(r.at) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import { fmtDT } from '../../utils'
import { uid } from '../../utils/nodepush'
import { v2 } from '../../api/http'

// ===== 单目标 =====
const single = reactive({
  target: '', proto: 'tcp', port: 161, timeout: 3000, running: false
})
const singleErr = ref('')

function validateSingle() {
  const t = single.target.trim()
  if (!t) { singleErr.value = '目标地址必填'; return null }
  if (single.proto !== 'icmp' && (!Number.isFinite(single.port) || single.port < 1 || single.port > 65535)) {
    singleErr.value = '端口需在 1 - 65535 之间'
    return null
  }
  if (!Number.isFinite(single.timeout) || single.timeout < 100 || single.timeout > 10000) {
    singleErr.value = '超时需在 100 - 10000 ms 之间'
    return null
  }
  singleErr.value = ''
  return t
}

async function runSingle() {
  const t = validateSingle()
  if (!t) return
  single.running = true
  const r = await runProbe(t, single.proto, single.port, single.timeout)
  pushResult({ ...r, target: t, proto: single.proto, port: single.proto === 'icmp' ? '' : single.port })
  single.running = false
}

// ===== 批量 =====
const batchText = ref('')
const batchRunning = ref(false)
const batchDone = ref(0)
const batchTotal = ref(0)

function parseBatchLines() {
  return batchText.value
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'))
}

async function runBatch() {
  const lines = parseBatchLines()
  if (!lines.length) return
  batchRunning.value = true
  batchTotal.value = lines.length
  batchDone.value = 0
  for (const line of lines) {
    // "host:port" 拆分; ICMP 忽略端口
    let host = line
    let port = 161
    const i = line.lastIndexOf(':')
    if (i > 0 && /^\d{1,5}$/.test(line.slice(i + 1))) {
      host = line.slice(0, i)
      port = Number(line.slice(i + 1))
    }
    const proto = 'tcp'
    const r = await runProbe(host, proto, port, single.timeout)
    pushResult({ ...r, target: host, proto, port })
    batchDone.value++
    await new Promise(res => setTimeout(res, 120))   // 逐个执行, 进度可见
  }
  batchRunning.value = false
}

// ===== 结果 =====
const results = ref([])
function pushResult(r) {
  results.value.unshift({
    id: uid('ct'),
    at: new Date().toISOString(),
    ...r
  })
  if (results.value.length > 50) results.value = results.value.slice(0, 50)
}

// ===== 真实探测(2026-09-30 由本地模拟改为服务端真实发包) =====
// POST /api/v2/node/connectivity: 服务端 tcp 建连即断 / icmp 一次回显 / http 一次 GET。
// 返回 { status: 'ok'|'timeout'|'fail', latencyMs, detail }。
// 请求本身失败(如未登录/后端不可达)按"不可达"展示并带原因, 不让整页报错。
async function probe(target, proto, port, timeout) {
  const d = await v2('/node/connectivity', {
    method: 'POST',
    body: { target, proto, port: proto === 'icmp' ? 0 : port, timeoutMs: timeout }
  })
  return {
    status: d.status || 'fail',
    latency: Number(d.latencyMs) || 0,
    detail: d.detail || ''
  }
}

// 单目标统一执行: 真实探测, 请求异常降级为 fail 行(不抛)
async function runProbe(target, proto, port, timeout) {
  try {
    return await probe(target, proto, port, timeout)
  } catch (e) {
    return { status: 'fail', latency: 0, detail: '探测请求失败: ' + e.message }
  }
}

// ===== 路由跟踪(2026-09-30: 服务端真实逐跳, ping/端口两种) =====
const trace = reactive({
  target: '', mode: 'icmp', port: 161, maxHops: 15, perHopMs: 1000,
  running: false, result: null
})
const traceErr = ref('')

async function runTrace() {
  const t = trace.target.trim()
  if (!t) { traceErr.value = '目标地址必填'; return }
  if (trace.mode === 'port' && (!Number.isFinite(trace.port) || trace.port < 1 || trace.port > 65535)) {
    traceErr.value = '端口需在 1 - 65535 之间'
    return
  }
  if (!Number.isFinite(trace.maxHops) || trace.maxHops < 1 || trace.maxHops > 30) {
    traceErr.value = '最大跳数需在 1 - 30 之间'
    return
  }
  traceErr.value = ''
  trace.running = true
  try {
    trace.result = await v2('/node/trace', {
      method: 'POST',
      body: {
        target: t,
        mode: trace.mode,
        port: trace.mode === 'port' ? trace.port : 0,
        maxHops: trace.maxHops,
        perHopMs: trace.perHopMs
      }
    })
  } catch (e) {
    traceErr.value = e.message
  } finally {
    trace.running = false
  }
}

// 2026-10-01: 端口模式下 ICMP 逐跳列表常因"连续 3 跳无回应"提前截断(表里只有 5 行),
// 而顶部"10 跳"来自 TCP 端口探测(hopsNeeded) —— 两行数字对不上。把截断缺口补齐:
//   hops.length+1 ~ hopsNeeded-1 = "(未回应)"占位(这些跳 ICMP 根本没探到);
//   第 hopsNeeded 跳 = "目标端口响应(TCP 探测)"。ICMP 模式 / 未截断时原样返回。
const displayHops = computed(() => {
  const r = trace.result
  if (!r) return []
  const base = (r.hops || []).map(h => ({ hop: h.hop, ip: h.ip || '', rttMs: h.rttMs, kind: 'icmp' }))
  if (r.port > 0 && r.hopsNeeded > 0 && r.hopsNeeded > base.length) {
    for (let h = base.length + 1; h < r.hopsNeeded; h++) {
      base.push({ hop: h, ip: '', rttMs: -1, kind: 'gap' })
    }
    base.push({ hop: r.hopsNeeded, ip: '', rttMs: -1, kind: 'probe' })
  }
  return base
})

function portStateLabel(s) {
  return s === 'open' ? '开放' : s === 'closed' ? '关闭' : s === 'timeout' ? '超时' : (s || '-')
}
</script>

<style scoped>
.req { color: var(--red); }
.form-err { color: var(--red); font-size: 12px; margin-top: 4px; margin-left: 10px; }
/* 路由跟踪结果 */
.trace-result { margin-top: 14px; }
.trace-summary { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.trace-summary .mono { font-size: 13px; }
</style>
