<template>
  <div v-if="v">
    <PageHeader :title="v.title">
      <button class="btn sm" @click="$router.push('/vulns')">返回列表</button>
      <button class="btn sm green" v-if="vulnStatus(v.status) !== 'fixed'" @click="setStatus('fixed')">标记已修复</button>
      <button class="btn sm" v-else @click="setStatus('open')">恢复为开放</button>
      <button class="btn sm" v-if="!v.falsePositive" @click="showFP = true">标记误报</button>
      <button class="btn sm" v-else @click="clearFP">取消误报</button>
      <button class="btn sm danger" @click="del">删除</button>
      <!-- 阶段 5 联动: 本条已知漏洞 -> 渗透工作台执行验证(仅管理员) -->
      <button class="btn sm primary" v-if="admin" @click="sendToPenta">发送到渗透工作台</button>
    </PageHeader>

    <div class="alert" :class="v.falsePositive ? 'warn' : (v.status === 'fixed' ? 'ok' : 'info')" style="margin-bottom:14px">
      <SevTag :sev="v.severity" />
      <b style="margin-left:8px">{{ v.title }}</b>
      <span style="margin-left:10px"><StatusTag :status="vulnStatus(v.status)" /></span>
      <span v-if="v.falsePositive" style="margin-left:10px">误报标记: {{ v.fpNote || '(无备注)' }}</span>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <div class="card-title">基本信息</div>
        <div class="kv">
          <div class="k">漏洞 ID</div><div class="v mono small">{{ v.id }}</div>
          <div class="k">CVE</div><div class="v mono">{{ v.cve || '-' }}</div>
          <div class="k">资产 IP</div><div class="v mono">{{ v.assetIp }}</div>
          <div class="k">端口</div><div class="v mono">{{ v.port || '-' }}</div>
          <div class="k">协议</div><div class="v">{{ v.protocol || '-' }}</div>
          <div class="k">风险等级</div><div class="v"><SevTag :sev="v.severity" /></div>
          <div class="k">置信度</div><div class="v mono">{{ v.confidence != null ? v.confidence + ' / 100' : '-' }}</div>
          <div class="k">CVSS</div><div class="v mono">{{ v.cvss || '-' }}</div>
          <div class="k">来源引擎</div><div class="v">{{ v.source || '-' }}<span class="muted small" v-if="v.sources && v.sources.length"> ({{ v.sources.join(', ') }})</span></div>
          <div class="k">扫描任务</div><div class="v mono small">{{ v.scanTaskId || '-' }}</div>
          <div class="k">发现时间</div><div class="v mono small">{{ fmtDT(v.foundAt) }}</div>
          <div class="k">最后确认</div><div class="v mono small">{{ fmtDT(v.lastSeenAt) }}</div>
          <div class="k">修复时间</div><div class="v mono small">{{ fmtDT(v.fixedAt) }}</div>
          <!-- 阶段 5: 渗透验证结论由渗透工作台回传, 是本页上唯一"已被实际验证过"的证据 -->
          <div class="k">渗透验证</div>
          <div class="v">
            <span class="badge" v-if="v.pentaResult" :style="expStyle(v.pentaResult)">{{ expName(v.pentaResult) }}</span>
            <span class="muted small" v-else>未验证</span>
            <span class="muted small mono" v-if="v.pentaTaskId" style="margin-left:6px">{{ v.pentaTaskId }}</span>
          </div>
          <div class="k">验证后定级</div><div class="v mono small">{{ (v.pentaRiskLevel && pentaLevelName(v.pentaRiskLevel)) || '未修正（沿用扫描定级）' }}</div>
          <div class="k">回传时间</div><div class="v mono small">{{ fmtDT(v.pentaVerifiedAt) }}</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">描述与证据</div>
        <div class="field"><label class="label">描述</label>
          <div class="small" style="line-height:1.8">{{ v.description || '-' }}</div></div>
        <div class="field"><label class="label">验证证据</label>
          <div class="code-block" v-if="v.evidence">{{ v.evidence }}</div>
          <div class="muted small" v-else>-</div></div>
        <div class="field" v-if="v.request || v.response">
          <label class="label">原始请求 / 响应</label>
          <div class="code-block" v-if="v.request">{{ v.request }}</div>
          <div class="code-block" style="margin-top:8px" v-if="v.response">{{ v.response }}</div>
        </div>
        <div class="field" v-if="v.pcapFile">
          <label class="label">PCAP 证据附件</label>
          <div class="mono small">{{ v.pcapFile }}</div>
        </div>
      </div>
    </div>

    <!-- 误报备注 -->
    <Modal v-if="showFP" title="标记为误报" width="440px" @close="showFP = false">
      <div class="alert warn" style="margin-bottom:12px">
        标记后同资产+同 CVE 将被自动识别, 报告中自动排除。
      </div>
      <div class="field"><label class="label">备注(可选)</label>
        <input class="input" v-model="fpNote" placeholder="如: 内网测试环境, 风险可控" @keyup.enter="doFP"></div>
      <div class="login-err" style="text-align:left">{{ fpErr }}</div>
      <template #footer>
        <button class="btn" @click="showFP = false">取消</button>
        <button class="btn primary" :disabled="busy" @click="doFP">确认标记</button>
      </template>
    </Modal>
  </div>
  <div v-else class="card"><Empty :text="loading ? '加载中...' : '漏洞不存在或已删除'" /></div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import SevTag from '../components/SevTag.vue'
import StatusTag from '../components/StatusTag.vue'
import Modal from '../components/Modal.vue'
import Empty from '../components/Empty.vue'
import { v2 } from '../api/http'
import { fmtDT, vulnStatus } from '../utils'
import { isAdmin } from '../auth'

const route = useRoute()
const router = useRouter()
const v = ref(null)
const loading = ref(true)
const busy = ref(false)
const showFP = ref(false)
const fpNote = ref('')
const fpErr = ref('')
// admin 必须 computed 跟随响应式角色: 刷新快照会漏掉"发送到渗透工作台"按钮
const admin = computed(() => isAdmin())

// 阶段 5 渗透结论适配(文案与配色口径与渗透工作台保持一致)
function expName(s) {
  return { exploitable: '可利用', partial: '部分利用', not_exploitable: '不可利用' }[s] || s || '-'
}
function expStyle(s) {
  if (s === 'exploitable') return { color: '#fff', background: 'var(--danger,#e5484d)', borderColor: 'transparent' }
  if (s === 'partial') return { color: '#fff', background: 'var(--warning,#f0b429)', borderColor: 'transparent' }
  return { color: 'var(--muted,#8b93a7)' }
}
function pentaLevelName(s) {
  return { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }[s] || s
}
// 深链 ?import=<vulnId>: 工作台打开即预选本条漏洞, 用户点一下确认就完成导入
function sendToPenta() {
  router.push('/penta?import=' + encodeURIComponent(route.params.id))
}

async function load() {
  loading.value = true
  try {
    v.value = await v2('/vulns/' + route.params.id)
  } catch (e) {
    v.value = null
  } finally { loading.value = false }
}

async function setStatus(status) {
  try {
    v.value = await v2('/vulns/' + v.value.id, { method: 'PUT', body: { status } })
  } catch (e) { alert(e.message) }
}

async function doFP() {
  fpErr.value = ''
  busy.value = true
  try {
    await v2('/vulns/' + v.value.id, {
      method: 'PUT',
      body: { falsePositive: true, fpNote: fpNote.value }
    })
    // 同步沉淀到扫描管控误报规则(同资产+同CVE 后续自动标记)
    try {
      const { api } = await import('../api/http')
      await api('/api/vuln/fps/mark', {
        method: 'POST',
        body: { assetIp: v.value.assetIp, cve: v.value.cve || '', title: v.value.title, note: fpNote.value }
      })
    } catch (e) { /* 管控规则失败不影响本条标记 */ }
    showFP.value = false
    await load()
  } catch (e) { fpErr.value = e.message } finally { busy.value = false }
}

async function clearFP() {
  try {
    v.value = await v2('/vulns/' + v.value.id, { method: 'PUT', body: { falsePositive: false } })
  } catch (e) { alert(e.message) }
}

async function del() {
  if (!confirm('确认删除该漏洞记录?')) return
  try {
    await v2('/vulns/' + v.value.id, { method: 'DELETE' })
    router.push('/vulns')
  } catch (e) { alert(e.message) }
}

onMounted(load)
</script>
