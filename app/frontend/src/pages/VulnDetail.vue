<template>
  <div v-if="v">
    <PageHeader :title="v.title">
      <!-- 2026-09-27: 返回按钮 —— 优先 history.back() 回到"带 query 的精确列表 URL"
           (列表筛选条件/分页/排序状态持久化在 URL, 见 Vulns.vue); 无历史时(深链
           直接打开详情页)回退到默认列表。 -->
      <button class="btn sm" @click="goBack()">{{ t('vn.back') }}</button>
      <button class="btn sm green" v-if="vulnStatus(v.status) !== 'fixed'" @click="setStatus('fixed')">{{ t('vn.markFixed') }}</button>
      <button class="btn sm" v-else @click="setStatus('open')">{{ t('vn.reopen') }}</button>
      <button class="btn sm" v-if="!v.falsePositive" @click="showFP = true">{{ t('vn.markFP') }}</button>
      <button class="btn sm" v-else @click="clearFP">{{ t('vn.clearFP') }}</button>
      <button class="btn sm danger" @click="del">{{ t('common.del') }}</button>
      <!-- 阶段 5 联动: 本条已知漏洞 -> 渗透工作台执行验证(仅管理员) -->
      <button class="btn sm primary" v-if="admin" @click="sendToPenta">{{ t('vn.sendPentaBtn') }}</button>
    </PageHeader>

    <div class="alert" :class="v.falsePositive ? 'warn' : (v.status === 'fixed' ? 'ok' : 'info')" style="margin-bottom:14px">
      <SevTag :sev="v.severity" />
      <b style="margin-left:8px">{{ v.title }}</b>
      <span style="margin-left:10px"><StatusTag :status="vulnStatus(v.status)" /></span>
      <span v-if="v.falsePositive" style="margin-left:10px">{{ t('vn.fpLabel') }}{{ v.fpNote || t('vn.fpNoNote') }}</span>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <div class="card-title">{{ t('vn.basic') }}</div>
        <div class="kv">
          <div class="k">{{ t('vn.vulnId') }}</div><div class="v mono small">{{ v.id }}</div>
          <div class="k">CVE</div><div class="v mono">{{ v.cve || '-' }}</div>
          <div class="k">{{ t('vn.assetIp') }}</div><div class="v mono">{{ v.assetIp }}</div>
          <div class="k">{{ t('vn.port') }}</div><div class="v mono">{{ v.port || '-' }}</div>
          <div class="k">{{ t('vn.protocol') }}</div><div class="v">{{ v.protocol || '-' }}</div>
          <div class="k">{{ t('vn.riskLevel') }}</div><div class="v"><SevTag :sev="v.severity" /></div>
          <div class="k">{{ t('vn.confidence') }}</div><div class="v mono">{{ v.confidence != null ? v.confidence + ' / 100' : '-' }}</div>
          <div class="k">CVSS</div><div class="v mono">{{ v.cvss || '-' }}</div>
          <div class="k">{{ t('vn.sourceEngine') }}</div><div class="v">{{ v.source || '-' }}<span class="muted small" v-if="v.sources && v.sources.length"> ({{ v.sources.join(', ') }})</span></div>
          <div class="k">{{ t('vn.scanTask') }}</div><div class="v mono small">{{ v.scanTaskId || '-' }}</div>
          <div class="k">{{ t('vn.foundAt') }}</div><div class="v mono small">{{ fmtDT(v.foundAt) }}</div>
          <div class="k">{{ t('vn.lastSeen') }}</div><div class="v mono small">{{ fmtDT(v.lastSeenAt) }}</div>
          <div class="k">{{ t('vn.fixedAt') }}</div><div class="v mono small">{{ fmtDT(v.fixedAt) }}</div>
          <!-- 阶段 5: 渗透验证结论由渗透工作台回传, 是本页上唯一"已被实际验证过"的证据 -->
          <div class="k">{{ t('vn.pentaVerify') }}</div>
          <div class="v">
            <span class="badge" v-if="v.pentaResult" :style="expStyle(v.pentaResult)">{{ expName(v.pentaResult) }}</span>
            <span class="muted small" v-else>{{ t('vn.unverified') }}</span>
            <span class="muted small mono" v-if="v.pentaTaskId" style="margin-left:6px">{{ v.pentaTaskId }}</span>
          </div>
          <div class="k">{{ t('vn.pentaLevel') }}</div><div class="v mono small">{{ (v.pentaRiskLevel && pentaLevelName(v.pentaRiskLevel)) || t('vn.pentaLevelNone') }}</div>
          <div class="k">{{ t('vn.pentaTime') }}</div><div class="v mono small">{{ fmtDT(v.pentaVerifiedAt) }}</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">{{ t('vn.descEvidence') }}</div>
        <div class="field"><label class="label">{{ t('vn.description') }}</label>
          <div class="small" style="line-height:1.8">{{ v.description || '-' }}</div></div>
        <div class="field"><label class="label">{{ t('vn.evidence') }}</label>
          <div class="code-block" v-if="v.evidence">{{ v.evidence }}</div>
          <div class="muted small" v-else>-</div></div>
        <div class="field" v-if="v.request || v.response">
          <label class="label">{{ t('vn.reqResp') }}</label>
          <div class="code-block" v-if="v.request">{{ v.request }}</div>
          <div class="code-block" style="margin-top:8px" v-if="v.response">{{ v.response }}</div>
        </div>
        <div class="field" v-if="v.pcapFile">
          <label class="label">{{ t('vn.pcap') }}</label>
          <div class="mono small">{{ v.pcapFile }}</div>
        </div>
      </div>
    </div>

    <!-- 误报备注 -->
    <Modal v-if="showFP" :title="t('vn.fpTitle')" width="440px" @close="showFP = false">
      <div class="alert warn" style="margin-bottom:12px">
        {{ t('vn.fpHint') }}
      </div>
      <div class="field"><label class="label">{{ t('vn.fpNote') }}</label>
        <input class="input" v-model="fpNote" :placeholder="t('vn.fpNotePh')" @keyup.enter="doFP"></div>
      <div class="login-err" style="text-align:left">{{ fpErr }}</div>
      <template #footer>
        <button class="btn" @click="showFP = false">{{ t('common.cancel') }}</button>
        <button class="btn primary" :disabled="busy" @click="doFP">{{ t('vn.fpConfirm') }}</button>
      </template>
    </Modal>
  </div>
  <div v-else class="card"><Empty :text="loading ? t('vn.loading') : t('vn.notFound')" /></div>
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
import { setPageData } from '../assistant/context'
import { t } from '../i18n'

const route = useRoute()
const router = useRouter()
const v = ref(null)
// 小 Y 助手(2026-09-27): 注册"正在查看的详情项"(当前漏洞全字段, 脱敏由后端做)
setPageData('vulndetail', () => (v.value ? { vuln: v.value } : null))
const loading = ref(true)
const busy = ref(false)
const showFP = ref(false)
const fpNote = ref('')
const fpErr = ref('')
// admin 必须 computed 跟随响应式角色: 刷新快照会漏掉"发送到渗透工作台"按钮
const admin = computed(() => isAdmin())

// 阶段 5 渗透结论适配(文案与配色口径与渗透工作台保持一致)
const EXP_KEY = { exploitable: 'vn.expExploitable', partial: 'vn.expPartial', not_exploitable: 'vn.expNot' }
function expName(s) {
  return EXP_KEY[s] ? t(EXP_KEY[s]) : (s || '-')
}
function expStyle(s) {
  if (s === 'exploitable') return { color: '#fff', background: 'var(--danger,#e5484d)', borderColor: 'transparent' }
  if (s === 'partial') return { color: '#fff', background: 'var(--warning,#f0b429)', borderColor: 'transparent' }
  return { color: 'var(--muted,#8b93a7)' }
}
const SEV_KEY = { critical: 'sev.critical', high: 'sev.high', medium: 'sev.medium', low: 'sev.low', info: 'sev.info' }
function pentaLevelName(s) {
  return SEV_KEY[s] ? t(SEV_KEY[s]) : s
}
// 深链 ?import=<vulnId>: 工作台打开即预选本条漏洞, 用户点一下确认就完成导入
function sendToPenta() {
  router.push('/penta?import=' + encodeURIComponent(route.params.id))
}

// 返回漏洞列表(2026-09-27): 列表状态(筛选/分页)持久化在 URL query 上,
// back() 回到精确的列表 URL 即原样保留; 无上一条历史(深链/刷新后直开详情)
// 时退回默认列表, 不出现"按了返回没反应"。
function goBack() {
  if (window.history.state && window.history.state.back) {
    router.back()
  } else {
    router.push('/vulns')
  }
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
  if (!confirm(t('vn.delConfirm'))) return
  try {
    await v2('/vulns/' + v.value.id, { method: 'DELETE' })
    goBack() // 同"返回": 保留列表原有筛选/分页状态
  } catch (e) { alert(e.message) }
}

onMounted(load)
</script>
