<script setup>
// AICfg AI 配置页(阶段 3, 系统配置分组, 路由 /settings/ai)。
//
// 四大板块(与后端 ai 包/settings.json ai 节一一对应):
//   1. AI 接口基础配置 —— API 地址/Key/模型/超时/上下文/温度/核采样 +
//      连通性测试 + 三大业务模块总开关;
//   2. Prompt 模板管理 —— 三套预设(流量/漏洞/监控), 高亮编辑器 +
//      RAG 绑定开关, 保存/恢复默认;
//   3. RAG 非结构化知识库(文档库) —— 文档上传/分片/向量化/启用禁用 +
//      检索预览;
//   4. 结构化记忆库 —— 与 RAG 严格区分: RAG 查"上传的文档", 记忆库
//      查"平台数据库里的结构化历史", 检索结果注入 {{structured_memory}}。
//
// 边界(用户口径): 本页只管配置 —— AI 分析触发按钮保留在各业务页面
// (实时抓包/扫描作业/弱口令/节点监控), 不在本页触发分析。
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '../api/http'
import { fmtDT } from '../utils'
import { t } from '../i18n'
import PageHeader from '../components/PageHeader.vue'
import AiPromptEditor from '../components/AiPromptEditor.vue'

// 2026-09-26 AI 配置并入授权管理: embedded=true 时隐藏自身 PageHeader(由父页统一管理标题)
const props = defineProps({ embedded: { type: Boolean, default: false } })

const tab = ref('api')
const st = ref(null) // /api/ai 全量状态
const msg = ref('')
const err = ref('')
function say(ok, text) {
  err.value = ok ? '' : text
  msg.value = ok ? text : ''
  setTimeout(() => (msg.value = ''), 4000)
}

async function loadStatus() {
  try {
    st.value = await api('/api/ai')
  } catch {
    st.value = null
  }
}
// ===== 板块 1: 基础配置 =====
const basic = reactive({
  apiBase: '', apiKey: '', model: '',
  timeoutSec: 60, maxContext: 32000, maxTokens: 4096,
  temperature: 0.2, topP: 0.9
})
const modules = reactive({ capture: true, scan: true, monitor: true })
const showKey = ref(false)
const testing = ref(false)
const testInfo = ref('')

function fillFromStatus() {
  if (!st.value) return
  basic.apiBase = st.value.apiBase || ''
  basic.apiKey = st.value.apiKey || ''
  basic.model = st.value.model || ''
  basic.timeoutSec = st.value.timeoutSec || 60
  basic.maxContext = st.value.maxContext || 32000
  basic.maxTokens = st.value.maxTokens || 4096
  basic.temperature = st.value.temperature ?? 0.2
  basic.topP = st.value.topP ?? 0.9
  if (st.value.modules) {
    modules.capture = !!st.value.modules.capture
    modules.scan = !!st.value.modules.scan
    modules.monitor = !!st.value.modules.monitor
  }
}

onMounted(async () => {
  await loadStatus()
  fillFromStatus() // 状态就绪后再回填表单(单入口, 避免两个 onMounted 竞态)
  await loadAssistant() // 小 Y 配置(2026-09-27)
  await loadTemplates()
  await loadRAG()
  await loadMemory()
})

async function saveBasic() {
  try {
    await api('/api/ai/config', {
      method: 'POST',
      body: JSON.stringify({
        apiBase: basic.apiBase, apiKey: basic.apiKey, model: basic.model,
        enabled: true,
        timeoutSec: +basic.timeoutSec, maxContext: +basic.maxContext,
        maxTokens: +basic.maxTokens, temperature: +basic.temperature, topP: +basic.topP
      })
    })
    say(true, t('aic.saveBasicOk'))
    await loadStatus()
  } catch (e) { say(false, e.message) }
}

async function saveModules() {
  try {
    await api('/api/ai/config', {
      method: 'POST',
      body: JSON.stringify({ modules: { ...modules } })
    })
    say(true, t('aic.saveModulesOk'))
    await loadStatus()
  } catch (e) { say(false, e.message) }
}

// 测试连通: 只验证地址/Key/模型是否可达, 不落盘(落盘交给"保存"按钮)。
// 后端 /api/ai/test 返回 {ok, error, models, modelMsg} —— 直接读顶层 ok 即可判定。
async function testConn() {
  testing.value = true
  testInfo.value = ''
  try {
    const d = await api('/api/ai/test', {
      method: 'POST',
      body: JSON.stringify({
        apiBase: basic.apiBase, apiKey: basic.apiKey, model: basic.model
      })
    })
    if (d.ok) {
      const samples = (d.models && d.models.length)
        ? t('aic.modelSamples', { x: d.models.slice(0, 5).join(', ') + (d.models.length > 5 ? '…' : '') })
        : ''
      testInfo.value = t('aic.connOk', { x: samples })
      if (d.modelMsg) testInfo.value += t('aic.modelMsgWrap', { x: d.modelMsg })
    } else {
      testInfo.value = t('aic.connFail', { x: d.error || t('aic.unknownErr') })
    }
    say(!!d.ok, testInfo.value)
  } catch (e) {
    say(false, e.message)
  } finally {
    testing.value = false
  }
}

// ===== 小 Y 助手(2026-09-27): 配置项自上而下 = ①总开关 ②模型基础配置 ③系统提示词 =====
//
// 模型地址/Key/模型名称与下方"AI 接口"卡共用同一数据源(basic.*), 小 Y 卡内
// 编辑后随"保存小 Y 配置"一并落盘 —— 不做第二套模型配置(会漂移)。
// prompt 回显的是"生效提示词"(自定义或内置默认), 编辑保存后即成为自定义;
// "恢复默认"= 提交空串, 后端回退内置默认 PROMPT。
const assistant = reactive({ enabled: false, prompt: '' })
const assistantSaving = ref(false)
const assistantInfo = ref(null) // /api/v1/ai/assistant 状态(effective/hasCustomPrompt)
const assistantEff = computed(() => !!(assistantInfo.value && assistantInfo.value.effective))

async function loadAssistant() {
  try {
    const d = await api('/api/v1/ai/assistant')
    assistant.enabled = !!d.enabled
    assistant.prompt = d.prompt || ''
    assistantInfo.value = d
  } catch {
    assistantInfo.value = null
  }
}

// 保存小 Y 配置(总开关 + PROMPT + 模型三字段, 即时生效无需重启)
async function saveAssistant() {
  assistantSaving.value = true
  try {
    await api('/api/v1/ai/assistant', {
      method: 'POST',
      body: JSON.stringify({
        enabled: assistant.enabled,
        prompt: assistant.prompt,
        apiBase: basic.apiBase,
        apiKey: basic.apiKey,
        model: basic.model
      })
    })
    say(true, assistant.enabled ? t('aic.assistOn') : t('aic.assistOff'))
    await Promise.all([loadAssistant(), loadStatus()])
  } catch (e) {
    say(false, e.message)
  } finally {
    assistantSaving.value = false
  }
}

// 恢复默认 PROMPT: 提交空串 = 后端回退内置默认
async function resetAssistantPrompt() {
  if (!confirm(t('aic.resetPromptConfirm'))) return
  assistant.prompt = ''
  assistantSaving.value = true
  try {
    await api('/api/v1/ai/assistant', {
      method: 'POST',
      body: JSON.stringify({ prompt: '' })
    })
    say(true, t('aic.resetPromptOk'))
    await loadAssistant()
  } catch (e) {
    say(false, e.message)
  } finally {
    assistantSaving.value = false
  }
}

// ===== 板块 2: Prompt 模板 =====
const tplVars = ref([])
const tpls = reactive({}) // key → {label,name,content,rag,topK}
const tplBusy = ref({})

async function loadTemplates() {
  try {
    const d = await api('/api/ai/templates')
    tplVars.value = d.vars || []
    for (const t of d.templates || []) {
      tpls[t.key] = { ...t }
    }
  } catch (e) { say(false, t('aic.tplLoadFail', { err: e.message })) }
}

async function saveTpl(key) {
  const p = tpls[key]
  tplBusy.value[key] = true
  try {
    await api('/api/ai/templates', {
      method: 'POST',
      body: JSON.stringify({ key, name: p.name, content: p.content, rag: p.rag, topK: +p.topK })
    })
    say(true, t('aic.tplSaved', { x: p.label }))
  } catch (e) { say(false, e.message) } finally {
    tplBusy.value[key] = false
  }
}

async function resetTpl(key) {
  if (!confirm(t('aic.tplResetConfirm', { x: tpls[key].label }))) return
  try {
    await api('/api/ai/templates/reset', { method: 'POST', body: JSON.stringify({ key }) })
    say(true, t('aic.tplResetOk'))
    await loadTemplates()
  } catch (e) { say(false, e.message) }
}

// ===== 板块 3: RAG 文档库 =====
const rag = reactive({ enabled: true, topK: 3, chunkSize: 800 })
const ragDocs = ref([])
const ragBusy = ref(false)
const up = reactive({ name: '', category: '安全基线', content: '' })
// 分类是落库数据值(中文存库, 与存量文档一致), 显示走词条映射, 未匹配原样
const categories = ['安全基线', '漏洞手册', '设备资料', '运维文档', '其它']
const CAT_KEY = { 安全基线: 'aic.cat1', 漏洞手册: 'aic.cat2', 设备资料: 'aic.cat3', 运维文档: 'aic.cat4', 其它: 'aic.cat5' }
function aicCat(c) { return CAT_KEY[c] ? t(CAT_KEY[c]) : c }
const searchQ = ref('')
const searchHits = ref(null)
const searchMode = ref('') // 检索预览回带的实际模式(vector/keyword)

// 向量检索组件(可选插拔, 默认关): embedding=向量化, reranker=重排序。
// 开关关闭 → 对应字段置灰不可编辑; 未启用不初始化/不占资源。
const emb = reactive({ enabled: false, apiBase: '', apiKey: '', model: '', batchSize: 32, dimension: 1024 })
const rr = reactive({ enabled: false, apiBase: '', apiKey: '', model: '', topN: 5 })
const embShowKey = ref(false)
const rrShowKey = ref(false)

async function loadRAG() {
  try {
    const d = await api('/api/ai/rag')
    rag.enabled = !!d.enabled
    rag.topK = d.topK || 3
    rag.chunkSize = d.chunkSize || 800
    ragDocs.value = d.docs || []
    if (d.embedding) {
      emb.enabled = !!d.embedding.enabled
      emb.apiBase = d.embedding.apiBase || ''
      emb.apiKey = d.embedding.apiKey || ''
      emb.model = d.embedding.model || ''
      emb.batchSize = d.embedding.batchSize || 32
      emb.dimension = d.embedding.dimension || 1024
    }
    if (d.reranker) {
      rr.enabled = !!d.reranker.enabled
      rr.apiBase = d.reranker.apiBase || ''
      rr.apiKey = d.reranker.apiKey || ''
      rr.model = d.reranker.model || ''
      rr.topN = d.reranker.topN || 5
    }
  } catch (e) { say(false, t('aic.ragLoadFail', { err: e.message })) }
}

async function saveRagCfg() {
  try {
    await api('/api/ai/rag/config', {
      method: 'POST',
      body: JSON.stringify({ enabled: rag.enabled, topK: +rag.topK, chunkSize: +rag.chunkSize })
    })
    say(true, t('aic.ragSaved'))
    await loadRAG()
  } catch (e) { say(false, e.message) }
}

// 保存 Embedding 配置(开启后后台向量化文档; 缺地址/模型 → 检索时自动降级关键词)
async function saveEmb() {
  try {
    await api('/api/ai/rag/config', {
      method: 'POST',
      body: JSON.stringify({
        embedding: {
          enabled: emb.enabled, apiBase: emb.apiBase, apiKey: emb.apiKey,
          model: emb.model, batchSize: +emb.batchSize, dimension: +emb.dimension
        }
      })
    })
    say(true, emb.enabled ? t('aic.embOn') : t('aic.embOff'))
    await loadRAG()
  } catch (e) { say(false, e.message) }
}

// 保存 Reranker 配置(关闭 = 直接返回初筛 TopN)
async function saveRR() {
  try {
    await api('/api/ai/rag/config', {
      method: 'POST',
      body: JSON.stringify({
        reranker: {
          enabled: rr.enabled, apiBase: rr.apiBase, apiKey: rr.apiKey,
          model: rr.model, topN: +rr.topN
        }
      })
    })
    say(true, rr.enabled ? t('aic.rrOn') : t('aic.rrOff'))
    await loadRAG()
  } catch (e) { say(false, e.message) }
}

function onFilePick(e) {
  const f = e.target.files && e.target.files[0]
  if (!f) return
  if (f.size > 2 * 1024 * 1024) { say(false, t('aic.fileTooBig')); return }
  const reader = new FileReader()
  reader.onload = () => {
    up.content = String(reader.result || '')
    if (!up.name) up.name = f.name
  }
  reader.onerror = () => say(false, t('aic.fileReadFail'))
  reader.readAsText(f)
  e.target.value = ''
}

async function uploadDoc() {
  ragBusy.value = true
  try {
    await api('/api/ai/rag/docs', {
      method: 'POST',
      body: JSON.stringify({ name: up.name, category: up.category, content: up.content })
    })
    say(true, t('aic.docUploaded'))
    up.name = ''; up.content = ''
    await loadRAG()
  } catch (e) { say(false, e.message) } finally {
    ragBusy.value = false
  }
}

async function toggleDoc(id) {
  try {
    await api('/api/ai/rag/docs/' + id + '/toggle', { method: 'POST' })
    await loadRAG()
  } catch (e) { say(false, e.message) }
}

async function delDoc(id) {
  if (!confirm(t('aic.delDocConfirm'))) return
  try {
    await api('/api/ai/rag/docs/' + id, { method: 'DELETE' })
    say(true, t('aic.docDeleted'))
    await loadRAG()
  } catch (e) { say(false, e.message) }
}

async function doSearch() {
  if (!searchQ.value.trim()) return
  try {
    const d = await api('/api/ai/rag/search?q=' + encodeURIComponent(searchQ.value))
    searchHits.value = d.hits || []
    searchMode.value = d.mode || ''
  } catch (e) { say(false, e.message) }
}

// ===== 板块 4: 结构化记忆库 =====
const mem = reactive({
  enabled: true, retainDays: 30, maxItems: 20, compress: true,
  scopes: { assets: true, alerts: true, captures: true, metrics: true }
})
async function loadMemory() {
  try {
    const d = await api('/api/ai/memory')
    const c = d.config || {}
    mem.enabled = !!c.enabled
    mem.retainDays = c.retainDays || 30
    mem.maxItems = c.maxItems || 20
    mem.compress = c.compress !== false
    if (c.scopes) mem.scopes = { ...c.scopes }
  } catch (e) { say(false, t('aic.memLoadFail', { err: e.message })) }
}

// 模板里直接写 {{ '{{var}}' }} 会被 Vue 解析器在 }} 处截断(既有坑),
// 用函数拼出变量全名, 插值里不出现字面 }}
function vbrace(name) {
  return '{{' + name + '}}'
}

async function saveMem() {
  try {
    await api('/api/ai/memory', {
      method: 'POST',
      body: JSON.stringify({
        enabled: mem.enabled, retainDays: +mem.retainDays,
        maxItems: +mem.maxItems, compress: mem.compress, scopes: { ...mem.scopes }
      })
    })
    say(true, t('aic.memSaved'))
    await loadStatus()
  } catch (e) { say(false, e.message) }
}
</script>

<template>
  <div>
    <PageHeader v-if="!props.embedded" :title="t('aic.title')" :desc="t('aic.desc')">
      <div class="chip" :class="st && st.enabled ? 'on' : 'off'">
        {{ st && st.enabled ? t('aic.enabled') : t('aic.disabled') }}
      </div>
      <span class="muted small mono" v-if="st && st.model">{{ st.backend }} · {{ st.model }}</span>
      <span class="muted small" v-if="msg" style="color:var(--ok,#4cb782)">{{ msg }}</span>
      <span class="muted small" v-if="err" style="color:var(--danger,#e5484d)">{{ err }}</span>
      <button class="btn sm" @click="loadStatus">{{ t('common.refresh') }}</button>
    </PageHeader>

    <div class="tabs" style="margin-bottom:14px">
      <div class="tab" :class="{ active: tab === 'api' }" @click="tab = 'api'">{{ t('aic.tabApi') }}</div>
      <div class="tab" :class="{ active: tab === 'tpl' }" @click="tab = 'tpl'">{{ t('aic.tabTpl') }}</div>
      <div class="tab" :class="{ active: tab === 'rag' }" @click="tab = 'rag'">{{ t('aic.tabRag') }}</div>
      <div class="tab" :class="{ active: tab === 'mem' }" @click="tab = 'mem'">{{ t('aic.tabMem') }}</div>
    </div>

    <!-- ① 接口基础配置 -->
    <div v-if="tab === 'api'">
      <!-- 小 Y 助手(2026-09-27): 配置项自上而下 = ①总开关 ②模型基础配置 ③系统提示词(PROMPT) -->
      <div class="card">
        <div class="card-title">
          {{ t('aic.assistTitle') }}
          <span class="sub">{{ t('aic.assistSub') }}</span>
          <div class="spacer"></div>
          <span class="chip" :class="assistantEff ? 'on' : 'off'">{{ assistantEff ? t('aic.assistOnChip') : t('aic.assistOffChip') }}</span>
          <label class="chk"><input type="checkbox" v-model="assistant.enabled" @change="saveAssistant"> {{ t('aic.assistToggle') }}</label>
        </div>
        <p class="muted small" style="margin:0 0 10px">
          {{ t('aic.assistNote1') }}
          {{ t('aic.assistNote2') }}
        </p>
        <!-- ② AI 模型基础配置: 与下方"AI 接口基础参数"卡共用数据源(basic.*), 随"保存小 Y 配置"落盘 -->
        <div class="form-grid" :class="{ dimmed: !assistant.enabled }">
          <div class="field">
            <label class="label">{{ t('aic.apiBase') }}</label>
            <input class="input mono" :disabled="!assistant.enabled" v-model.trim="basic.apiBase" placeholder="http://127.0.0.1:11434/v1">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.apiKey') }}</label>
            <input class="input mono" :type="showKey ? 'text' : 'password'" :disabled="!assistant.enabled" v-model.trim="basic.apiKey" :placeholder="t('aic.phApiKey')">
            <label class="checkbox" style="margin-top:6px"><input type="checkbox" :checked="showKey" :disabled="!assistant.enabled" @change="showKey = !showKey"> {{ t('aic.showKey') }}</label>
          </div>
          <div class="field">
            <label class="label">{{ t('aic.modelName') }}</label>
            <input class="input mono" :disabled="!assistant.enabled" v-model.trim="basic.model" placeholder="qwen2.5:7b">
          </div>
        </div>
        <!-- ③ 系统提示词(PROMPT): 自定义小 Y 的人设/回答规则/输出约束/安全边界 -->
        <div style="margin-top:12px">
          <div class="form-row" style="margin-bottom:8px; align-items:center">
            <label class="label" style="margin:0">{{ t('aic.prompt') }}</label>
            <span class="muted small">
              {{ assistantInfo && assistantInfo.hasCustomPrompt ? t('aic.customNow') : t('aic.builtinNow') }} {{ t('aic.effectiveNote') }}
            </span>
            <div class="spacer"></div>
            <button class="btn sm" :disabled="!assistant.enabled" @click="resetAssistantPrompt">{{ t('aic.resetDefault') }}</button>
            <button class="btn sm primary" :disabled="!assistant.enabled || assistantSaving" @click="saveAssistant">
              <span class="spinner" v-if="assistantSaving"></span> {{ t('aic.saveAssist') }}
            </button>
          </div>
          <AiPromptEditor v-model="assistant.prompt" :vars="[]" :disabled="!assistant.enabled" height="200px" />
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          {{ t('aic.basicTitle') }}
          <span class="sub">{{ t('aic.basicSub') }}</span>
        </div>
        <div class="form-grid">
          <div class="field">
            <label class="label">{{ t('aic.timeout') }}</label>
            <input class="input" type="number" min="5" v-model.number="basic.timeoutSec">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.maxContext') }}</label>
            <input class="input" type="number" min="1000" step="1000" v-model.number="basic.maxContext">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.maxTokens') }}</label>
            <input class="input" type="number" min="256" step="256" v-model.number="basic.maxTokens">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.temperature') }}</label>
            <input class="input" type="number" min="0" max="2" step="0.1" v-model.number="basic.temperature">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.topP') }}</label>
            <input class="input" type="number" min="0" max="1" step="0.05" v-model.number="basic.topP">
          </div>
        </div>
        <div class="form-row" style="margin-top:12px">
          <div class="spacer"></div>
          <span class="muted small" v-if="testInfo">{{ testInfo }}</span>
          <button class="btn" :disabled="testing" @click="testConn"><span class="spinner" v-if="testing"></span> {{ t('aic.testBtn') }}</button>
          <button class="btn primary" @click="saveBasic"> {{ t('common.save') }}</button>
        </div>
        <p class="muted small" style="margin:8px 0 0">
          {{ t('aic.testNote') }}
        </p>
      </div>

      <div class="card">
        <div class="card-title">
          {{ t('aic.modTitle') }}
          <span class="sub">{{ t('aic.modSub') }}</span>
        </div>
        <div class="sw-grid" style="grid-template-columns:repeat(3,1fr)">
          <label class="sw">
            <input type="checkbox" v-model="modules.capture" @change="saveModules">
            <span>{{ t('aic.modCapture') }}</span>
            <span class="muted small">{{ t('aic.modCaptureSub') }}</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="modules.scan" @change="saveModules">
            <span>{{ t('aic.modScan') }}</span>
            <span class="muted small">{{ t('aic.modScanSub') }}</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="modules.monitor" @change="saveModules">
            <span>{{ t('aic.modMonitor') }}</span>
            <span class="muted small">{{ t('aic.modMonitorSub') }}</span>
          </label>
        </div>
      </div>
    </div>

    <!-- ② Prompt 模板 -->
    <div v-if="tab === 'tpl'">
      <p class="muted small" style="margin-bottom:10px">
        {{ t('aic.tplIntro') }}
        {{ t('aic.tplVarsNote') }}
        <span class="badge mono" v-for="v in tplVars" :key="v">{{ vbrace(v) }}</span>
      </p>
      <div class="card" v-for="p in tpls" :key="p.key" style="margin-bottom:14px">
        <div class="card-title">
          {{ p.label }}
          <span class="muted small mono">{{ p.key }}</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="p.rag"> {{ t('aic.tplRag') }}</label>
          <label class="chk">{{ t('aic.tplTopK') }} <input class="input" type="number" min="1" max="10" style="width:60px" v-model.number="p.topK"></label>
        </div>
        <div class="form-row" style="margin-bottom:10px">
          <div class="field" style="max-width:280px">
            <label class="label">{{ t('aic.tplName') }}</label>
            <input class="input" v-model.trim="p.name">
          </div>
          <div class="spacer"></div>
          <button class="btn sm" :disabled="!!tplBusy[p.key]" @click="resetTpl(p.key)">{{ t('aic.resetDefault') }}</button>
          <button class="btn sm primary" :disabled="!!tplBusy[p.key] || !p.content.trim()" @click="saveTpl(p.key)">
            <span class="spinner" v-if="tplBusy[p.key]"></span> {{ t('aic.saveTpl') }}
          </button>
        </div>
        <AiPromptEditor v-model="p.content" :vars="tplVars" height="240px" />
      </div>
    </div>

    <!-- ③ RAG 文档库 -->
    <div v-if="tab === 'rag'">
      <div class="card">
        <div class="card-title">
          {{ t('aic.ragTitle') }}
          <span class="sub">{{ t('aic.ragSub') }}</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="rag.enabled" @change="saveRagCfg"> {{ t('aic.ragEnable') }}</label>
          <label class="chk">{{ t('aic.ragTopK') }} <input class="input" type="number" min="1" max="10" style="width:60px" v-model.number="rag.topK" @change="saveRagCfg"></label>
          <label class="chk">{{ t('aic.ragChunk') }} <input class="input" type="number" min="100" step="100" style="width:80px" v-model.number="rag.chunkSize" @change="saveRagCfg"></label>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          {{ t('aic.embTitle') }}
          <span class="sub">{{ t('aic.embSub') }}</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="emb.enabled" @change="saveEmb"> {{ t('aic.embEnable') }}</label>
        </div>
        <div class="form-grid" :class="{ dimmed: !emb.enabled }">
          <div class="field">
            <label class="label">{{ t('aic.embApi') }}</label>
            <input class="input mono" :disabled="!emb.enabled" v-model.trim="emb.apiBase" placeholder="http://127.0.0.1:8080/v1">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.embKey') }}</label>
            <input class="input mono" :type="embShowKey ? 'text' : 'password'" :disabled="!emb.enabled" v-model.trim="emb.apiKey" :placeholder="t('aic.phApiKey')">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.modelName') }}</label>
            <input class="input mono" :disabled="!emb.enabled" v-model.trim="emb.model" placeholder="bge-m3">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.embBatch') }}</label>
            <input class="input" type="number" min="1" :disabled="!emb.enabled" v-model.number="emb.batchSize">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.embDim') }}</label>
            <input class="input" type="number" min="8" :disabled="!emb.enabled" v-model.number="emb.dimension">
          </div>
        </div>
        <div class="form-row" style="margin-top:12px">
          <label class="checkbox" style="max-width:120px"><input type="checkbox" :checked="embShowKey" :disabled="!emb.enabled" @change="embShowKey = !embShowKey"> {{ t('aic.showKeyEmb') }}</label>
          <div class="spacer"></div>
          <span class="muted small" v-if="emb.enabled && (!emb.apiBase || !emb.model)">{{ t('aic.embHint') }}</span>
          <button class="btn" :disabled="!emb.enabled" @click="saveEmb">{{ t('aic.saveEmb') }}</button>
        </div>
        <p class="muted small" style="margin:8px 0 0">
          {{ t('aic.embNote') }}
        </p>
      </div>

      <div class="card">
        <div class="card-title">
          {{ t('aic.rrTitle') }}
          <span class="sub">{{ t('aic.rrSub') }}</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="rr.enabled" @change="saveRR"> {{ t('aic.rrEnable') }}</label>
        </div>
        <div class="form-grid" :class="{ dimmed: !rr.enabled }">
          <div class="field">
            <label class="label">{{ t('aic.embApi') }}</label>
            <input class="input mono" :disabled="!rr.enabled" v-model.trim="rr.apiBase" placeholder="http://127.0.0.1:8903/v1">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.rrKey') }}</label>
            <input class="input mono" :type="rrShowKey ? 'text' : 'password'" :disabled="!rr.enabled" v-model.trim="rr.apiKey" :placeholder="t('aic.phApiKey')">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.modelName') }}</label>
            <input class="input mono" :disabled="!rr.enabled" v-model.trim="rr.model" placeholder="bge-reranker-v2-m3">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.rrTopN') }}</label>
            <input class="input" type="number" min="1" max="50" :disabled="!rr.enabled" v-model.number="rr.topN">
          </div>
        </div>
        <div class="form-row" style="margin-top:12px">
          <label class="checkbox" style="max-width:120px"><input type="checkbox" :checked="rrShowKey" :disabled="!rr.enabled" @change="rrShowKey = !rrShowKey"> {{ t('aic.showKeyEmb') }}</label>
          <div class="spacer"></div>
          <button class="btn" :disabled="!rr.enabled" @click="saveRR">{{ t('aic.saveRR') }}</button>
        </div>
        <p class="muted small" style="margin:8px 0 0">
          {{ t('aic.rrNote') }}
        </p>
      </div>

      <div class="card">
        <div class="card-title">{{ t('aic.uploadTitle') }}</div>
        <div class="form-grid">
          <div class="field">
            <label class="label">{{ t('aic.docName') }}</label>
            <input class="input" v-model.trim="up.name" :placeholder="t('aic.phDocName')">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.docCat') }}</label>
            <select class="input" v-model="up.category">
              <option v-for="c in categories" :key="c">{{ aicCat(c) }}</option>
            </select>
          </div>
        </div>
        <div class="form-row" style="margin-top:10px">
          <input type="file" class="input" accept=".txt,.md,.markdown,.html,.json,.yaml,.yml,.log,.csv" @change="onFilePick">
          <span class="muted small">{{ t('aic.orPaste') }}</span>
          <div class="spacer"></div>
          <button class="btn primary" :disabled="ragBusy || !up.name || !up.content.trim()" @click="uploadDoc">
            <span class="spinner" v-if="ragBusy"></span> {{ t('aic.uploadBtn') }}
          </button>
        </div>
        <textarea class="input mono" v-model="up.content" rows="5" style="margin-top:10px"
          :placeholder="t('aic.phDocContent')"></textarea>
      </div>

      <div class="card">
        <div class="card-title">
          {{ t('aic.docList') }}
          <span class="chip">{{ t('aic.docCount', { n: ragDocs.length }) }}</span>
        </div>
        <div class="table-wrap" v-if="ragDocs.length">
          <table class="table">
            <thead><tr><th>{{ t('aic.cName') }}</th><th>{{ t('aic.cCat') }}</th><th>{{ t('aic.cChunks') }}</th><th>{{ t('aic.cSize') }}</th><th>{{ t('aic.cUploaded') }}</th><th>{{ t('aic.cState') }}</th><th>{{ t('aic.cOps') }}</th></tr></thead>
            <tbody>
              <tr v-for="d in ragDocs" :key="d.id" :class="{ 'row-off': !d.enabled }">
                <td><b class="small">{{ d.name }}</b></td>
                <td><span class="badge blue">{{ aicCat(d.category) }}</span></td>
                <td class="mono">{{ d.chunks }}</td>
                <td class="muted small">{{ (d.size / 1024).toFixed(1) }} KB</td>
                <td class="muted small">{{ fmtDT(d.createdAt) }}</td>
                <td>
                  <span class="chip" :class="d.enabled ? 'on' : 'off'">{{ d.enabled ? t('aic.stateOn') : t('aic.stateOff') }}</span>
                </td>
                <td style="white-space:nowrap">
                  <button class="btn sm" @click="toggleDoc(d.id)">{{ d.enabled ? t('aic.stateOff') : t('aic.stateOn') }}</button>
                  <button class="btn sm danger" @click="delDoc(d.id)">{{ t('common.del') }}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="muted small" v-else>{{ t('aic.noDocs') }}</p>
      </div>

      <div class="card">
        <div class="card-title">{{ t('aic.searchTitle') }}</div>
        <div class="form-row">
          <input class="input mono" style="max-width:340px" v-model="searchQ" :placeholder="t('aic.phSearch')" @keyup.enter="doSearch">
          <button class="btn sm" @click="doSearch" :disabled="!searchQ.trim()">{{ t('aic.searchBtn') }}</button>
          <span class="muted small" v-if="searchMode">
            {{ t('aic.searchMode') }} <b :style="{ color: searchMode === 'vector' ? 'var(--ok,#4cb782)' : 'var(--warn,#e0a53a)' }">{{ searchMode === 'vector' ? t('aic.modeVector') : t('aic.modeKw') }}</b>
          </span>
        </div>
        <div class="muted small" v-if="searchHits === null && searchQ">{{ t('aic.searchHint') }}</div>
        <div v-else-if="searchHits && searchHits.length">
          <div class="hit" v-for="(h, i) in searchHits" :key="i">
            <div class="hit-h">
              <span class="badge blue">{{ h.docName }}</span>
              <span class="muted small mono" v-if="h.category">{{ aicCat(h.category) }}</span>
              <span class="muted small mono">{{ t('aic.similarity', { x: (h.score * 100).toFixed(1) }) }}</span>
            </div>
            <div class="hit-t mono">{{ h.text }}</div>
          </div>
        </div>
        <p class="muted small" v-else-if="searchHits && !searchHits.length">{{ t('aic.noHits') }}</p>
      </div>
    </div>

    <!-- ④ 结构化记忆库 -->
    <div v-if="tab === 'mem'">
      <div class="card">
        <div class="card-title">
          {{ t('aic.memTitle') }}
          <span class="sub">{{ t('aic.memSub') }}</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="mem.enabled"> {{ t('aic.memToggle') }}</label>
        </div>
        <p class="muted small" style="margin:0 0 10px">
          {{ t('aic.memDiff1') }} <b>{{ t('aic.ragLib') }}</b> {{ t('aic.memDiff2') }} <b>{{ t('aic.uploadDocs') }}</b> ({{ t('aic.memDiff3') }});
          <b>{{ t('aic.memLib') }}</b> {{ t('aic.memDiff2') }} <b>{{ t('aic.bizHistory') }}</b> {{ t('aic.memDiff5') }}
          {{ t('aic.memDiff6') }} <span class="badge mono">{{ vbrace('structured_memory') }}</span>{{ t('aic.memDiff7') }}
        </p>
        <div class="form-grid">
          <div class="field">
            <label class="label">{{ t('aic.memRetain') }}</label>
            <input class="input" type="number" min="1" v-model.number="mem.retainDays">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.memMax') }}</label>
            <input class="input" type="number" min="1" max="100" v-model.number="mem.maxItems">
          </div>
          <div class="field">
            <label class="label">{{ t('aic.memCompress') }}</label>
            <div class="sw-grid" style="grid-template-columns:1fr">
              <label class="sw">
                <input type="checkbox" v-model="mem.compress">
                <span>{{ t('aic.compressMode') }}</span>
                <span class="muted small">{{ t('aic.compressOff') }}</span>
              </label>
            </div>
          </div>
        </div>
        <div class="muted small" style="margin:12px 0 6px">{{ t('aic.memScopes') }}</div>
        <div class="sw-grid" style="grid-template-columns:repeat(2,1fr)">
          <label class="sw">
            <input type="checkbox" v-model="mem.scopes.assets">
            <span>{{ t('aic.scopeAssets') }}</span>
            <span class="muted small">{{ t('aic.scopeAssetsSub') }}</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="mem.scopes.alerts">
            <span>{{ t('aic.scopeAlerts') }}</span>
            <span class="muted small">{{ t('aic.scopeAlertsSub') }}</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="mem.scopes.captures">
            <span>{{ t('aic.scopeCaptures') }}</span>
            <span class="muted small">{{ t('aic.scopeCapturesSub') }}</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="mem.scopes.metrics">
            <span>{{ t('aic.scopeMetrics') }}</span>
            <span class="muted small">{{ t('aic.scopeMetricsSub') }}</span>
          </label>
        </div>
        <div class="form-row" style="margin-top:12px">
          <div class="spacer"></div>
          <button class="btn primary" @click="saveMem">{{ t('aic.saveMem') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.hit {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 10px;
  margin-top: 8px;
}
.hit-h {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}
.hit-t {
  font-size: 12px;
  color: var(--muted, #9aa4b2);
  white-space: pre-wrap;
  max-height: 120px;
  overflow: auto;
}
.row-off td {
  opacity: 0.55;
}
/* 组件开关关闭时, 对应配置项整组置灰不可编辑 */
.dimmed {
  opacity: 0.5;
}
.dimmed .input:disabled {
  cursor: not-allowed;
}
</style>
