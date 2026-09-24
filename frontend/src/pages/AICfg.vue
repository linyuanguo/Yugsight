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
import { ref, reactive, onMounted } from 'vue'
import { api } from '../api/http'
import { fmtDT } from '../utils'
import PageHeader from '../components/PageHeader.vue'
import AiPromptEditor from '../components/AiPromptEditor.vue'

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
        timeoutSec: +basic.timeoutSec, maxContext: +basic.maxContext,
        maxTokens: +basic.maxTokens, temperature: +basic.temperature, topP: +basic.topP
      })
    })
    say(true, '基础参数已保存')
    await loadStatus()
  } catch (e) { say(false, e.message) }
}

async function saveModules() {
  try {
    await api('/api/ai/config', {
      method: 'POST',
      body: JSON.stringify({ modules: { ...modules } })
    })
    say(true, '模块开关已保存(关闭后业务页 AI 分析按钮置灰)')
    await loadStatus()
  } catch (e) { say(false, e.message) }
}

// 测试并保存: 连通通过才落盘(与经典页/旧 Capture 页同口径, /api/ai/test)
async function testAndSave() {
  testing.value = true
  testInfo.value = ''
  try {
    const d = await api('/api/ai/test', {
      method: 'POST',
      body: JSON.stringify({
        apiBase: basic.apiBase, apiKey: basic.apiKey, model: basic.model
      })
    })
    testInfo.value = d.ok
      ? `连通成功, 已保存启用 (模型: ${d.model || basic.model})`
      : `连通失败: ${d.error || '未知错误'}`
    say(!!d.ok, testInfo.value)
    if (d.ok) await loadStatus()
  } catch (e) {
    say(false, e.message)
  } finally {
    testing.value = false
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
  } catch (e) { say(false, '模板加载失败: ' + e.message) }
}

async function saveTpl(key) {
  const p = tpls[key]
  tplBusy.value[key] = true
  try {
    await api('/api/ai/templates', {
      method: 'POST',
      body: JSON.stringify({ key, name: p.name, content: p.content, rag: p.rag, topK: +p.topK })
    })
    say(true, `「${p.label}」已保存(业务页点 AI 分析时自动绑定)`)
  } catch (e) { say(false, e.message) } finally {
    tplBusy.value[key] = false
  }
}

async function resetTpl(key) {
  if (!confirm(`恢复「${tpls[key].label}」为默认模板? 当前内容将丢弃。`)) return
  try {
    await api('/api/ai/templates/reset', { method: 'POST', body: JSON.stringify({ key }) })
    say(true, '已恢复默认模板')
    await loadTemplates()
  } catch (e) { say(false, e.message) }
}

// ===== 板块 3: RAG 文档库 =====
const rag = reactive({ enabled: true, topK: 3, chunkSize: 800 })
const ragDocs = ref([])
const ragBusy = ref(false)
const up = reactive({ name: '', category: '安全基线', content: '' })
const categories = ['安全基线', '漏洞手册', '设备资料', '运维文档', '其它']
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
  } catch (e) { say(false, '文档库加载失败: ' + e.message) }
}

async function saveRagCfg() {
  try {
    await api('/api/ai/rag/config', {
      method: 'POST',
      body: JSON.stringify({ enabled: rag.enabled, topK: +rag.topK, chunkSize: +rag.chunkSize })
    })
    say(true, 'RAG 参数已保存')
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
    say(true, emb.enabled
      ? 'Embedding 已启用(后台开始向量化文档, 换模型/维度自动重算)'
      : 'Embedding 已禁用(检索走内置关键词)')
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
    say(true, rr.enabled ? 'Reranker 已启用(初筛后重排序)' : 'Reranker 已禁用(返回初筛结果)')
    await loadRAG()
  } catch (e) { say(false, e.message) }
}

function onFilePick(e) {
  const f = e.target.files && e.target.files[0]
  if (!f) return
  if (f.size > 2 * 1024 * 1024) { say(false, '文档超过 2MB 上限'); return }
  const reader = new FileReader()
  reader.onload = () => {
    up.content = String(reader.result || '')
    if (!up.name) up.name = f.name
  }
  reader.onerror = () => say(false, '文件读取失败')
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
    say(true, '文档已上传(自动分片 + 向量化, 立即可被检索)')
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
  if (!confirm('删除该文档? 删除后其内容不再参与 RAG 检索。')) return
  try {
    await api('/api/ai/rag/docs/' + id, { method: 'DELETE' })
    say(true, '文档已删除')
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
  } catch (e) { say(false, '记忆库加载失败: ' + e.message) }
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
    say(true, '记忆库配置已保存(AI 分析时自动注入 {{structured_memory}})')
    await loadStatus()
  } catch (e) { say(false, e.message) }
}
</script>

<template>
  <div>
    <PageHeader title="AI 配置" desc="全局参数 / Prompt 模板 / RAG 文档库 / 结构化记忆库 —— 分析触发入口在各业务页面(抓包/扫描/弱口令/节点监控)">
      <div class="chip" :class="st && st.enabled ? 'on' : 'off'">
        {{ st && st.enabled ? 'AI 已启用' : 'AI 未启用' }}
      </div>
      <span class="muted small mono" v-if="st && st.model">{{ st.backend }} · {{ st.model }}</span>
      <span class="muted small" v-if="msg" style="color:var(--ok,#4cb782)">{{ msg }}</span>
      <span class="muted small" v-if="err" style="color:var(--danger,#e5484d)">{{ err }}</span>
      <button class="btn sm" @click="loadStatus">刷新</button>
    </PageHeader>

    <div class="tabs" style="margin-bottom:14px">
      <div class="tab" :class="{ active: tab === 'api' }" @click="tab = 'api'">① 接口基础配置</div>
      <div class="tab" :class="{ active: tab === 'tpl' }" @click="tab = 'tpl'">② Prompt 模板</div>
      <div class="tab" :class="{ active: tab === 'rag' }" @click="tab = 'rag'">③ 文档库 (RAG)</div>
      <div class="tab" :class="{ active: tab === 'mem' }" @click="tab = 'mem'">④ 结构化记忆库</div>
    </div>

    <!-- ① 接口基础配置 -->
    <div v-if="tab === 'api'">
      <div class="card">
        <div class="card-title">AI 接口(OpenAI 兼容协议, 支持 Ollama / vLLM / OpenAI 等)</div>
        <div class="form-grid">
          <div class="field">
            <label class="label">API 地址</label>
            <input class="input mono" v-model.trim="basic.apiBase" placeholder="http://127.0.0.1:11434/v1">
          </div>
          <div class="field">
            <label class="label">API Key(本地模型可留空)</label>
            <input class="input mono" :type="showKey ? 'text' : 'password'" v-model.trim="basic.apiKey" placeholder="本地 Ollama 可留空">
          </div>
          <div class="field">
            <label class="label">模型名称</label>
            <input class="input mono" v-model.trim="basic.model" placeholder="qwen2.5:7b">
          </div>
          <div class="field">
            <label class="label">请求超时(秒)</label>
            <input class="input" type="number" min="5" v-model.number="basic.timeoutSec">
          </div>
          <div class="field">
            <label class="label">最大上下文长度(输入预算, 字符)</label>
            <input class="input" type="number" min="1000" step="1000" v-model.number="basic.maxContext">
          </div>
          <div class="field">
            <label class="label">最大输出 token</label>
            <input class="input" type="number" min="256" step="256" v-model.number="basic.maxTokens">
          </div>
          <div class="field">
            <label class="label">temperature(采样温度 0-2)</label>
            <input class="input" type="number" min="0" max="2" step="0.1" v-model.number="basic.temperature">
          </div>
          <div class="field">
            <label class="label">top_p(核采样 0-1)</label>
            <input class="input" type="number" min="0" max="1" step="0.05" v-model.number="basic.topP">
          </div>
        </div>
        <div class="form-row" style="margin-top:12px">
          <label class="checkbox" style="max-width:130px"><input type="checkbox" :checked="showKey" @change="showKey = !showKey"> 显示 Key</label>
          <div class="spacer"></div>
          <span class="muted small" v-if="testInfo">{{ testInfo }}</span>
          <button class="btn" :disabled="testing" @click="saveBasic"><span class="spinner" v-if="testing"></span> 保存参数</button>
          <button class="btn primary" :disabled="testing" @click="testAndSave">
            <span class="spinner" v-if="testing"></span> 测试并保存
          </button>
        </div>
        <p class="muted small" style="margin:8px 0 0">
          测试通过才落盘启用(settings.json 的 ai 节, 热生效免重启)。关闭状态下不发起任何 LLM 调用。
        </p>
      </div>

      <div class="card">
        <div class="card-title">
          模块总开关
          <span class="sub">关闭后对应业务页面的"AI 分析"按钮置灰不可用</span>
        </div>
        <div class="sw-grid" style="grid-template-columns:repeat(3,1fr)">
          <label class="sw">
            <input type="checkbox" v-model="modules.capture" @change="saveModules">
            <span>实时抓包 AI 分析</span>
            <span class="muted small">抓包页按钮</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="modules.scan" @change="saveModules">
            <span>扫描结果 AI 研判</span>
            <span class="muted small">扫描作业 / 弱口令(共用)</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="modules.monitor" @change="saveModules">
            <span>节点监控告警 AI 分析</span>
            <span class="muted small">节点监控页按钮</span>
          </label>
        </div>
      </div>
    </div>

    <!-- ② Prompt 模板 -->
    <div v-if="tab === 'tpl'">
      <p class="muted small" style="margin-bottom:10px">
        业务页点击"AI 分析"时自动绑定对应模板: 抓包 → 流量分析模板, 扫描/弱口令 → 漏洞报告模板, 节点监控 → 监控告警研判模板。
        占位变量(编辑器内高亮, 未知变量橙色提醒):
        <span class="badge mono" v-for="v in tplVars" :key="v">{{ vbrace(v) }}</span>
      </p>
      <div class="card" v-for="p in tpls" :key="p.key" style="margin-bottom:14px">
        <div class="card-title">
          {{ p.label }}
          <span class="muted small mono">{{ p.key }}</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="p.rag"> 启用 RAG 检索文档片段</label>
          <label class="chk">RAG 条数 <input class="input" type="number" min="1" max="10" style="width:60px" v-model.number="p.topK"></label>
        </div>
        <div class="form-row" style="margin-bottom:10px">
          <div class="field" style="max-width:280px">
            <label class="label">模板名称</label>
            <input class="input" v-model.trim="p.name">
          </div>
          <div class="spacer"></div>
          <button class="btn sm" :disabled="!!tplBusy[p.key]" @click="resetTpl(p.key)">恢复默认</button>
          <button class="btn sm primary" :disabled="!!tplBusy[p.key] || !p.content.trim()" @click="saveTpl(p.key)">
            <span class="spinner" v-if="tplBusy[p.key]"></span> 保存模板
          </button>
        </div>
        <AiPromptEditor v-model="p.content" :vars="tplVars" height="240px" />
      </div>
    </div>

    <!-- ③ RAG 文档库 -->
    <div v-if="tab === 'rag'">
      <div class="card">
        <div class="card-title">
          知识库参数
          <span class="sub">非结构化文档: 分片 → 向量化/关键词检索 → 重排序(可选) → 注入 LLM</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="rag.enabled" @change="saveRagCfg"> 启用文档库</label>
          <label class="chk">检索条数 TopK <input class="input" type="number" min="1" max="10" style="width:60px" v-model.number="rag.topK" @change="saveRagCfg"></label>
          <label class="chk">分片大小 <input class="input" type="number" min="100" step="100" style="width:80px" v-model.number="rag.chunkSize" @change="saveRagCfg"></label>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          Embedding 向量嵌入接口
          <span class="sub">OpenAI 兼容 /embeddings; 关闭 = 检索走内置关键词(自动降级)</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="emb.enabled" @change="saveEmb"> 启用向量检索</label>
        </div>
        <div class="form-grid" :class="{ dimmed: !emb.enabled }">
          <div class="field">
            <label class="label">接口地址</label>
            <input class="input mono" :disabled="!emb.enabled" v-model.trim="emb.apiBase" placeholder="http://127.0.0.1:8080/v1">
          </div>
          <div class="field">
            <label class="label">API Key(本地可留空)</label>
            <input class="input mono" :type="embShowKey ? 'text' : 'password'" :disabled="!emb.enabled" v-model.trim="emb.apiKey" placeholder="本地模型可留空">
          </div>
          <div class="field">
            <label class="label">模型名称</label>
            <input class="input mono" :disabled="!emb.enabled" v-model.trim="emb.model" placeholder="bge-m3">
          </div>
          <div class="field">
            <label class="label">批次大小</label>
            <input class="input" type="number" min="1" :disabled="!emb.enabled" v-model.number="emb.batchSize">
          </div>
          <div class="field">
            <label class="label">向量维度(与服务端一致)</label>
            <input class="input" type="number" min="8" :disabled="!emb.enabled" v-model.number="emb.dimension">
          </div>
        </div>
        <div class="form-row" style="margin-top:12px">
          <label class="checkbox" style="max-width:120px"><input type="checkbox" :checked="embShowKey" :disabled="!emb.enabled" @change="embShowKey = !embShowKey"> 显示 Key</label>
          <div class="spacer"></div>
          <span class="muted small" v-if="emb.enabled && (!emb.apiBase || !emb.model)">提示: 未填接口地址/模型时, 检索会自动降级为关键词</span>
          <button class="btn" :disabled="!emb.enabled" @click="saveEmb">保存 Embedding</button>
        </div>
        <p class="muted small" style="margin:8px 0 0">
          启用后文档将向量化并落库(换模型/维度自动重算); 未启用的组件不初始化、不占资源。检索失败自动降级关键词, 不中断分析。
        </p>
      </div>

      <div class="card">
        <div class="card-title">
          Reranker 重排序接口
          <span class="sub">OpenAI/Jina 兼容 /rerank; 关闭 = 直接返回初筛结果(自动降级)</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="rr.enabled" @change="saveRR"> 启用重排序</label>
        </div>
        <div class="form-grid" :class="{ dimmed: !rr.enabled }">
          <div class="field">
            <label class="label">接口地址</label>
            <input class="input mono" :disabled="!rr.enabled" v-model.trim="rr.apiBase" placeholder="http://127.0.0.1:8903/v1">
          </div>
          <div class="field">
            <label class="label">API Key</label>
            <input class="input mono" :type="rrShowKey ? 'text' : 'password'" :disabled="!rr.enabled" v-model.trim="rr.apiKey" placeholder="本地模型可留空">
          </div>
          <div class="field">
            <label class="label">模型名称</label>
            <input class="input mono" :disabled="!rr.enabled" v-model.trim="rr.model" placeholder="bge-reranker-v2-m3">
          </div>
          <div class="field">
            <label class="label">重排序返回数量 topN</label>
            <input class="input" type="number" min="1" max="50" :disabled="!rr.enabled" v-model.number="rr.topN">
          </div>
        </div>
        <div class="form-row" style="margin-top:12px">
          <label class="checkbox" style="max-width:120px"><input type="checkbox" :checked="rrShowKey" :disabled="!rr.enabled" @change="rrShowKey = !rrShowKey"> 显示 Key</label>
          <div class="spacer"></div>
          <button class="btn" :disabled="!rr.enabled" @click="saveRR">保存 Reranker</button>
        </div>
        <p class="muted small" style="margin:8px 0 0">
          对初筛候选池重打分排序; 调用失败自动回退初筛顺序, 不中断分析。
        </p>
      </div>

      <div class="card">
        <div class="card-title">上传文档(文本类: .txt / .md / .html / .json / .yaml / .log)</div>
        <div class="form-grid">
          <div class="field">
            <label class="label">文档名称</label>
            <input class="input" v-model.trim="up.name" placeholder="如: 等保 2.0 三级基线">
          </div>
          <div class="field">
            <label class="label">分类</label>
            <select class="input" v-model="up.category">
              <option v-for="c in categories" :key="c">{{ c }}</option>
            </select>
          </div>
        </div>
        <div class="form-row" style="margin-top:10px">
          <input type="file" class="input" accept=".txt,.md,.markdown,.html,.json,.yaml,.yml,.log,.csv" @change="onFilePick">
          <span class="muted small">或直接在下方粘贴文本</span>
          <div class="spacer"></div>
          <button class="btn primary" :disabled="ragBusy || !up.name || !up.content.trim()" @click="uploadDoc">
            <span class="spinner" v-if="ragBusy"></span> 上传并分片
          </button>
        </div>
        <textarea class="input mono" v-model="up.content" rows="5" style="margin-top:10px"
          placeholder="粘贴文档内容…(上传时自动分片 + 向量化)"></textarea>
      </div>

      <div class="card">
        <div class="card-title">
          文档列表
          <span class="chip">共 {{ ragDocs.length }} 篇</span>
        </div>
        <div class="table-wrap" v-if="ragDocs.length">
          <table class="table">
            <thead><tr><th>名称</th><th>分类</th><th>分片数</th><th>大小</th><th>上传时间</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>
              <tr v-for="d in ragDocs" :key="d.id" :class="{ 'row-off': !d.enabled }">
                <td><b class="small">{{ d.name }}</b></td>
                <td><span class="badge blue">{{ d.category }}</span></td>
                <td class="mono">{{ d.chunks }}</td>
                <td class="muted small">{{ (d.size / 1024).toFixed(1) }} KB</td>
                <td class="muted small">{{ fmtDT(d.createdAt) }}</td>
                <td>
                  <span class="chip" :class="d.enabled ? 'on' : 'off'">{{ d.enabled ? '启用' : '禁用' }}</span>
                </td>
                <td style="white-space:nowrap">
                  <button class="btn sm" @click="toggleDoc(d.id)">{{ d.enabled ? '禁用' : '启用' }}</button>
                  <button class="btn sm danger" @click="delDoc(d.id)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="muted small" v-else>暂无文档 —— 上传安全基线 / 漏洞手册 / 设备资料 / 运维文档后, 模板开启 RAG 绑定时自动检索注入。</p>
      </div>

      <div class="card">
        <div class="card-title">检索预览(验证文档可被检索到)</div>
        <div class="form-row">
          <input class="input mono" style="max-width:340px" v-model="searchQ" placeholder="如: Redis 未授权访问" @keyup.enter="doSearch">
          <button class="btn sm" @click="doSearch" :disabled="!searchQ.trim()">检索</button>
          <span class="muted small" v-if="searchMode">
            当前检索模式: <b :style="{ color: searchMode === 'vector' ? 'var(--ok,#4cb782)' : 'var(--warn,#e0a53a)' }">{{ searchMode === 'vector' ? '向量检索' : '关键词(降级)' }}</b>
          </span>
        </div>
        <div class="muted small" v-if="searchHits === null && searchQ">输入关键词后点"检索"。</div>
        <div v-else-if="searchHits && searchHits.length">
          <div class="hit" v-for="(h, i) in searchHits" :key="i">
            <div class="hit-h">
              <span class="badge blue">{{ h.docName }}</span>
              <span class="muted small mono" v-if="h.category">{{ h.category }}</span>
              <span class="muted small mono">相似度 {{ (h.score * 100).toFixed(1) }}%</span>
            </div>
            <div class="hit-t mono">{{ h.text }}</div>
          </div>
        </div>
        <p class="muted small" v-else-if="searchHits && !searchHits.length">无命中 —— 检查文档是否启用、关键词是否出现在文档中。</p>
      </div>
    </div>

    <!-- ④ 结构化记忆库 -->
    <div v-if="tab === 'mem'">
      <div class="card">
        <div class="card-title">
          结构化记忆库
          <span class="sub">读取平台数据库内的结构化历史记录(与 RAG 文档库严格区分)</span>
          <div class="spacer"></div>
          <label class="chk"><input type="checkbox" v-model="mem.enabled"> 全局总开关</label>
        </div>
        <p class="muted small" style="margin:0 0 10px">
          与 RAG 的区别: <b>RAG 文档库</b> 检索的是<b>上传的非结构化文档</b>(安全基线/漏洞手册/设备资料/运维文档, 向量化);
          <b>结构化记忆库</b> 检索的是<b>平台数据库里的业务历史</b>(扫描落库的漏洞/告警事件/抓包报告/节点指标), 不额外存储、只按时间窗读取。
          AI 分析时, 检索到的记忆自动注入 Prompt 变量 <span class="badge mono">{{ vbrace('structured_memory') }}</span>。
        </p>
        <div class="form-grid">
          <div class="field">
            <label class="label">记忆保留时长(天)</label>
            <input class="input" type="number" min="1" v-model.number="mem.retainDays">
          </div>
          <div class="field">
            <label class="label">每范围检索条数上限</label>
            <input class="input" type="number" min="1" max="100" v-model.number="mem.maxItems">
          </div>
          <div class="field">
            <label class="label">记忆压缩</label>
            <div class="sw-grid" style="grid-template-columns:1fr">
              <label class="sw">
                <input type="checkbox" v-model="mem.compress">
                <span>单行摘要模式</span>
                <span class="muted small">关闭 = 每条附完整内容(更详细, 更占上下文)</span>
              </label>
            </div>
          </div>
        </div>
        <div class="muted small" style="margin:12px 0 6px">记忆检索范围(勾选项均参与注入):</div>
        <div class="sw-grid" style="grid-template-columns:repeat(2,1fr)">
          <label class="sw">
            <input type="checkbox" v-model="mem.scopes.assets">
            <span>资产历史扫描记录</span>
            <span class="muted small">漏洞库(时间窗内, 新→旧)</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="mem.scopes.alerts">
            <span>历史告警事件</span>
            <span class="muted small">节点采集告警(级别/类型/详情)</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="mem.scopes.captures">
            <span>历史抓包分析记录</span>
            <span class="muted small">抓包报告(含历史 AI 结论摘要)</span>
          </label>
          <label class="sw">
            <input type="checkbox" v-model="mem.scopes.metrics">
            <span>节点历史指标</span>
            <span class="muted small">采集轮次(CPU/内存/时延等)</span>
          </label>
        </div>
        <div class="form-row" style="margin-top:12px">
          <div class="spacer"></div>
          <button class="btn primary" @click="saveMem">保存记忆库配置</button>
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
