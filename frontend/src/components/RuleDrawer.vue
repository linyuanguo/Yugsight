<template>
  <Teleport to="body">
    <div class="drawer-overlay" v-if="open" @click.self="close">
      <div class="drawer-panel">
        <div class="drawer-head">
          <b>规则库</b>
          <button class="btn xs" @click="close">关闭</button>
        </div>
        <div class="drawer-body">

          <!-- 官方 Nuclei 模板更新(主机扫描用) -->
          <div class="sec">
            <div class="sec-title">
              官方模板更新 <span class="muted small">Nuclei · 主机扫描</span>
            </div>
            <div class="row">
              <span class="chip" :class="upd.running ? 'warn' : (upd.available ? 'blue' : 'on')">
                <span class="spinner" v-if="upd.running" style="width:10px;height:10px;border-width:1.5px"></span>
                {{ upd.running ? '更新中' : (upd.available ? '有新版本' : '最新') }}
              </span>
              <span class="chip muted" v-if="upd.localCommit">{{ short(upd.localCommit) }}</span>
              <div class="spacer"></div>
              <button class="btn xs" :disabled="updBusy || upd.running" @click="checkUpdate">检查</button>
              <button class="btn xs primary" :disabled="updBusy || upd.running || !upd.directEnabled" @click="startUpdate">更新</button>
              <button class="btn xs" :disabled="updBusy" @click="showLog">日志</button>
            </div>
            <div class="muted small" v-if="updProgText" style="margin-top:6px">{{ updProgText }}</div>
            <div class="err-line small" v-if="updErr">{{ updErr }}</div>
          </div>

          <!-- 导入自定义规则(web + host 共用) -->
          <div class="sec">
            <div class="sec-title">
              导入自定义规则 <span class="muted small">Web / 主机</span>
            </div>
            <textarea class="input mono" rows="6" v-model="importJSON"
              placeholder='{"rules":[{"id":"MY-001","name":"示例","severity":"medium","type":"body","pattern":"xss","scope":"web"}]}'></textarea>
            <div class="row" style="margin-top:8px">
              <input class="input mono" style="max-width:160px" v-model.trim="importName" placeholder="文件名(可选)">
              <div class="spacer"></div>
              <button class="btn xs" :disabled="importBusy" @click="doImport">导入</button>
            </div>
            <div class="err-line small" v-if="importErr">{{ importErr }}</div>
            <div class="ok-line small" v-if="importOk">{{ importOk }}</div>
          </div>

        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ref } from 'vue'
import { api } from '../api/http'

const props = defineProps({ open: Boolean })
const emit = defineEmits(['close'])

const upd = ref({})
const updBusy = ref(false)
const updErr = ref('')
const updProgText = ref('')
let pollTimer = null

const importJSON = ref('')
const importName = ref('')
const importErr = ref('')
const importOk = ref('')
const importBusy = ref(false)

function close() {
  emit('close')
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
}

function short(s) { return s ? s.slice(0, 8) : '-' }

async function checkUpdate() {
  updBusy.value = true
  updErr.value = ''
  try {
    const d = await api('/api/rules/update/status')
    upd.value = d || {}
    if (d && d.direct) upd.value.directRepo = d.direct.repo
  } catch (e) { updErr.value = e.message }
  finally { updBusy.value = false }
}

async function startUpdate() {
  updErr.value = ''
  upd.value.running = true
  try {
    await api('/api/rules/update/direct/start', { method: 'POST' })
    pollTimer = setInterval(pollProgress, 1500)
    pollProgress()
  } catch (e) {
    upd.value.running = false
    updErr.value = e.message
  }
}

async function pollProgress() {
  try {
    const p = await api('/api/rules/update/progress')
    upd.value = { ...upd.value, running: p.running }
    if (p.progress) updProgText.value = p.progress
    if (!p.running) {
      clearInterval(pollTimer); pollTimer = null
      upd.value.running = false
      checkUpdate()
    }
  } catch { /* 瞬时抖动不终止 */ }
}

async function showLog() {
  updErr.value = ''
  try {
    const d = await api('/api/rules/update/log')
    const entries = d.entries || []
    if (!entries.length) { alert('暂无更新记录'); return }
    const lines = entries.slice(0, 20).map(e =>
      `${e.time}  ${e.kind || '-'}  ${short(e.fromCommit)}→${short(e.toCommit)}  ${e.files || 0}f  ${e.status}`
    ).join('\n')
    alert('更新日志(最近 20 条):\n\n' + lines)
  } catch (e) { updErr.value = e.message }
}

async function doImport() {
  importErr.value = ''
  importOk.value = ''
  if (!importJSON.value.trim()) { importErr.value = '规则 JSON 不能为空'; return }
  importBusy.value = true
  try {
    await api('/api/vuln/import', { method: 'POST', body: { json: importJSON.value, name: importName.value } })
    importOk.value = '导入成功'
    importJSON.value = ''
    importName.value = ''
  } catch (e) { importErr.value = e.message }
  finally { importBusy.value = false }
}
</script>

<style scoped>
.drawer-overlay {
  position: fixed; inset: 0; z-index: 9000;
  background: rgba(0,0,0,.45);
  display: flex; justify-content: flex-end;
}
.drawer-panel {
  width: 440px; max-width: 90vw; height: 100%;
  background: var(--bg-card, #1a1d23);
  border-left: 1px solid var(--border, #2a2e36);
  display: flex; flex-direction: column;
}
.drawer-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px; border-bottom: 1px solid var(--border, #2a2e36);
}
.drawer-body {
  flex: 1; overflow-y: auto; padding: 16px;
}
.sec { margin-bottom: 24px; }
.sec-title {
  font-size: 13px; margin-bottom: 10px;
  display: flex; align-items: center; gap: 8px;
}
.row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.spacer { flex: 1; }
.chip {
  padding: 2px 8px; border-radius: 3px; font-size: 11px;
  background: var(--bg, #14161a); border: 1px solid var(--border, #2a2e36);
}
.chip.on { color: var(--green, #4caf50); border-color: var(--green, #4caf50); }
.chip.warn { color: var(--yellow, #ff9800); border-color: var(--yellow, #ff9800); }
.chip.blue { color: var(--accent, #4fc3f7); border-color: var(--accent, #4fc3f7); }
.chip.muted { color: var(--text-muted, #888); }
.err-line { color: var(--red, #f44336); margin-top: 6px; }
.ok-line { color: var(--green, #4caf50); margin-top: 6px; }
</style>
