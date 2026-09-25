<template>
  <div>
    <PageHeader title="漏扫管控" desc="白名单 / 误报 / 置信度评分">
      <span class="chip" :class="status && status.enabled ? 'on' : 'off'">
        {{ status && status.enabled ? '白名单已启用' : '白名单未启用(添加条目时自动开启)' }}
      </span>
      <button class="btn sm" @click="loadAll"><span class="spinner" v-if="loading"></span> 刷新</button>
    </PageHeader>

    <div class="tabs">
      <div class="tab" :class="{ active: tab === 'wl' }" @click="tab = 'wl'">白名单 ({{ wlList.length }})</div>
      <div class="tab" :class="{ active: tab === 'fp' }" @click="tab = 'fp'">误报 ({{ fpList.length }})</div>
      <div class="tab" :class="{ active: tab === 'score' }" @click="tab = 'score'">置信度评分</div>
    </div>

    <!-- 白名单条目 -->
    <div v-if="tab === 'wl'">
      <div class="card">
        <div class="card-title">添加白名单 <span class="sub">命中后该来源的漏洞结果自动过滤(不推送/不进报告)</span></div>
        <div class="form-row">
          <div class="field" style="max-width:150px">
            <label class="label">类型</label>
            <select class="select" v-model="wl.type">
              <option value="ip">IP (ip)</option>
              <option value="cidr">CIDR 网段 (cidr)</option>
              <option value="port">端口 (port)</option>
              <option value="cve">CVE 编号 (cve)</option>
              <option value="tag">资产标签 (tag)</option>
            </select>
          </div>
          <div class="field">
            <label class="label">匹配值 *</label>
            <input class="input mono" v-model.trim="wl.match" :placeholder="wlPh" @keyup.enter="addWl">
          </div>
          <div class="field">
            <label class="label">原因(可选)</label>
            <input class="input" v-model.trim="wl.reason" placeholder="如: 内网测试环境">
          </div>
          <div class="field" style="max-width:210px">
            <label class="label">有效期(可选, 空 = 永久)</label>
            <input class="input" type="datetime-local" v-model="wl.expires">
          </div>
          <div style="align-self:flex-end">
            <button class="btn primary" :disabled="busy" @click="addWl">添加</button>
          </div>
        </div>
        <div class="login-err" style="text-align:left">{{ err }}</div>
      </div>

      <div class="card">
        <div class="table-wrap" v-if="wlList.length">
          <table class="table">
            <thead>
              <tr><th>ID</th><th>类型</th><th>匹配值</th><th>原因</th><th>有效期</th><th>添加时间</th><th>操作</th></tr>
            </thead>
            <tbody>
              <tr v-for="e in wlList" :key="e.id">
                <td class="mono small">{{ e.id }}</td>
                <td><span class="badge blue">{{ TYPE_NAME[e.type] || e.type }}</span></td>
                <td class="mono">{{ e.match }}</td>
                <td class="small muted">{{ e.reason || '-' }}</td>
                <td class="mono small">{{ e.expiresAt && e.expiresAt !== '0001-01-01T00:00:00Z' ? fmtDT(e.expiresAt) : '永久' }}</td>
                <td class="muted small mono">{{ fmtDT(e.createdAt) }}</td>
                <td><button class="btn xs danger" @click="rmWl(e)">删除</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else text="暂无白名单条目" />
      </div>
    </div>

    <!-- 误报规则 -->
    <div v-else-if="tab === 'fp'">
      <div class="card">
        <div class="card-title">标记误报 <span class="sub">同资产 + 同 CVE 规则: 后续扫描自动标记, 报告导出时排除</span></div>
        <div class="form-row">
          <div class="field" style="max-width:180px">
            <label class="label">资产 IP *</label>
            <input class="input mono" v-model.trim="fp.assetIp" placeholder="如 192.168.1.10" @keyup.enter="addFp">
          </div>
          <div class="field" style="max-width:180px">
            <label class="label">CVE(可选)</label>
            <input class="input mono" v-model.trim="fp.cve" placeholder="无 CVE 按标题匹配">
          </div>
          <div class="field">
            <label class="label">标题(可选)</label>
            <input class="input" v-model.trim="fp.title" placeholder="规则标题">
          </div>
          <div class="field">
            <label class="label">备注(可选)</label>
            <input class="input" v-model.trim="fp.note" placeholder="误报原因">
          </div>
          <div style="align-self:flex-end">
            <button class="btn primary" :disabled="busy" @click="addFp">标记</button>
          </div>
        </div>
        <div class="login-err" style="text-align:left">{{ err }}</div>
      </div>

      <div class="card">
        <div class="table-wrap" v-if="fpList.length">
          <table class="table">
            <thead>
              <tr><th>ID</th><th>资产 IP</th><th>CVE</th><th>标题</th><th>备注</th><th>标记人</th><th>标记时间</th><th>操作</th></tr>
            </thead>
            <tbody>
              <tr v-for="r in fpList" :key="r.id">
                <td class="mono small">{{ r.id }}</td>
                <td class="mono">{{ r.assetIp }}</td>
                <td class="mono small">{{ r.cve || '-' }}</td>
                <td class="small">{{ r.title || '-' }}</td>
                <td class="small muted">{{ r.note || '-' }}</td>
                <td class="small muted">{{ r.markedBy || '-' }}</td>
                <td class="muted small mono">{{ fmtDT(r.createdAt) }}</td>
                <td><button class="btn xs danger" @click="rmFp(r)">删除</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else text="暂无误报规则" />
      </div>
    </div>

    <!-- 置信度评分: 只读说明卡。扫描结果里的"置信度"列与漏洞详情都按这套模型打分,
         用户看到 62 分却不知道意味着什么, 这里给出判据与它如何影响风险等级。 -->
    <div v-else>
      <div class="card">
        <div class="card-title">四级打分模型 <span class="sub">置信度 0-100, 由证据强度决定</span></div>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr><th>分值</th><th>等级</th><th>判据</th></tr>
            </thead>
            <tbody>
              <tr v-for="t in tiers" :key="t.tier">
                <td class="mono">{{ t.range }}</td>
                <td><span class="badge blue">{{ t.name }}</span></td>
                <td class="small muted">{{ t.remark }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="small muted" style="margin-top:8px">分值与等级见漏洞列表「置信度」列与漏洞详情。</div>
      </div>

      <div class="card">
        <div class="card-title">风险等级映射 <span class="sub">来源严重级别 + 置信度 → 最终等级</span></div>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr><th>来源级别</th><th>置信度 ≥ 40</th><th>置信度 &lt; 40（可疑）</th></tr>
            </thead>
            <tbody>
              <tr v-for="r in RISK_MAP" :key="r.base">
                <td><span class="badge" :class="r.cls">{{ r.base }}</span></td>
                <td class="small">{{ r.base }}</td>
                <td class="small">{{ r.down }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="small muted" style="margin-top:8px">
          info 恒为 Info（加固建议, 不参与风险定级）; 可疑级证据不足, 自动降一级。
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import { api } from '../api/http'
import { fmtDT, localToISO } from '../utils'

const TYPE_NAME = { ip: 'IP', cidr: 'CIDR', port: '端口', cve: 'CVE', tag: '标签' }

// 风险等级映射说明(与 scanctl.MapRiskLevel 同口径: info 恒 Info, <40 降一级)
const RISK_MAP = [
  { base: 'Critical', down: 'High', cls: 'st-failed' },
  { base: 'High', down: 'Medium', cls: 'st-failed' },
  { base: 'Medium', down: 'Low', cls: 'st-running' },
  { base: 'Low', down: 'Info', cls: 'st-pending' }
]

// 服务端没回 scoring 时(老版本/接口异常)用静态兜底, 说明卡不至于空白
const TIER_FALLBACK = [
  { tier: 'verified', name: '已验证', range: '100', remark: '完整 POC 成功验证' },
  { tier: 'exact', name: '精确匹配', range: '70-99', remark: '精确版本匹配 + 服务 Banner 匹配' },
  { tier: 'fuzzy', name: '模糊匹配', range: '40-69', remark: '模糊版本匹配, 无 POC 验证' },
  { tier: 'suspicious', name: '可疑', range: '0-39', remark: '仅关键词匹配, 标记为可疑' }
]

const tab = ref('wl')
const loading = ref(false)
const busy = ref(false)
const err = ref('')
const status = ref(null)
const wlList = ref([])
const fpList = ref([])

const wl = reactive({ type: 'ip', match: '', reason: '', expires: '' })
const fp = reactive({ assetIp: '', cve: '', title: '', note: '' })

const tiers = computed(() => {
  const t = status.value && status.value.scoring && status.value.scoring.tiers
  return t && t.length ? t : TIER_FALLBACK
})

const wlPh = computed(() => ({
  ip: '如 192.168.1.10', cidr: '如 192.168.1.0/24', port: '如 8080',
  cve: '如 CVE-2021-44228', tag: '如 test'
}[wl.type] || ''))

async function loadAll() {
  loading.value = true
  err.value = ''
  try {
    const [st, wl, fpr] = await Promise.all([
      api('/api/vuln/control/status'),
      api('/api/vuln/whitelist'),
      api('/api/vuln/fps')
    ])
    status.value = st
    wlList.value = wl.entries || []
    fpList.value = fpr.rules || []
  } catch (e) { err.value = e.message }
  finally { loading.value = false }
}

async function addWl() {
  err.value = ''
  if (!wl.match) { err.value = '匹配值不能为空'; return }
  busy.value = true
  try {
    await api('/api/vuln/whitelist/add', {
      method: 'POST',
      body: { type: wl.type, match: wl.match, reason: wl.reason, expiresAt: localToISO(wl.expires) }
    })
    Object.assign(wl, { match: '', reason: '', expires: '' })
    await loadAll()
  } catch (e) { err.value = e.message } finally { busy.value = false }
}

async function rmWl(e) {
  if (!confirm('确认删除白名单条目 ' + e.match + ' ?')) return
  try {
    await api('/api/vuln/whitelist/remove', { method: 'POST', body: { id: e.id } })
    await loadAll()
  } catch (err2) { alert(err2.message) }
}

async function addFp() {
  err.value = ''
  if (!fp.assetIp) { err.value = '资产 IP 不能为空'; return }
  busy.value = true
  try {
    await api('/api/vuln/fps/mark', {
      method: 'POST',
      body: { assetIp: fp.assetIp, cve: fp.cve, title: fp.title, note: fp.note }
    })
    Object.assign(fp, { assetIp: '', cve: '', title: '', note: '' })
    await loadAll()
  } catch (e) { err.value = e.message } finally { busy.value = false }
}

async function rmFp(r) {
  if (!confirm('确认删除误报规则 ' + r.assetIp + (r.cve ? ' / ' + r.cve : '') + ' ?')) return
  try {
    await api('/api/vuln/fps/remove', { method: 'POST', body: { id: r.id } })
    await loadAll()
  } catch (e) { alert(e.message) }
}

onMounted(loadAll)
</script>
