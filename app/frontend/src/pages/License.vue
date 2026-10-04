<template>
  <div>
    <PageHeader :title="t('lic.title')" :desc="t('lic.desc')"></PageHeader>

    <div class="tabs" style="margin-bottom:14px">
      <div class="tab" :class="{ active: tab === 'license' }" @click="setTab('license')">{{ t('lic.tabLicense') }}</div>
      <div class="tab" :class="{ active: tab === 'ai' }" @click="setTab('ai')">{{ t('lic.tabAi') }}</div>
    </div>

    <div v-if="tab === 'license'">
    <div class="grid cols-2">
      <!-- 账户 -->
      <div class="card">
        <div class="card-title">{{ t('lic.account') }}</div>
        <div class="kv">
          <div class="k">{{ t('lic.cUser') }}</div><div class="v mono">{{ user || '-' }}</div>
          <div class="k">{{ t('lic.cRole') }}</div>
          <div class="v"><span class="badge" :class="role === 'admin' ? 'st-success' : (role === 'operator' ? 'st-pending' : '')">{{ roleLabel(role) }}</span></div>
          <div class="k">{{ t('lic.registered') }}</div>
          <div class="v"><span class="badge" :class="st.registered ? 'st-success' : 'st-failed'">{{ st.registered ? t('lic.yes') : t('lic.no') }}</span></div>
          <div class="k">{{ t('lic.mode') }}</div>
          <div class="v"><span class="badge" :class="st.disabled ? 'st-success' : 'st-pending'">{{ st.disabled ? t('lic.noLogin') : t('lic.standard') }}</span></div>
        </div>
        <!-- 2FA 动态码"点击自动填入"开关(2026-10-03 用户要求): 本机浏览器偏好,
             存 localStorage, 默认开(保持既有行为); 关后登录页点数字不填入需手输。
             与登录页 Login.vue 共用 key=yugsight_2fa_clickfill, 免重启即时生效。
             注: 本页整体尚未接入 i18n(批次 8), 文案暂为中文, 与本页现状一致 -->
        <div style="border-top:1px solid var(--border); margin-top:12px; padding-top:12px">
          <label style="display:flex; align-items:center; gap:8px; font-size:13px; color:var(--text); cursor:pointer">
            <input type="checkbox" v-model="clickFillOn" @change="saveClickFill" />
            {{ t('lic.clickFill') }}
          </label>
          <p class="muted small" style="margin:6px 0 0; line-height:1.6">
            {{ t('lic.clickFillOn') }} {{ t('lic.clickFillOff') }}
            <span class="muted">{{ t('lic.clickFillLocal') }}</span>
          </p>
        </div>
      </div>

      <!-- 用户管理(仅管理员可见; auditor 的写接口会被后端 403 兜底) -->
      <div class="card" v-if="role === 'admin'">
        <div class="card-title">{{ t('lic.users') }} <span class="sub">{{ t('lic.usersSub') }}</span></div>
        <div class="form-row">
          <input v-model="newUser.name" class="input" :placeholder="t('lic.phUser')" maxlength="20" />
          <input v-model="newUser.pass" class="input" type="password" :placeholder="t('lic.phPass')" />
          <select v-model="newUser.role" class="input">
            <option value="auditor">{{ t('lic.rAuditor') }}</option>
            <option value="operator">{{ t('lic.rOperator') }}</option>
            <option value="admin">{{ t('lic.rAdmin') }}</option>
          </select>
          <button class="btn" :disabled="busy" @click="createUser">{{ t('lic.create') }}</button>
        </div>
        <div class="table-wrap" v-if="users.length">
          <table class="table">
            <thead><tr><th>{{ t('lic.cUser') }}</th><th>{{ t('lic.cRole') }}</th><th>{{ t('lic.cState') }}</th><th>{{ t('lic.cOps') }}</th></tr></thead>
            <tbody>
              <tr v-for="u in users" :key="u.username">
                <td class="mono small">{{ u.username }}</td>
                <td><span class="badge" :class="u.role === 'admin' ? 'st-success' : (u.role === 'operator' ? 'st-pending' : '')">{{ roleLabel(u.role) }}</span></td>
                <td><span class="badge" :class="u.enabled ? 'st-success' : 'st-failed'">{{ u.enabled ? t('lic.enabled') : t('lic.disabled') }}</span></td>
                <td>
                  <button class="btn xs" @click="askPassword(u)">{{ t('lic.changePass') }}</button>
                  <!-- 唯一启用中的管理员: 降权/停用/删除会被后端拒(防锁死), 这里显式置灰
                       并给出原因 —— 之前是点了才报错, 用户以为"功能坏了" -->
                  <!-- 三角色后"点击轮换"容易点过头(admin→operator→auditor), 改成下拉直选 -->
                  <select class="input" style="width:92px;display:inline-block" :value="u.role" :disabled="locked(u)"
                          :title="locked(u) ? t('lic.lockedRole') : t('lic.switchRole')"
                          @change="setRole(u, $event.target.value)">
                    <option value="admin">{{ t('lic.rAdmin') }}</option>
                    <option value="operator">{{ t('lic.rOperator') }}</option>
                    <option value="auditor">{{ t('lic.rAuditor') }}</option>
                  </select>
                  <button class="btn xs" :disabled="locked(u)" :title="locked(u) ? t('lic.lockedDisable') : ''" @click="toggleEnable(u)">{{ u.enabled ? t('lic.disabled') : t('lic.enabled') }}</button>
                  <button class="btn xs danger" :disabled="locked(u)" :title="locked(u) ? t('lic.lockedDelete') : ''" @click="delUser(u)">{{ t('common.del') }}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="t('lic.noUsers')" />
        <div class="muted small" style="margin-top:6px">
          {{ t('lic.lockedNote') }}
        </div>
      </div>

      <!-- 登录会话 -->
      <div class="card">
        <div class="card-title">{{ t('lic.sessions') }} <span class="sub">{{ t('lic.sessionsSub') }}</span></div>
        <div class="table-wrap" v-if="sessions.length">
          <table class="table">
            <thead><tr><th>{{ t('lic.cToken') }}</th><th>{{ t('lic.cExpires') }}</th><th>{{ t('lic.cState') }}</th><th>{{ t('lic.cOps') }}</th></tr></thead>
            <tbody>
              <tr v-for="(s, i) in sessions" :key="i">
                <td class="mono small">{{ s.token }}</td>
                <td class="mono small">{{ fmtDT(s.expiresAt) }}</td>
                <td><span class="badge" :class="s.valid ? 'st-success' : 'st-failed'">{{ s.valid ? t('lic.valid') : t('lic.expired') }}</span></td>
                <td><button class="btn xs danger" @click="revoke(s)">{{ t('lic.revoke') }}</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="t('lic.noSessions')" />
      </div>

      <!-- 服务管理: "停止服务"按钮从顶栏移到这里(2026-09-21 收尾)—— 破坏性动作
           不该常驻全局顶栏, 放在授权与模型页降低误触; /api/quit 端点保留不变 -->
      <div class="card">
        <div class="card-title">{{ t('lic.svc') }} <span class="sub">{{ t('lic.svcSub') }}</span></div>
        <p class="muted small" style="margin:0 0 10px">
          {{ t('lic.svcNote1') }}
          {{ t('lic.svcNote2') }}
        </p>
        <button class="btn quit" :disabled="busy" @click="quitService">{{ t('lic.quit') }}</button>

        <!-- 恢复出厂: 清空全部运行期数据 + 配置(打 dist 分发包发给他人前用) -->
        <div style="border-top:1px solid var(--border); margin:14px 0 10px"></div>
        <div class="card-title">{{ t('lic.reset') }} <span class="sub">{{ t('lic.resetSub') }}</span></div>
        <p class="muted small" style="margin:0 0 10px">
          {{ t('lic.resetNote1') }}
          {{ t('lic.resetNote2') }}
        </p>
        <label style="display:flex; align-items:center; gap:6px; font-size:12px; color:var(--muted); margin:0 0 10px; cursor:pointer">
          <input type="checkbox" v-model="resetCleanEnv"> {{ t('lic.resetCleanEnv') }}
        </label>
        <div style="display:flex; gap:8px">
          <input class="input" style="flex:1" v-model="resetConfirm" :placeholder="t('lic.resetWordPh', { w: t('lic.resetWord') })" @keyup.enter="doFactoryReset">
          <button class="btn quit" :disabled="busy" @click="doFactoryReset">{{ t('lic.resetWord') }}</button>
        </div>
        <p v-if="resetErr" style="color:var(--danger,#ff6b6b); font-size:12px; margin:8px 0 0">{{ resetErr }}</p>
        <p v-if="resetOk" style="color:#34d399; font-size:12px; margin:8px 0 0">{{ resetOk }}</p>
      </div>

      <!-- 品牌自定义(2026-09-28): 系统名称 + 页脚版权, 仅 2 个可配置字段;
           保存走 brand 节合并写, 立即生效无需重启; 仅 admin 可改
           (后端 adminOnly 是最终边界) -->
      <div class="card" v-if="role === 'admin'">
        <div class="card-title">{{ t('lic.brand') }} <span class="sub">{{ t('lic.brandSub') }}</span></div>
        <div class="form-row" style="flex-direction:column; align-items:stretch">
          <label class="muted small">{{ t('lic.sysName') }} <span class="muted">{{ t('lic.sysNameNote') }}</span></label>
          <input class="input" v-model="brand.system_name" maxlength="120" placeholder="Yugsight 御视" :disabled="brandSaving" />
          <label class="muted small" style="margin-top:8px">{{ t('lic.copyright') }} <span class="muted">{{ t('lic.copyrightNote') }}</span></label>
          <input class="input" v-model="brand.copyright" maxlength="120" placeholder="Copyright © 2026 Yugsight" :disabled="brandSaving" />
        </div>
        <div style="display:flex; align-items:center; gap:10px; margin-top:10px">
          <button class="btn" :disabled="brandSaving || !brandDirty" @click="saveBrand">{{ brandSaving ? t('lic.saving') : t('common.save') }}</button>
          <span class="muted small" v-if="brandMsg">{{ brandMsg }}</span>
        </div>
      </div>

      <!-- HTTPS 访问白名单(2026-09-29): 空 = 不限制任何 IP(默认); 配 IP/网段 = 只放行列表内来源。
           保存即热加载(无需重启); 换 IP 也无需改这里(服务器按访问 IP 自动签发证书),
           白名单只用于"限制谁能访问"。仅 admin 可改(后端 adminOnly 是最终边界) -->
      <div class="card" v-if="role === 'admin'">
        <div class="card-title">{{ t('lic.httpsWl') }} <span class="sub">{{ t('lic.httpsWlSub') }}</span></div>
        <p class="muted small" style="margin:0 0 10px">
          {{ t('lic.httpsNote1') }}<b>{{ t('lic.httpsUnlimited') }}</b>{{ t('lic.httpsNote2') }}<span class="mono">192.168.1.0/24</span>{{ t('lic.httpsNote3') }}<span class="mono">10.0.0.5</span>{{ t('lic.httpsNote4') }}
        </p>
        <div class="form-row">
          <input class="input" style="flex:1" v-model="httpsNew" :placeholder="t('lic.phHttpsIp')" :disabled="httpsSaving" @keyup.enter="addHttpsIp" />
          <button class="btn" :disabled="httpsSaving || !httpsNew.trim()" @click="addHttpsIp">{{ t('lic.add') }}</button>
        </div>
        <div class="form-row" style="flex-wrap:wrap; gap:6px; margin-top:8px" v-if="httpsIps.length">
          <span class="badge" v-for="ip in httpsIps" :key="ip" style="cursor:pointer" @click="removeHttpsIp(ip)" :title="t('lic.clickRemove')">{{ ip }} ×</span>
        </div>
        <Empty v-else :text="t('lic.httpsEmpty')" />
        <div style="display:flex; align-items:center; gap:10px; margin-top:10px">
          <button class="btn" :disabled="httpsSaving" @click="saveHttps">{{ httpsSaving ? t('lic.saving') : t('common.save') }}</button>
          <span class="muted small" v-if="httpsMsg">{{ httpsMsg }}</span>
        </div>
      </div>
    </div>

    <!-- 审计日志: 全量操作/登录/启动记录 + 筛选 + 分页 + 保存天数 -->
    <div class="card">
      <div class="card-title">{{ t('lic.audit') }} <span class="sub">{{ t('lic.auditSub', { n: retention }) }} <span class="muted">| {{ t('lic.auditPenta') }}</span></span></div>
      <div class="form-row" style="flex-wrap:wrap">
        <!-- 2026-10-02 用户口径: 筛选选项基于当前数据里存在的 —— 用户选项=审计
             记录里出现过的用户(与动作同口径, 不再用用户表全量) -->
        <select class="input" v-model="flt.user" style="width:130px">
          <option value="">{{ t('lic.allUsers') }}</option>
          <option v-for="u in auditUsers" :key="u" :value="u">{{ u }}</option>
        </select>
        <select class="input" v-model="flt.action" style="width:170px">
          <option value="">{{ t('pw.allActions') }}</option>
          <option v-for="a in actions" :key="a" :value="a">{{ a }}</option>
        </select>
        <input class="input" v-model="flt.keyword" :placeholder="t('pw.phKeyword')" style="width:170px" @keyup.enter="applyFilter" />
        <input class="input" type="date" v-model="flt.from" :title="t('lic.startDate')" />
        <input class="input" type="date" v-model="flt.to" :title="t('lic.endDate')" />
        <button class="btn" @click="applyFilter">{{ t('pw.filter') }}</button>
        <button class="btn" @click="resetFilter">{{ t('common.reset') }}</button>
        <span class="muted small" v-if="total > 0">{{ t('pw.totalItems', { n: total }) }}</span>
        <!-- 清理日志(admin 专属): 清空全部记录; 清空动作本身会留一条 audit.clear 记录 -->
        <button class="btn danger" v-if="role === 'admin'" :disabled="busy || total === 0" @click="clearAudits">{{ t('lic.clearLog') }}</button>
      </div>
      <div class="table-wrap" v-if="audits.length">
        <table class="table">
          <thead><tr><th>{{ t('pw.cTime') }}</th><th>{{ t('common.user') }}</th><th>{{ t('pw.cAction') }}</th><th>{{ t('pw.cObject') }}</th><th>{{ t('pw.cDetail') }}</th><th>{{ t('pw.cClientIp') }}</th><th v-if="role === 'admin'" style="width:70px">{{ t('lic.cOps') }}</th></tr></thead>
          <tbody>
            <tr v-for="a in audits" :key="a.id">
              <td class="mono small">{{ fmtDT(a.createdAt) }}</td>
              <td class="small">{{ a.userId || '-' }}</td>
              <td class="mono small">{{ a.action }}</td>
              <td class="small" :title="a.target">{{ a.target || '-' }}</td>
              <td class="small muted" :title="a.detail">{{ a.detail || '-' }}</td>
              <td class="mono small">{{ a.clientIp || '-' }}</td>
              <td v-if="role === 'admin'"><button class="btn xs danger" @click="delAudit(a)">{{ t('common.del') }}</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else :text="t('lic.noAudits')" />
      <!-- 分页 -->
      <div class="form-row" v-if="total > pageSize" style="justify-content:flex-end">
        <button class="btn xs" :disabled="page <= 1" @click="gotoPage(page - 1)">{{ t('al.prev') }}</button>
        <span class="muted small">{{ page }} / {{ totalPages }}</span>
        <button class="btn xs" :disabled="page >= totalPages" @click="gotoPage(page + 1)">{{ t('al.next') }}</button>
      </div>
      <!-- 保存天数(admin): 保存后立即生效并裁剪一次 -->
      <div class="form-row" v-if="role === 'admin'">
        <label class="muted small">{{ t('lic.retention') }}</label>
        <input class="input" type="number" min="0" max="3650" v-model.number="retention" style="width:90px" />
        <button class="btn" :disabled="busy" @click="saveRetention">{{ t('common.save') }}</button>
        <span class="muted small">{{ t('lic.retentionNote') }}</span>
      </div>
    </div>
    </div>

    <!-- AI 配置并入授权与模型(2026-09-26): 内嵌 AICfg(embedded 隐藏自身 PageHeader) -->
    <AICfg v-if="tab === 'ai'" embedded />
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import AICfg from './AICfg.vue'
import { api } from '../api/http'
import { v2 } from '../api/http'
import { fmtDT } from '../utils'
import { currentUser } from '../auth'
import { t } from '../i18n'

const router = useRouter()
const route = useRoute()
// AI 配置并入授权与模型(2026-09-26): URL query 驱动 tab; 旧 /settings/ai 重定向到 ?tab=ai
const tab = computed(() => (route.query.tab === 'ai' ? 'ai' : 'license'))
function setTab(t) { router.replace({ path: '/license', query: t === 'ai' ? { tab: 'ai' } : {} }) }

const st = ref({ registered: false, disabled: false })
// 响应式绑定(与 Layout 同一修复): 整页刷新时本组件先于守卫 whoami 挂载,
// ref(getUser()) 快照永远是 null, "当前用户"会一直显示 '-'
const user = currentUser
const role = ref('') // whoami 返回(admin/operator/auditor); 仅 admin 显示用户管理与日志清理
const msg = ref('')
const busy = ref(false)
// ===== 恢复出厂(打 dist 分发包前清空全部数据) =====
const resetCleanEnv = ref(false)
const resetConfirm = ref('')
const resetErr = ref('')
const resetOk = ref('')
const sessions = ref([])
const audits = ref([])
const users = ref([])
const newUser = ref({ name: '', pass: '', role: 'auditor' })

// ===== 2FA 动态码"点击自动填入"开关(2026-10-03): 本机浏览器偏好, localStorage =====
// 与登录页 Login.vue 共用 key; 默认开(保持既有行为), 存 '0' 表示关闭。
// 纯客户端 UX 偏好, 不写 settings.json(它只影响"点数字自动填入"这个交互,
// 码值本身始终展示, 安全性与开关无关)
const CLICKFILL_KEY = 'yugsight_2fa_clickfill'
const clickFillOn = ref(localStorage.getItem(CLICKFILL_KEY) !== '0')
function saveClickFill() {
  try { localStorage.setItem(CLICKFILL_KEY, clickFillOn.value ? '1' : '0') } catch { /* 存储不可用: 仅本次会话生效 */ }
}

// ===== 品牌自定义(2026-09-28): 系统名称 + 页脚版权(仅 2 个可配置字段) =====
// brandBase 记录加载时的原值, 用于"有改动才允许保存"(避免无意义写盘)
const brand = ref({ system_name: '', copyright: '' })
const brandBase = ref({ system_name: '', copyright: '' })
const brandSaving = ref(false)
const brandMsg = ref('')
const brandDirty = computed(
  () => brand.value.system_name !== brandBase.value.system_name
    || brand.value.copyright !== brandBase.value.copyright
)

// ===== HTTPS 访问白名单(2026-09-29): 空 = 不限制, 配 IP/网段 = 只放行列表内来源 =====
const httpsIps = ref([])
const httpsNew = ref('')
const httpsSaving = ref(false)
const httpsMsg = ref('')

async function loadBrand() {
  try {
    const d = await v2('/brand')
    brand.value = { system_name: d.system_name || '', copyright: d.copyright || '' }
    brandBase.value = { ...brand.value }
  } catch (e) { /* 非 admin/异常: 面板本身已按 role 隐藏, 这里静默 */ }
}

async function saveBrand() {
  if (!brand.value.system_name.trim() || !brand.value.copyright.trim()) { alert(t('lic.brandEmpty')); return }
  brandSaving.value = true
  brandMsg.value = ''
  try {
    const d = await v2('/brand', { method: 'POST', body: JSON.stringify(brand.value) })
    brand.value = { system_name: d.system_name, copyright: d.copyright }
    brandBase.value = { ...brand.value }
    brandMsg.value = t('lic.savedNow')
    // 标签页标题同源更新(与 Layout 的 /api/info.brandName 一致)
    if (d.system_name) document.title = d.system_name
  } catch (e) { brandMsg.value = e.message || t('lic.saveFail') }
  finally { brandSaving.value = false }
}

// ===== HTTPS 访问白名单: 读取/增删/保存(保存即热加载, 无需重启) =====
async function loadHttps() {
  try {
    const d = await v2('/https')
    httpsIps.value = (d && d.ips) || []
  } catch (e) { /* 非 admin/异常: 面板按 role 隐藏, 静默 */ }
}
function addHttpsIp() {
  const v = httpsNew.value.trim()
  if (!v) return
  if (!httpsIps.value.includes(v)) httpsIps.value.push(v)
  httpsNew.value = ''
}
function removeHttpsIp(ip) {
  httpsIps.value = httpsIps.value.filter(x => x !== ip)
}
async function saveHttps() {
  httpsSaving.value = true
  httpsMsg.value = ''
  try {
    const d = await v2('/https', { method: 'POST', body: JSON.stringify({ ips: httpsIps.value }) })
    httpsIps.value = (d && d.ips) || []
    httpsMsg.value = httpsIps.value.length ? t('lic.httpsSaved', { n: httpsIps.value.length }) : t('lic.httpsSavedOff')
  } catch (e) { httpsMsg.value = e.message || t('lic.saveFail') }
  finally { httpsSaving.value = false }
}

// ===== 审计日志: 筛选 / 分页 / 保存天数 =====
const flt = ref({ user: '', action: '', keyword: '', from: '', to: '' })
const actions = ref([]) // 动作下拉选项(全表 distinct, 挂载时取一次)
const page = ref(1)
const pageSize = 50
const total = ref(0)
const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))
const retention = ref(90) // 保存天数, 0 = 不限制

// 角色键值化: 值存词条键, 渲染期 t() 解析
const ROLE_LABELS = { admin: 'lic.rAdmin', operator: 'lic.rOperator', auditor: 'lic.rAuditor' }
function roleLabel(r) { return ROLE_LABELS[r] ? t(ROLE_LABELS[r]) : (r || '-') }

function locked(u) {
  // 唯一启用中的管理员: 后端拒绝对其降权/停用/删除(防锁死), 前端显式置灰
  if (u.role !== 'admin' || !u.enabled) return false
  return users.value.filter(x => x.role === 'admin' && x.enabled).length === 1
}

async function loadAudits() {
  const q = new URLSearchParams()
  q.set('page', String(page.value))
  q.set('size', String(pageSize))
  if (flt.value.user) q.set('user', flt.value.user)
  if (flt.value.action) q.set('action', flt.value.action)
  if (flt.value.keyword) q.set('keyword', flt.value.keyword)
  if (flt.value.from) q.set('from', flt.value.from)
  if (flt.value.to) q.set('to', flt.value.to)
  try {
    const r = await v2('/audit?' + q.toString())
    audits.value = r.list || []
    total.value = r.total || 0
  } catch (e) { msg.value = e.message }
}

const auditUsers = ref([])
async function loadActions() {
  // 动作/用户下拉: 审计记录 distinct(最多 5000 条, 一次取完足够)。
  // 2026-10-02 用户口径: 用户选项也从审计记录聚合(不再用用户表全量 ——
  // 没留过审计记录的用户不该出现在筛选选项里)
  try {
    const r = await v2('/audit?limit=5000')
    const list = r.list || []
    const s = new Set(list.map(a => a.action))
    actions.value = Array.from(s).sort()
    const u = new Set(list.map(a => a.userId).filter(Boolean))
    auditUsers.value = Array.from(u).sort()
  } catch (e) { /* 下拉可空, 不影响主体 */ }
}
watch(auditUsers, () => {
  // 已选用户的记录全被删/清空 → 选项消失, 筛选自清(防列表卡死为空)
  if (flt.value.user && !auditUsers.value.includes(flt.value.user)) {
    flt.value.user = ''
    loadAudits()
  }
})

function applyFilter() { page.value = 1; loadAudits() }
function resetFilter() {
  flt.value = { user: '', action: '', keyword: '', from: '', to: '' }
  page.value = 1
  loadAudits()
}
function gotoPage(p) { page.value = p; loadAudits() }

// delAudit 删除单条审计记录(admin): 删掉后补一条 audit.delete 记录留痕
async function delAudit(a) {
  if (!confirm(t('lic.delAuditConfirm', { x: fmtDT(a.createdAt) + '  ' + (a.userId || '-') + '  ' + a.action }))) return
  busy.value = true
  try {
    await v2('/audit/' + a.id, { method: 'DELETE' })
    await loadAudits()
    loadActions()
  } catch (e) { alert(e.message) } finally { busy.value = false }
}

// clearAudits 清空全部审计日志(admin)。不可恢复, 二次确认里写清"会留一条凭据"
async function clearAudits() {
  if (!confirm(t('lic.clearAuditsConfirm', { n: total.value }))) return
  busy.value = true
  try {
    const d = await v2('/audit', { method: 'DELETE' })
    page.value = 1
    actions.value = []
    await loadAudits()
    alert(t('lic.auditsCleared', { n: (d && d.deleted != null) ? d.deleted : 0 }))
  } catch (e) { alert(e.message) } finally { busy.value = false }
}

async function saveRetention() {
  if (retention.value < 0 || retention.value > 3650) { alert(t('lic.retentionRange')); return }
  busy.value = true
  try {
    await v2('/audit/config', { method: 'POST', body: JSON.stringify({ retentionDays: retention.value }) })
    msg.value = t('lic.retentionSaved', { n: retention.value })
  } catch (e) { alert(e.message) } finally { busy.value = false }
}

async function loadAll() {
  try {
    const [st2, sess, me, us, cfg] = await Promise.allSettled([
      api('/api/auth/status'),
      v2('/sessions'),
      api('/api/whoami'),
      v2('/users'),
      v2('/audit/config')
    ])
    if (st2.status === 'fulfilled') st.value = st2.value
    if (sess.status === 'fulfilled') sessions.value = sess.value.list || []
    if (me.status === 'fulfilled') role.value = me.value.role || 'auditor'
    if (us.status === 'fulfilled') users.value = us.value || []
    if (cfg.status === 'fulfilled') retention.value = cfg.value.retentionDays ?? 90
  } catch (e) { msg.value = e.message }
  loadAudits()
  loadActions()
}

async function createUser() {
  if (!newUser.value.name || newUser.value.pass.length < 6) { alert(t('lic.userPassReq')); return }
  busy.value = true
  try {
    await v2('/users', { method: 'POST', body: JSON.stringify(newUser.value) })
    newUser.value = { name: '', pass: '', role: 'auditor' }
    await loadAll()
  } catch (e) { alert(e.message) } finally { busy.value = false }
}

async function askPassword(u) {
  const p = prompt(t('lic.setPassPrompt', { x: u.username }))
  if (!p) return
  if (p.length < 6) { alert(t('lic.passShort')); return }
  try {
    await v2('/users/' + u.username, { method: 'PUT', body: JSON.stringify({ password: p }) })
    await loadAll()
  } catch (e) { alert(e.message) }
}

// setRole 三态角色切换(下拉框直选)。失败也要重载: 把下拉框复位回库里的真实角色,
// 否则界面会显示一个"看起来改了其实没改"的角色(下次刷新又变回去, 更难排查)。
async function setRole(u, r) {
  if (r === u.role) return
  try {
    await v2('/users/' + u.username, { method: 'PUT', body: JSON.stringify({ role: r }) })
  } catch (e) { alert(e.message) }
  await loadAll()
}

async function toggleEnable(u) {
  if (u.enabled && !confirm(t('lic.disableConfirm', { x: u.username }))) return
  try {
    await v2('/users/' + u.username, { method: 'PUT', body: JSON.stringify({ enabled: !u.enabled }) })
    await loadAll()
  } catch (e) { alert(e.message) }
}

async function delUser(u) {
  if (!confirm(t('lic.delUserConfirm', { x: u.username }))) return
  try {
    await v2('/users/' + u.username, { method: 'DELETE' })
    await loadAll()
  } catch (e) { alert(e.message) }
}

async function revoke(s) {
  if (!confirm(t('lic.revokeConfirm', { x: s.token }))) return
  try {
    await v2('/sessions/' + s.token, { method: 'DELETE' })
    await loadAll()
  } catch (e) { alert(e.message) }
}

// 停止整个服务(进程退出)。/api/quit 免登录; 服务停止后页面不可达, 原地提示而不是跳转。
async function quitService() {
  if (!confirm(t('lic.quitConfirm'))) return
  try { await api('/api/quit', { method: 'POST' }) } catch (e) { /* 服务停止瞬间连接中断属正常 */ }
  document.body.innerHTML = '<p style="min-height:100vh;display:flex;align-items:center;justify-content:center;color:#7d8db0;font-size:14px">'
    + t('lic.stoppedPage') + '</p>'
}

// 一键恢复出厂: 清空全部运行期数据 + 配置(打 dist 分发包发给他人前)。
// 需输入"恢复出厂"确认; cleanEnv 勾选时额外清外部引擎/探针包/日志。
async function doFactoryReset() {
  if (resetConfirm.value !== t('lic.resetWord')) { resetErr.value = t('lic.resetWordErr', { w: t('lic.resetWord') }); return }
  if (!confirm(t('lic.resetConfirm') + (resetCleanEnv.value ? t('lic.resetCleanEnv2') : ''))) return
  busy.value = true
  resetErr.value = ''; resetOk.value = ''
  try {
    const d = await v2('/factory-reset', { method: 'POST', body: JSON.stringify({ cleanEnv: resetCleanEnv.value }) })
    resetOk.value = t('lic.resetDone', { n: d.cleared || 0 })
    resetConfirm.value = ''
  } catch (e) { resetErr.value = e.message || t('lic.resetFail') }
  finally { busy.value = false }
}

onMounted(() => { loadAll(); loadBrand(); loadHttps() })
</script>

<style scoped>
/* "停止服务"是破坏性动作, 用警示色描边与其它按钮区分 */
.btn.quit { background: transparent; border: 1px solid var(--danger, #ff6b6b); color: var(--danger, #ff6b6b); }
.btn.quit:hover { background: var(--danger, #ff6b6b); color: #fff; }
</style>
