<template>
  <div>
    <PageHeader title="授权管理" desc="用户 / 登录会话 / 审计日志 / 服务管理"></PageHeader>

    <div class="grid cols-2">
      <!-- 账户 -->
      <div class="card">
        <div class="card-title">账户</div>
        <div class="kv">
          <div class="k">当前用户</div><div class="v mono">{{ user || '-' }}</div>
          <div class="k">角色</div>
          <div class="v"><span class="badge" :class="role === 'admin' ? 'st-success' : (role === 'operator' ? 'st-pending' : '')">{{ roleLabel(role) }}</span></div>
          <div class="k">已注册</div>
          <div class="v"><span class="badge" :class="st.registered ? 'st-success' : 'st-failed'">{{ st.registered ? '是' : '否' }}</span></div>
          <div class="k">模式</div>
          <div class="v"><span class="badge" :class="st.disabled ? 'st-success' : 'st-pending'">{{ st.disabled ? '免登录' : '标准' }}</span></div>
        </div>
      </div>

      <!-- 用户管理(仅管理员可见; auditor 的写接口会被后端 403 兜底) -->
      <div class="card" v-if="role === 'admin'">
        <div class="card-title">用户管理 <span class="sub">admin 全权限 / operator 除授权管理外全功能 / auditor 只读</span></div>
        <div class="form-row">
          <input v-model="newUser.name" class="input" placeholder="用户名" maxlength="20" />
          <input v-model="newUser.pass" class="input" type="password" placeholder="初始密码" />
          <select v-model="newUser.role" class="input">
            <option value="auditor">只读</option>
            <option value="operator">操作员</option>
            <option value="admin">管理员</option>
          </select>
          <button class="btn" :disabled="busy" @click="createUser">创建</button>
        </div>
        <div class="table-wrap" v-if="users.length">
          <table class="table">
            <thead><tr><th>用户</th><th>角色</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>
              <tr v-for="u in users" :key="u.username">
                <td class="mono small">{{ u.username }}</td>
                <td><span class="badge" :class="u.role === 'admin' ? 'st-success' : (u.role === 'operator' ? 'st-pending' : '')">{{ roleLabel(u.role) }}</span></td>
                <td><span class="badge" :class="u.enabled ? 'st-success' : 'st-failed'">{{ u.enabled ? '启用' : '停用' }}</span></td>
                <td>
                  <button class="btn xs" @click="askPassword(u)">改密</button>
                  <!-- 唯一启用中的管理员: 降权/停用/删除会被后端拒(防锁死), 这里显式置灰
                       并给出原因 —— 之前是点了才报错, 用户以为"功能坏了" -->
                  <!-- 三角色后"点击轮换"容易点过头(admin→operator→auditor), 改成下拉直选 -->
                  <select class="input" style="width:92px;display:inline-block" :value="u.role" :disabled="locked(u)"
                          :title="locked(u) ? '唯一启用的管理员不可降权(防止锁死), 请先创建其它管理员' : '切换角色'"
                          @change="setRole(u, $event.target.value)">
                    <option value="admin">管理员</option>
                    <option value="operator">操作员</option>
                    <option value="auditor">只读</option>
                  </select>
                  <button class="btn xs" :disabled="locked(u)" :title="locked(u) ? '唯一启用的管理员不可停用(防止锁死), 请先创建其它管理员' : ''" @click="toggleEnable(u)">{{ u.enabled ? '停用' : '启用' }}</button>
                  <button class="btn xs danger" :disabled="locked(u)" :title="locked(u) ? '唯一启用的管理员不可删除(防止锁死), 请先创建其它管理员' : ''" @click="delUser(u)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else text="暂无用户" />
        <div class="muted small" style="margin-top:6px">
          唯一启用中的管理员只能改密(防止误操作锁死系统); 先创建/提升另一个管理员后, 对其全部操作即可用。
        </div>
      </div>

      <!-- 登录会话 -->
      <div class="card">
        <div class="card-title">登录会话 <span class="sub">token 已脱敏(前 8 位), 可吊销</span></div>
        <div class="table-wrap" v-if="sessions.length">
          <table class="table">
            <thead><tr><th>Token(脱敏)</th><th>过期时间</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>
              <tr v-for="(s, i) in sessions" :key="i">
                <td class="mono small">{{ s.token }}</td>
                <td class="mono small">{{ fmtDT(s.expiresAt) }}</td>
                <td><span class="badge" :class="s.valid ? 'st-success' : 'st-failed'">{{ s.valid ? '有效' : '已过期' }}</span></td>
                <td><button class="btn xs danger" @click="revoke(s)">吊销</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else text="暂无会话" />
      </div>

      <!-- 服务管理: "停止服务"按钮从顶栏移到这里(2026-09-21 收尾)—— 破坏性动作
           不该常驻全局顶栏, 放在授权管理页降低误触; /api/quit 端点保留不变 -->
      <div class="card">
        <div class="card-title">服务管理 <span class="sub">停止后进程退出, 需重新运行 exe</span></div>
        <p class="muted small" style="margin:0 0 10px">
          停止整个 Yugsight 服务(进程退出)。控制台窗口关闭后服务留在后台运行,
          本按钮与登录页的"停止服务"链接是仅有的两个停止入口。
        </p>
        <button class="btn quit" :disabled="busy" @click="quitService">停止服务</button>
      </div>
    </div>

    <!-- 审计日志: 全量操作/登录/启动记录 + 筛选 + 分页 + 保存天数 -->
    <div class="card">
      <div class="card-title">审计日志 <span class="sub">登录 / 操作 / 启动 全量记录 · 保存 {{ retention }} 天(0=不限) · 上限 5000 条 <span class="muted">| 渗透审计在「渗透工作台 → 渗透审计」单独留痕(仅管理员可清空, 清空动作留 penta.audit.clear 痕迹)</span></span></div>
      <div class="form-row" style="flex-wrap:wrap">
        <select class="input" v-model="flt.user" style="width:130px">
          <option value="">全部用户</option>
          <option v-for="u in users" :key="u.username" :value="u.username">{{ u.username }}</option>
        </select>
        <select class="input" v-model="flt.action" style="width:170px">
          <option value="">全部动作</option>
          <option v-for="a in actions" :key="a" :value="a">{{ a }}</option>
        </select>
        <input class="input" v-model="flt.keyword" placeholder="关键字(对象/详情)" style="width:170px" @keyup.enter="applyFilter" />
        <input class="input" type="date" v-model="flt.from" title="起始日期" />
        <input class="input" type="date" v-model="flt.to" title="截止日期" />
        <button class="btn" @click="applyFilter">筛选</button>
        <button class="btn" @click="resetFilter">重置</button>
        <span class="muted small" v-if="total > 0">共 {{ total }} 条</span>
        <!-- 清理日志(admin 专属): 清空全部记录; 清空动作本身会留一条 audit.clear 记录 -->
        <button class="btn danger" v-if="role === 'admin'" :disabled="busy || total === 0" @click="clearAudits">清空日志</button>
      </div>
      <div class="table-wrap" v-if="audits.length">
        <table class="table">
          <thead><tr><th>时间</th><th>用户</th><th>动作</th><th>对象</th><th>详情</th><th>来源 IP</th><th v-if="role === 'admin'" style="width:70px">操作</th></tr></thead>
          <tbody>
            <tr v-for="a in audits" :key="a.id">
              <td class="mono small">{{ fmtDT(a.createdAt) }}</td>
              <td class="small">{{ a.userId || '-' }}</td>
              <td class="mono small">{{ a.action }}</td>
              <td class="small" :title="a.target">{{ a.target || '-' }}</td>
              <td class="small muted" :title="a.detail">{{ a.detail || '-' }}</td>
              <td class="mono small">{{ a.clientIp || '-' }}</td>
              <td v-if="role === 'admin'"><button class="btn xs danger" @click="delAudit(a)">删除</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else text="暂无审计记录" />
      <!-- 分页 -->
      <div class="form-row" v-if="total > pageSize" style="justify-content:flex-end">
        <button class="btn xs" :disabled="page <= 1" @click="gotoPage(page - 1)">上一页</button>
        <span class="muted small">{{ page }} / {{ totalPages }}</span>
        <button class="btn xs" :disabled="page >= totalPages" @click="gotoPage(page + 1)">下一页</button>
      </div>
      <!-- 保存天数(admin): 保存后立即生效并裁剪一次 -->
      <div class="form-row" v-if="role === 'admin'">
        <label class="muted small">日志保存天数:</label>
        <input class="input" type="number" min="0" max="3650" v-model.number="retention" style="width:90px" />
        <button class="btn" :disabled="busy" @click="saveRetention">保存</button>
        <span class="muted small">0 = 不限制(仅受 5000 条上限裁剪)</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import { api } from '../api/http'
import { v2 } from '../api/http'
import { fmtDT } from '../utils'
import { currentUser } from '../auth'

const st = ref({ registered: false, disabled: false })
// 响应式绑定(与 Layout 同一修复): 整页刷新时本组件先于守卫 whoami 挂载,
// ref(getUser()) 快照永远是 null, "当前用户"会一直显示 '-'
const user = currentUser
const role = ref('') // whoami 返回(admin/operator/auditor); 仅 admin 显示用户管理与日志清理
const msg = ref('')
const busy = ref(false)
const sessions = ref([])
const audits = ref([])
const users = ref([])
const newUser = ref({ name: '', pass: '', role: 'auditor' })

// ===== 审计日志: 筛选 / 分页 / 保存天数 =====
const flt = ref({ user: '', action: '', keyword: '', from: '', to: '' })
const actions = ref([]) // 动作下拉选项(全表 distinct, 挂载时取一次)
const page = ref(1)
const pageSize = 50
const total = ref(0)
const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))
const retention = ref(90) // 保存天数, 0 = 不限制

const ROLE_LABELS = { admin: '管理员', operator: '操作员', auditor: '只读' }
function roleLabel(r) { return ROLE_LABELS[r] || (r || '-') }

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

async function loadActions() {
  // 动作下拉: 全表 distinct(最多 5000 条, 一次取完足够)
  try {
    const r = await v2('/audit?limit=5000')
    const s = new Set((r.list || []).map(a => a.action))
    actions.value = Array.from(s).sort()
  } catch (e) { /* 下拉可空, 不影响主体 */ }
}

function applyFilter() { page.value = 1; loadAudits() }
function resetFilter() {
  flt.value = { user: '', action: '', keyword: '', from: '', to: '' }
  page.value = 1
  loadAudits()
}
function gotoPage(p) { page.value = p; loadAudits() }

// delAudit 删除单条审计记录(admin): 删掉后补一条 audit.delete 记录留痕
async function delAudit(a) {
  if (!confirm('删除这条审计记录?\n' + fmtDT(a.createdAt) + '  ' + (a.userId || '-') + '  ' + a.action)) return
  busy.value = true
  try {
    await v2('/audit/' + a.id, { method: 'DELETE' })
    await loadAudits()
    loadActions()
  } catch (e) { alert(e.message) } finally { busy.value = false }
}

// clearAudits 清空全部审计日志(admin)。不可恢复, 二次确认里写清"会留一条凭据"
async function clearAudits() {
  if (!confirm('确认清空全部审计日志(当前 ' + total.value + ' 条)? 不可恢复。\n清空动作本身会写入一条 audit.clear 记录作为凭据。')) return
  busy.value = true
  try {
    const d = await v2('/audit', { method: 'DELETE' })
    page.value = 1
    actions.value = []
    await loadAudits()
    alert('已清空审计日志 ' + ((d && d.deleted != null) ? d.deleted : 0) + ' 条')
  } catch (e) { alert(e.message) } finally { busy.value = false }
}

async function saveRetention() {
  if (retention.value < 0 || retention.value > 3650) { alert('保存天数需在 0~3650 之间(0 = 不限制)'); return }
  busy.value = true
  try {
    await v2('/audit/config', { method: 'POST', body: JSON.stringify({ retentionDays: retention.value }) })
    msg.value = '已保存: 审计日志保存 ' + retention.value + ' 天(0 = 不限制), 已立即生效'
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
  if (!newUser.value.name || newUser.value.pass.length < 6) { alert('用户名必填, 密码至少 6 位'); return }
  busy.value = true
  try {
    await v2('/users', { method: 'POST', body: JSON.stringify(newUser.value) })
    newUser.value = { name: '', pass: '', role: 'auditor' }
    await loadAll()
  } catch (e) { alert(e.message) } finally { busy.value = false }
}

async function askPassword(u) {
  const p = prompt('为用户 ' + u.username + ' 设置新密码(至少 6 位):')
  if (!p) return
  if (p.length < 6) { alert('密码至少 6 位'); return }
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
  if (u.enabled && !confirm('停用 ' + u.username + '? 该用户将无法登录且会话被踢出')) return
  try {
    await v2('/users/' + u.username, { method: 'PUT', body: JSON.stringify({ enabled: !u.enabled }) })
    await loadAll()
  } catch (e) { alert(e.message) }
}

async function delUser(u) {
  if (!confirm('删除用户 ' + u.username + '?')) return
  try {
    await v2('/users/' + u.username, { method: 'DELETE' })
    await loadAll()
  } catch (e) { alert(e.message) }
}

async function revoke(s) {
  if (!confirm('确认吊销会话 ' + s.token + ' ?')) return
  try {
    await v2('/sessions/' + s.token, { method: 'DELETE' })
    await loadAll()
  } catch (e) { alert(e.message) }
}

// 停止整个服务(进程退出)。/api/quit 免登录; 服务停止后页面不可达, 原地提示而不是跳转。
async function quitService() {
  if (!confirm('确定停止 Yugsight 服务？停止后本页面将不可访问，重新双击 exe 可再启动。')) return
  try { await api('/api/quit', { method: 'POST' }) } catch (e) { /* 服务停止瞬间连接中断属正常 */ }
  document.body.innerHTML = '<p style="min-height:100vh;display:flex;align-items:center;justify-content:center;color:#7d8db0;font-size:14px">'
    + 'Yugsight 服务已停止。如需继续使用，重新运行 yugsight_windows_amd64.exe。</p>'
}

onMounted(() => { loadAll() })
</script>

<style scoped>
/* "停止服务"是破坏性动作, 用警示色描边与其它按钮区分 */
.btn.quit { background: transparent; border: 1px solid var(--danger, #ff6b6b); color: var(--danger, #ff6b6b); }
.btn.quit:hover { background: var(--danger, #ff6b6b); color: #fff; }
</style>
