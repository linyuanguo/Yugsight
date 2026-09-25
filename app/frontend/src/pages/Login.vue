<script setup>
// Login 登录页: 账号 + 密码 + 6 位动态验证码 一屏一次性提交。
//
// 动态验证码展示在登录页(带 90s 倒计时), 用户"看得到才输得进" —— 点击数字可
// 一键填入。本工具为单管理员离线内网部署, 码值展示在登录页本身是既定设计
// (见 auth_2fa.go); 登录页不设开关, 2FA 常驻(后端未配置时自动启用)。
//
// "1天内记住密码": 勾选时把账号+密码存本机 localStorage, 24h 过期自动清除,
// 下次打开登录页自动回填 —— 只省敲键盘, 动态码每次都必须输入(安全边界不松)。
// 本工具为单管理员离线内网部署, 凭据只存本机浏览器, 不出网。
import { ref, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api/http.js'
import { setUser } from '../auth'
import { totpRemainSec } from '../utils/otp.js'

const router = useRouter()
const user = ref('')
const pass = ref('')
const code = ref('')
const remember = ref(true)   // 1天内记住密码
const showPass = ref(false)  // 密码框内"显示/隐藏密码"开关
const err = ref('')
const msg = ref('')
const loading = ref(false)

// ===== 记住密码(1天有效, 仅本机 localStorage) =====
// 存 {user, pass, ts}; 加载时超 24h 直接清掉。损坏数据也清掉, 不让脏数据
// 卡住登录页。存储失败(隐私模式等)静默跳过, 不阻断登录。
const CRED_KEY = 'yugsight_cred'
const CRED_TTL = 24 * 3600 * 1000

function loadCred() {
  try {
    const raw = localStorage.getItem(CRED_KEY)
    if (!raw) return
    const c = JSON.parse(raw)
    if (!c || typeof c.user !== 'string' || typeof c.pass !== 'string' || !c.user) {
      localStorage.removeItem(CRED_KEY)
      return
    }
    if (Date.now() - (c.ts || 0) > CRED_TTL) { localStorage.removeItem(CRED_KEY); return }
    user.value = c.user
    pass.value = c.pass
    remember.value = true
  } catch {
    try { localStorage.removeItem(CRED_KEY) } catch { /* 忽略 */ }
  }
}

function saveCred() {
  try {
    if (remember.value) {
      localStorage.setItem(CRED_KEY, JSON.stringify({ user: user.value, pass: pass.value, ts: Date.now() }))
    } else {
      localStorage.removeItem(CRED_KEY)
    }
  } catch { /* 存储不可用不阻断登录 */ }
}

// ===== 动态验证码(登录页内联展示, 常驻) =====
const fa = ref({ enabled: false, code: '', remain: 0 })
let faTimer = null
let faSlice = -1 // 当前 90s 时间片, 翻转时拉新码

// 拉取当前时间片码值(登录前接口, 按用户名; 后端未配置时会自动启用)
async function fetchCode() {
  try {
    const p = user.value ? '?user=' + encodeURIComponent(user.value) : ''
    const d = await api('/api/auth/2fa/code' + p)
    fa.value = { enabled: !!(d && d.enabled), code: (d && d.code) || '', remain: (d && d.remain) || 0 }
  } catch { fa.value = { enabled: false, code: '', remain: 0 } }
}

// 点击展示的数字一键填入(填入满 6 位后由 watch 自动提交登录)
function fillCode() {
  if (fa.value.code) code.value = fa.value.code
}

// 每秒刷新倒计时; 90s 时间片翻转时拉新码(码值每片变化, 本地倒计时跨片自动跟新)
function startFATimer() {
  if (faTimer) clearInterval(faTimer)
  faTimer = setInterval(() => {
    fa.value.remain = totpRemainSec()
    const slice = Math.floor(Date.now() / 1000 / 90)
    if (fa.value.enabled && slice !== faSlice) {
      faSlice = slice
      fetchCode()
    }
  }, 1000)
}

async function doLogin() {
  if (loading.value) return
  err.value = ''; msg.value = ''
  if (!user.value || !pass.value) { err.value = '请输入账号和密码'; return }
  if (fa.value.enabled && code.value.length !== 6) { err.value = '请输入 6 位动态验证码'; return }
  loading.value = true
  try {
    // 一屏一次提交: 口令 + 验证码(未启用 2FA 时 code 为空串)。
    // 不传 trust: 动态码每次都必输(旧"免动态码"信任令牌已弃用), 方便只靠记住密码
    const d = await api('/api/login', {
      method: 'POST',
      body: { user: user.value, pass: pass.value, code: code.value }
    })
    // 登录响应自带 user/role, 直接写入登录态: 顶栏立即显示真实账号,
    // 且守卫不会因"未登录"的旧判定把刚登录的导航打回登录页
    setUser((d && d.user) || user.value, (d && d.role) || 'admin')
    saveCred()
    router.push('/dashboard')
  } catch (e) {
    if (e && e.body && e.body.need2fa) {
      // 码值已过期(恰跨片): 重拉一次最新码并提示重输
      faSlice = Math.floor(Date.now() / 1000 / 90)
      fetchCode()
      code.value = ''
      err.value = '验证码已过期, 请输入页面上最新的动态码'
    } else {
      err.value = (e && e.message) || '登录失败'
      if (fa.value.enabled) code.value = ''
    }
  } finally {
    loading.value = false
  }
}

// 满 6 位自动提交(含点击填入/粘贴), 减少一次点击
watch(code, v => { if (fa.value.enabled && v.length === 6) doLogin() })
// 用户名变化时按新用户名重新拉码值(单管理员下通常无变化, 保留健壮性)。
// 400ms 防抖: 逐字输入 "admin" 时避免每个按键都发一次请求 —— 历史上这里每键
// 一发, 叠加后端旧版"未知用户也建 2FA 行"的缺陷, 在用户表留下了 ad/adm/admi
// 三个幽灵账号(后端已修, 防抖仍是少发无效请求的正解)。
let codeTimer = null
watch(user, () => {
  if (codeTimer) clearTimeout(codeTimer)
  codeTimer = setTimeout(() => { if (user.value) fetchCode() }, 400)
})

// 未登录时顶栏不可用, 登录页提供停止服务入口(/api/quit 免登录):
// 用户关了控制台黑窗口后服务留在后台, 这是找到停止按钮的唯二位置之一。
async function quitService() {
  if (!confirm('确定停止 Yugsight 服务？停止后本页面将不可访问，重新双击 exe 可再启动。')) return
  try { await api('/api/quit', { method: 'POST' }) } catch (e) { /* 服务停止瞬间连接中断属正常 */ }
  document.body.innerHTML = '<p style="min-height:100vh;display:flex;align-items:center;justify-content:center;color:#7d8db0;font-size:14px">'
    + 'Yugsight 服务已停止。如需继续使用，重新运行 yugsight_windows_amd64.exe。</p>'
}

onMounted(async () => {
  try {
    const st = await api('/api/auth/status')
    if (st && st.disabled) { msg.value = '测试模式(免登录), 正在进入控制台...'; router.push('/dashboard'); return }
    if (st && st.registered === false) { router.push('/register'); return }
  } catch { /* 状态获取失败不阻断登录页 */ }
  loadCred() // 回填记住的账号密码(必须在拉码值之前, 码值按用户名取)
  await fetchCode()
  startFATimer()
})
onBeforeUnmount(() => { if (faTimer) clearInterval(faTimer) })
</script>

<template>
  <div class="page-login">
    <form class="login-card" @submit.prevent="doLogin">
      <div class="brand">
        <h1>御视 <span class="en">Yugsight</span></h1>
        <p class="sub">网络安全扫描探测与运维大屏</p>
      </div>

      <label class="fld">
        <span>账号</span>
        <input v-model.trim="user" autocomplete="username" placeholder="管理员账号" />
      </label>
      <label class="fld">
        <span>密码</span>
        <div class="pw-wrap">
          <input v-model="pass" :type="showPass ? 'text' : 'password'" autocomplete="current-password" placeholder="密码" />
          <button type="button" class="pw-toggle" :class="{ on: showPass }" @click="showPass = !showPass"
                  :title="showPass ? '隐藏密码' : '显示密码'">
            <svg v-if="!showPass" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"
                 fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                 aria-hidden="true"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg v-else xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"
                 fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                 aria-hidden="true"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></svg>
          </button>
        </div>
      </label>

      <!-- 动态验证码: 常驻展示; 点击数字一键填入, 90 秒一换 -->
      <div v-if="fa.enabled" class="fa-box">
        <div class="fa-head">
          <span>动态验证码</span>
          <span class="fa-remain">每 90 秒刷新 · 剩余 {{ fa.remain }}s</span>
        </div>
        <div class="fa-show" @click="fillCode" title="点击一键填入">{{ fa.code || '······' }}</div>
        <div class="fa-hint">点击上方数字一键填入</div>
        <input v-model="code" class="code-input" inputmode="numeric" maxlength="6"
               autocomplete="one-time-code" placeholder="照上方 6 位数字输入" />
      </div>

      <div class="opts">
        <label class="opt"><input v-model="remember" type="checkbox" /> 1天内记住密码(仅存本机)</label>
      </div>

      <p v-if="err" class="err">{{ err }}</p>
      <p v-if="msg" class="ok">{{ msg }}</p>
      <button class="btn" type="submit" :disabled="loading">
        {{ loading ? '登录中...' : '登 录' }}
      </button>
    </form>
    <p class="foot">Yugsight · 离线本地部署 · 登录校验全程本地完成
      · <a class="quit-link" href="javascript:void(0)" @click="quitService">停止服务</a>
    </p>
  </div>
</template>

<style scoped>
.page-login { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px; background: var(--bg, #0d1220); }
.login-card { width: 360px; max-width: 92vw; background: var(--panel, #131a2c); border: 1px solid var(--line, #232c45); border-radius: 12px; padding: 28px 26px; display: flex; flex-direction: column; gap: 14px; }
.brand h1 { margin: 0; font-size: 22px; color: var(--fg, #e8ecf5); }
.brand .en { font-size: 15px; color: var(--dim, #7d8db0); font-weight: 400; }
.brand .sub { margin: 4px 0 0; font-size: 12px; color: var(--dim, #7d8db0); }
.fld { display: flex; flex-direction: column; gap: 6px; font-size: 13px; color: var(--dim, #7d8db0); }
.fld input, .fa-box .code-input { background: var(--input, #0d1220); border: 1px solid var(--line, #232c45); border-radius: 8px; padding: 10px 12px; color: var(--fg, #e8ecf5); font-size: 14px; outline: none; }
.fld input:focus, .fa-box .code-input:focus { border-color: var(--accent, #4c8dff); }
/* 浮动隐形: 平时透明不占视觉, 鼠标移到密码框/聚焦时淡入; 显示密码期间保持可见(要能点回去隐藏) */
.pw-wrap { position: relative; }
.pw-wrap input { width: 100%; padding-right: 38px; }
.pw-toggle { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); display: flex; padding: 3px; background: none; border: 0; color: var(--dim, #7d8db0); cursor: pointer; opacity: 0; transition: opacity .18s ease, color .18s ease; }
.pw-wrap:hover .pw-toggle, .pw-wrap:focus-within .pw-toggle, .pw-toggle.on { opacity: 1; }
.pw-toggle:hover { color: var(--fg, #e8ecf5); }
.pw-toggle svg { width: 18px; height: 18px; }
.fa-box { display: flex; flex-direction: column; gap: 6px; background: rgba(76, 141, 255, .06); border: 1px solid var(--line, #232c45); border-radius: 10px; padding: 12px 14px; }
.fa-head { display: flex; align-items: center; justify-content: space-between; font-size: 13px; color: var(--dim, #7d8db0); }
.fa-remain { font-size: 11px; color: var(--dim, #7d8db0); }
.fa-show { font-size: 20px; letter-spacing: 10px; text-align: center; color: var(--accent, #4c8dff); font-family: monospace; padding: 2px 0; cursor: pointer; user-select: none; transition: color .15s, transform .1s; }
.fa-show:hover { color: var(--fg, #e8ecf5); transform: translateY(-1px); }
.fa-hint { font-size: 11px; color: var(--dim, #7d8db0); text-align: center; }
.code-input { letter-spacing: 8px; text-align: center; font-size: 20px; }
.opts { display: flex; flex-direction: column; gap: 6px; }
.opt { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--dim, #7d8db0); cursor: pointer; }
.err { margin: 0; font-size: 12px; color: var(--danger, #ff6b6b); }
.ok { margin: 0; font-size: 12px; color: var(--accent, #4c8dff); }
.btn { background: var(--accent, #4c8dff); border: 0; border-radius: 8px; padding: 11px 0; color: #fff; font-size: 14px; cursor: pointer; }
.btn:disabled { opacity: .6; cursor: default; }
.foot { font-size: 12px; color: var(--dim, #7d8db0); }
.quit-link { color: var(--danger, #ff6b6b); text-decoration: none; }
.quit-link:hover { text-decoration: underline; }
</style>
