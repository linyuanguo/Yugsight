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
//
// 2026-10-03: 文案接入 i18n(中英切换, 右上角小按钮; 登录页无 Layout 外壳,
// 切换器独立放页面角落, 与 Layout 顶栏同一套 i18n 模块/持久化)。
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api/http.js'
import { setUser } from '../auth'
import { totpRemainSec } from '../utils/otp.js'
import { t, locale, toggleLocale } from '../i18n'

const router = useRouter()
const user = ref('')
const pass = ref('')
const code = ref('')
const remember = ref(true)   // 1天内记住密码
const showPass = ref(false)  // 密码框内"显示/隐藏密码"开关
const err = ref('')
const msg = ref('')
const loading = ref(false)

// ===== 证书信任引导(仅登录页, 先于登录表单渲染) =====
// 浏览器不向页面 JS 暴露"证书是否受系统信任"(受信与"点了继续访问"都是
// isSecureContext=true, JS 读不到地址栏), 前端自己永远判不准"装没装证书"。
// 唯一可靠依据在中心端: 后端进程直接读 Windows 证书存储, /api/auth/status 回
// certTrusted(根 CA 是否在机器/用户根存储)。登录页口径:
//   selfSigned && !certTrusted → 显示安装引导条;
//   certTrusted=true(已装)     → 提示自动消失, 无需点任何按钮;
//   卸载证书后刷新页面          → 提示自动回来(含 certmgr 手动卸载)。
// "不再提示"仅留作兜底(如非 Windows 平台后端恒回 certTrusted=false), 正常流程
// 不依赖它。
// 新 key(不沿用旧版 yugsight_cert_perm_dismissed): 旧状态是"无条件压横幅", 与现在
// "横幅跟随证书真实状态"的口径冲突, 旧残留会让卸载证书后提示回不来, 故换新名重置。
const CERT_ACK_KEY = 'yugsight_cert_ack_v2'
const CERT_LATER_KEY = 'yugsight_cert_later'
let ack0 = false
let later0 = false
try { ack0 = localStorage.getItem(CERT_ACK_KEY) === '1' } catch { ack0 = false }
try { later0 = sessionStorage.getItem(CERT_LATER_KEY) === '1' } catch { later0 = false }
const certSelfSigned = ref(false)   // 后端 selfSigned 标志, onMounted 填入
const certTrusted = ref(false)      // 后端 certTrusted: 根 CA 是否已装入信任存储
const certAcked = ref(ack0)
const certLater = ref(later0)
const certDownloading = ref(false)
const showCertWarn = computed(() => certSelfSigned.value && !certTrusted.value && !certAcked.value && !certLater.value)

// 永久收起(兜底, 正常流程靠 certTrusted 自动驱动)
function ackCert() {
  certAcked.value = true
  try { localStorage.setItem(CERT_ACK_KEY, '1') } catch { /* 隐私模式静默 */ }
}
// 本标签页本次会话不再显示(关标签页/重开浏览器后恢复)
function laterCert() {
  certLater.value = true
  try { sessionStorage.setItem(CERT_LATER_KEY, '1') } catch { /* 隐私模式静默 */ }
}
// 安装证书: 拉取 /static/YugsightCertTool.exe(同源, 跟随当前 http/https)→ blob →
// 触发下载; 按钮文字"安装证书"→"正在下载..."→ 完成后恢复。拉取失败(如工具未构建)
// 回退直接链接, 让浏览器自行处理 404。不拦截登录(按钮 type=button)。
async function downloadCertTool() {
  if (certDownloading.value) return
  certDownloading.value = true
  try {
    const r = await fetch('/static/YugsightCertTool.exe')
    if (!r.ok) throw new Error('HTTP ' + r.status)
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'YugsightCertTool.exe'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  } catch (e) {
    window.location.href = '/static/YugsightCertTool.exe'
  } finally {
    certDownloading.value = false
  }
}



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

// 2FA 动态码"点击自动填入"开关(2026-10-03): 本机浏览器偏好, 存 localStorage,
// 默认开(保持既有行为); 在「授权与模型」页(License.vue)可关闭。
// 关后点击数字不填入, 需手动输入 6 位码。与 License.vue 共用同一 key。
const CLICKFILL_KEY = 'yugsight_2fa_clickfill'
const clickFillOn = ref(localStorage.getItem(CLICKFILL_KEY) !== '0')

// 点击展示的数字一键填入(填入满 6 位后由 watch 自动提交登录); 开关关闭时不填入
function fillCode() {
  if (clickFillOn.value && fa.value.code) code.value = fa.value.code
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
  if (!user.value || !pass.value) { err.value = t('login.errNeedCred'); return }
  if (fa.value.enabled && code.value.length !== 6) { err.value = t('login.errNeedCode'); return }
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
      err.value = t('login.errCodeExpired')
    } else {
      // 后端错误消息(如"账号或密码错误")暂为中文, 未纳入 i18n
      err.value = (e && e.message) || t('login.errLoginFail')
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
  if (!confirm(t('login.quitConfirm'))) return
  try { await api('/api/quit', { method: 'POST' }) } catch (e) { /* 服务停止瞬间连接中断属正常 */ }
  document.body.innerHTML = '<p style="min-height:100vh;display:flex;align-items:center;justify-content:center;color:#7d8db0;font-size:14px">'
    + t('login.quitDone') + '</p>'
}

onMounted(async () => {
  try {
    const st = await api('/api/auth/status')
    if (st && st.disabled) { msg.value = t('login.testMode'); router.push('/dashboard'); return }
    if (st && st.registered === false) { router.push('/register'); return }
    // 自签部署 + 证书真实信任态均由后端给出(浏览器不向 JS 暴露受信状态, 只有
    // 中心端进程能读证书存储): selfSigned 决定"是否该引导", certTrusted 决定
    // "装了没"—— 装了不提示, 没装提示, 卸载后刷新自动回显。
    if (st && st.selfSigned) certSelfSigned.value = true
    if (st && st.certTrusted) certTrusted.value = true
  } catch { /* 状态获取失败不阻断登录页 */ }
  loadCred() // 回填记住的账号密码(必须在拉码值之前, 码值按用户名取)
  await fetchCode()
  startFATimer()
})
onBeforeUnmount(() => { if (faTimer) clearInterval(faTimer) })
</script>

<template>
  <div class="page-login">
    <!-- 语言切换(2026-10-03): 登录页无 Layout 外壳, 切换器放页面右上角 -->
    <button class="lang-toggle" @click="toggleLocale" :title="locale === 'zh' ? t('lang.toEn') : t('lang.toZh')">{{ locale === 'zh' ? 'English' : '中文' }}</button>
    <form class="login-card" @submit.prevent="doLogin">
      <!-- 证书安装引导条: 自签部署(selfSigned)且根证书未装入信任存储(certTrusted=false,
           后端读系统证书存储判定)时显示; 装好证书刷新页面即自动消失, 卸载后自动回显。
           未"稍后再说"(本标签页)且未"不再提示"(永久兜底)时可见; 登录成功后离开本页
           即不再出现。不拦截登录(按钮均 type=button)。 -->
      <div v-if="showCertWarn" class="cert-warn">
        <div class="cert-warn-top">
          <div class="cert-warn-main">
            <svg class="cert-warn-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24"
                 viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
              <path d="M12 8v4"/><path d="M12 16h.01"/>
            </svg>
            <p class="cert-warn-text">{{ t('login.certWarn') }}</p>
          </div>
          <div class="cert-warn-actions">
            <button type="button" class="cert-install" :disabled="certDownloading" @click="downloadCertTool">
              {{ certDownloading ? t('login.certDownloading') : t('login.certInstall') }}
            </button>
            <button type="button" class="cert-later" @click="ackCert">{{ t('login.certAck') }}</button>
            <button type="button" class="cert-later" @click="laterCert">{{ t('login.certLater') }}</button>
          </div>
        </div>
      </div>

      <div class="brand">
        <h1>御视 <span class="en">Yugsight</span></h1>
        <p class="sub">{{ t('login.sub') }}</p>
      </div>

      <label class="fld">
        <span>{{ t('login.account') }}</span>
        <input v-model.trim="user" autocomplete="username" :placeholder="t('login.accountPh')" />
      </label>
      <label class="fld">
        <span>{{ t('login.password') }}</span>
        <div class="pw-wrap">
          <input v-model="pass" :type="showPass ? 'text' : 'password'" autocomplete="current-password" :placeholder="t('login.passwordPh')" />
          <button type="button" class="pw-toggle" :class="{ on: showPass }" @click="showPass = !showPass"
                  :title="showPass ? t('login.hidePass') : t('login.showPass')">
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
          <span>{{ t('login.faTitle') }}</span>
          <span class="fa-remain">{{ t('login.faRemain', { sec: fa.remain }) }}</span>
        </div>
        <div class="fa-show" :class="{ clickable: clickFillOn }" @click="fillCode"
             :title="clickFillOn ? t('login.faHint') : ''">{{ fa.code || '······' }}</div>
        <div class="fa-hint">{{ clickFillOn ? t('login.faHint') : t('login.faHintOff') }}</div>
        <input v-model="code" class="code-input" inputmode="numeric" maxlength="6"
               autocomplete="one-time-code" :placeholder="t('login.faPh')" />
      </div>

      <div class="opts">
        <label class="opt"><input v-model="remember" type="checkbox" /> {{ t('login.remember') }}</label>
      </div>

      <p v-if="err" class="err">{{ err }}</p>
      <p v-if="msg" class="ok">{{ msg }}</p>
      <button class="btn" type="submit" :disabled="loading">
        {{ loading ? t('login.logging') : t('login.loginBtn') }}
      </button>

      <!-- 2026-09-27: 探针安装包下载入口(醒目位置, 用户明确要求)。
           用同源相对路径: 跟随当前浏览器地址(https/任意 IP 均正确, 换 IP 不用改)。
           该接口已移除登录校验, 未登录的操作者也能直接打开页面下载安装包。
           2026-09-29: 原写死 http://192.168.1.143:8420, 切 HTTPS 后失效, 改同源相对路径。 -->
      <a class="agent-dl" href="/api/v2/probe/agent/install" target="_blank" rel="noreferrer">
        {{ t('login.agentDl') }}
      </a>
    </form>
    <p class="foot">{{ t('login.foot') }}
      · <a class="quit-link" href="javascript:void(0)" @click="quitService">{{ t('login.quit') }}</a>
    </p>
  </div>
</template>

<style scoped>
.page-login { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px; background: var(--bg, #0d1220); }
.login-card { width: 360px; max-width: 92vw; background: var(--panel, #131a2c); border: 1px solid var(--line, #232c45); border-radius: 12px; padding: 28px 26px; display: flex; flex-direction: column; gap: 14px; }
/* 证书信任警示条: 登录卡顶部通栏(负边距抵消卡片内边距, 撑满卡片宽), 浅黄底 + 顶部
   描边, 与系统深色风格区分但不突兀。 */
.cert-warn { margin: -28px -26px 0; padding: 14px 16px 12px; background: #fbf3d0; border-top: 3px solid #e6a700; border-bottom: 1px solid var(--line, #232c45); border-radius: 11px 11px 0 0; }
.cert-warn-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.cert-warn-main { display: flex; align-items: flex-start; gap: 10px; flex: 1; min-width: 0; }
.cert-warn-icon { width: 20px; height: 20px; color: #b8860b; flex-shrink: 0; margin-top: 1px; }
.cert-warn-text { margin: 0; font-size: 13px; line-height: 1.5; color: #6b5900; }
.cert-warn-actions { display: flex; flex-direction: column; gap: 6px; align-items: flex-end; flex-shrink: 0; }
.cert-install { background: var(--accent, #4c8dff); color: #fff; border: 0; border-radius: 6px; padding: 6px 16px; font-size: 13px; cursor: pointer; }
.cert-install:hover { filter: brightness(1.08); }
.cert-install:disabled { opacity: .7; cursor: default; }
.cert-later { background: none; border: 0; color: var(--dim, #7d8db0); font-size: 12px; cursor: pointer; padding: 2px 4px; }
.cert-later:hover { color: var(--fg, #e8ecf5); text-decoration: underline; }

/* 语言切换(2026-10-03): 页面右上角轻量按钮, 显示"目标语言" */
.lang-toggle { position: fixed; top: 14px; right: 18px; background: none; border: 1px solid var(--line, #232c45); border-radius: 6px; color: var(--dim, #7d8db0); font-size: 12px; padding: 3px 10px; cursor: pointer; z-index: 10; }
.lang-toggle:hover { color: var(--fg, #e8ecf5); border-color: var(--accent, #4c8dff); }

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
.fa-show { font-size: 20px; letter-spacing: 10px; text-align: center; color: var(--accent, #4c8dff); font-family: monospace; padding: 2px 0; user-select: none; transition: color .15s, transform .1s; }
/* 点击自动填入开关关闭时: 无手型光标/无 hover 反馈(授权与模型页可重新开启) */
.fa-show.clickable { cursor: pointer; }
.fa-show.clickable:hover { color: var(--fg, #e8ecf5); transform: translateY(-1px); }
.fa-hint { font-size: 11px; color: var(--dim, #7d8db0); text-align: center; }
.code-input { letter-spacing: 8px; text-align: center; font-size: 20px; }
.opts { display: flex; flex-direction: column; gap: 6px; }
.opt { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--dim, #7d8db0); cursor: pointer; }
.err { margin: 0; font-size: 12px; color: var(--danger, #ff6b6b); }
.ok { margin: 0; font-size: 12px; color: var(--accent, #4c8dff); }
.btn { background: var(--accent, #4c8dff); border: 0; border-radius: 8px; padding: 11px 0; color: #fff; font-size: 14px; cursor: pointer; }
.btn:disabled { opacity: .6; cursor: default; }
/* 探针安装包下载入口(2026-09-27): 登录页醒目位置, 免登录直开安装落地页 */
.agent-dl { display: block; text-align: center; text-decoration: none; font-size: 13px; color: var(--accent, #4c8dff); border: 1px dashed var(--accent, #4c8dff); border-radius: 8px; padding: 9px 10px; transition: background .15s, color .15s; }
.agent-dl:hover { background: rgba(76, 141, 255, .1); color: var(--fg, #e8ecf5); }
.foot { font-size: 12px; color: var(--dim, #7d8db0); }
.quit-link { color: var(--danger, #ff6b6b); text-decoration: none; }
.quit-link:hover { text-decoration: underline; }
</style>
