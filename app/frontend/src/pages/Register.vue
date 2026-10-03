<script setup>
// Register 首次注册页: 创建首个管理员账号(绑定本机设备 + 生成迁移密钥)。
// 仅在"未注册"时由 Login 页自动跳转过来(见 Login.vue onMounted 的 registered 判定)。
// 2026-10-03: 文案接入 i18n, 语言切换按钮同 Login 页(页面右上角)。
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api/http.js'
import { t, locale, toggleLocale } from '../i18n'

const router = useRouter()
const user = ref('')
const pass = ref('')
const pass2 = ref('')
const err = ref('')
const loading = ref(false)

async function doRegister() {
  if (loading.value) return
  err.value = ''
  if (!user.value || !pass.value) { err.value = t('register.errNeedCred'); return }
  if (pass.value.length < 6) { err.value = t('register.errPassShort'); return }
  if (pass.value !== pass2.value) { err.value = t('register.errPassMismatch'); return }
  loading.value = true
  try {
    await api('/api/register', {
      method: 'POST',
      body: { user: user.value, pass: pass.value, pass2: pass2.value }
    })
    router.push('/login')
  } catch (e) {
    // 后端错误消息暂为中文, 未纳入 i18n
    err.value = (e && e.message) || t('register.errFail')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="page-login">
    <button class="lang-toggle" @click="toggleLocale" :title="locale === 'zh' ? t('lang.toEn') : t('lang.toZh')">{{ locale === 'zh' ? 'English' : '中文' }}</button>
    <form class="login-card" @submit.prevent="doRegister">
      <div class="brand">
        <h1>御视 <span class="en">Yugsight</span></h1>
        <p class="sub">{{ t('register.sub') }}</p>
      </div>

      <label class="fld">
        <span>{{ t('login.account') }}</span>
        <input v-model.trim="user" autocomplete="username" :placeholder="t('login.accountPh')" />
      </label>
      <label class="fld">
        <span>{{ t('login.password') }}</span>
        <input v-model="pass" type="password" autocomplete="new-password" :placeholder="t('register.passPh2')" />
      </label>
      <label class="fld">
        <span>{{ t('register.confirmPass') }}</span>
        <input v-model="pass2" type="password" autocomplete="new-password" :placeholder="t('register.passPh3')" />
      </label>

      <p v-if="err" class="err">{{ err }}</p>
      <button class="btn" type="submit" :disabled="loading">
        {{ loading ? t('register.creating') : t('register.createBtn') }}
      </button>
      <a class="back" href="#/login">{{ t('register.back') }}</a>
    </form>
    <p class="foot">{{ t('register.foot') }}</p>
  </div>
</template>

<style scoped>
.page-login { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px; background: var(--bg, #0d1220); }
.login-card { width: 360px; max-width: 92vw; background: var(--panel, #131a2c); border: 1px solid var(--line, #232c45); border-radius: 12px; padding: 28px 26px; display: flex; flex-direction: column; gap: 14px; }
/* 语言切换(2026-10-03): 页面右上角轻量按钮, 与 Login 页同款式 */
.lang-toggle { position: fixed; top: 14px; right: 18px; background: none; border: 1px solid var(--line, #232c45); border-radius: 6px; color: var(--dim, #7d8db0); font-size: 12px; padding: 3px 10px; cursor: pointer; z-index: 10; }
.lang-toggle:hover { color: var(--fg, #e8ecf5); border-color: var(--accent, #4c8dff); }
.brand h1 { margin: 0; font-size: 22px; color: var(--fg, #e8ecf5); }
.brand .en { font-size: 15px; color: var(--dim, #7d8db0); font-weight: 400; }
.brand .sub { margin: 4px 0 0; font-size: 12px; color: var(--dim, #7d8db0); }
.fld { display: flex; flex-direction: column; gap: 6px; font-size: 13px; color: var(--dim, #7d8db0); }
.fld input { background: var(--input, #0d1220); border: 1px solid var(--line, #232c45); border-radius: 8px; padding: 10px 12px; color: var(--fg, #e8ecf5); font-size: 14px; outline: none; }
.fld input:focus { border-color: var(--accent, #4c8dff); }
.err { margin: 0; font-size: 12px; color: var(--danger, #ff6b6b); }
.btn { background: var(--accent, #4c8dff); border: 0; border-radius: 8px; padding: 11px 0; color: #fff; font-size: 14px; cursor: pointer; }
.btn:disabled { opacity: .6; cursor: default; }
.back { font-size: 12px; color: var(--dim, #7d8db0); text-align: center; text-decoration: none; }
.back:hover { color: var(--fg, #e8ecf5); }
.foot { font-size: 12px; color: var(--dim, #7d8db0); }
</style>
