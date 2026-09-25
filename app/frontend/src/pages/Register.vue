<script setup>
// Register 首次注册页: 创建首个管理员账号(绑定本机设备 + 生成迁移密钥)。
// 仅在"未注册"时由 Login 页自动跳转过来(见 Login.vue onMounted 的 registered 判定)。
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api/http.js'

const router = useRouter()
const user = ref('')
const pass = ref('')
const pass2 = ref('')
const err = ref('')
const loading = ref(false)

async function doRegister() {
  if (loading.value) return
  err.value = ''
  if (!user.value || !pass.value) { err.value = '请输入账号和密码'; return }
  if (pass.value.length < 6) { err.value = '密码至少 6 位'; return }
  if (pass.value !== pass2.value) { err.value = '两次输入的密码不一致'; return }
  loading.value = true
  try {
    await api('/api/register', {
      method: 'POST',
      body: { user: user.value, pass: pass.value, pass2: pass2.value }
    })
    router.push('/login')
  } catch (e) {
    err.value = (e && e.message) || '注册失败'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="page-login">
    <form class="login-card" @submit.prevent="doRegister">
      <div class="brand">
        <h1>御视 <span class="en">Yugsight</span></h1>
        <p class="sub">首次使用 · 创建管理员账号</p>
      </div>

      <label class="fld">
        <span>账号</span>
        <input v-model.trim="user" autocomplete="username" placeholder="管理员账号" />
      </label>
      <label class="fld">
        <span>密码</span>
        <input v-model="pass" type="password" autocomplete="new-password" placeholder="至少 6 位" />
      </label>
      <label class="fld">
        <span>确认密码</span>
        <input v-model="pass2" type="password" autocomplete="new-password" placeholder="再次输入密码" />
      </label>

      <p v-if="err" class="err">{{ err }}</p>
      <button class="btn" type="submit" :disabled="loading">
        {{ loading ? '创建中...' : '创建账号' }}
      </button>
      <a class="back" href="#/login">← 返回登录</a>
    </form>
    <p class="foot">Yugsight · 离线本地部署 · 注册信息仅存本机</p>
  </div>
</template>

<style scoped>
.page-login { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px; background: var(--bg, #0d1220); }
.login-card { width: 360px; max-width: 92vw; background: var(--panel, #131a2c); border: 1px solid var(--line, #232c45); border-radius: 12px; padding: 28px 26px; display: flex; flex-direction: column; gap: 14px; }
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
