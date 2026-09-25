// 统一 HTTP 封装(纯 fetch, 无第三方库):
// - api(): 旧版 /api/* 接口(原始 JSON; 错误体为 {error})
// - v2():  /api/v2/* 接口(统一响应 Resp{code,message,data}, code=0 成功)
// 401 统一跳登录页(cookie 由 Go 端设置, fetch 自动携带)
import router from '../router'
import { resetAuth } from '../auth'

let redirecting = false

async function onUnauth() {
  resetAuth()
  if (!redirecting && router.currentRoute.value.path !== '/login') {
    redirecting = true
    router.push('/login').finally(() => { redirecting = false })
  }
}

async function doFetch(path, { method = 'GET', body } = {}) {
  const opt = { method, headers: {} }
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json'
    opt.body = JSON.stringify(body)
  }
  const r = await fetch(path, opt)
  const text = await r.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch (e) { data = text }
  if (!r.ok) {
    // 401 先解响应体再分流: 登录接口的 need2fa(口令已通过, 待输动态码)也是
    // 401, 不能与会话失效混为一谈触发跳转 —— 带 need2fa 标记时交给调用方处理
    if (r.status === 401 && !(data && data.need2fa)) await onUnauth()
    const msg = (data && typeof data === 'object' && (data.error || data.message))
      || (r.status === 401 ? '未登录' : 'HTTP ' + r.status)
    // 业务标记(need2fa)与状态码挂到错误对象, 供登录页两步流转
    const err = new Error(msg)
    err.body = data
    err.status = r.status
    throw err
  }
  return data
}

// 旧版接口: 直接返回 JSON 体
export function api(path, opt) {
  return doFetch(path, opt)
}

// v2 接口: 拆包 Resp, code!=0 抛错误(message), 返回 data
export async function v2(path, opt = {}) {
  const d = await doFetch('/api/v2' + path, opt)
  if (d && typeof d === 'object' && 'code' in d) {
    if (d.code !== 0) throw new Error(d.message || `请求失败(code=${d.code})`)
    return d.data
  }
  return d
}

// v2dash: 用 v2 统一信封但路径不在 /api/v2 前缀下的数据端点(如 /api/dashboard/flows)。
// 与 v2 唯一区别是不加 /api/v2 前缀, 信封拆包逻辑一致。
export async function v2dash(path, opt = {}) {
  const d = await doFetch(path, opt)
  if (d && typeof d === 'object' && 'code' in d) {
    if (d.code !== 0) throw new Error(d.message || `request failed(code=${d.code})`)
    return d.data
  }
  return d
}
