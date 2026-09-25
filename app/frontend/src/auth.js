// 登录态(复用 Go 端 yugsight_session cookie; /api/whoami 免注册校验)
// role 与 user 一起缓存: 路由守卫与侧边栏菜单需要在同步阶段就知道角色,
// 每次渲染都异步问后端会让"授权管理"菜单先出现再消失(闪烁)。
//
// 【为什么用 ref 而不是普通模块变量(2026-09-23 修复"刷新后用户: local")】
// App.vue 里 <Layout> 在路由守卫解析之前就挂载(它在 router-view 外层),
// 整页刷新时守卫里的 whoami 是异步的 —— 组件 setup 若用 `ref(getUser())`
// 快照普通模块变量, 拿到的是 whoami 返回前的 null, 之后模块变量更新了
// 组件也不会再变, 顶栏永远显示 "用户: local", 管理员的授权管理菜单也
// 被 isAdmin() 快照成 false 藏掉。登录时不暴露这个问题, 因为 setUser()
// 发生在导航之前(Layout 重新挂载时快照恰好有值)。
// 现在登录态本身是响应式的: whoami 返回后所有绑定处(顶栏用户/角色菜单)
// 自动更新, 不需要组件自己再发一次请求。
//
// 【为什么负结果(401)不缓存】只缓存"已登录"。未登录态若被缓存, 用户刚登录成功
// (cookie 是登录后才写上的)再次导航时守卫会直接返回 false, 把人打回登录页 ——
// 全新浏览器"登录成功却进不去"就是这个坑。未登录时每次导航多一次 whoami 请求,
// 代价可忽略。
import { ref } from 'vue'

const user = ref(null)
const role = ref(null)

// currentUser 供模板直接绑定的响应式句别(顶栏"用户: xx"用它, 而非快照)。
// 未解析(null)与"免登录模式的 local"是两种含义, 模板里分别显示 '-' 与 'local'。
export const currentUser = user

export async function requireLogin() {
  if (user.value !== null) return true
  try {
    // no-store: 登录前的 401 不能被浏览器缓存, 否则登录成功后重试仍命中旧 401
    const r = await fetch('/api/whoami', { cache: 'no-store' })
    if (r.status === 401) {
      user.value = null
      role.value = null
      return false
    }
    const d = await r.json().catch(() => ({}))
    user.value = d.user || 'local'
    role.value = d.role || 'admin'
    return true
  } catch (e) {
    // 网络异常不拦截(与经典页一致: 允许进入, 接口层再处理)
    return user.value !== null
  }
}

export function setUser(u, r) {
  user.value = u
  if (r) role.value = r
}

export function getUser() {
  return user.value
}

// getRole 当前角色(admin/operator/auditor); 未登录或未解析时返回空串
export function getRole() {
  return role.value || ''
}

// isAdmin 仅管理员 —— "授权管理"页与用户管理入口的判定口径。
// 注意: 操作员(operator)在业务页面上与管理员等价, 但进不了授权管理页。
export function isAdmin() {
  return role.value === 'admin'
}

export function resetAuth() {
  user.value = null
  role.value = null
}
