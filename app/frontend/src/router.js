import { createRouter, createWebHashHistory } from 'vue-router'
import { requireLogin, getRole } from './auth'

// hash 路由: 单文件 exe 嵌入场景下无需服务端 history 回退, 刷新/深链均直接可用
const routes = [
  { path: '/login', component: () => import('./pages/Login.vue'), meta: { public: true, title: '登录' } },
  // 首次注册: 仅在未注册时由登录页自动跳转(registered=false), 手动访问无意义
  { path: '/register', component: () => import('./pages/Register.vue'), meta: { public: true, title: '创建账号' } },
  { path: '/', component: () => import('./pages/Dashboard.vue'), meta: { title: '首页仪表盘' } },
  { path: '/assets', component: () => import('./pages/Assets.vue'), meta: { title: '资产管理' } },
  // 菜单 B 方案(2026-09-22): 「实时扫描控制台」+「扫描任务管理」合并为 /console 两 tab,
  // 旧 /scans 保留为重定向(先例 /rules → /env?tab=rules): 书签/外链不失效, 打开即落在任务队列 tab
  { path: '/scans', redirect: { path: '/console', query: { tab: 'queue' } }, meta: { title: '扫描作业' } },
  { path: '/console', component: () => import('./pages/Console.vue'), meta: { title: '扫描作业' } },
  { path: '/weakpass', component: () => import('./pages/Weakpass.vue'), meta: { title: '弱口令检测' } },
  // 阶段 5: 渗透工作台(仅 admin —— 攻击性能力, operator/auditor 无入口无权限;
  // 与扫描模块物理隔离: 扫描只发现, 渗透只做已知漏洞的验证)。
  // meta.admin 守卫同 /license: 角色未知时不拦, 真边界在后端 adminOnly 中间件。
  { path: '/penta', component: () => import('./pages/PentaWorkbench.vue'), meta: { title: '渗透工作台', admin: true } },
  // UX 审计 §5.2: 引擎状态 + 规则库管理合并为一页(Engrules.vue 内两 tab)
  { path: '/env', component: () => import('./pages/Engrules.vue'), meta: { title: '引擎与规则' } },
  // 旧 /rules 路由保留为重定向: 书签/外链不失效, 打开即落在规则 tab(query 驱动, 见 Engrules.vue)
  { path: '/rules', redirect: { path: '/env', query: { tab: 'rules' } }, meta: { title: '引擎与规则' } },
  // 节点监控(阶段 1): 探针节点管理 + 网络设备监控合并为一页(内两 Tab, 同 Engrules 口径)。
  // 旧 /probes、/monitor 路由保留为重定向: 书签/外链不失效, 打开即落在对应 Tab。
  { path: '/nodemonitor', component: () => import('./pages/NodeMonitor.vue'), meta: { title: '节点监控' } },
  { path: '/probes', redirect: { path: '/nodemonitor' }, meta: { title: '节点监控' } },
  { path: '/capture', component: () => import('./pages/Capture.vue'), meta: { title: '实时抓包分析' } },
  { path: '/monitor', redirect: { path: '/nodemonitor', query: { tab: 'net' } }, meta: { title: '节点监控' } },
  { path: '/vulns', component: () => import('./pages/Vulns.vue'), meta: { title: '漏洞管理' } },
  { path: '/vulns/:id', component: () => import('./pages/VulnDetail.vue'), meta: { title: '漏洞详情' } },

  // 漏扫管控(白名单/误报/置信度): 路由路径保持 /whitelist 不变以免破坏书签, 仅改展示名
  { path: '/whitelist', component: () => import('./pages/Whitelist.vue'), meta: { title: '漏扫管控' } },
  { path: '/reports', component: () => import('./pages/Reports.vue'), meta: { title: '报告中心' } },
  // 阶段 3: AI 配置(系统配置分组, 用户指定路由 /settings/ai)。
  // 只管配置(参数/模板/文档库/记忆库), 分析触发入口在各业务页面。
  { path: '/settings/ai', component: () => import('./pages/AICfg.vue'), meta: { title: 'AI 配置' } },
  // 授权管理 = admin 专属(用户/会话/审计清理); 操作员与只读角色进不去 →
  // meta.admin 由下方守卫拦截并回首页, 侧边栏菜单同步隐藏
  { path: '/license', component: () => import('./pages/License.vue'), meta: { title: '授权管理', admin: true } },
  // 阶段 4: 安全大屏并入首页仪表盘内建 Tab2(页面内嵌, 不再是独立全屏页)。
  // 旧 /bigscreen 保留为重定向(先例 /scans → /console?tab=queue): 书签/外链不失效。
  { path: '/bigscreen', redirect: { path: '/', query: { tab: 'screen' } }, meta: { title: '安全大屏' } },
  { path: '/:pathMatch(.*)*', redirect: '/' }
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

// 登录守卫: 复用 Go 端 yugsight_session cookie(/api/whoami), 未登录一律进登录页
router.beforeEach(async (to) => {
  if (to.meta.public) return true
  if (!(await requireLogin())) return { path: '/login', query: { from: to.fullPath } }
  // admin 专属路由: 角色未知(空串, 如 whoami 异常)时不拦 —— 真正的权限边界是
  // 后端 adminOnly 中间件, 这里只是让操作员有个明确落点而不是白屏/403 弹窗。
  if (to.meta.admin && getRole() && getRole() !== 'admin') return { path: '/' }
  return true
})

router.afterEach((to) => {
  document.title = (to.meta.title ? to.meta.title + ' - ' : '') + 'Yugsight'
})

export default router
