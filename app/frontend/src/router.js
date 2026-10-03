import { createRouter, createWebHashHistory } from 'vue-router'
import { requireLogin, getRole } from './auth'
import { t } from './i18n'

// hash 路由: 单文件 exe 嵌入场景下无需服务端 history 回退, 刷新/深链均直接可用
// titleKey = 页面标题的 i18n 键(menu.*); meta.title 保留作中文兜底(键缺失时回落)
const routes = [
  { path: '/login', component: () => import('./pages/Login.vue'), meta: { public: true, title: '登录', titleKey: 'menu.login' } },
  // 首次注册: 仅在未注册时由登录页自动跳转(registered=false), 手动访问无意义
  { path: '/register', component: () => import('./pages/Register.vue'), meta: { public: true, title: '创建账号', titleKey: 'menu.register' } },
  { path: '/', component: () => import('./pages/Dashboard.vue'), meta: { title: '首页仪表盘', titleKey: 'menu.dashboard' } },
  { path: '/assets', component: () => import('./pages/Assets.vue'), meta: { title: '资产管理', titleKey: 'menu.assets' } },
  // 菜单 B 方案(2026-09-22): 「实时扫描控制台」+「扫描任务管理」合并为 /console 两 tab,
  // 旧 /scans 保留为重定向(先例 /rules → /env?tab=rules): 书签/外链不失效, 打开即落在任务队列 tab
  { path: '/scans', redirect: { path: '/console', query: { tab: 'queue' } }, meta: { title: '扫描控制台', titleKey: 'menu.console' } },
  { path: '/console', component: () => import('./pages/Console.vue'), meta: { title: '扫描控制台', titleKey: 'menu.console' } },
  // 2026-09-25 四轮换口径: "扫描作业"页面已去掉 —— 命名扫描任务就是控制台
  // 立即扫描 + 任务名(任务名+IP/子网 快速发现 → 勾选主机做主机漏扫/web漏扫/
  // 弱口令/渗透), 报告中心按任务名生成报告 / 分类原始报告。
  { path: '/weakpass', component: () => import('./pages/Weakpass.vue'), meta: { title: '弱口令检测', titleKey: 'menu.weakpass' } },
  // 阶段 5: 渗透工作台(仅 admin —— 攻击性能力, operator/auditor 无入口无权限;
  // 与扫描模块物理隔离: 扫描只发现, 渗透只做已知漏洞的验证)。
  // meta.admin 守卫同 /license: 角色未知时不拦, 真边界在后端 adminOnly 中间件。
  { path: '/penta', component: () => import('./pages/PentaWorkbench.vue'), meta: { title: '渗透工作台', admin: true, titleKey: 'menu.penta' } },
  // UX 审计 §5.2: 引擎状态 + 规则库管理合并为一页(Engrules.vue 内两 tab)
  { path: '/env', component: () => import('./pages/Engrules.vue'), meta: { title: '引擎与规则', titleKey: 'menu.env' } },
  // 旧 /rules 路由保留为重定向: 书签/外链不失效, 打开即落在规则 tab(query 驱动, 见 Engrules.vue)
  { path: '/rules', redirect: { path: '/env', query: { tab: 'rules' } }, meta: { title: '引擎与规则', titleKey: 'menu.env' } },
  // 节点监控(阶段 1): 探针节点管理 + 网络设备监控合并为一页(内两 Tab, 同 Engrules 口径)。
  // 旧 /probes、/monitor 路由保留为重定向: 书签/外链不失效, 打开即落在对应 Tab。
  { path: '/nodemonitor', component: () => import('./pages/NodeMonitor.vue'), meta: { title: '节点监控', titleKey: 'menu.nodemonitor' } },
  { path: '/probes', redirect: { path: '/nodemonitor' }, meta: { title: '节点监控', titleKey: 'menu.nodemonitor' } },
  { path: '/capture', component: () => import('./pages/Capture.vue'), meta: { title: '实时抓包分析', titleKey: 'menu.capture' } },
  { path: '/monitor', redirect: { path: '/nodemonitor', query: { tab: 'net' } }, meta: { title: '节点监控', titleKey: 'menu.nodemonitor' } },
  { path: '/vulns', component: () => import('./pages/Vulns.vue'), meta: { title: '漏洞管理', titleKey: 'menu.vulns' } },
  { path: '/vulns/:id', component: () => import('./pages/VulnDetail.vue'), meta: { title: '漏洞详情', titleKey: 'menu.vulnDetail' } },

  // 漏扫管控并入漏洞管理(2026-09-26): /whitelist 重定向到 /vulns?tab=control(旧书签不失效)
  { path: '/whitelist', redirect: { path: '/vulns', query: { tab: 'control' } }, meta: { title: '漏洞管理', titleKey: 'menu.vulns' } },
  { path: '/reports', component: () => import('./pages/Reports.vue'), meta: { title: '报告中心', titleKey: 'menu.reports' } },
  // 版权信息(2026-09-25): 版本号从顶栏移到这里常驻(左上方菜单入口)
  { path: '/copyright', component: () => import('./pages/Copyright.vue'), meta: { title: '版权信息', titleKey: 'menu.copyright' } },
  // 2026-09-28: 独立网络拓扑页(套 Layout 外壳, 不加 meta.full; 全屏由页内按钮触发)。
  // 2026-09-29: 一级菜单与节点监控内嵌入口按用户要求移除 —— 唯一入口=安全大屏的
  // 网络拓扑卡(TopoCard, 卡内「⤢ 全屏」跳转本页); 本页保留供跳转与深链。
  // 2026-09-30 用户要求: 页面改名"网络拓扑"(去掉 3D), 3D 三维视图移除, 只剩当前画布(2D)。
  { path: '/topology/3d', component: () => import('./pages/NetworkTopology3d.vue'), meta: { title: '网络拓扑', titleKey: 'menu.topology' } },
  // 阶段 3: AI 配置(系统配置分组, 用户指定路由 /settings/ai)。
  // 只管配置(参数/模板/文档库/记忆库), 分析触发入口在各业务页面。
  // AI 配置并入授权与模型(2026-09-26): /settings/ai 重定向到 /license?tab=ai(旧书签不失效; /license 为 admin 专属)
  { path: '/settings/ai', redirect: { path: '/license', query: { tab: 'ai' } }, meta: { title: '授权与模型', titleKey: 'menu.license' } },
  // 授权与模型 = admin 专属(用户/会话/审计清理); 操作员与只读角色进不去 →
  // meta.admin 由下方守卫拦截并回首页, 侧边栏菜单同步隐藏
  { path: '/license', component: () => import('./pages/License.vue'), meta: { title: '授权与模型', admin: true, titleKey: 'menu.license' } },
  // 阶段 4: 安全大屏并入首页仪表盘内建 Tab2(页面内嵌, 不再是独立全屏页)。
  // 2026-09-28: 旧 /bigscreen 重定向随仪表盘 Tab2 一并删除(Tab2 已迁至独立页
  // /bigscreen-pro)。此处不留死路由: 落到一个不存在的 tab 会让书签打开后停在空白页。
  // 2026-09-27: 安全大屏 Pro —— 一级菜单「安全大屏」入口, 套 Layout 外壳站内跳转
  // (保留左侧菜单/顶部导航; 用户反馈: 之前的 meta.full 全屏脱离外壳, 像"打开新页面"
  // 而非"转跳过去")。画布仍通过「一键全屏」按钮进入真正的浏览器全屏(投屏场景)。
  // 与旧 /bigscreen(仪表盘 Tab2)并存: 两个入口各走各的, 旧重定向语义不变。
  { path: '/bigscreen-pro', component: () => import('./pages/BigScreenPro.vue'), meta: { title: '安全大屏', titleKey: 'menu.bigscreen' } },
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

// 页面标题跟随当前语言(titleKey → i18n; 缺键时回落中文 meta.title)
router.afterEach((to) => {
  const name = to.meta.titleKey ? t(to.meta.titleKey) : (to.meta.title || '')
  document.title = (name ? name + ' - ' : '') + 'Yugsight'
})

export default router
