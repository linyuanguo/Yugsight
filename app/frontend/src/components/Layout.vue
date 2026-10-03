<template>
  <div class="layout" :class="{ collapsed }">
    <aside class="sidebar">
      <!-- 品牌区(2026-09-25 二轮): logo+名称整体居中, 名称后跟版本号,
           点击整块跳到版权信息页(用户: "点击这个位置会跳转到版权 licence 页面") -->
      <div class="brand-wrap" @click="goCopyright" :title="collapsed ? '版权信息' : '点击查看版权信息'">
        <div class="logo">YS</div>
        <!-- 品牌自定义(2026-09-28): 系统名称 = settings.json brand 节,
             缺省 = 原始项目名; 与浏览器标签页标题同源(/api/info.brandName) -->
        <div class="brand">{{ brandName }}<span class="brand-ver" v-if="ver">v{{ ver }}</span><span class="brand-sub">安服管理平台</span></div>
      </div>
      <nav>
        <!-- 菜单(2026-09-23 阶段 4; 2026-09-27 分组分隔线化 + 调序): 5 组 11 项。
             2026-09-27 调序(用户要求): 报告中心移到扫描控制台下面(进扫描作业组);
             弱口令检测移到渗透工作台下面(进渗透测试组)。
             组标题(运维总览/扫描作业/渗透测试/资产与风险/诊断与观测/系统配置)
             由文字改为分隔线(.nav-sep): 用户要求去掉组标题字, 用分隔线区分分组;
             第一组不放分隔线(品牌区即视觉分隔)。
             底部「关于/版权信息」独立菜单项删除: 版权入口 = 点顶部品牌区(goCopyright),
             版本号仍在品牌区常驻(brand-ver)。
             阶段 3 的「实时扫描控制台 + 扫描任务管理」合并为「扫描作业」(/console 两 tab);
             「扫描控制」改名「漏扫管控」;
             「探针管理」+「网络监控 (SNMP)」合并为「节点监控」(/nodemonitor 内两 Tab);
             系统配置组: 引擎与规则 + AI 配置 + 授权与模型(admin)。
             阶段 4: 独立「安全大屏」菜单项移除 —— 大屏并入「首页仪表盘」内建 Tab2
             (2026-09-28: 仪表盘内嵌 Tab2 与旧 /bigscreen 已删除, 入口统一为本站 /bigscreen-pro)。 -->
        <!-- 运维总览组(第一组, 无分隔线)
             首页仪表盘内置两个 Tab: 概览仪表盘 + 安全大屏(原独立大屏页能力全量迁入)
             安全大屏 Pro(2026-09-27): 独立全屏页(meta.full 不套外壳), 一级菜单与仪表盘同级、在其下 -->
        <router-link class="nav-item" to="/" :title="collapsed ? '首页仪表盘' : ''"><span class="nav-dot"></span><span class="nav-ico">首</span><span class="nav-label">首页仪表盘</span></router-link>
        <router-link class="nav-item" to="/bigscreen-pro" :title="collapsed ? '安全大屏' : ''"><span class="nav-dot"></span><span class="nav-ico">屏</span><span class="nav-label">安全大屏</span></router-link>
        <!-- 2026-09-29 用户要求: 一级菜单不再单列「网络拓扑」—— 入口收敛为安全大屏里的
             网络拓扑卡(卡内「⤢ 全屏」进 /topology/3d 独立页, 路由保留) -->

        <div class="nav-sep"></div><!-- 组: 扫描作业(2026-09-27: 报告中心自运维总览调入, 排在扫描控制台下) -->
        <!-- 2026-09-25 四轮换口径: 独立"扫描作业"页去掉 —— 命名扫描任务就在
             扫描控制台的立即扫描里(任务名 + IP/子网 → 快速发现 → 勾选主机做
             主机漏扫/web漏扫/弱口令/渗透), 报告中心按任务名生成报告。 -->
        <router-link class="nav-item" to="/console" :title="collapsed ? '扫描控制台' : ''"><span class="nav-dot"></span><span class="nav-ico">扫</span><span class="nav-label">扫描控制台</span></router-link>
        <router-link class="nav-item" to="/reports" :title="collapsed ? '报告中心' : ''"><span class="nav-dot"></span><span class="nav-ico">报</span><span class="nav-label">报告中心</span></router-link>

        <!-- 阶段 5: 渗透测试组(与扫描作业平级对称, 物理隔离入口)。
             2026-09-27 调序: 弱口令检测自扫描作业移入(排渗透工作台下);
             该条目本身不限 admin(operator/auditor 也可见);
             渗透工作台仅 admin —— 渗透是攻击性能力, 与 router.js 的 meta.admin 守卫双保险。 -->
        <div class="nav-sep"></div><!-- 组: 渗透测试 -->
        <router-link class="nav-item" v-if="admin" to="/penta" :title="collapsed ? '渗透工作台' : ''"><span class="nav-dot"></span><span class="nav-ico">渗</span><span class="nav-label">渗透工作台</span></router-link>
        <router-link class="nav-item" to="/weakpass" :title="collapsed ? '弱口令检测' : ''"><span class="nav-dot"></span><span class="nav-ico">弱</span><span class="nav-label">弱口令检测</span></router-link>

        <div class="nav-sep"></div><!-- 组: 资产与风险 -->
        <router-link class="nav-item" to="/assets" :title="collapsed ? '资产管理' : ''"><span class="nav-dot"></span><span class="nav-ico">资</span><span class="nav-label">资产管理</span></router-link>
        <!-- 2026-09-26: 漏扫管控并入漏洞管理(/vulns?tab=control), 菜单不再单列 -->
        <router-link class="nav-item" to="/vulns" :title="collapsed ? '漏洞管理' : ''"><span class="nav-dot"></span><span class="nav-ico">漏</span><span class="nav-label">漏洞管理</span></router-link>

        <div class="nav-sep"></div><!-- 组: 诊断与观测 -->
        <router-link class="nav-item" to="/capture" :title="collapsed ? '实时抓包分析' : ''"><span class="nav-dot"></span><span class="nav-ico">抓</span><span class="nav-label">实时抓包</span></router-link>
        <!-- 节点监控(阶段 1): 原「探针管理」(系统配置) + 「网络监控 (SNMP)」合并为内两 Tab 页面,
             旧 /probes、/monitor 路由保留重定向(见 router.js) -->
        <router-link class="nav-item" to="/nodemonitor" :title="collapsed ? '节点监控' : ''"><span class="nav-dot"></span><span class="nav-ico">监</span><span class="nav-label">节点监控</span></router-link>

        <div class="nav-sep"></div><!-- 组: 系统配置 -->
        <router-link class="nav-item" to="/env" :title="collapsed ? '引擎与规则' : ''"><span class="nav-dot"></span><span class="nav-ico">引</span><span class="nav-label">引擎与规则</span></router-link>
        <!-- 2026-09-26: AI 配置并入授权与模型(/license?tab=ai), 菜单不再单列 AI 配置 -->
        <!-- 授权与模型仅 admin 可见(操作员/只读进不去, 见 router.js 的 meta.admin 守卫) -->
        <router-link class="nav-item" v-if="admin" to="/license" :title="collapsed ? '授权与模型' : ''"><span class="nav-dot"></span><span class="nav-ico">授</span><span class="nav-label">授权与模型</span></router-link>

        <!-- 2026-09-27: 底部「关于/版权信息」菜单项删除(用户: 点顶部 logo 即有版权页链接,
             独立项多余); 版权入口保留为顶部品牌区点击(goCopyright), 版本号仍常驻品牌区 -->
      </nav>
    </aside>

    <div class="main-col">
      <header class="topbar">
        <button class="collapse-btn" @click="toggleCollapse" :title="collapsed ? '展开菜单' : '收起菜单'">{{ collapsed ? '»' : '«' }}</button>
        <div class="top-title">{{ route.meta.title || '' }}</div>
        <!-- 2026-09-25 口径调整: 顶栏右上角展示"系统当前时间"(每秒刷新, 确认服务
             进程活着且时钟正常); 版本号移入「版权信息」页(左上方菜单)。 -->
        <div class="top-right">
          <span class="chip blue mono" title="系统当前时间">{{ clock || '--:--:--' }}</span>
          <!-- user 为空 = whoami 未返回(加载中的瞬时态), 显示 '-';
               'local' 只可能来自免登录模式的服务端真实返回, 原样展示 -->
          <span class="chip">用户: {{ user || '-' }}</span>
          <button class="btn sm" @click="logout">退出登录</button>
        </div>
      </header>
      <main class="page-main"><slot /></main>
    </div>
    <!-- 小 Y 助手(2026-09-27): fixed 定位悬浮在 .layout 之上, 总开关关时不渲染 -->
    <AssistantWidget />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api/http'
import { currentUser, getRole, resetAuth } from '../auth'
// 小 Y 问答助手(2026-09-27): 全局悬浮入口, 总开关关闭时组件自身不渲染
import AssistantWidget from './AssistantWidget.vue'

const route = useRoute()
const router = useRouter()

// 系统当前时间(每秒刷新): 顶栏右上角常驻, 兼作"服务活着"的直观信号。
// 2026-09-25 二轮: 加上年月日 —— 运维看报告/截图时"哪天几点"比"几点"更有用。
// onBeforeUnmount 必须清定时器 —— 布局组件常驻, 但路由级 unmount 场景
// (如回到登录页)下不清会让 setInterval 泄漏。
const clock = ref('')
let clockTimer = null
function tickClock() {
  const d = new Date()
  const p = n => String(n).padStart(2, '0')
  clock.value = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
// user 直接绑定 auth 模块的响应式登录态(不能用 ref(getUser()) 快照:
// 整页刷新时本组件在路由守卫的 whoami 返回前就挂载, 快照永远是 null,
// 刷新后顶栏会一直显示 local —— 2026-09-23 修复)
const user = currentUser
// admin: "授权与模型"菜单可见性。必须 computed 跟随响应式角色 —— 快照式
// ref(isAdmin()) 在刷新场景下同样拿到守卫解析前的 false, 管理员菜单被藏。
const admin = computed(() => getRole() === 'admin')
const collapsed = ref(localStorage.getItem('ys_sidebar_collapsed') === '1')
function toggleCollapse() {
  collapsed.value = !collapsed.value
  try { localStorage.setItem('ys_sidebar_collapsed', collapsed.value ? '1' : '0') } catch (e) { /* 忽略 */ }
}
// 手机端: 侧边栏固定 218px, 375px 的屏幕上会占掉大半屏(2026-09-27 用户反馈
// 手机访问不协调)。宽度 <768 自动收起成 64px 图标栏(复用既有 collapsed 态样式),
// 回到宽屏再恢复用户的手动偏好。自动收起不写 localStorage —— 桌面/手机各自
// 记忆, 互不覆盖(手机上手动展开只影响当次会话, 下次进窄屏仍自动收)。
let narrowActive = false
function onViewportResize() {
  const narrow = window.innerWidth < 768
  if (narrow && !narrowActive) {
    narrowActive = true
    collapsed.value = true
  } else if (!narrow && narrowActive) {
    narrowActive = false
    collapsed.value = localStorage.getItem('ys_sidebar_collapsed') === '1'
  }
}
// 版本号(2026-09-25 二轮: 左上角 Yugsight 后跟版本): 与「版权信息」页同源
// (/api/info 的 version, 即构建注入的 main.appVersion), 两处不会漂移。
const ver = ref('')
// 品牌自定义(2026-09-28): 侧边栏系统名称, 缺省 = 原始项目名;
// /api/info 返回后覆盖(brand 节缺失时后端返回默认值, 与缺省一致)
const brandName = ref('Yugsight 御视')
// 点击品牌区 → 版权信息页(用户: "点击这个位置会跳转到版权 licence 页面")
function goCopyright() {
  if (route.path !== '/copyright') router.push('/copyright')
}

async function logout() {
  try { await api('/api/logout', { method: 'POST' }) } catch (e) { /* 忽略 */ }
  resetAuth()
  router.push('/login')
}

onMounted(async () => {
  tickClock()
  clockTimer = setInterval(tickClock, 1000)
  // 首帧按当前视口判定(手机直接打开即是窄屏, 不能等 resize 才收起)
  onViewportResize()
  window.addEventListener('resize', onViewportResize)
  // 拉版本号(左上角系统名后展示)+ 品牌自定义(系统名称 → 侧边栏 + 标签页标题);
  // 失败不阻塞布局
  try {
    const d = await api('/api/info')
    ver.value = (d && d.version) || ''
    if (d && d.brandName) {
      brandName.value = d.brandName
      document.title = d.brandName
    }
  } catch (e) { /* 未登录/异常: 不显示版本, 不影响其余 */ }
})
onBeforeUnmount(() => {
  if (clockTimer) clearInterval(clockTimer)
  clockTimer = null
  window.removeEventListener('resize', onViewportResize)
})
</script>
