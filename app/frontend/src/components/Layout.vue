<template>
  <div class="layout" :class="{ collapsed }">
    <aside class="sidebar">
      <div class="logo">YS</div>
      <div class="brand">Yugsight<span class="brand-sub">安全扫描管理控制台</span></div>
      <nav>
        <!-- 菜单(2026-09-23 阶段 4): 5 组 12 项。
             阶段 3 的「实时扫描控制台 + 扫描任务管理」合并为「扫描作业」(/console 两 tab);
             「报告中心」并入运维总览; 「扫描控制」改名「漏扫管控」;
             「探针管理」+「网络监控 (SNMP)」合并为「节点监控」(/nodemonitor 内两 Tab);
             系统配置组: 引擎与规则 + AI 配置 + 授权管理(admin)。
             阶段 4: 独立「安全大屏」菜单项移除 —— 大屏并入「首页仪表盘」内建 Tab2
             (页面内嵌, 旧 /bigscreen 地址重定向到 ?tab=screen, 见 router.js)。 -->
        <div class="nav-group">运维总览</div>
        <!-- 首页仪表盘内置两个 Tab: 概览仪表盘 + 安全大屏(原独立大屏页能力全量迁入) -->
        <router-link class="nav-item" to="/" :title="collapsed ? '首页仪表盘' : ''"><span class="nav-dot"></span><span class="nav-ico">首</span><span class="nav-label">首页仪表盘</span></router-link>
        <router-link class="nav-item" to="/reports" :title="collapsed ? '报告中心' : ''"><span class="nav-dot"></span><span class="nav-ico">报</span><span class="nav-label">报告中心</span></router-link>

        <div class="nav-group">扫描作业</div>
        <router-link class="nav-item" to="/console" :title="collapsed ? '扫描作业' : ''"><span class="nav-dot"></span><span class="nav-ico">扫</span><span class="nav-label">扫描作业</span></router-link>
        <router-link class="nav-item" to="/weakpass" :title="collapsed ? '弱口令检测' : ''"><span class="nav-dot"></span><span class="nav-ico">弱</span><span class="nav-label">弱口令检测</span></router-link>

        <!-- 阶段 5: 渗透测试组(与扫描作业平级对称, 物理隔离入口)。
             整组仅 admin 可见 —— 渗透是攻击性能力, operator/auditor 无入口
             无权限(与 router.js 的 meta.admin 守卫双保险)。 -->
        <template v-if="admin">
          <div class="nav-group">渗透测试</div>
          <router-link class="nav-item" to="/penta" :title="collapsed ? '渗透工作台' : ''"><span class="nav-dot"></span><span class="nav-ico">渗</span><span class="nav-label">渗透工作台</span></router-link>
        </template>

        <div class="nav-group">资产与风险</div>
        <router-link class="nav-item" to="/assets" :title="collapsed ? '资产管理' : ''"><span class="nav-dot"></span><span class="nav-ico">资</span><span class="nav-label">资产管理</span></router-link>
        <router-link class="nav-item" to="/vulns" :title="collapsed ? '漏洞管理' : ''"><span class="nav-dot"></span><span class="nav-ico">漏</span><span class="nav-label">漏洞管理</span></router-link>
        <router-link class="nav-item" to="/whitelist" :title="collapsed ? '漏扫管控' : ''"><span class="nav-dot"></span><span class="nav-ico">管</span><span class="nav-label">漏扫管控</span></router-link>

        <div class="nav-group">诊断与观测</div>
        <router-link class="nav-item" to="/capture" :title="collapsed ? '实时抓包分析' : ''"><span class="nav-dot"></span><span class="nav-ico">抓</span><span class="nav-label">实时抓包</span></router-link>
        <!-- 节点监控(阶段 1): 原「探针管理」(系统配置) + 「网络监控 (SNMP)」合并为内两 Tab 页面,
             旧 /probes、/monitor 路由保留重定向(见 router.js) -->
        <router-link class="nav-item" to="/nodemonitor" :title="collapsed ? '节点监控' : ''"><span class="nav-dot"></span><span class="nav-ico">监</span><span class="nav-label">节点监控</span></router-link>

        <div class="nav-group">系统配置</div>
        <router-link class="nav-item" to="/env" :title="collapsed ? '引擎与规则' : ''"><span class="nav-dot"></span><span class="nav-ico">引</span><span class="nav-label">引擎与规则</span></router-link>
        <!-- 阶段 3: AI 配置(参数/模板/文档库/记忆库; 分析触发入口在各业务页面) -->
        <router-link class="nav-item" to="/settings/ai" :title="collapsed ? 'AI 配置' : ''"><span class="nav-dot"></span><span class="nav-ico">智</span><span class="nav-label">AI 配置</span></router-link>
        <!-- 授权管理仅 admin 可见(操作员/只读进不去, 见 router.js 的 meta.admin 守卫) -->
        <router-link class="nav-item" v-if="admin" to="/license" :title="collapsed ? '授权管理' : ''"><span class="nav-dot"></span><span class="nav-ico">授</span><span class="nav-label">授权管理</span></router-link>
      </nav>
    </aside>

    <div class="main-col">
      <header class="topbar">
        <button class="collapse-btn" @click="toggleCollapse" :title="collapsed ? '展开菜单' : '收起菜单'">{{ collapsed ? '»' : '«' }}</button>
        <div class="top-title">{{ route.meta.title || '' }}</div>
        <!-- 阶段 4 职责拆分: 顶栏右上角只放静态版本标识(只读, 随页面加载, 无动态负载),
             用于快速确认程序版本; 动态系统指标(CPU/内存/磁盘/队列/链路)统一进
             首页仪表盘 Tab1 的「中心端运行状态」面板, 避免版本与系统信息两处重复展示。 -->
        <div class="top-right">
          <span class="chip blue">v{{ info.version || '-' }}</span>
          <!-- user 为空 = whoami 未返回(加载中的瞬时态), 显示 '-';
               'local' 只可能来自免登录模式的服务端真实返回, 原样展示 -->
          <span class="chip">用户: {{ user || '-' }}</span>
          <button class="btn sm" @click="logout">退出登录</button>
        </div>
      </header>
      <main class="page-main"><slot /></main>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api/http'
import { currentUser, getRole, resetAuth } from '../auth'

const route = useRoute()
const router = useRouter()

const info = ref({})
// user 直接绑定 auth 模块的响应式登录态(不能用 ref(getUser()) 快照:
// 整页刷新时本组件在路由守卫的 whoami 返回前就挂载, 快照永远是 null,
// 刷新后顶栏会一直显示 local —— 2026-09-23 修复)
const user = currentUser
// admin: "授权管理"菜单可见性。必须 computed 跟随响应式角色 —— 快照式
// ref(isAdmin()) 在刷新场景下同样拿到守卫解析前的 false, 管理员菜单被藏。
const admin = computed(() => getRole() === 'admin')
const collapsed = ref(localStorage.getItem('ys_sidebar_collapsed') === '1')
function toggleCollapse() {
  collapsed.value = !collapsed.value
  try { localStorage.setItem('ys_sidebar_collapsed', collapsed.value ? '1' : '0') } catch (e) { /* 忽略 */ }
}

// 顶栏只做一次性静态加载(阶段 4: 版本标识随页面加载, 不做轮询;
// 动态负载数据归首页「中心端运行状态」面板, 见 Dashboard.vue)
async function loadInfo() {
  try { info.value = await api('/api/info') } catch (e) { /* 未登录/服务异常: 顶栏留空 */ }
}

async function logout() {
  try { await api('/api/logout', { method: 'POST' }) } catch (e) { /* 忽略 */ }
  resetAuth()
  router.push('/login')
}

onMounted(() => { loadInfo() })
</script>
